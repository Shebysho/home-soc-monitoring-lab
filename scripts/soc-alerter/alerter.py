import html, json, os, time, urllib.request

BOT_TOKEN = os.getenv("TG_BOT_TOKEN", "YOUR_TELEGRAM_BOT_TOKEN")
CHAT_ID = os.getenv("TG_CHAT_ID", "YOUR_TELEGRAM_CHAT_ID")
EVE_PATH = "/var/log/suricata/eve.json"
COOLDOWN = 300
seen = {}

def send_alert(event: dict) -> None:
    alert = event.get("alert", {})
    sev = alert.get("severity", 3)
    badge = "🔴 CRITICAL" if sev == 1 else "🟠 HIGH"
    src = f"{html.escape(str(event.get('src_ip', '?')))}:{html.escape(str(event.get('src_port', '-')))}"
    dst = f"{html.escape(str(event.get('dest_ip', '?')))}:{html.escape(str(event.get('dest_port', '-')))}"
    sig = html.escape(str(alert.get("signature", "Unknown")))
    cat = html.escape(str(alert.get("category", "N/A")))
    ts = html.escape(str(event.get("timestamp", "")))
    text = chr(10).join([
        f"<b>{badge} | SOC Alert (Severity {sev})</b>",
        f"<b>Signature:</b> <code>{sig}</code>",
        f"<b>Source:</b> <code>{src}</code>",
        f"<b>Destination:</b> <code>{dst}</code>",
        f"<b>Category:</b> {cat}",
        f"<b>Time:</b> <code>{ts}</code>",
    ])
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    req = urllib.request.Request(url, data=json.dumps({"chat_id": CHAT_ID, "text": text, "parse_mode": "HTML"}).encode("utf-8"), headers={"Content-Type": "application/json"})
    try:
        urllib.request.urlopen(req, timeout=5)
    except Exception as exc:
        print(f"Telegram API error: {exc}", flush=True)

def tail_eve() -> None:
    while not os.path.exists(EVE_PATH):
        time.sleep(1)
    f = open(EVE_PATH, "r", encoding="utf-8")
    f.seek(0, 2)
    inode = os.fstat(f.fileno()).st_ino
    while True:
        line = f.readline()
        if not line:
            try:
                if os.stat(EVE_PATH).st_ino != inode:
                    f.close()
                    f = open(EVE_PATH, "r", encoding="utf-8")
                    inode = os.fstat(f.fileno()).st_ino
            except FileNotFoundError:
                pass
            time.sleep(0.5)
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("event_type") == "alert":
            alert = event.get("alert", {})
            if alert.get("severity", 3) <= 2:
                key = (event.get("src_ip"), alert.get("signature_id"))
                now = time.time()
                if now - seen.get(key, 0) > COOLDOWN:
                    seen[key] = now
                    send_alert(event)

if __name__ == "__main__":
    tail_eve()
