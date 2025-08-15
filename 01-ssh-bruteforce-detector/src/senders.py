import json
import sys

def send_console(alert: dict):
    print(json.dumps(alert, indent=2))

def send_slack_webhook(alert: dict, webhook_url: str | None = None):
    # Placeholder: print what would be sent
    payload = {"text": f"[ALERT] {alert['rule']} | {alert['summary']}", "details": alert}
    print("[SLACK] (stub) would POST:", json.dumps(payload)[:300], file=sys.stderr)

def send_splunk_hec(alert: dict, hec_url: str | None = None, token: str | None = None):
    # Placeholder: print what would be sent
    event = {"event": alert, "sourcetype": "sec:auto:ssh", "host": "local"}
    print("[SPLUNK] (stub) would POST:", json.dumps(event)[:300], file=sys.stderr)
