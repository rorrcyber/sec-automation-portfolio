import argparse
from collections import defaultdict, deque
from datetime import datetime, timedelta
import time
import yaml
from utils import parse_syslog_ts, first_regex_group
from senders import send_console, send_slack_webhook, send_splunk_hec

def load_rule(path: str) -> dict:
    with open(path, "r") as f:
        return yaml.safe_load(f)

def line_matches(line: str, pattern: dict) -> bool:
    # very simple matcher: pattern['contains_all'] -> all substrings must be present
    for s in pattern.get("contains_all", []):
        if s not in line:
            return False
    return True

def build_alert(rule: dict, ip: str, hits: int, first_seen, last_seen) -> dict:
    return {
        "rule": rule["name"],
        "description": rule.get("description",""),
        "ip": ip,
        "hits": hits,
        "window_minutes": rule.get("window_minutes", 10),
        "first_seen": first_seen.isoformat(),
        "last_seen": last_seen.isoformat(),
        "summary": f"{ip} failed SSH login {hits} times in ~{rule.get('window_minutes',10)}m"
    }

def process_lines(lines, rule: dict, slack_url=None, splunk_hec=None, splunk_token=None):
    window = timedelta(minutes=rule.get("window_minutes", 10))
    threshold = rule.get("threshold", 6)
    ip_buckets = defaultdict(deque)
    alerts = []

    for raw in lines:
        line = raw.rstrip("\n")
        if not line_matches(line, rule["pattern"]):
            continue
        ts = parse_syslog_ts(line) or datetime.utcnow()
        ip = first_regex_group(rule["extract_ip_regex"], line, "ip")
        if not ip:
            continue
        dq = ip_buckets[ip]
        dq.append(ts)
        # evict old
        while dq and ts - dq[0] > window:
            dq.popleft()
        if len(dq) >= threshold:
            alert = build_alert(rule, ip, len(dq), dq[0], dq[-1])
            alerts.append(alert)
            ip_buckets[ip].clear()
            send_console(alert)
            send_slack_webhook(alert, slack_url)
            send_splunk_hec(alert, splunk_hec, splunk_token)
    return alerts

def main():
    ap = argparse.ArgumentParser(description="SSH Brute Force Detector")
    ap.add_argument("--rule", default="rules/ssh_bruteforce.yml")
    ap.add_argument("--log", default="samples/auth.log.sample")
    ap.add_argument("--follow", action="store_true", help="tail -f style")
    ap.add_argument("--slack", default=None, help="Slack webhook URL (optional)")
    ap.add_argument("--splunk-hec", default=None, help="Splunk HEC URL (optional)")
    ap.add_argument("--splunk-token", default=None, help="Splunk HEC token (optional)")
    args = ap.parse_args()

    rule = load_rule(args.rule)

    if args.follow:
        with open(args.log, "r") as f:
            f.seek(0, 2)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.5)
                    continue
                process_lines([line], rule, args.slack, args.splunk_hec, args.splunk_token)
    else:
        with open(args.log, "r") as f:
            process_lines(f, rule, args.slack, args.splunk_hec, args.splunk_token)

if __name__ == "__main__":
    main()
