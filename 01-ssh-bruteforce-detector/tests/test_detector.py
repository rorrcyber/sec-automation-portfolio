from src.detector import process_lines, load_rule

def test_alert_triggers():
    rule = load_rule("rules/ssh_bruteforce.yml")
    lines = open("samples/auth.log.sample").read().splitlines()
    alerts = process_lines(lines, rule)
    assert len(alerts) == 1
    a = alerts[0]
    assert a["ip"] == "10.1.2.3"
    assert a["hits"] >= rule["threshold"]
