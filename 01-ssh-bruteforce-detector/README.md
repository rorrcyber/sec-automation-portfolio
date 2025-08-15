# SSH Brute-Force Detector (Python)

Detects repeated failed SSH logins in syslog/auth.log and emits alerts.

## Quickstart
```bash
pip install -r requirements.txt
python src/detector.py --log samples/auth.log.sample
```
Use `--follow` to tail a live `/var/log/auth.log`.

## Send alerts
Add `--slack https://hooks.slack...` or `--splunk-hec https://SPLUNK:8088 --splunk-token <token>` (stubs now).

## Tests
```bash
pytest -q
```
