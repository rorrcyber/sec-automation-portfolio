import re
from datetime import datetime

MONTHS = {m:i for i,m in enumerate(
    ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"], start=1)}

def parse_syslog_ts(line: str, year: int | None = None) -> datetime | None:
    # e.g., "Aug 14 09:00:01"
    try:
        mon = MONTHS[line[0:3]]
        day = int(line[4:6].strip())
        time_part = line[7:15]
        if year is None:
            year = datetime.utcnow().year
        return datetime.strptime(f"{year}-{mon:02d}-{day:02d} {time_part}", "%Y-%m-%d %H:%M:%S")
    except Exception:
        return None

def first_regex_group(pattern: str, text: str, name: str = "ip") -> str | None:
    m = re.search(pattern, text)
    if not m:
        return None
    if name in m.groupdict():
        return m.group(name)
    return m.group(1) if m.groups() else None
