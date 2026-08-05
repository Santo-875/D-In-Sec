import re
from datetime import datetime
from schemas import ParsedLogLine
from typing import Optional
LOG_LINE_PATTERN = re.compile(
    r"^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]\s\[(\w+)\]\s(.*)$"
)
def parse_log_line(raw_line: str, source_file: str = "system.log") -> Optional[ParsedLogLine]:
    raw_line = raw_line.strip()
    if not raw_line:
        return None

    match = LOG_LINE_PATTERN.match(raw_line)
    if not match:
        return None

    timestamp_str, level, message = match.groups()

    try:
        timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None

    return ParsedLogLine(
        timestamp=timestamp,
        level=level,
        raw_message=message,
        source_file=source_file,
    )