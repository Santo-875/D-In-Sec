import time
import os
from pathlib import Path

from parser import parse_log_line
from template_detector import detect_template
from masking.regex import mask_structured_pii
from masking.ner_masking import mask_named_entities

LOG_FILE_PATH = Path(r"F:\D-inSec\mock_site\logs\system.log")
POLL_INTERVAL_SECONDS = 1.0


def tail_log_file(path: Path):
    f = open(path, "r", encoding="utf-8")
    f.seek(0, 2)
    current_size = os.path.getsize(path)

    while True:
        line = f.readline()

        if line:
            yield line
            continue

        time.sleep(POLL_INTERVAL_SECONDS)

        try:
            new_size = os.path.getsize(path)
        except FileNotFoundError:
            continue

        if new_size < current_size:
            f.close()
            f = open(path, "r", encoding="utf-8")
            print("[tailer] Detected log rotation — reopened system.log")

        current_size = new_size


def main():
    print(f"Watching: {LOG_FILE_PATH}")
    print("Waiting for new log lines... (Ctrl+C to stop)\n")

    for raw_line in tail_log_file(LOG_FILE_PATH):
        parsed = parse_log_line(raw_line)
        if parsed is None:
            continue

        tagged = detect_template(parsed)

        # Run masking on the raw_message
        masked_text, regex_found = mask_structured_pii(tagged.raw_message)
        masked_text, ner_found = mask_named_entities(masked_text)

        print(f"[{tagged.template.value}]")
        print(f"  RAW:    {tagged.raw_message}")
        print(f"  MASKED: {masked_text}")
        print(f"  FOUND:  regex={regex_found} | ner={ner_found}")
        print()


if __name__ == "__main__":
    main()