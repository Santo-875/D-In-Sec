import time
import os
import sqlite3
from pathlib import Path

from parser import parse_log_line
from template_detector import detect_template
from masking.regex import mask_from_schema
from masking.ner_masking import mask_named_entities

# Paths resolved relative to script location to avoid hardcoding machine-specific paths
BASE_DIR = Path(__file__).resolve().parent.parent
LOG_FILE_PATH = BASE_DIR / "mock_site" / "logs" / "system.log"
DB_PATH = BASE_DIR / "mock_site" / "instance" / "mock_site.db"

POLL_INTERVAL_SECONDS = 1.0


def get_schema_fields(db_path: Path) -> list:
    """Read admin-defined field schemas directly from SQLite DB."""
    if not db_path.exists():
        return []
    try:
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT regex_pattern, mask_label, pii_category FROM field_schemas")
        rows = cursor.fetchall()
        fields = [dict(row) for row in rows]
        conn.close()
        return fields
    except Exception:
        return []


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
    print(f"Database: {DB_PATH}")
    print("Waiting for new log lines... (Ctrl+C to stop)\n")

    # Cache schema fields to prevent high DB connection overhead on every log line
    schema_fields = get_schema_fields(DB_PATH)
    last_cache_time = time.time()

    for raw_line in tail_log_file(LOG_FILE_PATH):
        parsed = parse_log_line(raw_line)
        if parsed is None:
            continue

        tagged = detect_template(parsed)

        # Re-query schema fields every 10 seconds
        current_time = time.time()
        if current_time - last_cache_time > 10.0:
            schema_fields = get_schema_fields(DB_PATH)
            last_cache_time = current_time

        # Run masking on the raw_message using dynamic schema + ner
        masked_text, regex_found = mask_from_schema(tagged.raw_message, schema_fields)
        masked_text, ner_found = mask_named_entities(masked_text)

        print(f"[{tagged.template.value}]")
        print(f"  RAW:    {tagged.raw_message}")
        print(f"  MASKED: {masked_text}")
        print(f"  FOUND:  regex={regex_found} | ner={ner_found}")
        print()


if __name__ == "__main__":
    main()