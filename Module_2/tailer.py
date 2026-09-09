import time
import os
import sys
import re
import hashlib
import sqlite3
from pathlib import Path
from datetime import datetime, timezone
import requests

MODULE_DIR = Path(__file__).resolve().parent
BASE_DIR = MODULE_DIR.parent
if str(MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(MODULE_DIR))
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from parser import parse_log_line
from template_detector import detect_template
from masking.regex import mask_from_schema
from masking.ner_masking import mask_named_entities
from classifier import analyze_log_batch
from m3.crypto_signer import (
    sign_payload,
    load_private_key_from_env,
    get_public_key_from_private_pem
)

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


def _ensure_event_id_column(db_path: Path):
    """Ensures incident_alerts table has the event_id column for Merkle tree references."""
    try:
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(incident_alerts)")
        cols = [col[1] for col in cursor.fetchall()]
        if cols and "event_id" not in cols:
            cursor.execute("ALTER TABLE incident_alerts ADD COLUMN event_id TEXT")
            conn.commit()
        conn.close()
    except Exception:
        pass


def _extract_user_id_from_context(context_text: str) -> str:
    """Extracts a user identity from log context if present, defaulting to system identity."""
    patterns = [
        r"User\s+([a-zA-Z0-9_\-]+)",
        r"username[=:]\s*([a-zA-Z0-9_\-]+)",
        r"username\s+'([a-zA-Z0-9_\-]+)'",
        r"user_id[=:]\s*([a-zA-Z0-9_\-]+)",
    ]
    for pat in patterns:
        m = re.search(pat, context_text, re.IGNORECASE)
        if m:
            return m.group(1).lower()
    return "system_audit"


def _insert_incident_alert(db_path: Path, classification, context_text: str):
    """Save an alert directly to the Flask app database and return its row ID."""
    try:
        _ensure_event_id_column(db_path)
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO incident_alerts (incident_type, severity, confidence, masked_log_context, cert_in_draft, status, created_at)
            VALUES (?, ?, ?, ?, ?, 'Open', datetime('now'))
        """, (
            classification.incident_type.value,
            classification.severity.value,
            classification.confidence,
            context_text,
            classification.cert_in_report_draft
        ))
        conn.commit()
        alert_id = cursor.lastrowid
        conn.close()
        print(f"[*] Saved incident {classification.incident_type.value} to database (ID: {alert_id}).")
        return alert_id
    except Exception as e:
        print(f"[ERROR] Failed to save IncidentAlert to DB: {e}")
        return None


def _update_incident_event_id(db_path: Path, alert_id: int, event_id: str):
    """Updates an IncidentAlert row with its corresponding M3 Merkle event ID."""
    try:
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        cursor.execute("UPDATE incident_alerts SET event_id = ? WHERE id = ?", (event_id, alert_id))
        conn.commit()
        conn.close()
        print(f"[*] Linked IncidentAlert #{alert_id} to M3 event_id: {event_id}")
    except Exception as e:
        print(f"[ERROR] Failed to update IncidentAlert event_id: {e}")


def _send_update_to_m3(db_path: Path, alert_id: int, classification, context_text: str):
    """
    Submits a signed update request to Module 3 Merkle Tree API.
    Best-effort: logs failures, never crashes caller or main pipeline.
    """
    try:
        # Load private key from environment variable - NEVER from a file
        private_key_pem = load_private_key_from_env("M3_SIGNING_PRIVATE_KEY")
        if not private_key_pem:
            print("[WARN] M3_SIGNING_PRIVATE_KEY not set in environment. Skipping M3 Merkle update.")
            return

        user_id = _extract_user_id_from_context(context_text)
        leaf_id = f"alert_{alert_id}" if alert_id else f"alert_{int(time.time() * 1000)}"

        # Compute cryptographic digests binding masked context and classification
        masked_pii_hash = hashlib.sha256(context_text.encode('utf-8')).hexdigest()
        real_repr = f"{classification.incident_type.value}:{classification.severity.value}:{classification.confidence}:{context_text}"
        real_data_hash = hashlib.sha256(real_repr.encode('utf-8')).hexdigest()
        timestamp = datetime.now(timezone.utc).isoformat()

        payload = {
            "user_id": str(user_id),
            "leaf_id": str(leaf_id),
            "masked_pii_hash": masked_pii_hash,
            "real_data_hash": real_data_hash,
            "timestamp": timestamp
        }

        # Sign payload using RSA-2048 private key in memory
        signature_hex = sign_payload(private_key_pem, payload)
        public_key_pem = get_public_key_from_private_pem(private_key_pem)

        request_body = {
            **payload,
            "signature_hex": signature_hex,
            "public_key_pem": public_key_pem
        }

        m3_url = os.environ.get("M3_API_URL", "http://127.0.0.1:5001/api/v1/tree/update")
        response = requests.post(m3_url, json=request_body, timeout=5.0)

        if response.status_code == 200:
            data = response.json()
            event_id = data.get("event_id")
            print(f"[M3] Tree update successful. event_id={event_id}")
            if alert_id and event_id:
                _update_incident_event_id(db_path, alert_id, event_id)
        else:
            print(f"[WARN] M3 update returned HTTP {response.status_code}: {response.text}")
    except Exception as e:
        # Best-effort: log warning, never crash the main pipeline
        print(f"[WARN] Failed to send update to Module 3 (best-effort): {e}")

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
    
    log_buffer = []

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
        
        # Buffer logic for classification
        log_buffer.append(masked_text)
        if len(log_buffer) > 20:
            log_buffer.pop(0)
            
        classification = analyze_log_batch(log_buffer)
        if classification:
            print(f"!!! [ALERT DETECTED] {classification.incident_type.value} (Severity: {classification.severity.value}) !!!")
            context_text = "\n".join(log_buffer[-5:])
            alert_id = _insert_incident_alert(DB_PATH, classification, context_text)
            _send_update_to_m3(DB_PATH, alert_id, classification, context_text)
            log_buffer.clear() # Debounce until next event series
            
        print()


if __name__ == "__main__":
    main()