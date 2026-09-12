import time
import os
import sys
import re
import uuid
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
            
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS m2_outbox (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id INTEGER,
                user_id TEXT,
                leaf_id TEXT,
                masked_pii_hash TEXT,
                real_data_hash TEXT,
                status TEXT DEFAULT 'PENDING',
                retry_count INTEGER DEFAULT 0,
                created_at TEXT
            )
        """)
        conn.commit()
        conn.close()
    except Exception:
        pass


# Removed legacy _extract_user_id_from_context


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


def _register_key_with_m3(public_key_pem: str, user_id: str = "m2_service"):
    """
    Pre-registers Module 2's public key with M3 on startup.
    Requires M3_ADMIN_API_KEY for ADMIN-level access to /identity/register.
    Best-effort: logs warning if M3 is unreachable.
    """
    admin_key = os.environ.get("M3_ADMIN_API_KEY", "dev-admin-key")
    m3_base = os.environ.get("M3_API_URL", "http://127.0.0.1:5001/api/v1/tree/update")
    register_url = m3_base.rsplit("/tree/update", 1)[0] + "/identity/register"

    try:
        resp = requests.post(
            register_url,
            json={"identity_id": user_id, "public_key_pem": public_key_pem},
            headers={"X-API-Key": admin_key},
            timeout=5.0
        )
        if resp.status_code == 200:
            data = resp.json()
            print(f"[M3-AUTH] Registered public key with M3. fingerprint={data.get('fingerprint', 'N/A')[:16]}...")
        else:
            print(f"[WARN] M3 key registration returned HTTP {resp.status_code}: {resp.text[:100]}")
    except Exception as e:
        print(f"[WARN] Failed to register key with M3 (best-effort): {e}")


def _process_outbox_item(db_path: Path, outbox_id: int, alert_id: int, user_id: str, leaf_id: str, masked_pii_hash: str, real_data_hash: str) -> bool:
    """Attempts to sign and send an outbox item to M3. Returns True on success."""
    try:
        private_key_pem = load_private_key_from_env("M3_SIGNING_PRIVATE_KEY")
        if not private_key_pem:
            return False

        timestamp = datetime.now(timezone.utc).isoformat()
        payload = {
            "user_id": user_id,
            "leaf_id": leaf_id,
            "masked_pii_hash": masked_pii_hash,
            "real_data_hash": real_data_hash,
            "timestamp": timestamp
        }

        signature_hex = sign_payload(private_key_pem, payload)
        event_id = f"evt_{uuid.uuid4().hex[:12]}"
        nonce = uuid.uuid4().hex

        request_body = {
            **payload,
            "signature_hex": signature_hex,
            "event_id": event_id,
            "nonce": nonce
        }

        service_key = os.environ.get("M3_SERVICE_API_KEY", "dev-service-key")
        headers = {"X-API-Key": service_key}
        m3_url = os.environ.get("M3_API_URL", "http://127.0.0.1:5001/api/v1/tree/update")
        
        response = requests.post(m3_url, json=request_body, headers=headers, timeout=5.0)

        if response.status_code == 200:
            m3_event_id = response.json().get("event_id")
            print(f"[M3] Tree update successful. event_id={m3_event_id}")
            
            conn = sqlite3.connect(str(db_path))
            cursor = conn.cursor()
            cursor.execute("UPDATE m2_outbox SET status = 'SENT' WHERE id = ?", (outbox_id,))
            if alert_id and m3_event_id:
                cursor.execute("UPDATE incident_alerts SET event_id = ? WHERE id = ?", (m3_event_id, alert_id))
            conn.commit()
            conn.close()
            return True
        else:
            print(f"[WARN] M3 update returned HTTP {response.status_code}: {response.text[:200]}")
            conn = sqlite3.connect(str(db_path))
            conn.execute("UPDATE m2_outbox SET retry_count = retry_count + 1 WHERE id = ?", (outbox_id,))
            conn.commit()
            conn.close()
            return False
    except Exception as e:
        print(f"[WARN] Failed to process outbox item {outbox_id}: {e}")
        try:
            conn = sqlite3.connect(str(db_path))
            conn.execute("UPDATE m2_outbox SET retry_count = retry_count + 1 WHERE id = ?", (outbox_id,))
            conn.commit()
            conn.close()
        except:
            pass
        return False

def _outbox_retry_worker(db_path: Path):
    """Background worker that periodically retries PENDING outbox items."""
    import time
    while True:
        try:
            conn = sqlite3.connect(str(db_path))
            cursor = conn.cursor()
            cursor.execute("SELECT id, alert_id, user_id, leaf_id, masked_pii_hash, real_data_hash FROM m2_outbox WHERE status = 'PENDING' LIMIT 10")
            rows = cursor.fetchall()
            conn.close()
            
            for row in rows:
                _process_outbox_item(db_path, *row)
                
        except Exception as e:
            pass
        time.sleep(10.0)

def _send_update_to_m3(db_path: Path, alert_id: int, classification, context_text: str, user_id: str = "system_audit"):
    """
    Writes an update request to the M2 Outbox and attempts immediate delivery.
    """
    try:
        leaf_id = f"alert_{alert_id}" if alert_id else f"alert_{int(time.time() * 1000)}"

        masked_pii_hash = hashlib.sha256(context_text.encode('utf-8')).hexdigest()
        real_repr = f"{classification.incident_type.value}:{classification.severity.value}:{classification.confidence}:{context_text}"
        real_data_hash = hashlib.sha256(real_repr.encode('utf-8')).hexdigest()

        # Insert into outbox
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO m2_outbox (alert_id, user_id, leaf_id, masked_pii_hash, real_data_hash, created_at)
            VALUES (?, ?, ?, ?, ?, datetime('now'))
        """, (alert_id, user_id, leaf_id, masked_pii_hash, real_data_hash))
        outbox_id = cursor.lastrowid
        conn.commit()
        conn.close()

        # Attempt immediate send
        _process_outbox_item(db_path, outbox_id, alert_id, user_id, leaf_id, masked_pii_hash, real_data_hash)
        
    except Exception as e:
        print(f"[WARN] Failed to enqueue update to M3 Outbox: {e}")

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

    # Auto-register public key with M3 on startup
    private_key_pem = load_private_key_from_env("M3_SIGNING_PRIVATE_KEY")
    if private_key_pem:
        public_key_pem = get_public_key_from_private_pem(private_key_pem)
        _register_key_with_m3(public_key_pem)
    else:
        print("[WARN] M3_SIGNING_PRIVATE_KEY not set. M3 wiring will be skipped.")

    # Start outbox retry worker
    import threading
    worker_thread = threading.Thread(target=_outbox_retry_worker, args=(DB_PATH,), daemon=True)
    worker_thread.start()
    print("[*] M2 Outbox retry worker started.")

    # Cache schema fields to prevent high DB connection overhead on every log line
    schema_fields = get_schema_fields(DB_PATH)
    last_cache_time = time.time()
    
    log_buffer = []
    failure_window = {}  # actor_id -> list of timestamps

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
        masked_text, regex_found, has_leak = mask_from_schema(tagged.raw_message, schema_fields)
        masked_text, ner_found = mask_named_entities(masked_text)

        print(f"[{tagged.template.value}]")
        print(f"  RAW:    {tagged.raw_message}")
        print(f"  MASKED: {masked_text}")
        print(f"  FOUND:  regex={regex_found} | ner={ner_found}")
        
        # Buffer logic for classification
        log_buffer.append(masked_text)
        if len(log_buffer) > 20:
            log_buffer.pop(0)
            
        # Sliding Window Anomaly Detection for Brute Force
        if tagged.template.value == "LOGIN_FAILED":
            if tagged.actor_id:
                now = time.time()
                if tagged.actor_id not in failure_window:
                    failure_window[tagged.actor_id] = []
                failure_window[tagged.actor_id].append(now)
                # Keep only failures in the last 60 seconds
                failure_window[tagged.actor_id] = [t for t in failure_window[tagged.actor_id] if now - t <= 60]
                
                if len(failure_window[tagged.actor_id]) >= 5:
                    from schemas import IncidentType, Severity, ClassificationResult
                    classification = ClassificationResult(
                        incident_type=IncidentType.BRUTE_FORCE,
                        severity=Severity.HIGH,
                        confidence=1.0,
                        source="rule_engine"
                    )
                    print(f"!!! [ALERT DETECTED] {classification.incident_type.value} (Severity: {classification.severity.value}) via Sliding Window !!!")
                    context_text = "\n".join(log_buffer[-5:])
                    alert_id = _insert_incident_alert(DB_PATH, classification, context_text)
                    _send_update_to_m3(DB_PATH, alert_id, classification, context_text, user_id=tagged.actor_id)
                    failure_window[tagged.actor_id] = []
                    log_buffer.clear()
                    print()
                    continue

        if has_leak:
            from schemas import IncidentType, Severity, ClassificationResult
            classification = ClassificationResult(
                incident_type=IncidentType.PII_LEAK,
                severity=Severity.CRITICAL,
                confidence=1.0,
                source="rule_engine"
            )
            print(f"!!! [ALERT DETECTED] {classification.incident_type.value} (Severity: {classification.severity.value}) via Rule Engine (Raw PII Leak) !!!")
            context_text = "\n".join(log_buffer[-5:]) if log_buffer else masked_text
            alert_id = _insert_incident_alert(DB_PATH, classification, context_text)
            user_id = tagged.actor_id if tagged.actor_id else "system_audit"
            _send_update_to_m3(DB_PATH, alert_id, classification, context_text, user_id=user_id)
            log_buffer.clear()
            print()
            continue

        classification = analyze_log_batch(log_buffer)
        if classification:
            print(f"!!! [ALERT DETECTED] {classification.incident_type.value} (Severity: {classification.severity.value}) !!!")
            context_text = "\n".join(log_buffer[-5:])
            alert_id = _insert_incident_alert(DB_PATH, classification, context_text)
            
            # Use the most recent actor_id, or fallback to system_audit
            user_id = tagged.actor_id if tagged.actor_id else "system_audit"
            _send_update_to_m3(DB_PATH, alert_id, classification, context_text, user_id=user_id)
            log_buffer.clear() # Debounce until next event series
            
        print()


if __name__ == "__main__":
    main()