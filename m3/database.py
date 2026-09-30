import sqlite3
import json
from pathlib import Path
from contextlib import closing
from typing import Dict, List, Any, Optional

class M3Database:
    """
    SQLite persistence layer for Module 3.
    Stores identities, Merkle leaves, audit events, checkpoints, and M4 payloads.
    Uses WAL mode for high concurrency.
    """
    def __init__(self, db_path: str = "m3.db"):
        self.db_path = Path(db_path)
        self._init_db()

    def get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_db(self):
        with closing(self.get_connection()) as conn:
            with conn:
                cursor = conn.cursor()
                # 1. Identity Registry
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS identity_keys (
                        identity_id TEXT PRIMARY KEY,
                        public_key_pem TEXT NOT NULL,
                        fingerprint TEXT NOT NULL,
                        registered_at TEXT NOT NULL,
                        is_revoked INTEGER DEFAULT 0
                    )
                ''')
                try:
                    cursor.execute("ALTER TABLE identity_keys ADD COLUMN is_revoked INTEGER DEFAULT 0")
                except sqlite3.OperationalError:
                    pass
                # 2. Merkle Leaves (for rebuilding tree)
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS merkle_leaves (
                        user_id TEXT,
                        leaf_id TEXT,
                        masked_pii_hash TEXT NOT NULL,
                        real_data_hash TEXT NOT NULL,
                        combined_hash TEXT NOT NULL,
                        timestamp TEXT NOT NULL,
                        version INTEGER NOT NULL,
                        PRIMARY KEY (user_id, leaf_id)
                    )
                ''')
                # 3. Audit Events (Detailed Log)
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS audit_events (
                        event_id TEXT PRIMARY KEY,
                        timestamp TEXT NOT NULL,
                        user_id TEXT NOT NULL,
                        leaf_id TEXT NOT NULL,
                        old_leaf_hash TEXT,
                        new_leaf_hash TEXT NOT NULL,
                        old_master_root TEXT NOT NULL,
                        new_master_root TEXT NOT NULL,
                        signature_hex TEXT NOT NULL,
                        signer_fingerprint TEXT NOT NULL,
                        previous_hash TEXT,
                        event_hash TEXT NOT NULL
                    )
                ''')
                # 4. Root Checkpoints (Permanent Chain)
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS root_checkpoints (
                        event_id TEXT PRIMARY KEY,
                        timestamp TEXT NOT NULL,
                        master_root TEXT NOT NULL,
                        user_id TEXT NOT NULL,
                        previous_hash TEXT,
                        checkpoint_hash TEXT NOT NULL
                    )
                ''')
                # 5. Freeze States
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS freeze_states (
                        user_id TEXT PRIMARY KEY,
                        reason TEXT NOT NULL,
                        frozen_at TEXT NOT NULL,
                        freeze_id TEXT,
                        expires_at TEXT,
                        initiated_by TEXT
                    )
                ''')
                try:
                    cursor.execute("ALTER TABLE freeze_states ADD COLUMN freeze_id TEXT")
                    cursor.execute("ALTER TABLE freeze_states ADD COLUMN expires_at TEXT")
                    cursor.execute("ALTER TABLE freeze_states ADD COLUMN initiated_by TEXT")
                except sqlite3.OperationalError:
                    pass
                # 6. M4 Payloads (for SOC integration)
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS m4_payloads (
                        event_id TEXT PRIMARY KEY,
                        payload_json TEXT NOT NULL
                    )
                ''')
                # 8. AI Background Jobs
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS ai_jobs (
                        job_id TEXT PRIMARY KEY,
                        status TEXT NOT NULL,
                        facts_json TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        completed_at TEXT
                    )
                ''')
                # 9. Admin Audit Logs
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS admin_audit_logs (
                        log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        action TEXT NOT NULL,
                        target TEXT,
                        reason TEXT,
                        timestamp TEXT NOT NULL
                    )
                ''')
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS replay_guard_events (
                        event_id TEXT PRIMARY KEY,
                        timestamp TEXT NOT NULL
                    )
                ''')
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS replay_guard_nonces (
                        nonce TEXT PRIMARY KEY,
                        timestamp TEXT NOT NULL
                    )
                ''')
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS replay_guard_versions (
                        user_id TEXT NOT NULL,
                        leaf_id TEXT NOT NULL,
                        version INTEGER NOT NULL,
                        PRIMARY KEY (user_id, leaf_id)
                    )
                ''')
                
                # AI Jobs (idempotent duplicate CREATE — table already created above)
                # pending_uploads — write-through retry queue for S3 outages
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS pending_uploads (
                        upload_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        op TEXT NOT NULL,
                        meta_json TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        attempts INTEGER DEFAULT 0
                    )
                ''')
                # review_queue — human labelling for ML retrain (Phase 2)
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS review_queue (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_id TEXT NOT NULL,
                        model_label TEXT,
                        human_label TEXT,
                        reviewer TEXT,
                        ts TEXT,
                        fn_flag INTEGER DEFAULT 0
                    )
                ''')
                # model_registry — ML model versions (Phase 2)
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS model_registry (
                        version TEXT PRIMARY KEY,
                        metrics_json TEXT,
                        sha256 TEXT,
                        promoted_at TEXT,
                        is_active INTEGER DEFAULT 0
                    )
                ''')
                # daily_summaries — CERT-In daily summaries (Phase 2)
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS daily_summaries (
                        date TEXT PRIMARY KEY,
                        summary_json TEXT NOT NULL,
                        created_at TEXT NOT NULL
                    )
                ''')
                # alerts — alert log for Phase 4
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS alerts (
                        alert_id TEXT PRIMARY KEY,
                        alert_type TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        details_json TEXT,
                        ai_explanation TEXT,
                        created_at TEXT NOT NULL,
                        resolved INTEGER DEFAULT 0
                    )
                ''')
            conn.commit()

    # --- Identity Keys ---
    def save_identity_key(self, identity_id: str, public_key_pem: str, fingerprint: str, registered_at: str):
        with closing(self.get_connection()) as conn:
            with conn:
                conn.execute(
                    "INSERT OR REPLACE INTO identity_keys (identity_id, public_key_pem, fingerprint, registered_at, is_revoked) VALUES (?, ?, ?, ?, 0)",
                    (identity_id, public_key_pem, fingerprint, registered_at)
                )

    def load_identity_keys(self) -> Dict[str, Dict[str, str]]:
        keys = {}
        with closing(self.get_connection()) as conn:
            cursor = conn.execute("SELECT identity_id, public_key_pem, fingerprint, registered_at, is_revoked FROM identity_keys")
            for row in cursor:
                keys[row[0]] = {
                    "public_key_pem": row[1],
                    "fingerprint": row[2],
                    "registered_at": row[3],
                    "is_revoked": bool(row[4])
                }
        return keys

    def revoke_identity(self, identity_id: str) -> bool:
        with closing(self.get_connection()) as conn:
            with conn:
                cursor = conn.execute("UPDATE identity_keys SET is_revoked = 1 WHERE identity_id = ?", (identity_id,))
                return cursor.rowcount > 0

    # --- Merkle Leaves ---
    def save_merkle_leaf(self, user_id: str, leaf_id: str, masked_pii_hash: str, real_data_hash: str, combined_hash: str, timestamp: str, version: int, conn: Optional[sqlite3.Connection] = None):
        def _execute(c):
            c.execute(
                """INSERT OR REPLACE INTO merkle_leaves 
                   (user_id, leaf_id, masked_pii_hash, real_data_hash, combined_hash, timestamp, version) 
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (user_id, leaf_id, masked_pii_hash, real_data_hash, combined_hash, timestamp, version)
            )
        if conn:
            _execute(conn)
        else:
            with closing(self.get_connection()) as c:
                with c:
                    _execute(c)

    def load_merkle_leaves(self) -> List[Dict[str, Any]]:
        with closing(self.get_connection()) as conn:
            cursor = conn.execute("SELECT user_id, leaf_id, masked_pii_hash, real_data_hash, combined_hash, timestamp, version FROM merkle_leaves ORDER BY timestamp ASC")
            return [
                {
                    "user_id": row[0], "leaf_id": row[1], "masked_pii_hash": row[2],
                    "real_data_hash": row[3], "combined_hash": row[4], "timestamp": row[5], "version": row[6]
                }
                for row in cursor.fetchall()
            ]

    # --- Audit Events ---
    def save_audit_event(self, entry: Dict[str, Any], conn: Optional[sqlite3.Connection] = None):
        def _execute(c):
            c.execute(
                """INSERT INTO audit_events 
                   (event_id, timestamp, user_id, leaf_id, old_leaf_hash, new_leaf_hash, old_master_root, new_master_root, signature_hex, signer_fingerprint, previous_hash, event_hash)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (entry["event_id"], entry["timestamp"], entry["user_id"], entry["leaf_id"], entry.get("old_leaf_hash"),
                 entry["new_leaf_hash"], entry["old_master_root"], entry["new_master_root"], entry["signature_hex"],
                 entry["signer_fingerprint"], entry.get("previous_hash"), entry["event_hash"])
            )
        if conn:
            _execute(conn)
        else:
            with closing(self.get_connection()) as c:
                with c:
                    _execute(c)

    def load_audit_events(self) -> List[Dict[str, Any]]:
        with closing(self.get_connection()) as conn:
            cursor = conn.execute("SELECT * FROM audit_events ORDER BY timestamp ASC")
            cols = [desc[0] for desc in cursor.description]
            return [dict(zip(cols, row)) for row in cursor.fetchall()]

    # --- Checkpoints ---
    def save_checkpoint(self, checkpoint: Dict[str, Any], conn: Optional[sqlite3.Connection] = None):
        def _execute(c):
            c.execute(
                """INSERT INTO root_checkpoints (event_id, timestamp, master_root, user_id, previous_hash, checkpoint_hash)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (checkpoint["event_id"], checkpoint["timestamp"], checkpoint["master_root"], checkpoint["user_id"],
                 checkpoint.get("previous_hash"), checkpoint["checkpoint_hash"])
            )
        if conn:
            _execute(conn)
        else:
            with closing(self.get_connection()) as c:
                with c:
                    _execute(c)

    def load_checkpoints(self) -> List[Dict[str, Any]]:
        with closing(self.get_connection()) as conn:
            cursor = conn.execute("SELECT * FROM root_checkpoints ORDER BY timestamp ASC")
            cols = [desc[0] for desc in cursor.description]
            return [dict(zip(cols, row)) for row in cursor.fetchall()]

    def save_freeze_state(self, user_id: str, reason: str, frozen_at: str, freeze_id: str = None, expires_at: str = None, initiated_by: str = None):
        with closing(self.get_connection()) as conn:
            with conn:
                conn.execute("INSERT OR REPLACE INTO freeze_states (user_id, reason, frozen_at, freeze_id, expires_at, initiated_by) VALUES (?, ?, ?, ?, ?, ?)",
                             (user_id, reason, frozen_at, freeze_id, expires_at, initiated_by))

    def delete_freeze_state(self, user_id: str):
        with closing(self.get_connection()) as conn:
            with conn:
                conn.execute("DELETE FROM freeze_states WHERE user_id = ?", (user_id,))

    def load_freeze_states(self) -> Dict[str, Dict[str, str]]:
        with closing(self.get_connection()) as conn:
            cursor = conn.execute("SELECT user_id, reason, frozen_at, freeze_id, expires_at, initiated_by FROM freeze_states")
            return {
                row[0]: {
                    "reason": row[1], 
                    "frozen_at": row[2],
                    "freeze_id": row[3],
                    "expires_at": row[4],
                    "initiated_by": row[5]
                } 
                for row in cursor.fetchall()
            }

    # --- M4 Payloads ---
    def save_m4_payload(self, event_id: str, payload: Dict[str, Any], conn: Optional[sqlite3.Connection] = None):
        def _execute(c):
            c.execute("INSERT OR REPLACE INTO m4_payloads (event_id, payload_json) VALUES (?, ?)",
                      (event_id, json.dumps(payload)))
        if conn:
            _execute(conn)
        else:
            with closing(self.get_connection()) as c:
                with c:
                    _execute(c)

    def load_m4_payload(self, event_id: str) -> Optional[Dict[str, Any]]:
        with closing(self.get_connection()) as conn:
            cursor = conn.execute("SELECT payload_json FROM m4_payloads WHERE event_id = ?", (event_id,))
            row = cursor.fetchone()
            if row:
                return json.loads(row[0])
            return None

    def register_identity(self, identity_id: str, public_key_pem: str):
        with closing(self.get_connection()) as conn:
            with conn:
                conn.execute("INSERT OR REPLACE INTO identity_keys (identity_id, public_key_pem, is_revoked) VALUES (?, ?, 0)", 
                             (identity_id, public_key_pem))

    def get_public_key(self, identity_id: str) -> Optional[str]:
        with closing(self.get_connection()) as conn:
            cursor = conn.execute("SELECT public_key_pem, is_revoked FROM identity_keys WHERE identity_id = ?", (identity_id,))
            row = cursor.fetchone()
            if row:
                if row[1] == 1:
                    return "REVOKED"
                return row[0]
            return None

    # --- AI Jobs ---
    def save_ai_job(self, job_id: str, status: str, facts: Dict[str, Any], created_at: str, conn: Optional[sqlite3.Connection] = None):
        def _execute(c):
            c.execute("INSERT OR REPLACE INTO ai_jobs (job_id, status, facts_json, created_at) VALUES (?, ?, ?, ?)",
                      (job_id, status, json.dumps(facts), created_at))
        if conn:
            _execute(conn)
        else:
            with closing(self.get_connection()) as c:
                with c:
                    _execute(c)

    def update_ai_job_status(self, job_id: str, status: str, completed_at: Optional[str] = None):
        with closing(self.get_connection()) as conn:
            with conn:
                if completed_at:
                    conn.execute("UPDATE ai_jobs SET status = ?, completed_at = ? WHERE job_id = ?", (status, completed_at, job_id))
                else:
                    conn.execute("UPDATE ai_jobs SET status = ? WHERE job_id = ?", (status, job_id))

    def get_pending_ai_jobs(self) -> List[Dict[str, Any]]:
        with closing(self.get_connection()) as conn:
            cursor = conn.execute("SELECT job_id, facts_json, created_at FROM ai_jobs WHERE status = 'PENDING'")
            return [
                {
                    "job_id": row[0],
                    "facts": json.loads(row[1]),
                    "created_at": row[2]
                }
                for row in cursor.fetchall()
            ]

    # --- Admin Audit Logs ---
    def save_admin_audit_log(self, action: str, target: str, reason: str, timestamp: str):
        with closing(self.get_connection()) as conn:
            with conn:
                conn.execute("INSERT INTO admin_audit_logs (action, target, reason, timestamp) VALUES (?, ?, ?, ?)",
                             (action, target, reason, timestamp))

    # --- Replay Guard ---
    def save_replay_guard(self, event_id: str, nonce: str, timestamp: str, user_id: str, leaf_id: str, version: Optional[int], conn: Optional[sqlite3.Connection] = None):
        def _execute(c):
            c.execute("INSERT OR REPLACE INTO replay_guard_events (event_id, timestamp) VALUES (?, ?)", (event_id, timestamp))
            c.execute("INSERT OR REPLACE INTO replay_guard_nonces (nonce, timestamp) VALUES (?, ?)", (nonce, timestamp))
            if version is not None:
                c.execute("INSERT OR REPLACE INTO replay_guard_versions (user_id, leaf_id, version) VALUES (?, ?, ?)", (user_id, leaf_id, version))
        if conn:
            _execute(conn)
        else:
            with closing(self.get_connection()) as c:
                with c:
                    _execute(c)

    def delete_expired_replay_guard(self, expired_events: List[str], expired_nonces: List[str], conn: Optional[sqlite3.Connection] = None):
        def _execute(c):
            for eid in expired_events:
                c.execute("DELETE FROM replay_guard_events WHERE event_id = ?", (eid,))
            for n in expired_nonces:
                c.execute("DELETE FROM replay_guard_nonces WHERE nonce = ?", (n,))
        if conn:
            _execute(conn)
        else:
            with closing(self.get_connection()) as c:
                with c:
                    _execute(c)

    # --- Pending Uploads (S3 retry queue) ---
    def enqueue_pending_upload(self, op: str, meta: Dict[str, Any]) -> int:
        from datetime import datetime, timezone
        created_at = datetime.now(timezone.utc).isoformat()
        with closing(self.get_connection()) as conn:
            with conn:
                cursor = conn.execute(
                    "INSERT INTO pending_uploads (op, meta_json, created_at, attempts) VALUES (?, ?, ?, 0)",
                    (op, json.dumps(meta), created_at)
                )
                return cursor.lastrowid

    def get_pending_uploads(self) -> List[Dict[str, Any]]:
        with closing(self.get_connection()) as conn:
            cursor = conn.execute(
                "SELECT upload_id, op, meta_json, attempts FROM pending_uploads ORDER BY upload_id ASC"
            )
            return [
                {"upload_id": r[0], "op": r[1], "meta_json": r[2], "attempts": r[3]}
                for r in cursor.fetchall()
            ]

    def count_pending_uploads(self) -> int:
        with closing(self.get_connection()) as conn:
            cursor = conn.execute("SELECT COUNT(*) FROM pending_uploads")
            return cursor.fetchone()[0]

    def delete_pending_upload(self, upload_id: int) -> None:
        with closing(self.get_connection()) as conn:
            with conn:
                conn.execute("DELETE FROM pending_uploads WHERE upload_id = ?", (upload_id,))

    def increment_pending_attempt(self, upload_id: int) -> None:
        with closing(self.get_connection()) as conn:
            with conn:
                conn.execute("UPDATE pending_uploads SET attempts = attempts + 1 WHERE upload_id = ?", (upload_id,))

    # --- Review Queue (ML retrain labelling) ---
    def enqueue_review(self, event_id: str, model_label: str) -> None:
        from datetime import datetime, timezone
        ts = datetime.now(timezone.utc).isoformat()
        with closing(self.get_connection()) as conn:
            with conn:
                conn.execute(
                    "INSERT OR IGNORE INTO review_queue (event_id, model_label, ts) VALUES (?, ?, ?)",
                    (event_id, model_label, ts)
                )

    def get_review_queue(self, unlabelled_only: bool = False) -> List[Dict[str, Any]]:
        with closing(self.get_connection()) as conn:
            if unlabelled_only:
                cursor = conn.execute(
                    "SELECT id, event_id, model_label, human_label, reviewer, ts, fn_flag FROM review_queue WHERE human_label IS NULL ORDER BY id ASC"
                )
            else:
                cursor = conn.execute(
                    "SELECT id, event_id, model_label, human_label, reviewer, ts, fn_flag FROM review_queue ORDER BY id ASC"
                )
            cols = ["id", "event_id", "model_label", "human_label", "reviewer", "ts", "fn_flag"]
            return [dict(zip(cols, r)) for r in cursor.fetchall()]

    def label_review_item(self, item_id: int, human_label: str, reviewer: str, fn_flag: bool = False) -> None:
        from datetime import datetime, timezone
        ts = datetime.now(timezone.utc).isoformat()
        with closing(self.get_connection()) as conn:
            with conn:
                conn.execute(
                    "UPDATE review_queue SET human_label=?, reviewer=?, ts=?, fn_flag=? WHERE id=?",
                    (human_label, reviewer, ts, 1 if fn_flag else 0, item_id)
                )

    # --- Model Registry ---
    def register_model(self, version: str, metrics: Dict[str, Any], sha256: str) -> None:
        from datetime import datetime, timezone
        promoted_at = datetime.now(timezone.utc).isoformat()
        with closing(self.get_connection()) as conn:
            with conn:
                conn.execute("UPDATE model_registry SET is_active = 0")
                conn.execute(
                    "INSERT OR REPLACE INTO model_registry (version, metrics_json, sha256, promoted_at, is_active) VALUES (?, ?, ?, ?, 1)",
                    (version, json.dumps(metrics), sha256, promoted_at)
                )

    def get_model_registry(self) -> List[Dict[str, Any]]:
        with closing(self.get_connection()) as conn:
            cursor = conn.execute(
                "SELECT version, metrics_json, sha256, promoted_at, is_active FROM model_registry ORDER BY promoted_at DESC"
            )
            return [
                {"version": r[0], "metrics": json.loads(r[1]) if r[1] else {}, "sha256": r[2], "promoted_at": r[3], "is_active": bool(r[4])}
                for r in cursor.fetchall()
            ]

    def rollback_model(self, version: str) -> bool:
        with closing(self.get_connection()) as conn:
            with conn:
                cursor = conn.execute("SELECT version FROM model_registry WHERE version = ?", (version,))
                if not cursor.fetchone():
                    return False
                conn.execute("UPDATE model_registry SET is_active = 0")
                conn.execute("UPDATE model_registry SET is_active = 1 WHERE version = ?", (version,))
                return True

    # --- Daily Summaries ---
    def save_daily_summary(self, date: str, summary: Dict[str, Any]) -> None:
        from datetime import datetime, timezone
        created_at = datetime.now(timezone.utc).isoformat()
        with closing(self.get_connection()) as conn:
            with conn:
                conn.execute(
                    "INSERT OR REPLACE INTO daily_summaries (date, summary_json, created_at) VALUES (?, ?, ?)",
                    (date, json.dumps(summary), created_at)
                )

    def get_daily_summary(self, date: str) -> Optional[Dict[str, Any]]:
        with closing(self.get_connection()) as conn:
            cursor = conn.execute("SELECT summary_json FROM daily_summaries WHERE date = ?", (date,))
            row = cursor.fetchone()
            return json.loads(row[0]) if row else None

    def list_daily_summaries(self, from_date: str = None, to_date: str = None) -> List[Dict[str, Any]]:
        with closing(self.get_connection()) as conn:
            if from_date and to_date:
                cursor = conn.execute(
                    "SELECT date, summary_json, created_at FROM daily_summaries WHERE date >= ? AND date <= ? ORDER BY date ASC",
                    (from_date, to_date)
                )
            else:
                cursor = conn.execute("SELECT date, summary_json, created_at FROM daily_summaries ORDER BY date ASC")
            return [
                {"date": r[0], "summary": json.loads(r[1]), "created_at": r[2]}
                for r in cursor.fetchall()
            ]

    # --- Alerts ---
    def save_alert(self, alert_id: str, alert_type: str, severity: str,
                   details: Dict[str, Any], ai_explanation: str = None) -> None:
        from datetime import datetime, timezone
        created_at = datetime.now(timezone.utc).isoformat()
        with closing(self.get_connection()) as conn:
            with conn:
                conn.execute(
                    "INSERT OR REPLACE INTO alerts (alert_id, alert_type, severity, details_json, ai_explanation, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                    (alert_id, alert_type, severity, json.dumps(details), ai_explanation, created_at)
                )

    def get_alerts(self, unresolved_only: bool = False) -> List[Dict[str, Any]]:
        with closing(self.get_connection()) as conn:
            if unresolved_only:
                cursor = conn.execute(
                    "SELECT alert_id, alert_type, severity, details_json, ai_explanation, created_at, resolved FROM alerts WHERE resolved = 0 ORDER BY created_at DESC"
                )
            else:
                cursor = conn.execute(
                    "SELECT alert_id, alert_type, severity, details_json, ai_explanation, created_at, resolved FROM alerts ORDER BY created_at DESC"
                )
            cols = ["alert_id", "alert_type", "severity", "details", "ai_explanation", "created_at", "resolved"]
            result = []
            for r in cursor.fetchall():
                row = dict(zip(cols, r))
                if row["details"] and isinstance(row["details"], str):
                    try:
                        row["details"] = json.loads(row["details"])
                    except Exception:
                        pass
                result.append(row)
            return result

    def resolve_alert(self, alert_id: str) -> bool:
        with closing(self.get_connection()) as conn:
            with conn:
                cursor = conn.execute("UPDATE alerts SET resolved = 1 WHERE alert_id = ?", (alert_id,))
                return cursor.rowcount > 0
