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
                        registered_at TEXT NOT NULL
                    )
                ''')
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
            conn.commit()

    # --- Identity Keys ---
    def save_identity_key(self, identity_id: str, public_key_pem: str, fingerprint: str, registered_at: str):
        with closing(self.get_connection()) as conn:
            with conn:
                conn.execute(
                    "INSERT OR REPLACE INTO identity_keys (identity_id, public_key_pem, fingerprint, registered_at) VALUES (?, ?, ?, ?)",
                    (identity_id, public_key_pem, fingerprint, registered_at)
                )

    def load_identity_keys(self) -> Dict[str, Dict[str, str]]:
        with closing(self.get_connection()) as conn:
            cursor = conn.execute("SELECT identity_id, public_key_pem, fingerprint, registered_at FROM identity_keys")
            return {
                row[0]: {"public_key_pem": row[1], "fingerprint": row[2], "registered_at": row[3]}
                for row in cursor.fetchall()
            }

    # --- Merkle Leaves ---
    def save_merkle_leaf(self, user_id: str, leaf_id: str, masked_pii_hash: str, real_data_hash: str, combined_hash: str, timestamp: str, version: int):
        with closing(self.get_connection()) as conn:
            with conn:
                conn.execute(
                    """INSERT OR REPLACE INTO merkle_leaves 
                       (user_id, leaf_id, masked_pii_hash, real_data_hash, combined_hash, timestamp, version) 
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (user_id, leaf_id, masked_pii_hash, real_data_hash, combined_hash, timestamp, version)
                )

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
    def save_audit_event(self, entry: Dict[str, Any]):
        with closing(self.get_connection()) as conn:
            with conn:
                conn.execute(
                    """INSERT INTO audit_events 
                       (event_id, timestamp, user_id, leaf_id, old_leaf_hash, new_leaf_hash, old_master_root, new_master_root, signature_hex, signer_fingerprint, previous_hash, event_hash)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (entry["event_id"], entry["timestamp"], entry["user_id"], entry["leaf_id"], entry.get("old_leaf_hash"),
                     entry["new_leaf_hash"], entry["old_master_root"], entry["new_master_root"], entry["signature_hex"],
                     entry["signer_fingerprint"], entry.get("previous_hash"), entry["event_hash"])
                )

    def load_audit_events(self) -> List[Dict[str, Any]]:
        with closing(self.get_connection()) as conn:
            cursor = conn.execute("SELECT * FROM audit_events ORDER BY timestamp ASC")
            cols = [desc[0] for desc in cursor.description]
            return [dict(zip(cols, row)) for row in cursor.fetchall()]

    # --- Checkpoints ---
    def save_checkpoint(self, checkpoint: Dict[str, Any]):
        with closing(self.get_connection()) as conn:
            with conn:
                conn.execute(
                    """INSERT INTO root_checkpoints (event_id, timestamp, master_root, user_id, previous_hash, checkpoint_hash)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (checkpoint["event_id"], checkpoint["timestamp"], checkpoint["master_root"], checkpoint["user_id"],
                     checkpoint.get("previous_hash"), checkpoint["checkpoint_hash"])
                )

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
    def save_m4_payload(self, event_id: str, payload: Dict[str, Any]):
        with closing(self.get_connection()) as conn:
            with conn:
                conn.execute("INSERT OR REPLACE INTO m4_payloads (event_id, payload_json) VALUES (?, ?)",
                             (event_id, json.dumps(payload)))

    def load_m4_payload(self, event_id: str) -> Optional[Dict[str, Any]]:
        with closing(self.get_connection()) as conn:
            cursor = conn.execute("SELECT payload_json FROM m4_payloads WHERE event_id = ?", (event_id,))
            row = cursor.fetchone()
            if row:
                return json.loads(row[0])
            return None
