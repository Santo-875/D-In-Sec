"""
vault/token_manager.py — Token storage and enforcement.
Manages the mapping: token_id → encrypted blob + ownership metadata.
Uses a SEPARATE vault.db SQLite database — never touches the main app DB.
"""

import os
import uuid
import sqlite3
from datetime import datetime, timezone, timedelta
from vault.crypto import encrypt, decrypt

# Separate SQLite DB for the vault — never mixed with app data
_VAULT_DB = os.path.join(os.path.dirname(__file__), 'vault.db')

# Default token TTL (no expiry for project scope — set to 10 years)
_DEFAULT_TTL_DAYS = 3650
# Max usages per token (0 = unlimited)
_DEFAULT_MAX_USAGE = 0


def _get_conn():
    conn = sqlite3.connect(_VAULT_DB)
    conn.row_factory = sqlite3.Row
    return conn


def _init_db():
    """Create the vault tokens table if it doesn't exist."""
    with _get_conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS vault_tokens (
                token_id    TEXT PRIMARY KEY,
                owner_id    INTEGER NOT NULL,
                purpose     TEXT NOT NULL,
                blob        BLOB NOT NULL,
                created_at  TEXT NOT NULL,
                expires_at  TEXT NOT NULL,
                usage_count INTEGER NOT NULL DEFAULT 0,
                max_usage   INTEGER NOT NULL DEFAULT 0
            )
        """)
        conn.commit()


_init_db()


def store(owner_id: int, purpose: str, data: dict) -> str:
    """
    Encrypt 'data' and store it in the vault.
    Returns the token_id (UUID) that references this record.
    """
    token_id = uuid.uuid4().hex
    blob = encrypt(data)
    now = datetime.now(timezone.utc)
    expires = now + timedelta(days=_DEFAULT_TTL_DAYS)

    with _get_conn() as conn:
        conn.execute("""
            INSERT INTO vault_tokens
                (token_id, owner_id, purpose, blob, created_at, expires_at, usage_count, max_usage)
            VALUES (?, ?, ?, ?, ?, ?, 0, ?)
        """, (
            token_id,
            owner_id,
            purpose,
            blob,
            now.isoformat(),
            expires.isoformat(),
            _DEFAULT_MAX_USAGE,
        ))
        conn.commit()

    return token_id


def retrieve(token_id: str, requesting_user_id: int) -> dict:
    """
    Retrieve and decrypt vault data.
    Enforces: ownership check, expiry check, usage limit check.
    Raises VaultAccessError on any violation.
    """
    with _get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM vault_tokens WHERE token_id = ?", (token_id,)
        ).fetchone()

    if not row:
        raise VaultAccessError("TOKEN_NOT_FOUND")

    if row['owner_id'] != requesting_user_id:
        raise VaultAccessError("UNAUTHORIZED_OWNER")

    expires_at = datetime.fromisoformat(row['expires_at'])
    if datetime.now(timezone.utc) > expires_at:
        raise VaultAccessError("TOKEN_EXPIRED")

    max_usage = row['max_usage']
    if max_usage > 0 and row['usage_count'] >= max_usage:
        raise VaultAccessError("USAGE_LIMIT_EXCEEDED")

    # Increment usage count
    with _get_conn() as conn:
        conn.execute(
            "UPDATE vault_tokens SET usage_count = usage_count + 1 WHERE token_id = ?",
            (token_id,)
        )
        conn.commit()

    return decrypt(row['blob'])


def update(token_id: str, owner_id: int, new_data: dict):
    """
    Re-encrypt and update an existing token's data.
    Only the owner can update their token.
    """
    with _get_conn() as conn:
        row = conn.execute(
            "SELECT owner_id FROM vault_tokens WHERE token_id = ?", (token_id,)
        ).fetchone()

    if not row:
        raise VaultAccessError("TOKEN_NOT_FOUND")
    if row['owner_id'] != owner_id:
        raise VaultAccessError("UNAUTHORIZED_OWNER")

    blob = encrypt(new_data)
    with _get_conn() as conn:
        conn.execute(
            "UPDATE vault_tokens SET blob = ? WHERE token_id = ?",
            (blob, token_id)
        )
        conn.commit()


class VaultAccessError(Exception):
    """Raised when vault access is denied for any reason."""
    pass
