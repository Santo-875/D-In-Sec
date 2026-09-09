"""
vault/crypto.py — Fernet AES-128 encryption/decryption.
Handles the raw encrypt/decrypt layer. No other file should call this directly
except token_manager.py.
"""

import os
import json
from cryptography.fernet import Fernet

# Key file location — MUST be in .gitignore
_KEY_FILE = os.path.join(os.path.dirname(__file__), 'vault.key')


def _load_or_create_key() -> bytes:
    """
    Load the Fernet key from the VAULT_ENCRYPTION_KEY environment variable if present.
    Otherwise, fall back to the existing vault.key file on disk or create one.
    """
    env_key = os.environ.get('VAULT_ENCRYPTION_KEY')
    if env_key:
        return env_key.strip().encode('utf-8')
    if os.path.exists(_KEY_FILE):
        with open(_KEY_FILE, 'rb') as f:
            return f.read()
    key = Fernet.generate_key()
    try:
        with open(_KEY_FILE, 'wb') as f:
            f.write(key)
    except OSError:
        pass
    return key


_fernet = Fernet(_load_or_create_key())


def encrypt(data: dict) -> bytes:
    """Serialize a dict to JSON and encrypt it. Returns ciphertext bytes."""
    plaintext = json.dumps(data).encode('utf-8')
    return _fernet.encrypt(plaintext)


def decrypt(blob: bytes) -> dict:
    """Decrypt ciphertext bytes and return the original dict."""
    plaintext = _fernet.decrypt(blob)
    return json.loads(plaintext.decode('utf-8'))
