"""
Cryptographic Identity & Signature Engine for Module 3 (M3).

Provides RSA-2048 digital signature generation, verification,
key pair creation, and public key registry management.
"""

import hashlib
import json
import os
from typing import Any

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def generate_rsa_key_pair() -> tuple[str, str]:
    """
    Generates a new RSA-2048 key pair in PEM format.

    Returns:
        Tuple[str, str]: (private_key_pem, public_key_pem)
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    return private_pem, public_pem


def canonicalize_payload(payload: dict[str, Any]) -> bytes:
    """
    Deterministically serializes a payload dictionary to bytes.

    Args:
        payload (Dict[str, Any]): Dictionary to serialize.

    Returns:
        bytes: Canonical JSON byte representation.
    """
    return json.dumps(payload, sort_keys=True, separators=(',', ':')).encode('utf-8')


def get_public_key_fingerprint(public_key_pem: str) -> str:
    """
    Computes SHA-256 fingerprint of a public key PEM string.

    Args:
        public_key_pem (str): Public key in PEM format.

    Returns:
        str: SHA-256 fingerprint hex string.
    """
    clean_pem = public_key_pem.strip().encode('utf-8')
    return hashlib.sha256(clean_pem).hexdigest()


def sign_payload(private_key_pem: str, payload: dict[str, Any]) -> str:
    """
    Signs a dictionary payload using an RSA private key with SHA-256 & PKCS1v15 padding.

    Args:
        private_key_pem (str): RSA private key in PEM format.
        payload (Dict[str, Any]): Payload dictionary.

    Returns:
        str: Signature as a hex-encoded string.
    """
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode('utf-8'),
        password=None,
        backend=default_backend()
    )

    canonical_data = canonicalize_payload(payload)

    signature = private_key.sign(
        canonical_data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    return signature.hex()


def load_private_key_from_env(var_name: str = "M3_SIGNING_PRIVATE_KEY") -> str | None:
    """
    Loads an RSA private key in PEM format strictly from an environment variable.
    Kept in memory only — never read from or written to a file.
    Supports both standard multiline PEM strings and single-line PEMs with literal \\n characters.

    Args:
        var_name (str): Environment variable name. Defaults to 'M3_SIGNING_PRIVATE_KEY'.

    Returns:
        Optional[str]: Cleaned PEM string if found, None otherwise.
    """
    raw_key = os.environ.get(var_name)
    if not raw_key:
        return None

    cleaned_key = raw_key.strip()
    if "\\n" in cleaned_key:
        cleaned_key = cleaned_key.replace("\\n", "\n")

    return cleaned_key.strip()


def get_public_key_from_private_pem(private_key_pem: str) -> str:
    """
    Derives the corresponding RSA public key in PEM format directly from an
    in-memory private key PEM string. Operates strictly in memory without disk I/O.

    Args:
        private_key_pem (str): RSA private key in PEM format.

    Returns:
        str: RSA public key in PEM format.
    """
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode('utf-8'),
        password=None,
        backend=default_backend()
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    return public_pem


def verify_signature(public_key_pem: str, payload: dict[str, Any], signature_hex: str) -> bool:
    """
    Verifies an RSA signature against a payload using a public key.

    Args:
        public_key_pem (str): RSA public key in PEM format.
        payload (Dict[str, Any]): Payload dictionary.
        signature_hex (str): Hex-encoded signature.

    Returns:
        bool: True if valid, False otherwise.
    """
    try:
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode('utf-8'),
            backend=default_backend()
        )

        canonical_data = canonicalize_payload(payload)
        signature_bytes = bytes.fromhex(signature_hex)

        public_key.verify(
            signature_bytes,
            canonical_data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


class PublicKeyRegistry:
    """
    Registry for authorized user and developer public keys.
    Synchronizes state to an M3Database instance if provided.
    """

    def __init__(self, db=None):
        # Maps user_id -> public_key_pem
        self._user_keys: dict[str, str] = {}
        # Maps fingerprint -> user_id
        self._fingerprint_map: dict[str, str] = {}
        self.db = db
        
        if self.db:
            self._load_from_db()

    def _load_from_db(self):
        keys = self.db.load_identity_keys()
        for identity_id, data in keys.items():
            if data.get("is_revoked", False):
                self._user_keys[identity_id] = "REVOKED"
                # If they are revoked, they should not map fingerprint back
            else:
                self._user_keys[identity_id] = data["public_key_pem"]
                self._fingerprint_map[data["fingerprint"]] = identity_id

    def register_key(self, identity_id: str, public_key_pem: str) -> str:
        """
        Registers a public key for a user/developer identity.

        Args:
            identity_id (str): User ID or Developer ID.
            public_key_pem (str): Public key in PEM format.

        Returns:
            str: SHA-256 fingerprint of the key.
        """
        fingerprint = get_public_key_fingerprint(public_key_pem)
        self._user_keys[identity_id] = public_key_pem
        self._fingerprint_map[fingerprint] = identity_id
        
        if self.db:
            from datetime import datetime, timezone
            registered_at = datetime.now(timezone.utc).isoformat()
            self.db.save_identity_key(identity_id, public_key_pem, fingerprint, registered_at)
            
        return fingerprint

    def get_public_key(self, identity_id: str) -> str | None:
        """
        Retrieves public key PEM for a given identity.
        """
        return self._user_keys.get(identity_id)

    def is_registered(self, identity_id: str) -> bool:
        """
        Checks if identity has a registered public key.
        """
        return identity_id in self._user_keys

    def get_identity_by_fingerprint(self, fingerprint: str) -> str | None:
        """
        Finds identity ID associated with key fingerprint.
        """
        return self._fingerprint_map.get(fingerprint)
