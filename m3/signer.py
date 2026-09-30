"""
m3/signer.py — Signer abstraction for Module 3.

Provides a uniform Signer interface with two backends:
  - LocalRSASigner: Uses the existing RSA private key from env (dev/CI).
  - KMSSigner:      Delegates signing to AWS KMS (RSASSA_PSS_SHA_256).
                    Public key is cached in memory; private key never on disk.

Env:
    SIGNER_BACKEND   = local | kms   (default: local)
    KMS_KEY_ID       = <key id or alias/...>
    AWS_REGION       = <region>
    M3_SIGNING_PRIVATE_KEY = <PEM> (required for local backend)
"""

import os
import base64
import hashlib
import json
import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

logger = logging.getLogger("m3.signer")


class Signer(ABC):
    """Uniform signing interface. Implementations must never log private key material."""

    @abstractmethod
    def sign(self, payload: Dict[str, Any]) -> str:
        """
        Sign a dictionary payload. Returns hex-encoded signature.
        Raises RuntimeError if signing fails.
        """

    @property
    @abstractmethod
    def public_key_pem(self) -> str:
        """Return the public key in PEM format (cached)."""

    @property
    def fingerprint(self) -> str:
        """SHA-256 fingerprint of the public key PEM."""
        pem_bytes = self.public_key_pem.strip().encode("utf-8")
        return hashlib.sha256(pem_bytes).hexdigest()


# ── Local RSA Signer (existing logic, wrapped) ───────────────────────────────

class LocalRSASigner(Signer):
    """
    Signs using the RSA-2048 private key loaded from M3_SIGNING_PRIVATE_KEY env var.
    Compatible with the existing crypto_signer.sign_payload() PKCS1v15/SHA-256 scheme.
    Private key is kept in memory only — never written to disk or logged.
    """

    def __init__(self, private_key_pem: Optional[str] = None):
        if private_key_pem is None:
            from m3.crypto_signer import load_private_key_from_env
            private_key_pem = load_private_key_from_env()
        if not private_key_pem:
            from m3.crypto_signer import generate_rsa_key_pair
            private_key_pem, _ = generate_rsa_key_pair()
        self._private_key_pem = private_key_pem
        # Derive and cache public key
        from m3.crypto_signer import get_public_key_from_private_pem
        self._public_key_pem = get_public_key_from_private_pem(private_key_pem)

    def sign(self, payload: Dict[str, Any]) -> str:
        from m3.crypto_signer import sign_payload
        return sign_payload(self._private_key_pem, payload)

    @property
    def public_key_pem(self) -> str:
        return self._public_key_pem


# ── KMS Signer ───────────────────────────────────────────────────────────────

class KMSSigner(Signer):
    """
    Delegates signing to AWS KMS using RSASSA_PSS_SHA_256.
    The public key is fetched once and cached; the private key never leaves KMS.

    Produces a hex-encoded signature from the KMS DER-encoded response.
    Callers that need to verify against this signature must use RSA-PSS/SHA-256.
    """

    def __init__(self, key_id: str, region: str):
        import boto3
        self._key_id = key_id
        self._kms = boto3.client("kms", region_name=region)
        self._cached_public_key: Optional[str] = None

    @property
    def public_key_pem(self) -> str:
        if self._cached_public_key is None:
            self._cached_public_key = self._fetch_public_key()
        return self._cached_public_key

    def _fetch_public_key(self) -> str:
        """Fetch DER public key from KMS and convert to PEM."""
        from cryptography.hazmat.primitives.serialization import (
            Encoding, PublicFormat, load_der_public_key
        )
        resp = self._kms.get_public_key(KeyId=self._key_id)
        der_bytes = resp["PublicKey"]
        pub_key = load_der_public_key(der_bytes)
        return pub_key.public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")

    def sign(self, payload: Dict[str, Any]) -> str:
        """
        Signs the canonical JSON of payload with KMS RSASSA_PSS_SHA_256.
        Returns a hex-encoded signature string.
        Private key never leaves KMS.
        """
        from m3.crypto_signer import canonicalize_payload
        import hashlib as _hl
        message = canonicalize_payload(payload)
        # KMS requires raw message digest for SHA_256 signing
        digest = _hl.sha256(message).digest()
        try:
            resp = self._kms.sign(
                KeyId=self._key_id,
                Message=digest,
                MessageType="DIGEST",
                SigningAlgorithm="RSASSA_PSS_SHA_256",
            )
            return resp["Signature"].hex()
        except Exception as exc:
            logger.error("KMS sign failed: %s", exc)
            raise RuntimeError(f"KMS signing failed: {exc}") from exc


# ── Factory ──────────────────────────────────────────────────────────────────

def get_signer() -> Signer:
    """
    Returns the configured Signer based on SIGNER_BACKEND env var.
      SIGNER_BACKEND=local  → LocalRSASigner (default)
      SIGNER_BACKEND=kms    → KMSSigner
    """
    backend = os.environ.get("SIGNER_BACKEND", "local").lower()
    if backend == "kms":
        key_id = os.environ.get("KMS_KEY_ID", "")
        region = os.environ.get("AWS_REGION", "ap-south-1")
        if not key_id:
            raise RuntimeError("SIGNER_BACKEND=kms but KMS_KEY_ID is not set.")
        return KMSSigner(key_id=key_id, region=region)
    return LocalRSASigner()
