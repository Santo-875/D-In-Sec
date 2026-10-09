"""
M3 Client for Mock Site (Module 1).
Provides cryptographic log / document anchoring to Module 3 Hierarchical Merkle Tree.
"""

import os
import uuid
import logging
from datetime import datetime, timezone
import requests

try:
    from m3.crypto_signer import (
        sign_payload,
        load_private_key_from_env,
        get_public_key_from_private_pem,
    )
except ImportError:
    sign_payload = None
    load_private_key_from_env = None
    get_public_key_from_private_pem = None

logger = logging.getLogger("mock_site.m3_client")

_registered_identities = set()


def _get_api_urls():
    m3_url = os.environ.get("M3_API_URL", "http://127.0.0.1:5001/api/v1/tree/update")
    if "/tree/update" in m3_url:
        base_url = m3_url.rsplit("/api/v1/tree/update", 1)[0].rsplit("/tree/update", 1)[0]
    else:
        base_url = m3_url.rstrip("/")
        m3_url = f"{base_url}/api/v1/tree/update"
    register_url = f"{base_url}/api/v1/identity/register"
    return m3_url, register_url


def _register_identity_if_needed(user_id: str, private_key_pem: str, admin_key: str, register_url: str) -> bool:
    if user_id in _registered_identities:
        return True
    try:
        pub_pem = get_public_key_from_private_pem(private_key_pem)
        resp = requests.post(
            register_url,
            json={"identity_id": user_id, "public_key_pem": pub_pem},
            headers={"X-API-Key": admin_key},
            timeout=3.0,
        )
        if resp.status_code in (200, 201):
            _registered_identities.add(user_id)
            return True
        else:
            logger.warning(
                "M3 identity registration for %s returned HTTP %d: %s",
                user_id, resp.status_code, resp.text[:100]
            )
            return False
    except Exception as e:
        logger.warning("Failed to register identity with M3 (%s): %s", user_id, e)
        return False


def push_leaf(user_id: str, leaf_id: str, masked_pii_hash: str, real_data_hash: str, version: int = 1) -> bool:
    """
    Signs and pushes a leaf to M3 Hierarchical Merkle Tree.
    Returns True on success, False otherwise. Never raises exceptions.
    """
    try:
        if not sign_payload or not load_private_key_from_env or not get_public_key_from_private_pem:
            logger.warning("m3.crypto_signer not available; skipping M3 leaf push.")
            return False

        private_key_pem = load_private_key_from_env("M3_SIGNING_PRIVATE_KEY")
        if not private_key_pem:
            logger.warning("M3_SIGNING_PRIVATE_KEY not configured; skipping M3 leaf push.")
            return False

        admin_key = os.environ.get("M3_ADMIN_API_KEY")
        service_key = os.environ.get("M3_SERVICE_API_KEY")
        if not admin_key or not service_key:
            logger.warning("M3_ADMIN_API_KEY or M3_SERVICE_API_KEY not configured; skipping M3 leaf push.")
            return False

        m3_url, register_url = _get_api_urls()

        # Register identity once per user_id
        if not _register_identity_if_needed(user_id, private_key_pem, admin_key, register_url):
            return False

        timestamp = datetime.now(timezone.utc).isoformat()
        event_id = f"evt_{uuid.uuid4().hex[:12]}"
        nonce = uuid.uuid4().hex + uuid.uuid4().hex

        payload = {
            "user_id": user_id,
            "leaf_id": leaf_id,
            "event_id": event_id,
            "nonce": nonce,
            "version": version,
            "masked_pii_hash": masked_pii_hash,
            "real_data_hash": real_data_hash,
            "timestamp": timestamp,
        }

        signature_hex = sign_payload(private_key_pem, payload)

        request_body = {
            **payload,
            "signature_hex": signature_hex,
        }

        response = requests.post(
            m3_url,
            json=request_body,
            headers={"X-API-Key": service_key},
            timeout=3.0,
        )

        if response.status_code == 200:
            return True
        else:
            logger.warning(
                "M3 leaf update returned HTTP %d: %s",
                response.status_code, response.text[:200]
            )
            return False
    except Exception as e:
        logger.warning("Failed to push leaf to M3: %s", e)
        return False
