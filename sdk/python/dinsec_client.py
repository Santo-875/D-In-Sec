"""
sdk/python/dinsec_client.py — Official Python SDK for D-In-Sec M3 Sidecar.
"""

import os
import uuid
import hashlib
import requests
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List

class DinSecClient:
    """
    Client for interacting with the D-In-Sec M3 Sidecar.
    """

    def __init__(self, base_url: str = "http://127.0.0.1:5001", api_key: str = "dev-service-key", tenant_id: str = "default"):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.tenant_id = tenant_id

    def _headers(self, custom: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        headers = {
            "X-API-Key": self.api_key,
            "X-Tenant-ID": self.tenant_id,
            "Content-Type": "application/json"
        }
        if custom:
            headers.update(custom)
        return headers

    def is_alive(self) -> bool:
        """Liveness check (/healthz)."""
        try:
            r = requests.get(f"{self.base_url}/healthz", timeout=3)
            return r.status_code == 200
        except Exception:
            return False

    def is_ready(self) -> Dict[str, Any]:
        """Readiness check (/readyz)."""
        r = requests.get(f"{self.base_url}/readyz", headers=self._headers(), timeout=3)
        return r.json()

    def ingest_event(
        self,
        user_id: str,
        leaf_id: str,
        masked_pii: str,
        real_data: str,
        private_key_pem: str,
        version: int = 1
    ) -> Dict[str, Any]:
        """
        Signs and submits an event to /v1/events with deterministic Merkle insertion.
        """
        from m3.crypto_signer import sign_payload

        masked_pii_hash = hashlib.sha256(masked_pii.encode('utf-8')).hexdigest()
        real_data_hash = hashlib.sha256(real_data.encode('utf-8')).hexdigest()
        ts = datetime.now(timezone.utc).isoformat()
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
            "timestamp": ts
        }
        payload["signature_hex"] = sign_payload(private_key_pem, payload)

        r = requests.post(f"{self.base_url}/v1/events", json=payload, headers=self._headers(), timeout=5)
        return r.json()

    def classify_text(self, text: str) -> Dict[str, Any]:
        """Runs fast AI classification on raw event text via /v1/events."""
        r = requests.post(f"{self.base_url}/v1/events", json={"text": text}, headers=self._headers(), timeout=5)
        return r.json()

    def verify_audit_chain(self, user_id: str, leaf_id: str, masked_pii_hash: str, real_data_hash: str) -> Dict[str, Any]:
        """Verifies leaf hash, Merkle path, and storage anchor match."""
        req_body = {
            "user_id": user_id,
            "leaf_id": leaf_id,
            "masked_pii_hash": masked_pii_hash,
            "real_data_hash": real_data_hash
        }
        r = requests.post(f"{self.base_url}/audit/verify", json=req_body, headers=self._headers(), timeout=5)
        return r.json()

    def full_verify(self) -> Dict[str, Any]:
        """Executes full Merkle tree verification against latest S3 anchor."""
        r = requests.get(f"{self.base_url}/v1/verify/full", headers=self._headers(), timeout=10)
        return r.json()

    def trigger_anchor(self) -> Dict[str, Any]:
        """Triggers manual signed root checkpoint anchor to storage."""
        r = requests.post(f"{self.base_url}/v1/admin/anchor", headers=self._headers(), timeout=5)
        return r.json()

    def get_alerts(self, unresolved_only: bool = False) -> List[Dict[str, Any]]:
        """Retrieves tamper and security alerts."""
        params = {"unresolved": "true"} if unresolved_only else {}
        r = requests.get(f"{self.base_url}/v1/alerts", params=params, headers=self._headers(), timeout=5)
        return r.json().get("alerts", [])

    def export_certin_bundle(self, from_date: str = "", to_date: str = "") -> Dict[str, Any]:
        """Fetches CERT-In compliance export bundle."""
        params = {}
        if from_date: params["from"] = from_date
        if to_date: params["to"] = to_date
        r = requests.get(f"{self.base_url}/v1/export/certin", params=params, headers=self._headers(), timeout=10)
        return r.json()
