import unittest
import json
import os
import time
from datetime import datetime, timezone, timedelta
import uuid
from unittest.mock import patch

from m3.api import create_m3_app
from m3.crypto_signer import generate_rsa_key_pair, sign_payload

class TestM3Hardening(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        pass

    def setUp(self):
        self.db_path = f"test_m3_hard_{uuid.uuid4().hex[:8]}.db"
        self.anchor_path = f"test_anchor_hard_{uuid.uuid4().hex[:8]}.log"
        if os.path.exists(self.db_path):
            try: os.remove(self.db_path)
            except: pass
        if os.path.exists(self.anchor_path):
            try: os.remove(self.anchor_path)
            except: pass
            
        self.app = create_m3_app(db_path=self.db_path, anchor_path=self.anchor_path)
        self.client = self.app.test_client()
        
        self.private_pem, self.public_pem = generate_rsa_key_pair()
        self.identity_id = "hard_user_1"
        
        # Register Identity
        self.client.post('/api/v1/identity/register', 
            json={"identity_id": self.identity_id, "public_key_pem": self.public_pem},
            headers=self._get_auth_header("ADMIN")
        )

    def tearDown(self):
        if os.path.exists(self.db_path):
            try: os.remove(self.db_path)
            except Exception: pass
        if os.path.exists(self.anchor_path):
            try: os.remove(self.anchor_path)
            except Exception: pass

    def _get_auth_header(self, role="ADMIN"):
        keys = {
            "ADMIN": "dev-admin-key",
            "SERVICE": "dev-service-key",
            "VIEWER": "dev-viewer-key"
        }
        return {"X-API-Key": keys.get(role)}

    def _base_payload(self):
        return {
            "user_id": self.identity_id,
            "leaf_id": "leaf_1",
            "event_id": f"evt_{uuid.uuid4().hex[:12]}",
            "nonce": uuid.uuid4().hex + uuid.uuid4().hex,
            "version": 1,
            "masked_pii_hash": "a" * 64,
            "real_data_hash": "b" * 64,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    # P0: Unauthorized Access
    def test_auth_no_key(self):
        payload = self._base_payload()
        resp = self.client.post('/api/v1/tree/update', json=payload)
        self.assertEqual(resp.status_code, 401)
        
    def test_auth_viewer_cannot_update(self):
        payload = self._base_payload()
        resp = self.client.post('/api/v1/tree/update', json=payload, headers=self._get_auth_header("VIEWER"))
        self.assertEqual(resp.status_code, 403)
        self.assertIn("Insufficient permissions", resp.json["error"])

    def test_auth_service_cannot_admin(self):
        resp = self.client.post('/api/v1/freeze', json={"target": "master"}, headers=self._get_auth_header("SERVICE"))
        self.assertEqual(resp.status_code, 403)

    # P0: Identity Edge Cases
    def test_unknown_identity(self):
        payload = self._base_payload()
        payload["user_id"] = "unknown_user"
        payload["signature_hex"] = sign_payload(self.private_pem, payload)
        
        resp = self.client.post('/api/v1/tree/update', json=payload, headers=self._get_auth_header("SERVICE"))
        self.assertEqual(resp.status_code, 401)
        self.assertIn("No public key registered", resp.json["error"])

    def test_revoked_identity(self):
        # Revoke the identity
        self.client.post('/api/v1/identity/revoke', json={"identity_id": self.identity_id}, headers=self._get_auth_header("ADMIN"))
        
        payload = self._base_payload()
        payload["signature_hex"] = sign_payload(self.private_pem, payload)
        
        resp = self.client.post('/api/v1/tree/update', json=payload, headers=self._get_auth_header("SERVICE"))
        self.assertEqual(resp.status_code, 401)
        self.assertIn("has been revoked", resp.json["error"])

    # P0: Timestamp Boundaries
    def test_stale_timestamp(self):
        payload = self._base_payload()
        past_time = datetime.now(timezone.utc) - timedelta(minutes=10)
        payload["timestamp"] = past_time.isoformat()
        payload["signature_hex"] = sign_payload(self.private_pem, payload)
        
        resp = self.client.post('/api/v1/tree/update', json=payload, headers=self._get_auth_header("SERVICE"))
        self.assertEqual(resp.status_code, 409)
        self.assertIn("Stale timestamp", resp.json["detail"])

    def test_future_timestamp(self):
        payload = self._base_payload()
        future_time = datetime.now(timezone.utc) + timedelta(minutes=5)
        payload["timestamp"] = future_time.isoformat()
        payload["signature_hex"] = sign_payload(self.private_pem, payload)
        
        resp = self.client.post('/api/v1/tree/update', json=payload, headers=self._get_auth_header("SERVICE"))
        self.assertEqual(resp.status_code, 409)
        self.assertIn("in the future", resp.json["detail"])

    def test_invalid_timestamp_format(self):
        payload = self._base_payload()
        payload["timestamp"] = "2023-10-10 10:10:10"
        payload["signature_hex"] = sign_payload(self.private_pem, payload)
        
        resp = self.client.post('/api/v1/tree/update', json=payload, headers=self._get_auth_header("SERVICE"))
        self.assertEqual(resp.status_code, 400)
        self.assertIn("valid ISO-8601 UTC string", resp.json["error"])

    # P0: Input Fuzzing
    def test_input_fuzzing(self):
        # Empty IDs
        p = self._base_payload()
        p["user_id"] = ""
        resp = self.client.post('/api/v1/tree/update', json=p, headers=self._get_auth_header("SERVICE"))
        self.assertEqual(resp.status_code, 400)
        
        # Too long IDs
        p = self._base_payload()
        p["leaf_id"] = "a" * 70
        resp = self.client.post('/api/v1/tree/update', json=p, headers=self._get_auth_header("SERVICE"))
        self.assertEqual(resp.status_code, 400)
        
        # Invalid Hex
        p = self._base_payload()
        p["masked_pii_hash"] = "z" * 64
        resp = self.client.post('/api/v1/tree/update', json=p, headers=self._get_auth_header("SERVICE"))
        self.assertEqual(resp.status_code, 400)

    # P0: Freeze Enforcement
    def test_freeze_enforcement(self):
        # Freeze user
        self.client.post('/api/v1/freeze', json={"target": "subtree", "user_id": self.identity_id}, headers=self._get_auth_header("ADMIN"))
        
        p = self._base_payload()
        p["signature_hex"] = sign_payload(self.private_pem, p)
        
        resp = self.client.post('/api/v1/tree/update', json=p, headers=self._get_auth_header("SERVICE"))
        self.assertEqual(resp.status_code, 403)
        self.assertIn("frozen", resp.json["error"])
        
        # Unfreeze user
        self.client.post('/api/v1/unfreeze', json={"target": "subtree", "user_id": self.identity_id}, headers=self._get_auth_header("ADMIN"))
        
        p = self._base_payload()
        p["event_id"] = f"evt_{uuid.uuid4().hex[:12]}"
        p["nonce"] = uuid.uuid4().hex
        p["signature_hex"] = sign_payload(self.private_pem, p)
        
        resp2 = self.client.post('/api/v1/tree/update', json=p, headers=self._get_auth_header("SERVICE"))
        self.assertEqual(resp2.status_code, 200)

    # P0: Database Rollback (Transaction atomicity)
    @patch('m3.database.M3Database.save_m4_payload')
    def test_database_rollback(self, mock_save_m4):
        # Force a failure at the last step of the transaction
        mock_save_m4.side_effect = Exception("Simulated DB failure")
        
        p = self._base_payload()
        p["signature_hex"] = sign_payload(self.private_pem, p)
        
        resp = self.client.post('/api/v1/tree/update', json=p, headers=self._get_auth_header("SERVICE"))
        self.assertEqual(resp.status_code, 500)
        
        # Ensure the merkle leaf wasn't committed
        r = self.client.get('/api/v1/tree/root', headers=self._get_auth_header("VIEWER"))
        self.assertEqual(r.json["total_user_subroots"], 0)
        
        # Ensure audit log is empty
        r2 = self.client.get('/api/v1/audit/logs', headers=self._get_auth_header("VIEWER"))
        self.assertEqual(r2.json["count"], 0)

    # P1: Concurrent Updates
    def test_concurrent_updates(self):
        import threading
        
        results = []
        def send_req():
            p = self._base_payload()
            p["leaf_id"] = "concurrent_leaf"
            p["event_id"] = f"evt_{uuid.uuid4().hex[:12]}"
            p["nonce"] = uuid.uuid4().hex
            p["version"] = 1
            p["signature_hex"] = sign_payload(self.private_pem, p)
            
            r = self.client.post('/api/v1/tree/update', json=p, headers=self._get_auth_header("SERVICE"))
            results.append(r.status_code)

        threads = [threading.Thread(target=send_req) for _ in range(5)]
        for t in threads: t.start()
        for t in threads: t.join()
        
        # Only ONE should succeed with 200, the rest should fail with 409 (version collision or SQLite lock timeout)
        success_count = results.count(200)
        self.assertEqual(success_count, 1)

    # P1: Audit-chain verification against tampering
    def test_audit_chain_tampering(self):
        p = self._base_payload()
        p["signature_hex"] = sign_payload(self.private_pem, p)
        self.client.post('/api/v1/tree/update', json=p, headers=self._get_auth_header("SERVICE"))
        
        # Tamper with the database manually
        import sqlite3
        conn = sqlite3.connect(self.db_path)
        conn.execute("UPDATE merkle_leaves SET real_data_hash = 't'*64 WHERE user_id = ?", (self.identity_id,))
        conn.commit()
        conn.close()
        
        verify_payload = {
            "user_id": self.identity_id,
            "leaf_id": "leaf_1",
            "masked_pii_hash": "a"*64,
            "real_data_hash": "t"*64
        }
        r = self.client.post('/api/v1/audit/verify', json=verify_payload, headers=self._get_auth_header("VIEWER"))
        self.assertEqual(r.status_code, 400)
        self.assertIn("hash recalculation mismatch", r.json["reason"])

if __name__ == '__main__':
    os.environ["M3_API_KEYS"] = json.dumps({
        "dev-admin-key": "ADMIN",
        "dev-service-key": "SERVICE",
        "dev-viewer-key": "VIEWER"
    })
    unittest.main()
