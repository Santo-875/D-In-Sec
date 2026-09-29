import unittest
import json
import os
import time
import shutil
from datetime import datetime, timezone
import uuid

# We will test the API endpoints using Flask's test client
from m3.api import create_m3_app
from m3.database import M3Database
from m3.crypto_signer import generate_rsa_key_pair, get_public_key_fingerprint, sign_payload

class TestM3E2E(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.db_path = f"test_m3_e2e_{uuid.uuid4().hex[:8]}.db"
        cls.anchor_path = f"test_anchor_e2e_{uuid.uuid4().hex[:8]}.log"

    def setUp(self):
        # Ensure fresh state
        if os.path.exists(self.db_path):
            try: os.remove(self.db_path)
            except: pass
        if os.path.exists(self.anchor_path):
            try: os.remove(self.anchor_path)
            except: pass
            
        self.app = create_m3_app(db_path=self.db_path, anchor_path=self.anchor_path)
        self.client = self.app.test_client()
        
        # Setup test keys
        self.private_pem, self.public_pem = generate_rsa_key_pair()
        self.identity_id = "test_user_123"
        
        # Register Identity (ADMIN)
        resp = self.client.post('/api/v1/identity/register', 
            json={"identity_id": self.identity_id, "public_key_pem": self.public_pem},
            headers={"X-API-Key": self._get_auth_header("ADMIN")["X-API-Key"]}
        )

    def tearDown(self):
        # Clean up test DBs, ignore if locked
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

    def test_1_normal_update(self):
        # Test 1 - Normal update
        payload = {
            "user_id": self.identity_id,
            "leaf_id": "record_001",
            "event_id": f"evt_{uuid.uuid4().hex[:12]}",
            "nonce": uuid.uuid4().hex + uuid.uuid4().hex,
            "version": 1,
            "masked_pii_hash": "a" * 64,
            "real_data_hash": "b" * 64,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        sig = sign_payload(self.private_pem, payload)
        payload["signature_hex"] = sig

        resp = self.client.post('/api/v1/tree/update', json=payload, headers=self._get_auth_header("SERVICE"))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json["status"], "SUCCESS")

    def test_2_wrong_signature(self):
        # Test 2 - Wrong signature
        payload = {
            "user_id": self.identity_id,
            "leaf_id": "record_002",
            "event_id": f"evt_{uuid.uuid4().hex[:12]}",
            "nonce": uuid.uuid4().hex + uuid.uuid4().hex,
            "version": 1,
            "masked_pii_hash": "a" * 64,
            "real_data_hash": "b" * 64,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        # Sign with a different key
        wrong_priv, _ = generate_rsa_key_pair()
        sig = sign_payload(wrong_priv, payload)
        payload["signature_hex"] = sig

        resp = self.client.post('/api/v1/tree/update', json=payload, headers=self._get_auth_header("SERVICE"))
        self.assertEqual(resp.status_code, 401)
        self.assertIn("Invalid signature", resp.json["error"])

    def test_3_replay_attack(self):
        # Test 3 - Replay
        payload = {
            "user_id": self.identity_id,
            "leaf_id": "record_003",
            "event_id": f"evt_{uuid.uuid4().hex[:12]}",
            "nonce": uuid.uuid4().hex + uuid.uuid4().hex,
            "version": 1,
            "masked_pii_hash": "a" * 64,
            "real_data_hash": "b" * 64,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        sig = sign_payload(self.private_pem, payload)
        payload["signature_hex"] = sig

        resp1 = self.client.post('/api/v1/tree/update', json=payload, headers=self._get_auth_header("SERVICE"))
        self.assertEqual(resp1.status_code, 200)

        # Send identical request again
        resp2 = self.client.post('/api/v1/tree/update', json=payload, headers=self._get_auth_header("SERVICE"))
        self.assertEqual(resp2.status_code, 409)
        self.assertIn("Replay attack detected", resp2.json["error"])

    def test_4_changed_event_id(self):
        # Test 4 - Same signed data, changed event ID
        payload = {
            "user_id": self.identity_id,
            "leaf_id": "record_004",
            "event_id": f"evt_{uuid.uuid4().hex[:12]}",
            "nonce": uuid.uuid4().hex + uuid.uuid4().hex,
            "version": 1,
            "masked_pii_hash": "a" * 64,
            "real_data_hash": "b" * 64,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        sig = sign_payload(self.private_pem, payload)
        
        # Tamper with event ID after signing
        payload["event_id"] = f"evt_{uuid.uuid4().hex[:12]}"
        payload["signature_hex"] = sig

        resp = self.client.post('/api/v1/tree/update', json=payload, headers=self._get_auth_header("SERVICE"))
        self.assertEqual(resp.status_code, 401)
        self.assertIn("Invalid signature", resp.json["error"])

    def test_5_version_checks(self):
        # Test 5 - Version progression and rejection
        leaf_id = "record_005"
        
        def send_update(version):
            payload = {
                "user_id": self.identity_id,
                "leaf_id": leaf_id,
                "event_id": f"evt_{uuid.uuid4().hex[:12]}",
                "nonce": uuid.uuid4().hex + uuid.uuid4().hex,
                "version": version,
                "masked_pii_hash": "a" * 64,
                "real_data_hash": "b" * 64,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            payload["signature_hex"] = sign_payload(self.private_pem, payload)
            return self.client.post('/api/v1/tree/update', json=payload, headers=self._get_auth_header("SERVICE"))
            
        # v1 -> SUCCESS
        r1 = send_update(1)
        self.assertEqual(r1.status_code, 200)
        
        # v2 -> SUCCESS
        r2 = send_update(2)
        self.assertEqual(r2.status_code, 200)
        
        # v2 again -> REJECT
        r3 = send_update(2)
        self.assertEqual(r3.status_code, 409)
        
        # v1 -> REJECT
        r4 = send_update(1)
        self.assertEqual(r4.status_code, 409)
        
        # v3 -> SUCCESS
        r5 = send_update(3)
        self.assertEqual(r5.status_code, 200)

    def test_6_tampering_detection(self):
        # Test 6 - Tampering
        # Insert valid record
        payload = {
            "user_id": self.identity_id,
            "leaf_id": "record_006",
            "event_id": f"evt_{uuid.uuid4().hex[:12]}",
            "nonce": uuid.uuid4().hex + uuid.uuid4().hex,
            "version": 1,
            "masked_pii_hash": "a" * 64,
            "real_data_hash": "b" * 64,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        payload["signature_hex"] = sign_payload(self.private_pem, payload)
        r1 = self.client.post('/api/v1/tree/update', json=payload, headers=self._get_auth_header("SERVICE"))
        self.assertEqual(r1.status_code, 200)
        
        # Verify valid record
        verify_payload = {
            "user_id": self.identity_id,
            "leaf_id": "record_006",
            "masked_pii_hash": "a" * 64,
            "real_data_hash": "b" * 64
        }
        r2 = self.client.post('/api/v1/tree/verify-leaf', json=verify_payload, headers=self._get_auth_header("VIEWER"))
        self.assertEqual(r2.status_code, 200)
        self.assertTrue(r2.json["integrity_verified"])
        
        # Verify tampered record
        verify_payload["real_data_hash"] = "c" * 64
        r3 = self.client.post('/api/v1/tree/verify-leaf', json=verify_payload, headers=self._get_auth_header("VIEWER"))
        self.assertEqual(r3.status_code, 200)
        self.assertFalse(r3.json["integrity_verified"])
        self.assertTrue(r3.json["tamper_detected"])

    def test_7_restart_consistency(self):
        # Test 7 - Restart
        # 1. Add some records
        for i in range(3):
            payload = {
                "user_id": self.identity_id,
                "leaf_id": f"record_restart_{i}",
                "event_id": f"evt_{uuid.uuid4().hex[:12]}",
                "nonce": uuid.uuid4().hex + uuid.uuid4().hex,
                "version": 1,
                "masked_pii_hash": "a" * 64,
                "real_data_hash": "b" * 64,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            payload["signature_hex"] = sign_payload(self.private_pem, payload)
            self.client.post('/api/v1/tree/update', json=payload, headers=self._get_auth_header("SERVICE"))
            
        r_before = self.client.get('/api/v1/tree/root', headers=self._get_auth_header("VIEWER"))
        root_before = r_before.json["master_root"]
        
        # 2. Simulate restart by reloading app (this recreates tree from DB)
        self.app = create_m3_app(db_path=self.db_path, anchor_path=self.anchor_path)
        self.client = self.app.test_client()
        
        r_after = self.client.get('/api/v1/tree/root', headers=self._get_auth_header("VIEWER"))
        root_after = r_after.json["master_root"]
        
        self.assertEqual(root_before, root_after)

    def test_8_anchor_verification(self):
        # Test 8 - Anchor
        # Insert a record to generate an anchor
        payload = {
            "user_id": self.identity_id,
            "leaf_id": "record_008",
            "event_id": f"evt_{uuid.uuid4().hex[:12]}",
            "nonce": uuid.uuid4().hex + uuid.uuid4().hex,
            "version": 1,
            "masked_pii_hash": "a" * 64,
            "real_data_hash": "b" * 64,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        payload["signature_hex"] = sign_payload(self.private_pem, payload)
        self.client.post('/api/v1/tree/update', json=payload, headers=self._get_auth_header("SERVICE"))
        
        # Verify Anchor
        r1 = self.client.get('/api/v1/audit/verify-anchor', headers=self._get_auth_header("VIEWER"))
        self.assertEqual(r1.status_code, 200)
        self.assertEqual(r1.json["status"], "VERIFIED")
        
        # Tamper with anchor file
        with open(self.anchor_path, "a") as f:
            f.write(json.dumps({"event_id": "fake", "timestamp": "fake", "master_root": "0"*64, "checkpoint_hash": "fake"}) + "\n")
            
        r2 = self.client.get('/api/v1/audit/verify-anchor', headers=self._get_auth_header("VIEWER"))
        self.assertEqual(r2.status_code, 400)
        self.assertEqual(r2.json["status"], "FAILED")

if __name__ == '__main__':
    # Setup mock env vars for auth matching auth.py's expected dev keys or custom keys
    os.environ["M3_API_KEYS"] = json.dumps({
        "dev-admin-key": "ADMIN",
        "dev-service-key": "SERVICE",
        "dev-viewer-key": "VIEWER"
    })
    unittest.main()
