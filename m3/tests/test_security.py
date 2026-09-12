import pytest
import os
import time
import uuid
from datetime import datetime, timezone

from m3.crypto_signer import generate_rsa_key_pair, sign_payload
from m3.api import app
from m3.database import M3Database

@pytest.fixture
def client():
    # Setup test DB
    test_db_path = "test_m3.db"
    if os.path.exists(test_db_path):
        os.remove(test_db_path)
    
    app.config['TESTING'] = True
    app.config['M3_DB_PATH'] = test_db_path
    
    # Use dev keys
    os.environ["M3_API_KEYS"] = "dev-admin-key,dev-service-key,dev-viewer-key"
    
    with app.test_client() as client:
        yield client
        
    if os.path.exists(test_db_path):
        try:
            os.remove(test_db_path)
        except PermissionError:
            pass

def test_replay_protection_duplicate_event_id(client):
    """Test that submitting the same event_id twice fails."""
    private_key, public_key = generate_rsa_key_pair()
    client.post('/api/v1/identity/register', 
                json={"identity_id": "test_user", "public_key_pem": public_key},
                headers={"X-API-Key": "dev-admin-key"})

    event_id = "evt_test123"
    nonce = "nonce_1"
    timestamp = datetime.now(timezone.utc).isoformat()
    
    payload = {
        "user_id": "test_user",
        "leaf_id": "leaf_1",
        "event_id": event_id,
        "nonce": nonce,
        "version": 1,
        "masked_pii_hash": "a"*64,
        "real_data_hash": "b"*64,
        "timestamp": timestamp
    }
    signature = sign_payload(private_key, payload)
    
    req_data = {**payload, "signature_hex": signature}
    
    # First request should succeed
    res1 = client.post('/api/v1/tree/update', json=req_data, headers={"X-API-Key": "dev-service-key"})
    assert res1.status_code == 200
    
    # Second request with same event_id should fail
    payload["nonce"] = "nonce_2"
    signature2 = sign_payload(private_key, payload)
    req_data2 = {**payload, "signature_hex": signature2}
    
    res2 = client.post('/api/v1/tree/update', json=req_data2, headers={"X-API-Key": "dev-service-key"})
    assert res2.status_code == 409
    assert "event_id has already been processed" in res2.get_json()["reason"]

def test_merkle_tamper_detection(client):
    """Test that tampering with the DB is detected via the verify endpoint."""
    private_key, public_key = generate_rsa_key_pair()
    client.post('/api/v1/identity/register', 
                json={"identity_id": "tamper_user", "public_key_pem": public_key},
                headers={"X-API-Key": "dev-admin-key"})

    timestamp = datetime.now(timezone.utc).isoformat()
    payload = {
        "user_id": "tamper_user",
        "leaf_id": "leaf_1",
        "event_id": "evt_tamper_1",
        "nonce": "nonce_tamper_1",
        "version": 1,
        "masked_pii_hash": "a"*64,
        "real_data_hash": "b"*64,
        "timestamp": timestamp
    }
    signature = sign_payload(private_key, payload)
    req_data = {**payload, "signature_hex": signature}
    
    # Insert valid record
    res = client.post('/api/v1/tree/update', json=req_data, headers={"X-API-Key": "dev-service-key"})
    assert res.status_code == 200
    
    # Now simulate a DB tamper: directly edit the merkle_leaves table
    db = M3Database(db_path="test_m3.db")
    with db.get_connection() as conn:
        conn.execute("UPDATE merkle_leaves SET masked_pii_hash = ? WHERE user_id = ? AND leaf_id = ?",
                     ("c"*64, "tamper_user", "leaf_1"))
        conn.commit()

    # Trigger verify
    verify_res = client.post('/api/v1/audit/verify', json={
        "user_id": "tamper_user",
        "leaf_id": "leaf_1",
        "masked_pii_hash": "a"*64, # The expected hash from the client
        "real_data_hash": "b"*64
    }, headers={"X-API-Key": "dev-viewer-key"})
    
    assert verify_res.status_code == 400
    assert verify_res.get_json()["status"] == "FAILED"
    assert "recalculation mismatch" in verify_res.get_json()["reason"]
