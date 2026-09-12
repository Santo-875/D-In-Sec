"""
Security-focused Test Suite for Module 3 (M3) Phase 1 Hardening.

Tests cover:
  - Token authentication (missing, invalid, valid)
  - Role-based access control (role escalation prevention)
  - Anti-replay protection (duplicate nonce, duplicate event_id, stale timestamp)
  - Decoupled key registration (unregistered identity rejection)
  - Independent Merkle proof verification (valid and tampered proofs)
"""

import hashlib
import uuid
from datetime import datetime, timezone, timedelta
import pytest

from m3.crypto_signer import generate_rsa_key_pair, sign_payload, get_public_key_fingerprint
from m3.api import create_m3_app


# ── Fixtures ─────────────────────────────────────────────────────────────

@pytest.fixture
def keys():
    private_pem, public_pem = generate_rsa_key_pair()
    return {"private_pem": private_pem, "public_pem": public_pem}


@pytest.fixture
def app_client():
    """Creates a test client with dev API keys loaded."""
    app = create_m3_app()
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


ADMIN_HEADERS = {"X-API-Key": "dev-admin-key"}
SERVICE_HEADERS = {"X-API-Key": "dev-service-key"}
VIEWER_HEADERS = {"X-API-Key": "dev-viewer-key"}


def _register_and_update(client, keys, leaf_id="leaf_sec_01"):
    """Helper: registers key and submits a signed tree update. Returns (event_id, payload_used)."""
    user_id = "sec_user"
    # Register key first (ADMIN)
    client.post('/api/v1/identity/register', json={
        "identity_id": user_id,
        "public_key_pem": keys["public_pem"]
    }, headers=ADMIN_HEADERS)

    timestamp = datetime.now(timezone.utc).isoformat()
    payload = {
        "user_id": user_id,
        "leaf_id": leaf_id,
        "masked_pii_hash": hashlib.sha256(b"masked_sec").hexdigest(),
        "real_data_hash": hashlib.sha256(b"real_sec").hexdigest(),
        "timestamp": timestamp
    }
    sig = sign_payload(keys["private_pem"], payload)

    event_id = f"evt_{uuid.uuid4().hex[:12]}"
    nonce = uuid.uuid4().hex

    request_body = {
        **payload,
        "signature_hex": sig,
        "event_id": event_id,
        "nonce": nonce
    }

    res = client.post('/api/v1/tree/update', json=request_body, headers=SERVICE_HEADERS)
    return res, event_id, nonce, request_body


# ── 1. Authentication Tests ─────────────────────────────────────────────

def test_no_token_returns_401(app_client):
    """Request without X-API-Key header should be rejected with 401."""
    res = app_client.post('/api/v1/freeze', json={"target": "master"})
    assert res.status_code == 401
    assert "Authentication required" in res.get_json()["error"]


def test_wrong_token_returns_401(app_client):
    """Invalid API key should be rejected with 401."""
    res = app_client.post('/api/v1/freeze',
                          json={"target": "master"},
                          headers={"X-API-Key": "bogus-key-12345"})
    assert res.status_code == 401
    assert "Invalid API key" in res.get_json()["error"]


# ── 2. RBAC Tests ────────────────────────────────────────────────────────

def test_viewer_cannot_freeze(app_client):
    """VIEWER role should NOT be able to freeze (requires ADMIN)."""
    res = app_client.post('/api/v1/freeze',
                          json={"target": "master", "reason": "test"},
                          headers=VIEWER_HEADERS)
    assert res.status_code == 403
    assert "Insufficient permissions" in res.get_json()["error"]


def test_viewer_can_read_root(app_client):
    """VIEWER role should be able to read the master root."""
    res = app_client.get('/api/v1/tree/root', headers=VIEWER_HEADERS)
    assert res.status_code == 200
    assert "master_root" in res.get_json()


def test_service_cannot_register_key(app_client, keys):
    """SERVICE role should NOT be able to register public keys (requires ADMIN)."""
    res = app_client.post('/api/v1/identity/register', json={
        "identity_id": "hacker",
        "public_key_pem": keys["public_pem"]
    }, headers=SERVICE_HEADERS)
    assert res.status_code == 403


def test_health_is_public(app_client):
    """Health endpoint should work without any authentication."""
    res = app_client.get('/api/v1/health')
    assert res.status_code == 200
    assert res.get_json()["status"] == "healthy"


# ── 3. Anti-Replay Tests ────────────────────────────────────────────────

def test_replay_duplicate_nonce_rejected(app_client, keys):
    """Sending the same nonce twice should be rejected as replay attack."""
    res1, event_id1, nonce, body1 = _register_and_update(app_client, keys, leaf_id="leaf_replay_nonce_1")
    assert res1.status_code == 200

    # Replay with same nonce but new event_id and new timestamp
    body2 = dict(body1)
    body2["event_id"] = f"evt_{uuid.uuid4().hex[:12]}"
    body2["nonce"] = nonce  # SAME nonce
    body2["leaf_id"] = "leaf_replay_nonce_2"
    body2["timestamp"] = datetime.now(timezone.utc).isoformat()
    # Re-sign with new payload
    signable = {k: body2[k] for k in ["user_id", "leaf_id", "masked_pii_hash", "real_data_hash", "timestamp"]}
    body2["signature_hex"] = sign_payload(keys["private_pem"], signable)

    res2 = app_client.post('/api/v1/tree/update', json=body2, headers=SERVICE_HEADERS)
    assert res2.status_code == 409
    assert "replay" in res2.get_json()["error"].lower()


def test_replay_duplicate_event_id_rejected(app_client, keys):
    """Sending the same event_id twice should be rejected."""
    res1, event_id, nonce, body1 = _register_and_update(app_client, keys, leaf_id="leaf_replay_eid_1")
    assert res1.status_code == 200

    # Replay with same event_id but new nonce
    body2 = dict(body1)
    body2["event_id"] = event_id  # SAME event_id
    body2["nonce"] = uuid.uuid4().hex
    body2["leaf_id"] = "leaf_replay_eid_2"
    body2["timestamp"] = datetime.now(timezone.utc).isoformat()
    signable = {k: body2[k] for k in ["user_id", "leaf_id", "masked_pii_hash", "real_data_hash", "timestamp"]}
    body2["signature_hex"] = sign_payload(keys["private_pem"], signable)

    res2 = app_client.post('/api/v1/tree/update', json=body2, headers=SERVICE_HEADERS)
    assert res2.status_code == 409
    assert "replay" in res2.get_json()["error"].lower()


def test_replay_stale_timestamp_rejected(app_client, keys):
    """Request with a timestamp older than 5 minutes should be rejected."""
    user_id = "sec_user_stale"
    app_client.post('/api/v1/identity/register', json={
        "identity_id": user_id,
        "public_key_pem": keys["public_pem"]
    }, headers=ADMIN_HEADERS)

    stale_time = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
    payload = {
        "user_id": user_id,
        "leaf_id": "leaf_stale",
        "masked_pii_hash": hashlib.sha256(b"stale_masked").hexdigest(),
        "real_data_hash": hashlib.sha256(b"stale_real").hexdigest(),
        "timestamp": stale_time
    }
    sig = sign_payload(keys["private_pem"], payload)

    request_body = {
        **payload,
        "signature_hex": sig,
        "event_id": f"evt_{uuid.uuid4().hex[:12]}",
        "nonce": uuid.uuid4().hex
    }

    res = app_client.post('/api/v1/tree/update', json=request_body, headers=SERVICE_HEADERS)
    assert res.status_code == 409
    assert "stale" in res.get_json()["detail"].lower()


# ── 4. Decoupled Key Registration Tests ─────────────────────────────────

def test_unregistered_identity_rejected(app_client, keys):
    """An identity that hasn't been pre-registered should be rejected on /tree/update."""
    timestamp = datetime.now(timezone.utc).isoformat()
    payload = {
        "user_id": "unknown_hacker",
        "leaf_id": "leaf_hack",
        "masked_pii_hash": hashlib.sha256(b"hack_masked").hexdigest(),
        "real_data_hash": hashlib.sha256(b"hack_real").hexdigest(),
        "timestamp": timestamp
    }
    sig = sign_payload(keys["private_pem"], payload)

    request_body = {
        **payload,
        "signature_hex": sig,
        "event_id": f"evt_{uuid.uuid4().hex[:12]}",
        "nonce": uuid.uuid4().hex
    }

    res = app_client.post('/api/v1/tree/update', json=request_body, headers=SERVICE_HEADERS)
    assert res.status_code == 401
    assert "No public key registered" in res.get_json()["error"]


# ── 5. Proof Verification Tests ─────────────────────────────────────────

def test_proof_verification_valid(app_client, keys):
    """Valid proof from the tree should verify successfully."""
    res, _, _, _ = _register_and_update(app_client, keys, leaf_id="leaf_proof_valid")
    assert res.status_code == 200

    # Get the proof for this leaf
    proof_res = app_client.get('/api/v1/tree/proof/sec_user/leaf_proof_valid', headers=VIEWER_HEADERS)
    assert proof_res.status_code == 200
    proof_data = proof_res.get_json()

    # Verify the proof independently
    verify_res = app_client.post('/api/v1/tree/verify-proof', json={
        "leaf_hash": proof_data["leaf_hash"],
        "leaf_proof": proof_data["leaf_proof"],
        "subroot_proof": proof_data["subroot_proof"],
        "user_id": "sec_user",
        "claimed_master_root": proof_data["master_root"]
    }, headers=VIEWER_HEADERS)

    assert verify_res.status_code == 200
    verify_data = verify_res.get_json()
    assert verify_data["proof_valid"] is True
    assert verify_data["computed_master_root"] == proof_data["master_root"]


def test_proof_verification_tampered(app_client, keys):
    """Proof with a tampered leaf hash should fail verification."""
    res, _, _, _ = _register_and_update(app_client, keys, leaf_id="leaf_proof_tamper")
    assert res.status_code == 200

    proof_res = app_client.get('/api/v1/tree/proof/sec_user/leaf_proof_tamper', headers=VIEWER_HEADERS)
    assert proof_res.status_code == 200
    proof_data = proof_res.get_json()

    # Tamper with the leaf hash
    verify_res = app_client.post('/api/v1/tree/verify-proof', json={
        "leaf_hash": hashlib.sha256(b"TAMPERED_LEAF").hexdigest(),  # Wrong hash!
        "leaf_proof": proof_data["leaf_proof"],
        "subroot_proof": proof_data["subroot_proof"],
        "user_id": "sec_user",
        "claimed_master_root": proof_data["master_root"]
    }, headers=VIEWER_HEADERS)

    assert verify_res.status_code == 200
    verify_data = verify_res.get_json()
    assert verify_data["proof_valid"] is False
    assert verify_data["computed_master_root"] != proof_data["master_root"]
