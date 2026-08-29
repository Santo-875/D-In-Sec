"""
Comprehensive Test Suite for Module 3 (M3):
Identity, Hierarchical Merkle Tree & Root Verification Engine.
"""

import pytest
import hashlib
from datetime import datetime, timezone, timedelta
from m3.crypto_signer import (
    generate_rsa_key_pair,
    sign_payload,
    verify_signature,
    PublicKeyRegistry,
    get_public_key_fingerprint
)
from m3.merkle_tree import HierarchicalMerkleTree, compute_combined_leaf_hash
from m3.audit_log import AppendOnlyAuditLog
from m3.freeze_manager import FreezeManager
from m3.m4_interface import M4PayloadFormatter
from m3.api import create_m3_app


@pytest.fixture
def keys():
    private_pem, public_pem = generate_rsa_key_pair()
    return {
        "private_pem": private_pem,
        "public_pem": public_pem,
        "fingerprint": get_public_key_fingerprint(public_pem)
    }


@pytest.fixture
def app_client():
    app = create_m3_app()
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


def test_rsa_signature_verification(keys):
    payload = {
        "user_id": "user_001",
        "leaf_id": "doc_123",
        "masked_pii_hash": hashlib.sha256(b"masked_pii").hexdigest(),
        "real_data_hash": hashlib.sha256(b"real_data").hexdigest(),
        "timestamp": "2026-07-25T12:00:00Z"
    }

    # Valid signature
    sig_hex = sign_payload(keys["private_pem"], payload)
    assert verify_signature(keys["public_pem"], payload, sig_hex) is True

    # Tampered payload should fail verification
    tampered_payload = dict(payload)
    tampered_payload["real_data_hash"] = hashlib.sha256(b"tampered").hexdigest()
    assert verify_signature(keys["public_pem"], tampered_payload, sig_hex) is False


def test_hierarchical_merkle_tree():
    tree = HierarchicalMerkleTree()

    user1 = "user_alpha"
    user2 = "user_beta"

    initial_root = tree.master_root

    # Update user 1 leaf 1
    res1 = tree.update_leaf(
        user_id=user1,
        leaf_id="leaf_1",
        masked_pii_hash=hashlib.sha256(b"masked_1").hexdigest(),
        real_data_hash=hashlib.sha256(b"real_1").hexdigest(),
        timestamp="2026-07-25T12:00:00Z"
    )

    root_after_user1 = tree.master_root
    assert root_after_user1 != initial_root
    assert res1["old_master_root"] == initial_root
    assert res1["new_master_root"] == root_after_user1

    # Update user 2 leaf 1 (isolation check - user 1 subroot unchanged)
    user1_subroot_before = tree.user_subroots[user1].subroot_hash

    res2 = tree.update_leaf(
        user_id=user2,
        leaf_id="leaf_1",
        masked_pii_hash=hashlib.sha256(b"masked_2").hexdigest(),
        real_data_hash=hashlib.sha256(b"real_2").hexdigest(),
        timestamp="2026-07-25T12:05:00Z"
    )

    user1_subroot_after = tree.user_subroots[user1].subroot_hash
    assert user1_subroot_before == user1_subroot_after, "User 1 subroot must remain isolated when User 2 updates"
    assert tree.master_root != root_after_user1


def test_leaf_integrity_and_tamper_detection():
    tree = HierarchicalMerkleTree()
    user_id = "user_gamma"
    leaf_id = "leaf_target"
    masked_hash = hashlib.sha256(b"pii_data").hexdigest()
    real_hash = hashlib.sha256(b"real_db_row").hexdigest()

    tree.update_leaf(user_id, leaf_id, masked_hash, real_hash, "2026-07-25T12:00:00Z")

    # Authentic leaf verify
    assert tree.verify_leaf_integrity(user_id, leaf_id, masked_hash, real_hash) is True

    # Tampered leaf verify (tampered real database record)
    tampered_real_hash = hashlib.sha256(b"tampered_db_row").hexdigest()
    assert tree.verify_leaf_integrity(user_id, leaf_id, masked_hash, tampered_real_hash) is False


def test_certin_180_day_retention_pruning():
    audit_log = AppendOnlyAuditLog()

    now = datetime.now(timezone.utc)
    old_date = (now - timedelta(days=200)).isoformat()
    recent_date = (now - timedelta(days=10)).isoformat()

    # Add old event (> 180 days)
    audit_log.log_event(
        user_id="user_old",
        leaf_id="leaf_old",
        old_leaf_hash=None,
        new_leaf_hash="hash_old",
        old_master_root="root_0",
        new_master_root="root_1",
        signature_hex="sig_old",
        signer_fingerprint="fp_old",
        timestamp=old_date
    )

    # Add recent event (< 180 days)
    audit_log.log_event(
        user_id="user_recent",
        leaf_id="leaf_recent",
        old_leaf_hash=None,
        new_leaf_hash="hash_recent",
        old_master_root="root_1",
        new_master_root="root_2",
        signature_hex="sig_recent",
        signer_fingerprint="fp_recent",
        timestamp=recent_date
    )

    assert len(audit_log.get_all_detailed_logs()) == 2
    assert len(audit_log.get_permanent_root_chain()) == 2

    # Prune logs older than 180 days
    prune_res = audit_log.prune_logs_older_than(days=180, reference_now=now)

    assert prune_res["logs_pruned"] == 1
    assert prune_res["detailed_logs_remaining"] == 1
    # Permanent 32-byte root chain must remain complete (2 items)
    assert prune_res["permanent_root_checkpoints_preserved"] == 2
    assert len(audit_log.get_permanent_root_chain()) == 2


def test_write_freeze_manager():
    mgr = FreezeManager()
    user_id = "suspicious_user"

    # Initially not frozen
    frozen, reason = mgr.is_frozen(user_id)
    assert frozen is False

    # Freeze subtree
    mgr.freeze_subtree(user_id, "Potential brute-force attack detected")
    frozen, reason = mgr.is_frozen(user_id)
    assert frozen is True
    assert "brute-force" in reason

    # Unfreeze subtree
    mgr.unfreeze_subtree(user_id)
    frozen, reason = mgr.is_frozen(user_id)
    assert frozen is False

    # Freeze master
    mgr.freeze_master("Master compromise alert")
    frozen, reason = mgr.is_frozen(user_id)
    assert frozen is True
    assert "Master Tree Frozen" in reason


def test_api_workflow(app_client):
    # 1. Health check
    res = app_client.get('/api/v1/health')
    assert res.status_code == 200

    # 2. Generate RSA Key Pair
    res = app_client.post('/api/v1/identity/generate-keys')
    assert res.status_code == 201
    keys_data = res.get_json()
    private_pem = keys_data["private_key_pem"]
    public_pem = keys_data["public_key_pem"]

    # 3. Register Key
    user_id = "api_user_01"
    res = app_client.post('/api/v1/identity/register', json={
        "identity_id": user_id,
        "public_key_pem": public_pem
    })
    assert res.status_code == 200

    # 4. Sign update payload
    payload_to_sign = {
        "user_id": user_id,
        "leaf_id": "profile_record_1",
        "masked_pii_hash": hashlib.sha256(b"masked_john_doe").hexdigest(),
        "real_data_hash": hashlib.sha256(b"real_john_doe_row").hexdigest(),
        "timestamp": "2026-07-25T12:30:00Z"
    }
    sig_hex = sign_payload(private_pem, payload_to_sign)

    # 5. Submit signed tree update
    update_req = dict(payload_to_sign)
    update_req["signature_hex"] = sig_hex
    res = app_client.post('/api/v1/tree/update', json=update_req)
    assert res.status_code == 200
    update_json = res.get_json()
    assert update_json["status"] == "SUCCESS"
    event_id = update_json["event_id"]
    next_root = update_json["calculated_next_master_root"]

    # 6. Verify Master Root
    res = app_client.get('/api/v1/tree/root')
    assert res.status_code == 200
    assert res.get_json()["master_root"] == next_root

    # 7. Get M4 Payload
    res = app_client.get(f'/api/v1/m4/payload/{event_id}')
    assert res.status_code == 200
    m4_data = res.get_json()
    assert m4_data["event_id"] == event_id
    assert m4_data["user_identity"]["user_id"] == user_id
    assert m4_data["user_identity"]["signature_verified"] is True
    assert m4_data["root_transition"]["calculated_next_master_root"] == next_root

    # 8. Test Write-Freeze rejection
    app_client.post('/api/v1/freeze', json={"target": "subtree", "user_id": user_id, "reason": "Test freeze"})
    res = app_client.post('/api/v1/tree/update', json=update_req)
    assert res.status_code == 403
    assert "frozen" in res.get_json()["error"].lower()
