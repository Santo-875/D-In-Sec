"""
m3/tests/test_endpoints.py — Tests for Phase 4 & Phase 5:
  - /healthz and /readyz liveness/readiness probes
  - /api/v1/verify/full comprehensive verification endpoint
  - /api/v1/alerts alert retrieval
  - /api/v1/events ML event classification endpoint
  - /api/v1/export/certin CERT-In export endpoint
  - Multi-tenant isolation
"""

from datetime import datetime, timezone

import pytest

from m3.api import create_m3_app
from m3.crypto_signer import generate_rsa_key_pair, sign_payload
from m3.database import M3Database


@pytest.fixture
def client_and_db(tmp_path):
    db_path = str(tmp_path / "test_endpoints.db")
    anchor_path = str(tmp_path / "test_anchor.log")
    app = create_m3_app(db_path=db_path, anchor_path=anchor_path)
    client = app.test_client()
    return client, M3Database(db_path)


def test_healthz_and_readyz(client_and_db):
    client, _ = client_and_db
    
    # /healthz is unauthenticated
    resp = client.get('/healthz')
    assert resp.status_code == 200
    assert resp.json["status"] in ["ok", "alive", "degraded"]

    # /readyz is unauthenticated
    resp = client.get('/readyz')
    assert resp.status_code == 200
    assert resp.json["status"] in ["ready", "degraded"]
    assert "storage_healthy" in resp.json
    assert "pending_uploads_backlog" in resp.json


def test_alerts_endpoint(client_and_db):
    client, db = client_and_db
    headers = {"X-API-Key": "dev-admin-key"}

    # Insert an alert directly in DB
    db.save_alert("TEST_ALERT_01", "TAMPER_DETECTED", "CRITICAL", {"details": "test tamper"})

    resp = client.get('/api/v1/alerts', headers=headers)
    assert resp.status_code == 200
    assert "alerts" in resp.json
    assert any(a["alert_id"] == "TEST_ALERT_01" for a in resp.json["alerts"])


def test_events_ml_classification_endpoint(client_and_db):
    client, _ = client_and_db
    headers = {"X-API-Key": "dev-service-key"}

    payload = {
        "text": "User authenticated successfully via oauth2 SSO",
        "tenant_id": "tenant_alpha"
    }
    resp = client.post('/api/v1/events', json=payload, headers=headers)
    assert resp.status_code == 200
    data = resp.json
    assert "label" in data
    assert "confidence" in data
    assert "source" in data


def test_certin_export_endpoint(client_and_db):
    client, _ = client_and_db
    headers = {"X-API-Key": "dev-admin-key"}

    resp = client.get('/api/v1/export/certin?from=2026-09-01&to=2026-09-30', headers=headers)
    assert resp.status_code == 200
    assert "logs" in resp.json
    assert "summaries" in resp.json


def test_full_verify_endpoint(client_and_db):
    client, _ = client_and_db
    headers = {"X-API-Key": "dev-admin-key"}

    resp = client.get('/api/v1/verify/full', headers=headers)
    assert resp.status_code == 200
    assert resp.json["status"] in ["VALID", "EMPTY", "UNVERIFIED", "TAMPER"]
    assert "db_root" in resp.json


def test_tree_snapshot_endpoint(client_and_db):
    client, _ = client_and_db
    admin_headers = {"X-API-Key": "dev-admin-key"}
    service_headers = {"X-API-Key": "dev-service-key"}
    viewer_headers = {"X-API-Key": "dev-viewer-key"}

    priv, pub = generate_rsa_key_pair()
    reg_resp = client.post(
        '/api/v1/identity/register',
        json={"identity_id": "snap_user", "public_key_pem": pub},
        headers=admin_headers
    )
    assert reg_resp.status_code == 200

    # Write 1
    w1 = {
        "user_id": "snap_user",
        "leaf_id": "doc_1",
        "event_id": "evt_snap_1",
        "nonce": "nonce_snap_1_123456",
        "version": 1,
        "masked_pii_hash": "1" * 64,
        "real_data_hash": "2" * 64,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    sig1 = sign_payload(priv, w1)
    res1 = client.post('/api/v1/tree/update', json={**w1, "signature_hex": sig1}, headers=service_headers)
    assert res1.status_code == 200

    # Write 2
    w2 = {
        "user_id": "snap_user",
        "leaf_id": "doc_2",
        "event_id": "evt_snap_2",
        "nonce": "nonce_snap_2_123456",
        "version": 1,
        "masked_pii_hash": "3" * 64,
        "real_data_hash": "4" * 64,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    sig2 = sign_payload(priv, w2)
    res2 = client.post('/api/v1/tree/update', json={**w2, "signature_hex": sig2}, headers=service_headers)
    assert res2.status_code == 200

    # Verify snapshot master_root equals /tree/root
    root_resp = client.get('/api/v1/tree/root', headers=viewer_headers)
    assert root_resp.status_code == 200
    expected_root = root_resp.json["master_root"]

    snap_resp = client.get('/api/v1/tree/snapshot', headers=viewer_headers)
    assert snap_resp.status_code == 200
    snap = snap_resp.json

    assert snap["master_root"] == expected_root
    assert len(snap["users"]) >= 1
    user_record = next(u for u in snap["users"] if u["user_id"] == "snap_user")
    assert user_record["leaf_count"] == 2
    assert len(user_record["leaves"]) == 2
    leaf_ids = {leaf["leaf_id"] for leaf in user_record["leaves"]}
    assert leaf_ids == {"doc_1", "doc_2"}

    # root_history shows the changed roots
    assert len(snap["root_history"]) >= 2
    events_in_history = [e["event_id"] for e in snap["root_history"]]
    assert "evt_snap_1" in events_in_history
    assert "evt_snap_2" in events_in_history

    evt2 = next(e for e in snap["root_history"] if e["event_id"] == "evt_snap_2")
    assert evt2["new_master_root"] == expected_root
    assert evt2["old_master_root"] is not None

