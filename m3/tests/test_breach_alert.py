"""
Unit and Integration tests for AI Breach Alert on Tamper Detection.
"""

import sqlite3
from datetime import datetime, timezone

from m3.api import create_m3_app
from m3.breach_alert import deterministic_fallback_alert, record_breach_alert_to_db
from m3.merkle_tree import compute_hash


def test_deterministic_fallback_alert_structure():
    """Verifies that the deterministic fallback produces exact expected fields without hallucination."""
    facts = {
        "affected_user": "alice",
        "leaf_id": "profile_record_1",
        "expected_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "actual_hash": "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
        "detected_at": "2026-09-09T16:00:00Z"
    }

    alert = deterministic_fallback_alert(facts)
    assert alert["affected_user"] == "alice"
    assert alert["severity"] == "CRITICAL"
    assert "alice" in alert["summary"]
    assert "profile_record_1" in alert["summary"]
    assert alert["detected_at"] == "2026-09-09T16:00:00Z"
    assert alert["tamper_evidence"]["expected_hash"] == facts["expected_hash"]
    assert alert["tamper_evidence"]["actual_hash"] == facts["actual_hash"]


def test_breach_alert_db_persistence(tmp_path):
    """Verifies that breach alerts are recorded to the SQLite incident_alerts table."""
    db_path = tmp_path / "mock_site.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute("""
        CREATE TABLE incident_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            confidence REAL NOT NULL,
            masked_log_context TEXT NOT NULL,
            cert_in_draft TEXT,
            status TEXT DEFAULT 'Open',
            created_at DATETIME
        )
    """)
    conn.commit()
    conn.close()

    alert = {
        "summary": "Unauthorized tampering detected in user 'bob' compliance records.",
        "severity": "CRITICAL",
        "affected_user": "bob",
        "detected_at": "2026-09-09T16:05:00Z",
        "tamper_evidence": {
            "leaf_id": "doc_42",
            "expected_hash": "abc123expected",
            "actual_hash": "def456tampered"
        }
    }

    alert_id = record_breach_alert_to_db(alert, db_path=db_path)
    assert alert_id is not None

    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()
    cursor.execute("SELECT incident_type, severity, confidence, masked_log_context, status FROM incident_alerts WHERE id = ?", (alert_id,))
    row = cursor.fetchone()
    conn.close()

    assert row is not None
    assert row[0] == "DATA_TAMPERING"
    assert row[1] == "CRITICAL"
    assert row[2] == 1.0
    assert "bob" in row[3]
    assert row[4] == "Open"


def test_verify_leaf_api_tamper_detection_flow(monkeypatch, tmp_path):
    """
    Verifies end-to-end flow in Flask API:
    1. Update tree with valid leaf.
    2. Verification with correct data passes (no alert).
    3. Verification with altered/tampered hash fails deterministically.
    4. Mismatch triggers breach alert with summary, severity, and facts.
    """
    import uuid

    ADMIN_HEADERS = {"X-API-Key": "dev-admin-key"}
    SERVICE_HEADERS = {"X-API-Key": "dev-service-key"}
    VIEWER_HEADERS = {"X-API-Key": "dev-viewer-key"}

    db_path = f"test_breach_{uuid.uuid4().hex[:8]}.db"
    app = create_m3_app(db_path=db_path)
    client = app.test_client()

    # Step 1: Register identity and update leaf
    from m3.crypto_signer import generate_rsa_key_pair, sign_payload
    priv_pem, pub_pem = generate_rsa_key_pair()

    # Pre-register key (ADMIN required by Phase 1)
    client.post("/api/v1/identity/register", json={
        "identity_id": "carol",
        "public_key_pem": pub_pem
    }, headers=ADMIN_HEADERS)

    real_data_hash = compute_hash("valid_real_data")
    masked_pii_hash = compute_hash("valid_masked_pii")
    timestamp = datetime.now(timezone.utc).isoformat()

    payload = {
        "user_id": "carol",
        "leaf_id": "leaf_001",
        "masked_pii_hash": masked_pii_hash,
        "real_data_hash": real_data_hash,
        "timestamp": timestamp,
        "event_id": f"evt_{uuid.uuid4().hex[:12]}",
        "nonce": uuid.uuid4().hex,
        "version": 1
    }
    sig = sign_payload(priv_pem, payload)

    update_resp = client.post("/api/v1/tree/update", json={
        **payload,
        "signature_hex": sig
    }, headers=SERVICE_HEADERS)
    assert update_resp.status_code == 200

    # Step 2: Verify with correct data -> Should pass with NO breach alert
    verify_resp_valid = client.post("/api/v1/tree/verify-leaf", json={
        "user_id": "carol",
        "leaf_id": "leaf_001",
        "masked_pii_hash": masked_pii_hash,
        "real_data_hash": real_data_hash
    }, headers=VIEWER_HEADERS)
    assert verify_resp_valid.status_code == 200
    valid_data = verify_resp_valid.get_json()
    assert valid_data["integrity_verified"] is True
    assert "breach_alert" not in valid_data

    # Step 3: Verify with TAMPERED data -> Should fail and trigger breach alert
    tampered_real_data_hash = compute_hash("hacked_data_record")
    verify_resp_tampered = client.post("/api/v1/tree/verify-leaf", json={
        "user_id": "carol",
        "leaf_id": "leaf_001",
        "masked_pii_hash": masked_pii_hash,
        "real_data_hash": tampered_real_data_hash
    }, headers=VIEWER_HEADERS)
    assert verify_resp_tampered.status_code == 200
    tampered_data = verify_resp_tampered.get_json()
    assert tampered_data["integrity_verified"] is False

    # Verify new non-blocking response shape
    assert tampered_data.get("tamper_detected") is True
    assert "tamper_facts" in tampered_data
    assert "message" in tampered_data

    facts = tampered_data["tamper_facts"]
    assert facts["affected_user"] == "carol"
    assert facts["leaf_id"] == "leaf_001"
    assert "detected_at" in facts
    assert "expected_hash" in facts
    assert "actual_hash" in facts
    assert tampered_data["message"].startswith("Tamper detected")

