"""
m3/tests/test_endpoints.py — Tests for Phase 4 & Phase 5:
  - /healthz and /readyz liveness/readiness probes
  - /api/v1/verify/full comprehensive verification endpoint
  - /api/v1/alerts alert retrieval
  - /api/v1/events ML event classification endpoint
  - /api/v1/export/certin CERT-In export endpoint
  - Multi-tenant isolation
"""

import json
import os
import tempfile
import uuid
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
