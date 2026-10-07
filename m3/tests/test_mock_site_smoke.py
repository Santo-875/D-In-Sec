"""
m3/tests/test_mock_site_smoke.py — Smoke tests for mock_site and SOC dashboard routes.
"""

import os
import sys

import pytest

# Ensure mock_site is on Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "mock_site")))
flask_login = pytest.importorskip("flask_login")
from app import create_app
from models import IncidentAlert, User, db


@pytest.fixture
def mock_app(tmp_path):
    app = create_app()
    app.config["TESTING"] = True
    app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{tmp_path / 'test_smoke.db'}"
    app.config["WTF_CSRF_ENABLED"] = False
    with app.app_context():
        db.create_all()
        # Seed an incident
        alert = IncidentAlert(
            incident_type="SQL_INJECTION",
            severity="CRITICAL",
            confidence=0.95,
            masked_log_context="SELECT * FROM users WHERE id='admin'",
            cert_in_draft="Draft report",
            status="Open"
        )
        db.session.add(alert)
        db.session.commit()
    return app

@pytest.fixture
def mock_client(mock_app):
    return mock_app.test_client()

def test_mock_site_home_route(mock_client):
    res = mock_client.get("/")
    assert res.status_code in [200, 302]

def test_mock_site_auth_routes(mock_client):
    r_login = mock_client.get("/auth/login")
    assert r_login.status_code == 200
    r_signup = mock_client.get("/auth/signup")
    assert r_signup.status_code == 200

def test_soc_index_route(mock_client):
    # Even if M3 sidecar is not running, dashboard must not crash (timeouts/error states handled)
    res = mock_client.get("/soc/")
    assert res.status_code == 200
    assert b"SOC Operations & Merkle Sidecar Integrity" in res.data
    assert b"Cloud Infrastructure & Sidecar Status" in res.data

def test_soc_verify_full_route(mock_client):
    res = mock_client.post("/soc/verify/full")
    assert res.status_code == 302  # Redirects to /soc/?verified=1
    followed = mock_client.get(res.headers["Location"])
    assert followed.status_code == 200

def test_soc_verify_full_json_route(mock_client):
    res = mock_client.post("/soc/verify/full", headers={"Accept": "application/json"})
    assert res.status_code == 200
    data = res.get_json()
    assert "status" in data
    assert "steps" in data

def test_soc_export_certin_route(mock_client):
    res = mock_client.get("/soc/export/certin")
    assert res.status_code in [200, 503]

def test_soc_anchor_route(mock_client):
    res = mock_client.post("/soc/anchor")
    assert res.status_code == 302

def test_soc_model_rollback_route(mock_client):
    res = mock_client.post("/soc/model/rollback/v1.0.0")
    assert res.status_code == 302


def test_login_alias_route(mock_client):
    res = mock_client.get("/login")
    assert res.status_code == 200


def test_admin_and_merkle_routes(mock_app, mock_client):
    with mock_app.app_context():
        admin = User.query.filter_by(is_admin=True).first()
        if not admin:
            admin = User(username="admin_user", email="admin@test.com", is_admin=True)
            admin.set_password("validpassword10")
            db.session.add(admin)
            db.session.commit()
        admin_id = admin.id

    with mock_client.session_transaction() as sess:
        sess["_user_id"] = str(admin_id)
        sess["_fresh"] = True

    r_admin = mock_client.get("/admin/")
    assert r_admin.status_code == 200

    r_merkle = mock_client.get("/admin/merkle")
    assert r_merkle.status_code == 200

    r_merkle_data = mock_client.get("/admin/merkle/data")
    assert r_merkle_data.status_code == 200

