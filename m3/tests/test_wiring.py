"""
Integration tests for Module 2 -> Module 3 wiring, key storage, and best-effort resilience.

spaCy is imported lazily / mocked so this file passes even without the en_core_web_sm model.
"""

import sqlite3
import sys
import threading
import time
import types

import pytest


# ── Lazy / mock spaCy so tests pass without the model installed ───────────────
def _mock_spacy():
    """Insert a minimal spacy stub into sys.modules if spaCy or its model is absent."""
    try:
        import spacy
        spacy.load("en_core_web_sm")   # will raise OSError if model missing
    except Exception:
        # Build a lightweight stub that satisfies any import of spacy.load(...)
        spacy_stub = types.ModuleType("spacy")

        class _NLP:
            def __call__(self, text):
                class _Doc:
                    def __init__(self):
                        self.ents = []
                return _Doc()

        def _load(*args, **kwargs):
            return _NLP()

        spacy_stub.load = _load
        spacy_stub.blank = lambda lang: _NLP()
        sys.modules.setdefault("spacy", spacy_stub)
        # Also stub the model package so `import en_core_web_sm` won't blow up
        model_stub = types.ModuleType("en_core_web_sm")
        model_stub.load = _load
        sys.modules.setdefault("en_core_web_sm", model_stub)

_mock_spacy()
# ─────────────────────────────────────────────────────────────────────────────

from m3.api import create_m3_app
from m3.crypto_signer import (
    generate_rsa_key_pair,
    get_public_key_from_private_pem,
    load_private_key_from_env,
)
from mock_site.vault.crypto import _load_or_create_key, decrypt, encrypt
from Module_2.schemas import ClassificationResult, IncidentType, Severity
from Module_2.tailer import (
    _insert_incident_alert,
    _register_key_with_m3,
    _send_update_to_m3,
)


@pytest.fixture(scope="module")
def rsa_keys():
    """Generates an RSA-2048 key pair in memory."""
    priv, pub = generate_rsa_key_pair()
    return priv, pub


@pytest.fixture(scope="module")
def m3_server(tmp_path_factory):
    """Spawns background M3 Flask server on port 5001 using a temp DB."""
    db_path = str(tmp_path_factory.mktemp("wiring_db") / "test_wiring.db")
    app = create_m3_app(db_path=db_path)
    server = threading.Thread(
        target=lambda: app.run(host="127.0.0.1", port=5001, debug=False, use_reloader=False),
        daemon=True
    )
    server.start()
    time.sleep(1.0)  # Allow server to bind and start listening
    return "http://127.0.0.1:5001"


def test_key_storage_in_memory_only(rsa_keys, monkeypatch):
    """Verifies RSA private key is loaded from env var strictly in memory with no file creation."""
    priv_pem, pub_pem = rsa_keys

    # Test loading from env var
    monkeypatch.setenv("M3_SIGNING_PRIVATE_KEY", priv_pem)
    loaded_priv = load_private_key_from_env("M3_SIGNING_PRIVATE_KEY")
    assert loaded_priv == priv_pem.strip()

    # Test derived public key matches original
    derived_pub = get_public_key_from_private_pem(loaded_priv)
    assert derived_pub.strip() == pub_pem.strip()

    # Test literal \n newline normalisation
    escaped_pem = priv_pem.replace("\n", "\\n")
    monkeypatch.setenv("M3_SIGNING_PRIVATE_KEY", escaped_pem)
    normalized_priv = load_private_key_from_env("M3_SIGNING_PRIVATE_KEY")
    assert "\n" in normalized_priv
    assert normalized_priv == priv_pem.strip()


def test_vault_key_env_var_support(monkeypatch, tmp_path):
    """Verifies VAULT_ENCRYPTION_KEY loads directly from env without disk dependency."""
    from cryptography.fernet import Fernet
    test_key = Fernet.generate_key().decode('utf-8')
    monkeypatch.setenv("VAULT_ENCRYPTION_KEY", test_key)

    key = _load_or_create_key()
    assert key == test_key.encode('utf-8')

    # Test round-trip encryption with env-supplied key
    test_payload = {"user_id": 42, "pan": "ABCDE1234F"}
    blob = encrypt(test_payload)
    decrypted = decrypt(blob)
    assert decrypted == test_payload


def test_module2_to_module3_wiring_end_to_end(rsa_keys, m3_server, monkeypatch, tmp_path):
    """
    Tests complete wiring flow:
    1. Incident classified in Module 2
    2. IncidentAlert row saved to SQLite DB
    3. Payload signed with env RSA key
    4. POST to M3 API on port 5001
    5. Returned event_id stored back on IncidentAlert row
    """
    priv_pem, _ = rsa_keys
    monkeypatch.setenv("M3_SIGNING_PRIVATE_KEY", priv_pem)
    monkeypatch.setenv("M3_API_URL", "http://127.0.0.1:5001/api/v1/tree/update")
    monkeypatch.setenv("M3_SERVICE_API_KEY", "dev-service-key")
    monkeypatch.setenv("M3_ADMIN_API_KEY", "dev-admin-key")

    # Set up temporary SQLite database
    db_path = tmp_path / "test_mock_site.db"
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

    classification = ClassificationResult(
        incident_type=IncidentType.SQL_INJECTION,
        severity=Severity.CRITICAL,
        confidence=0.98,
        cert_in_report_draft="CERT-In Incident Report: SQL Injection attempt detected on login portal."
    )
    context_text = "User admin accessed login with payload ' OR 1=1 --"

    # Step 1: Insert alert into DB
    alert_id = _insert_incident_alert(db_path, classification, context_text)
    assert alert_id is not None

    # Step 2: Pre-register public key with M3 (required by Phase 1 decoupled registration)
    _, pub_pem = rsa_keys
    _register_key_with_m3(pub_pem, user_id="admin")
    time.sleep(0.2)  # Allow registration to complete

    # Step 3: Send update to M3
    _send_update_to_m3(db_path, alert_id, classification, context_text)

    # Step 4: Verify event_id is saved to database
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()
    cursor.execute("SELECT id, incident_type, event_id FROM incident_alerts WHERE id = ?", (alert_id,))
    row = cursor.fetchone()
    conn.close()

    assert row is not None
    assert row[0] == alert_id
    assert row[1] == "SQL_INJECTION"
    assert row[2] is not None
    assert len(row[2]) > 0
    assert row[2].startswith("EVT-") or len(row[2]) >= 16


def test_m3_down_resilience_best_effort(rsa_keys, monkeypatch, tmp_path):
    """Verifies that if M3 is unreachable, Module 2 logs warning and does NOT crash."""
    priv_pem, _ = rsa_keys
    monkeypatch.setenv("M3_SIGNING_PRIVATE_KEY", priv_pem)
    # Point to nonexistent port to trigger connection error
    monkeypatch.setenv("M3_API_URL", "http://127.0.0.1:59999/api/v1/tree/update")
    monkeypatch.setenv("M3_SERVICE_API_KEY", "dev-service-key")

    db_path = tmp_path / "test_down.db"
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

    classification = ClassificationResult(
        incident_type=IncidentType.BRUTE_FORCE,
        severity=Severity.HIGH,
        confidence=0.92,
        cert_in_report_draft="CERT-In Incident Report: Brute force detected."
    )
    context_text = "User test failed login 5 times."

    alert_id = _insert_incident_alert(db_path, classification, context_text)
    assert alert_id is not None

    # Must NOT raise exception despite M3 being down
    try:
        _send_update_to_m3(db_path, alert_id, classification, context_text)
    except Exception as e:
        pytest.fail(f"_send_update_to_m3 raised an exception instead of failing gracefully: {e}")

    # Row remains saved with event_id as None
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()
    cursor.execute("SELECT event_id FROM incident_alerts WHERE id = ?", (alert_id,))
    row = cursor.fetchone()
    conn.close()
    assert row[0] is None
