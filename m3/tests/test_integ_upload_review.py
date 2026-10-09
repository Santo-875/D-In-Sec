import hashlib
import io
import os
import sqlite3
import sys

import pytest

# Ensure mock_site and m3 are on Python path
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(BASE_DIR, "mock_site"))
sys.path.insert(0, BASE_DIR)

from app import create_app
from models import Document, User, db


@pytest.fixture
def app_and_client(tmp_path, monkeypatch):
    monkeypatch.delenv("S3_AUDIT_BUCKET", raising=False)
    monkeypatch.delenv("S3_BUCKET_NAME", raising=False)
    db_file = tmp_path / "integ_test.db"
    app = create_app(config_override={
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{db_file}",
        "WTF_CSRF_ENABLED": False,
    })

    with app.app_context():
        db.create_all()
        suffix = tmp_path.name
        user = User(username=f"user_{suffix}", email=f"user_{suffix}@example.com", is_admin=False)
        user.set_password("pass123")
        db.session.add(user)

        other_user = User(username=f"other_{suffix}", email=f"other_{suffix}@example.com", is_admin=False)
        other_user.set_password("pass123")
        db.session.add(other_user)

        admin = User(username=f"admin_{suffix}", email=f"admin_{suffix}@example.com", is_admin=True)
        admin.set_password("pass123")
        db.session.add(admin)

        db.session.commit()
        user_id = user.id
        other_id = other_user.id
        admin_id = admin.id

    client = app.test_client()
    return app, client, user_id, other_id, admin_id


def login_user(client, user_id):
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user_id)
        sess["_fresh"] = True


def test_upload_saves_file_sha256_and_calls_push_leaf(app_and_client, monkeypatch):
    app, client, user_id, _other_id, _admin_id = app_and_client
    calls = []

    def mock_push_leaf(u_id, leaf_id, masked_hash, real_hash, version=1):
        calls.append((u_id, leaf_id, masked_hash, real_hash))
        return True

    import m3_client
    monkeypatch.setattr(m3_client, "push_leaf", mock_push_leaf)

    login_user(client, user_id)
    pdf_bytes = b"%PDF-1.4 test content here"
    expected_sha = hashlib.sha256(pdf_bytes).hexdigest()

    data = {
        'doc_type': 'Aadhaar Card',
        'document': (io.BytesIO(pdf_bytes), 'id.pdf')
    }
    res = client.post('/dashboard/upload', data=data, content_type='multipart/form-data')
    assert res.status_code == 302

    with app.app_context():
        doc = Document.query.filter_by(user_id=user_id).first()
        assert doc is not None
        assert doc.file_sha256 == expected_sha
        assert doc.file_name == 'id.pdf'
        assert len(calls) == 1
        assert calls[0][0] == f"user_{user_id}"
        assert calls[0][1] == f"doc_{doc.id}"
        assert calls[0][3] == expected_sha


def test_file_access_permissions_and_headers(app_and_client):
    app, client, user_id, _other_id, admin_id = app_and_client

    login_user(client, user_id)
    pdf_bytes = b"%PDF-1.4 secure document"
    data = {'doc_type': 'Passport', 'document': (io.BytesIO(pdf_bytes), 'doc.pdf')}
    client.post('/dashboard/upload', data=data, content_type='multipart/form-data')

    with app.app_context():
        doc = Document.query.filter_by(user_id=user_id).first()
        doc_id = doc.id

    # 1. Anonymous gets 302
    anon_client = app.test_client()
    r_anon = anon_client.get(f'/admin/documents/{doc_id}/file')
    assert r_anon.status_code == 302

    # 2. Non-admin gets 403
    r_non_admin = client.get(f'/admin/documents/{doc_id}/file')
    assert r_non_admin.status_code == 403

    # 3. Admin gets 200 + nosniff + CSP sandbox + no-store
    login_user(client, admin_id)
    r_admin = client.get(f'/admin/documents/{doc_id}/file')
    assert r_admin.status_code == 200
    assert r_admin.data == pdf_bytes
    assert r_admin.headers.get('X-Content-Type-Options') == 'nosniff'
    assert r_admin.headers.get('Content-Security-Policy') == 'sandbox'
    assert r_admin.headers.get('Cache-Control') == 'no-store'
    assert 'inline' in r_admin.headers.get('Content-Disposition', '')


def test_owner_only_vault_check_blocks_other_user(app_and_client):
    app, client, user_id, other_id, _admin_id = app_and_client
    from vault.service import vault_get_file

    login_user(client, user_id)
    pdf_bytes = b"%PDF-1.4 confidential"
    data = {'doc_type': 'Voter ID', 'document': (io.BytesIO(pdf_bytes), 'voter.pdf')}
    client.post('/dashboard/upload', data=data, content_type='multipart/form-data')

    with app.app_context():
        doc = Document.query.filter_by(user_id=user_id).first()
        file_token = doc.file_token

    # Other user calling vault_get_file directly should get (None, None)
    file_bytes, meta = vault_get_file(file_token, requesting_user_id=other_id)
    assert file_bytes is None
    assert meta is None

    # Original owner gets file
    file_bytes, meta = vault_get_file(file_token, requesting_user_id=user_id)
    assert file_bytes == pdf_bytes


def test_tampering_stored_bytes_causes_integrity_failure_and_approve_refused(app_and_client):
    app, client, user_id, _other_id, admin_id = app_and_client

    login_user(client, user_id)
    pdf_bytes = b"%PDF-1.4 original file"
    data = {'doc_type': 'PAN Card', 'document': (io.BytesIO(pdf_bytes), 'pan.pdf')}
    client.post('/dashboard/upload', data=data, content_type='multipart/form-data')

    with app.app_context():
        doc = Document.query.filter_by(user_id=user_id).first()
        doc_id = doc.id
        token = doc.file_token

    # Tamper with the raw vault payload
    from vault.crypto import encrypt
    from vault.token_manager import _VAULT_DB
    conn = sqlite3.connect(_VAULT_DB)
    tampered_bytes = b"%PDF-1.4 TAMPERED BYTES"
    tampered_payload = {'meta': {'original_name': 'pan.pdf', 'extension': 'pdf'}, 'file_b64': tampered_bytes.hex()}
    tampered_blob = encrypt(tampered_payload)
    conn.execute("UPDATE vault_tokens SET blob = ? WHERE token_id = ?", (tampered_blob, token))
    conn.commit()
    conn.close()

    # Admin checks integrity
    login_user(client, admin_id)
    r_integ = client.post(f'/admin/documents/{doc_id}/integrity')
    assert r_integ.status_code == 200
    res = r_integ.get_json()
    assert res['file_hash_ok'] is False

    # Admin tries to approve -> refused
    r_verify = client.post(f'/admin/documents/{doc_id}/verify', data={'action': 'approve'})
    assert r_verify.status_code == 302
    with app.app_context():
        doc = db.session.get(Document, doc_id)
        assert doc.status == 'Pending'


def test_user_self_verify_leaves_status_pending(app_and_client):
    app, client, user_id, _other_id, _admin_id = app_and_client

    login_user(client, user_id)
    pdf_bytes = b"%PDF-1.4 profile check"
    data = {'doc_type': 'Driving License', 'document': (io.BytesIO(pdf_bytes), 'dl.pdf')}
    client.post('/dashboard/upload', data=data, content_type='multipart/form-data')

    with app.app_context():
        doc = Document.query.filter_by(user_id=user_id).first()
        doc_id = doc.id

    # User clicks self-verify
    r_user_verify = client.post(f'/dashboard/verify/{doc_id}')
    assert r_user_verify.status_code == 302

    with app.app_context():
        doc = db.session.get(Document, doc_id)
        assert doc.status == 'Pending'


def test_admin_decision_pushes_decision_leaf(app_and_client, monkeypatch):
    app, client, user_id, _other_id, admin_id = app_and_client

    calls = []

    def mock_push_leaf(u_id, leaf_id, masked_hash, real_hash, version=1):
        calls.append((u_id, leaf_id, masked_hash, real_hash))
        return True

    import m3_client
    monkeypatch.setattr(m3_client, "push_leaf", mock_push_leaf)

    login_user(client, user_id)
    pdf_bytes = b"%PDF-1.4 test document"
    data = {'doc_type': 'Address Proof', 'document': (io.BytesIO(pdf_bytes), 'addr.pdf')}
    client.post('/dashboard/upload', data=data, content_type='multipart/form-data')

    with app.app_context():
        doc = Document.query.filter_by(user_id=user_id).first()
        doc_id = doc.id

    calls.clear()

    # Reject without note should fail
    login_user(client, admin_id)
    r_reject_nonote = client.post(f'/admin/documents/{doc_id}/verify', data={'action': 'reject', 'admin_note': ''})
    assert r_reject_nonote.status_code == 302
    with app.app_context():
        assert db.session.get(Document, doc_id).status == 'Pending'
    assert len(calls) == 0

    # Reject with note pushes decision leaf
    r_reject = client.post(f'/admin/documents/{doc_id}/verify', data={'action': 'reject', 'admin_note': 'Illegible scan'})
    assert r_reject.status_code == 302
    with app.app_context():
        assert db.session.get(Document, doc_id).status == 'Rejected'
    assert len(calls) == 1
    assert calls[0][0] == f"user_{user_id}"
    assert calls[0][1] == f"doc_{doc_id}_decision"


def test_magic_byte_mismatch_rejected(app_and_client):
    app, client, user_id, _other_id, _admin_id = app_and_client
    login_user(client, user_id)

    fake_pdf = b"This is NOT a valid pdf file content"
    data = {'doc_type': 'Passport', 'document': (io.BytesIO(fake_pdf), 'fake.pdf')}
    r = client.post('/dashboard/upload', data=data, content_type='multipart/form-data')
    assert r.status_code == 302

    with app.app_context():
        docs = Document.query.filter_by(file_name='fake.pdf').all()
        assert len(docs) == 0


def test_upload_end_to_end_leaf_in_snapshot(app_and_client, monkeypatch, tmp_path):
    from m3.api import create_m3_app
    from m3.crypto_signer import generate_rsa_key_pair

    priv_pem, _pub_pem = generate_rsa_key_pair()
    m3_db = str(tmp_path / "m3_e2e.db")
    m3_anchor = str(tmp_path / "m3_e2e_anchor.log")
    m3_app = create_m3_app(db_path=m3_db, anchor_path=m3_anchor)
    m3_test_client = m3_app.test_client()

    monkeypatch.setenv("M3_SIGNING_PRIVATE_KEY", priv_pem)
    monkeypatch.setenv("M3_ADMIN_API_KEY", "dev-admin-key")
    monkeypatch.setenv("M3_SERVICE_API_KEY", "dev-service-key")

    import mock_site.m3_client as m3c

    def mock_post(url, json=None, headers=None, timeout=None):
        path = url.split("5001")[-1] if "5001" in url else url
        if not path.startswith("/"):
            path = "/" + path

        class MockResp:
            def __init__(self, r):
                self._r = r
                self.status_code = r.status_code
                self.text = r.get_data(as_text=True)

            def json(self):
                return self._r.get_json()

        r = m3_test_client.post(path, json=json, headers=headers)
        return MockResp(r)

    monkeypatch.setattr(m3c.requests, "post", mock_post)

    app, client, user_id, _other_id, _admin_id = app_and_client
    login_user(client, user_id)
    pdf_bytes = b"%PDF-1.4 end to end test file"
    data = {'doc_type': 'Passport', 'document': (io.BytesIO(pdf_bytes), 'e2e.pdf')}
    res = client.post('/dashboard/upload', data=data, content_type='multipart/form-data')
    assert res.status_code == 302

    with app.app_context():
        doc = Document.query.filter_by(file_name='e2e.pdf').first()
        doc_id = doc.id

    snap_resp = m3_test_client.get('/api/v1/tree/snapshot', headers={"X-API-Key": "dev-viewer-key"})
    assert snap_resp.status_code == 200
    snap = snap_resp.get_json()
    user_tree = next((u for u in snap["users"] if u["user_id"] == f"user_{user_id}"), None)
    assert user_tree is not None
    assert f"doc_{doc_id}" in user_tree["leaf_ids"]


def test_one_decision_per_document(app_and_client, monkeypatch):
    """
    T2 Test: One decision per document.
    Approve then reject leaves status Verified and exactly one doc_<id>_decision leaf.
    """
    app, client, user_id, _other_id, admin_id = app_and_client
    decision_leaves = []

    def mock_push_leaf(u_id, leaf_id, p1, p2, version=1):
        if "decision" in leaf_id:
            decision_leaves.append((u_id, leaf_id, p1, p2))
        return True

    import m3_client
    monkeypatch.setattr(m3_client, "push_leaf", mock_push_leaf)

    import routes.admin as admin_module
    monkeypatch.setattr(admin_module, "_check_doc_integrity", lambda doc, aid: {
        "file_hash_ok": True,
        "m3": {"status": "MATCH"},
        "master_root": "0" * 64,
        "checked_at": "2026-10-09T00:00:00Z"
    })

    login_user(client, user_id)
    pdf_bytes = b"%PDF-1.4 test document content"
    data = {'doc_type': 'Voter ID', 'document': (io.BytesIO(pdf_bytes), 'voter.pdf')}
    client.post('/dashboard/upload', data=data, content_type='multipart/form-data')

    with app.app_context():
        doc = Document.query.filter_by(user_id=user_id, file_name='voter.pdf').first()
        doc_id = doc.id
        assert doc.status == 'Pending'

    # 1. Admin approves
    login_user(client, admin_id)
    r_approve = client.post(f'/admin/documents/{doc_id}/verify', data={'action': 'approve'})
    assert r_approve.status_code == 302
    with app.app_context():
        assert db.session.get(Document, doc_id).status == 'Verified'
    assert len(decision_leaves) == 1
    assert decision_leaves[0][1] == f"doc_{doc_id}_decision"

    # 2. Admin tries to reject the already verified doc
    r_reject = client.post(f'/admin/documents/{doc_id}/verify', data={'action': 'reject', 'admin_note': 'Attempt reject'})
    assert r_reject.status_code == 302
    with app.app_context():
        # Status MUST remain Verified
        assert db.session.get(Document, doc_id).status == 'Verified'
    # Exactly one decision leaf still
    assert len(decision_leaves) == 1


def test_stricter_approve_integrity(app_and_client, monkeypatch):
    """
    T3 Tests:
    - MATCH approves
    - OFFLINE without override is refused
    - with override+note approves
    - MISMATCH refused even with override
    """
    app, client, user_id, _other_id, admin_id = app_and_client
    pushed_leaves = []

    def mock_push_leaf(u_id, leaf_id, p1, p2, version=1):
        pushed_leaves.append((u_id, leaf_id, p1, p2))
        return True

    import m3_client
    monkeypatch.setattr(m3_client, "push_leaf", mock_push_leaf)

    import routes.admin as admin_module

    login_user(client, user_id)
    pdf_bytes = b"%PDF-1.4 sample data"
    data = {'doc_type': 'PAN Card', 'document': (io.BytesIO(pdf_bytes), 'pan.pdf')}
    client.post('/dashboard/upload', data=data, content_type='multipart/form-data')

    with app.app_context():
        doc = Document.query.filter_by(user_id=user_id, file_name='pan.pdf').first()
        doc_id = doc.id

    login_user(client, admin_id)

    # Case 1: OFFLINE without override is refused
    monkeypatch.setattr(admin_module, "_check_doc_integrity", lambda d, aid: {
        "file_hash_ok": True,
        "m3": {"status": "OFFLINE"},
        "master_root": None,
        "checked_at": "2026-10-09T00:00:00Z"
    })
    r_off = client.post(f'/admin/documents/{doc_id}/verify', data={'action': 'approve'})
    assert r_off.status_code == 302
    with app.app_context():
        assert db.session.get(Document, doc_id).status == 'Pending'

    # Case 2: OFFLINE with override+note approves
    pushed_leaves.clear()
    r_off_override = client.post(
        f'/admin/documents/{doc_id}/verify',
        data={'action': 'approve', 'override': '1', 'admin_note': 'Manual check ok'}
    )
    assert r_off_override.status_code == 302
    with app.app_context():
        assert db.session.get(Document, doc_id).status == 'Verified'
    assert len(pushed_leaves) == 1
    assert pushed_leaves[0][1] == f"doc_{doc_id}_decision"

    # Reset doc to Pending for next cases
    with app.app_context():
        d = db.session.get(Document, doc_id)
        d.status = 'Pending'
        db.session.commit()

    # Case 3: MISMATCH refused even with override
    monkeypatch.setattr(admin_module, "_check_doc_integrity", lambda d, aid: {
        "file_hash_ok": True,
        "m3": {"status": "MISMATCH"},
        "master_root": "0" * 64,
        "checked_at": "2026-10-09T00:00:00Z"
    })
    r_mismatch = client.post(
        f'/admin/documents/{doc_id}/verify',
        data={'action': 'approve', 'override': '1', 'admin_note': 'Forced'}
    )
    assert r_mismatch.status_code == 302
    with app.app_context():
        assert db.session.get(Document, doc_id).status == 'Pending'

    # Case 4: MATCH approves directly
    monkeypatch.setattr(admin_module, "_check_doc_integrity", lambda d, aid: {
        "file_hash_ok": True,
        "m3": {"status": "MATCH"},
        "master_root": "0" * 64,
        "checked_at": "2026-10-09T00:00:00Z"
    })
    r_match = client.post(f'/admin/documents/{doc_id}/verify', data={'action': 'approve'})
    assert r_match.status_code == 302
    with app.app_context():
        assert db.session.get(Document, doc_id).status == 'Verified'


def test_anchoring_status_and_retry(app_and_client, monkeypatch, tmp_path):
    """
    T4 Tests:
    - Failure on upload -> m3_synced False
    - retry flips it True and the leaf appears in the snapshot
    """
    from m3.api import create_m3_app
    from m3.crypto_signer import generate_rsa_key_pair

    priv_pem, _pub_pem = generate_rsa_key_pair()
    m3_db = str(tmp_path / "m3_retry.db")
    m3_anchor = str(tmp_path / "m3_retry_anchor.log")
    m3_app = create_m3_app(db_path=m3_db, anchor_path=m3_anchor)
    m3_test_client = m3_app.test_client()

    monkeypatch.setenv("M3_SIGNING_PRIVATE_KEY", priv_pem)
    monkeypatch.setenv("M3_ADMIN_API_KEY", "dev-admin-key")
    monkeypatch.setenv("M3_SERVICE_API_KEY", "dev-service-key")

    import mock_site.m3_client as m3c
    m3c._registered_identities.clear()

    should_fail = True

    def mock_post(url, json=None, headers=None, timeout=None):
        if should_fail:
            class FailResp:
                status_code = 500
                text = "Simulated M3 outage"
                def json(self): return {"error": "down"}
            return FailResp()

        path = url.split("5001")[-1] if "5001" in url else url
        if not path.startswith("/"):
            path = "/" + path

        class MockResp:
            def __init__(self, r):
                self._r = r
                self.status_code = r.status_code
                self.text = r.get_data(as_text=True)

            def json(self):
                return self._r.get_json()

        r = m3_test_client.post(path, json=json, headers=headers)
        return MockResp(r)

    monkeypatch.setattr(m3c.requests, "post", mock_post)

    app, client, user_id, _other_id, _admin_id = app_and_client
    login_user(client, user_id)
    pdf_bytes = b"%PDF-1.4 test retry document"
    data = {'doc_type': 'Passport', 'document': (io.BytesIO(pdf_bytes), 'itr.pdf')}

    # 1. Upload during M3 outage -> failure -> m3_synced is False
    res = client.post('/dashboard/upload', data=data, content_type='multipart/form-data')
    assert res.status_code == 302

    with app.app_context():
        doc = Document.query.filter_by(file_name='itr.pdf').first()
        doc_id = doc.id
        assert doc.m3_synced is False

    # Snapshot currently does NOT contain this leaf
    snap_resp = m3_test_client.get('/api/v1/tree/snapshot', headers={"X-API-Key": "dev-viewer-key"})
    assert snap_resp.status_code == 200
    snap = snap_resp.get_json()
    user_tree = next((u for u in snap["users"] if u["user_id"] == f"user_{user_id}"), None)
    assert user_tree is None or f"doc_{doc_id}" not in user_tree["leaf_ids"]

    # 2. Outage resolved -> retry flips it True
    should_fail = False
    with app.app_context():
        from app import retry_unsynced_documents
        synced = retry_unsynced_documents(limit=10)
        assert synced >= 1

        reloaded = db.session.get(Document, doc_id)
        assert reloaded.m3_synced is True

    # 3. Leaf now appears in snapshot
    snap_resp2 = m3_test_client.get('/api/v1/tree/snapshot', headers={"X-API-Key": "dev-viewer-key"})
    assert snap_resp2.status_code == 200
    snap2 = snap_resp2.get_json()
    user_tree2 = next((u for u in snap2["users"] if u["user_id"] == f"user_{user_id}"), None)
    assert user_tree2 is not None
    assert f"doc_{doc_id}" in user_tree2["leaf_ids"]
