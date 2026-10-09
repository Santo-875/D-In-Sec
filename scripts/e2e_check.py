#!/usr/bin/env python3
"""
scripts/e2e_check.py — End-to-end integration verification script:
1. Start M3 in-process on a free port.
2. Run portal test client with CSRF off.
3. Signup + login user.
4. Upload PDF document.
5. Admin runs integrity check -> asserts MATCH.
6. Admin approves -> status Verified.
7. Second decision refused -> status stays Verified.
8. Tamper stored hash -> approve refused -> status stays Pending.
9. Assert M3 snapshot contains doc_1 and doc_1_decision.
"""

import io
import os
import socket
import sys
import tempfile
import threading
import time
import requests
from werkzeug.serving import make_server

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
MOCK_SITE_DIR = os.path.join(BASE_DIR, "mock_site")
sys.path.insert(0, MOCK_SITE_DIR)
sys.path.insert(0, BASE_DIR)

from m3.api import create_m3_app
from m3.crypto_signer import generate_rsa_key_pair
from app import create_app
from models import Document, User, db


def get_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def run_e2e():
    print("[1/9] Starting in-process M3 instance...")
    port = get_free_port()
    temp_dir = tempfile.TemporaryDirectory()
    m3_db_path = os.path.join(temp_dir.name, "m3_e2e.db")
    m3_anchor_path = os.path.join(temp_dir.name, "m3_anchor.log")

    m3_app = create_m3_app(db_path=m3_db_path, anchor_path=m3_anchor_path)
    server = make_server('127.0.0.1', port, m3_app)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    # Configure environment
    priv_pem, _ = generate_rsa_key_pair()
    os.environ["M3_SIGNING_PRIVATE_KEY"] = priv_pem
    os.environ["M3_ADMIN_API_KEY"] = "dev-admin-key"
    os.environ["M3_SERVICE_API_KEY"] = "dev-service-key"
    os.environ["M3_API_URL"] = f"http://127.0.0.1:{port}/api/v1/tree/update"
    os.environ["M3_BASE_URL"] = f"http://127.0.0.1:{port}"

    # Wait for healthz
    for _ in range(50):
        try:
            r = requests.get(f"http://127.0.0.1:{port}/healthz", timeout=1)
            if r.status_code == 200:
                break
        except Exception:
            time.sleep(0.1)

    print(f"      M3 sidecar running on port {port}")

    print("[2/9] Initializing portal application...")
    portal_db_path = os.path.join(temp_dir.name, "portal.db")
    portal_app = create_app(config_override={
        "TESTING": True,
        "WTF_CSRF_ENABLED": False,
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{portal_db_path}",
    })
    client = portal_app.test_client()

    with portal_app.app_context():
        db.create_all()

    print("[3/9] Signup and Login testuser...")
    signup_resp = client.post("/auth/signup", data={
        "username": "e2e_user",
        "email": "e2e_user@example.com",
        "password": "SecurePassword123!",
        "confirm_password": "SecurePassword123!",
    })
    assert signup_resp.status_code == 302, f"Signup failed: {signup_resp.status_code}"

    login_resp = client.post("/auth/login", data={
        "username": "e2e_user",
        "password": "SecurePassword123!",
    })
    assert login_resp.status_code == 302, f"Login failed: {login_resp.status_code}"

    print("[4/9] Uploading PDF document...")
    pdf_bytes = b"%PDF-1.4 E2E Integrity Test Verification Document Content"
    upload_resp = client.post("/dashboard/upload", data={
        "doc_type": "Passport",
        "document": (io.BytesIO(pdf_bytes), "sample_passport.pdf"),
    }, content_type="multipart/form-data")
    assert upload_resp.status_code == 302, f"Upload failed: {upload_resp.status_code}"

    with portal_app.app_context():
        doc1 = Document.query.filter_by(file_name="sample_passport.pdf").first()
        assert doc1 is not None, "Document not created in DB"
        assert doc1.id == 1
        assert doc1.m3_synced is True, "Document was not anchored to M3 on upload"

    print("[5/9] Admin integrity check -> MATCH...")
    with portal_app.app_context():
        admin = User(username="admin_e2e", email="admin_e2e@example.com", is_admin=True)
        admin.set_password("AdminSecure123!")
        db.session.add(admin)
        db.session.commit()

    logout_resp = client.post("/auth/logout")
    assert logout_resp.status_code == 302
    admin_login = client.post("/auth/login", data={
        "username": "admin_e2e",
        "password": "AdminSecure123!",
    })
    assert admin_login.status_code == 302

    integ_resp = client.post("/admin/documents/1/integrity")
    assert integ_resp.status_code == 200, f"Integrity check failed: {integ_resp.status_code}"
    integ_data = integ_resp.get_json()
    assert integ_data["file_hash_ok"] is True, f"File hash not OK: {integ_data}"
    assert integ_data["m3"]["status"] == "MATCH", f"M3 status not MATCH: {integ_data}"

    print("[6/9] Approving document...")
    verify_resp = client.post("/admin/documents/1/verify", data={"action": "approve"})
    assert verify_resp.status_code == 302
    with portal_app.app_context():
        doc1 = db.session.get(Document, 1)
        assert doc1.status == "Verified"

    print("[7/9] Second decision on same document refused...")
    second_resp = client.post("/admin/documents/1/verify", data={"action": "reject", "admin_note": "Disallow reject"})
    assert second_resp.status_code == 302
    with portal_app.app_context():
        doc1 = db.session.get(Document, 1)
        assert doc1.status == "Verified", "Second decision corrupted status"

    print("[8/9] Tamper stored hash -> approve refused...")
    # Switch back to user and upload second doc
    client.post("/auth/logout")
    client.post("/auth/login", data={"username": "e2e_user", "password": "SecurePassword123!"})
    upload2_resp = client.post("/dashboard/upload", data={
        "doc_type": "Passport",
        "document": (io.BytesIO(b"%PDF-1.4 Second test document"), "tamper_doc.pdf"),
    }, content_type="multipart/form-data")
    assert upload2_resp.status_code == 302

    with portal_app.app_context():
        doc2 = Document.query.filter_by(file_name="tamper_doc.pdf").first()
        assert doc2 is not None
        doc2_id = doc2.id
        # Deliberately tamper the hash in DB
        doc2.file_sha256 = "a" * 64
        db.session.commit()

    # Admin checks tampered doc and attempts approve
    client.post("/auth/logout")
    client.post("/auth/login", data={"username": "admin_e2e", "password": "AdminSecure123!"})

    integ_tamper = client.post(f"/admin/documents/{doc2_id}/integrity").get_json()
    assert integ_tamper["file_hash_ok"] is False, "Tampered doc did not trigger file_hash_ok False"

    # Even with override=1, approve must be hard-blocked
    attempt_approve = client.post(f"/admin/documents/{doc2_id}/verify", data={
        "action": "approve",
        "override": "1",
        "admin_note": "Attempt bypass on tampered doc",
    })
    assert attempt_approve.status_code == 302
    with portal_app.app_context():
        doc2 = db.session.get(Document, doc2_id)
        assert doc2.status == "Pending", "Tampered document was approved!"

    print("[9/9] Verifying M3 hierarchical Merkle snapshot...")
    snap_resp = requests.get(f"http://127.0.0.1:{port}/api/v1/tree/snapshot", headers={"X-API-Key": "dev-viewer-key"})
    assert snap_resp.status_code == 200
    snap = snap_resp.json()
    user_tree = next((u for u in snap["users"] if u["user_id"] == "user_1"), None)
    assert user_tree is not None, "user_1 missing from snapshot"
    assert "doc_1" in user_tree["leaf_ids"], "doc_1 leaf missing from snapshot"
    assert "doc_1_decision" in user_tree["leaf_ids"], "doc_1_decision leaf missing from snapshot"

    with portal_app.app_context():
        db.session.remove()
        db.engine.dispose()

    server.shutdown()
    try:
        temp_dir.cleanup()
    except Exception:
        pass
    print("\n[SUCCESS] All E2E checks PASSED successfully.")


if __name__ == "__main__":
    run_e2e()
