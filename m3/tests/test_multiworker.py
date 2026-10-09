import hashlib
import uuid
from datetime import datetime, timezone

from m3.api import create_m3_app
from m3.crypto_signer import generate_rsa_key_pair, sign_payload
from m3.storage import LocalBackend


def test_multi_app_worker_consistency(tmp_path):
    """
    T1 Test: two create_m3_app instances sharing one DB.
    Write on A, then B's /tree/root and /tree/snapshot equal A's.
    """
    db_path = str(tmp_path / "shared_worker.db")
    anchor_a = str(tmp_path / "anchor_a.log")
    anchor_b = str(tmp_path / "anchor_b.log")
    storage_a = LocalBackend(base_dir=str(tmp_path / "storage_a"))
    storage_b = LocalBackend(base_dir=str(tmp_path / "storage_b"))

    app_a = create_m3_app(db_path=db_path, anchor_path=anchor_a, storage_backend=storage_a)
    app_b = create_m3_app(db_path=db_path, anchor_path=anchor_b, storage_backend=storage_b)

    client_a = app_a.test_client()
    client_b = app_b.test_client()

    admin_headers = {"X-API-Key": "dev-admin-key"}
    service_headers = {"X-API-Key": "dev-service-key"}
    viewer_headers = {"X-API-Key": "dev-viewer-key"}

    # 1. Register identity on A (which writes to shared DB)
    priv_key, pub_key = generate_rsa_key_pair()
    user_id = "user_worker_1"
    reg_resp = client_a.post(
        "/api/v1/identity/register",
        json={"identity_id": user_id, "public_key_pem": pub_key},
        headers=admin_headers,
    )
    assert reg_resp.status_code == 200

    # 2. Write leaf on A
    leaf_id = "leaf_test_1"
    masked_pii_hash = hashlib.sha256(b"masked_pii_content").hexdigest()
    real_data_hash = hashlib.sha256(b"real_data_content").hexdigest()
    timestamp = datetime.now(timezone.utc).isoformat()
    event_id = f"evt_{uuid.uuid4().hex[:12]}"
    nonce = uuid.uuid4().hex + uuid.uuid4().hex
    version = 1

    payload = {
        "user_id": user_id,
        "leaf_id": leaf_id,
        "event_id": event_id,
        "nonce": nonce,
        "version": version,
        "masked_pii_hash": masked_pii_hash,
        "real_data_hash": real_data_hash,
        "timestamp": timestamp,
    }
    sig = sign_payload(priv_key, payload)
    update_req = {**payload, "signature_hex": sig}

    write_resp = client_a.post("/api/v1/tree/update", json=update_req, headers=service_headers)
    assert write_resp.status_code == 200, write_resp.get_json()

    # 3. Read /tree/root from A and B
    root_a = client_a.get("/tree/root", headers=viewer_headers)
    root_b = client_b.get("/tree/root", headers=viewer_headers)
    assert root_a.status_code == 200
    assert root_b.status_code == 200
    assert root_b.json["master_root"] == root_a.json["master_root"]
    assert root_b.json["master_root"] != ""

    # 4. Read /tree/snapshot from A and B
    snap_a = client_a.get("/tree/snapshot", headers=viewer_headers)
    snap_b = client_b.get("/tree/snapshot", headers=viewer_headers)
    assert snap_a.status_code == 200
    assert snap_b.status_code == 200
    assert snap_b.json["master_root"] == snap_a.json["master_root"]
    assert snap_b.json["users"] == snap_a.json["users"]
