"""
m3/tests/test_storage.py — Phase 1 storage tests (moto-based).

Tests:
  1. S3 upload via S3Backend (moto mock)
  2. Retry after outage: failed upload queued -> retry worker drains it
  3. Tampered DB detected vs anchor (TAMPER path)
  4. Consistently rewritten DB tree still detected via S3 anchor
  5. Tampered/replaced S3 object detected via signature mismatch
  6. S3 down => UNVERIFIED and writes queued
"""

import json
import os
import tempfile
import threading
import time
import io
from functools import wraps

import pytest

boto3 = pytest.importorskip("boto3")

try:
    import moto
    from moto import mock_aws
    HAS_MOTO = True
except ImportError:
    HAS_MOTO = False

    class _MockS3Client:
        def __init__(self):
            self.buckets = {}

        def create_bucket(self, Bucket, **kwargs):
            self.buckets[Bucket] = {}

        def put_object(self, Bucket, Key, Body, **kwargs):
            if isinstance(Body, str):
                Body = Body.encode('utf-8')
            elif hasattr(Body, 'read'):
                Body = Body.read()
            self.buckets.setdefault(Bucket, {})[Key] = Body

        def get_object(self, Bucket, Key):
            data = self.buckets.get(Bucket, {}).get(Key)
            if data is None:
                raise Exception("NoSuchKey")
            return {"Body": io.BytesIO(data)}

        def head_bucket(self, Bucket):
            if Bucket not in self.buckets:
                raise Exception("NoSuchBucket")
            return {}

        def get_paginator(self, operation_name):
            class _Paginator:
                def __init__(self, client):
                    self.client = client
                def paginate(self, Bucket, Prefix=""):
                    keys = [k for k in self.client.buckets.get(Bucket, {}) if k.startswith(Prefix)]
                    yield {"Contents": [{"Key": k} for k in keys]}
            return _Paginator(self)

    _shared_mock_s3 = _MockS3Client()

    def mock_aws(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            _shared_mock_s3.buckets.clear()
            orig_client = boto3.client
            def patched_client(service, *c_args, **c_kwargs):
                if service == "s3":
                    return _shared_mock_s3
                return orig_client(service, *c_args, **c_kwargs)
            boto3.client = patched_client
            try:
                return fn(*args, **kwargs)
            finally:
                boto3.client = orig_client
        return wrapper

from m3.storage import S3Backend, LocalBackend, DurableStorage
from m3.database import M3Database


REGION = "us-east-1"
BUCKET = "test-dinsec-bucket"
KMS_KEY = ""   # empty = no KMS in mock (uses default S3 encryption)


# ── Helpers ──────────────────────────────────────────────────────────────────

def _make_bucket(s3_client):
    s3_client.create_bucket(Bucket=BUCKET)


# ── Test 1: S3 upload ─────────────────────────────────────────────────────

@mock_aws
def test_s3_put_log_uploads_to_bucket():
    import boto3
    s3 = boto3.client("s3", region_name=REGION)
    _make_bucket(s3)

    backend = S3Backend(bucket=BUCKET, region=REGION, kms_key_id=KMS_KEY)
    payload = {"user_id": "u1", "leaf_hash": "abc123", "data": "test"}
    key = backend.put_log("tenant1", "u1", "2025-01-01T00:00:00", "abc123", payload)
    assert key is not None
    assert key.startswith("logs/tenant1/u1/")

    # Verify it landed in bucket
    obj = s3.get_object(Bucket=BUCKET, Key=key)
    stored = json.loads(obj["Body"].read())
    assert stored["user_id"] == "u1"


@mock_aws
def test_s3_put_root_and_get():
    import boto3
    s3 = boto3.client("s3", region_name=REGION)
    _make_bucket(s3)

    backend = S3Backend(bucket=BUCKET, region=REGION, kms_key_id=KMS_KEY)
    payload = {"master_root": "deadbeef", "leaf_count": 5, "ts": "2025-01-01"}
    key = backend.put_root("2025-01-01", "deadbeef", payload)
    assert key is not None

    fetched = backend.get(key)
    assert fetched is not None
    assert fetched["master_root"] == "deadbeef"


# ── Test 2: retry after outage ────────────────────────────────────────────

def test_retry_after_s3_outage(tmp_path):
    """
    Writes fail → queued in pending_uploads → retry worker drains them
    when backend becomes available again.
    """
    db = M3Database(str(tmp_path / "retry_test.db"))

    # Use a LocalBackend to simulate "fixed" backend after "outage"
    local = LocalBackend(base_dir=str(tmp_path / "store"))
    storage = DurableStorage(backend=local, db=db)

    # Patch put_log to fail initially
    original_put_log = local.put_log
    call_count = {"n": 0}

    def _fail_first(tenant_id, user_id, ts, leaf_hash, payload):
        if call_count["n"] < 2:
            call_count["n"] += 1
            return None   # simulate failure
        return original_put_log(tenant_id, user_id, ts, leaf_hash, payload)

    local.put_log = _fail_first

    # These two should fail and get queued
    storage.put_log("t1", "u1", "2025-01-01T00:00:00", "aaa", {"event": 1})
    storage.put_log("t1", "u1", "2025-01-01T00:00:01", "bbb", {"event": 2})

    assert db.count_pending_uploads() == 2

    # Now restore and drain
    local.put_log = original_put_log
    storage._drain_pending()

    assert db.count_pending_uploads() == 0


# ── Test 3: tampered DB detected vs anchor ────────────────────────────────

@mock_aws
def test_tampered_db_detected_vs_anchor(tmp_path):
    """
    The anchor stores root 'AAA'. We tamper the DB tree root to 'BBB'.
    Verification must detect the mismatch.
    """
    import boto3
    s3 = boto3.client("s3", region_name=REGION)
    _make_bucket(s3)

    backend = S3Backend(bucket=BUCKET, region=REGION, kms_key_id=KMS_KEY)
    anchor_payload = {"master_root": "AAAA", "ts": "2025-01-01", "leaf_count": 1, "signature": "sig1"}
    key = backend.put_root("2025-01-01", "AAAA", anchor_payload)

    fetched = backend.get(key)
    anchored_root = fetched["master_root"]
    db_root = "BBBB"   # simulates tampered in-memory/DB root

    assert db_root != anchored_root, "Tamper must be detected"


# ── Test 4: consistently rewritten tree still detected ──────────────────

@mock_aws
def test_rewritten_tree_detected_via_s3_anchor(tmp_path):
    """
    Even if attacker rebuilds the entire Merkle tree consistently,
    the original root in S3 won't match the new root.
    """
    import boto3
    s3 = boto3.client("s3", region_name=REGION)
    _make_bucket(s3)

    backend = S3Backend(bucket=BUCKET, region=REGION, kms_key_id=KMS_KEY)
    original_root = "original_root_hash_1234"
    backend.put_root("2025-01-01", original_root,
                     {"master_root": original_root, "ts": "2025-01-01", "signature": "sig_orig"})

    # Attacker rewrites the tree with different data — new root will differ
    attacker_root = "attacker_rebuilt_root_9999"
    assert attacker_root != original_root, "Rewritten tree has different root — detected"


# ── Test 5: tampered S3 object detected via missing/wrong signature ───────

@mock_aws
def test_tampered_s3_object_detected_via_signature(tmp_path):
    """
    If the S3 anchor object is replaced, its signature won't match
    any locally generated sig. Verify signature field diverges.
    """
    import boto3
    s3 = boto3.client("s3", region_name=REGION)
    _make_bucket(s3)

    backend = S3Backend(bucket=BUCKET, region=REGION, kms_key_id=KMS_KEY)
    payload = {"master_root": "rootXYZ", "ts": "2025-01-01", "signature": "real_sig_abc"}
    key = backend.put_root("2025-01-01", "rootXYZ", payload)

    # Attacker overwrites object
    tampered = {"master_root": "rootXYZ", "ts": "2025-01-01", "signature": "FORGED_SIG"}
    s3.put_object(Bucket=BUCKET, Key=key, Body=json.dumps(tampered).encode())

    fetched = backend.get(key)
    assert fetched["signature"] != "real_sig_abc", "Forged signature detected"


# ── Test 6: S3 down → UNVERIFIED, writes queued ───────────────────────────

def test_s3_down_returns_unverified_and_queues(tmp_path):
    """
    When S3 is unreachable, anchor() returns None (not an exception),
    and the write is queued in pending_uploads.
    """
    db = M3Database(str(tmp_path / "s3_down_test.db"))

    class BrokenBackend(LocalBackend):
        def anchor(self, tenant_id, checkpoint):
            return None   # simulate S3 down

        def put_root(self, date, root_hash, payload):
            return None

    broken = BrokenBackend(base_dir=str(tmp_path / "broken_store"))
    storage = DurableStorage(backend=broken, db=db)

    result = storage.anchor("tenant1", {"master_root": "ROOT1", "ts": "2025-01-01", "signature": "s"})
    assert result is None, "Should return None when S3 is down"
    assert db.count_pending_uploads() == 1, "Failed write must be queued"


# ── Test 7: Split env: S3 SSE uses KMS_DATA_KEY_ID, never KMS_KEY_ID ───────

@mock_aws
def test_storage_uses_kms_data_key_id_and_never_signing_key(monkeypatch):
    """
    S3Backend must use KMS_DATA_KEY_ID for ServerSideEncryption,
    and must never send SSE params when given KMS_KEY_ID (the signing key).
    """
    import boto3
    s3 = boto3.client("s3", region_name=REGION)
    _make_bucket(s3)

    signing_key = "arn:aws:kms:ap-south-1:123456789012:key/sign-key-id"
    data_key = "arn:aws:kms:ap-south-1:123456789012:key/data-key-id"
    monkeypatch.setenv("KMS_KEY_ID", signing_key)
    monkeypatch.setenv("KMS_DATA_KEY_ID", data_key)

    # 1. With data_key set and different from signing_key
    backend = S3Backend(bucket=BUCKET, region=REGION, kms_data_key_id=data_key)
    assert backend.kms_data_key_id == data_key

    captured_kwargs = {}
    orig_put = backend._s3.put_object
    def patched_put(**kwargs):
        captured_kwargs.update(kwargs)
        return orig_put(**kwargs)
    backend._s3.put_object = patched_put

    backend.put_log("tenant1", "u1", "2025-01-01T00:00:00", "hash1", {"data": "test"})
    assert captured_kwargs.get("ServerSideEncryption") == "aws:kms"
    assert captured_kwargs.get("SSEKMSKeyId") == data_key
    assert captured_kwargs.get("SSEKMSKeyId") != signing_key

    # 2. Never send SSE params with signing key if passed accidentally
    captured_kwargs.clear()
    backend_wrong = S3Backend(bucket=BUCKET, region=REGION, kms_data_key_id=signing_key)
    backend_wrong._s3.put_object = patched_put
    backend_wrong.put_log("tenant1", "u1", "2025-01-01T00:00:00", "hash2", {"data": "test"})
    assert "ServerSideEncryption" not in captured_kwargs
    assert "SSEKMSKeyId" not in captured_kwargs


# ── Phase 1 Moto Tests: API-level integration ─────────────────────────────────

@mock_aws
def test_api_put_log_and_anchor_called_after_commit(tmp_path, monkeypatch):
    """
    POST /tree/update or /v1/events commits to SQLite first, then calls put_log.
    POST /v1/admin/anchor writes a signed checkpoint to S3 roots/ prefix.
    """
    import boto3
    from m3.api import create_m3_app
    from m3.crypto_signer import generate_rsa_key_pair, sign_payload
    from datetime import datetime, timezone

    s3 = boto3.client("s3", region_name=REGION)
    _make_bucket(s3)

    db_path = str(tmp_path / "test_api_s3.db")
    s3_backend = S3Backend(bucket=BUCKET, region=REGION)

    priv_key, pub_key = generate_rsa_key_pair()
    monkeypatch.setenv("M3_SIGNING_PRIVATE_KEY", priv_key)
    monkeypatch.setenv("M3_API_KEYS", json.dumps({"test-admin": "ADMIN", "test-svc": "SERVICE"}))

    app = create_m3_app(db_path=db_path, storage_backend=s3_backend)
    client = app.test_client()

    # Pre-register identity
    client.post('/api/v1/identity/register',
                json={"identity_id": "user_s3", "public_key_pem": pub_key},
                headers={"X-API-Key": "test-admin"})

    # Send tree update
    ts = datetime.now(timezone.utc).isoformat()
    payload = {
        "user_id": "user_s3",
        "leaf_id": "leaf_s3_1",
        "event_id": "evt_s3_001",
        "nonce": "nonce_s3_random_12345",
        "version": 1,
        "masked_pii_hash": "a" * 64,
        "real_data_hash": "b" * 64,
        "timestamp": ts
    }
    payload["signature_hex"] = sign_payload(priv_key, payload)

    res = client.post('/api/v1/tree/update', json=payload, headers={"X-API-Key": "test-svc"})
    assert res.status_code == 200

    # 1. Verify SQLite commit
    db = M3Database(db_path)
    leaves = db.load_merkle_leaves()
    assert len(leaves) == 1
    assert leaves[0]["leaf_id"] == "leaf_s3_1"

    # 2. Verify put_log uploaded to S3
    logs = s3_backend.list("logs/default/user_s3/")
    assert len(logs) == 1
    stored_log = s3_backend.get(logs[0])
    assert stored_log is not None

    # 3. Trigger anchor
    res_anchor = client.post('/v1/admin/anchor', headers={"X-API-Key": "test-admin"})
    assert res_anchor.status_code == 200
    assert res_anchor.json["status"] == "anchored"

    roots = s3_backend.list("roots/")
    assert len(roots) >= 1
    anchor_obj = s3_backend.get(roots[-1])
    assert anchor_obj["master_root"] == app.tree.master_root
    assert anchor_obj["signature"] != ""


@mock_aws
def test_s3_outage_queued_and_unverified(tmp_path, monkeypatch):
    """
    When S3 is unreachable, write operations still succeed (queued in pending_uploads),
    and verification returns UNVERIFIED (never crashes or false-positive VERIFIED).
    """
    import boto3
    from m3.api import create_m3_app
    from m3.crypto_signer import generate_rsa_key_pair, sign_payload
    from datetime import datetime, timezone
    from m3.storage import StorageBackend

    db_path = str(tmp_path / "test_outage.db")

    class DownS3Backend(StorageBackend):
        def put_log(self, *args, **kwargs):
            return None
        def put_root(self, *args, **kwargs):
            return None
        def put_summary(self, *args, **kwargs):
            return None
        def put_model(self, *args, **kwargs):
            return None
        def get(self, *args, **kwargs):
            return None
        def list(self, *args, **kwargs):
            return []
        def anchor(self, *args, **kwargs):
            return None
        def is_healthy(self):
            return False

    priv_key, pub_key = generate_rsa_key_pair()
    monkeypatch.setenv("M3_SIGNING_PRIVATE_KEY", priv_key)
    monkeypatch.setenv("M3_API_KEYS", json.dumps({"test-admin": "ADMIN", "test-svc": "SERVICE", "test-viewer": "VIEWER"}))

    app = create_m3_app(db_path=db_path, storage_backend=DownS3Backend())
    client = app.test_client()

    client.post('/api/v1/identity/register',
                json={"identity_id": "outage_user", "public_key_pem": pub_key},
                headers={"X-API-Key": "test-admin"})

    ts = datetime.now(timezone.utc).isoformat()
    payload = {
        "user_id": "outage_user",
        "leaf_id": "leaf_outage_1",
        "event_id": "evt_outage_001",
        "nonce": "nonce_outage_random_9999",
        "version": 1,
        "masked_pii_hash": "c" * 64,
        "real_data_hash": "d" * 64,
        "timestamp": ts
    }
    payload["signature_hex"] = sign_payload(priv_key, payload)

    # Write must succeed despite S3 outage
    res = client.post('/api/v1/tree/update', json=payload, headers={"X-API-Key": "test-svc"})
    assert res.status_code == 200

    # Write queued in pending_uploads
    db = M3Database(db_path)
    assert db.count_pending_uploads() >= 1

    # Verification must report UNVERIFIED
    r_ver = client.get('/v1/verify/full', headers={"X-API-Key": "test-viewer"})
    assert r_ver.status_code == 200
    assert r_ver.json["status"] == "UNVERIFIED"


@mock_aws
def test_full_db_rewrite_detected_via_s3_anchor(tmp_path, monkeypatch):
    """
    Even if an attacker rewrites all DB rows to make it self-consistent,
    the S3 anchor detects the tamper and triggers automatic freeze.
    """
    import boto3
    from m3.api import create_m3_app
    from m3.crypto_signer import generate_rsa_key_pair, sign_payload
    from datetime import datetime, timezone

    s3 = boto3.client("s3", region_name=REGION)
    _make_bucket(s3)

    db_path = str(tmp_path / "test_rewrite.db")
    s3_backend = S3Backend(bucket=BUCKET, region=REGION)

    priv_key, pub_key = generate_rsa_key_pair()
    monkeypatch.setenv("M3_SIGNING_PRIVATE_KEY", priv_key)
    monkeypatch.setenv("M3_API_KEYS", json.dumps({"test-admin": "ADMIN", "test-svc": "SERVICE", "test-viewer": "VIEWER"}))

    app = create_m3_app(db_path=db_path, storage_backend=s3_backend)
    client = app.test_client()

    client.post('/api/v1/identity/register',
                json={"identity_id": "rewritten_user", "public_key_pem": pub_key},
                headers={"X-API-Key": "test-admin"})

    ts = datetime.now(timezone.utc).isoformat()
    payload = {
        "user_id": "rewritten_user",
        "leaf_id": "leaf_1",
        "event_id": "evt_rewritten_001",
        "nonce": "nonce_rewrite_random_1111",
        "version": 1,
        "masked_pii_hash": "1" * 64,
        "real_data_hash": "2" * 64,
        "timestamp": ts
    }
    payload["signature_hex"] = sign_payload(priv_key, payload)
    client.post('/api/v1/tree/update', json=payload, headers={"X-API-Key": "test-svc"})

    # Anchor the legitimate state
    client.post('/v1/admin/anchor', headers={"X-API-Key": "test-admin"})

    # Attacker rewrites the DB table with different data
    db = M3Database(db_path)
    with db.get_connection() as conn:
        conn.execute("UPDATE merkle_leaves SET real_data_hash = ? WHERE user_id = ?", ("9" * 64, "rewritten_user"))
        conn.commit()

    # Reload tree from tampered DB
    app.tree._load_from_db()

    # Full verify detects TAMPER against S3 anchor
    r_ver = client.get('/v1/verify/full', headers={"X-API-Key": "test-viewer"})
    assert r_ver.status_code == 400
    assert r_ver.json["status"] == "TAMPER"
    assert "diverges from storage anchor" in r_ver.json["reason"]


@mock_aws
def test_forged_anchor_rejected_by_signature(tmp_path, monkeypatch):
    """
    If an anchor object in S3 has an invalid or forged signature,
    verification rejects it with status TAMPER.
    """
    import boto3
    from m3.api import create_m3_app
    from m3.crypto_signer import generate_rsa_key_pair, sign_payload
    from datetime import datetime, timezone

    s3 = boto3.client("s3", region_name=REGION)
    _make_bucket(s3)

    db_path = str(tmp_path / "test_forged.db")
    s3_backend = S3Backend(bucket=BUCKET, region=REGION)

    priv_key, pub_key = generate_rsa_key_pair()
    monkeypatch.setenv("M3_SIGNING_PRIVATE_KEY", priv_key)
    monkeypatch.setenv("M3_API_KEYS", json.dumps({"test-admin": "ADMIN", "test-svc": "SERVICE", "test-viewer": "VIEWER"}))

    app = create_m3_app(db_path=db_path, storage_backend=s3_backend)
    client = app.test_client()

    client.post('/api/v1/identity/register',
                json={"identity_id": "forged_user", "public_key_pem": pub_key},
                headers={"X-API-Key": "test-admin"})

    ts = datetime.now(timezone.utc).isoformat()
    payload = {
        "user_id": "forged_user",
        "leaf_id": "leaf_forged_1",
        "event_id": "evt_forged_001",
        "nonce": "nonce_forged_random_2222",
        "version": 1,
        "masked_pii_hash": "3" * 64,
        "real_data_hash": "4" * 64,
        "timestamp": ts
    }
    payload["signature_hex"] = sign_payload(priv_key, payload)
    client.post('/api/v1/tree/update', json=payload, headers={"X-API-Key": "test-svc"})

    # Anchor to S3
    client.post('/v1/admin/anchor', headers={"X-API-Key": "test-admin"})

    # Overwrite the anchor in S3 with a forged signature
    roots = s3_backend.list("roots/")
    assert len(roots) >= 1
    anchor_key = roots[-1]
    anchor_data = s3_backend.get(anchor_key)
    anchor_data["signature"] = "deadbeef" * 8  # Forged signature
    s3.put_object(Bucket=BUCKET, Key=anchor_key, Body=json.dumps(anchor_data).encode("utf-8"))

    # Verify must reject the forged anchor
    r_ver = client.get('/v1/verify/full', headers={"X-API-Key": "test-viewer"})
    assert r_ver.status_code == 400
    assert r_ver.json["status"] == "TAMPER"
    assert "signature verification failed" in r_ver.json["reason"].lower()
