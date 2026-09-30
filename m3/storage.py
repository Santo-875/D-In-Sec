"""
m3/storage.py  — Storage Backend abstraction for Module 3.

SQLite is the source of truth. S3 is a write-through sink.
Writes are never lost because of S3 failure: a pending_uploads
table queues failed PUTs and a retry worker re-drains on startup.

Env:
    STORAGE_BACKEND = local | s3   (default: local)
    S3_BUCKET       = <bucket name>
    AWS_REGION      = <region>
    KMS_DATA_KEY_ID = <kms data encryption key id or alias>
    M3_ENV          = dev | prod   (default: dev)
"""

import os
import json
import logging
import threading
import time
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("m3.storage")


# ── Key-naming helpers ──────────────────────────────────────────────────────

def _log_key(tenant_id: str, user_id: str, ts: str, leaf_hash: str) -> str:
    safe_ts = ts.replace(":", "-")
    return f"logs/{tenant_id}/{user_id}/{safe_ts}-{leaf_hash[:16]}.json"

def _root_key(date: str, root_hash: str) -> str:
    return f"roots/{date}-{root_hash[:16]}.json"

def _summary_key(date: str) -> str:
    return f"summaries/{date}.json"

def _model_key(version: str) -> str:
    return f"models/{version}.json"


# ── Abstract backend ────────────────────────────────────────────────────────

class StorageBackend(ABC):
    """Interface every backend must implement."""

    @abstractmethod
    def put_log(self, tenant_id: str, user_id: str, ts: str,
                leaf_hash: str, payload: Dict[str, Any]) -> Optional[str]:
        """Upload a log entry. Returns the key/path or None on failure."""

    @abstractmethod
    def put_root(self, date: str, root_hash: str,
                 payload: Dict[str, Any]) -> Optional[str]:
        """Upload a signed root checkpoint. Returns the key/path or None."""

    @abstractmethod
    def put_summary(self, date: str,
                    payload: Dict[str, Any]) -> Optional[str]:
        """Upload a daily CERT-In summary. Returns the key/path or None."""

    @abstractmethod
    def put_model(self, version: str,
                  payload: Dict[str, Any]) -> Optional[str]:
        """Upload model metadata. Returns the key/path or None."""

    @abstractmethod
    def get(self, key: str) -> Optional[Dict[str, Any]]:
        """Download and parse a stored JSON object. Returns None if missing."""

    @abstractmethod
    def list(self, prefix: str) -> List[str]:
        """List keys/paths under prefix."""

    @abstractmethod
    def anchor(self, tenant_id: str, checkpoint: Dict[str, Any]) -> Optional[str]:
        """
        Write a signed checkpoint to roots/ prefix.
        Returns the key used or None on failure.
        """

    def is_healthy(self) -> bool:
        """Quick reachability check. Override to implement real probe."""
        return True


# ── Local backend (dev / CI) ────────────────────────────────────────────────

class LocalBackend(StorageBackend):
    """
    Stores objects as JSON files under a local directory tree.
    Mirrors the S3 key structure for parity.
    """

    def __init__(self, base_dir: str = "local_storage"):
        self.base_dir = base_dir
        os.makedirs(base_dir, exist_ok=True)

    def _write(self, key: str, payload: Dict[str, Any]) -> str:
        path = os.path.join(self.base_dir, key.replace("/", os.sep))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        return key

    def put_log(self, tenant_id, user_id, ts, leaf_hash, payload):
        return self._write(_log_key(tenant_id, user_id, ts, leaf_hash), payload)

    def put_root(self, date, root_hash, payload):
        return self._write(_root_key(date, root_hash), payload)

    def put_summary(self, date, payload):
        return self._write(_summary_key(date), payload)

    def put_model(self, version, payload):
        return self._write(_model_key(version), payload)

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        path = os.path.join(self.base_dir, key.replace("/", os.sep))
        if not os.path.exists(path):
            return None
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    def list(self, prefix: str) -> List[str]:
        prefix_path = os.path.join(self.base_dir, prefix.replace("/", os.sep))
        results = []
        if not os.path.isdir(prefix_path):
            return results
        for root, _, files in os.walk(prefix_path):
            for fn in files:
                full = os.path.join(root, fn)
                rel = os.path.relpath(full, self.base_dir).replace(os.sep, "/")
                results.append(rel)
        return sorted(results)

    def anchor(self, tenant_id, checkpoint):
        ts_val = checkpoint.get("ts", datetime.now(timezone.utc).isoformat())
        safe_ts = ts_val.replace(":", "-")
        root_hash = checkpoint.get("master_root", "unknown")
        return self.put_root(safe_ts, root_hash, checkpoint)


# ── S3 backend ──────────────────────────────────────────────────────────────

class S3Backend(StorageBackend):
    """
    Stores objects in S3 with SSE-KMS encryption.
    Never raises — returns None on failure (caller queues retry).
    """

    def __init__(self, bucket: str, region: str, kms_data_key_id: str = "", **kwargs):
        import boto3  # lazy import so non-S3 envs don't need boto3 installed
        self.bucket = bucket
        self.region = region
        self.kms_data_key_id = kms_data_key_id or kwargs.get("kms_key_id", "")
        self._s3 = boto3.client("s3", region_name=region)

    def _put(self, key: str, payload: Dict[str, Any]) -> Optional[str]:
        try:
            body = json.dumps(payload).encode("utf-8")
            kwargs: Dict[str, Any] = {
                "Bucket": self.bucket,
                "Key": key,
                "Body": body,
                "ContentType": "application/json",
            }
            # Never send SSE params with the signing key (must use KMS_DATA_KEY_ID)
            signing_key_id = os.environ.get("KMS_KEY_ID", "")
            if self.kms_data_key_id and self.kms_data_key_id != signing_key_id:
                kwargs["ServerSideEncryption"] = "aws:kms"
                kwargs["SSEKMSKeyId"] = self.kms_data_key_id
            self._s3.put_object(**kwargs)
            logger.debug("S3 PUT %s", key)
            return key
        except Exception as exc:
            logger.warning("S3 PUT failed for key=%s: %s", key, exc)
            return None

    def put_log(self, tenant_id, user_id, ts, leaf_hash, payload):
        return self._put(_log_key(tenant_id, user_id, ts, leaf_hash), payload)

    def put_root(self, date, root_hash, payload):
        return self._put(_root_key(date, root_hash), payload)

    def put_summary(self, date, payload):
        return self._put(_summary_key(date), payload)

    def put_model(self, version, payload):
        return self._put(_model_key(version), payload)

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        try:
            resp = self._s3.get_object(Bucket=self.bucket, Key=key)
            return json.loads(resp["Body"].read().decode("utf-8"))
        except Exception as exc:
            logger.debug("S3 GET failed for key=%s: %s", key, exc)
            return None

    def list(self, prefix: str) -> List[str]:
        try:
            paginator = self._s3.get_paginator("list_objects_v2")
            keys = []
            for page in paginator.paginate(Bucket=self.bucket, Prefix=prefix):
                for obj in page.get("Contents", []):
                    keys.append(obj["Key"])
            return sorted(keys)
        except Exception as exc:
            logger.warning("S3 LIST failed for prefix=%s: %s", prefix, exc)
            return []

    def anchor(self, tenant_id, checkpoint):
        ts_val = checkpoint.get("ts", datetime.now(timezone.utc).isoformat())
        safe_ts = ts_val.replace(":", "-")
        root_hash = checkpoint.get("master_root", "unknown")
        return self.put_root(safe_ts, root_hash, checkpoint)

    def is_healthy(self) -> bool:
        try:
            self._s3.head_bucket(Bucket=self.bucket)
            return True
        except Exception:
            return False


# ── Factory ─────────────────────────────────────────────────────────────────

def get_storage_backend() -> StorageBackend:
    """
    Returns the configured StorageBackend.
    Reads STORAGE_BACKEND, S3_BUCKET, AWS_REGION, KMS_DATA_KEY_ID from env.
    """
    backend_type = os.environ.get("STORAGE_BACKEND", "local").lower()
    if backend_type == "s3":
        bucket = os.environ.get("S3_BUCKET", "")
        region = os.environ.get("AWS_REGION", "ap-south-1")
        kms_data_key_id = os.environ.get("KMS_DATA_KEY_ID", "")
        if not bucket:
            raise RuntimeError("STORAGE_BACKEND=s3 but S3_BUCKET is not set.")
        return S3Backend(bucket=bucket, region=region, kms_data_key_id=kms_data_key_id)
    return LocalBackend(base_dir=os.environ.get("LOCAL_STORAGE_DIR", "local_storage"))


# ── Write-through wrapper with pending_uploads retry queue ─────────────────

class DurableStorage:
    """
    Wraps a StorageBackend with a SQLite pending_uploads queue.

    On every put_* call:
      1. Write to backend.
      2. If backend returns None (failed), insert into pending_uploads.
    On startup / via retry_worker(), drain pending_uploads.

    This ensures S3 outages never lose data or block writes.
    """

    def __init__(self, backend: StorageBackend, db):
        """
        Args:
            backend: StorageBackend instance.
            db: M3Database instance (must expose pending_uploads helpers).
        """
        self.backend = backend
        self.db = db
        self._lock = threading.Lock()

    def _queue_retry(self, op: str, payload: Dict[str, Any]) -> None:
        """Persist a failed upload to pending_uploads table."""
        try:
            self.db.enqueue_pending_upload(op, payload)
        except Exception as exc:
            logger.error("Failed to queue pending upload for op=%s: %s", op, exc)

    # ── Delegating put methods that auto-queue on failure ──────────────────

    def put_log(self, tenant_id, user_id, ts, leaf_hash, payload):
        key = None
        try:
            key = self.backend.put_log(tenant_id, user_id, ts, leaf_hash, payload)
        except Exception as exc:
            logger.warning("backend.put_log failed: %s", exc)
        if key is None:
            self._queue_retry("put_log", {
                "tenant_id": tenant_id, "user_id": user_id,
                "ts": ts, "leaf_hash": leaf_hash, "payload": payload
            })
        return key

    def put_root(self, date, root_hash, payload):
        key = None
        try:
            key = self.backend.put_root(date, root_hash, payload)
        except Exception as exc:
            logger.warning("backend.put_root failed: %s", exc)
        if key is None:
            self._queue_retry("put_root", {
                "date": date, "root_hash": root_hash, "payload": payload
            })
        return key

    def put_summary(self, date, payload):
        key = None
        try:
            key = self.backend.put_summary(date, payload)
        except Exception as exc:
            logger.warning("backend.put_summary failed: %s", exc)
        if key is None:
            self._queue_retry("put_summary", {"date": date, "payload": payload})
        return key

    def put_model(self, version, payload):
        key = None
        try:
            key = self.backend.put_model(version, payload)
        except Exception as exc:
            logger.warning("backend.put_model failed: %s", exc)
        if key is None:
            self._queue_retry("put_model", {"version": version, "payload": payload})
        return key

    def anchor(self, tenant_id, checkpoint):
        key = None
        try:
            key = self.backend.anchor(tenant_id, checkpoint)
        except Exception as exc:
            logger.warning("backend.anchor failed: %s", exc)
        if key is None:
            self._queue_retry("anchor", {
                "tenant_id": tenant_id, "checkpoint": checkpoint
            })
        return key

    # Passthrough reads
    def get(self, key):
        try:
            return self.backend.get(key)
        except Exception:
            return None

    def list(self, prefix):
        try:
            return self.backend.list(prefix)
        except Exception:
            return []

    def is_healthy(self):
        try:
            return self.backend.is_healthy()
        except Exception:
            return False

    def pending_count(self) -> int:
        try:
            return self.db.count_pending_uploads()
        except Exception:
            return -1

    # ── Retry worker ───────────────────────────────────────────────────────

    def retry_worker(self, interval_seconds: int = 60) -> None:
        """
        Background loop that drains pending_uploads.
        Call once in a daemon thread on app startup.
        """
        logger.info("Storage retry worker started (interval=%ds).", interval_seconds)
        while True:
            try:
                self._drain_pending()
            except Exception as exc:
                logger.error("retry_worker error: %s", exc)
            time.sleep(interval_seconds)

    def _drain_pending(self) -> None:
        rows = self.db.get_pending_uploads()
        for row in rows:
            upload_id, op, meta_json = row["upload_id"], row["op"], row["meta_json"]
            meta = json.loads(meta_json)
            success = self._replay(op, meta)
            if success:
                self.db.delete_pending_upload(upload_id)
                logger.info("Retried and succeeded pending upload id=%s op=%s", upload_id, op)
            else:
                logger.warning("Pending upload id=%s op=%s still failing.", upload_id, op)

    def _replay(self, op: str, meta: Dict[str, Any]) -> bool:
        """Re-execute a queued storage operation. Returns True on success."""
        try:
            if op == "put_log":
                return self.backend.put_log(
                    meta["tenant_id"], meta["user_id"],
                    meta["ts"], meta["leaf_hash"], meta["payload"]
                ) is not None
            elif op == "put_root":
                return self.backend.put_root(
                    meta["date"], meta["root_hash"], meta["payload"]
                ) is not None
            elif op == "put_summary":
                return self.backend.put_summary(meta["date"], meta["payload"]) is not None
            elif op == "put_model":
                return self.backend.put_model(meta["version"], meta["payload"]) is not None
            elif op == "anchor":
                return self.backend.anchor(meta["tenant_id"], meta["checkpoint"]) is not None
        except Exception as exc:
            logger.warning("Replay op=%s failed: %s", op, exc)
        return False
