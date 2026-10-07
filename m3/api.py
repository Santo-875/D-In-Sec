"""
Standalone REST API Server for Module 3 (M3).

Provides endpoints for identity key registration, hierarchical Merkle tree updates,
signature verification, CERT-In audit log retention management, write-freeze mitigation,
independent proof verification, and M4 anomaly verification payload exports.

Security:
  - Token-based authentication via X-API-Key header
  - Role-based access control (ADMIN / SERVICE / VIEWER)
  - Anti-replay protection (nonce, event_id, timestamp validation)
  - Decoupled public-key registration (admin-only)

Runs independently on port 5001.
"""

import os
import sys
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

# Load .env
env_file = BASE_DIR / ".env"
if env_file.exists():
    load_dotenv(dotenv_path=env_file)

import json
import re
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from flask import Flask, jsonify, request

from m3.anchoring import ExternalAnchor
from m3.audit_log import AppendOnlyAuditLog
from m3.auth import require_role
from m3.breach_alert import generate_breach_alert, record_breach_alert_to_db
from m3.crypto_signer import (
    PublicKeyRegistry,
    generate_rsa_key_pair,
    get_public_key_fingerprint,
    verify_signature,
)
from m3.database import M3Database
from m3.freeze_manager import FreezeManager
from m3.m4_interface import M4PayloadFormatter
from m3.merkle_tree import HierarchicalMerkleTree
from m3.replay_guard import ReplayGuard
from m3.signer import get_signer
from m3.storage import DurableStorage, get_storage_backend


def create_m3_app(db_path="m3.db", anchor_path="external_anchor.log",
                  storage_backend=None, signer_instance=None):
    app = Flask(__name__)

    # 1. Initialize Persistence Layer
    db = M3Database(db_path)
    storage_backend_name = os.environ.get("STORAGE_BACKEND", "local").lower()
    external_anchor = ExternalAnchor(anchor_path) if storage_backend_name == "local" else None

    # 2. Initialize Storage & Signer backends
    _raw_storage = storage_backend if storage_backend is not None else get_storage_backend()
    storage = DurableStorage(backend=_raw_storage, db=db)
    try:
        signer = signer_instance if signer_instance is not None else get_signer()
    except Exception as _e:
        import logging as _log
        _log.getLogger("m3.api").warning("Signer init failed (dev mode): %s", _e)
        signer = None

    # Default tenant (multi-tenant: pass X-Tenant-ID header or env TENANT_ID)
    DEFAULT_TENANT = os.environ.get("TENANT_ID", "default")

    # 3. Initialize Core M3 Engine Instances (Loaded from DB)
    registry = PublicKeyRegistry(db=db)
    tree = HierarchicalMerkleTree(db=db)
    audit_log = AppendOnlyAuditLog(db=db, external_anchor=external_anchor)
    freeze_mgr = FreezeManager(db=db)
    replay_guard = ReplayGuard(db=db)

    app.tree = tree
    app.storage = storage
    app.signer = signer
    app.config['M3_DB_PATH'] = db_path

    ANCHOR_EVERY_N = int(os.environ.get("ANCHOR_EVERY_N", "10"))
    ANCHOR_EVERY_SEC = int(os.environ.get("ANCHOR_EVERY_SEC", "300"))
    app._write_count = 0
    app._last_anchor_time = time.time()
    app._anchor_lock = threading.Lock()

    def _do_anchor(tenant_id=DEFAULT_TENANT):
        leaf_count = sum(len(subroot.leaves) for subroot in tree.user_subroots.values())
        ts = datetime.now(timezone.utc).isoformat()
        master_root = tree.master_root
        key_id = getattr(signer, "_key_id", getattr(signer, "fingerprint", "local")) if signer else "none"

        checkpoint_data = {
            "tenant": tenant_id,
            "master_root": master_root,
            "leaf_count": leaf_count,
            "ts": ts,
            "key_id": key_id
        }

        sig = ""
        if signer:
            try:
                sig = signer.sign(checkpoint_data)
            except Exception as exc:
                import logging
                logging.getLogger("m3.api").warning("Signer failed to sign anchor: %s", exc)
                sig = ""

        checkpoint = dict(checkpoint_data)
        checkpoint["signature"] = sig

        try:
            anchor_key = storage.anchor(tenant_id, checkpoint)
            return {"checkpoint": checkpoint, "key": anchor_key}
        except Exception as exc:
            import logging
            logging.getLogger("m3.api").warning("storage.anchor failed (queued): %s", exc)
            return {"checkpoint": checkpoint, "key": None}

    def _verify_anchor_signature(anchor_dict: dict[str, Any]) -> bool:
        if not isinstance(anchor_dict, dict):
            return False
        sig = anchor_dict.get("signature")
        if not sig:
            return False
        signable = {k: v for k, v in anchor_dict.items() if k != "signature"}

        pub_key_pem = None
        if signer is not None:
            try:
                pub_key_pem = signer.public_key_pem
            except Exception:
                pub_key_pem = None

        if not pub_key_pem:
            if os.environ.get("SIGNER_BACKEND") == "kms" and os.environ.get("KMS_KEY_ID"):
                try:
                    import boto3
                    kms = boto3.client("kms", region_name=os.environ.get("AWS_REGION", "ap-south-1"))
                    resp = kms.get_public_key(KeyId=os.environ.get("KMS_KEY_ID"))
                    from cryptography.hazmat.primitives.serialization import (
                        Encoding,
                        PublicFormat,
                        load_der_public_key,
                    )
                    pub = load_der_public_key(resp["PublicKey"])
                    pub_key_pem = pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode('utf-8')
                except Exception:
                    pass
            elif os.environ.get("M3_SIGNING_PRIVATE_KEY"):
                from m3.crypto_signer import (
                    get_public_key_from_private_pem,
                    load_private_key_from_env,
                )
                priv = load_private_key_from_env()
                if priv:
                    pub_key_pem = get_public_key_from_private_pem(priv)

        if not pub_key_pem:
            return False

        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives.serialization import load_pem_public_key

        from m3.crypto_signer import canonicalize_payload

        try:
            public_key = load_pem_public_key(pub_key_pem.encode('utf-8'), backend=default_backend())
            sig_bytes = bytes.fromhex(sig)
            data = canonicalize_payload(signable)
            # Try RSASSA-PSS (KMS)
            try:
                public_key.verify(
                    sig_bytes,
                    data,
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.AUTO),
                    hashes.SHA256()
                )
                return True
            except Exception:
                pass
            # Try PKCS1v15 (LocalRSASigner)
            try:
                public_key.verify(
                    sig_bytes,
                    data,
                    padding.PKCS1v15(),
                    hashes.SHA256()
                )
                return True
            except Exception:
                pass
        except Exception:
            pass
        return False

    # 4. Resume pending AI jobs
    def _resume_ai_job(facts_copy: dict, j_id: str):
        try:
            alert = generate_breach_alert(facts_copy)
            record_breach_alert_to_db(alert)
            db.update_ai_job_status(j_id, "COMPLETED", datetime.now(timezone.utc).isoformat())
        except Exception as e:
            db.update_ai_job_status(j_id, f"FAILED: {e!s}", datetime.now(timezone.utc).isoformat())

    for job in db.get_pending_ai_jobs():
        thread = threading.Thread(
            target=_resume_ai_job,
            args=(job["facts"], job["job_id"]),
            daemon=True
        )
        thread.start()

    # 5. Start storage retry worker
    _retry_thread = threading.Thread(
        target=storage.retry_worker,
        kwargs={"interval_seconds": int(os.environ.get("STORAGE_RETRY_INTERVAL", "60"))},
        daemon=True
    )
    _retry_thread.start()

    # ── Health & Readiness ─────────────────────────────────────────────────

    @app.route('/healthz', methods=['GET'])
    def healthz():
        """Liveness probe — always 200 if process is alive."""
        return jsonify({"status": "alive"}), 200

    @app.route('/readyz', methods=['GET'])
    def readyz():
        """Readiness probe — reports S3 reachability and pending upload backlog."""
        s3_ok = storage.is_healthy()
        backlog = storage.pending_count()
        status = "ready" if s3_ok else "degraded"
        return jsonify({
            "status": status,
            "storage_healthy": s3_ok,
            "pending_uploads_backlog": backlog
        }), 200 if s3_ok else 503

    # ── Public Endpoints ─────────────────────────────────────────────────

    @app.route('/api/v1/health', methods=['GET'])
    def health():
        """Public health check — no authentication required."""
        return jsonify({
            "status": "healthy",
            "module": "Module 3 — Identity & Merkle Tree Integrity Engine",
            "master_root": tree.master_root,
            "replay_guard_stats": replay_guard.get_stats()
        }),200

    # ── ADMIN Endpoints ──────────────────────────────────────────────────

    @app.route('/api/v1/identity/generate-keys', methods=['POST'])
    @require_role("ADMIN")
    def generate_keys():
        """Generates a new RSA-2048 key pair. ADMIN only."""
        private_pem, public_pem = generate_rsa_key_pair()
        fingerprint = get_public_key_fingerprint(public_pem)
        return jsonify({
            "private_key_pem": private_pem,
            "public_key_pem": public_pem,
            "fingerprint": fingerprint
        }), 201

    @app.route('/api/v1/identity/register', methods=['POST'])
    @require_role("ADMIN")
    def register_identity():
        """
        Registers a public key for a user/developer identity. ADMIN only.

        This is a trusted operation — the admin pre-registers keys for authorized
        identities. The /tree/update endpoint only accepts signatures from
        pre-registered keys.
        """
        data = request.get_json() or {}
        identity_id = data.get("identity_id")
        public_key_pem = data.get("public_key_pem")

        if not identity_id or not public_key_pem:
            return jsonify({"error": "Missing identity_id or public_key_pem"}), 400

        fingerprint = registry.register_key(identity_id, public_key_pem)
        return jsonify({
            "message": "Public key registered successfully",
            "identity_id": identity_id,
            "fingerprint": fingerprint
        }), 200

    @app.route('/api/v1/identity/revoke', methods=['POST'])
    @require_role("ADMIN")
    def revoke_identity():
        data = request.get_json() or {}
        identity_id = data.get("identity_id")

        if not identity_id:
            return jsonify({"error": "Missing identity_id"}), 400

        success = db.revoke_identity(identity_id)
        if not success:
            return jsonify({"error": f"Identity '{identity_id}' not found"}), 404

        registry._load_from_db()
        db.save_admin_audit_log("REVOKE_IDENTITY", identity_id, "Key revoked", datetime.now(timezone.utc).isoformat())
        return jsonify({
            "message": "Public key revoked successfully",
            "identity_id": identity_id
        }), 200

    @app.route('/api/v1/freeze', methods=['POST'])
    @require_role("ADMIN")
    def freeze():
        """Triggers write-freeze on master or subtree. ADMIN only."""
        data = request.get_json() or {}
        target = data.get("target", "master")
        user_id = data.get("user_id")
        reason = data.get("reason", "Security alert triggered")

        if target == "master":
            res = freeze_mgr.freeze_master(reason)
            db.save_admin_audit_log("FREEZE_MASTER", "ALL", reason, datetime.now(timezone.utc).isoformat())
        elif target == "subtree" and user_id:
            res = freeze_mgr.freeze_subtree(user_id, reason)
            db.save_admin_audit_log("FREEZE_SUBTREE", user_id, reason, datetime.now(timezone.utc).isoformat())
        else:
            return jsonify({"error": "Invalid freeze target or missing user_id for subtree"}), 400

        return jsonify({"message": f"{target} frozen", "details": res}), 200

    @app.route('/api/v1/audit/verify-anchor', methods=['GET'])
    @require_role("ADMIN", "VIEWER")
    def verify_external_anchor():
        """
        Verifies that the current Master Root mathematically matches the
        latest checkpoint written to the external anchor file.
        """
        if not audit_log.external_anchor or not os.path.exists(audit_log.external_anchor.anchor_file_path):
            return jsonify({"status": "FAILED", "reason": "No external anchor file found"}), 404
            
        anchor_file = audit_log.external_anchor.anchor_file_path
        with open(anchor_file, 'r') as f:
            lines = [l.strip() for l in f if l.strip()]
            
        if not lines:
            return jsonify({"status": "FAILED", "reason": "External anchor file is empty"}), 404
            
        try:
            # Handle potential non-JSON lines or multiple lines
            latest_line = lines[-1]
            if isinstance(latest_line, str):
                latest_anchor_data = json.loads(latest_line)
            else:
                latest_anchor_data = latest_line
                
            if isinstance(latest_anchor_data, str):
                latest_anchor_data = json.loads(latest_anchor_data)
                
            latest_anchor = latest_anchor_data.get("master_root")
            if not latest_anchor:
                return jsonify({"status": "FAILED", "reason": "No master_root in anchor data"}), 400
        except (json.JSONDecodeError, TypeError) as e:
            return jsonify({"status": "FAILED", "reason": f"Anchor file format is invalid: {e!s}"}), 400
        
        if latest_anchor == tree.master_root:
            return jsonify({
                "status": "VERIFIED",
                "message": "Master root perfectly matches the external anchor.",
                "anchor": latest_anchor
            }), 200
        else:
            return jsonify({
                "status": "FAILED",
                "reason": "Master root divergence detected! External anchor mismatch.",
                "expected_anchor": latest_anchor,
                "actual_root": tree.master_root
            }), 400

    @app.route('/api/v1/unfreeze', methods=['POST'])
    @require_role("ADMIN")
    def unfreeze():
        """Lifts write-freeze on master or subtree. ADMIN only."""
        data = request.get_json() or {}
        target = data.get("target", "master")
        user_id = data.get("user_id")
        reason = data.get("reason", "Administrative action")

        if target == "master":
            res = freeze_mgr.unfreeze_master()
            db.save_admin_audit_log("UNFREEZE_MASTER", "ALL", reason, datetime.now(timezone.utc).isoformat())
        elif target == "subtree" and user_id:
            res = freeze_mgr.unfreeze_subtree(user_id)
            db.save_admin_audit_log("UNFREEZE_SUBTREE", user_id, reason, datetime.now(timezone.utc).isoformat())
        else:
            return jsonify({"error": "Invalid unfreeze target or missing user_id for subtree"}), 400

        return jsonify({"message": f"{target} unfrozen", "details": res}), 200

    @app.route('/api/v1/audit/prune', methods=['POST'])
    @require_role("ADMIN")
    def prune_audit_logs():
        """
        Executes CERT-In 180-day retention pruning. ADMIN only.
        Detailed logs older than 180 days are purged; 32-byte root checkpoints remain permanently.
        """
        data = request.get_json() or {}
        days = data.get("days", 180)
        result = audit_log.prune_logs_older_than(days=days)
        return jsonify(result), 200

    # ── SERVICE Endpoints (Module 2 pipeline) ────────────────────────────

    @app.route('/tree/update', methods=['POST'])
    @app.route('/api/v1/tree/update', methods=['POST'])
    @require_role("ADMIN", "SERVICE")
    def update_tree():
        """
        Submits a signed update request. SERVICE or ADMIN role required.

        Security pipeline:
        1. Validates write-freeze status.
        2. Anti-replay check (event_id, nonce, timestamp).
        3. Looks up pre-registered public key (no auto-registration).
        4. Verifies cryptographic RSA signature.
        5. Recalculates O(log n) path: Leaf -> User Subroot -> Master Root.
        6. Logs event in append-only log and permanent root chain.
        7. Formats M4 output payload.
        """
        data = request.get_json() or {}
        user_id = data.get("user_id")
        leaf_id = data.get("leaf_id")
        masked_pii_hash = data.get("masked_pii_hash")
        real_data_hash = data.get("real_data_hash")
        timestamp = data.get("timestamp")
        signature_hex = data.get("signature_hex")
        event_id = data.get("event_id")
        nonce = data.get("nonce")
        version = data.get("version")

        if not all([user_id, leaf_id, masked_pii_hash, real_data_hash, signature_hex, timestamp, event_id, nonce, version]):
            return jsonify({"error": "Missing required parameters: user_id, leaf_id, masked_pii_hash, real_data_hash, signature_hex, timestamp, event_id, nonce, version"}), 400

        # Input Validation
        try:
            version = int(version)
            if version <= 0:
                raise ValueError
        except ValueError:
            return jsonify({"error": "Version must be a positive integer"}), 400
            
        if not re.match(r"^[a-fA-F0-9]{64}$", masked_pii_hash) or not re.match(r"^[a-fA-F0-9]{64}$", real_data_hash):
            return jsonify({"error": "Invalid hash format. Must be 64-character hex."}), 400
        
        # ID and Nonce Validation
        id_pattern = r"^[a-zA-Z0-9_-]{1,64}$"
        if not re.match(id_pattern, user_id) or not re.match(id_pattern, leaf_id) or not re.match(id_pattern, event_id):
            return jsonify({"error": "Identifiers must be alphanumeric with underscores/dashes and <= 64 chars."}), 400
        if not re.match(r"^[a-zA-Z0-9_-]{16,64}$", nonce):
            return jsonify({"error": "Nonce must be high-entropy alphanumeric and between 16 to 64 chars."}), 400

        # Timestamp Validation (ISO-8601 UTC)
        try:
            # Enforce UTC timezone by replacing Z with +00:00 for strict parsing
            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            if dt.tzinfo is None:
                raise ValueError
        except ValueError:
            return jsonify({"error": "Timestamp must be a valid ISO-8601 UTC string (e.g., ending with Z or +00:00)."}), 400
        # 1. Look up pre-registered public key — NO auto-registration
        public_key_pem = registry.get_public_key(user_id)
        if not public_key_pem:
            return jsonify({
                "error": f"No public key registered for identity '{user_id}'",
                "detail": "Keys must be pre-registered via /identity/register by an ADMIN."
            }), 401
        elif public_key_pem == "REVOKED":
            return jsonify({
                "error": f"Identity '{user_id}' has been revoked.",
                "detail": "Cannot accept updates from a revoked identity."
            }), 401

        # 3. Reconstruct signed payload and verify signature
        signable_payload = {
            "user_id": user_id,
            "leaf_id": leaf_id,
            "event_id": event_id,
            "nonce": nonce,
            "version": version,
            "masked_pii_hash": masked_pii_hash,
            "real_data_hash": real_data_hash,
            "timestamp": timestamp
        }
        if not verify_signature(public_key_pem, signable_payload, signature_hex):
            return jsonify({
                "error": "Invalid signature. Signature verification failed.",
                "signature_status": "REJECTED"
            }), 401

        fingerprint = get_public_key_fingerprint(public_key_pem)

        # 4. Get old leaf hash if existing
        old_subroot = tree.user_subroots.get(user_id)
        old_leaf_hash = old_subroot.leaves[leaf_id].combined_hash if old_subroot and leaf_id in old_subroot.leaves else None

        # 5. Execute hierarchical tree update and DB save in a single transaction
        from contextlib import closing
        try:
            with closing(db.get_connection()) as conn:
                with conn:
                    # 5a. Check write-freeze status
                    frozen, freeze_reason = freeze_mgr.is_frozen(user_id)
                    if frozen:
                        return jsonify({
                            "error": "Write operations are currently frozen",
                            "reason": freeze_reason
                        }), 403

                    # 5b. Anti-replay validation (locks in-memory and writes to DB via conn)
                    replay_valid, replay_reason = replay_guard.validate_request(
                        event_id=event_id,
                        nonce=nonce,
                        timestamp=timestamp,
                        user_id=user_id,
                        leaf_id=leaf_id,
                        version=version,
                        conn=conn
                    )
                    if not replay_valid:
                        return jsonify({
                            "error": "Replay attack detected",
                            "detail": replay_reason
                        }), 409

                    # 5c. Update Merkle Tree
                    update_proof = tree.update_leaf(
                        user_id=user_id,
                        leaf_id=leaf_id,
                        masked_pii_hash=masked_pii_hash,
                        real_data_hash=real_data_hash,
                        timestamp=timestamp,
                        conn=conn
                    )

                    # 5d. Log event in append-only log and permanent root chain
                    audit_entry = audit_log.log_event(
                        user_id=user_id,
                        leaf_id=leaf_id,
                        old_leaf_hash=old_leaf_hash,
                        new_leaf_hash=update_proof["leaf"]["combined_hash"],
                        old_master_root=update_proof["old_master_root"],
                        new_master_root=update_proof["new_master_root"],
                        signature_hex=signature_hex,
                        signer_fingerprint=fingerprint,
                        timestamp=timestamp,
                        event_id=event_id,
                        conn=conn
                    )

                    # 5e. Format and save M4 payload
                    m4_payload = M4PayloadFormatter.format_m4_payload(
                        audit_entry=audit_entry,
                        update_proof=update_proof,
                        signature_valid=True,
                        freeze_status=freeze_mgr.get_freeze_status()
                    )
                    db.save_m4_payload(audit_entry.event_id, m4_payload, conn=conn)
        except Exception as e:
            print(f"Error updating tree: {e!s}")
            # Rollback in-memory state to match DB
            tree._load_from_db()
            audit_log._load_from_db()
            replay_guard._load_from_db()
            return jsonify({"error": "Failed to update tree", "detail": str(e)}), 500

        # AFTER SQLite commit: call storage.put_log & anchor if threshold met
        tenant_id = request.headers.get("X-Tenant-ID", DEFAULT_TENANT)
        try:
            storage.put_log(
                tenant_id=tenant_id,
                user_id=user_id,
                ts=timestamp,
                leaf_hash=audit_entry.new_leaf_hash,
                payload=m4_payload
            )
        except Exception as exc:
            import logging
            logging.getLogger("m3.api").warning("storage.put_log failed (queued): %s", exc)

        should_anchor = False
        with app._anchor_lock:
            app._write_count += 1
            now = time.time()
            if (app._write_count >= ANCHOR_EVERY_N) or ((now - app._last_anchor_time) >= ANCHOR_EVERY_SEC):
                should_anchor = True
                app._write_count = 0
                app._last_anchor_time = now

        if should_anchor:
            _do_anchor(tenant_id)

        return jsonify({
            "status": "SUCCESS",
            "message": "Leaf updated and Master Root recomputed successfully",
            "event_id": audit_entry.event_id,
            "old_master_root": update_proof["old_master_root"],
            "calculated_next_master_root": update_proof["new_master_root"],
            "update_proof": update_proof,
            "m4_payload": m4_payload
        }), 200

    # ── VIEWER Endpoints (read-only) ─────────────────────────────────────

    @app.route('/api/v1/tree/root', methods=['GET'])
    @require_role("ADMIN", "SERVICE", "VIEWER")
    def get_root():
        """Returns current Master Root state and permanent root chain."""
        return jsonify({
            "master_root": tree.master_root,
            "total_user_subroots": len(tree.user_subroots),
            "permanent_root_chain_length": len(audit_log.get_permanent_root_chain()),
            "permanent_root_chain": audit_log.get_permanent_root_chain()
        }), 200

    @app.route('/api/v1/tree/snapshot', methods=['GET'])
    @require_role("ADMIN", "SERVICE", "VIEWER")
    def get_tree_snapshot():
        """Returns full hierarchical Merkle snapshot and recent root history without PII."""
        users_list = []
        for u_id, subroot in tree.user_subroots.items():
            leaves_list = []
            for leaf in subroot.leaves.values():
                leaves_list.append({
                    "leaf_id": leaf.leaf_id,
                    "version": leaf.version,
                    "combined_hash": leaf.combined_hash,
                    "timestamp": leaf.timestamp
                })
            users_list.append({
                "user_id": u_id,
                "subroot_hash": subroot.subroot_hash,
                "leaf_count": len(subroot.leaves),
                "leaves": leaves_list
            })

        recent_entries = audit_log._detailed_logs[-50:] if hasattr(audit_log, "_detailed_logs") else []
        root_history = []
        for entry in recent_entries:
            if isinstance(entry, dict):
                root_history.append({
                    "event_id": entry.get("event_id"),
                    "timestamp": entry.get("timestamp"),
                    "user_id": entry.get("user_id"),
                    "leaf_id": entry.get("leaf_id"),
                    "old_master_root": entry.get("old_master_root"),
                    "new_master_root": entry.get("new_master_root"),
                })
            else:
                root_history.append({
                    "event_id": getattr(entry, "event_id", None),
                    "timestamp": getattr(entry, "timestamp", None),
                    "user_id": getattr(entry, "user_id", None),
                    "leaf_id": getattr(entry, "leaf_id", None),
                    "old_master_root": getattr(entry, "old_master_root", None),
                    "new_master_root": getattr(entry, "new_master_root", None),
                })

        return jsonify({
            "master_root": tree.master_root,
            "users": users_list,
            "root_history": root_history
        }), 200

    @app.route('/api/v1/tree/proof/<user_id>/<leaf_id>', methods=['GET'])
    @require_role("ADMIN", "SERVICE", "VIEWER")
    def get_proof(user_id, leaf_id):
        """Generates cryptographic inclusion proof for a leaf."""
        if user_id not in tree.user_subroots:
            return jsonify({"error": f"User '{user_id}' not found"}), 404
        
        proof = tree.generate_full_proof(user_id, leaf_id)
        if proof is None:
            return jsonify({"error": f"Leaf '{leaf_id}' not found for user '{user_id}'"}), 404
            
        return jsonify(proof), 200

    @app.route('/api/v1/tree/verify-leaf', methods=['POST'])
    @require_role("ADMIN", "SERVICE", "VIEWER")
    def verify_leaf():
        """
        Verifies leaf integrity against current tree state.
        On tamper detection (hash mismatch):
          - Gathers deterministic facts immediately.
          - Fires breach alert generation + DB persistence in a background thread
            so the HTTP response is never delayed by Gemini latency.
          - Returns the deterministic mismatch fact set synchronously.
        """
        import threading

        data = request.get_json() or {}
        user_id = data.get("user_id")
        leaf_id = data.get("leaf_id")
        masked_pii_hash = data.get("masked_pii_hash")
        real_data_hash = data.get("real_data_hash")

        if not all([user_id, leaf_id, masked_pii_hash, real_data_hash]):
            return jsonify({"error": "Missing required parameters: user_id, leaf_id, masked_pii_hash, real_data_hash"}), 400

        # Prompt Injection Protection: validate IDs before they ever reach the AI
        id_pattern = r"^[a-zA-Z0-9_-]{1,64}$"
        if not re.match(id_pattern, user_id) or not re.match(id_pattern, leaf_id):
            return jsonify({"error": "Identifiers must be alphanumeric with underscores/dashes and <= 64 chars."}), 400

        # 1. Deterministic SHA-256 check — no AI involved in this decision
        is_valid, expected_hash, actual_hash = tree.check_leaf_integrity(
            user_id, leaf_id, masked_pii_hash, real_data_hash
        )

        response_body = {
            "user_id": user_id,
            "leaf_id": leaf_id,
            "integrity_verified": is_valid
        }

        if not is_valid:
            if expected_hash is None and actual_hash is None:
                response_body["error"] = "LEAF_NOT_FOUND"
                return jsonify(response_body), 404
                
            detected_at = datetime.now(timezone.utc).isoformat()
            facts = {
                "affected_user": user_id,
                "leaf_id": leaf_id,
                "expected_hash": expected_hash or "LEAF_NOT_FOUND",
                "actual_hash": actual_hash or "LEAF_NOT_FOUND",
                "detected_at": detected_at
            }

            # Expose the deterministic facts immediately in the response
            response_body["tamper_detected"] = True
            response_body["tamper_facts"] = {
                "affected_user": user_id,
                "leaf_id": leaf_id,
                "detected_at": detected_at,
                "expected_hash": (expected_hash or "")[:16] + "...",
                "actual_hash": (actual_hash or "")[:16] + "...",
            }
            response_body["message"] = (
                f"Tamper detected for user '{user_id}' record '{leaf_id}'. "
                f"AI breach alert generation and SOC notification dispatched in background."
            )

            # 2. Rate Limiting / Deduplication for Breach Alerts
            if not hasattr(app, '_alert_cache'):
                app._alert_cache = {}
            
            cache_key = f"{user_id}:{leaf_id}"
            now = time.time()
            if cache_key in app._alert_cache and (now - app._alert_cache[cache_key]) < 300:
                response_body["message"] = (
                    f"Tamper detected for user '{user_id}' record '{leaf_id}'. "
                    f"Alert already dispatched recently (rate-limited)."
                )
                return jsonify(response_body), 400
            
            app._alert_cache[cache_key] = now

            # 3. Fire AI alert generation + DB write in background — never blocks the response
            job_id = f"job_{uuid.uuid4().hex[:12]}"
            db.save_ai_job(job_id, "PENDING", facts, detected_at)

            def _background_alert(facts_copy: dict, j_id: str):
                try:
                    alert = generate_breach_alert(facts_copy)
                    record_breach_alert_to_db(alert)
                    db.update_ai_job_status(j_id, "COMPLETED", datetime.now(timezone.utc).isoformat())
                except Exception as e:
                    try:
                        db.update_ai_job_status(j_id, f"FAILED: {e!s}", datetime.now(timezone.utc).isoformat())
                    except Exception:
                        pass

            thread = threading.Thread(
                target=_background_alert,
                args=(facts, job_id),
                daemon=True
            )
            thread.start()

        return jsonify(response_body), 200

    @app.route('/api/v1/tree/verify-proof', methods=['POST'])
    @require_role("ADMIN", "SERVICE", "VIEWER")
    def verify_proof():
        """
        Independently verifies a Merkle inclusion proof.

        Accepts a proof path and recomputes the root from leaf hash up,
        without accessing the tree state. Suitable for third-party verification.
        """
        data = request.get_json() or {}
        leaf_hash = data.get("leaf_hash")
        leaf_proof = data.get("leaf_proof", [])
        subroot_proof = data.get("subroot_proof", [])
        user_id = data.get("user_id")
        claimed_master_root = data.get("claimed_master_root")

        if not all([leaf_hash, user_id, claimed_master_root]):
            return jsonify({"error": "Missing required parameters: leaf_hash, user_id, claimed_master_root"}), 400

        is_valid, computed_root = HierarchicalMerkleTree.verify_proof(
            leaf_hash=leaf_hash,
            leaf_proof=leaf_proof,
            subroot_proof=subroot_proof,
            user_id=user_id,
            claimed_master_root=claimed_master_root
        )

        return jsonify({
            "proof_valid": is_valid,
            "computed_master_root": computed_root,
            "claimed_master_root": claimed_master_root,
            "user_id": user_id,
            "leaf_hash": leaf_hash
        }), 200

    @app.route('/audit/verify', methods=['POST'])
    @app.route('/api/v1/audit/verify', methods=['POST'])
    @require_role("ADMIN", "SERVICE", "VIEWER")
    def verify_audit_chain():
        """
        End-to-end Merkle proof verification.
        Recalculates leaf hash, verifies proof to master root, and compares with storage anchor.
        """
        data = request.get_json() or {}
        user_id = data.get("user_id")
        leaf_id = data.get("leaf_id")
        masked_pii_hash = data.get("masked_pii_hash")
        real_data_hash = data.get("real_data_hash")

        if not all([user_id, leaf_id, masked_pii_hash, real_data_hash]):
            return jsonify({"error": "Missing required parameters"}), 400

        # Prompt Injection Protection: validate IDs before processing
        id_pattern = r"^[a-zA-Z0-9_-]{1,64}$"
        if not re.match(id_pattern, user_id) or not re.match(id_pattern, leaf_id):
            return jsonify({"error": "Identifiers must be alphanumeric with underscores/dashes and <= 64 chars."}), 400

        # Step 1: Check leaf integrity (recalculate hash from current DB)
        is_leaf_valid, expected_hash, actual_hash = tree.check_leaf_integrity(
            user_id, leaf_id, masked_pii_hash, real_data_hash
        )

        if not is_leaf_valid:
            if expected_hash is None and actual_hash is None:
                return jsonify({
                    "status": "FAILED",
                    "reason": "LEAF_NOT_FOUND"
                }), 404
            return jsonify({
                "status": "FAILED",
                "reason": "Leaf hash recalculation mismatch. Tampering detected."
            }), 400

        # Step 2: Generate current inclusion proof
        proof = tree.generate_full_proof(user_id, leaf_id)
        if not proof:
            return jsonify({"error": "Failed to generate proof. Leaf might not exist."}), 404

        # Step 3: Verify proof against the current Master Root
        is_proof_valid, computed_master = HierarchicalMerkleTree.verify_proof(
            leaf_hash=actual_hash,
            leaf_proof=proof["leaf_proof"],
            subroot_proof=proof["subroot_proof"],
            user_id=user_id,
            claimed_master_root=tree.master_root
        )

        if not is_proof_valid:
            return jsonify({
                "status": "FAILED",
                "reason": "Merkle proof verification failed. Path has been tampered."
            }), 400

        # Step 4: Compare with latest anchor from storage (not local file)
        anchor_keys = storage.list("roots/")
        if not anchor_keys:
            return jsonify({
                "status": "UNVERIFIED",
                "reason": "No anchors found in storage. Cannot verify.",
                "leaf_hash": actual_hash,
                "master_root": computed_master
            }), 200

        latest_key = max(anchor_keys)
        anchor_data = storage.get(latest_key)
        if not anchor_data or not anchor_data.get("master_root"):
            return jsonify({
                "status": "UNVERIFIED",
                "reason": "Anchor object unreachable in storage. Cannot verify.",
                "leaf_hash": actual_hash,
                "master_root": computed_master
            }), 200

        latest_anchor = anchor_data.get("master_root")
        if latest_anchor != computed_master:
            return jsonify({
                "status": "FAILED",
                "reason": "Master root perfectly matches DB but diverges from storage anchor! Severe tampering detected.",
                "expected_anchor": latest_anchor,
                "actual_root": computed_master
            }), 400

        if not _verify_anchor_signature(anchor_data):
            return jsonify({
                "status": "FAILED",
                "reason": "Anchor signature verification failed! Forged or invalid anchor signature.",
                "expected_anchor": latest_anchor,
                "actual_root": computed_master
            }), 400

        return jsonify({
            "status": "VERIFIED",
            "message": "End-to-end Merkle verification succeeded, including storage anchor match and signature verification.",
            "leaf_hash": actual_hash,
            "master_root": computed_master,
            "anchored_root": latest_anchor,
            "anchor_key": latest_key
        }), 200

    @app.route('/api/v1/audit/logs', methods=['GET'])
    @require_role("ADMIN", "SERVICE", "VIEWER")
    def get_audit_logs():
        """Returns detailed append-only audit log."""
        return jsonify({
            "count": len(audit_log._detailed_logs),
            "detailed_logs": audit_log.get_all_detailed_logs()
        }), 200

    @app.route('/api/v1/audit/anchors', methods=['GET'])
    @require_role("ADMIN", "SERVICE", "VIEWER")
    def get_external_anchors():
        """Exports permanent 32-byte root checkpoints for external WORM / RFC 3161 anchoring."""
        return jsonify({
            "count": len(audit_log.export_external_anchors()),
            "anchors": audit_log.export_external_anchors()
        }), 200

    @app.route('/api/v1/m4/payload/<event_id>', methods=['GET'])
    @require_role("VIEWER")
    def get_m4_payload(event_id):
        """
        Retrieves the verified payload required by Module 4 (SOC/AI) to make a determination.
        """
        if not db:
            return jsonify({"error": "Database not initialized"}), 500
            
        payload = db.load_m4_payload(event_id)
        if not payload:
            return jsonify({"error": "Payload not found for event_id"}), 404
        return jsonify(payload), 200

    # ── Phase 1: Full verification + S3 anchor check ─────────────────────

    @app.route('/v1/verify/full', methods=['GET'])
    @app.route('/api/v1/verify/full', methods=['GET'])
    @require_role("ADMIN", "SERVICE", "VIEWER")
    def full_verify():
        """
        Recomputes all subroots + master root from DB and compares with storage anchor.
        Deterministic — AI never participates in the pass/fail decision.
        Anchor must match DB root AND anchor signature must verify.
        On mismatch or forged signature: saves alert + triggers freeze.
        If anchor unreachable: returns UNVERIFIED (never VERIFIED).
        """
        # Step 1: Recompute master root from DB
        db_root = tree.master_root

        # Step 2: Fetch latest anchored root from storage
        anchor_keys = storage.list("roots/")
        if not anchor_keys:
            return jsonify({
                "status": "UNVERIFIED",
                "reason": "No anchors found in storage. Cannot verify.",
                "db_root": db_root
            }), 200

        # Get the latest (lexicographically last by key)
        latest_key = max(anchor_keys)
        anchor_data = storage.get(latest_key)
        if not anchor_data or not anchor_data.get("master_root"):
            return jsonify({
                "status": "UNVERIFIED",
                "reason": "Anchor object unreachable in storage. Cannot verify.",
                "db_root": db_root
            }), 200

        anchored_root = anchor_data.get("master_root")

        # Step 3: Compare master root with anchor
        if db_root != anchored_root:
            alert_id = f"alert_{uuid.uuid4().hex[:12]}"
            db.save_alert(
                alert_id=alert_id,
                alert_type="FULL_VERIFY_MISMATCH",
                severity="CRITICAL",
                details={"db_root": db_root, "anchored_root": anchored_root, "anchor_key": latest_key}
            )
            freeze_mgr.freeze_master("Full-verify mismatch detected — automatic integrity freeze.")
            return jsonify({
                "status": "TAMPER",
                "reason": "DB root diverges from storage anchor. System frozen.",
                "db_root": db_root,
                "anchored_root": anchored_root,
                "alert_id": alert_id
            }), 400

        # Step 4: Verify anchor signature
        if not _verify_anchor_signature(anchor_data):
            alert_id = f"alert_{uuid.uuid4().hex[:12]}"
            db.save_alert(
                alert_id=alert_id,
                alert_type="FORGED_ANCHOR_SIGNATURE",
                severity="CRITICAL",
                details={"db_root": db_root, "anchored_root": anchored_root, "anchor_key": latest_key}
            )
            freeze_mgr.freeze_master("Forged anchor signature detected — automatic integrity freeze.")
            return jsonify({
                "status": "TAMPER",
                "reason": "Anchor signature verification failed! Forged or invalid anchor signature.",
                "db_root": db_root,
                "anchored_root": anchored_root,
                "alert_id": alert_id
            }), 400

        return jsonify({
            "status": "VERIFIED",
            "message": "Full verification passed. DB root matches storage anchor and signature is valid.",
            "db_root": db_root,
            "anchored_root": anchored_root,
            "anchor_key": latest_key
        }), 200

    # ── Phase 1: Single-call ingestion endpoint ───────────────────────────

    @app.route('/v1/events', methods=['POST'])
    @app.route('/api/v1/events', methods=['POST'])
    @require_role("ADMIN", "SERVICE")
    def ingest_event():
        """
        Unified ingestion endpoint. Accepts a signed event, runs the full
        tree update pipeline, and returns an inclusion proof.
        If a raw text event is provided without tree parameters, runs fast AI classification.
        This is the primary sidecar integration point.
        """
        data = request.get_json() or {}
        if "text" in data and "leaf_id" not in data:
            from m3.retrain import classify_event
            result = classify_event(data.get("text", ""))
            return jsonify(result), 200

        with app.test_request_context(
            '/api/v1/tree/update',
            method='POST',
            json=data,
            headers={
                "X-API-Key": request.headers.get("X-API-Key", ""),
                "X-Tenant-ID": request.headers.get("X-Tenant-ID", DEFAULT_TENANT)
            }
        ):
            result = update_tree()
        return result

    # ── Phase 1: Admin anchor endpoint ───────────────────────────────────

    @app.route('/v1/admin/anchor', methods=['POST'])
    @app.route('/api/v1/admin/anchor', methods=['POST'])
    @require_role("ADMIN")
    def trigger_admin_anchor():
        """Manually triggers a signed root checkpoint anchor to storage."""
        tenant_id = request.headers.get("X-Tenant-ID", DEFAULT_TENANT)
        res = _do_anchor(tenant_id)
        with app._anchor_lock:
            app._write_count = 0
            app._last_anchor_time = time.time()
        return jsonify({
            "status": "anchored" if res.get("key") else "queued",
            "key": res.get("key"),
            "checkpoint": res.get("checkpoint")
        }), 200

    # ── Phase 4: Alerts endpoint ──────────────────────────────────────────

    @app.route('/v1/alerts', methods=['GET'])
    @app.route('/api/v1/alerts', methods=['GET'])
    @require_role("ADMIN", "SERVICE", "VIEWER")
    def get_alerts():
        """Returns alerts log. VIEWER role can read."""
        unresolved_only = request.args.get("unresolved", "false").lower() == "true"
        alerts = db.get_alerts(unresolved_only=unresolved_only)
        return jsonify({"count": len(alerts), "alerts": alerts}), 200

    # ── Phase 2: Summary endpoints ────────────────────────────────────────

    @app.route('/v1/admin/summary/run', methods=['POST'])
    @app.route('/api/v1/admin/summary/run', methods=['POST'])
    @require_role("ADMIN")
    def run_summary():
        """Generate and store the daily CERT-In summary. Idempotent per date."""
        from m3.summary import generate_daily_summary
        data = request.get_json() or {}
        date = data.get("date", datetime.now(timezone.utc).date().isoformat())
        existing = db.get_daily_summary(date)
        if existing:
            return jsonify({"status": "already_exists", "date": date, "summary": existing}), 200
        summary = generate_daily_summary(db, date)
        db.save_daily_summary(date, summary)
        storage.put_summary(date, summary)
        return jsonify({"status": "created", "date": date, "summary": summary}), 201

    @app.route('/v1/export/certin', methods=['GET'])
    @app.route('/api/v1/export/certin', methods=['GET'])
    @require_role("ADMIN", "SERVICE", "VIEWER")
    def export_certin():
        """Export logs + summaries bundle with root-hash integrity proof."""
        from_date = request.args.get("from", "")
        to_date = request.args.get("to", "")
        summaries = db.list_daily_summaries(from_date=from_date or None, to_date=to_date or None)
        logs = audit_log.get_all_detailed_logs()
        # Filter by date range if provided
        if from_date or to_date:
            logs = [l for l in logs if
                    (not from_date or l.get("timestamp", "") >= from_date) and
                    (not to_date or l.get("timestamp", "") <= to_date + "Z")]
        return jsonify({
            "from": from_date,
            "to": to_date,
            "master_root": tree.master_root,
            "logs_count": len(logs),
            "summaries_count": len(summaries),
            "logs": logs,
            "summaries": summaries
        }), 200

    # ── Phase 2: ML model management ─────────────────────────────────────

    @app.route('/v1/admin/model/rollback/<version>', methods=['POST'])
    @require_role("ADMIN")
    def rollback_model(version):
        """Roll back to a previous model version."""
        success = db.rollback_model(version)
        if not success:
            return jsonify({"error": f"Version '{version}' not found"}), 404
        return jsonify({"status": "rolled_back", "version": version}), 200

    @app.route('/v1/admin/model/registry', methods=['GET'])
    @require_role("ADMIN", "VIEWER")
    def model_registry():
        """List all model versions in the registry."""
        return jsonify({"models": db.get_model_registry()}), 200

    return app



if __name__ == '__main__':
    # Development runner — for production use gunicorn:
    #   gunicorn -w 4 -b 127.0.0.1:5001 "m3.api:create_m3_app()" --timeout 120
    # Set M3_DEBUG=1 to enable Flask debug mode (development only).
    _debug = os.environ.get("M3_DEBUG", "0") == "1"
    application = create_m3_app()
    print("\n" + "=" * 60)
    print("  Module 3: Identity & Hierarchical Merkle Tree Engine")
    print("  Server running on http://127.0.0.1:5001")
    print("  Auth: X-API-Key header required (see M3_API_KEYS env)")
    print(f"  Debug mode: {'ON (M3_DEBUG=1)' if _debug else 'OFF'}")
    print("=" * 60 + "\n")
    application.run(debug=_debug, host='127.0.0.1', port=5001)
