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

import uuid
from flask import Flask, request, jsonify
from m3.crypto_signer import (
    PublicKeyRegistry,
    generate_rsa_key_pair,
    verify_signature,
    sign_payload,
    get_public_key_fingerprint
)
from m3.merkle_tree import HierarchicalMerkleTree
from m3.audit_log import AppendOnlyAuditLog
from m3.freeze_manager import FreezeManager
from m3.m4_interface import M4PayloadFormatter
from m3.breach_alert import generate_breach_alert, record_breach_alert_to_db
from m3.auth import require_role
from m3.replay_guard import ReplayGuard
from m3.database import M3Database
from m3.anchoring import ExternalAnchor
from datetime import datetime, timezone


def create_m3_app():
    app = Flask(__name__)

    # 1. Initialize Persistence Layer
    db = M3Database("m3.db")
    external_anchor = ExternalAnchor("external_anchor.log")

    # 2. Initialize Core M3 Engine Instances (Loaded from DB)
    registry = PublicKeyRegistry(db=db)
    tree = HierarchicalMerkleTree(db=db)
    audit_log = AppendOnlyAuditLog(db=db, external_anchor=external_anchor)
    freeze_mgr = FreezeManager(db=db)
    replay_guard = ReplayGuard()

    # ── Public Endpoints ─────────────────────────────────────────────────

    @app.route('/api/v1/health', methods=['GET'])
    def health():
        """Public health check — no authentication required."""
        return jsonify({
            "status": "healthy",
            "module": "Module 3 — Identity & Merkle Tree Integrity Engine",
            "master_root": tree.master_root,
            "replay_guard_stats": replay_guard.get_stats()
        }), 200

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
        elif target == "subtree" and user_id:
            res = freeze_mgr.freeze_subtree(user_id, reason)
        else:
            return jsonify({"error": "Invalid freeze target or missing user_id for subtree"}), 400

        return jsonify(res), 200

    @app.route('/api/v1/unfreeze', methods=['POST'])
    @require_role("ADMIN")
    def unfreeze():
        """Unfreezes master or subtree. ADMIN only."""
        data = request.get_json() or {}
        target = data.get("target", "master")
        user_id = data.get("user_id")

        if target == "master":
            res = freeze_mgr.unfreeze_master()
        elif target == "subtree" and user_id:
            res = freeze_mgr.unfreeze_subtree(user_id)
        else:
            return jsonify({"error": "Invalid target or missing user_id"}), 400

        return jsonify(res), 200

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

        if not all([user_id, leaf_id, masked_pii_hash, real_data_hash, signature_hex, timestamp]):
            return jsonify({"error": "Missing required parameters: user_id, leaf_id, masked_pii_hash, real_data_hash, signature_hex, timestamp"}), 400

        # Generate event_id/nonce server-side if not provided (backwards compatibility)
        if not event_id:
            event_id = f"evt_{uuid.uuid4().hex[:12]}"
        if not nonce:
            nonce = uuid.uuid4().hex

        # 1. Check write-freeze status
        frozen, freeze_reason = freeze_mgr.is_frozen(user_id)
        if frozen:
            return jsonify({
                "error": "Write operations are currently frozen",
                "reason": freeze_reason
            }), 403

        # 2. Anti-replay validation
        replay_valid, replay_reason = replay_guard.validate_request(
            event_id=event_id,
            nonce=nonce,
            timestamp=timestamp,
            user_id=user_id,
            leaf_id=leaf_id
        )
        if not replay_valid:
            return jsonify({
                "error": "Replay attack detected",
                "detail": replay_reason
            }), 409

        # 3. Look up pre-registered public key — NO auto-registration
        public_key_pem = registry.get_public_key(user_id)
        if not public_key_pem:
            return jsonify({
                "error": f"No public key registered for identity '{user_id}'",
                "detail": "Keys must be pre-registered via /identity/register by an ADMIN."
            }), 401

        # 4. Reconstruct signed payload and verify signature
        signable_payload = {
            "user_id": user_id,
            "leaf_id": leaf_id,
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

        # 5. Get old leaf hash if existing
        old_subroot = tree.user_subroots.get(user_id)
        old_leaf_hash = old_subroot.leaves[leaf_id].combined_hash if old_subroot and leaf_id in old_subroot.leaves else None

        # 6. Execute O(log n) tree update
        update_proof = tree.update_leaf(
            user_id=user_id,
            leaf_id=leaf_id,
            masked_pii_hash=masked_pii_hash,
            real_data_hash=real_data_hash,
            timestamp=timestamp
        )

        # 7. Log event in append-only log and permanent root chain
        audit_entry = audit_log.log_event(
            user_id=user_id,
            leaf_id=leaf_id,
            old_leaf_hash=old_leaf_hash,
            new_leaf_hash=update_proof["leaf"]["combined_hash"],
            old_master_root=update_proof["old_master_root"],
            new_master_root=update_proof["new_master_root"],
            signature_hex=signature_hex,
            signer_fingerprint=fingerprint,
            timestamp=timestamp
        )

        # 8. Format M4 payload
        m4_payload = M4PayloadFormatter.format_m4_payload(
            audit_entry=audit_entry,
            update_proof=update_proof,
            signature_valid=True,
            freeze_status=freeze_mgr.get_freeze_status()
        )
        if db:
            db.save_m4_payload(audit_entry.event_id, m4_payload)

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

    @app.route('/api/v1/tree/proof/<user_id>/<leaf_id>', methods=['GET'])
    @require_role("ADMIN", "SERVICE", "VIEWER")
    def get_proof(user_id, leaf_id):
        """Generates cryptographic inclusion proof for a leaf."""
        proof = tree.generate_full_proof(user_id, leaf_id)
        if not proof:
            return jsonify({"error": f"Leaf '{leaf_id}' for user '{user_id}' not found"}), 404
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

            # 2. Fire AI alert generation + DB write in background — never blocks the response
            def _background_alert(facts_copy: dict):
                alert = generate_breach_alert(facts_copy)
                record_breach_alert_to_db(alert)

            thread = threading.Thread(
                target=_background_alert,
                args=(facts,),
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

    return app


if __name__ == '__main__':
    application = create_m3_app()
    print("\n" + "=" * 60)
    print("  Module 3: Identity & Hierarchical Merkle Tree Engine")
    print("  Server running on http://127.0.0.1:5001")
    print("  Auth: X-API-Key header required (see M3_API_KEYS env)")
    print("=" * 60 + "\n")
    application.run(debug=True, host='0.0.0.0', port=5001)
