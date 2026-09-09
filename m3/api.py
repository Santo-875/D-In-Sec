"""
Standalone REST API Server for Module 3 (M3).

Provides endpoints for identity key registration, hierarchical Merkle tree updates,
signature verification, CERT-In audit log retention management, write-freeze mitigation,
and M4 anomaly verification payload exports.

Runs independently on port 5001.
"""

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
from datetime import datetime, timezone


def create_m3_app():
    app = Flask(__name__)

    # Core M3 Engine Instances
    registry = PublicKeyRegistry()
    tree = HierarchicalMerkleTree()
    audit_log = AppendOnlyAuditLog()
    freeze_mgr = FreezeManager()

    # M4 Payload Store (event_id -> m4_payload)
    m4_payloads = {}

    @app.route('/api/v1/health', methods=['GET'])
    def health():
        return jsonify({
            "status": "healthy",
            "module": "Module 3 — Identity & Merkle Tree Integrity Engine",
            "master_root": tree.master_root
        }), 200

    @app.route('/api/v1/identity/generate-keys', methods=['POST'])
    def generate_keys():
        """Generates a new RSA-2048 key pair."""
        private_pem, public_pem = generate_rsa_key_pair()
        fingerprint = get_public_key_fingerprint(public_pem)
        return jsonify({
            "private_key_pem": private_pem,
            "public_key_pem": public_pem,
            "fingerprint": fingerprint
        }), 201

    @app.route('/api/v1/identity/register', methods=['POST'])
    def register_identity():
        """Registers a public key for a user/developer identity."""
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

    @app.route('/api/v1/tree/update', methods=['POST'])
    def update_tree():
        """
        Submits a signed update request:
        1. Validates write-freeze status.
        2. Verifies cryptographic signature against registered public key.
        3. Recalculates O(log n) path: Leaf -> User Subroot -> Master Root.
        4. Logs event in append-only log and permanent root chain.
        5. Formats M4 output payload.
        """
        data = request.get_json() or {}
        user_id = data.get("user_id")
        leaf_id = data.get("leaf_id")
        masked_pii_hash = data.get("masked_pii_hash")
        real_data_hash = data.get("real_data_hash")
        timestamp = data.get("timestamp")
        signature_hex = data.get("signature_hex")
        provided_public_key = data.get("public_key_pem")

        if not all([user_id, leaf_id, masked_pii_hash, real_data_hash, signature_hex]):
            return jsonify({"error": "Missing required parameters"}), 400

        # Check write-freeze status
        frozen, freeze_reason = freeze_mgr.is_frozen(user_id)
        if frozen:
            return jsonify({
                "error": "Write operations are currently frozen",
                "reason": freeze_reason
            }), 403

        # Resolve public key
        public_key_pem = provided_public_key or registry.get_public_key(user_id)
        if not public_key_pem:
            return jsonify({"error": f"No public key registered for identity '{user_id}'"}), 401

        # Reconstruct signed payload dictionary
        signable_payload = {
            "user_id": user_id,
            "leaf_id": leaf_id,
            "masked_pii_hash": masked_pii_hash,
            "real_data_hash": real_data_hash,
            "timestamp": timestamp
        }

        # Verify signature
        if not verify_signature(public_key_pem, signable_payload, signature_hex):
            return jsonify({
                "error": "Invalid signature. Signature verification failed.",
                "signature_status": "REJECTED"
            }), 401

        # Register key if not already in registry
        fingerprint = registry.register_key(user_id, public_key_pem)

        # Get old leaf hash if existing
        old_subroot = tree.user_subroots.get(user_id)
        old_leaf_hash = old_subroot.leaves[leaf_id].combined_hash if old_subroot and leaf_id in old_subroot.leaves else None

        # Execute O(log n) tree update
        update_proof = tree.update_leaf(
            user_id=user_id,
            leaf_id=leaf_id,
            masked_pii_hash=masked_pii_hash,
            real_data_hash=real_data_hash,
            timestamp=timestamp
        )

        # Log event in append-only log and permanent root chain
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

        # Format M4 payload
        m4_payload = M4PayloadFormatter.format_m4_payload(
            audit_entry=audit_entry,
            update_proof=update_proof,
            signature_valid=True,
            freeze_status=freeze_mgr.get_freeze_status()
        )
        m4_payloads[audit_entry.event_id] = m4_payload

        return jsonify({
            "status": "SUCCESS",
            "message": "Leaf updated and Master Root recomputed successfully",
            "event_id": audit_entry.event_id,
            "old_master_root": update_proof["old_master_root"],
            "calculated_next_master_root": update_proof["new_master_root"],
            "update_proof": update_proof,
            "m4_payload": m4_payload
        }), 200

    @app.route('/api/v1/tree/root', methods=['GET'])
    def get_root():
        """Returns current Master Root state and permanent root chain."""
        return jsonify({
            "master_root": tree.master_root,
            "total_user_subroots": len(tree.user_subroots),
            "permanent_root_chain_length": len(audit_log.get_permanent_root_chain()),
            "permanent_root_chain": audit_log.get_permanent_root_chain()
        }), 200

    @app.route('/api/v1/tree/proof/<user_id>/<leaf_id>', methods=['GET'])
    def get_proof(user_id, leaf_id):
        """Generates cryptographic inclusion proof for a leaf."""
        proof = tree.generate_full_proof(user_id, leaf_id)
        if not proof:
            return jsonify({"error": f"Leaf '{leaf_id}' for user '{user_id}' not found"}), 4404 if False else 404
        return jsonify(proof), 200

    @app.route('/api/v1/tree/verify-leaf', methods=['POST'])
    def verify_leaf():
        """Verifies leaf integrity against current tree state, triggering AI breach alert on tamper detection."""
        data = request.get_json() or {}
        user_id = data.get("user_id")
        leaf_id = data.get("leaf_id")
        masked_pii_hash = data.get("masked_pii_hash")
        real_data_hash = data.get("real_data_hash")

        if not all([user_id, leaf_id, masked_pii_hash, real_data_hash]):
            return jsonify({"error": "Missing parameters"}), 400

        # Deterministic verification
        is_valid, expected_hash, actual_hash = tree.check_leaf_integrity(user_id, leaf_id, masked_pii_hash, real_data_hash)
        
        response_body = {
            "user_id": user_id,
            "leaf_id": leaf_id,
            "integrity_verified": is_valid
        }

        if not is_valid:
            # Deterministic detection occurred -> Gather facts
            facts = {
                "affected_user": user_id,
                "leaf_id": leaf_id,
                "expected_hash": expected_hash or "NOT_FOUND",
                "actual_hash": actual_hash or "NOT_FOUND",
                "detected_at": datetime.now(timezone.utc).isoformat()
            }
            # AI breach alert generation with deterministic fallback
            alert = generate_breach_alert(facts)
            response_body["breach_alert"] = alert

            # Route alert to SOC database
            record_breach_alert_to_db(alert)

        return jsonify(response_body), 200

    @app.route('/api/v1/audit/logs', methods=['GET'])
    def get_audit_logs():
        """Returns detailed append-only audit log."""
        return jsonify({
            "count": len(audit_log._detailed_logs),
            "detailed_logs": audit_log.get_all_detailed_logs()
        }), 200

    @app.route('/api/v1/audit/prune', methods=['POST'])
    def prune_audit_logs():
        """
        Executes CERT-In 180-day retention pruning.
        Detailed logs older than 180 days are purged; 32-byte root checkpoints remain permanently.
        """
        data = request.get_json() or {}
        days = data.get("days", 180)
        result = audit_log.prune_logs_older_than(days=days)
        return jsonify(result), 200

    @app.route('/api/v1/audit/anchors', methods=['GET'])
    def get_external_anchors():
        """Exports permanent 32-byte root checkpoints for external WORM / RFC 3161 anchoring."""
        return jsonify({
            "count": len(audit_log.export_external_anchors()),
            "anchors": audit_log.export_external_anchors()
        }), 200

    @app.route('/api/v1/freeze', methods=['POST'])
    def freeze():
        """Triggers write-freeze on master or subtree."""
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
    def unfreeze():
        """Unfreezes master or subtree."""
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

    @app.route('/api/v1/m4/payload/<event_id>', methods=['GET'])
    def get_m4_payload(event_id):
        """Retrieves exact M4 verification input payload for an event ID."""
        payload = m4_payloads.get(event_id)
        if not payload:
            return jsonify({"error": f"M4 payload for event '{event_id}' not found"}), 404
        return jsonify(payload), 200

    return app


if __name__ == '__main__':
    application = create_m3_app()
    print("\n" + "=" * 60)
    print("  Module 3: Identity & Hierarchical Merkle Tree Engine")
    print("  Server running on http://127.0.0.1:5001")
    print("=" * 60 + "\n")
    application.run(debug=True, host='0.0.0.0', port=5001)
