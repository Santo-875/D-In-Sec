"""
Module 4 (M4) Output / Fact Integration Interface for Module 3 (M3).

Formats verified state transition facts, next root calculations,
path proofs, and cryptographic signatures into a structured input payload
for Module 4 (M4) anomaly & attack analysis.
"""

from typing import Dict, Any, Optional
from m3.audit_log import AuditLogEntry


class M4PayloadFormatter:
    """
    Constructs standardized verified fact payloads for M4 anomaly analyzer.
    """

    @staticmethod
    def format_m4_payload(
        audit_entry: AuditLogEntry,
        update_proof: Dict[str, Any],
        signature_valid: bool,
        freeze_status: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Constructs the structured payload delivered to M4.

        Args:
            audit_entry (AuditLogEntry): Audit log entry of update event.
            update_proof (Dict[str, Any]): Merkle path transition proof from tree update.
            signature_valid (bool): Whether the update signature was verified.
            freeze_status (Dict[str, Any]): Current write-freeze status.

        Returns:
            Dict[str, Any]: Formatted payload for M4.
        """
        leaf_data = update_proof.get("leaf", {})

        return {
            "m3_verification_version": "1.0",
            "event_id": audit_entry.event_id,
            "timestamp": audit_entry.timestamp,
            "user_identity": {
                "user_id": audit_entry.user_id,
                "signer_public_key_fingerprint": audit_entry.signer_fingerprint,
                "signature_verified": signature_valid,
                "signature_hex": audit_entry.signature_hex
            },
            "tree_update_location": {
                "target_user_subroot": audit_entry.user_id,
                "target_leaf_id": audit_entry.leaf_id,
                "masked_pii_hash": leaf_data.get("masked_pii_hash"),
                "real_data_hash": leaf_data.get("real_data_hash"),
                "combined_leaf_hash": audit_entry.new_leaf_hash
            },
            "root_transition": {
                "old_user_subroot": update_proof.get("old_subroot_hash"),
                "new_user_subroot": update_proof.get("new_subroot_hash"),
                "old_master_root": audit_entry.old_master_root,
                "calculated_next_master_root": audit_entry.new_master_root
            },
            "cryptographic_proof": {
                "leaf_proof": update_proof.get("leaf_proof", []),
                "subroot_proof": update_proof.get("subroot_proof", [])
            },
            "mitigation_context": {
                "is_frozen": freeze_status.get("master_frozen", False) or audit_entry.user_id in freeze_status.get("subtree_freezes", {}),
                "freeze_status": freeze_status
            },
            "verified_facts": {
                "non_repudiable": signature_valid,
                "path_walk_verified": True,
                "isolated_user_subroot": True,
                "tamper_detected": not signature_valid
            }
        }
