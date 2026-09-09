"""
Append-Only Audit Log & CERT-In 180-Day Retention Manager for Module 3 (M3).

Maintains a permanent, tamper-evident record of all system events:
  - Detailed update logs retained for rolling 180-day window (CERT-In requirement).
  - Permanent 32-byte Root Hash chain checkpoints retained indefinitely.
  - External Anchoring Export (WORM / RFC 3161 / Public Ledger).
"""

import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any


class AuditLogEntry:
    """
    Detailed audit log entry recording a single signed state update.
    """
    def __init__(
        self,
        event_id: str,
        timestamp: str,
        user_id: str,
        leaf_id: str,
        old_leaf_hash: Optional[str],
        new_leaf_hash: str,
        old_master_root: str,
        new_master_root: str,
        signature_hex: str,
        signer_fingerprint: str
    ):
        self.event_id = event_id
        self.timestamp = timestamp
        self.user_id = user_id
        self.leaf_id = leaf_id
        self.old_leaf_hash = old_leaf_hash
        self.new_leaf_hash = new_leaf_hash
        self.old_master_root = old_master_root
        self.new_master_root = new_master_root
        self.signature_hex = signature_hex
        self.signer_fingerprint = signer_fingerprint

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "user_id": self.user_id,
            "leaf_id": self.leaf_id,
            "old_leaf_hash": self.old_leaf_hash,
            "new_leaf_hash": self.new_leaf_hash,
            "old_master_root": self.old_master_root,
            "new_master_root": self.new_master_root,
            "signature_hex": self.signature_hex,
            "signer_fingerprint": self.signer_fingerprint
        }


class PermanentRootCheckpoint:
    """
    32-byte Master Root Checkpoint retained permanently even after detailed log pruning.
    """
    def __init__(self, event_id: str, timestamp: str, master_root: str, user_id: str):
        self.event_id = event_id
        self.timestamp = timestamp
        self.master_root = master_root
        self.user_id = user_id

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "master_root": self.master_root,
            "user_id": self.user_id
        }


class AppendOnlyAuditLog:
    """
    Append-only log store managing detailed event logs and permanent root hash checkpoints.
    """
    RETENTION_DAYS = 180

    def __init__(self):
        self._detailed_logs: List[AuditLogEntry] = []
        self._permanent_root_chain: List[PermanentRootCheckpoint] = []
        self._event_index: Dict[str, AuditLogEntry] = {}

    def log_event(
        self,
        user_id: str,
        leaf_id: str,
        old_leaf_hash: Optional[str],
        new_leaf_hash: str,
        old_master_root: str,
        new_master_root: str,
        signature_hex: str,
        signer_fingerprint: str,
        timestamp: Optional[str] = None
    ) -> AuditLogEntry:
        """
        Appends a signed event to the detailed log and records a permanent root checkpoint.
        """
        if timestamp is None:
            timestamp = datetime.now(timezone.utc).isoformat()

        event_id = f"evt_{uuid.uuid4().hex[:12]}"

        entry = AuditLogEntry(
            event_id=event_id,
            timestamp=timestamp,
            user_id=user_id,
            leaf_id=leaf_id,
            old_leaf_hash=old_leaf_hash,
            new_leaf_hash=new_leaf_hash,
            old_master_root=old_master_root,
            new_master_root=new_master_root,
            signature_hex=signature_hex,
            signer_fingerprint=signer_fingerprint
        )

        checkpoint = PermanentRootCheckpoint(
            event_id=event_id,
            timestamp=timestamp,
            master_root=new_master_root,
            user_id=user_id
        )

        self._detailed_logs.append(entry)
        self._permanent_root_chain.append(checkpoint)
        self._event_index[event_id] = entry

        return entry

    def get_event(self, event_id: str) -> Optional[AuditLogEntry]:
        """Retrieves a detailed event entry by event_id."""
        return self._event_index.get(event_id)

    def get_all_detailed_logs(self) -> List[Dict[str, Any]]:
        """Returns all detailed logs."""
        return [log.to_dict() for log in self._detailed_logs]

    def get_permanent_root_chain(self) -> List[Dict[str, Any]]:
        """Returns the complete permanent root hash checkpoint chain."""
        return [cp.to_dict() for cp in self._permanent_root_chain]

    def prune_logs_older_than(self, days: int = RETENTION_DAYS, reference_now: Optional[datetime] = None) -> Dict[str, Any]:
        """
        Prunes detailed event logs older than `days` (default 180 days for CERT-In).
        The permanent 32-byte root hash chain is NEVER pruned.

        Returns:
            Dict[str, Any]: Pruning summary metrics.
        """
        if reference_now is None:
            reference_now = datetime.now(timezone.utc)

        cutoff_date = reference_now - timedelta(days=days)
        retained_logs = []
        pruned_count = 0

        for entry in self._detailed_logs:
            try:
                entry_dt = datetime.fromisoformat(entry.timestamp.replace('Z', '+00:00'))
            except ValueError:
                retained_logs.append(entry)
                continue

            if entry_dt >= cutoff_date:
                retained_logs.append(entry)
            else:
                pruned_count += 1
                if entry.event_id in self._event_index:
                    del self._event_index[entry.event_id]

        self._detailed_logs = retained_logs

        return {
            "retention_policy_days": days,
            "cutoff_timestamp": cutoff_date.isoformat(),
            "logs_pruned": pruned_count,
            "detailed_logs_remaining": len(self._detailed_logs),
            "permanent_root_checkpoints_preserved": len(self._permanent_root_chain)
        }

    def export_external_anchors(self) -> List[Dict[str, Any]]:
        """
        Exports permanent 32-byte root checkpoints formatted for external WORM / RFC 3161 / ledger anchoring.
        """
        return [
            {
                "sequence_id": idx + 1,
                "event_id": cp.event_id,
                "timestamp": cp.timestamp,
                "root_hash_32bytes": cp.master_root,
                "anchor_payload": f"{cp.event_id}:{cp.timestamp}:{cp.master_root}"
            }
            for idx, cp in enumerate(self._permanent_root_chain)
        ]
