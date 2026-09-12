import os
from pathlib import Path
from typing import Dict, Any
import json

class ExternalAnchor:
    """
    Simulates external WORM (Write Once Read Many) storage or a public ledger.
    In a production system, this would push hashes to a blockchain or a timestamping authority (RFC 3161).
    Here, it appends to a flat file that acts as an immutable external anchor.
    """
    def __init__(self, anchor_file_path: str = "external_anchor.log"):
        self.anchor_file_path = Path(anchor_file_path)
        # Ensure the file exists
        if not self.anchor_file_path.exists():
            self.anchor_file_path.touch()

    def anchor_checkpoint(self, checkpoint: Dict[str, Any]):
        """
        Appends the checkpoint hash to the external anchor log.
        """
        anchor_entry = {
            "event_id": checkpoint["event_id"],
            "timestamp": checkpoint["timestamp"],
            "master_root": checkpoint["master_root"],
            "checkpoint_hash": checkpoint["checkpoint_hash"]
        }
        
        with open(self.anchor_file_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(anchor_entry) + "\n")
