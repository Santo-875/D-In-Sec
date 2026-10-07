import os
import unittest

from m3.anchoring import ExternalAnchor
from m3.audit_log import AppendOnlyAuditLog
from m3.database import M3Database


class TestChaining(unittest.TestCase):
    def setUp(self):
        self.db_path = "test_m3_chain.db"
        self.anchor_path = "test_anchor.log"
        if os.path.exists(self.db_path):
            os.remove(self.db_path)
        if os.path.exists(self.anchor_path):
            os.remove(self.anchor_path)

    def tearDown(self):
        if os.path.exists(self.db_path):
            os.remove(self.db_path)
        if os.path.exists(self.anchor_path):
            os.remove(self.anchor_path)

    def test_cryptographic_chain(self):
        db = M3Database(self.db_path)
        anchor = ExternalAnchor(self.anchor_path)
        log = AppendOnlyAuditLog(db=db, external_anchor=anchor)

        e1 = log.log_event("u1", "l1", None, "hash1", "root0", "root1", "sig1", "fp1")
        e2 = log.log_event("u1", "l2", None, "hash2", "root1", "root2", "sig2", "fp2")
        
        # Verify event chaining
        self.assertIsNone(e1.previous_hash)
        self.assertEqual(e2.previous_hash, e1.event_hash)

        # Verify checkpoints
        chain = log._permanent_root_chain
        self.assertEqual(len(chain), 2)
        c1, c2 = chain[0], chain[1]
        self.assertIsNone(c1.previous_hash)
        self.assertEqual(c2.previous_hash, c1.checkpoint_hash)
        
        # Verify external anchor file
        self.assertTrue(os.path.exists(self.anchor_path))
        with open(self.anchor_path, "r") as f:
            lines = f.readlines()
        self.assertEqual(len(lines), 2)
        
        # Simulate restart
        log2 = AppendOnlyAuditLog(db=M3Database(self.db_path))
        self.assertEqual(len(log2._detailed_logs), 2)
        self.assertEqual(len(log2._permanent_root_chain), 2)
        
        e2_loaded = log2._detailed_logs[1]
        self.assertEqual(e2_loaded.previous_hash, log2._detailed_logs[0].event_hash)

if __name__ == '__main__':
    unittest.main()
