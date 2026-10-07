import os
import unittest

from m3.crypto_signer import (
    PublicKeyRegistry,
    generate_rsa_key_pair,
)
from m3.database import M3Database
from m3.freeze_manager import FreezeManager
from m3.merkle_tree import HierarchicalMerkleTree


class TestM3Persistence(unittest.TestCase):
    def setUp(self):
        self.db_path = "test_m3.db"
        if os.path.exists(self.db_path):
            os.remove(self.db_path)
            
    def tearDown(self):
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def test_identity_persistence(self):
        db1 = M3Database(self.db_path)
        reg1 = PublicKeyRegistry(db=db1)
        _, pub = generate_rsa_key_pair()
        reg1.register_key("dev1", pub)
        
        # Simulate restart
        db2 = M3Database(self.db_path)
        reg2 = PublicKeyRegistry(db=db2)
        
        self.assertTrue(reg2.is_registered("dev1"))
        self.assertEqual(reg2.get_public_key("dev1"), pub)

    def test_merkle_tree_persistence(self):
        db1 = M3Database(self.db_path)
        tree1 = HierarchicalMerkleTree(db=db1)
        tree1.update_leaf("user_abc", "leaf_123", "hashA", "hashB", "2023-10-27T10:00:00Z")
        root1 = tree1.master_root
        
        # Simulate restart
        db2 = M3Database(self.db_path)
        tree2 = HierarchicalMerkleTree(db=db2)
        
        self.assertEqual(tree2.master_root, root1)
        
    def test_freeze_state_persistence(self):
        db1 = M3Database(self.db_path)
        fmgr1 = FreezeManager(db=db1)
        fmgr1.freeze_master("incident 42")
        fmgr1.freeze_subtree("user_99", "fraud")
        
        # Simulate restart
        db2 = M3Database(self.db_path)
        fmgr2 = FreezeManager(db=db2)
        
        frozen_master, reason_master = fmgr2.is_frozen()
        self.assertTrue(frozen_master)
        self.assertIn("incident 42", reason_master)
        
        frozen_sub, _reason_sub = fmgr2.is_frozen("user_99")
        self.assertTrue(frozen_sub)
        self.assertEqual(fmgr2._subtree_freezes["user_99"]["reason"], "fraud")

if __name__ == '__main__':
    unittest.main()
