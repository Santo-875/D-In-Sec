"""
Hierarchical Merkle Tree implementation for Module 3 (M3).

Architecture:
  MASTER ROOT
     /     |      \\
User Subroot  User Subroot  User Subroot ... (1 per user)
   /   |   \\
 Leaf Leaf Leaf  Hash(user_id:leaf_id:version:timestamp:masked_pii_hash:real_data_hash)

Provides fast, provable state updates, O(log n) path recomputations,
cryptographic path inclusion/transition proofs, and independent proof verification.
"""

import hashlib
from typing import Dict, List, Optional, Tuple, Any


def compute_hash(data: str) -> str:
    """Computes SHA-256 hex digest of input string."""
    return hashlib.sha256(data.encode('utf-8')).hexdigest()


def compute_combined_leaf_hash(
    user_id: str,
    leaf_id: str,
    version: int,
    timestamp: str,
    masked_pii_hash: str,
    real_data_hash: str
) -> str:
    """
    Binds all 6 fields into a single leaf digest, preventing cross-user/cross-record
    transplant attacks, version replay, and timestamp manipulation.

    Args:
        user_id: Owner identity (prevents moving leaf to another user).
        leaf_id: Record identifier (prevents swapping leaf IDs).
        version: Monotonic version counter (prevents version regression).
        timestamp: ISO-8601 timestamp (prevents timestamp replay).
        masked_pii_hash: Hash of masked PII record from Module 2.
        real_data_hash: Hash of real database record.

    Returns:
        SHA-256 digest binding all fields.
    """
    combined = (
        f"{user_id}:{leaf_id}:{version}:{timestamp}"
        f":{masked_pii_hash.lower()}:{real_data_hash.lower()}"
    )
    return compute_hash(combined)


class LeafNode:
    """
    Represents a single leaf in a user's subroot tree.
    """
    def __init__(self, user_id: str, leaf_id: str, masked_pii_hash: str,
                 real_data_hash: str, timestamp: str, version: int = 1):
        self.user_id = user_id
        self.leaf_id = leaf_id
        self.masked_pii_hash = masked_pii_hash
        self.real_data_hash = real_data_hash
        self.timestamp = timestamp
        self.version = version
        self.combined_hash = compute_combined_leaf_hash(
            user_id, leaf_id, version, timestamp,
            masked_pii_hash, real_data_hash
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "leaf_id": self.leaf_id,
            "user_id": self.user_id,
            "masked_pii_hash": self.masked_pii_hash,
            "real_data_hash": self.real_data_hash,
            "combined_hash": self.combined_hash,
            "timestamp": self.timestamp,
            "version": self.version
        }


class UserSubroot:
    """
    Represents an isolated user subtree aggregating that user's leaves.
    """
    EMPTY_SUBROOT_HASH = compute_hash("EMPTY_USER_SUBROOT")

    def __init__(self, user_id: str):
        self.user_id = user_id
        # Maps leaf_id -> LeafNode
        self.leaves: Dict[str, LeafNode] = {}
        self.subroot_hash: str = self.EMPTY_SUBROOT_HASH

    def update_leaf(self, leaf_id: str, masked_pii_hash: str, real_data_hash: str,
                    timestamp: str) -> Tuple[LeafNode, str, str]:
        """
        Updates or appends a leaf in this user's subroot.

        Returns:
            Tuple[LeafNode, str, str]: (updated_leaf, old_subroot_hash, new_subroot_hash)
        """
        old_subroot_hash = self.subroot_hash

        if leaf_id in self.leaves:
            existing = self.leaves[leaf_id]
            updated_leaf = LeafNode(
                user_id=self.user_id,
                leaf_id=leaf_id,
                masked_pii_hash=masked_pii_hash,
                real_data_hash=real_data_hash,
                timestamp=timestamp,
                version=existing.version + 1
            )
        else:
            updated_leaf = LeafNode(
                user_id=self.user_id,
                leaf_id=leaf_id,
                masked_pii_hash=masked_pii_hash,
                real_data_hash=real_data_hash,
                timestamp=timestamp,
                version=1
            )

        self.leaves[leaf_id] = updated_leaf
        self._recompute_subroot()
        return updated_leaf, old_subroot_hash, self.subroot_hash

    def _recompute_subroot(self):
        """
        Deterministically recomputes the user's subroot hash from its leaves in sorted order.
        """
        if not self.leaves:
            self.subroot_hash = self.EMPTY_SUBROOT_HASH
            return

        # Sort leaves by leaf_id for deterministic Merkle hashing
        sorted_leaf_ids = sorted(self.leaves.keys())
        hashes = [self.leaves[lid].combined_hash for lid in sorted_leaf_ids]

        # Compute Merkle tree root for leaf hashes
        while len(hashes) > 1:
            if len(hashes) % 2 != 0:
                hashes.append(hashes[-1])  # Duplicate last element if odd
            next_level = []
            for i in range(0, len(hashes), 2):
                combined = f"{hashes[i]}:{hashes[i+1]}"
                next_level.append(compute_hash(combined))
            hashes = next_level

        self.subroot_hash = compute_hash(f"USER:{self.user_id}:{hashes[0]}")

    def get_leaf_proof(self, leaf_id: str) -> List[Dict[str, str]]:
        """
        Generates Merkle inclusion proof siblings for a specific leaf within user subroot.
        """
        if leaf_id not in self.leaves:
            return []

        sorted_ids = sorted(self.leaves.keys())
        target_idx = sorted_ids.index(leaf_id)
        current_level = [self.leaves[lid].combined_hash for lid in sorted_ids]
        proof = []

        idx = target_idx
        while len(current_level) > 1:
            if len(current_level) % 2 != 0:
                current_level.append(current_level[-1])

            sibling_idx = idx + 1 if idx % 2 == 0 else idx - 1
            direction = "right" if idx % 2 == 0 else "left"
            proof.append({
                "direction": direction,
                "hash": current_level[sibling_idx]
            })

            next_level = []
            for i in range(0, len(current_level), 2):
                next_level.append(compute_hash(f"{current_level[i]}:{current_level[i+1]}"))
            current_level = next_level
            idx = idx // 2

        return proof


class HierarchicalMerkleTree:
    """
    Master Hierarchical Merkle Tree managing user subroots and Master Root.
    Synchronizes state to an M3Database instance if provided.
    """
    EMPTY_MASTER_ROOT = compute_hash("EMPTY_MASTER_ROOT")

    def __init__(self, db=None):
        # Maps user_id -> UserSubroot
        self.user_subroots: Dict[str, UserSubroot] = {}
        self.master_root: str = self.EMPTY_MASTER_ROOT
        self.db = db
        
        if self.db:
            self._load_from_db()

    def _load_from_db(self):
        leaves = self.db.load_merkle_leaves()
        # Group by user_id
        for leaf_data in leaves:
            uid = leaf_data["user_id"]
            lid = leaf_data["leaf_id"]
            
            subroot = self.get_or_create_subroot(uid)
            subroot.leaves[lid] = LeafNode(
                user_id=uid,
                leaf_id=lid,
                masked_pii_hash=leaf_data["masked_pii_hash"],
                real_data_hash=leaf_data["real_data_hash"],
                timestamp=leaf_data["timestamp"],
                version=leaf_data["version"]
            )
            
        # Recompute all subroots
        for subroot in self.user_subroots.values():
            subroot._recompute_subroot()
            
        # Recompute master root
        self._recompute_master_root()

    def get_or_create_subroot(self, user_id: str) -> UserSubroot:
        if user_id not in self.user_subroots:
            self.user_subroots[user_id] = UserSubroot(user_id)
        return self.user_subroots[user_id]

    def update_leaf(self, user_id: str, leaf_id: str, masked_pii_hash: str,
                    real_data_hash: str, timestamp: str) -> Dict[str, Any]:
        """
        Executes O(log n) path update: leaf -> user subroot -> master root.

        Returns:
            Dict[str, Any]: Proof details including old and new subroot and master roots.
        """
        subroot = self.get_or_create_subroot(user_id)

        old_master_root = self.master_root
        leaf, old_subroot_hash, new_subroot_hash = subroot.update_leaf(
            leaf_id=leaf_id,
            masked_pii_hash=masked_pii_hash,
            real_data_hash=real_data_hash,
            timestamp=timestamp
        )

        self._recompute_master_root()
        new_master_root = self.master_root

        subroot_sibling_proof = self._get_master_sibling_proof(user_id)
        leaf_sibling_proof = subroot.get_leaf_proof(leaf_id)
        
        if self.db:
            self.db.save_merkle_leaf(
                user_id=user_id,
                leaf_id=leaf_id,
                masked_pii_hash=masked_pii_hash,
                real_data_hash=real_data_hash,
                combined_hash=leaf.combined_hash,
                timestamp=timestamp,
                version=leaf.version
            )

        return {
            "user_id": user_id,
            "leaf_id": leaf_id,
            "leaf": leaf.to_dict(),
            "old_subroot_hash": old_subroot_hash,
            "new_subroot_hash": new_subroot_hash,
            "old_master_root": old_master_root,
            "new_master_root": new_master_root,
            "leaf_proof": leaf_sibling_proof,
            "subroot_proof": subroot_sibling_proof
        }

    def _recompute_master_root(self):
        """
        Recomputes top-level Master Root from all user subroots in sorted user_id order.
        """
        if not self.user_subroots:
            self.master_root = self.EMPTY_MASTER_ROOT
            return

        sorted_users = sorted(self.user_subroots.keys())
        hashes = [self.user_subroots[uid].subroot_hash for uid in sorted_users]

        while len(hashes) > 1:
            if len(hashes) % 2 != 0:
                hashes.append(hashes[-1])
            next_level = []
            for i in range(0, len(hashes), 2):
                next_level.append(compute_hash(f"{hashes[i]}:{hashes[i+1]}"))
            hashes = next_level

        self.master_root = compute_hash(f"MASTER:{hashes[0]}")

    def _get_master_sibling_proof(self, target_user_id: str) -> List[Dict[str, str]]:
        """
        Generates Merkle siblings proof for user subroots under master root.
        """
        sorted_users = sorted(self.user_subroots.keys())
        if target_user_id not in sorted_users:
            return []

        target_idx = sorted_users.index(target_user_id)
        current_level = [self.user_subroots[uid].subroot_hash for uid in sorted_users]
        proof = []

        idx = target_idx
        while len(current_level) > 1:
            if len(current_level) % 2 != 0:
                current_level.append(current_level[-1])

            sibling_idx = idx + 1 if idx % 2 == 0 else idx - 1
            direction = "right" if idx % 2 == 0 else "left"
            proof.append({
                "direction": direction,
                "hash": current_level[sibling_idx]
            })

            next_level = []
            for i in range(0, len(current_level), 2):
                next_level.append(compute_hash(f"{current_level[i]}:{current_level[i+1]}"))
            current_level = next_level
            idx = idx // 2

        return proof

    def generate_full_proof(self, user_id: str, leaf_id: str) -> Optional[Dict[str, Any]]:
        """
        Generates cryptographic inclusion proof for a leaf and user subtree up to Master Root.
        """
        if user_id not in self.user_subroots:
            return None

        subroot = self.user_subroots[user_id]
        if leaf_id not in subroot.leaves:
            return None

        leaf = subroot.leaves[leaf_id]
        leaf_proof = subroot.get_leaf_proof(leaf_id)
        master_proof = self._get_master_sibling_proof(user_id)

        return {
            "user_id": user_id,
            "leaf_id": leaf_id,
            "leaf_hash": leaf.combined_hash,
            "subroot_hash": subroot.subroot_hash,
            "master_root": self.master_root,
            "leaf_proof": leaf_proof,
            "subroot_proof": master_proof
        }

    def check_leaf_integrity(self, user_id: str, leaf_id: str,
                             masked_pii_hash: str, real_data_hash: str) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Deterministically checks leaf integrity against current tree state.

        Uses the leaf's stored version and timestamp for hash recomputation,
        comparing against the presented masked_pii_hash and real_data_hash.

        Returns:
            Tuple[bool, Optional[str], Optional[str]]: (is_valid, expected_hash, actual_hash)
        """
        if user_id not in self.user_subroots:
            return False, None, None
        subroot = self.user_subroots[user_id]
        if leaf_id not in subroot.leaves:
            return False, None, None

        leaf = subroot.leaves[leaf_id]
        # Recompute what the hash SHOULD be with the presented data + stored metadata
        expected_combined = compute_combined_leaf_hash(
            user_id, leaf_id, leaf.version, leaf.timestamp,
            masked_pii_hash, real_data_hash
        )
        is_valid = (leaf.combined_hash == expected_combined)
        return is_valid, expected_combined, leaf.combined_hash

    def verify_leaf_integrity(self, user_id: str, leaf_id: str,
                              masked_pii_hash: str, real_data_hash: str) -> bool:
        """
        Verifies that a leaf's masked PII and real data hashes match current state and have not been tampered with.
        """
        is_valid, _, _ = self.check_leaf_integrity(user_id, leaf_id, masked_pii_hash, real_data_hash)
        return is_valid

    @staticmethod
    def verify_proof(
        leaf_hash: str,
        leaf_proof: List[Dict[str, str]],
        subroot_proof: List[Dict[str, str]],
        user_id: str,
        claimed_master_root: str
    ) -> Tuple[bool, str]:
        """
        Independently verifies a Merkle inclusion proof by walking
        leaf → subroot → master root and comparing against claimed root.

        This method does NOT require access to the tree state — it operates
        purely on the proof path, making it suitable for external/third-party
        verification.

        Args:
            leaf_hash: The combined hash of the leaf being verified.
            leaf_proof: Sibling hashes for the leaf-to-subroot path.
            subroot_proof: Sibling hashes for the subroot-to-master path.
            user_id: User ID (needed for subroot hash computation).
            claimed_master_root: The master root to verify against.

        Returns:
            Tuple[bool, str]: (is_valid, computed_master_root)
        """
        # Walk leaf proof to compute subroot internal hash
        current = leaf_hash
        for step in leaf_proof:
            sibling = step["hash"]
            if step["direction"] == "right":
                current = compute_hash(f"{current}:{sibling}")
            else:
                current = compute_hash(f"{sibling}:{current}")

        # Apply user binding to get subroot hash
        computed_subroot = compute_hash(f"USER:{user_id}:{current}")

        # Walk subroot proof to compute master root
        current = computed_subroot
        for step in subroot_proof:
            sibling = step["hash"]
            if step["direction"] == "right":
                current = compute_hash(f"{current}:{sibling}")
            else:
                current = compute_hash(f"{sibling}:{current}")

        # Apply master binding
        computed_master = compute_hash(f"MASTER:{current}")

        is_valid = (computed_master == claimed_master_root)
        return is_valid, computed_master
