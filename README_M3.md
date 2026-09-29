# D-In-Sec: Module 3 (Integrity Engine)

Module 3 is the cryptographic heart of the **D-In-Sec** architecture. It ensures that data written by upstream modules (Module 1 and Module 2) cannot be tampered with, deleted, or reordered without immediate detection.

It achieves this through a **Hierarchical Merkle Tree with cryptographic inclusion proofs and deterministic root verification**.

## Core Architecture

### 1. Hierarchical Merkle Tree
Unlike traditional simple lists of hashes, M3 organizes user data into a **Hierarchical Merkle Tree**.
- Every user gets their own isolated **Subtree**.
- A user's subtree roots up into a single **Master Root**.
- When a user's data is updated, a deterministic operation recalculates only their branch, allowing precise updates and cryptographic inclusion proofs.

### 2. End-to-End Cryptographic Verification
When data is written, M3 generates an **Inclusion Proof (M4 Payload)**. This proof contains the exact sequence of sibling hashes needed to mathematically trace the data's leaf hash all the way up to the Master Root.

A verifier (like our SOC Dashboard) can recalculate the leaf hash from raw data, walk the proof up to the root, and compare it against the securely anchored Master Root. If **any bit** of data has been altered in the database, the math fails, and tampering is immediately detected.

### 3. Persistent Replay Guard
M3 completely protects against Replay Attacks. Every write request must contain:
- `event_id`
- `nonce`
- `version`

These fields are strictly validated and persistently tracked in SQLite across server restarts. An attacker cannot intercept a valid signed payload and replay it, because the `nonce` and `event_id` will be rejected.

### 4. Atomic Transactions & Audit Integrity
Tree updates, root checkpoints, replay guard records, and the append-only audit log are executed within a **single atomic SQLite transaction**. This guarantees that the system never enters an inconsistent state. The audit log is completely append-only and cryptographically chained, meaning an attacker cannot insert or delete events from the middle of the history.

### 5. External Root Anchor Prototype
To prevent an attacker from rolling back the entire database to a previous valid state, the M3 Master Root is periodically anchored to an external log file (`external_anchor.log`). Verification ensures the internal Master Root perfectly matches this external root anchor prototype.

## Security Overview

- **Authentication**: Strict `X-API-Key` headers required. M3 refuses to start in `production` mode if secure keys are missing.
- **Key Registration**: Separation of concerns. Public keys are registered out-of-band by an ADMIN.
- **Key Revocation**: Compromised identity keys can be instantly revoked.
- **Freeze State**: Subtrees (or the Master Root) can be write-frozen in the event of an ongoing breach, cutting off all further updates.

This prototype fulfills the core cryptographic requirements for a robust 5th-semester cybersecurity project!
