# D-In-Sec Module 3 — Security Architecture & Threat Model

## 1. Executive Summary
Module 3 (M3) operates as an immutable, tamper-evident cryptographic sidecar. It anchors audit trails using a hierarchical Merkle tree structure, guarantees non-repudiation with asymmetric cryptographic signatures (local RSA-2048 or AWS KMS RSASSA_PSS_SHA_256), persists immutable logs into an AWS S3 bucket with Object Lock compliance mode, and executes automated CERT-In incident aggregation.

---

## 2. Threat Model & Mitigations

| Threat | Vector | Mitigation Strategy |
| :--- | :--- | :--- |
| **Log Tampering / Alteration** | Malicious insider or compromised DB admin alters database records | Hierarchical Merkle tree recomputed dynamically. Any leaf change causes master root mismatch. Checkpoint anchored to S3 Object Lock (WORM). |
| **Database History Rewrite** | Attacker recalculates entire Merkle tree from forged records | External anchor verification detects mismatch between local master root and S3 immutable anchor. |
| **Replay Attacks** | Replaying previously captured valid audit update payloads | Anti-replay guard table enforces unique `(event_id, nonce)` and rejects timestamps outside a ±300s clock-skew window. |
| **Unauthorized Write / Privilege Escalation** | Callers attempting tree updates or freeze controls | Role-Based Access Control (`ADMIN`, `SERVICE`, `VIEWER`) via hashed API keys (`X-API-Key`) with constant-time comparison (`hmac.compare_digest`). |
| **S3 Outage / Network Partition** | Cloud storage sink becomes unreachable | Local SQLite is authoritative source of truth. Writes never fail when S3 is down; failed PUTs are enqueued in `pending_uploads` and redriven on background worker / startup / `/readyz`. |
| **Key Compromise** | Exposure of local private keys | AWS KMS RSASSA_PSS_SHA_256 backend delegates private key operations to hardware security modules without exporting private keys. |
| **PII Leakage in Summaries** | Compliance reports containing raw user identities or sensitive data | Daily CERT-In summary generator only computes masked aggregates, hash fingerprints, and counts. Raw PII is never included in summaries. |

---

## 3. Cryptographic Primitives

- **Hashing**: SHA-256 (`hashlib.sha256`) bound to `user_id`, `leaf_id`, `version`, `nonce`, and timestamps.
- **Signatures**:
  - Dev/CI: RSA-2048 with PSS padding (MGF1, SHA-256) and SHA-256 digest.
  - Production: AWS KMS `RSASSA_PSS_SHA_256`.
- **Integrity Anchors**: Periodic root checkpoints written to WORM-compliant storage (`roots/YYYY-MM-DD-<roothash>.json`).

---

## 4. CERT-In 180-Day Retention Compliance
- System retains logs within a rolling 180-day window per CERT-In directives.
- Automated pruner endpoint (`/api/v1/audit/prune`) securely cleans expired nonces and replay guards while preserving root verification audit chains.
