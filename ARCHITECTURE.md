# D-In-Sec Module 3 — Sidecar Architecture

## Overview
Module 3 (M3) is designed as a standalone, cloud-ready API sidecar service that provides cryptographic integrity, tamper detection, anti-replay protection, and compliance reporting for audit streams.

```
+-------------------------------------------------------------------------+
|                              Host Application                           |
|                      (Module 2 Tailer / Microservices)                  |
+-------------------------------------------------------------------------+
                                    |
                    REST / JSON (X-API-Key, Signed Payload)
                                    v
+-------------------------------------------------------------------------+
|                             M3 API SIDECAR                              |
|                                                                         |
|   +-------------------+  +-------------------+  +-------------------+   |
|   | /healthz, /readyz |  |  Fast AI Loop     |  | Role-Based Auth   |   |
|   | Probes & Metrics  |  |  TF-IDF + LogReg  |  | ADMIN/SVC/VIEWER  |   |
|   +-------------------+  +-------------------+  +-------------------+   |
|                                                                         |
|   +-----------------------------------------------------------------+   |
|   |                   Anti-Replay & Freeze Guard                    |   |
|   |     (Clock skew check, UUID nonce uniqueness, Write-Freeze)     |   |
|   +-----------------------------------------------------------------+   |
|                                                                         |
|   +-----------------------------------------------------------------+   |
|   |                   Hierarchical Merkle Tree Engine               |   |
|   |           Leaves -> User Subroots -> Master Root Chain          |   |
|   +-----------------------------------------------------------------+   |
|                                                                         |
|   +-----------------------------------------------------------------+   |
|   |                   Durable Storage Coordinator                   |   |
|   |  Authoritative SQLite  <====== Write-Through ======>  S3 / KMS  |   |
|   |  (pending_uploads queue for offline resilience)                 |   |
|   +-----------------------------------------------------------------+   |
+-------------------------------------------------------------------------+
                                    |
                         Write-Through Sink / WORM
                                    v
+-------------------------------------------------------------------------+
|                       AWS Infrastructure (Ephemeral)                    |
|       - S3 Bucket (Object Lock Compliance, SSE-KMS, Versioning)         |
|       - KMS Asymmetric Key (RSASSA_PSS_SHA_256)                         |
|       - KMS Symmetric Key (SSE-KMS Encryption at Rest)                  |
+-------------------------------------------------------------------------+
```

## Component Breakdown

1. **API Layer (`m3/api.py`)**:
   - Production WSGI compatible (`gunicorn -w 4 -b 0.0.0.0:5001 "m3.api:create_m3_app()"`).
   - `/healthz` & `/readyz` for Kubernetes / container orchestrator health checks.
   - Comprehensive verification `/api/v1/verify/full` verifying both local database and external anchor.
   - `/v1/events` unified ingestion with fast local ML event classification (`m3/retrain.py`).

2. **Storage Layer (`m3/storage.py`)**:
   - `StorageBackend` abstraction supporting `LocalBackend` (dev/test) and `S3Backend` (AWS S3 + SSE-KMS).
   - `DurableStorage` write-through sink with `pending_uploads` database queue ensuring zero write loss during cloud storage partitions or outages.

3. **Signer Layer (`m3/signer.py`)**:
   - `Signer` abstraction supporting `LocalRSASigner` (local in-memory RSA key) and `KMSSigner` (AWS KMS asymmetric signing).

4. **AI & Retraining Pipeline (`m3/retrain.py`, `m3/summary.py`)**:
   - Fast loop: TF-IDF + Logistic Regression running sub-millisecond local inference.
   - Deferral: Borderline/uncertain predictions automatically defer to Gemini AI.
   - Slow loop: Human review queue (`review_queue`) collects feedback. Automated `retrain()` trains candidate model, validates against holdout set, and promotes only if F1 >= active model.
   - Compliance: Daily summary generator produces masked CERT-In compliance summaries.
