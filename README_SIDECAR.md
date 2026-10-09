# D-In-Sec Module 3 (M3) Sidecar

[![CI Pipeline](https://github.com/Santo-875/D-In-Sec/actions/workflows/ci.yml/badge.svg)](https://github.com/Santo-875/D-In-Sec/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

A cloud-ready, reusable security sidecar designed to provide **immutable audit trail integrity**, **hierarchical Merkle tree state verification**, **S3 WORM / Object Lock write-through anchoring**, and **CERT-In 180-day compliance**.

---

## 🏛️ Architecture & Principles

```
  Upstream Service (e.g. Mock Site / Node App)
            │
            ▼ (HTTP POST /v1/events)
 ┌───────────────────────────────────────────────┐
 │            D-In-Sec M3 Sidecar                │
 │  ┌─────────────────────────────────────────┐  │
 │  │ SQLite Database (Source of Truth)       │  │
 │  │   - Hierarchical Merkle Tree (O(log n)) │  │
 │  │   - Replay Guard (Nonce / Monotonic)    │  │
 │  │   - Append-Only 180-day Audit Chain     │  │
 │  └────────────────────┬────────────────────┘  │
 │                       │                       │
 │  ┌────────────────────▼────────────────────┐  │
 │  │ Durable Storage Write-Through Wrapper   │  │
 │  │   - Write to S3 (logs/ & roots/)        │  │
 │  │   - pending_uploads queue (never blocks)│  │
 │  │   - Auto-retry background drain worker  │  │
 │  └────────────────────┬────────────────────┘  │
 └───────────────────────┼───────────────────────┘
                         │
                         ▼
        ┌────────────────────────────────┐
        │        AWS Infrastructure      │
        │  ┌──────────────────────────┐  │
        │  │ S3 Bucket (Object Lock)  │  │
        │  │  - SSE-KMS (Data Key)    │  │
        │  │  - 180d Lifecycle Logs   │  │
        │  │  - Permanent roots/ WORM │  │
        │  └──────────────────────────┘  │
        │  ┌──────────────────────────┐  │
        │  │ KMS Signing Key          │  │
        │  │  - RSASSA_PSS_SHA_256    │  │
        │  └──────────────────────────┘  │
        └────────────────────────────────┘
```

1. **SQLite is the Authoritative Source of Truth**: Writes commit to SQLite first. If S3 fails or is degraded, the write is queued in `pending_uploads` and drained when connectivity restores. Outages **never block writes**.
2. **Cryptographic Checkpoint Anchoring**: Signed checkpoints `{tenant, master_root, leaf_count, ts, key_id, signature}` are uploaded to S3 `roots/` periodically and on admin demand.
3. **Strict Separation of KMS Keys**:
   - `KMS_KEY_ID`: Asymmetric key used exclusively by `signer.py` for RSASSA_PSS_SHA_256 digital signatures.
   - `KMS_DATA_KEY_ID`: Symmetric key used exclusively by `storage.py` for S3 server-side encryption (SSE-KMS).
4. **Deterministic Tamper Detection**: AI never participates in pass/fail decisions. Merkle math and cryptographic signatures deterministically freeze the system on any unauthorized state modification.

---

## 🚀 Quickstart

### 1. Running with Docker Compose

```bash
# Start M3 Sidecar alongside the corporate mock site
docker-compose up --build
```
- Sidecar API: `http://localhost:5001`
- Mock Corporate Portal & SOC Dashboard: `http://localhost:5000/soc/`

### 2. Running Locally (Development)

```bash
# Install dependencies
pip install -r requirements.txt

# Start M3 sidecar with Flask development runner
python m3/api.py
```

### 3. Production Deployment (Gunicorn)

```bash
gunicorn -w 1 --threads 8 -b 0.0.0.0:5001 "m3.api:create_m3_app()" --timeout 120
```

> **Note on Worker Model**: Deploy with `-w 1 --threads 8` because Merkle tree state and append-only audit caches are held in-memory per-process. A single worker with multi-threading maintains state consistency across requests while handling concurrent traffic. For cross-worker sync, automated staleness detection via database versions refreshes in-memory structures.

---

## ⚙️ Configuration Reference

Copy `.env.example` to `.env` to configure:

| Variable | Default | Purpose |
| :--- | :--- | :--- |
| `STORAGE_BACKEND` | `local` | Storage sink: `local` (disk) or `s3` (AWS S3) |
| `SIGNER_BACKEND` | `local` | Signature engine: `local` (RSA in-memory) or `kms` (AWS KMS) |
| `S3_BUCKET` | — | Target AWS S3 bucket name (required if `STORAGE_BACKEND=s3`) |
| `AWS_REGION` | `ap-south-1` | AWS region |
| `KMS_KEY_ID` | — | Asymmetric KMS key ID for digital signing (`RSASSA_PSS_SHA_256`) |
| `KMS_DATA_KEY_ID` | — | Symmetric KMS key ID for S3 SSE (`ENCRYPT_DECRYPT`) |
| `M3_API_KEYS` | (Dev keys) | JSON mapping of API keys to roles (`ADMIN`, `SERVICE`, `VIEWER`) |
| `ANCHOR_EVERY_N` | `10` | Write count interval between S3 root anchors |
| `ANCHOR_EVERY_SEC`| `300` | Seconds interval between S3 root anchors |
| `TENANT_ID` | `default` | Tenant namespace identifier |

---

## 📡 API Reference

All requests requiring authentication require an `X-API-Key` header.

| Method | Endpoint | Role | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/healthz` | Public | Liveness probe (200 alive) |
| `GET` | `/readyz` | Public | Readiness probe (S3 reachability & pending backlog) |
| `POST` | `/v1/events` | `SERVICE`, `ADMIN` | Unified event ingestion & tree update |
| `GET` | `/api/v1/tree/root` | `VIEWER`, `ADMIN` | Current Master Root state & root chain |
| `POST` | `/audit/verify` | `VIEWER`, `ADMIN` | End-to-end leaf proof & storage anchor verification |
| `GET` | `/v1/verify/full` | `VIEWER`, `ADMIN` | Full tree vs S3 anchor comparison & signature verification |
| `POST` | `/v1/admin/anchor` | `ADMIN` | Immediately anchor signed checkpoint to S3 |
| `GET` | `/v1/alerts` | `VIEWER`, `ADMIN` | Security and tamper alerts list |
| `GET` | `/v1/export/certin` | `VIEWER`, `ADMIN` | Export 180-day compliance audit bundle |
| `GET` | `/v1/admin/model/registry` | `VIEWER`, `ADMIN` | Fast classifier model versions |
| `POST` | `/v1/admin/model/rollback/<v>` | `ADMIN` | Rollback ML classifier to prior version |

---

## 💻 SDK Usage

### Python

```python
from sdk.python.dinsec_client import DinSecClient

client = DinSecClient(base_url="http://127.0.0.1:5001", api_key="dev-service-key")

# Check readiness & cloud health
health = client.is_ready()
print("Cloud status:", health["status"])

# Submit and verify an event
res = client.ingest_event(
    user_id="user_42",
    leaf_id="document_101",
    masked_pii="USER: ********",
    real_data="USER: John Doe",
    private_key_pem=my_private_pem
)
print("Event ID:", res["event_id"])
print("Master Root:", res["calculated_next_master_root"])

# Full verification against S3 anchor
verify = client.full_verify()
print("Verification Status:", verify["status"]) # VERIFIED
```

### JavaScript / Node.js

```javascript
const { DinSecClient } = require('./sdk/js/dinsec');

const client = new DinSecClient({
    baseUrl: 'http://127.0.0.1:5001',
    apiKey: 'dev-service-key'
});

async function main() {
    const ready = await client.isReady();
    console.log('Sidecar ready:', ready.status);

    const result = await client.fullVerify();
    console.log('Full verify:', result.status);
}
main();
```
