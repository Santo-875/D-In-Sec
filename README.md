# D-In-Sec

> An AI-driven, decoupled compliance sidecar API that resolves the architectural conflict between DPDP data privacy laws and CERT-In 6-hour incident reporting mandates by automating PII masking, classifying attack vectors, and ensuring cryptographic log integrity using Merkle Trees for MSME.

---

## Architecture Overview

D-In-Sec is designed as a **modular, decoupled system** where the core business application (the mock corporate portal) remains completely oblivious to compliance logic. The compliance engine operates as an external sidecar, plugging into the application's raw log stream.

| Module | Description | Status |
|---|---|---|
| **Module 1** — Mock Corporate Portal | User auth, document uploads, PII data collection, raw system logging | ✅ Built |
| **Module 2** — Sidecar Tailer & AI | SpaCy NER PII masking, Gemini log classification, DB persistence | ✅ Built |
| **Module 3** — Integrity Engine | Hierarchical Merkle Tree, cryptographic signatures, Replay Guard | ✅ Built |
| **Module 4** — AI SOC Dashboard | AI CERT-In drafts, end-to-end cryptographic integrity verification | ✅ Built |

---

## Module 1: Mock Corporate Portal

A clean, enterprise-grade document verification portal that collects sensitive PII and generates raw, un-anonymized system logs.

- **Backend:** Flask + SQLAlchemy + Flask-Login
- **Database:** SQLite (Encrypted Vault for PII)
- **Logging:** All actions dump raw event logs to `stdout` and `mock_site/logs/system.log`

---

## Module 2, 3, 4: The Compliance Sidecar

The downstream pipeline monitors `system.log` in real-time. It intercepts logs, masks PII, detects anomalies using Gemini, and cryptographically anchors the events in a Hierarchical Merkle Tree (M3). If a breach or tampering is detected, it auto-generates CERT-In compliance drafts.

---

## Quick Start & End-to-End Demonstrations

### 1. Setup Environment
```bash
# 1. Create a virtual environment
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # macOS/Linux

# 2. Install dependencies
pip install -r mock_site/requirements.txt
# Note: You may need to install spacy and cryptography separately.
pip install spacy cryptography google-genai
python -m spacy download en_core_web_sm

# 3. Setup Environment Variables
# Copy .env.example to .env and fill in your GEMINI_API_KEY
```

### 2. Run the Services
You need to run three separate processes concurrently to see the system working end-to-end.

**Terminal 1: Mock Portal (Module 1)**
```bash
$env:PYTHONPATH="."  # Windows
python mock_site/app.py
# Running on http://127.0.0.1:5000
```

**Terminal 2: Integrity Engine (Module 3)**
```bash
$env:PYTHONPATH="."  # Windows
python m3/api.py
# Running on http://127.0.0.1:5001
```

**Terminal 3: Compliance Tailer (Module 2)**
```bash
$env:PYTHONPATH="."  # Windows
python Module_2/tailer.py
# Tails mock_site/logs/system.log in real-time
```

### 3. Run Attack Demonstrations

We have prepared three attack simulations that interact with the Mock Portal and bypass the backend to trigger the compliance engine.

**Terminal 4: Run Demos**
```bash
# Demo 1: Malware Upload
python demonstrations/demo_1_malware_upload.py

# Demo 2: SQL Injection 
python demonstrations/demo_2_sql_injection.py

# Demo 3: Database Tampering (The ultimate compliance test)
# (Directly modifies a Merkle leaf hash in M3, triggering an AI breach alert)
python demonstrations/demo_3_database_tampering.py
```

### 4. View the SOC Dashboard (Module 4)

After running the demos, log into the Mock Portal at `http://127.0.0.1:5000` as an Admin (or run `python mock_site/create_admin.py` to create one).

Click the red **SOC** button in the navigation bar to access the Incident Dashboard.
You will see:
1. The Incident alerts.
2. The AI-generated CERT-In drafts.
3. The real-time cryptographic inclusion proofs and M3 verification statuses!

---

## License

This project is developed as part of an academic cybersecurity research initiative.
