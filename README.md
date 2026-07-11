# D-In-Sec

> An AI-driven, decoupled compliance sidecar API that resolves the architectural conflict between DPDP data privacy laws and CERT-In 6-hour incident reporting mandates by automating PII masking, classifying attack vectors, and ensuring cryptographic log integrity using Merkle Trees for MSME.

---

## Architecture Overview

D-In-Sec is designed as a **modular, decoupled system** where the core business application (the mock corporate portal) remains completely oblivious to compliance logic. The compliance engine operates as an external sidecar, plugging into the application's raw log stream.

| Module | Description | Status |
|---|---|---|
| **Module 1** — Mock Corporate Portal | User auth, document uploads, PII data collection, raw system logging | ✅ Built |
| **Module 2** — Compliance Sidecar API | SpaCy NER PII masking, Merkle Tree log integrity, CERT-In reporting | 🔜 Planned |
| **Module 3** — Attack Simulator | SQL injection, brute-force, malicious upload simulation scripts | 🔜 Planned |

---

## Module 1: Mock Corporate Portal

A clean, enterprise-grade document verification portal that collects sensitive PII and generates raw, un-anonymized system logs.

### Features

- **User Authentication** — Signup/Login with session-based auth and hashed passwords
- **Profile Management** — Full Name, DOB, Aadhaar, PAN, Phone, Address
- **Document Upload** — PDF/PNG/JPG/DOC file uploads with type classification
- **Mock Verification** — Validates profile completeness before marking documents as Verified
- **Raw PII Logging** — All actions dump un-anonymized event logs to `stdout` and `logs/system.log`

### Tech Stack

- **Backend:** Flask + SQLAlchemy + Flask-Login
- **Database:** SQLite
- **Frontend:** Jinja2 Templates + Vanilla CSS + JavaScript
- **Auth:** Werkzeug password hashing + session cookies

### Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/YOUR_USERNAME/D-In-Sec.git
cd D-In-Sec/mock_site

# 2. Create a virtual environment
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # macOS/Linux

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the server
python app.py
```

The portal will be live at **http://127.0.0.1:5000**

### Log Output Format

While processing user actions, the server outputs raw, un-anonymized event logs:

```
[2026-07-11 12:30:45] [INFO] User john_doe (john_doe@email.com) logged in successfully from IP 192.168.1.50
[2026-07-11 12:31:12] [INFO] User john_doe (john_doe@email.com) updated profile: full_name=John Doe, dob=1995-03-15, aadhaar=1234-5678-9012, pan=ABCDE1234F, phone=+91-9876543210, address=42 MG Road, Bangalore
[2026-07-11 12:31:30] [INFO] User john_doe (john_doe@email.com) uploaded document Aadhaar_Card.pdf (type: Aadhaar Card) from IP 192.168.1.50
[2026-07-11 12:35:00] [WARNING] Failed login attempt for username 'admin' from IP 10.0.0.5
[2026-07-11 12:36:00] [ERROR] File upload rejected: user john_doe (john_doe@email.com) attempted to upload malware.exe (disallowed extension) from IP 192.168.1.50
```

These raw logs are the **pivot point** — consumed by the downstream Module 2 compliance sidecar for PII masking, attack classification, and CERT-In report generation.

### Project Structure

```
D-In-Sec/
├── mock_site/
│   ├── app.py                  # Flask app factory
│   ├── models.py               # SQLAlchemy models (User, Document)
│   ├── routes/
│   │   ├── __init__.py         # Blueprint registration
│   │   ├── auth.py             # Login / Signup / Logout
│   │   └── dashboard.py       # Profile, Upload, Verify
│   ├── templates/
│   │   ├── base.html           # Master layout
│   │   ├── login.html          # Login page
│   │   ├── signup.html         # Signup page
│   │   └── dashboard.html      # User dashboard
│   ├── static/
│   │   ├── css/style.css       # Enterprise dark theme
│   │   └── js/main.js          # Client-side interactions
│   ├── uploads/                # User-uploaded files (gitignored)
│   ├── logs/                   # Raw system logs (gitignored)
│   └── requirements.txt
├── .gitignore
└── README.md
```

---

## License

This project is developed as part of an academic research initiative.
