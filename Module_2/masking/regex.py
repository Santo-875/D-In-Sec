import re
import hashlib

PII_PATTERNS = {
    "AADHAAR": re.compile(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}\b"),
    "PAN": re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b", re.IGNORECASE),
    "EMAIL": re.compile(r"\b[\w.+-]+@[\w-]+\.[a-zA-Z]{2,}\b"),
    "PHONE": re.compile(r"\b\d{10,12}\b"),
    "CREDIT_CARD": re.compile(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b"),
    "DOB": re.compile(r"\bdob=\d{4}-\d{2}-\d{2}\b"),
    "IFSC": re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b"),
    "FULL_NAME": re.compile(r"full_name=[^,]+"),
    "ADDRESS": re.compile(r"address=[^,]+(?:,\s*[^,]+)*?(?=\s+from IP)"),
    "IP_ADDRESS": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
}

SECRET_SALT = "DInSec_Secret_Salt_8Xq2zL9mP!"

def mask_structured_pii(text: str) -> tuple[str, list[dict]]:
    entities_found = []

    for pii_type, pattern in PII_PATTERNS.items():
        matches = pattern.findall(text)
        if matches:
            entities_found.append({"pii_type": pii_type, "count": len(matches)})
            if pii_type == "IP_ADDRESS":
                text = pattern.sub(lambda m: f"[HASHED_IP_{hashlib.sha256((m.group(0) + SECRET_SALT).encode()).hexdigest()[:16]}]", text)
            else:
                text = pattern.sub(f"[REDACTED_{pii_type}]", text)

    return text, entities_found