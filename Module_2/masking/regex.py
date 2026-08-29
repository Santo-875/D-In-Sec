import re
import hashlib

PII_PATTERNS = {
    "AADHAAR": re.compile(r"(?:(?<=aadhaar=)[\w\s-]+|\b\d{4}[-\s]?\d{4}[-\s]?\d{4,6}\b)"),
    "PAN": re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b", re.IGNORECASE),
    "EMAIL": re.compile(r"\b[\w.+-]+@[\w-]+\.[a-zA-Z]{2,}\b"),
    "PHONE": re.compile(r"\b\d{10,12}\b"),
    "CREDIT_CARD": re.compile(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b"),
    "DOB": re.compile(r"(?<=dob=)\d{4}-\d{2}-\d{2}\b"),
    "IFSC": re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b"),
    "FULL_NAME": re.compile(r"(?<=full_name=)[^,]+"),
    "ADDRESS": re.compile(r"(?<=address=).*?(?=\s+from IP|$)"),
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


def mask_from_schema(text: str, schema_fields: list) -> tuple[str, list]:
    """
    Dynamic masking using admin-defined FieldSchema records.
    Falls back to mask_structured_pii if no schema fields are provided.

    schema_fields: list of dicts with keys:
        - regex_pattern (str)
        - mask_label (str)  e.g. '[REDACTED_AADHAAR]'
        - pii_category (str) e.g. 'AADHAAR'
    """
    if not schema_fields:
        return mask_structured_pii(text)

    entities_found = []
    for field in schema_fields:
        regex = field.get('regex_pattern')
        mask  = field.get('mask_label') or f"[REDACTED_{field.get('pii_category', 'PII')}]"
        cat   = field.get('pii_category', 'CUSTOM')

        if not regex:
            continue
        try:
            pattern = re.compile(regex)
            matches = pattern.findall(text)
            if matches:
                entities_found.append({'pii_type': cat, 'count': len(matches)})
                text = pattern.sub(mask, text)
        except re.error:
            # Skip invalid regex patterns
            continue

    # Always run IP hashing regardless of schema
    ip_pattern = PII_PATTERNS['IP_ADDRESS']
    ip_matches = ip_pattern.findall(text)
    if ip_matches:
        entities_found.append({'pii_type': 'IP_ADDRESS', 'count': len(ip_matches)})
        text = ip_pattern.sub(
            lambda m: f"[HASHED_IP_{hashlib.sha256((m.group(0) + SECRET_SALT).encode()).hexdigest()[:16]}]",
            text
        )

    return text, entities_found