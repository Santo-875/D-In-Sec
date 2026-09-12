import re
import hashlib
import hmac
import os
import ipaddress

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

SECRET_KEY = os.environ.get("PII_HASH_KEY", "DInSec_Secret_Salt_8Xq2zL9mP!").encode()

def _hash_ip(ip: str) -> str:
    return hmac.new(SECRET_KEY, ip.encode(), hashlib.sha256).hexdigest()[:16]

def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def is_valid_credit_card(cc: str) -> bool:
    # Remove all non-digit characters
    digits = [int(c) for c in cc if c.isdigit()]
    if not digits:
        return False
    # Luhn algorithm
    checksum = 0
    for i, digit in enumerate(reversed(digits)):
        if i % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0

def mask_structured_pii(text: str) -> tuple[str, list[dict], bool]:
    entities_found = []
    has_leak = False

    for pii_type, pattern in PII_PATTERNS.items():
        matches = pattern.findall(text)
        if matches:
            for m in matches:
                if pii_type == "IP_ADDRESS":
                    if is_valid_ip(m):
                        entities_found.append({"pii_type": pii_type, "count": 1})
                        text = text.replace(m, f"[HASHED_IP_{_hash_ip(m)}]")
                elif pii_type == "CREDIT_CARD":
                    if is_valid_credit_card(m):
                        entities_found.append({"pii_type": pii_type, "count": 1})
                        has_leak = True
                        text = text.replace(m, f"[REDACTED_{pii_type}]")
                else:
                    entities_found.append({"pii_type": pii_type, "count": 1})
                    has_leak = True
                    text = text.replace(m, f"[REDACTED_{pii_type}]")

    return text, entities_found, has_leak


def mask_from_schema(text: str, schema_fields: list) -> tuple[str, list, bool]:
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
    has_leak = False
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
                if cat != 'IP_ADDRESS':
                    has_leak = True
        except re.error:
            # Skip invalid regex patterns
            continue

    # Always run IP hashing regardless of schema with strict validation
    ip_pattern = PII_PATTERNS['IP_ADDRESS']
    ip_matches = ip_pattern.findall(text)
    if ip_matches:
        for m in ip_matches:
            if is_valid_ip(m):
                entities_found.append({'pii_type': 'IP_ADDRESS', 'count': 1})
                text = text.replace(m, f"[HASHED_IP_{_hash_ip(m)}]")

    # Check for structured defaults in case schema missed them
    if not has_leak:
        for pii_type in ["AADHAAR", "PAN", "CREDIT_CARD", "PHONE"]:
            matches = PII_PATTERNS[pii_type].findall(text)
            if matches:
                for m in matches:
                    if pii_type == "CREDIT_CARD" and not is_valid_credit_card(m):
                        continue
                    has_leak = True
                    text = text.replace(m, f"[REDACTED_{pii_type}]")

    return text, entities_found, has_leak