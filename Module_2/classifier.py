import os
import time
from schemas import ClassificationResult, IncidentType, Severity

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

try:
    from google import genai
    from google.genai import types
    HAS_GENAI = True
except ImportError:
    HAS_GENAI = False

def generate_cert_in_draft(incident_type: IncidentType, logs: list[str]) -> str:
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S UTC")
    draft = f"""CERT-In CYBER SECURITY INCIDENT REPORT (DRAFT)
==================================================
Date of Detection: {timestamp}
Incident Type: {incident_type.name}

Description:
A potential security incident was detected by the automated SOC classification engine. 
The system detected anomalous patterns consistent with {incident_type.name}.

Masked Logs Evidence:
"""
    for log in logs:
        draft += f"- {log}\n"
    
    draft += """
Recommended Action:
- Review the source IP and block if necessary.
- Reset credentials for affected user accounts.
- Audit the firewall rules.

(Draft generated automatically by D-In-Sec SOC Engine)
"""
    return draft

def _fallback_classification(combined: str, masked_logs: list[str]) -> ClassificationResult | None:
    """Deterministic rule-based fallback if LLM is unavailable."""
    if combined.count("LOGIN_FAILED") >= 3 or combined.count("event=LOGIN_FAIL") >= 3:
        res = ClassificationResult(incident_type=IncidentType.BRUTE_FORCE, severity=Severity.HIGH, confidence=0.92, source="fallback_rules")
    elif "SELECT" in combined and "UNION" in combined:
        res = ClassificationResult(incident_type=IncidentType.SQL_INJECTION, severity=Severity.CRITICAL, confidence=0.98, source="fallback_rules")
    elif "UPLOAD_REJECTED" in combined:
        res = ClassificationResult(incident_type=IncidentType.MALICIOUS_UPLOAD, severity=Severity.HIGH, confidence=0.95, source="fallback_rules")
    elif "VERIFY_UNAUTHORIZED" in combined or "UNAUTHORIZED_ADMIN_ACCESS" in combined:
        res = ClassificationResult(incident_type=IncidentType.UNAUTHORIZED_ACCESS, severity=Severity.MEDIUM, confidence=0.88, source="fallback_rules")
    else:
        return None
        
    if res.severity in (Severity.HIGH, Severity.CRITICAL):
        res.cert_in_report_draft = generate_cert_in_draft(res.incident_type, masked_logs)
    return res

def analyze_log_batch(masked_logs: list[str]) -> ClassificationResult | None:
    """
    Hybrid pipeline: uses rule-based triggers as a fast pre-filter to avoid burning API calls,
    and then sends the batch to Gemini for structured deep classification.
    """
    if not masked_logs:
        return None
        
    combined = " ".join(masked_logs)
    
    # 1. Fast Pre-Filter (Rules) - only invoke the expensive LLM if it looks suspicious
    needs_llm = False
    if combined.count("LOGIN_FAILED") >= 3 or combined.count("event=LOGIN_FAIL") >= 3:
        needs_llm = True
    elif "SELECT" in combined and "UNION" in combined:
        needs_llm = True
    elif "UPLOAD_REJECTED" in combined:
        needs_llm = True
    elif "VERIFY_UNAUTHORIZED" in combined or "UNAUTHORIZED_ADMIN_ACCESS" in combined:
        needs_llm = True
        
    if not needs_llm:
        return None

    # 2. Real LLM Call
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key or not HAS_GENAI:
        print("[WARNING] GEMINI_API_KEY not set or google-genai missing! Using deterministic fallback rules.")
        return _fallback_classification(combined, masked_logs)

    prompt = f"""
    You are a Security Operations Center (SOC) expert. 
    Analyze the following batch of masked application logs and determine if a security incident occurred.
    
    Masked Logs:
    {chr(10).join(masked_logs)}
    
    Return a structured JSON object matching the requested schema. 
    If you detect a brute force attack (e.g., multiple login failures), malicious upload, unauthorized access, or SQL injection, 
    classify it appropriately. Ensure you classify Brute Force attacks as HIGH severity. Set a realistic confidence score between 0.0 and 1.0.
    """
    
    # Suppress the noisy AFC warning from the SDK
    import logging
    logging.getLogger("google.genai").setLevel(logging.ERROR)
    
    client = genai.Client(api_key=api_key)
    config = types.GenerateContentConfig(
        response_mime_type="application/json",
        response_schema=ClassificationResult,
        temperature=0.1
    )
    
    try:
        # Tier 1: Try flagship model
        response = client.models.generate_content(
            model='gemini-3.6-flash',
            contents=prompt,
            config=config,
        )
    except Exception as e1:
        print(f"[WARNING] Primary model gemini-3.6-flash failed ({e1}). Attempting retry with gemini-2.5-flash...")
        try:
            # Tier 2: Try fallback model
            response = client.models.generate_content(
                model='gemini-2.5-flash',
                contents=prompt,
                config=config,
            )
        except Exception as e2:
            print(f"[ERROR] Both LLM models failed ({e2}). Falling back to deterministic rules.")
            return _fallback_classification(combined, masked_logs)

    try:
        res = response.parsed
        if res and res.severity in (Severity.HIGH, Severity.CRITICAL):
            res.cert_in_report_draft = generate_cert_in_draft(res.incident_type, masked_logs)
        return res
    except Exception as e3:
        print(f"[ERROR] LLM parsing failed ({e3}). Falling back to deterministic rules.")
        return _fallback_classification(combined, masked_logs)
