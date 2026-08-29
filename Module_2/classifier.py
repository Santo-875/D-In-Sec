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
        # Fallback for local testing without an API key
        print("[WARNING] GEMINI_API_KEY not set or google-genai missing! Falling back to basic mock rule logic.")
        if combined.count("LOGIN_FAIL") >= 3:
            return ClassificationResult(
                incident_type=IncidentType.BRUTE_FORCE,
                severity=Severity.HIGH,
                confidence=0.92,
                cert_in_report_draft=generate_cert_in_draft(IncidentType.BRUTE_FORCE, masked_logs),
                source="llm_mock"
            )
        return None

    try:
        client = genai.Client(api_key=api_key)
        prompt = f"""
        You are a Security Operations Center (SOC) expert. 
        Analyze the following batch of masked application logs and determine if a security incident occurred.
        
        Masked Logs:
        {chr(10).join(masked_logs)}
        
        Return a structured JSON object matching the requested schema. 
        If you detect a brute force attack (e.g., multiple login failures), malicious upload, unauthorized access, or SQL injection, 
        classify it appropriately. Ensure you classify Brute Force attacks as HIGH severity. Set a realistic confidence score between 0.0 and 1.0.
        If severity is HIGH or CRITICAL, draft a CERT-In compliance report in the 'cert_in_report_draft' field.
        """
        
        # Suppress the noisy AFC warning from the SDK
        import logging
        logging.getLogger("google.genai").setLevel(logging.ERROR)
        
        response = client.models.generate_content(
            model='gemini-3.6-flash',
            contents=prompt,
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                response_schema=ClassificationResult,
                temperature=0.1
            ),
        )
        return response.parsed
    except Exception as e:
        print(f"[ERROR] LLM Classification failed: {e}")
        return None
