import sys
import os
from pathlib import Path

# Setup paths and environment
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(BASE_DIR))

from dotenv import load_dotenv
load_dotenv(BASE_DIR / '.env')

from classifier import analyze_log_batch
from tailer import _insert_incident_alert, DB_PATH

def run_test():
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key or api_key == "PASTE_YOUR_KEY_HERE":
        print("[!] Warning: GEMINI_API_KEY is not set in .env. It will use the fallback mock.")
    else:
        print("[+] GEMINI_API_KEY found! Connecting to Google GenAI...")

    print("\n--- Sending Simulated Brute Force Attack to Classifier ---\n")
    
    # 3 consecutive LOGIN_FAIL events to trigger the rule pre-filter
    bf_logs = [
        "[2026-08-08 09:00:01] event=LOGIN_FAIL user=[REDACTED_PERSON] ip=[HASHED_IP_123]",
        "[2026-08-08 09:00:02] event=LOGIN_FAIL user=[REDACTED_PERSON] ip=[HASHED_IP_123]",
        "[2026-08-08 09:00:03] event=LOGIN_FAIL user=[REDACTED_PERSON] ip=[HASHED_IP_123]"
    ]

    res = analyze_log_batch(bf_logs)
    
    if res:
        print("✅ [CLASSIFICATION RESULT]")
        print(f"Incident Type: {res.incident_type.value}")
        print(f"Severity:      {res.severity.value}")
        print(f"Confidence:    {res.confidence}")
        
        # Insert into DB so it shows up on the SOC Dashboard
        _insert_incident_alert(DB_PATH, res, "\n".join(bf_logs))
        
        print("\n📝 [CERT-In DRAFT REPORT PREVIEW]")
        print("-" * 50)
        print(res.cert_in_report_draft)
        print("-" * 50)
        
        print("\nTest passed! Check the SOC Dashboard in the web UI to see the alert.")
    else:
        print("❌ No incident detected.")

if __name__ == "__main__":
    run_test()
