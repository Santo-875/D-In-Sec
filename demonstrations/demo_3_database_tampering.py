"""
Demo 3: Database Tampering Attempt
Simulates a rogue admin or attacker modifying a record directly in the SQLite database,
bypassing the application logic. Then triggers an M3 integrity verification.
"""

import os
import sqlite3
import requests
import json
import time

M3_API_URL = "http://127.0.0.1:5001/api/v1"
ADMIN_KEY = os.environ.get("M3_ADMIN_API_KEY", "dev-admin-key")

# Database path (assuming the script runs from the project root)
DB_PATH = os.path.join(os.path.dirname(__file__), "..", "m3", "m3.db")

def run_demo():
    print("="*60)
    print("  D-In-Sec Attack Simulation: Database Tampering")
    print("="*60)
    
    if not os.path.exists(DB_PATH):
        print(f"[!] M3 Database not found at {DB_PATH}. Is M3 running and initialized?")
        return

    # 1. Fetch a leaf from the database
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT user_id, leaf_id, masked_pii_hash, real_data_hash FROM merkle_leaves LIMIT 1")
    row = cursor.fetchone()
    
    if not row:
        print("[!] No records found in the Merkle Tree. Please run Demo 1 or 2 first.")
        conn.close()
        return
        
    user_id, leaf_id, masked_hash, real_hash = row
    print(f"[*] Found target record: User '{user_id}', Leaf '{leaf_id}'")
    
    # 2. Tamper with the hash in the database
    print("[*] Attacker connecting directly to SQLite database...")
    tampered_hash = "tampered_" + masked_hash[9:]
    cursor.execute("UPDATE merkle_leaves SET masked_pii_hash = ? WHERE leaf_id = ?", (tampered_hash, leaf_id))
    conn.commit()
    conn.close()
    
    print(f"[+] Record tampered! Masked hash changed to: {tampered_hash[:20]}...")
    
    # 3. Trigger verification
    print("[*] SOC Dashboard (or scheduled task) requesting integrity verification...")
    
    req_body = {
        "user_id": user_id,
        "leaf_id": leaf_id,
        "masked_pii_hash": tampered_hash,
        "real_data_hash": real_hash
    }
    
    try:
        res = requests.post(
            f"{M3_API_URL}/audit/verify", 
            json=req_body, 
            headers={"X-API-Key": ADMIN_KEY}
        )
        data = res.json()
        print("\n[+] Verification Result:")
        print(json.dumps(data, indent=2))
        
    except Exception as e:
        print(f"[!] Failed to connect to M3: {e}")
        return

    print("\nExpected Outcomes:")
    print("1. M3 detects the hash mismatch and returns a FAILED verification.")
    print("2. M3's breach_alert.py intercepts this failure.")
    print("3. Gemini translates the cryptographic mismatch into a CERT-In plain-language draft.")
    print("4. A DATA_TAMPERING incident is immediately inserted into the SOC Dashboard.")
    print("\nCheck the SOC Dashboard at http://127.0.0.1:5000/soc to see the generated Breach Alert!")

if __name__ == "__main__":
    run_demo()
