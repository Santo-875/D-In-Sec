"""
Demo 2: SQL Injection Attempt
Simulates an attacker attempting to exploit the profile update endpoint using a SQL injection payload.
"""

import os
import requests
import time

PORTAL_URL = "http://127.0.0.1:5000"

def run_demo():
    print("="*60)
    print("  D-In-Sec Attack Simulation: SQL Injection")
    print("="*60)
    
    session = requests.Session()
    
    # 1. Attacker creates an account
    username = f"sqli_attacker_{int(time.time())}"
    password = "password123"
    print(f"[*] Attacker registering account: {username}")
    
    res = session.post(f"{PORTAL_URL}/auth/signup", data={
        "username": username,
        "email": f"{username}@example.com",
        "password": password
    })
    
    if res.status_code != 200:
        print("[!] Failed to connect to Mock Portal. Is it running on port 5000?")
        return

    # 2. Attacker attempts to update profile with a SQL injection payload
    print("[*] Attacker injecting SQL payload into 'full_name' field: ' OR 1=1 --")
    
    # Needs to hit the /dashboard/profile endpoint
    data = {
        'full_name': "' OR 1=1 --",
        'date_of_birth': '1990-01-01',
        'phone': '9876543210',
        'address': '123 Main St',
        'aadhaar_number': '1234-5678-9012',
        'pan_number': 'ABCDE1234F'
    }
    
    res = session.post(f"{PORTAL_URL}/dashboard/profile", data=data)
    
    print("[+] Payload sent.")
    print("\nExpected Outcomes:")
    print("1. Mock Portal processes it and logs the event.")
    print("2. Module 2 Tailer intercepts the log, uses Gemini to classify it as SQL_INJECTION.")
    print("3. Module 2 sends a cryptographically signed alert to M3.")
    print("4. M3 anchors it in the Merkle Tree and generates an M4 payload.")
    print("5. Incident appears on the SOC Dashboard!\n")
    print("Check the SOC Dashboard at http://127.0.0.1:5000/soc to verify the incident!")

if __name__ == "__main__":
    run_demo()
