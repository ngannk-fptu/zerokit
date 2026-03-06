import requests
import sys

# Target Configuration
TARGET_URL = "{{TARGET}}"
PAYLOAD = "{{PAYLOAD}}" # e.g., "<script>alert(1)</script>"

def check_vulnerability():
    print(f"[*] Testing {TARGET_URL} with payload: {PAYLOAD}")
    
    # Attack Request
    target_with_payload = f"{TARGET_URL}{PAYLOAD}"
    
    try:
        resp = requests.get(target_with_payload, timeout=10)
        content = resp.text
        
        if PAYLOAD in content:
            print("[+] SUCCESS: Payload reflected in response!")
            return True
        else:
            print("[-] Payload not found in response.")
            # Check for encoded version?
            return False
            
    except Exception as e:
        print(f"[-] Request failed: {e}")
        return False

if __name__ == "__main__":
    if check_vulnerability():
        sys.exit(0)
    sys.exit(1)
