import requests
import sys

# Target Configuration
TARGET_URL = "{{TARGET}}"

def check_vulnerability():
    print(f"[*] Testing {TARGET_URL} for missing authentication (CWE-306)")

    try:
        # Access sensitive endpoint without any auth headers
        resp = requests.get(TARGET_URL, timeout=10)

        if resp.status_code == 200:
            print(f"[+] SUCCESS: Endpoint accessible without authentication (HTTP 200)")
            return True

        print(f"[-] Endpoint returned {resp.status_code} — auth likely enforced.")
        return False

    except Exception as e:
        print(f"[-] Request failed: {e}")
        return False

if __name__ == "__main__":
    sys.exit(0 if check_vulnerability() else 1)
