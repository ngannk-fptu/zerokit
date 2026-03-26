import requests
import sys

# Target Configuration
TARGET_URL = "{{TARGET}}"

def check_vulnerability():
    print(f"[*] Testing {TARGET_URL} for information disclosure")

    try:
        resp = requests.get(TARGET_URL, timeout=10)
        content = resp.text.lower()

        # Common sensitive data indicators
        indicators = ["password", "secret", "token", "api_key", "private_key",
                      "stack trace", "exception", "debug", "internal server error"]
        found = [ind for ind in indicators if ind in content]

        if found or resp.status_code in (500, 403):
            print(f"[+] SUCCESS: Sensitive data indicators found: {found}")
            return True

        print("[-] No obvious sensitive information disclosed.")
        return False

    except Exception as e:
        print(f"[-] Request failed: {e}")
        return False

if __name__ == "__main__":
    sys.exit(0 if check_vulnerability() else 1)
