import requests
import time
import sys

# Target Configuration
TARGET_URL = "{{TARGET}}"
REQUEST_COUNT = 50

def check_vulnerability():
    print(f"[*] Testing {TARGET_URL} for resource exhaustion (CWE-400)")

    start = time.time()
    failures = 0
    for i in range(REQUEST_COUNT):
        try:
            requests.get(TARGET_URL, timeout=5)
        except Exception:
            failures += 1

    elapsed = time.time() - start
    fail_rate = failures / REQUEST_COUNT

    print(f"[*] {REQUEST_COUNT} requests in {elapsed:.2f}s, failure rate: {fail_rate:.0%}")

    # Server degradation indicates DoS susceptibility
    if fail_rate > 0.5 or elapsed > 30:
        print("[+] SUCCESS: Server shows signs of resource exhaustion")
        return True

    print("[-] Server handled load without visible degradation.")
    return False

if __name__ == "__main__":
    sys.exit(0 if check_vulnerability() else 1)
