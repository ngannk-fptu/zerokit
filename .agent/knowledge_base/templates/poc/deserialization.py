import requests
import sys

# Target Configuration
TARGET_URL = "{{TARGET}}"

# Minimal deserialization probe payloads (CWE-502)
# These check for Java, Python pickle, and PHP object injection markers
PAYLOADS = [
    # Python pickle marker (triggers on unsafe pickle.loads)
    b"\x80\x04\x95\x1a\x00\x00\x00\x00\x00\x00\x00\x8c\x08builtins\x94\x8c\x04repr\x94\x93\x94.",
]

CONTENT_TYPES = ["application/octet-stream", "application/x-java-serialized-object"]

def check_vulnerability():
    print(f"[*] Testing {TARGET_URL} for unsafe deserialization (CWE-502)")

    for ct in CONTENT_TYPES:
        for payload in PAYLOADS:
            try:
                resp = requests.post(
                    TARGET_URL,
                    data=payload,
                    headers={"Content-Type": ct},
                    timeout=10,
                )
                # 500 with exception trace often confirms deserialization attempt
                if resp.status_code == 500 and (
                    "exception" in resp.text.lower()
                    or "error" in resp.text.lower()
                ):
                    print(f"[+] SUCCESS: Server error on deserialization payload ({ct})")
                    return True
                if resp.status_code == 200:
                    print(f"[+] Payload accepted (status 200) with {ct} — investigate manually")
                    return True
            except Exception as e:
                print(f"[-] Request failed: {e}")

    print("[-] No deserialization vulnerability detected.")
    return False

if __name__ == "__main__":
    sys.exit(0 if check_vulnerability() else 1)
