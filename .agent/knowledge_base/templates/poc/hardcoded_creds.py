import re
import sys

# Target Configuration — path to source file under test
TARGET_FILE = "{{TARGET}}"

# Patterns that indicate hardcoded credentials (CWE-798, CWE-327)
PATTERNS = [
    r'password\s*=\s*["\'][^"\']{3,}["\']',
    r'secret\s*=\s*["\'][^"\']{3,}["\']',
    r'api_key\s*=\s*["\'][^"\']{3,}["\']',
    r'token\s*=\s*["\'][^"\']{3,}["\']',
    r'private_key\s*=\s*["\'][^"\']{3,}["\']',
]

def check_vulnerability():
    print(f"[*] Scanning {TARGET_FILE} for hardcoded credentials")

    try:
        with open(TARGET_FILE, "r", errors="replace") as f:
            content = f.read()
    except OSError as e:
        print(f"[-] Cannot read file: {e}")
        return False

    for pattern in PATTERNS:
        matches = re.findall(pattern, content, re.IGNORECASE)
        if matches:
            print(f"[+] SUCCESS: Hardcoded credential found: {matches[0][:80]}")
            return True

    print("[-] No hardcoded credentials detected.")
    return False

if __name__ == "__main__":
    sys.exit(0 if check_vulnerability() else 1)
