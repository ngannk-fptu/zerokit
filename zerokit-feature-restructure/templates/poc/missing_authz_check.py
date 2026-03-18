import sys
import requests
import requests.exceptions

def verify():
    target_url = "{{TARGET_URL}}"
    # LLM needs to fill in cookies/tokens for an Admin and a Regular User
    headers_admin = {"Authorization": "Bearer {{TOKEN_ADMIN}}"}
    headers_user = {"Authorization": "Bearer {{TOKEN_USER}}"}

    try:
        print(f"[+] Verifying Missing Authorization at {target_url}")
        # Request 1: Regular User tries to access Admin resource
        resp = requests.get(target_url, headers=headers_user, timeout=5)

        # LLM writes check logic here, example:
        if resp.status_code == 200 and "admin_dashboard" in resp.text:
            print("[+] CONFIRMED: Regular user can access administrative functionality.")
            sys.exit(0)
        else:
            print("[-] REJECTED: Proper authorization in place.")
            sys.exit(1)
            
    except requests.exceptions.ConnectionError:
        print("[-] REJECTED: Connection refused (Sandbox is likely isolated / --network none).")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    verify()
