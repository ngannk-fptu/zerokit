import sys
import requests
import requests.exceptions

def verify():
    target_url = "{{TARGET_URL}}"
    # LLM needs to fill in cookies/tokens for User A and User B
    headers_user_a = {"Authorization": "Bearer {{TOKEN_A}}"}
    headers_user_b = {"Authorization": "Bearer {{TOKEN_B}}"}

    try:
        print(f"[+] Verifying IDOR / Cross-User Access at {target_url}")
        # Request 1: User A creates or accesses resource
        resp_a = requests.get(target_url, headers=headers_user_a, timeout=5)
        
        # Request 2: User B tries to access User A's resource
        resp_b = requests.get(target_url, headers=headers_user_b, timeout=5)

        # LLM writes check logic here, example:
        if resp_b.status_code == 200 and "sensitive_data" in resp_b.text:
            print("[+] CONFIRMED: User B can access User A's data.")
            sys.exit(0)
        else:
            print("[-] REJECTED: Proper authorization in place or resource inaccessible.")
            sys.exit(1)
            
    except requests.exceptions.ConnectionError:
        print("[-] REJECTED: Connection refused (Sandbox is likely isolated / --network none).")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    verify()
