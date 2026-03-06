import argparse
import subprocess
import json
import sys
import os

def run_gitleaks(target, output_file):
    """Runs gitleaks and normalizes output."""
    try:
        subprocess.run(["gitleaks", "version"], capture_output=True, check=True)
    except FileNotFoundError:
        print("Error: gitleaks not found. Please install it.")
        return

    print(f"Running Gitleaks on {target}...")
    
    temp_out = "gitleaks_temp.json"
    # gitleaks detect --source . --report-path val
    cmd = ["gitleaks", "detect", "--source", target, "--report-path", temp_out, "--no-banner"]
    
    # Gitleaks returns 1 if leaks found
    subprocess.run(cmd, capture_output=True, text=True)
    
    if not os.path.exists(temp_out):
        print("Gitleaks finished (no finding file generated, likely clean or error).")
        return

    try:
        with open(temp_out, "r") as f:
            results = json.load(f) # Gitleaks output is a list root
    except json.JSONDecodeError:
        print("Failed to parse Gitleaks output.")
        if os.path.exists(temp_out): os.remove(temp_out)
        return

    # Normalize
    findings = []
    for r in results:
        findings.append({
            "tool": "gitleaks",
            "rule_id": r.get("RuleID"),
            "severity": "CRITICAL",
            "file": r.get("File"),
            "line": r.get("StartLine"),
            "code_snippet": r.get("Secret"), # Careful logging secrets!
            "message": f"Secret detected: {r.get('Description')}"
        })
    
    # Cleanup
    if os.path.exists(temp_out): os.remove(temp_out)

    # Append/Write
    existing = []
    if os.path.exists(output_file):
        try:
            with open(output_file, 'r') as f:
                existing = json.load(f)
        except: pass
        
    existing.extend(findings)
    
    with open(output_file, "w") as f:
        json.dump(existing, f, indent=2)
        
    print(f"Gitleaks found {len(findings)} issues.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default=".")
    parser.add_argument("--output", default="raw_findings.json")
    args = parser.parse_args()
    
    run_gitleaks(args.target, args.output)
