import argparse
import subprocess
import json
import sys
import os

def run_bandit(target, output_file):
    """Runs bandit and normalizes output."""
    try:
        subprocess.run(["bandit", "--version"], capture_output=True, check=True)
    except FileNotFoundError:
        print("Error: bandit not found. Please install it (pip install bandit).")
        return

    print(f"Running Bandit on {target}...")
    
    # bandit -r . -f json
    cmd = ["bandit", "-r", target, "-f", "json"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    # Bandit exit codes: 0=No issues, 1=Issues found, >1=Error
    
    try:
        data = json.loads(result.stdout)
        results = data.get("results", [])
    except json.JSONDecodeError:
        print("Failed to parse Bandit output.")
        return

    # Normalize
    findings = []
    for r in results:
        findings.append({
            "tool": "bandit",
            "rule_id": r.get("test_id"),
            "severity": r.get("issue_severity"),
            "file": r.get("filename"),
            "line": r.get("line_number"),
            "code_snippet": r.get("code"),
            "message": r.get("issue_text")
        })
        
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
        
    print(f"Bandit found {len(findings)} issues.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default=".")
    parser.add_argument("--output", default="raw_findings.json")
    args = parser.parse_args()
    
    run_bandit(args.target, args.output)
