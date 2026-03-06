import argparse
import subprocess
import json
import sys
import os

def run_gosec(target, output_file):
    """Runs gosec and normalizes output."""
    try:
        subprocess.run(["gosec", "--version"], capture_output=True, check=True)
    except FileNotFoundError:
        print("Error: gosec not found. Please install it.")
        return

    print(f"Running Gosec on {target}...")
    
    # gosec -fmt=json -out=TEMP target
    # We capture stdout/stderr or read the file. -out is required for json usually.
    # We'll use a temp file for output to avoid parsing stdout mixed with logs
    temp_out = "gosec_temp.json"
    cmd = ["gosec", "-fmt=json", "-out=" + temp_out, target + "/..."]
    
    subprocess.run(cmd, capture_output=True, text=True)
    
    if not os.path.exists(temp_out):
        print("Gosec failed to generate output.")
        return

    try:
        with open(temp_out, "r") as f:
            data = json.load(f)
        
        results = data.get("Issues", [])
    except json.JSONDecodeError:
        print("Failed to parse Gosec output.")
        if os.path.exists(temp_out): os.remove(temp_out)
        return

    # Normalize
    findings = []
    for r in results:
        findings.append({
            "tool": "gosec",
            "rule_id": r.get("rule_id"),
            "severity": r.get("severity"),
            "file": r.get("file"),
            "line": int(r.get("line", 0)),
            "code_snippet": r.get("code"),
            "message": r.get("details")
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
        
    print(f"Gosec found {len(findings)} issues.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default=".")
    parser.add_argument("--output", default="raw_findings.json")
    args = parser.parse_args()
    
    run_gosec(args.target, args.output)
