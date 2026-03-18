import argparse
import subprocess
import json
import os
import sys

def run_semgrep(target, output_file):
    """Runs semgrep and normalizes output to findings.schema.json"""
    
    # Check if semgrep is installed
    try:
        subprocess.run(["semgrep", "--version"], capture_output=True, check=True)
    except FileNotFoundError:
        print("Error: semgrep not found. Please install it.")
        sys.exit(1)

    print(f"Running Semgrep on {target}...")
    
    # Auto-detect WordPress
    config = ["--config", "auto"]
    is_wp = False
    for root, _, files in os.walk(target):
        if "style.css" in files or any(f.endswith(".php") for f in files):
            # Crude check, but safe. 'p/wordpress' is high signal.
            is_wp = True
            break
            
    if is_wp:
        print("WordPress detected! Enabling p/wordpress ruleset.")
        config.extend(["--config", "p/wordpress"])

    # Run Semgrep with JSON output
    cmd = ["semgrep", "scan"] + config + ["--json", target]
    result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', errors='replace')
    
    if result.returncode != 0 and result.stderr:
        print(f"Semgrep Error: {result.stderr}")
        # Semgrep returns 0 on success, even if findings. 1 usually means error.
        # But sometimes it exits non-zero if findings? No, typically 0.
        
    try:
        data = json.loads(result.stdout)
        results = data.get("results", [])
    except json.JSONDecodeError:
        print("Failed to parse Semgrep output.")
        return []

    # Normalize
    findings = []
    for r in results:
        findings.append({
            "tool": "semgrep",
            "rule_id": r.get("check_id"),
            "severity": r.get("extra", {}).get("severity", "UNKNOWN"),
            "file": r.get("path"),
            "line": r.get("start", {}).get("line"),
            "code_snippet": r.get("extra", {}).get("lines"),
            "message": r.get("extra", {}).get("message")
        })
        
    # Write Normalized Output
    with open(output_file, "w") as f:
        json.dump(findings, f, indent=2)
        
    print(f"Semgrep found {len(findings)} issues. Saved to {output_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default=".")
    parser.add_argument("--output", default="raw_findings.json")
    args = parser.parse_args()
    
    run_semgrep(args.target, args.output)
