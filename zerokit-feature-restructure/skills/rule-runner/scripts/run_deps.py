import argparse
import subprocess
import json
import sys
import os

def run_npm_audit(target, output_file):
    """Runs npm audit and normalizes."""
    if not os.path.exists(os.path.join(target, "package-lock.json")):
        print("No package-lock.json found. Skipping npm audit.")
        return

    print("Running npm audit...")
    # npm audit --json
    try:
        cmd = ["npm", "audit", "--json"]
        result = subprocess.run(cmd, cwd=target, capture_output=True, text=True)
        # npm audit exits 1 if vulns found
    except Exception as e:
        print(f"Error running npm audit: {e}")
        return

    try:
        data = json.loads(result.stdout)
        advisories = data.get("advisories", {}) # Legacy format
        # Modern npm audit json structure varies (vulnerabilities object)
        vulnerabilities = data.get("vulnerabilities", {})
        
        findings = []
        
        # Simple recursive check or flat parsing depending on npm version
        # This is a basic parser for modern npm audit
        def parse_vulns(vulns):
            for name, info in vulns.items():
                if isinstance(info, dict):
                   if "severity" in info:
                       findings.append({
                           "tool": "npm-audit",
                           "rule_id": f"npm-{name}",
                           "severity": info.get("severity", "info").upper(),
                           "file": "package-lock.json",
                           "line": 0,
                           "code_snippet": f"Package: {name}",
                           "message": f"Vulnerable dependency: {name}"
                       })
                       if "via" in info and isinstance(info["via"], list):
                           # Deep traversal could happen here
                           pass

        parse_vulns(vulnerabilities)

        # Merge new findings
        existing = []
        if os.path.exists(output_file):
            try:
                with open(output_file, 'r') as f:
                    existing = json.load(f)
            except: pass
            
        existing.extend(findings)
        
        with open(output_file, "w") as f:
            json.dump(existing, f, indent=2)
            
        print(f"npm audit added {len(findings)} findings.")

    except json.JSONDecodeError:
        print("Failed to parse npm audit output.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default=".")
    parser.add_argument("--output", default="raw_findings.json")
    args = parser.parse_args()
    
    # Clear output file first if it acts as accumulator, or handle externally
    # For now, we assume this script handles one tool.
    # In reality, Rule Runner orchestrates multiple.
    
    run_npm_audit(args.target, args.output)
