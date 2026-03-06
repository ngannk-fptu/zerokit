import argparse
import subprocess
import json
import sys
import os

def run_trivy(target, output_file):
    """Runs trivy fs and normalizes output."""
    try:
        subprocess.run(["trivy", "--version"], capture_output=True, check=True)
    except FileNotFoundError:
        print("Error: trivy not found. Please install it.")
        return

    print(f"Running Trivy FS scan on {target}...")
    
    # trivy fs . --format json
    cmd = ["trivy", "fs", target, "--format", "json"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    try:
        data = json.loads(result.stdout)
        results = data.get("Results", [])
    except json.JSONDecodeError:
        print("Failed to parse Trivy output.")
        return

    # Normalize
    findings = []
    for section in results:
        target_file = section.get("Target")
        # Trivy finds vulns and misconfigs
        
        # 1. Vulnerabilities (CVEs)
        for v in section.get("Vulnerabilities", []):
            if v.get("Severity") in ["HIGH", "CRITICAL"]:
                findings.append({
                    "tool": "trivy-fs",
                    "rule_id": v.get("VulnerabilityID"),
                    "severity": v.get("Severity"),
                    "file": target_file,
                    "line": 0,
                    "code_snippet": f"Pkg: {v.get('PkgName')} {v.get('InstalledVersion')}",
                    "message": f"{v.get('Title')}: {v.get('Description')}"
                })
        
        # 2. Misconfigurations (IaC)
        for m in section.get("Misconfigurations", []):
            if m.get("Severity") in ["HIGH", "CRITICAL"]:
                findings.append({
                    "tool": "trivy-config",
                    "rule_id": m.get("ID"),
                    "severity": m.get("Severity"),
                    "file": target_file,
                    "line": m.get("IacMetadata", {}).get("StartLine", 0),
                    "code_snippet": "",
                    "message": m.get("Description")
                })
        
        # 3. Secrets (Trivy also scans secrets, might be dup with Gitleaks)
        for s in section.get("Secrets", []):
             findings.append({
                "tool": "trivy-secrets",
                "rule_id": s.get("RuleID"),
                "severity": s.get("Severity"),
                "file": target_file,
                "line": s.get("StartLine", 0),
                "code_snippet": "******",
                "message": f"Secret found: {s.get('Title')}"
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
        
    print(f"Trivy found {len(findings)} issues.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default=".")
    parser.add_argument("--output", default="raw_findings.json")
    args = parser.parse_args()
    
    run_trivy(args.target, args.output)
