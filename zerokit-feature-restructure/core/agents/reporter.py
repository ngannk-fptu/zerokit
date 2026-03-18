from typing import List
import json
import logging
from ..models import VerifiedVuln, ConfirmedStatus, FindingSeverity

logger = logging.getLogger(__name__)

class Reporter:
    def generate_report(self, vulns: List[VerifiedVuln]) -> str:
        """
        Generates a markdown report including a complete Evidence Package for each verified vulnerability.
        """
        logger.info(f"Generating report for {len(vulns)} items...")
        
        confirmed_vulns = [v for v in vulns if v.status == ConfirmedStatus.CONFIRMED]
        
        report = "# Automated Security Pipeline Report\n\n"
        report += f"**Total Verified Vulnerabilities:** {len(confirmed_vulns)}\n\n"
        
        if not confirmed_vulns:
            report += "No confirmed vulnerabilities found in this run.\n"
            return report

        for i, v in enumerate(confirmed_vulns, 1):
            severity = v.severity_adjustment or "UNKNOWN"
            
            report += f"## {i}. Confirmed Vulnerability (ID: {v.finding_id})\n"
            report += f"- **Severity:** {severity}\n"
            report += f"- **Status:** {v.status.value}\n"
            
            # CWE Details section
            if v.cwe_details:
                cwe_attr = v.cwe_details.get("attr", {})
                cwe_id = cwe_attr.get("@_ID")
                cwe_name = cwe_attr.get("@_Name")
                report += f"- **CWE:** [{cwe_id}: {cwe_name}](https://cwe.mitre.org/data/definitions/{cwe_id}.html)\n"
                
                description = v.cwe_details.get("Description", "")
                if description:
                    report += f"\n> **CWE Description:** {description}\n"
                
                # Memberships (OWASP etc)
                from ..tools.cwe_manager import CweManager
                mgr = CweManager()
                memberships = mgr.get_memberships(cwe_id)
                if memberships:
                    report += "\n#### Related Classifications\n"
                    for m in memberships:
                        report += f"- {m.get('membershipName')}: {m.get('memberId')}\n"
            
            report += "\n### Evidence Package\n"
            
            # PoC Details
            report += "#### 1. Proof of Concept\n"
            report += "```json\n"
            report += json.dumps(v.poc, indent=2)
            report += "\n```\n"
            
            # Runtime Logs
            report += "#### 2. Runtime Output / Crash Log\n"
            if v.runtime_output:
                report += "```text\n"
                report += v.runtime_output
                report += "\n```\n"
            else:
                report += "*No runtime output captured.*\n"
                
            # Original Static Evidence
            report += "#### 3. Static Analysis Trace\n"
            report += f"> {v.evidence}\n"
            
            report += "\n---\n"
            
        return report

    def generate_json_report(self, vulns: List[VerifiedVuln]) -> str:
        """Generates a machine-readable JSON report."""
        export_data = [v.dict() for v in vulns if v.status == ConfirmedStatus.CONFIRMED]
        return json.dumps(export_data, indent=2)

    def create_evidence_bundle(self, vuln: VerifiedVuln, base_dir: str):
        """
        Creates a directory bundle for the vulnerability containing:
        - poc.py: Reproducible script
        - crash.log: Sandbox output
        - metadata.json: Full finding details
        """
        import os
        
        # Safe directory name
        safe_id = "".join(c for c in vuln.finding_id if c.isalnum() or c in ('-', '_'))
        vuln_dir = os.path.join(base_dir, f"vuln_{safe_id}")
        os.makedirs(vuln_dir, exist_ok=True)
        
        # 1. Save PoC
        if vuln.poc:
            poc_content = vuln.poc.get("repro.py", "") or vuln.poc.get("poc", "")
            if poc_content:
                with open(os.path.join(vuln_dir, "repro.py"), "w", encoding="utf-8") as f:
                    f.write(poc_content)
        
        # 2. Save Crash Log
        if vuln.runtime_output:
            with open(os.path.join(vuln_dir, "crash.log"), "w", encoding="utf-8") as f:
                f.write(vuln.runtime_output)
                
        # 3. Save Metadata
        with open(os.path.join(vuln_dir, "metadata.json"), "w", encoding="utf-8") as f:
            json.dump(vuln.dict(), f, indent=2)
            
        logger.info(f"Evidence bundle created at {vuln_dir}")
        return vuln_dir
