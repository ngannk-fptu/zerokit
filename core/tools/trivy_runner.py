"""
TrivyRunner: Wrapper for Trivy vulnerability scanner

Trivy scans:
- Container images
- Filesystem (dependency vulnerabilities)
- Git repositories (IaC misconfigurations)

Usage:
- Scan dependencies for known CVEs
- Detect misconfigurations
- Generate SBOM (Software Bill of Materials)
"""

import subprocess
import json
import os
import logging
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)

class TrivyRunner:
    def __init__(self, trivy_path: str = None, workspace: str = None):
        """
        Initialize Trivy runner.
        
        Args:
            trivy_path: Path to trivy binary (defaults to 'trivy' in PATH)
            workspace: Path to store scan results
        """
        # Default to local storage path
        self.trivy_bin = trivy_path or os.path.join("storage", "tools", "trivy", "trivy.exe")
        # Ensure absolute path
        if not os.path.isabs(self.trivy_bin):
            self.trivy_bin = os.path.abspath(self.trivy_bin)
        
        self.workspace = workspace or os.path.join("storage", "workspaces", "trivy_workspace")
        
        os.makedirs(self.workspace, exist_ok=True)
        
        # Check if trivy is available
        self.available = self._check_available()
        
        if self.available:
            logger.info(f"TrivyRunner initialized: {self.trivy_bin}")
        else:
            logger.warning("Trivy not found - install from https://github.com/aquasecurity/trivy")
    
    def _check_available(self) -> bool:
        """Check if trivy is in PATH."""
        try:
            result = subprocess.run(
                [self.trivy_bin, "version"],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except:
            return False
    
    def scan_filesystem(self, 
                       target_path: str,
                       scan_type: str = "vuln,config",
                       severity: str = "CRITICAL,HIGH") -> List[Dict]:
        """
        Scan filesystem for vulnerabilities and misconfigurations using optimized flags.
        
        Args:
            target_path: Path to scan
            scan_type: Type of scan (vuln, config, secret, license)
            severity: Severity filter (CRITICAL,HIGH)
        
        Returns:
            List of vulnerability findings in standardized format
        """
        if not self.available:
            logger.warning("Trivy not available, skipping scan")
            return []
        
        output_file = os.path.join(self.workspace, "trivy_fs_report.json")
        
        # Optimized for Worker API: trivy fs --format json --severity HIGH,CRITICAL .
        cmd = [
            self.trivy_bin,
            "fs",
            "--format", "json",
            "--output", output_file,
            "--severity", severity,
            "--scanners", scan_type,
            target_path
        ]
        
        logger.info(f"Scanning {target_path} with Power-Trivy ({scan_type})...")
        
        try:
            # Clear old report to ensure fresh results
            if os.path.exists(output_file):
                os.remove(output_file)

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600  # Upgraded timeout for deep scans
            )
            
            if result.returncode != 0:
                logger.warning(f"Trivy scan status {result.returncode}: {result.stderr}")
            
            # Parse results
            if os.path.exists(output_file):
                with open(output_file, "r", encoding="utf-8") as f:
                    scan_results = json.load(f)
                    
                    findings = []
                    for res in scan_results.get("Results", []):
                        # Extract Vulnerabilities (SCA)
                        for vuln in res.get("Vulnerabilities", []):
                            findings.append({
                                "type": "vulnerability",
                                "package": vuln.get("PkgName"),
                                "version": vuln.get("InstalledVersion"),
                                "vulnerability_id": vuln.get("VulnerabilityID"),
                                "severity": vuln.get("Severity"),
                                "title": vuln.get("Title", "Dependency Vulnerability"),
                                "fixed_version": vuln.get("FixedVersion"),
                                "description": vuln.get("Description", "")[:500],
                                "target": res.get("Target", "Filesystem"),
                                "class": res.get("Class", "unknown")
                            })
                        
                        # Extract Misconfigurations (IaC)
                        for config in res.get("Misconfigurations", []):
                            findings.append({
                                "type": "misconfig",
                                "id": config.get("ID"),
                                "title": config.get("Title"),
                                "description": config.get("Description"),
                                "message": config.get("Message"),
                                "severity": config.get("Severity"),
                                "target": res.get("Target"),
                                "resolution": config.get("Resolution")
                            })
                    
                    logger.info(f"Power-Trivy found {len(findings)} findings")
                    return findings
            else:
                logger.error("Trivy report file not generated")
                return []
        
        except subprocess.TimeoutExpired:
            logger.error("Trivy scan timeout after 600s")
            return []
        except Exception as e:
            logger.error(f"Trivy error: {e}")
            return []
    
    def scan_config(self, target_path: str) -> List[Dict]:
        """
        Scan for IaC misconfigurations (Dockerfile, K8s, Terraform, etc.).
        
        Args:
            target_path: Path to scan
        
        Returns:
            List of misconfiguration findings
        """
        if not self.available:
            return []
        
        output_file = os.path.join(self.workspace, "trivy_config_report.json")
        
        cmd = [
            self.trivy_bin,
            "config",
            "--format", "json",
            "--output", output_file,
            target_path
        ]
        
        logger.info(f"Scanning {target_path} for misconfigurations...")
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            if os.path.exists(output_file):
                with open(output_file, "r", encoding="utf-8") as f:
                    return json.load(f).get("Results", [])
            else:
                return []
        
        except Exception as e:
            logger.error(f"Trivy config scan error: {e}")
            return []
    
    def generate_sbom(self, target_path: str, output_format: str = "cyclonedx") -> Optional[str]:
        """
        Generate Software Bill of Materials (SBOM).
        
        Args:
            target_path: Path to scan
            output_format: SBOM format (cyclonedx, spdx, spdx-json)
        
        Returns:
            Path to SBOM file
        """
        if not self.available:
            return None
        
        sbom_file = os.path.join(self.workspace, f"sbom.{output_format}.json")
        
        cmd = [
            self.trivy_bin,
            "fs",
            "--format", output_format,
            "--output", sbom_file,
            target_path
        ]
        
        logger.info(f"Generating SBOM for {target_path}...")
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            if os.path.exists(sbom_file):
                logger.info(f"SBOM generated: {sbom_file}")
                return sbom_file
            else:
                return None
        
        except Exception as e:
            logger.error(f"SBOM generation error: {e}")
            return None

    def scan_filesystem_with_evidence(
        self,
        target_path: str,
        scan_type: str = "vuln,config",
        severity: str = "CRITICAL,HIGH",
    ):
        """
        Evidence-aware filesystem scan for PipelineObserver integration.

        Returns:
            Tuple: (findings: List[Dict], exit_code: int, stdout: str, stderr: str, command: str)

        Exit code semantics:
            0  → scan completed (findings or clean) — accepted
            1  → tool error / DB issue — rejected by gate
        """
        if not self.available:
            return [], 1, "", "Trivy binary not found", "trivy [not found]"

        output_file = os.path.join(self.workspace, "trivy_fs_evidence.json")
        cmd = [
            self.trivy_bin, "fs",
            "--format", "json",
            "--output", output_file,
            "--severity", severity,
            "--scanners", scan_type,
            target_path,
        ]
        cmd_str = " ".join(cmd)
        logger.info(f"[Evidence] Running: {cmd_str}")

        try:
            if os.path.exists(output_file):
                os.remove(output_file)

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            stdout = result.stdout or ""
            stderr = result.stderr or ""
            exit_code = result.returncode

            findings = []
            if os.path.exists(output_file):
                with open(output_file, "r", encoding="utf-8") as f:
                    try:
                        scan_results = json.load(f)
                    except json.JSONDecodeError:
                        scan_results = {}

                for res in scan_results.get("Results", []):
                    for vuln in res.get("Vulnerabilities", []):
                        findings.append({
                            "type": "vulnerability",
                            "package": vuln.get("PkgName"),
                            "version": vuln.get("InstalledVersion"),
                            "vulnerability_id": vuln.get("VulnerabilityID"),
                            "severity": vuln.get("Severity"),
                            "title": vuln.get("Title", "Dependency Vulnerability"),
                            "fixed_version": vuln.get("FixedVersion"),
                            "description": vuln.get("Description", "")[:500],
                            "target": res.get("Target", "Filesystem"),
                            "class": res.get("Class", "unknown"),
                        })
                    for config in res.get("Misconfigurations", []):
                        findings.append({
                            "type": "misconfig",
                            "id": config.get("ID"),
                            "title": config.get("Title"),
                            "description": config.get("Description"),
                            "severity": config.get("Severity"),
                            "target": res.get("Target"),
                        })

            logger.info(f"[Evidence] trivy exit={exit_code}, {len(findings)} findings")
            return findings, exit_code, stdout, stderr, cmd_str

        except subprocess.TimeoutExpired:
            return [], 1, "", "Trivy timeout after 600s", cmd_str
        except Exception as e:
            return [], 1, "", str(e), cmd_str
