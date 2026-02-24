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
        from ..config import config
        
        self.trivy_bin = trivy_path or config.TRIVY_PATH
        self.workspace = workspace or config.TRIVY_WORKSPACE
        
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
                       scan_type: str = "vuln",
                       severity: str = "CRITICAL,HIGH") -> List[Dict]:
        """
        Scan filesystem for vulnerabilities.
        
        Args:
            target_path: Path to scan
            scan_type: Type of scan (vuln, config, secret, license)
            severity: Severity filter (CRITICAL,HIGH,MEDIUM,LOW)
        
        Returns:
            List of vulnerability findings
        """
        if not self.available:
            logger.warning("Trivy not available, skipping scan")
            return []
        
        output_file = os.path.join(self.workspace, "trivy_fs_report.json")
        
        # trivy fs --format json --output report.json --severity CRITICAL,HIGH /path
        cmd = [
            self.trivy_bin,
            "fs",
            "--format", "json",
            "--output", output_file,
            "--severity", severity,
            "--scanners", scan_type,
            target_path
        ]
        
        logger.info(f"Scanning {target_path} with Trivy ({scan_type})...")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # Can be slow for large projects
            )
            
            if result.returncode != 0:
                logger.warning(f"Trivy scan warning: {result.stderr}")
            
            # Parse results
            if os.path.exists(output_file):
                with open(output_file, "r", encoding="utf-8") as f:
                    scan_results = json.load(f)
                    
                    # Extract vulnerabilities from Trivy format
                    findings = []
                    for result in scan_results.get("Results", []):
                        for vuln in result.get("Vulnerabilities", []):
                            findings.append({
                                "package": vuln.get("PkgName"),
                                "version": vuln.get("InstalledVersion"),
                                "vulnerability_id": vuln.get("VulnerabilityID"),
                                "severity": vuln.get("Severity"),
                                "title": vuln.get("Title"),
                                "fixed_version": vuln.get("FixedVersion"),
                                "description": vuln.get("Description", "")[:200]  # Truncate
                            })
                    
                    logger.info(f"Trivy found {len(findings)} vulnerabilities")
                    return findings
            else:
                return []
        
        except subprocess.TimeoutExpired:
            logger.error("Trivy scan timeout")
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
