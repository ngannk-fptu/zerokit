"""
DependencyCheckRunner: Wrapper for OWASP Dependency-Check
Runs SCA (Software Composition Analysis) to find known vulnerabilities in dependencies.
"""

import subprocess
import json
import os
import logging
import uuid
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)

class DependencyCheckRunner:
    def __init__(self, bin_path: str = None, workspace: str = None):
        """
        Initialize Dependency-Check runner.
        
        Args:
            bin_path: Path to dependency-check.bat (Windows) or .sh (Linux)
            workspace: Path to store scan results and NVD data
        """
        from ..config import config
        
        # Default to local storage path
        self.dc_bin = bin_path or os.path.join("storage", "tools", "dependency-check", "dependency-check", "bin", "dependency-check.bat")
        # Ensure absolute path for the binary
        if not os.path.isabs(self.dc_bin):
            self.dc_bin = os.path.abspath(self.dc_bin)

        self.workspace = workspace or os.path.join("storage", "workspaces", "dependency_check_workspace")
        self.data_dir = os.path.join(self.workspace, "data")
        self.report_dir = os.path.join(self.workspace, "reports")
        
        os.makedirs(self.data_dir, exist_ok=True)
        os.makedirs(self.report_dir, exist_ok=True)
        
        # Check if java is available
        self.java_available = self._check_java()
        self.available = os.path.exists(self.dc_bin) and self.java_available
        
        if self.available:
            logger.info(f"DependencyCheckRunner initialized: {self.dc_bin}")
        else:
            if not self.java_available:
                logger.error("Java not found. Dependency-Check requires JRE/JDK 18+.")
            if not os.path.exists(self.dc_bin):
                logger.warning(f"Dependency-Check binary not found at {self.dc_bin}")

    def _check_java(self) -> bool:
        """Check if Java is available in the system."""
        try:
            result = subprocess.run(["java", "-version"], capture_output=True, timeout=5)
            return result.returncode == 0
        except:
            return False

    async def scan_repo(self, repo_path: str, format: str = "JSON") -> List[Dict]:
        """
        Scan a repository for dependency vulnerabilities.
        
        Args:
            repo_path: Path to the repository source
            format: Output format (JSON, SARIF)
        
        Returns:
            List of findings in a standardized format
        """
        if not self.available:
            logger.warning("Dependency-Check not available, skipping scan.")
            return []

        repo_path = os.path.abspath(repo_path)
        output_file = os.path.join(self.report_dir, f"dependency-check-report.{format.lower()}")
        
        cmd = [
            self.dc_bin,
            "--project", f"ZeroKit-{os.path.basename(repo_path)}",
            "--scan", repo_path,
            "--format", format.upper(),
            "--out", self.report_dir,
            "--data", self.data_dir,
            "--noupdate"  # Faster for worker runs if DB exists
        ]
        
        logger.info(f"Running Dependency-Check on {repo_path}...")
        
        try:
            # Run the scan (can take several minutes)
            import asyncio
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                logger.error(f"Dependency-Check failed with code {process.returncode}")
                err_text = stderr.decode()
                logger.error(f"STDERR snippet: {err_text[:500]}")
                
                # If DB is missing, retry with update
                if "database does not exist" in err_text or "NVD" in err_text:
                    logger.info("Initializing NVD DB (first run, this will take a few minutes)...")
                    if "--noupdate" in cmd:
                        cmd.remove("--noupdate")
                    process = await asyncio.create_subprocess_exec(
                        *cmd, 
                        stdout=asyncio.subprocess.PIPE, 
                        stderr=asyncio.subprocess.PIPE
                    )
                    stdout, stderr = await process.communicate()
            
            logger.info(f"Dependency-Check STDOUT: {stdout.decode()[:500]}")

            # Parse findings from JSON
            if os.path.exists(output_file) and format.upper() == "JSON":
                with open(output_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    return self._parse_json_report(data)
            
            return []

        except Exception as e:
            logger.error(f"Dependency-Check error: {e}")
            return []

    def _parse_json_report(self, data: Dict) -> List[Dict]:
        """Convert Dependency-Check JSON report to standardized findings."""
        findings = []
        dependencies = data.get("dependencies", [])
        
        for dep in dependencies:
            vulnerabilities = dep.get("vulnerabilities", [])
            for vuln in vulnerabilities:
                findings.append({
                    "id": vuln.get("name"),
                    "package": dep.get("fileName"),
                    "severity": vuln.get("severity", "MEDIUM"),
                    "cvss_score": vuln.get("cvssv3", {}).get("baseScore") or vuln.get("cvssv2", {}).get("score"),
                    "description": vuln.get("description", ""),
                    "evidence": f"Dependency: {dep.get('filePath')}",
                    "tool": "dependency-check"
                })
        
        return findings

    async def scan_repo_with_evidence(self, repo_path: str, format: str = "JSON"):
        """
        Evidence-aware async scan for PipelineObserver integration.

        Returns:
            Tuple: (findings: List[Dict], exit_code: int, stdout: str, stderr: str, command: str)

        Exit code semantics:
            0  → scan completed successfully — accepted
            1+ → tool error — rejected by gate
        """
        if not self.available:
            reason = "Java not found" if not self.java_available else f"Binary not found: {self.dc_bin}"
            return [], 1, "", reason, "dependency-check [not found]"

        repo_path = os.path.abspath(repo_path)
        output_file = os.path.join(self.report_dir, f"dependency-check-report.{format.lower()}")
        cmd = [
            self.dc_bin,
            "--project", f"ZeroKit-{os.path.basename(repo_path)}",
            "--scan", repo_path,
            "--format", format.upper(),
            "--out", self.report_dir,
            "--data", self.data_dir,
            "--noupdate",
        ]
        cmd_str = " ".join(cmd)
        logger.info(f"[Evidence] Running: {cmd_str}")

        try:
            import asyncio
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout_b, stderr_b = await process.communicate()
            stdout = stdout_b.decode(errors="replace")
            stderr = stderr_b.decode(errors="replace")
            exit_code = process.returncode

            # Retry without --noupdate if NVD DB is missing
            if exit_code != 0 and ("database does not exist" in stderr or "NVD" in stderr):
                logger.info("[Evidence] NVD DB missing — retrying with update (first run)...")
                cmd_update = [c for c in cmd if c != "--noupdate"]
                cmd_str = " ".join(cmd_update)
                process = await asyncio.create_subprocess_exec(
                    *cmd_update,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout_b, stderr_b = await process.communicate()
                stdout = stdout_b.decode(errors="replace")
                stderr = stderr_b.decode(errors="replace")
                exit_code = process.returncode

            findings = []
            if exit_code == 0 and os.path.exists(output_file) and format.upper() == "JSON":
                with open(output_file, "r", encoding="utf-8") as f:
                    try:
                        data = json.load(f)
                        findings = self._parse_json_report(data)
                    except json.JSONDecodeError:
                        pass

            logger.info(f"[Evidence] dependency-check exit={exit_code}, {len(findings)} findings")
            return findings, exit_code, stdout[:2000], stderr[:1000], cmd_str

        except Exception as e:
            return [], 1, "", str(e), cmd_str
