"""
GitleaksRunner: Wrapper for Gitleaks secret scanning

Gitleaks detects hardcoded secrets, API keys, passwords in code and git history.

Usage:
- Scan repository for secrets
- Parse findings with severity
- Report exposed credentials
"""

import subprocess
import json
import os
import logging
from typing import List, Dict

logger = logging.getLogger(__name__)

class GitleaksRunner:
    def __init__(self, gitleaks_path: str = None, workspace: str = None):
        """
        Initialize Gitleaks runner.
        
        Args:
            gitleaks_path: Path to gitleaks binary (defaults to 'gitleaks' in PATH)
            workspace: Path to store scan results
        """
        from ..config import config
        
        self.gitleaks_bin = gitleaks_path or config.GITLEAKS_PATH
        self.workspace = workspace or config.GITLEAKS_WORKSPACE
        
        os.makedirs(self.workspace, exist_ok=True)
        
        # Check if gitleaks is available
        self.available = self._check_available()
        
        if self.available:
            logger.info(f"GitleaksRunner initialized: {self.gitleaks_bin}")
        else:
            logger.warning("Gitleaks not found - install via 'brew install gitleaks' or download binary")
    
    def _check_available(self) -> bool:
        """Check if gitleaks is in PATH."""
        try:
            result = subprocess.run(
                [self.gitleaks_bin, "version"],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except:
            return False
    
    def scan_repo(self, repo_path: str, output_format: str = "json") -> List[Dict]:
        """
        Scan repository for secrets.
        
        Args:
            repo_path: Path to git repository
            output_format: Output format (json, sarif, csv)
        
        Returns:
            List of secret findings
        """
        if not self.available:
            logger.warning("Gitleaks not available, skipping scan")
            return []
        
        output_file = os.path.join(self.workspace, f"gitleaks_report.{output_format}")
        
        # gitleaks detect --source=/path --report-format=json --report-path=output.json
        cmd = [
            self.gitleaks_bin,
            "detect",
            "--source", repo_path,
            "--report-format", output_format,
            "--report-path", output_file,
            "--no-git"  # Scan files without git history (faster)
        ]
        
        logger.info(f"Scanning {repo_path} for secrets with Gitleaks...")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            # Gitleaks returns 1 if secrets found, 0 if clean
            if result.returncode == 1:
                logger.info("Gitleaks found potential secrets")
            elif result.returncode == 0:
                logger.info("Gitleaks: no secrets detected")
            else:
                logger.warning(f"Gitleaks scan error: {result.stderr}")
            
            # Parse results
            if os.path.exists(output_file) and output_format == "json":
                with open(output_file, "r", encoding="utf-8") as f:
                    findings = json.load(f)
                    logger.info(f"Gitleaks found {len(findings)} potential secrets")
                    return findings
            else:
                return []
        
        except subprocess.TimeoutExpired:
            logger.error("Gitleaks scan timeout")
            return []
        except Exception as e:
            logger.error(f"Gitleaks error: {e}")
            return []
    
    def scan_diff(self, repo_path: str, base_ref: str = "HEAD~1") -> List[Dict]:
        """
        Scan git diff for secrets (useful for CI/CD).
        
        Args:
            repo_path: Path to git repository
            base_ref: Base reference to compare (e.g., HEAD~1, main)
        
        Returns:
            List of secret findings in diff
        """
        if not self.available:
            return []
        
        output_file = os.path.join(self.workspace, "gitleaks_diff.json")
        
        # gitleaks protect --source=/path --staged
        cmd = [
            self.gitleaks_bin,
            "protect",
            "--source", repo_path,
            "--report-format", "json",
            "--report-path", output_file
        ]
        
        logger.info("Scanning uncommitted changes for secrets...")
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if os.path.exists(output_file):
                with open(output_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            else:
                return []
        
        except Exception as e:
            logger.error(f"Gitleaks diff scan error: {e}")
            return []
