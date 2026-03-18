"""
AtherisRunner: Wrapper for Atheris Python fuzzing

Atheris is a coverage-guided fuzzer for Python (by Google).
Based on learn.md lines 899-909.

Usage:
- Generate fuzz harnesses for Python functions
- Execute Atheris fuzzing with timeout
- Parse crash reports
"""

import subprocess
import os
import logging
from typing import Dict, Optional

logger = logging.getLogger(__name__)

class AtherisRunner:
    def __init__(self, workspace: str = None):
        """
        Initialize Atheris runner.
        
        Args:
            workspace: Path to store harnesses and findings
        """
        from ..config import config
        
        self.workspace = workspace or config.ATHERIS_WORKSPACE
        os.makedirs(self.workspace, exist_ok=True)
        
        # Check if atheris is installed
        try:
            import atheris
            logger.info("AtherisRunner initialized (atheris found)")
        except ImportError:
            logger.warning("atheris not installed - run 'pip install atheris'")
    
    def generate_harness(self,
                        target_module: str,
                        target_function: str,
                        output_dir: str = None) -> str:
        """
        Generate an Atheris fuzz harness from template.
        
        Based on learn.md lines 899-909.
        
        Args:
            target_module: Python module path (e.g., 'myapp.parser')
            target_function: Function to fuzz (e.g., 'parse_image')
            output_dir: Where to save harness
        
        Returns:
            Path to generated harness .py file
        """
        output_dir = output_dir or self.workspace
        os.makedirs(output_dir, exist_ok=True)
        
        harness_name = f"fuzz_{target_function}.py"
        harness_file = os.path.join(output_dir, harness_name)
        
        # Template from learn.md line 900-909
        harness_code = f'''import atheris
import sys

# Import target
from {target_module} import {target_function}

def TestOneInput(data: bytes) -> None:
    """Fuzz harness for {target_function}."""
    try:
        {target_function}(data)
    except Exception as e:
        # Allow expected exceptions
        pass

if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
'''
        
        with open(harness_file, "w", encoding="utf-8") as f:
            f.write(harness_code)
        
        logger.info(f"Generated Atheris harness: {harness_file}")
        return harness_file
    
    def run_fuzzing(self,
                   harness_file: str,
                   duration_sec: int = 60,
                   runs: int = None) -> Dict:
        """
        Run Atheris fuzzing.
        
        Args:
            harness_file: Path to fuzz harness .py
            duration_sec: Fuzzing duration (approximate)
            runs: Number of iterations (overrides duration if set)
        
        Returns:
            Dictionary with findings
        """
        # python fuzz_test.py -max_total_time=60
        cmd = ["python", harness_file]
        
        if runs:
            cmd.append(f"-runs={runs}")
        else:
            cmd.append(f"-max_total_time={duration_sec}")
        
        logger.info(f"Starting Atheris fuzzing for {duration_sec}s...")
        
        findings = {
            "crashes": [],
            "status": "running",
            "executions": 0
        }
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=duration_sec + 10,
                cwd=os.path.dirname(harness_file)
            )
            
            findings["status"] = "completed"
            
            # Atheris outputs crash info to stderr
            if "ERROR" in result.stderr or "Traceback" in result.stderr:
                findings["crashes"].append({
                    "stacktrace": result.stderr,
                    "output": result.stdout
                })
                logger.info("Atheris found crash!")
            
            # Parse execution count from output
            # Example: "#12345 REDUCE" or "Done 10000 runs"
            import re
            exec_matches = re.findall(r'#(\d+)', result.stderr)
            if exec_matches:
                findings["executions"] = int(exec_matches[-1])
            
            logger.info(f"Fuzzing complete: {len(findings['crashes'])} crashes")
        
        except subprocess.TimeoutExpired:
            findings["status"] = "timeout"
            logger.info("Fuzzing timeout (expected)")
        except Exception as e:
            findings["status"] = "error"
            findings["error"] = str(e)
            logger.error(f"Fuzzing error: {e}")
        
        return findings
