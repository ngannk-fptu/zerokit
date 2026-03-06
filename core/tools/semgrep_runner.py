import subprocess
import json
import logging
import asyncio
import time
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from .rule_validator import RuleValidator
from .rule_repairer import RuleRepairer

logger = logging.getLogger(__name__)

@dataclass
class ScanResult:
    findings: List[Dict] = field(default_factory=list)
    duration_ms: float = 0.0
    tool: str = "semgrep"
    success: bool = True
    error_msg: Optional[str] = None

class SemgrepRunner:
    def __init__(self):
        self.validator = RuleValidator()
        self.repairer = RuleRepairer()
        self.max_repair_attempts = 3
    
    def run_scan(self, rule_config: str, target_path: str) -> List[Dict]:
        """
        Runs semgrep synchronously (wrapper around async).
        Returns only findings for backward compatibility.
        """
        res = asyncio.run(self.run_scan_async(rule_config, target_path))
        return res.findings

    async def run_scan_async(self, rule_config: str, target_path: str | List[str], jobs: int = 0) -> ScanResult:
        """
        Async Semgrep Execution with --jobs support and pre-scan validation.
        Target can be a single path (str) or list of paths (List[str]).
        Returns ScanResult with metrics.
        """
        start_time = time.time()
        
        # ============================================================
        # PRE-SCAN VALIDATION & AUTO-REPAIR LOOP
        # ============================================================
        is_valid, error_msg = self.validator.validate(rule_config)
        
        if not is_valid:
            logger.warning(f"Rule validation failed: {error_msg}")
            
            # Attempt auto-repair (max 3 attempts)
            for attempt in range(1, self.max_repair_attempts + 1):
                logger.info(f"🔧 Auto-repair attempt {attempt}/{self.max_repair_attempts}...")
                
                error_type = self.validator.extract_error_type(error_msg)
                repaired_path = self.repairer.repair(rule_config, error_msg, error_type)
                
                if not repaired_path:
                    logger.warning(f"Repair attempt {attempt} failed")
                    continue
                
                # Validate repaired rules
                is_valid, error_msg = self.validator.validate(repaired_path)
                
                if is_valid:
                    logger.info(f"✅ Rules repaired successfully on attempt {attempt}")
                    rule_config = repaired_path
                    break
                else:
                    logger.warning(f"Repaired rules still invalid: {error_msg}")
            
            # If still invalid after all attempts, abort
            if not is_valid:
                logger.error(f"❌ Rule validation failed after {self.max_repair_attempts} repair attempts")
                return ScanResult(
                    success=False,
                    error_msg=f"Rule validation failed: {error_msg}",
                    duration_ms=(time.time() - start_time) * 1000
                )
        else:
            logger.debug(f"✅ Rule validation passed: {rule_config}")
        
        # ============================================================
        # RUN SEMGREP SCAN
        # ============================================================
        cmd = ["semgrep", "scan", "--config", rule_config, "--json", "--no-git-ignore", "--disable-version-check", "--metrics=off"]
        
        if jobs > 0:
            cmd.extend(["--jobs", str(jobs)])
            
        # Handle target(s)
        if isinstance(target_path, list):
            cmd.extend(target_path)
            targets_log = f"{len(target_path)} files"
        else:
            cmd.append(target_path)
            targets_log = target_path
        
        logger.info(f"Running Semgrep (Async) [Jobs={jobs}] on {targets_log}")
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                # 5 min timeout for Semgrep Scout
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=300)
            except asyncio.TimeoutError:
                process.kill()
                duration = (time.time() - start_time) * 1000
                logger.error(f"Semgrep timed out after {duration:.2f}ms")
                return ScanResult(success=False, error_msg="Timeout", duration_ms=duration)

            duration = (time.time() - start_time) * 1000

            if process.returncode != 0:
                stderr_text = stderr.decode()
                logger.error(f"Semgrep execution failed (Exit Code {process.returncode}): {stderr_text}")
                return ScanResult(success=False, error_msg=stderr_text, duration_ms=duration)

            try:
                data = json.loads(stdout.decode())
                findings = data.get("results", [])
                logger.info(f"Semgrep finished in {duration:.2f}ms, found {len(findings)} issues.")
                return ScanResult(findings=findings, duration_ms=duration, success=True)
                
            except json.JSONDecodeError:
                logger.error("Failed to parse Semgrep JSON output.")
                return ScanResult(success=False, error_msg="Invalid JSON", duration_ms=duration)
        
        except Exception as e:
            logger.error(f"Semgrep execution error: {str(e)}")
            return ScanResult(success=False, error_msg=str(e), duration_ms=(time.time() - start_time) * 1000)

    def validate_rule(self, rule_content: str) -> bool:
        """
        Checks if a custom rule is valid before running.
        This is the entry point for the Repair Loop to check its work.
        """
        cmd = ["semgrep", "--validate", "--config", "-"]
        try:
            subprocess.run(cmd, input=rule_content, text=True, check=True, capture_output=True)
            return True
        except subprocess.CalledProcessError:
            return False
