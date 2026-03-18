"""
Rule Validator for Semgrep rules.
Validates YAML syntax and Semgrep rule structure before execution.
"""
import os
import subprocess
import logging
from typing import Tuple, Optional

logger = logging.getLogger(__name__)


class RuleValidator:
    """Validates Semgrep rules using semgrep --validate."""
    
    def __init__(self, semgrep_path: str = "semgrep"):
        """
        Initialize RuleValidator.
        
        Args:
            semgrep_path: Path to semgrep binary (default: "semgrep" in PATH)
        """
        self.semgrep_path = semgrep_path
    
    def validate(self, rule_path: str) -> Tuple[bool, Optional[str]]:
        """
        Validate a Semgrep rule file.
        
        Args:
            rule_path: Path to YAML rule file or directory
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        # Skip file existence check for Semgrep registry configs (p/php, p/owasp-top-ten, etc.)
        if not rule_path.startswith(("p/", "r/")) and not os.path.exists(rule_path):
            return False, f"Rule file not found: {rule_path}"

        # Registry configs don't need local validation — Semgrep handles them at scan time
        if rule_path.startswith(("p/", "r/")):
            return True, None
        
        try:
            result = subprocess.run(
                [self.semgrep_path, "--validate", rule_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                logger.debug(f"✅ Rule validation passed: {rule_path}")
                return True, None
            else:
                error_msg = result.stderr.strip() or result.stdout.strip()
                logger.warning(f"❌ Rule validation failed: {error_msg}")
                return False, error_msg
                
        except subprocess.TimeoutExpired:
            error_msg = "Validation timed out after 30 seconds"
            logger.error(error_msg)
            return False, error_msg
        except FileNotFoundError:
            error_msg = f"Semgrep binary not found at: {self.semgrep_path}"
            logger.error(error_msg)
            return False, error_msg
        except Exception as e:
            error_msg = f"Validation error: {str(e)}"
            logger.error(error_msg)
            return False, error_msg
    
    def extract_error_type(self, error_msg: str) -> str:
        """
        Extract error type from Semgrep validation error message.
        
        Args:
            error_msg: Error message from semgrep --validate
            
        Returns:
            Error type category (e.g., "yaml_syntax", "invalid_pattern", "missing_field")
        """
        if not error_msg:
            return "unknown"
        
        error_lower = error_msg.lower()
        
        # YAML syntax errors
        if "yaml" in error_lower or "indentation" in error_lower or "mapping" in error_lower:
            return "yaml_syntax"
        
        # Pattern errors
        if "pattern" in error_lower and ("invalid" in error_lower or "error" in error_lower):
            return "invalid_pattern"
        
        # Missing required fields
        if "required" in error_lower or "missing" in error_lower:
            return "missing_field"
        
        # Metavariable errors
        if "metavariable" in error_lower:
            return "metavariable_error"
        
        # Language errors
        if "language" in error_lower:
            return "invalid_language"
        
        return "unknown"
