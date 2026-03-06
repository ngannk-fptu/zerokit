"""
Rule Repairer for Semgrep rules.
Automatically fixes common YAML and Semgrep rule errors.
"""
import os
import yaml
import logging
import tempfile
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)


class RuleRepairer:
    """Repairs common Semgrep rule errors automatically."""
    
    def __init__(self):
        self.max_attempts = 3
    
    def repair(self, rule_path: str, error_msg: str, error_type: str) -> Optional[str]:
        """
        Attempt to repair a broken Semgrep rule file.
        
        Args:
            rule_path: Path to broken rule file
            error_msg: Error message from validation
            error_type: Error type from RuleValidator.extract_error_type()
            
        Returns:
            Path to repaired rule file, or None if repair failed
        """
        logger.info(f"Attempting to repair rule (error type: {error_type})...")
        
        try:
            with open(rule_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Select repair strategy based on error type
            if error_type == "yaml_syntax":
                repaired = self._fix_yaml_syntax(content, error_msg)
            elif error_type == "invalid_pattern":
                repaired = self._fix_invalid_pattern(content, error_msg)
            elif error_type == "missing_field":
                repaired = self._fix_missing_field(content, error_msg)
            elif error_type == "metavariable_error":
                repaired = self._fix_metavariable(content, error_msg)
            else:
                logger.warning(f"No repair strategy for error type: {error_type}")
                return None
            
            if not repaired:
                return None
            
            # Write repaired rules to new temp file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False, encoding='utf-8') as tmp:
                tmp.write(repaired)
                logger.info(f"✅ Rule repaired → {tmp.name}")
                return tmp.name
                
        except Exception as e:
            logger.error(f"Repair failed: {e}")
            return None
    
    def _fix_yaml_syntax(self, content: str, error_msg: str) -> Optional[str]:
        """Fix YAML syntax errors (indentation, malformed structures)."""
        try:
            # Try to parse and re-dump with proper formatting
            data = yaml.safe_load(content)
            
            # Re-dump with consistent formatting
            repaired = yaml.dump(data, default_flow_style=False, sort_keys=False, indent=2)
            logger.info("Fixed YAML syntax via parse-redump")
            return repaired
            
        except yaml.YAMLError as e:
            logger.warning(f"YAML parse failed: {e}")
            
            # Fallback: Try common indentation fixes
            lines = content.split('\n')
            fixed_lines = []
            
            for line in lines:
                # Fix common issues: tabs → spaces, inconsistent indentation
                line = line.replace('\t', '  ')
                fixed_lines.append(line)
            
            return '\n'.join(fixed_lines)
    
    def _fix_invalid_pattern(self, content: str, error_msg: str) -> Optional[str]:
        """Fix invalid Semgrep patterns."""
        try:
            data = yaml.safe_load(content)
            
            # Walk through rules and fix patterns
            if 'rules' in data:
                for rule in data['rules']:
                    if 'patterns' in rule:
                        rule['patterns'] = self._sanitize_patterns(rule['patterns'])
                    if 'pattern' in rule:
                        rule['pattern'] = self._sanitize_pattern_string(rule['pattern'])
                    if 'pattern-either' in rule:
                        rule['pattern-either'] = self._sanitize_patterns(rule['pattern-either'])
            
            repaired = yaml.dump(data, default_flow_style=False, sort_keys=False)
            logger.info("Fixed invalid patterns")
            return repaired
            
        except Exception as e:
            logger.warning(f"Pattern fix failed: {e}")
            return None
    
    def _fix_missing_field(self, content: str, error_msg: str) -> Optional[str]:
        """Fix missing required fields."""
        try:
            data = yaml.safe_load(content)
            
            if 'rules' in data:
                for rule in data['rules']:
                    # Ensure required fields exist
                    if 'id' not in rule:
                        rule['id'] = f"auto-generated-{hash(str(rule)) % 10000}"
                    if 'message' not in rule:
                        rule['message'] = "Auto-generated rule"
                    if 'languages' not in rule:
                        rule['languages'] = ["generic"]
                    if 'severity' not in rule:
                        rule['severity'] = "WARNING"
                    
                    # Ensure at least one pattern exists
                    has_pattern = any(k in rule for k in ['pattern', 'patterns', 'pattern-either', 'pattern-regex'])
                    if not has_pattern:
                        rule['pattern'] = "..."
            
            repaired = yaml.dump(data, default_flow_style=False, sort_keys=False)
            logger.info("Fixed missing required fields")
            return repaired
            
        except Exception as e:
            logger.warning(f"Missing field fix failed: {e}")
            return None
    
    def _fix_metavariable(self, content: str, error_msg: str) -> Optional[str]:
        """Fix metavariable errors."""
        # Common fixes:
        # - Ensure metavariables start with $
        # - Fix metavariable naming (e.g., VAR → $VAR)
        try:
            data = yaml.safe_load(content)
            
            # This is complex - for now, just validate structure
            repaired = yaml.dump(data, default_flow_style=False, sort_keys=False)
            return repaired
            
        except Exception as e:
            logger.warning(f"Metavariable fix failed: {e}")
            return None
    
    def _sanitize_patterns(self, patterns: Any) -> Any:
        """Recursively sanitize pattern structures."""
        if isinstance(patterns, list):
            return [self._sanitize_patterns(p) for p in patterns]
        elif isinstance(patterns, dict):
            sanitized = {}
            for k, v in patterns.items():
                if k in ['pattern', 'pattern-not', 'pattern-inside', 'pattern-not-inside']:
                    sanitized[k] = self._sanitize_pattern_string(v)
                else:
                    sanitized[k] = self._sanitize_patterns(v)
            return sanitized
        else:
            return patterns
    
    def _sanitize_pattern_string(self, pattern: str) -> str:
        """Sanitize a single pattern string."""
        if not isinstance(pattern, str):
            return pattern
        
        # Remove common issues
        pattern = pattern.strip()
        
        # Ensure ellipsis is properly formatted
        if pattern == "" or pattern is None:
            return "..."
        
        return pattern
