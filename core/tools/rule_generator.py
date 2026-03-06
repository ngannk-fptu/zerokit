"""
Dynamic Semgrep Rule Generator from SecurityProfile.
Generates YAML rules based on SecurityPattern objects.
"""
import os
import yaml
import logging
import tempfile
from typing import Optional
from ..models import SecurityProfile, VulnerabilityCategory

logger = logging.getLogger(__name__)


class RuleGenerator:
    """Generates Semgrep rules dynamically from SecurityProfile."""
    
    def __init__(self):
        self.lang_map = {
            "PHP": "php",
            "Python": "python",
            "Go": "go",
            "Java": "java",
            "JavaScript": "javascript",
            "C": "c",
            "C++": "cpp",
            "Generic": "generic"
        }
    
    def generate_rules(self, security_profile: SecurityProfile) -> str:
        """
        Generate Semgrep rules from SecurityProfile and return path to rules file.
        
        Args:
            security_profile: SecurityProfile with sources/sinks/sanitizers
            
        Returns:
            Path to generated YAML rules file (or directory of default rules)
        """
        if not security_profile:
            logger.warning("No SecurityProfile provided, using default rules")
            return self._get_default_rules_dir()
        
        logger.info(f"Generating dynamic rules for {security_profile.language}/{security_profile.framework or 'generic'}...")
        
        generated_rules = {"rules": []}
        
        # Group patterns by category
        sinks_by_category = {}
        sanitizers_by_category = {}
        
        for sink in security_profile.sinks:
            if sink.category not in sinks_by_category:
                sinks_by_category[sink.category] = []
            sinks_by_category[sink.category].append(sink)
        
        for sanitizer in security_profile.sanitizers:
            if sanitizer.category not in sanitizers_by_category:
                sanitizers_by_category[sanitizer.category] = []
            sanitizers_by_category[sanitizer.category].append(sanitizer)
        
        # Generate rules for each vulnerability category
        for category, sink_list in sinks_by_category.items():
            if not sink_list:
                continue
            
            rule = self._create_category_rule(
                category,
                sink_list,
                sanitizers_by_category.get(category, []),
                security_profile
            )
            if rule:
                generated_rules["rules"].append(rule)
        
        # Add framework-specific rules
        framework_rules = self._get_framework_specific_rules(security_profile)
        generated_rules["rules"].extend(framework_rules)
        
        # Fallback to default if no rules generated
        if not generated_rules["rules"]:
            logger.warning("No dynamic rules generated from SecurityProfile, using defaults")
            return self._get_default_rules_dir()
        
        # Write to temporary YAML file
        return self._write_rules_file(generated_rules, security_profile)
    
    def _create_category_rule(self, category, sink_list, san_list, profile):
        """Create a Semgrep rule for a specific vulnerability category."""
        language = self.lang_map.get(profile.language, "generic")
        
        # Build patterns
        patterns_config = []
        
        # Add sink patterns
        sink_patterns = [{"pattern": s.pattern} for s in sink_list]
        if len(sink_patterns) == 1:
            patterns_config.append(sink_patterns[0])
        else:
            patterns_config.append({"pattern-either": sink_patterns})
        
        # Add sanitizer exclusions
        for san in san_list:
            patterns_config.append({"pattern-not-inside": san.pattern})
        
        # Determine severity
        severities = [s.severity.value for s in sink_list]
        max_severity = max(severities, default="MEDIUM")
        semgrep_severity = "ERROR" if max_severity in ["CRITICAL", "HIGH"] else "WARNING"
        
        rule = {
            "id": f"zerokit-{category.value.lower()}-{profile.language.lower()}",
            "languages": [language] if language != "generic" else ["generic"],
            "message": f"Potential {category.value.replace('_', ' ')} in {profile.language}",
            "severity": semgrep_severity,
            "patterns": patterns_config,
            "metadata": {
                "category": category.value,
                "language": profile.language,
                "framework": profile.framework or "generic",
                "confidence": "MEDIUM",
                "auto_generated": True,
                "source": "SecurityProfile",
                "zerokit_version": "5.0"
            }
        }
        
        logger.debug(f"Generated rule for {category.value}: {len(sink_patterns)} sinks, {len(san_list)} sanitizers")
        return rule
    
    def _get_framework_specific_rules(self, profile: SecurityProfile) -> list:
        """Get framework-specific hardcoded rules."""
        rules = []
        
        if profile.framework == "WordPress":
            # WordPress unsafe prepare rule
            rules.append({
                "id": "wordpress-unsafe-prepare",
                "languages": ["php"],
                "message": "CRITICAL: Unsafe wpdb->prepare usage (string concatenation bypasses SQL injection protection)",
                "severity": "ERROR",
                "pattern-either": [
                    {"pattern": "$WPDB->prepare(\"...\" . $VAR, ...)"},
                    {"pattern": "$WPDB->prepare($QUERY . $VAR, ...)"},
                    {"pattern": "$WPDB->query($WPDB->prepare(\"...\" . $VAR, ...))"},
                    {"pattern": "$WPDB->get_results($WPDB->prepare(\"...\" . $VAR, ...))"},
                ],
                "metadata": {
                    "cwe": "CWE-89",
                    "owasp": "A03:2021-Injection",
                    "confidence": "HIGH",
                    "framework": "WordPress"
                }
            })
            
            # CSRF missing nonce check
            rules.append({
                "id": "wordpress-missing-nonce",
                "languages": ["php"],
                "message": "Potential CSRF: Missing wp_verify_nonce() check",
                "severity": "WARNING",
                "patterns": [
                    {"pattern-either": [
                        {"pattern": "$_POST[...]"},
                        {"pattern": "$_GET[...]"}
                    ]},
                    {"pattern-not-inside": "wp_verify_nonce(...)"}
                ],
                "metadata": {
                    "cwe": "CWE-352",
                    "owasp": "A01:2021-Broken Access Control",
                    "confidence": "LOW",
                    "framework": "WordPress"
                }
            })
        
        elif profile.framework in ["Django", "Django/Flask"]:
            # Django CSRF exempt (dangerous)
            rules.append({
                "id": "django-csrf-exempt-dangerous",
                "languages": ["python"],
                "message": "CRITICAL: @csrf_exempt disables CSRF protection",
                "severity": "ERROR",
                "pattern": "@csrf_exempt",
                "metadata": {
                    "cwe": "CWE-352",
                    "owasp": "A01:2021-Broken Access Control",
                    "confidence": "HIGH",
                    "framework": "Django"
                }
            })
        
        return rules
    
    def _get_default_rules_dir(self) -> str:
        """Get default Semgrep rules directory."""
        rules_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            "rules",
            "semgrep"
        )
        if os.path.exists(rules_dir):
            return rules_dir
        return os.path.dirname(__file__)
    
    def _write_rules_file(self, generated_rules: dict, profile: SecurityProfile) -> str:
        """Write generated rules to temporary YAML file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as tmp:
            yaml.dump(generated_rules, tmp, default_flow_style=False, sort_keys=False)
            logger.info(
                f"✅ Generated {len(generated_rules['rules'])} dynamic Semgrep rules "
                f"for {profile.language}/{profile.framework or 'generic'} → {tmp.name}"
            )
            return tmp.name
