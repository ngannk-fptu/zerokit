"""
PoC Template Manager
Manages loading and rendering of vulnerability PoC templates
"""
import os
import logging
from typing import Optional, Dict
from ..models import StaticFinding, VulnerabilityCategory

logger = logging.getLogger(__name__)


class PoCTemplateManager:
    """Manages PoC template loading and rendering for verified vulnerabilities."""
    
    def __init__(self):
        self.template_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            "templates",
            "poc"
        )
        
        # Map vulnerability categories to template files
        self.template_map = {
            VulnerabilityCategory.SQL_INJECTION: {
                "PHP": "php/sql_injection.php",
                "Python": "python/sql_injection.py",
                "Java": "java/sql_injection.java",
                "Go": "go/sql_injection.go"
            },
            VulnerabilityCategory.COMMAND_INJECTION: {
                "PHP": "php/rce.php",
                "Python": "python/command_injection.py",
                "Java": "java/command_injection.java",
                "Go": "go/command_injection.go"
            },
            VulnerabilityCategory.XSS: {
                "PHP": "php/xss.php",
                "Python": "python/xss.py",
                "JavaScript": "javascript/xss.js"
            },
            VulnerabilityCategory.PATH_TRAVERSAL: {
                "PHP": "php/path_traversal.php",
                "Python": "python/path_traversal.py"
            },
            VulnerabilityCategory.SSRF: {
                "Python": "python/ssrf.py",
                "Go": "go/ssrf.go",
                "Java": "java/ssrf.java"
            },
            VulnerabilityCategory.CSRF: {
                "PHP": "php/csrf.php"
            },
            VulnerabilityCategory.IDOR: {
                "PHP": "php/missing_authorization.php"
            },
            VulnerabilityCategory.DESERIALIZATION: {
                "PHP": "php/object_injection.php",
                "PHP_POP_CHAIN": "php/deserialization.php",
                "Python": "python/pickle_injection.py",
                "Java": "java/deserialization.java"
            },
            VulnerabilityCategory.XXE: {
                "PHP": "php/xxe.php",
                "Java": "java/xxe.java"
            },
            # Additional WordPress-specific templates
            "AUTH_BYPASS": {
                "PHP": "php/auth_bypass.php"
            },
            "FILE_UPLOAD": {
                "PHP": "php/file_upload.php"
            },
            "PRIVILEGE_ESCALATION": {
                "PHP": "php/privilege_escalation.php"
            },
            "INFO_DISCLOSURE": {
                "PHP": "php/info_disclosure.php"
            },
            "INSECURE_API": {
                "PHP": "php/insecure_api.php"
            },
            "OPEN_REDIRECT": {
                "PHP": "php/open_redirect.php",
                "Python": "python/open_redirect.py"
            }
        }
    
    def generate_poc(self, finding: StaticFinding, language: str) -> Optional[str]:
        """
        Generate a PoC from template for a given finding.
        
        Args:
            finding: StaticFinding with vulnerability details
            language: Target language (PHP, Python, Go, Java, etc.)
            
        Returns:
            Rendered PoC code string, or None if no template found
        """
        # Get vulnerability category from finding metadata
        category_str = finding.metadata.get("category", "UNKNOWN")
        try:
            category = VulnerabilityCategory(category_str)
        except ValueError:
            logger.warning(f"Unknown vulnerability category: {category_str}")
            return None
        
        # Find appropriate template
        template_path = self._get_template_path(category, language)
        if not template_path:
            logger.warning(f"No PoC template for {category}/{language}")
            return None
        
        # Load template
        try:
            with open(template_path, 'r', encoding='utf-8') as f:
                template = f.read()
        except FileNotFoundError:
            logger.error(f"Template file not found: {template_path}")
            return None
        
        # Render template with finding data
        poc_code = self._render_template(template, finding)
        
        logger.info(f"Generated PoC for {category}/{language} → {len(poc_code)} bytes")
        return poc_code
    
    def _get_template_path(self, category: VulnerabilityCategory, language: str) -> Optional[str]:
        """Get full path to template file."""
        if category not in self.template_map:
            return None
        
        lang_templates = self.template_map[category]
        if language not in lang_templates:
            return None
        
        rel_path = lang_templates[language]
        full_path = os.path.join(self.template_dir, rel_path)
        
        return full_path if os.path.exists(full_path) else None
    
    def _render_template(self, template: str, finding: StaticFinding) -> str:
        """Render template by replacing placeholders with finding data."""
        # Extract metadata
        file_path = finding.location.split(":")[0] if ":" in finding.location else finding.location
        line_num = finding.location.split(":")[1] if ":" in finding.location else "unknown"
        
        # Prepare replacements
        replacements = {
            "{{FILE}}": file_path,
            "{{LINE}}": str(line_num),
            "{{CATEGORY}}": finding.metadata.get("category", "Unknown"),
            "{{SEVERITY}}": finding.severity.value,
            "{{DESCRIPTION}}": finding.description or "No description",
            "{{VULNERABLE_CODE}}": self._extract_vulnerable_code(finding),
            "{{PAYLOAD}}": self._generate_payload(finding)
        }
        
        # Apply replacements
        rendered = template
        for placeholder, value in replacements.items():
            rendered = rendered.replace(placeholder, value)
        
        return rendered
    
    def _extract_vulnerable_code(self, finding: StaticFinding) -> str:
        """Extract vulnerable code snippet from finding evidence."""
        evidence = finding.evidence or finding.description or ""
        
        # Try to extract actual code
        if "code" in finding.metadata:
            return finding.metadata["code"]
        
        # Fallback: use evidence
        return f"// Vulnerable code at {finding.location}\n// {evidence}"
    
    def _generate_payload(self, finding: StaticFinding) -> str:
        """Generate appropriate payload for vulnerability type."""
        category_str = finding.metadata.get("category", "")
        
        payload_map = {
            "SQL_INJECTION": "' OR '1'='1' -- ",
            "COMMAND_INJECTION": "| echo ZEROKIT_PROOF",
            "XSS": "<script>alert('ZEROKIT')</script>",
            "PATH_TRAVERSAL": "../../../etc/passwd",
            "SSRF": "http://localhost:8080/admin",
            "DESERIALIZATION": 'O:8:"EvilClass":1:{s:3:"cmd";s:6:"whoami";}',
            "XXE": '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
            "OPEN_REDIRECT": "http://evil.com/phishing",
            "CSRF": "nonce=invalid&action=delete_user&user_id=1",
            "IDOR": "user_id=999999",
        }
        
        return payload_map.get(category_str, "PAYLOAD_HERE")

