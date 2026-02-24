import os
import re
from typing import List, Optional
from ..models import EntryPoint, EntryPointType, SecurityProfile, SecurityPattern, VulnerabilityCategory, FindingSeverity
from .base import LanguageAdapter

class PhpAdapter(LanguageAdapter):
    def detect(self, repo_path: str) -> bool:
        # Check for composer.json or *.php files
        if os.path.exists(os.path.join(repo_path, "composer.json")):
            return True
        
        for root, _, files in os.walk(repo_path):
            if any(f.endswith(".php") for f in files):
                return True
        return False

    def get_build_command(self) -> Optional[str]:
        # PHP projects typically don't need build step
        return None

    def get_test_command(self) -> Optional[str]:
        return "composer test"

    def get_security_profile(self) -> SecurityProfile:
        """Return WordPress/PHP security profile with categorized patterns."""
        profile = SecurityProfile(
            language="PHP",
            framework="WordPress",
            sources=[
                SecurityPattern(
                    pattern="$_GET",
                    category=VulnerabilityCategory.OTHER,
                    severity=FindingSeverity.INFO,
                    description="User input from GET parameters"
                ),
                SecurityPattern(
                    pattern="$_POST",
                    category=VulnerabilityCategory.OTHER,
                    severity=FindingSeverity.INFO,
                    description="User input from POST data"
                ),
                SecurityPattern(
                    pattern="$_REQUEST",
                    category=VulnerabilityCategory.OTHER,
                    severity=FindingSeverity.INFO,
                    description="User input from GET/POST/COOKIE"
                ),
                SecurityPattern(
                    pattern="$_COOKIE",
                    category=VulnerabilityCategory.OTHER,
                    severity=FindingSeverity.INFO,
                    description="User-controlled cookies"
                ),
                SecurityPattern(
                    pattern="$_FILES",
                    category=VulnerabilityCategory.OTHER,
                    severity=FindingSeverity.INFO,
                    description="Uploaded file data"
                ),
                SecurityPattern(
                    pattern=r"$_SERVER\[['\"]HTTP_",
                    category=VulnerabilityCategory.OTHER,
                    severity=FindingSeverity.INFO,
                    description="HTTP headers (user-controlled)"
                ),
            ],
            sinks=[
                # SQL Injection sinks
                SecurityPattern(
                    pattern=r"\$wpdb->query",
                    category=VulnerabilityCategory.SQL_INJECTION,
                    severity=FindingSeverity.HIGH,
                    description="WordPress DB query execution"
                ),
                SecurityPattern(
                    pattern=r"\$wpdb->get_results",
                    category=VulnerabilityCategory.SQL_INJECTION,
                    severity=FindingSeverity.HIGH),
                SecurityPattern(
                    pattern=r"\$wpdb->get_var",
                    category=VulnerabilityCategory.SQL_INJECTION,
                    severity=FindingSeverity.HIGH),
                SecurityPattern(
                    pattern=r"\$wpdb->get_row",
                    category=VulnerabilityCategory.SQL_INJECTION,
                    severity=FindingSeverity.HIGH),
                # XSS sinks
                SecurityPattern(
                    pattern=r"echo\s+\$",
                    category=VulnerabilityCategory.XSS,
                    severity=FindingSeverity.MEDIUM,
                    description="Direct output to HTML"
                ),
                SecurityPattern(
                    pattern=r"print\s+\$",
                    category=VulnerabilityCategory.XSS,
                    severity=FindingSeverity.MEDIUM),
                SecurityPattern(
                    pattern=r"printf\(",
                    category=VulnerabilityCategory.XSS,
                    severity=FindingSeverity.MEDIUM),
                # RCE sinks
                SecurityPattern(
                    pattern=r"eval\(",
                    category=VulnerabilityCategory.COMMAND_INJECTION,
                    severity=FindingSeverity.CRITICAL,
                    description="Code evaluation"
                ),
                SecurityPattern(
                    pattern=r"system\(",
                    category=VulnerabilityCategory.COMMAND_INJECTION,
                    severity=FindingSeverity.CRITICAL),
                SecurityPattern(
                    pattern=r"exec\(",
                    category=VulnerabilityCategory.COMMAND_INJECTION,
                    severity=FindingSeverity.CRITICAL),
                SecurityPattern(
                    pattern=r"shell_exec\(",
                    category=VulnerabilityCategory.COMMAND_INJECTION,
                    severity=FindingSeverity.CRITICAL),
                SecurityPattern(
                    pattern=r"passthru\(",
                    category=VulnerabilityCategory.COMMAND_INJECTION,
                    severity=FindingSeverity.CRITICAL),
                # Path Traversal sinks
                SecurityPattern(
                    pattern=r"include\s+\$",
                    category=VulnerabilityCategory.PATH_TRAVERSAL,
                    severity=FindingSeverity.HIGH),
                SecurityPattern(
                    pattern=r"require\s+\$",
                    category=VulnerabilityCategory.PATH_TRAVERSAL,
                    severity=FindingSeverity.HIGH),
                SecurityPattern(
                    pattern=r"file_get_contents\(",
                    category=VulnerabilityCategory.PATH_TRAVERSAL,
                    severity=FindingSeverity.MEDIUM),
            ],
            sanitizers=[
                # SQL sanitizers
                SecurityPattern(
                    pattern=r"\$wpdb->prepare",
                    category=VulnerabilityCategory.SQL_INJECTION,
                    severity=FindingSeverity.INFO,
                    description="WordPress prepared statements"
                ),
                SecurityPattern(
                    pattern=r"esc_sql\(",
                    category=VulnerabilityCategory.SQL_INJECTION,
                    severity=FindingSeverity.INFO),
                SecurityPattern(
                    pattern=r"intval\(",
                    category=VulnerabilityCategory.SQL_INJECTION,
                    severity=FindingSeverity.INFO),
                SecurityPattern(
                    pattern=r"absint\(",
                    category=VulnerabilityCategory.SQL_INJECTION,
                    severity=FindingSeverity.INFO),
                # XSS sanitizers
                SecurityPattern(
                    pattern=r"esc_html\(",
                    category=VulnerabilityCategory.XSS,
                    severity=FindingSeverity.INFO),
                SecurityPattern(
                    pattern=r"esc_attr\(",
                    category=VulnerabilityCategory.XSS,
                    severity=FindingSeverity.INFO),
                SecurityPattern(
                    pattern=r"sanitize_text_field\(",
                    category=VulnerabilityCategory.XSS,
                    severity=FindingSeverity.INFO,
                    description="General text sanitization (NOT for SQL!)"
                ),
                SecurityPattern(
                    pattern=r"wp_kses\(",
                    category=VulnerabilityCategory.XSS,
                    severity=FindingSeverity.INFO),
                SecurityPattern(
                    pattern=r"wp_kses_post\(",
                    category=VulnerabilityCategory.XSS,
                    severity=FindingSeverity.INFO),
                # Command sanitizers
                SecurityPattern(
                    pattern=r"escapeshellarg\(",
                    category=VulnerabilityCategory.COMMAND_INJECTION,
                    severity=FindingSeverity.INFO),
                SecurityPattern(
                    pattern=r"escapeshellcmd\(",
                    category=VulnerabilityCategory.COMMAND_INJECTION,
                    severity=FindingSeverity.INFO),
                # Path sanitizers
                SecurityPattern(
                    pattern=r"basename\(",
                    category=VulnerabilityCategory.PATH_TRAVERSAL,
                    severity=FindingSeverity.INFO),
                SecurityPattern(
                    pattern=r"realpath\(",
                    category=VulnerabilityCategory.PATH_TRAVERSAL,
                    severity=FindingSeverity.INFO),
            ],
            validators=[
                SecurityPattern(
                    pattern=r"wp_verify_nonce\(",
                    category=VulnerabilityCategory.CSRF,
                    severity=FindingSeverity.INFO,
                    description="CSRF token validation"
                ),
                SecurityPattern(
                    pattern=r"current_user_can\(",
                    category=VulnerabilityCategory.IDOR,
                    severity=FindingSeverity.INFO,
                    description="Permission check"
                ),
                SecurityPattern(
                    pattern=r"check_ajax_referer\(",
                    category=VulnerabilityCategory.CSRF,
                    severity=FindingSeverity.INFO),
            ],
            metadata={
                "framework_version": "6.x",
                "documentation": "https://developer.wordpress.org/apis/security/"
            }
        )
        
        # Inject patterns from external skills
        skill_patterns = self._get_skill_patterns("PHP")
        for p in skill_patterns:
            # Basic heuristic: mostly everything in skills is a sink
            profile.sinks.append(p)
            
        return profile

    def get_entry_points(self, repo_path: str) -> List[EntryPoint]:
        entry_points = []
        for root, _, files in os.walk(repo_path):
            for file in files:
                if file.endswith(".php"):
                    full_path = os.path.join(root, file)
                    rel_path = os.path.relpath(full_path, repo_path)
                    
                    try:
                        with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read()
                            
                        # Basic regex for AJAX actions and REST routes which are common entry points
                        # add_action('wp_ajax_...')
                        ajax_matches = re.finditer(r"add_action\s*\(\s*['\"]wp_ajax_(nopriv_)?([^'\"]+)['\"]", content)
                        for match in ajax_matches:
                            entry_points.append(EntryPoint(
                                category=EntryPointType.HTTP,
                                code_location=f"{rel_path}",
                                description=f"WP AJAX Action: {match.group(2)}"
                            ))
                            
                        # register_rest_route
                        rest_matches = re.finditer(r"register_rest_route", content)
                        if any(rest_matches):
                             entry_points.append(EntryPoint(
                                category=EntryPointType.HTTP,
                                code_location=f"{rel_path}",
                                description="WP REST API Route Registration"
                            ))

                        # 2. Hidden Entry Points (Global Access) [Phase 5]
                        global_matches = re.finditer(r"(\$_GET|\$_POST|\$_REQUEST|\$_SERVER)\[", content)
                        # Use a set to avoid duplicates per file for same var type
                        seen_globals = set()
                        for match in global_matches:
                            var_type = match.group(1)
                            if var_type not in seen_globals:
                                seen_globals.add(var_type)
                                entry_points.append(EntryPoint(
                                    category=EntryPointType.HTTP,
                                    code_location=f"{rel_path}",
                                    description=f"Direct Global Access: {var_type}"
                                ))

                        # 3. Custom Routers (URI Check) [Phase 5]
                        if "REQUEST_URI" in content:
                             entry_points.append(EntryPoint(
                                category=EntryPointType.HTTP, 
                                code_location=f"{rel_path}",
                                description="Custom Router Logic (REQUEST_URI check)"
                            ))

                    except Exception:
                        pass
        return entry_points
