import os
import ast
from typing import List, Optional
from ..models import EntryPoint, EntryPointType, SecurityProfile, SecurityPattern, VulnerabilityCategory, FindingSeverity
from .base import LanguageAdapter

class PythonAdapter(LanguageAdapter):
    def detect(self, repo_path: str) -> bool:
        # Smart detection: checks for standard Python build config files
        indicators = ["requirements.txt", "setup.py", "pyproject.toml", "Pipfile"]
        for ind in indicators:
            if os.path.exists(os.path.join(repo_path, ind)):
                return True
        # Fallback: check for *.py files in root
        for f in os.listdir(repo_path):
            if f.endswith(".py"):
                return True
        return False

    def get_build_command(self) -> Optional[str]:
        # Python typically doesn't need build, just dependency install
        return None

    def get_test_command(self) -> Optional[str]:
        return "python -m pytest --collect-only"

    def get_security_profile(self) -> SecurityProfile:
        """Return Django/Flask/Python security profile with categorized patterns."""
        profile = SecurityProfile(
            language="Python",
            framework="Django/Flask",
            sources=[
                SecurityPattern(
                    pattern=r"request\.POST",
                    category=VulnerabilityCategory.OTHER,
                    severity=FindingSeverity.INFO,
                    description="Django POST data"
                ),
                SecurityPattern(
                    pattern=r"request\.GET",
                    category=VulnerabilityCategory.OTHER,
                    severity=FindingSeverity.INFO,
                    description="Django GET parameters"
                ),
                SecurityPattern(
                    pattern=r"request\.args",
                    category=VulnerabilityCategory.OTHER,
                    severity=FindingSeverity.INFO,
                    description="Flask GET parameters"
                ),
                SecurityPattern(
                    pattern=r"request\.form",
                    category=VulnerabilityCategory.OTHER,
                    severity=FindingSeverity.INFO,
                    description="Flask POST data"
                ),
                SecurityPattern(
                    pattern=r"request\.json",
                    category=VulnerabilityCategory.OTHER,
                    severity=FindingSeverity.INFO,
                    description="JSON request body"
                ),
                SecurityPattern(
                    pattern=r"sys\.argv",
                    category=VulnerabilityCategory.OTHER,
                    severity=FindingSeverity.INFO,
                    description="Command line arguments"
                ),
                SecurityPattern(
                    pattern=r"os\.environ",
                    category=VulnerabilityCategory.OTHER,
                    severity=FindingSeverity.INFO,
                    description="Environment variables"
                ),
            ],
            sinks=[
                # Command Injection sinks
                SecurityPattern(
                    pattern=r"eval\(",
                    category=VulnerabilityCategory.COMMAND_INJECTION,
                    severity=FindingSeverity.CRITICAL,
                    description="Code evaluation"
                ),
                SecurityPattern(
                    pattern=r"exec\(",
                    category=VulnerabilityCategory.COMMAND_INJECTION,
                    severity=FindingSeverity.CRITICAL,
                    description="Code execution"
                ),
                SecurityPattern(
                    pattern=r"os\.system\(",
                    category=VulnerabilityCategory.COMMAND_INJECTION,
                    severity=FindingSeverity.CRITICAL),
                SecurityPattern(
                    pattern=r"subprocess\.call\(",
                    category=VulnerabilityCategory.COMMAND_INJECTION,
                    severity=FindingSeverity.HIGH),
                SecurityPattern(
                    pattern=r"subprocess\.Popen\(",
                    category=VulnerabilityCategory.COMMAND_INJECTION,
                    severity=FindingSeverity.HIGH),
                SecurityPattern(
                    pattern=r"subprocess\.run\(",
                    category=VulnerabilityCategory.COMMAND_INJECTION,
                    severity=FindingSeverity.HIGH),
                # SQL Injection sinks
                SecurityPattern(
                    pattern=r"\.raw\(",
                    category=VulnerabilityCategory.SQL_INJECTION,
                    severity=FindingSeverity.HIGH,
                    description="Django ORM raw query"
                ),
                SecurityPattern(
                    pattern=r"\.execute\(",
                    category=VulnerabilityCategory.SQL_INJECTION,
                    severity=FindingSeverity.HIGH,
                    description="Database cursor execute"
                ),
                SecurityPattern(
                    pattern=r"cursor\.execute",
                    category=VulnerabilityCategory.SQL_INJECTION,
                    severity=FindingSeverity.HIGH),
                # Path Traversal sinks
                SecurityPattern(
                    pattern=r"open\(",
                    category=VulnerabilityCategory.PATH_TRAVERSAL,
                    severity=FindingSeverity.MEDIUM,
                    description="File operations"
                ),
                SecurityPattern(
                    pattern=r"os\.path\.join\(",
                    category=VulnerabilityCategory.PATH_TRAVERSAL,
                    severity=FindingSeverity.MEDIUM),
                # Deserialization sinks
                SecurityPattern(
                    pattern=r"pickle\.loads\(",
                    category=VulnerabilityCategory.DESERIALIZATION,
                    severity=FindingSeverity.CRITICAL,
                    description="Unsafe deserialization"
                ),
                SecurityPattern(
                    pattern=r"yaml\.load\(",
                    category=VulnerabilityCategory.DESERIALIZATION,
                    severity=FindingSeverity.HIGH,
                    description="YAML deserialization (use safe_load)"
                ),
                # SSRF sinks
                SecurityPattern(
                    pattern=r"requests\.get\(",
                    category=VulnerabilityCategory.SSRF,
                    severity=FindingSeverity.MEDIUM),
                SecurityPattern(
                    pattern=r"requests\.post\(",
                    category=VulnerabilityCategory.SSRF,
                    severity=FindingSeverity.MEDIUM),
                SecurityPattern(
                    pattern=r"urllib\.request\.urlopen\(",
                    category=VulnerabilityCategory.SSRF,
                    severity=FindingSeverity.MEDIUM),
            ],
            sanitizers=[
                # SQL sanitizers
                SecurityPattern(
                    pattern=r"django\.db\.connection\.cursor",
                    category=VulnerabilityCategory.SQL_INJECTION,
                    severity=FindingSeverity.INFO,
                    description="Use with parameterized queries"
                ),
                # XSS sanitizers
                SecurityPattern(
                    pattern=r"escape\(",
                    category=VulnerabilityCategory.XSS,
                    severity=FindingSeverity.INFO,
                    description="HTML escaping"
                ),
                SecurityPattern(
                    pattern=r"mark_safe\(",
                    category=VulnerabilityCategory.XSS,
                    severity=FindingSeverity.INFO,
                    description="Marks string as safe HTML (use carefully!)"
                ),
                # Command sanitizers
                SecurityPattern(
                    pattern=r"shlex\.quote\(",
                    category=VulnerabilityCategory.COMMAND_INJECTION,
                    severity=FindingSeverity.INFO,
                    description="Shell argument escaping"
                ),
                # Path sanitizers
                SecurityPattern(
                    pattern=r"os\.path\.basename\(",
                    category=VulnerabilityCategory.PATH_TRAVERSAL,
                    severity=FindingSeverity.INFO),
                SecurityPattern(
                    pattern=r"os\.path\.realpath\(",
                    category=VulnerabilityCategory.PATH_TRAVERSAL,
                    severity=FindingSeverity.INFO),
                # Deserialization sanitizers
                SecurityPattern(
                    pattern=r"yaml\.safe_load\(",
                    category=VulnerabilityCategory.DESERIALIZATION,
                    severity=FindingSeverity.INFO,
                    description="Safe YAML loading"
                ),
            ],
            validators=[
                SecurityPattern(
                    pattern=r"@login_required",
                    category=VulnerabilityCategory.IDOR,
                    severity=FindingSeverity.INFO,
                    description="Django authentication check"
                ),
                SecurityPattern(
                    pattern=r"@require_POST",
                    category=VulnerabilityCategory.CSRF,
                    severity=FindingSeverity.INFO,
                    description="Django CSRF protection"
                ),
                SecurityPattern(
                    pattern=r"csrf_exempt",
                    category=VulnerabilityCategory.CSRF,
                    severity=FindingSeverity.HIGH,
                    description="CSRF protection disabled (DANGEROUS!)"
                ),
            ],
            metadata={
                "framework_version": "Django 4.x / Flask 3.x",
                "documentation": "https://docs.djangoproject.com/en/stable/topics/security/"
            }
        )
        
        # Inject patterns from external skills
        skill_patterns = self._get_skill_patterns("Python")
        for p in skill_patterns:
            profile.sinks.append(p)
            
        return profile

    def get_entry_points(self, repo_path: str) -> List[EntryPoint]:
        entry_points = []
        for root, _, files in os.walk(repo_path):
            for file in files:
                if file.endswith(".py"):
                    full_path = os.path.join(root, file)
                    rel_path = os.path.relpath(full_path, repo_path)
                    
                    try:
                        with open(full_path, "r", encoding="utf-8") as f:
                            node = ast.parse(f.read())
                            
                        # Basic heuristics for entry points
                        for item in node.body:
                            if isinstance(item, ast.FunctionDef):
                                # Detect Flask routes
                                if any(isinstance(d, ast.Call) and getattr(d.func, "attr", "") == "route" 
                                       for d in item.decorator_list):
                                    entry_points.append(EntryPoint(
                                        category=EntryPointType.HTTP,
                                        code_location=f"{rel_path}:{item.lineno}",
                                        description=f"Flask Route: {item.name}"
                                    ))
                                # Detect Click/Argparse (CLI) - Simplified check
                                elif "cli" in item.name.lower() or "main" in item.name.lower():
                                    entry_points.append(EntryPoint(
                                        category=EntryPointType.CLI,
                                        code_location=f"{rel_path}:{item.lineno}",
                                        description=f"Potential CLI: {item.name}"
                                    ))
                    except Exception:
                        pass # Ignore parsing errors
        return entry_points
