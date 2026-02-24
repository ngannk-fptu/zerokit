import os
import re
from typing import List, Optional
from ..models import EntryPoint, EntryPointType, SecurityProfile, SecurityPattern, VulnerabilityCategory, FindingSeverity
from .base import LanguageAdapter

class GoAdapter(LanguageAdapter):
    """Adapter for Go programming language (Gin, Echo, Chi frameworks)."""
    
    def detect(self, repo_path: str) -> bool:
        # Check for go.mod or go.sum
        if os.path.exists(os.path.join(repo_path, "go.mod")):
            return True
        if os.path.exists(os.path.join(repo_path, "go.sum")):
            return True
        # Fallback: check for *.go files
        for root, _, files in os.walk(repo_path):
            if any(f.endswith(".go") for f in files):
                return True
        return False

    def get_build_command(self) -> Optional[str]:
        return "go build ./..."

    def get_test_command(self) -> Optional[str]:
        return "go test ./..."

    def get_security_profile(self) -> SecurityProfile:
        """Return Go security profile with patterns for Gin, Echo, Chi frameworks."""
        return SecurityProfile(
            language="Go",
            framework="Gin/Echo/Chi",
            sources=[
                SecurityPattern(
                    pattern=r"c\.Param\(",
                    category=VulnerabilityCategory.OTHER,
                    severity=FindingSeverity.INFO,
                    description="Gin URL parameter"
                ),
                SecurityPattern(
                    pattern=r"c\.Query\(",
                    category=VulnerabilityCategory.OTHER,
                    severity=FindingSeverity.INFO,
                    description="Gin query parameter"
                ),
                SecurityPattern(
                    pattern=r"r\.FormValue\(",
                    category=VulnerabilityCategory.OTHER,
                    severity=FindingSeverity.INFO,
                    description="Go form value"
                ),
                SecurityPattern(
                    pattern=r"r\.URL\.Query\(",
                    category=VulnerabilityCategory.OTHER,
                    severity=FindingSeverity.INFO,
                    description="URL query parameters"
                ),
                SecurityPattern(
                    pattern=r"os\.Args",
                    category=VulnerabilityCategory.OTHER,
                    severity=FindingSeverity.INFO,
                    description="Command line arguments"
                ),
            ],
            sinks=[
                # Command Injection sinks
                SecurityPattern(
                    pattern=r"exec\.Command\(",
                    category=VulnerabilityCategory.COMMAND_INJECTION,
                    severity=FindingSeverity.HIGH,
                    description="OS command execution"
                ),
                SecurityPattern(
                    pattern=r"os\.Exec\(",
                    category=VulnerabilityCategory.COMMAND_INJECTION,
                    severity=FindingSeverity.HIGH),
                # SQL Injection sinks
                SecurityPattern(
                    pattern=r"db\.Query\(",
                    category=VulnerabilityCategory.SQL_INJECTION,
                    severity=FindingSeverity.HIGH,
                    description="Database query"
                ),
                SecurityPattern(
                    pattern=r"db\.Exec\(",
                    category=VulnerabilityCategory.SQL_INJECTION,
                    severity=FindingSeverity.HIGH),
                SecurityPattern(
                    pattern=r"\.Raw\(",
                    category=VulnerabilityCategory.SQL_INJECTION,
                    severity=FindingSeverity.HIGH,
                    description="GORM raw query"
                ),
                # SSRF sinks
                SecurityPattern(
                    pattern=r"http\.Get\(",
                    category=VulnerabilityCategory.SSRF,
                    severity=FindingSeverity.MEDIUM),
                SecurityPattern(
                    pattern=r"http\.Post\(",
                    category=VulnerabilityCategory.SSRF,
                    severity=FindingSeverity.MEDIUM),
                # Path Traversal sinks
                SecurityPattern(
                    pattern=r"os\.Open\(",
                    category=VulnerabilityCategory.PATH_TRAVERSAL,
                    severity=FindingSeverity.MEDIUM),
                SecurityPattern(
                    pattern=r"ioutil\.ReadFile\(",
                    category=VulnerabilityCategory.PATH_TRAVERSAL,
                    severity=FindingSeverity.MEDIUM),
            ],
            sanitizers=[
                # SQL sanitizers (parameterized queries)
                SecurityPattern(
                    pattern=r"db\.QueryRow\(",
                    category=VulnerabilityCategory.SQL_INJECTION,
                    severity=FindingSeverity.INFO,
                    description="Use with placeholders (?)"
                ),
                # HTML sanitizers
                SecurityPattern(
                    pattern=r"html\.EscapeString\(",
                    category=VulnerabilityCategory.XSS,
                    severity=FindingSeverity.INFO),
                SecurityPattern(
                    pattern=r"template\.HTMLEscapeString\(",
                    category=VulnerabilityCategory.XSS,
                    severity=FindingSeverity.INFO),
                # Regex sanitizers
                SecurityPattern(
                    pattern=r"regexp\.QuoteMeta\(",
                    category=VulnerabilityCategory.COMMAND_INJECTION,
                    severity=FindingSeverity.INFO),
                # Path sanitizers
                SecurityPattern(
                    pattern=r"filepath\.Clean\(",
                    category=VulnerabilityCategory.PATH_TRAVERSAL,
                    severity=FindingSeverity.INFO),
                SecurityPattern(
                    pattern=r"filepath\.Base\(",
                    category=VulnerabilityCategory.PATH_TRAVERSAL,
                    severity=FindingSeverity.INFO),
            ],
            validators=[
                SecurityPattern(
                    pattern=r"c\.GetHeader\(\"Authorization\"\)",
                    category=VulnerabilityCategory.IDOR,
                    severity=FindingSeverity.INFO,
                    description="Authentication header check"
                ),
            ],
            metadata={
                "framework_version": "Gin 1.x / Echo 4.x",
                "documentation": "https://pkg.go.dev/net/http"
            }
        )

    def get_entry_points(self, repo_path: str) -> List[EntryPoint]:
        entry_points = []
        for root, _, files in os.walk(repo_path):
            for file in files:
                if file.endswith(".go"):
                    full_path = os.path.join(root, file)
                    rel_path = os.path.relpath(full_path, repo_path)
                    
                    try:
                        with open(full_path, "r", encoding="utf-8") as f:
                            content = f.read()
                        
                        # Detect HTTP routes (Gin, Echo, Chi)
                        route_patterns = [
                            r"router\.GET\(\"([^\"]+)\"",
                            r"router\.POST\(\"([^\"]+)\"",
                            r"e\.GET\(\"([^\"]+)\"",
                            r"r\.Get\(\"([^\"]+)\"",
                            r"http\.HandleFunc\(\"([^\"]+)\""
                        ]
                        
                        for pattern in route_patterns:
                            matches = re.finditer(pattern, content)
                            for match in matches:
                                entry_points.append(EntryPoint(
                                    category=EntryPointType.HTTP,
                                    code_location=rel_path,
                                    description=f"HTTP Route: {match.group(1)}"
                                ))
                    except Exception:
                        pass
        
        return entry_points
