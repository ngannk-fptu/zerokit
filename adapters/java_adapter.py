import os
import re
from typing import List, Optional
from ..models import EntryPoint, EntryPointType, SecurityProfile, SecurityPattern, VulnerabilityCategory, FindingSeverity
from .base import LanguageAdapter

class JavaAdapter(LanguageAdapter):
    """Adapter for Java (Spring Boot, Jakarta EE)."""
    
    def detect(self, repo_path: str) -> bool:
        # Check for pom.xml (Maven) or build.gradle (Gradle)
        if os.path.exists(os.path.join(repo_path, "pom.xml")):
            return True
        if os.path.exists(os.path.join(repo_path, "build.gradle")):
            return True
        # Fallback: check for *.java files
        for root, _, files in os.walk(repo_path):
            if any(f.endswith(".java") for f in files):
                return True
        return False

    def get_build_command(self) -> Optional[str]:
        return "mvn clean compile"

    def get_test_command(self) -> Optional[str]:
        return "mvn test"

    def get_security_profile(self) -> SecurityProfile:
        """Return Java/Spring security profile."""
        profile = SecurityProfile(
            language="Java",
            framework="Spring Boot / Jakarta EE",
            sources=[
                SecurityPattern(
                    pattern=r"@RequestParam",
                    category=VulnerabilityCategory.OTHER,
                    severity=FindingSeverity.INFO,
                    description="Spring request parameter"
                ),
                SecurityPattern(
                    pattern=r"@PathVariable",
                    category=VulnerabilityCategory.OTHER,
                    severity=FindingSeverity.INFO,
                    description="Spring path variable"
                ),
                SecurityPattern(
                    pattern=r"request\.getParameter\(",
                    category=VulnerabilityCategory.OTHER,
                    severity=FindingSeverity.INFO,
                    description="Servlet request parameter"
                ),
                SecurityPattern(
                    pattern=r"request\.getHeader\(",
                    category=VulnerabilityCategory.OTHER,
                    severity=FindingSeverity.INFO,
                    description="HTTP header"
                ),
                SecurityPattern(
                    pattern=r"@RequestBody",
                    category=VulnerabilityCategory.OTHER,
                    severity=FindingSeverity.INFO,
                    description="Spring request body"
                ),
            ],
            sinks=[
                # Command Injection sinks
                SecurityPattern(
                    pattern=r"Runtime\.getRuntime\(\)\.exec\(",
                    category=VulnerabilityCategory.COMMAND_INJECTION,
                    severity=FindingSeverity.CRITICAL,
                    description="OS command execution"
                ),
                SecurityPattern(
                    pattern=r"ProcessBuilder\(",
                    category=VulnerabilityCategory.COMMAND_INJECTION,
                    severity=FindingSeverity.HIGH),
                # SQL Injection sinks
                SecurityPattern(
                    pattern=r"Statement\.executeQuery\(",
                    category=VulnerabilityCategory.SQL_INJECTION,
                    severity=FindingSeverity.HIGH,
                    description="JDBC statement execution"
                ),
                SecurityPattern(
                    pattern=r"Statement\.execute\(",
                    category=VulnerabilityCategory.SQL_INJECTION,
                    severity=FindingSeverity.HIGH),
                SecurityPattern(
                    pattern=r"createQuery\(",
                    category=VulnerabilityCategory.SQL_INJECTION,
                    severity=FindingSeverity.HIGH,
                    description="JPA query creation"
                ),
                # XXE sinks
                SecurityPattern(
                    pattern=r"DocumentBuilder\.parse\(",
                    category=VulnerabilityCategory.XXE,
                    severity=FindingSeverity.HIGH,
                    description="XML parsing (XXE risk)"
                ),
                # Deserialization sinks
                SecurityPattern(
                    pattern=r"ObjectInputStream\.readObject\(",
                    category=VulnerabilityCategory.DESERIALIZATION,
                    severity=FindingSeverity.CRITICAL,
                    description="Java deserialization"
                ),
                # Path Traversal sinks
                SecurityPattern(
                    pattern=r"new File\(",
                    category=VulnerabilityCategory.PATH_TRAVERSAL,
                    severity=FindingSeverity.MEDIUM),
                SecurityPattern(
                    pattern=r"Files\.readAllBytes\(",
                    category=VulnerabilityCategory.PATH_TRAVERSAL,
                    severity=FindingSeverity.MEDIUM),
                # SSRF sinks
                SecurityPattern(
                    pattern=r"URL\(",
                    category=VulnerabilityCategory.SSRF,
                    severity=FindingSeverity.MEDIUM),
                SecurityPattern(
                    pattern=r"HttpClient\.execute\(",
                    category=VulnerabilityCategory.SSRF,
                    severity=FindingSeverity.MEDIUM),
            ],
            sanitizers=[
                # SQL sanitizers
                SecurityPattern(
                    pattern=r"PreparedStatement",
                    category=VulnerabilityCategory.SQL_INJECTION,
                    severity=FindingSeverity.INFO,
                    description="Parameterized SQL queries"
                ),
                # XSS sanitizers
                SecurityPattern(
                    pattern=r"ESAPI\.encoder\(",
                    category=VulnerabilityCategory.XSS,
                    severity=FindingSeverity.INFO,
                    description="OWASP ESAPI encoding"
                ),
                SecurityPattern(
                    pattern=r"StringEscapeUtils\.escapeHtml\(",
                    category=VulnerabilityCategory.XSS,
                    severity=FindingSeverity.INFO),
                # Path sanitizers
                SecurityPattern(
                    pattern=r"Paths\.get\(",
                    category=VulnerabilityCategory.PATH_TRAVERSAL,
                    severity=FindingSeverity.INFO,
                    description="Safe path handling (with validation)"
                ),
            ],
            validators=[
                SecurityPattern(
                    pattern=r"@PreAuthorize",
                    category=VulnerabilityCategory.IDOR,
                    severity=FindingSeverity.INFO,
                    description="Spring Security authorization"
                ),
                SecurityPattern(
                    pattern=r"@Secured",
                    category=VulnerabilityCategory.IDOR,
                    severity=FindingSeverity.INFO),
            ],
            metadata={
                "framework_version": "Spring Boot 3.x / Jakarta EE 10",
                "documentation": "https://spring.io/projects/spring-security"
            }
        )
        
        # Inject patterns from external skills
        skill_patterns = self._get_skill_patterns("Java")
        for p in skill_patterns:
            profile.sinks.append(p)
            
        return profile

    def get_entry_points(self, repo_path: str) -> List[EntryPoint]:
        entry_points = []
        for root, _, files in os.walk(repo_path):
            for file in files:
                if file.endswith(".java"):
                    full_path = os.path.join(root, file)
                    rel_path = os.path.relpath(full_path, repo_path)
                    
                    try:
                        with open(full_path, "r", encoding="utf-8") as f:
                            content = f.read()
                        
                        # Detect Spring REST controllers
                        if "@RestController" in content or "@Controller" in content:
                            # Find @RequestMapping, @GetMapping, @PostMapping etc.
                            mapping_patterns = [
                                r"@RequestMapping\([^)]*\"([^\"]+)\"",
                                r"@GetMapping\([^)]*\"([^\"]+)\"",
                                r"@PostMapping\([^)]*\"([^\"]+)\"",
                                r"@PutMapping\([^)]*\"([^\"]+)\"",
                                r"@DeleteMapping\([^)]*\"([^\"]+)\""
                            ]
                            
                            for pattern in mapping_patterns:
                                matches = re.finditer(pattern, content)
                                for match in matches:
                                    entry_points.append(EntryPoint(
                                        category=EntryPointType.HTTP,
                                        code_location=rel_path,
                                        description=f"Spring REST Endpoint: {match.group(1)}"
                                    ))
                    except Exception:
                        pass
        
        return entry_points
