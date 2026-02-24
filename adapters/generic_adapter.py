import os
import logging
from typing import List, Optional
from ..models import EntryPoint, EntryPointType, SecurityProfile, SecurityPattern, VulnerabilityCategory, FindingSeverity
from .base import LanguageAdapter

logger = logging.getLogger(__name__)

class GenericAdapter(LanguageAdapter):
    """
    Fallback adapter for repositories with unknown/mixed frameworks.
    Provides basic security patterns for common vulnerabilities.
    """
    
    def detect(self, repo_path: str) -> bool:
        """Generic adapter is the fallback, always returns True."""
        return True
        
    def get_security_profile(self) -> SecurityProfile:
        """Return generic security profile with common vulnerability patterns."""
        return SecurityProfile(
            language="Generic",
            framework=None,
            sources=[
                SecurityPattern(
                    pattern=r"input\(",
                    category=VulnerabilityCategory.OTHER,
                    severity=FindingSeverity.INFO,
                    description="Generic user input"
                ),
            ],
            sinks=[
                # Command Injection
                SecurityPattern(
                    pattern=r"eval\(",
                    category=VulnerabilityCategory.COMMAND_INJECTION,
                    severity=FindingSeverity.CRITICAL),
                SecurityPattern(
                    pattern=r"exec\(",
                    category=VulnerabilityCategory.COMMAND_INJECTION,
                    severity=FindingSeverity.CRITICAL),
                # SQL Injection  
                SecurityPattern(
                    pattern=r"[Qq]uery\(",
                    category=VulnerabilityCategory.SQL_INJECTION,
                    severity=FindingSeverity.HIGH),
                # Path Traversal
                SecurityPattern(
                    pattern=r"[Oo]pen\(",
                    category=VulnerabilityCategory.PATH_TRAVERSAL,
                    severity=FindingSeverity.MEDIUM),
            ],
            sanitizers=[],
            validators=[],
            metadata={"adapter": "generic_fallback"}
        )
        
    def get_entry_points(self, repo_path: str) -> List[EntryPoint]:
        logger.info("Using Generic Adapter to find entry points...")
        entry_points = []
        
        # Extensions to ignore (binary, assets, etc.)
        ignored_exts = {
            '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.webp',
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.zip', '.tar', '.gz',
            '.exe', '.dll', '.so', '.dylib', '.bin', '.class', '.pyc',
            '.css', '.scss', '.less', '.html',
            '.json', '.xml', '.yaml', '.yml', '.md', '.txt'
        }
        
        for root, dirs, files in os.walk(repo_path):
            # Basic exclusions
            dirs[:] = [d for d in dirs if d not in {'.git', 'node_modules', 'vendor', '__pycache__', '.idea', '.vscode'}]
            
            for file in files:
                _, ext = os.path.splitext(file)
                if ext.lower() not in ignored_exts:
                    full_path = os.path.join(root, file)
                    rel_path = os.path.relpath(full_path, repo_path)
                    
                    entry_points.append(EntryPoint(
                        code_location=rel_path,
                        category=EntryPointType.HTTP,
                        metadata={"type": "generic_file"}
                    ))
                    
        return entry_points

    def get_build_command(self) -> Optional[str]:
        return None

    def get_test_command(self) -> Optional[str]:
        return None
