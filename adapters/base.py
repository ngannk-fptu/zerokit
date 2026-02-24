from typing import List, Optional
from ..models import EntryPoint

class LanguageAdapter:
    def detect(self, repo_path: str) -> bool:
        """
        Detects if this adapter applies to the repository.
        Inspects file structure for specific configuration files (e.g., pom.xml, requirements.txt).
        """
        raise NotImplementedError
        
    def get_build_command(self) -> Optional[str]:
        """Returns the command to build the project, or None if not applicable."""
        return None

    def get_test_command(self) -> Optional[str]:
        """Returns the command to run standard tests, or None if not applicable."""
        return None

    def get_security_profile(self) -> "SecurityProfile":
        """Returns the security profile (sanitizers, sinks) for this language/framework."""
        from ..models import SecurityProfile
        return SecurityProfile()

    def get_entry_points(self, repo_path: str) -> List[EntryPoint]:
        """
        Analyzes the repository to identify potential entry points (API endpoints, public interfaces).
        """
        raise NotImplementedError

    def _get_skill_patterns(self, language: str):
        """Discovers extra patterns from external skills (e.g. php-security-patterns)."""
        try:
            from ..tools.skill_engine import SkillEngine
            from ..models import SecurityPattern
            engine = SkillEngine()
            raw_patterns = engine.discover_patterns(language)
            
            patterns = []
            for rp in raw_patterns:
                try:
                    patterns.append(SecurityPattern(**rp))
                except Exception as ve:
                    import logging
                    logging.getLogger(__name__).warning(f"Skipping invalid skill pattern: {ve}")
            
            return patterns
        except Exception as e:
            # We don't want to fail the whole scan if skills can't be loaded
            import logging
            logging.getLogger(__name__).warning(f"Could not load skill patterns for {language}: {e}")
            return []
