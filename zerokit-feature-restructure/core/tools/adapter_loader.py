"""
AdapterLoader: Auto-detects framework and loads Security Adapter YAML.

Supports: Spring Boot (Java), Express/Next.js (JS/TS), ASP.NET Core (C#), Django/Flask (Python)
"""

import os
import yaml
import logging
from typing import Optional, Dict, List, Tuple

logger = logging.getLogger(__name__)

# Maps (detection_file, keyword) → adapter YAML filename
FRAMEWORK_SIGNATURES: List[Tuple[str, str, str]] = [
    # (filename_to_check, keyword_in_file_or_None, adapter_yaml)
    ("pom.xml",          "spring-boot",       "java_spring_boot.yaml"),
    ("build.gradle",     "springframework",   "java_spring_boot.yaml"),
    ("package.json",     "express",           "js_express.yaml"),
    ("package.json",     "next",              "js_express.yaml"),
    ("package.json",     "koa",               "js_express.yaml"),
    ("*.csproj",         None,                "csharp_aspnet.yaml"),
    ("*.sln",            None,                "csharp_aspnet.yaml"),
    ("requirements.txt", "django",            "python_django_flask.yaml"),
    ("requirements.txt", "flask",             "python_django_flask.yaml"),
    ("setup.py",         "django",            "python_django_flask.yaml"),
    ("setup.py",         "flask",             "python_django_flask.yaml"),
    ("pyproject.toml",   "django",            "python_django_flask.yaml"),
    ("pyproject.toml",   "flask",             "python_django_flask.yaml"),
    ("manage.py",        None,                "python_django_flask.yaml"),  # Django root marker
]

ADAPTERS_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", "..", ".agent", "knowledge_base", "adapters"
)


class AdapterLoader:
    """Detects framework in a repository and loads the matching Security YAML adapter."""

    def __init__(self, adapters_dir: str = None):
        self.adapters_dir = adapters_dir or ADAPTERS_DIR

    def detect_and_load(self, repo_path: str) -> Optional[Dict]:
        """
        Walk the repo_path, detect framework, and return the adapter dict.

        Returns:
            Adapter dict with 'framework', 'language', 'sources', 'sinks', 'sanitizers'
            or None if no matching adapter found.
        """
        for filename, keyword, yaml_file in FRAMEWORK_SIGNATURES:
            if self._file_exists(repo_path, filename, keyword):
                adapter = self._load_yaml(yaml_file)
                if adapter:
                    logger.info(f"[AdapterLoader] Detected framework: {adapter.get('framework')} ({adapter.get('language')})")
                    return adapter

        logger.warning("[AdapterLoader] No framework detected. Generic profile will be used.")
        return None

    def _file_exists(self, repo_path: str, filename: str, keyword: Optional[str]) -> bool:
        """Check if the target file exists and optionally contains the keyword."""
        import glob

        # Handle wildcard filenames (e.g., *.csproj)
        if "*" in filename:
            matches = glob.glob(os.path.join(repo_path, filename))
            return len(matches) > 0

        target = os.path.join(repo_path, filename)
        if not os.path.exists(target):
            return False

        if keyword is None:
            return True

        try:
            with open(target, "r", encoding="utf-8", errors="ignore") as f:
                return keyword.lower() in f.read().lower()
        except Exception:
            return False

    def _load_yaml(self, yaml_file: str) -> Optional[Dict]:
        """Load a specific adapter YAML file."""
        path = os.path.join(self.adapters_dir, yaml_file)
        if not os.path.exists(path):
            logger.error(f"[AdapterLoader] Adapter YAML not found: {path}")
            return None

        try:
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
                logger.debug(f"[AdapterLoader] Loaded adapter: {path}")
                return data
        except Exception as e:
            logger.error(f"[AdapterLoader] Failed to parse {path}: {e}")
            return None

    def adapter_to_security_profile_update(self, adapter: Dict) -> Dict:
        """
        Convert adapter YAML dict into a SecurityProfile-compatible dict
        with sources, sinks, and sanitizers.
        """
        return {
            "framework": adapter.get("framework"),
            "language": adapter.get("language"),
            "sources": [s.get("method") or s.get("annotation") or "" for s in adapter.get("sources", [])],
            "sinks": [
                {
                    "name": s.get("function"),
                    "cwe": s.get("cwe", ""),
                    "severity": s.get("severity", "MEDIUM")
                }
                for s in adapter.get("sinks", [])
            ],
            "sanitizers": [s.get("function") or s.get("annotation") or "" for s in adapter.get("sanitizers", [])],
        }
