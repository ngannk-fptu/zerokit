"""
Adapter Loader — identifies tech stack and loads appropriate adapters.
Uses core.profiles as the primary SecurityProfile factory.
Legacy adapter imports are optional for backward compatibility.
"""
import os
import logging
from typing import List, Any

logger = logging.getLogger(__name__)


class AdapterLoader:
    """Identifies project tech stack and loads appropriate adapters."""

    @staticmethod
    def detect_tech_stack(repo_path: str) -> List[str]:
        """Heuristic detection of technology stack."""
        langs = []
        has_php = has_python = has_js = has_java = False

        for root, _, files in os.walk(repo_path):
            if ".git" in root or "node_modules" in root:
                continue
            for f in files:
                if f.endswith(".php"):
                    has_php = True
                elif f.endswith(".py"):
                    has_python = True
                elif f.endswith(".js") or f.endswith(".ts"):
                    has_js = True
                elif f.endswith(".java"):
                    has_java = True

        if has_php:
            langs.append("php")
        if has_python:
            langs.append("python")
        if has_js:
            langs.append("javascript")
        if has_java:
            langs.append("java")

        return langs

    @staticmethod
    def get_adapter_for_finding(finding_location: str) -> str:
        """Returns adapter type identifier based on file location."""
        if finding_location.endswith(".php"):
            return "php"
        if finding_location.endswith(".py"):
            return "python"
        if finding_location.endswith(".java"):
            return "java"
        if finding_location.endswith((".js", ".ts")):
            return "javascript"
        return "generic"

    @staticmethod
    def load_adapter(adapter_type: str) -> Any:
        """Returns a SecurityProfile via core.profiles (preferred)."""
        from .profiles import build_security_profile
        return build_security_profile(adapter_type)
