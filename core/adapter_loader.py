import os
import logging
from typing import List, Dict, Any, Type
from .adapters.base import LLMAdapter
from .adapters.python_adapter import PythonAdapter
from .adapters.php_adapter import PhpAdapter
from .adapters.generic_adapter import GenericAdapter

logger = logging.getLogger(__name__)

class AdapterLoader:
    """
    Identifies project tech stack and loads appropriate adapters.
    """
    
    @staticmethod
    def detect_tech_stack(repo_path: str) -> List[str]:
        """
        Heuristic detection of technology stack.
        """
        langs = []
        
        # Simple extension check
        has_php = False
        has_python = False
        has_js = False
        has_java = False
        
        for root, _, files in os.walk(repo_path):
            if any(f.endswith('.php') for f in files): has_php = True
            if any(f.endswith('.py') for f in files): has_python = True
            if any(f.endswith('.js') for f in files): has_js = True
            if any(f.endswith('.java') for f in files): has_java = True
            
            # Optimization: break if common ones found? 
            # Or scan whole small repo.
            if len(langs) > 5: break

        if has_php: langs.append("php")
        if has_python: langs.append("python")
        if has_js: langs.append("javascript")
        if has_java: langs.append("java")
        
        return langs

    @staticmethod
    def get_adapter_for_finding(finding_location: str) -> str:
        """
        Returns the adapter type identifier based on file location.
        """
        if finding_location.endswith(".php"):
            return "php"
        if finding_location.endswith(".py"):
            return "python"
        return "generic"

    @staticmethod
    def load_adapter(adapter_type: str) -> Any:
        """
        Returns an instance of the requested adapter.
        """
        if adapter_type == "php":
            return PhpAdapter()
        if adapter_type == "python":
            return PythonAdapter()
        return GenericAdapter()
