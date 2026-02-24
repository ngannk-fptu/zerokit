from abc import ABC, abstractmethod
from typing import Any, Dict

class LLMAdapter(ABC):
    """
    Abstract Base Class for LLM Provider Adapters.
    """
    
    @abstractmethod
    def call(self, prompt: str, config: Dict[str, Any]) -> str:
        """
        Execute LLM call with provider-specific logic.
        """
        pass
