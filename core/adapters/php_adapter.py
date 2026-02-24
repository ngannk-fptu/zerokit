"""PHP adapter — routes calls for PHP/WordPress PoC generation."""
from typing import Any, Dict
from .base import LLMAdapter


class PhpAdapter(LLMAdapter):
    """Adapter for PHP-language PoC generation and analysis."""

    def call(self, prompt: str, config: Dict[str, Any]) -> str:
        # Delegate to configured LLM gateway at runtime
        return ""
