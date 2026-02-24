"""Python adapter — routes calls via the Antigravity/Gemini LLM gateway."""
from typing import Any, Dict
from .base import LLMAdapter


class PythonAdapter(LLMAdapter):
    """Adapter for Python-language PoC generation and analysis."""

    def call(self, prompt: str, config: Dict[str, Any]) -> str:
        # Delegate to configured LLM gateway at runtime
        # (actual call handled by LLMGateway, this is a routing stub)
        return ""
