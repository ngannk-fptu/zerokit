"""Generic adapter — fallback for unsupported languages."""
from typing import Any, Dict
from .base import LLMAdapter


class GenericAdapter(LLMAdapter):
    """Fallback adapter that returns an empty response."""

    def call(self, prompt: str, config: Dict[str, Any]) -> str:
        return ""
