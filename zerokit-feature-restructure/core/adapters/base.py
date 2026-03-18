"""Base class for LLM adapters — extracted for clean imports."""
from abc import ABC, abstractmethod


class LLMAdapter(ABC):
    """Abstract base for LLM provider adapters."""

    @abstractmethod
    def call(self, prompt: str, config: dict) -> str:
        """Send prompt to LLM and return response text."""
        ...
