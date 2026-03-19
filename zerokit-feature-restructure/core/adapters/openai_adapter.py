import os
import requests
import logging
from typing import Optional

from .base import LLMAdapter

logger = logging.getLogger(__name__)

class OpenAIAdapter(LLMAdapter):
    """
    Direct REST Adapter for OpenAI-compatible APIs (OpenAI, Groq, LM Studio, etc).
    Does not require heavy SDKs.
    """
    
    def __init__(self):
        self.api_key = os.getenv("OPENAI_API_KEY", "")
        # Support local LLMs via OpenAI standard schema
        self.base_url = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
        self.timeout = int(os.getenv("OPENAI_TIMEOUT", "60"))
        
    def call(self, prompt: str, config: dict) -> str:
        """
        Sends the prompt to the ChatCompletions endpoint.
        """
        if not self.api_key and "api.openai" in self.base_url:
            raise ValueError("OPENAI_API_KEY is not set for production API usage.")
            
        model = config.get("model", "gpt-4o")
        temperature = config.get("temperature", 0.0)
        
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}"
        }
        
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": "You are ZeroKit Security Analyzer. Output only the requested structured format."},
                {"role": "user", "content": prompt}
            ],
            "temperature": temperature,
            "stream": False
        }
        
        # Determine URL
        url = self.base_url
        if not url.endswith("/chat/completions"):
            url = f"{url.rstrip('/')}/chat/completions"
            
        logger.debug(f"Sending prompt to OpenAI REST API ({url}), Model: {model}")
        
        response = requests.post(
            url,
            headers=headers,
            json=payload,
            timeout=self.timeout
        )
        
        if response.status_code != 200:
            logger.error(f"OpenAI API Error {response.status_code}: {response.text}")
            response.raise_for_status()
            
        data = response.json()
        try:
            return data["choices"][0]["message"]["content"]
        except (KeyError, IndexError) as e:
            logger.error(f"Unexpected OpenAI response schema: {data}")
            raise ValueError("Invalid response format from generic chat completions API") from e
