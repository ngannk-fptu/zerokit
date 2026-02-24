import logging
import time
import google.generativeai as genai
from typing import Any, Dict, Optional
from .base import LLMAdapter

logger = logging.getLogger(__name__)

class GeminiAdapter(LLMAdapter):
    """
    Adapter for Google Gemini API with rate limiting.
    """
    
    def __init__(self, api_key: str, tracker: Any = None, rpm_limit: int = 2):
        self.api_key = api_key
        self.tracker = tracker
        self.rpm_limit = rpm_limit
        self.min_interval = 60.0 / rpm_limit  # seconds between calls
        self.last_call_time = 0.0
        
        if self.api_key:
            genai.configure(api_key=self.api_key)
        else:
            logger.warning("GeminiAdapter initialized without API Key")

    def call(self, prompt: str, config: Dict[str, Any]) -> str:
        """
        Call Gemini API with rate limiting.
        """
        # Rate limiting: ensure minimum interval between calls
        elapsed = time.time() - self.last_call_time
        if elapsed < self.min_interval:
            sleep_time = self.min_interval - elapsed
            logger.info(f"Rate limiting: sleeping {sleep_time:.1f}s (RPM={self.rpm_limit})")
            time.sleep(sleep_time)
        
        model_name = config.get("model", "gemini-1.5-pro")
        temperature = config.get("temperature", 0.1)
        max_tokens = config.get("max_tokens", 8192)
        
        try:
            model = genai.GenerativeModel(model_name)
            
            generation_config = genai.types.GenerationConfig(
                temperature=temperature,
                max_output_tokens=max_tokens,
            )
            
            # Call API
            self.last_call_time = time.time()
            response = model.generate_content(prompt, generation_config=generation_config)
            
            # Track usage if tracker available
            if self.tracker and hasattr(response, 'usage_metadata'):
                input_tokens = response.usage_metadata.prompt_token_count
                output_tokens = response.usage_metadata.candidates_token_count
                self.tracker.add_usage(input_tokens, output_tokens)
            
            return response.text
            
        except Exception as e:
            logger.error(f"Gemini Adapter Error: {e}")
            raise
