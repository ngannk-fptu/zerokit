import logging
import requests
import json
from typing import Any, Dict
from .base import LLMAdapter

logger = logging.getLogger(__name__)

class OllamaAdapter(LLMAdapter):
    """
    Adapter for Ollama local LLM API.
    No API key required, runs completely offline.
    """
    
    def __init__(self, base_url: str = "http://localhost:11434", model: str = "codellama:13b", tracker: Any = None):
        self.base_url = base_url
        self.model = model
        self.tracker = tracker
        self.api_endpoint = f"{base_url}/api/generate"
        
        # Test connection
        try:
            response = requests.get(f"{base_url}/api/tags", timeout=2)
            if response.status_code == 200:
                logger.info(f"Ollama connected successfully at {base_url}")
            else:
                logger.warning(f"Ollama service not responding at {base_url}")
        except Exception as e:
            logger.warning(f"Ollama not available: {e}. Make sure Ollama is running.")
    
    def call(self, prompt: str, config: Dict[str, Any]) -> str:
        """
        Call Ollama API.
        
        Args:
            prompt: The prompt to send
            config: Configuration dict (model, temperature, max_tokens)
        
        Returns:
            Generated text response
        """
        # If the model requested is a Gemini model, override it with our local model
        config_model = config.get("model")
        if config_model and ("gemini" in config_model.lower()):
            model_name = self.model
        else:
            model_name = config_model or self.model
        temperature = config.get("temperature", 0.1)
        max_tokens = config.get("max_tokens", 8192)
        
        payload = {
            "model": model_name,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
            }
        }
        
        try:
            logger.info(f"Calling Ollama with model: {model_name}")
            response = requests.post(
                self.api_endpoint,
                json=payload,
                timeout=300  # 5 minutes timeout for long generations
            )
            
            if response.status_code != 200:
                raise Exception(f"Ollama API error: {response.status_code} - {response.text}")
            
            result = response.json()
            generated_text = result.get("response", "")
            
            # Track usage if tracker available
            if self.tracker:
                # Ollama doesn't provide exact token counts, estimate
                input_tokens = len(prompt.split()) * 1.3  # rough estimate
                output_tokens = len(generated_text.split()) * 1.3
                self.tracker.add_usage(int(input_tokens), int(output_tokens))
            
            logger.info(f"Ollama response received ({len(generated_text)} chars)")
            return generated_text
            
        except requests.exceptions.Timeout:
            logger.error("Ollama request timed out (5 min)")
            raise Exception("Ollama timeout - model may be too slow or stuck")
        except requests.exceptions.ConnectionError:
            logger.error("Cannot connect to Ollama - is it running?")
            raise Exception("Ollama not running. Start with: ollama serve")
        except Exception as e:
            logger.error(f"Ollama Adapter Error: {e}")
            raise
