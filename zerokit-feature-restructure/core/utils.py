import logging
from typing import Any
import json_repair

logger = logging.getLogger(__name__)

def extract_json(text: str, default: Any = None) -> Any:
    """
    Robustly extract and parse JSON from LLM outputs using json_repair.
    Handles raw JSON, markdown-wrapped JSON (```json ... ```), missing commas, 
    unquoted keys, and trailing conversational text.
    
    Args:
        text (str): The raw LLM output.
        default (Any): The fallback value to return if parsing completely fails 
                       (e.g., [] for lists, {} for dicts).
                       
    Returns:
        Any: The parsed JSON object, or the default value on failure.
    """
    if not text or not text.strip():
        logger.warning("Empty text provided to extract_json.")
        return default if default is not None else {}
        
    try:
        # json_repair.loads automatically handles markdown stripping, 
        # structure repair, and aggressive JSON extraction.
        parsed = json_repair.loads(text)
        
        # json_repair might return an empty string if it finds nothing
        if parsed == "" and text.strip() != '""':
            logger.error(f"json_repair failed to extract JSON from: {text[:100]}...")
            return default if default is not None else {}
            
        return parsed
    except Exception as e:
        logger.error(f"Critical failure in json_repair: {e}")
        return default if default is not None else {}
