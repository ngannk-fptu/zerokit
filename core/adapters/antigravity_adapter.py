import logging
import json
import time
import uuid
import os
from pathlib import Path
from typing import Any, Dict, Optional
from datetime import datetime
from .base import LLMAdapter

logger = logging.getLogger(__name__)

class AntigravityNotAvailableError(Exception):
    """Raised when Antigravity does not respond within timeout."""
    pass

class AntigravityAdapter(LLMAdapter):
    """
    Adapter for Antigravity AI Assistant using file-based communication.
    
    Workflow:
    1. Write prompt to queue/<uuid>.json
    2. Poll for response in responses/<uuid>.json
    3. Parse response and return
    4. Archive prompt+response for dataset
    """
    
    def __init__(
        self, 
        queue_dir: str = ".agent/prompts/queue",
        response_dir: str = ".agent/prompts/responses",
        archive_dir: str = ".agent/prompts/archive",
        tracker: Any = None,
        timeout: int = 60,
        poll_interval: float = 0.5
    ):
        self.queue_dir = Path(queue_dir)
        self.response_dir = Path(response_dir)
        self.archive_dir = Path(archive_dir)
        self.tracker = tracker
        self.timeout = timeout
        self.poll_interval = poll_interval
        
        # Ensure directories exist
        self.queue_dir.mkdir(parents=True, exist_ok=True)
        self.response_dir.mkdir(parents=True, exist_ok=True)
        self.archive_dir.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"AntigravityAdapter initialized: queue={queue_dir}, timeout={timeout}s")

    def call(self, prompt: str, config: Dict[str, Any]) -> str:
        """
        Call Antigravity via file-based communication.
        
        Args:
            prompt: The rendered prompt text
            config: Configuration dict with 'agent', 'method', 'model', etc.
            
        Returns:
            Response text from Antigravity
            
        Raises:
            AntigravityNotAvailableError: If no response within timeout
        """
        request_id = str(uuid.uuid4())
        
        # 1. Create queue file
        queue_file = self.queue_dir / f"{request_id}.json"
        response_file = self.response_dir / f"{request_id}.json"
        
        request_data = {
            "id": request_id,
            "agent": config.get("agent", "unknown"),
            "method": config.get("method", "unknown"),
            "prompt": prompt,
            "config": {
                "model": config.get("model", "antigravity"),
                "temperature": config.get("temperature", 0.1),
                "max_tokens": config.get("max_tokens", 8192)
            },
            "timestamp": datetime.now().isoformat()
        }
        
        logger.info(f"📤 Antigravity Request [{request_id[:8]}]: {config.get('agent')}/{config.get('method')}")
        
        # Write queue file
        with open(queue_file, 'w', encoding='utf-8') as f:
            json.dump(request_data, f, indent=2, ensure_ascii=False)
        
        # 2. Poll for response
        start_time = time.time()
        
        while True:
            elapsed = time.time() - start_time
            
            if elapsed > self.timeout:
                logger.error(f"❌ Antigravity timeout after {self.timeout}s for [{request_id[:8]}]")
                # Cleanup queue file
                if queue_file.exists():
                    queue_file.unlink()
                raise AntigravityNotAvailableError(
                    f"No response from Antigravity within {self.timeout}s. "
                    f"Request ID: {request_id}"
                )
            
            # Check if response file exists
            if response_file.exists():
                try:
                    with open(response_file, 'r', encoding='utf-8') as f:
                        response_data = json.load(f)
                    
                    # Validate response
                    if response_data.get("id") != request_id:
                        logger.warning(f"⚠️ Response ID mismatch: expected {request_id}, got {response_data.get('id')}")
                        time.sleep(self.poll_interval)
                        continue
                    
                    response_text = response_data.get("response", "")
                    
                    if not response_text:
                        logger.error(f"❌ Empty response in [{request_id[:8]}]")
                        raise ValueError("Empty response from Antigravity")
                    
                    logger.info(f"✅ Antigravity Response [{request_id[:8]}]: {len(response_text)} chars")
                    
                    # 3. Track usage if available
                    if self.tracker and "usage" in response_data:
                        usage = response_data["usage"]
                        input_tokens = usage.get("input_tokens", 0)
                        output_tokens = usage.get("output_tokens", 0)
                        self.tracker.add_usage(input_tokens, output_tokens)
                    
                    # 4. Archive for dataset
                    self._archive_conversation(request_id, request_data, response_data)
                    
                    # 5. Cleanup
                    queue_file.unlink(missing_ok=True)
                    response_file.unlink(missing_ok=True)
                    
                    return response_text
                    
                except json.JSONDecodeError as e:
                    logger.error(f"❌ Malformed response JSON in [{request_id[:8]}]: {e}")
                    # Wait a bit in case file is being written
                    time.sleep(self.poll_interval)
                    continue
                except Exception as e:
                    logger.error(f"❌ Error reading response [{request_id[:8]}]: {e}")
                    raise
            
            # Wait before next poll
            time.sleep(self.poll_interval)
    
    def _archive_conversation(self, request_id: str, request: dict, response: dict):
        """
        Archive the prompt-response pair for dataset preservation.
        """
        try:
            archive_file = self.archive_dir / f"{request_id}.json"
            archive_data = {
                "request": request,
                "response": response,
                "archived_at": datetime.now().isoformat()
            }
            
            with open(archive_file, 'w', encoding='utf-8') as f:
                json.dump(archive_data, f, indent=2, ensure_ascii=False)
                
            logger.debug(f"📦 Archived conversation [{request_id[:8]}]")
        except Exception as e:
            logger.warning(f"⚠️ Failed to archive [{request_id[:8]}]: {e}")
