import logging
import uuid
import os
from typing import Optional
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

from .llm_cache import LLMCache
from .token_tracker import TokenTracker, BudgetExceededError
from .prompter import Prompter
from .adapters.gemini import GeminiAdapter
from .adapters.ollama import OllamaAdapter
from .adapters.antigravity_adapter import AntigravityAdapter, AntigravityNotAvailableError

logger = logging.getLogger(__name__)

class LLMGateway:
    """
    Gateway to Large Language Models for dynamic code/rule generation.
    Powered by Prompter (external .md prompts) and LLMAdapters.
    """
    
    def __init__(self):
        self.provider = os.getenv("LLM_PROVIDER", "antigravity")
        self.api_key = os.getenv("GOOGLE_API_KEY")
        self.fallback_mode = os.getenv("LLM_FALLBACK_MODE", "error")
        self.enable_gemini_fallback = os.getenv("ENABLE_GEMINI_FALLBACK", "true").lower() == "true"
        self.debug = os.getenv("LLM_DEBUG", "false").lower() == "true"
        
        # Initialize subsystems
        self.cache = LLMCache()
        self.tracker = TokenTracker()
        self.prompter = Prompter()
        
        # Initialize Adapter
        if self.provider == "antigravity":
            self.adapter = AntigravityAdapter(
                queue_dir=os.getenv("ANTIGRAVITY_QUEUE_DIR", ".agent/prompts/queue"),
                response_dir=os.getenv("ANTIGRAVITY_RESPONSE_DIR", ".agent/prompts/responses"),
                archive_dir=os.getenv("ANTIGRAVITY_ARCHIVE_DIR", ".agent/prompts/archive"),
                tracker=self.tracker,
                timeout=int(os.getenv("ANTIGRAVITY_TIMEOUT", "60"))
            )
            # Initialize fallback adapter if enabled
            if self.enable_gemini_fallback and self.api_key:
                self.fallback_adapter = GeminiAdapter(self.api_key, self.tracker)
                logger.info("Gemini fallback adapter enabled")
            else:
                self.fallback_adapter = None
        elif self.provider == "gemini":
            self.adapter = GeminiAdapter(self.api_key, self.tracker)
            self.fallback_adapter = None
        elif self.provider == "ollama":
            self.adapter = OllamaAdapter(
                base_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"),
                model=os.getenv("OLLAMA_MODEL", "codellama:13b"),
                tracker=self.tracker
            )
            self.fallback_adapter = None
        else:
            raise ValueError(f"Unsupported LLM Provider: {self.provider}")
            
        logger.info(f"LLMGateway initialized with {self.provider} adapter")

    def _execute_prompt(self, agent: str, method: str, **variables) -> str:
        """
        Helper to load prompt, render it, check cache, and call adapter.
        """
        # 1. Load Template
        template = self.prompt_loader.load(agent, method)
        
        # 2. Render Prompt
        prompt_text = self.prompt_loader.render(template, **variables)
        
        # 3. Get Config (Model, Temp, etc.)
        config = self.prompt_loader.get_config(template, self.provider)
        model_name = config.get("model")
        
        if self.debug:
            logger.debug(f"Executing {agent}/{method} (v{template.version})")
            logger.debug(f"Prompt Config: {config}")
        
        # 4. Check Cache
        cached = self.cache.get(prompt_text, model_name)
        if cached:
            return cached
            
        # 5. Call Adapter with Antigravity Fallback
        try:
            # Pass agent and method through config for Antigravity
            config["agent"] = agent
            config["method"] = method
            response = self.adapter.call(prompt_text, config)
            
            # 6. Cache Response (Cost tracked inside adapter/tracker)
            # Note: Adapter tracks usage, so we just need to cache the text here
            # We estimate tokens for the cache record if adapter didn't provide exact counts
            # But for simplicity, we let the cache handle raw storage
            # The adapter already updated the tracker.
            
            # For cache storage, we might want cost info. 
            # Current cache.set takes tokens/cost. 
            # We can get cost from tracker delta? 
            # For now, pass 0 as adapter handles tracking aggregation.
            self.cache.set(prompt_text, response, 0, 0.0, model_name)
            
            return response
        
        except AntigravityNotAvailableError as e:
            logger.error(f"Antigravity timeout: {e}")
            
            # Fallback to Gemini if enabled
            if self.fallback_adapter:
                logger.warning(f"⚠️ Antigravity is not responding. Attempting fallback to Gemini...")
                logger.warning(f"   Question: Would you like to continue with Gemini API?")
                logger.warning(f"   To disable this fallback, set ENABLE_GEMINI_FALLBACK=false in .env")
                
                try:
                    response = self.fallback_adapter.call(prompt_text, config)
                    self.cache.set(prompt_text, response, 0, 0.0, config.get("model", "gemini-fallback"))
                    logger.info(f"✅ Fallback to Gemini succeeded")
                    return response
                except Exception as fallback_err:
                    logger.error(f"Gemini fallback also failed: {fallback_err}")
                    raise e  # Raise original Antigravity error
            else:
                logger.error("No fallback adapter available. Pipeline cannot continue.")
                raise
            
        except Exception as e:
            logger.error(f"LLM Execution Failed: {e}")
            if self.fallback_mode == "mock":
                return self._mock_fallback(method, variables)
            raise

    def generate_semgrep_rule(self, description: str, context: str, target: str) -> str:
        return self._execute_prompt("detector", "generate_rule", 
                                  description=description, 
                                  context=context, 
                                  target=target)

    def fix_semgrep_rule(self, failed_rule: str, error_msg: str) -> str:
        return self._execute_prompt("detector", "fix_rule", 
                                  failed_rule=failed_rule, 
                                  error_msg=error_msg)

    def generate_poc(self, finding_description: str, location: str, language: str, context: str = "") -> str:
        return self._execute_prompt("verifier", "generate_poc", 
                                  finding_description=finding_description, 
                                  location=location, 
                                  language=language, 
                                  context=context)

    def generate_patch(self, vulnerability_type: str, original_code: str, location: str, root_cause: dict = None) -> str:
        """
        Generates a patch. Accepts optional root_cause analysis to improve context.
        """
        root_cause_text = ""
        if root_cause:
             root_cause_text = f"\nRoot Cause Analysis:\n{root_cause.get('description')}\nFaulty Function: {root_cause.get('faulty_function_name')}\nSuggestion: {root_cause.get('fix_suggestion')}"

        return self._execute_prompt("patcher", "generate_patch", 
                                  vulnerability_type=vulnerability_type, 
                                  original_code=original_code, 
                                  location=location,
                                  root_cause_context=root_cause_text)

    def analyze_root_cause(self, vulnerability_type: str, original_code: str, location: str, crash_log: str, static_trace: str) -> str:
        return self._execute_prompt("rca", "analyze_crash",
                                  vulnerability_type=vulnerability_type,
                                  original_code=original_code,
                                  location=location,
                                  crash_log=crash_log,
                                  static_trace=static_trace)

    def generate_hypotheses(self, filename: str, signature: str, route: str) -> str:
        """
        Generates security hypotheses based on code metadata.
        """
        return self._execute_prompt("threat_modeler", "analyze_risk",
                                  filename=filename,
                                  function_signature=signature,
                                  route_info=route)
                                  
    def extract_variant_pattern(self, code: str, vulnerability_description: str) -> str:
        """
        Extracts an abstract pattern from a confirmed vulnerability for variant analysis.
        """
        return self._execute_prompt("detector", "extract_variant",
                                  code=code,
                                  vulnerability_description=vulnerability_description)
                                  
    def get_usage_stats(self) -> dict:
        return {
            "tracker": self.tracker.get_current_usage(),
            "cache": self.cache.get_stats()
        }

    # Internal Mock Fallback
    def _mock_fallback(self, method: str, vars: dict) -> str:
        logger.warning(f"Using Mock Fallback for {method}")
        if method == "generate_semgrep_rule":
            return self._template_generic(vars.get("description", "Unknown"), vars.get("target", "Target"))
        if method == "analyze_risk":
            return self._template_hypothesis(vars.get("filename", "unknown.php"))
        return "Mock Response (Fallback)"

    def _template_hypothesis(self, filename: str) -> str:
        import json
        return json.dumps([
            {
                "risk": "Mock Logic Flaw",
                "severity": "HIGH",
                "reasoning": f"Mock AI thinks {filename} looks suspicious.",
                "suggested_check": "Verify manually."
            }
        ])

    def _template_generic(self, description: str, target: str) -> str:
        return f"""rules:
  - id: mock-rule-{uuid.uuid4().hex[:8]}
    languages: [python, php]
    severity: WARNING
    message: "{description}"
    patterns:
      - pattern: "$...MOCK"
"""
