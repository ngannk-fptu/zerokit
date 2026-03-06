import logging
import uuid
import os
from typing import Optional
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

from .llm_cache import LLMCache
from .token_tracker import TokenTracker
from .prompter import Prompter
from .adapters.antigravity_adapter import AntigravityAdapter

logger = logging.getLogger(__name__)

class LLMGateway:
    """
    Gateway to Antigravity AI Assistant using file-based communication (Worker API).
    Powered by Prompter (external .md prompts) and AntigravityAdapter.
    """
    
    def __init__(self):
        # Strict enforcement: Always use antigravity
        self.provider = "antigravity"
        self.debug = os.getenv("LLM_DEBUG", "false").lower() == "true"
        
        # Initialize subsystems
        self.cache = LLMCache()
        self.tracker = TokenTracker()
        self.prompter = Prompter()
        
        # Initialize Antigravity Adapter
        self.adapter = AntigravityAdapter(
            queue_dir=os.getenv("ANTIGRAVITY_QUEUE_DIR", ".agent/prompts/queue"),
            response_dir=os.getenv("ANTIGRAVITY_RESPONSE_DIR", ".agent/prompts/responses"),
            archive_dir=os.getenv("ANTIGRAVITY_ARCHIVE_DIR", ".agent/prompts/archive"),
            tracker=self.tracker,
            timeout=int(os.getenv("ANTIGRAVITY_TIMEOUT", "60"))
        )
            
        logger.info(f"LLMGateway initialized in STRICT Antigravity Worker API mode")

    def _execute_prompt(self, agent: str, method: str, **variables) -> str:
        """
        Helper to load prompt, render it, check cache, and call Antigravity adapter.
        """
        # 1. Load Template
        template = self.prompter.load(agent, method)
        
        # 2. Render Prompt
        prompt_text = self.prompter.render(template, **variables)
        
        # 3. Get Config (Model, Temp, etc.)
        config = self.prompter.get_config(template, self.provider)
        model_name = config.get("model", "antigravity")
        
        if self.debug:
            logger.debug(f"Executing {agent}/{method} (v{template.version})")
            logger.debug(f"Prompt Config: {config}")
        
        # 4. Check Cache
        cached = self.cache.get(prompt_text, model_name)
        if cached:
            return cached
            
        # 5. Call Antigravity Adapter
        try:
            # Pass agent and method through config for Antigravity
            config["agent"] = agent
            config["method"] = method
            response = self.adapter.call(prompt_text, config)
            
            # 6. Cache Response
            self.cache.set(prompt_text, response, 0, 0.0, model_name)
            
            return response
        
        except Exception as e:
            logger.error(f"Antigravity Execution Failed: {e}")
            raise

    def generate_semgrep_rule(self, hypothesis_id: str, description: str, cwe_id: str, language: str, source: str, sink: str, trust_boundary: str, sanitizers: str = "", sanitizer_bypass: str = "", target: str = "", context: str = "") -> str:
        return self._execute_prompt("detector", "generate_rule", 
                                  hypothesis_id=hypothesis_id,
                                  description=description,
                                  cwe_id=cwe_id,
                                  language=language,
                                  source=source,
                                  sink=sink,
                                  trust_boundary=trust_boundary,
                                  sanitizers=sanitizers,
                                  sanitizer_bypass=sanitizer_bypass,
                                  target=target,
                                  context=context)

    def fix_semgrep_rule(self, failed_rule: str, error_msg: str, language: str, attempt_number: int, hypothesis_id: str = "") -> str:
        return self._execute_prompt("detector", "fix_rule", 
                                  failed_rule=failed_rule, 
                                  error_msg=error_msg,
                                  language=language,
                                  attempt_number=attempt_number,
                                  hypothesis_id=hypothesis_id)

    def generate_poc(self, hypothesis_id: str, finding_description: str, cwe_id: str, location: str, language: str, trust_boundary: str, sink: str, target_function: str = "", source: str = "", context: str = "", sandbox_type: str = "subprocess") -> str:
        return self._execute_prompt("verifier", "generate_poc", 
                                  hypothesis_id=hypothesis_id,
                                  finding_description=finding_description,
                                  cwe_id=cwe_id,
                                  location=location,
                                  language=language,
                                  trust_boundary=trust_boundary,
                                  sink=sink,
                                  target_function=target_function,
                                  source=source,
                                  context=context,
                                  sandbox_type=sandbox_type)

    def generate_patch(self, hypothesis_id: str, vulnerability_type: str, cwe_id: str, location: str, original_code: str, faulty_lines: str, fix_strategy: str, patch_scope: str, regression_risk: str = "", language: str = "", test_command: str = "") -> str:
        """
        Generates a patch safely.
        """
        return self._execute_prompt("patcher", "generate_patch", 
                                  hypothesis_id=hypothesis_id,
                                  vulnerability_type=vulnerability_type,
                                  cwe_id=cwe_id,
                                  location=location,
                                  original_code=original_code,
                                  faulty_lines=faulty_lines,
                                  fix_strategy=fix_strategy,
                                  patch_scope=patch_scope,
                                  regression_risk=regression_risk,
                                  language=language,
                                  test_command=test_command)

    def analyze_root_cause(self, hypothesis_id: str, vulnerability_type: str, cwe_id: str, original_code: str, location: str, crash_log: str, static_trace: str = "", trust_boundary: str = "", target_function: str = "") -> str:
        return self._execute_prompt("rca", "analyze_crash",
                                  hypothesis_id=hypothesis_id,
                                  vulnerability_type=vulnerability_type,
                                  cwe_id=cwe_id,
                                  original_code=original_code,
                                  location=location,
                                  crash_log=crash_log,
                                  static_trace=static_trace,
                                  trust_boundary=trust_boundary,
                                  target_function=target_function)

    def generate_hypotheses(self, filename: str, function_signature: str, route_info: str, language: str, security_profile: str, code_graph_summary: str = "", context: str = "") -> str:
        """
        Generates security hypotheses based on code metadata and trust boundaries.
        """
        return self._execute_prompt("threat_modeler", "analyze_risk",
                                  filename=filename,
                                  function_signature=function_signature,
                                  route_info=route_info,
                                  language=language,
                                  security_profile=security_profile,
                                  code_graph_summary=code_graph_summary,
                                  context=context)

    def generate_fuzz_harness(self, hypothesis_id: str, description: str, language: str, target_function: str, source_code: str) -> str:
        """
        Generates a fuzzing harness (AFL++, Atheris, etc.) for a specific finding.
        """
        return self._execute_prompt("harness_agent", "generate_harness",
                                  hypothesis_id=hypothesis_id,
                                  description=description,
                                  language=language,
                                  target_function=target_function,
                                  source_code=source_code)

    def repair_fuzz_harness(self, hypothesis_id: str, failed_harness: str, error_msg: str, language: str, attempt_number: int) -> str:
        """
        Repairs a failing fuzzing harness based on compile/runtime error.
        """
        return self._execute_prompt("harness_agent", "repair_harness",
                                  hypothesis_id=hypothesis_id,
                                  failed_harness=failed_harness,
                                  error_msg=error_msg,
                                  language=language,
                                  attempt_number=attempt_number)
                                  
    def extract_variant_pattern(self, vulnerability_description: str, code: str, language: str, security_profile_sinks: str, cwe_id: str = "", confirmed_sink: str = "") -> str:
        """
        Extracts an abstract pattern from a confirmed vulnerability for variant analysis.
        """
        return self._execute_prompt("detector", "extract_variant",
                                  vulnerability_description=vulnerability_description,
                                  code=code,
                                  language=language,
                                  security_profile_sinks=security_profile_sinks,
                                  cwe_id=cwe_id,
                                  confirmed_sink=confirmed_sink)

    async def explain_vulnerability_path(self, finding: 'StaticFinding', trace: list) -> str:
        """
        Narrates the data-flow trace from Source to Sink.
        """
        return self._execute_prompt("detector", "explain_path",
                                  vuln_type=finding.description,
                                  cwe_id=finding.cwe_details.get("id", "UNKNOWN") if finding.cwe_details else "UNKNOWN",
                                  severity=finding.severity,
                                  trace_json=json.dumps(trace, indent=2))
                                  
    def generate_codeql_query(self, vulnerability_description: str, code: str, language: str, cwe_id: str = "") -> str:
        """
        Generates a CodeQL query for MRVA based on a confirmed vulnerability.
        """
        return self._execute_prompt("detector", "generate_codeql",
                                  vulnerability_description=vulnerability_description,
                                  code=code,
                                  language=language,
                                  cwe_id=cwe_id)
                                  
    def get_usage_stats(self) -> dict:
        return {
            "tracker": self.tracker.get_current_usage(),
            "cache": self.cache.get_stats()
        }
