import logging
import uuid
import os
import time
from datetime import datetime
from typing import Optional
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

from .llm_cache import LLMCache
from .token_tracker import TokenTracker
from .prompter import Prompter

logger = logging.getLogger(__name__)

class LLMGateway:
    """
    Gateway to Antigravity AI Assistant using file-based communication (Worker API).
    Powered by Prompter (external .md prompts) and AntigravityAdapter.
    """
    
    def __init__(self):
        self.debug = os.getenv("LLM_DEBUG", "false").lower() == "true"
        
        # Load Fallback Architecture (e.g. "antigravity,openai")
        chain_env = os.getenv("LLM_FALLBACK_CHAIN", "antigravity,openai")
        self.fallback_chain = [p.strip().lower() for p in chain_env.split(",") if p.strip()]
        
        # Initialize subsystems
        self.cache = LLMCache()
        self.tracker = TokenTracker()
        self.prompter = Prompter()
        
        # Lazy Load Adapter Registry
        self._adapters_cache = {}
            
        logger.info(f"LLMGateway initialized with Fallback Chain: {self.fallback_chain}")

    def _get_adapter(self, provider_name: str):
        """Lazy loads and caches adapters based on string name."""
        if provider_name in self._adapters_cache:
            return self._adapters_cache[provider_name]
            
        if provider_name == "antigravity":
            from .adapters.antigravity_adapter import AntigravityAdapter
            adapter = AntigravityAdapter(
                queue_dir=os.getenv("ANTIGRAVITY_QUEUE_DIR", ".agent/prompts/queue"),
                response_dir=os.getenv("ANTIGRAVITY_RESPONSE_DIR", ".agent/prompts/responses"),
                archive_dir=os.getenv("ANTIGRAVITY_ARCHIVE_DIR", ".agent/prompts/archive"),
                tracker=self.tracker,
                timeout=int(os.getenv("ANTIGRAVITY_TIMEOUT", "60"))
            )
        elif provider_name in ["openai", "groq"]:
            from .adapters.openai_adapter import OpenAIAdapter
            adapter = OpenAIAdapter()
        else:
            raise ValueError(f"Unknown LLM Provider mapping: {provider_name}")
            
        self._adapters_cache[provider_name] = adapter
        return adapter

    def _log_audit(
        self, agent: str, method: str, provider: str, model: str, 
        prompt_text: str, response_text: str, duration: float, error: str = None
    ):
        """Saves prompt and response as a Markdown file for debug + audit trail."""
        try:
            audit_dir = os.path.join(os.getcwd(), ".agent", "logs", "audit")
            os.makedirs(audit_dir, exist_ok=True)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            short_id = str(uuid.uuid4())[:6]
            status = "ERROR" if error else "SUCCESS"
            
            filename = f"{timestamp}_{agent}_{method}_{status}_{short_id}.md"
            filepath = os.path.join(audit_dir, filename)
            
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(f"# LLM Audit Log\n")
                f.write(f"- **Timestamp**: {datetime.now().isoformat()}\n")
                f.write(f"- **Agent**: `{agent}`\n")
                f.write(f"- **Prompt**: `{method}`\n")
                f.write(f"- **Provider**: `{provider}` (Model: `{model}`)\n")
                f.write(f"- **Status**: `{status}`\n")
                f.write(f"- **Duration**: `{duration:.2f}s`\n\n")
                
                f.write(f"## Rendered Prompt\n```text\n{prompt_text}\n```\n\n")
                
                if error:
                    f.write(f"## Error Details\n```text\n{error}\n```\n")
                else:
                    f.write(f"## LLM Response\n```text\n{response_text}\n```\n")
        except Exception as e:
            logger.error(f"Failed to write audit log: {e}")

    def _execute_prompt(self, agent: str, method: str, **variables) -> str:
        """
        Loads prompt, checks cache, and dynamically drops down the Fallback Chain until success.
        """
        # 1. Load Template & Render
        template = self.prompter.load(agent, method)
        prompt_text = self.prompter.render(template, **variables)
        
        errors = []
        
        # Try every provider in the configured Fallback Chain
        for provider in self.fallback_chain:
            # 2. Get Config specialized for this provider
            config = self.prompter.get_config(template, provider)
            model_name = config.get("model", provider)
            
            if self.debug:
                logger.debug(f"Attempting {provider} for {agent}/{method} via Model {model_name}")
            
            # 3. Check Cache
            cached = self.cache.get(prompt_text, model_name)
            if cached:
                if self.debug: logger.debug(f"Cache hit on {model_name}")
                return cached
                
            # 4. Invoke the Adapter
            start_time = time.time()
            try:
                adapter = self._get_adapter(provider)
                # Pass context to antigravity
                config["agent"] = agent
                config["method"] = method
                
                response = adapter.call(prompt_text, config)
                duration = time.time() - start_time
                
                # Log audit trail
                self._log_audit(agent, method, provider, model_name, prompt_text, response, duration)
                
                # Cache response on success
                self.cache.set(prompt_text, response, 0, 0.0, model_name)
                return response
                
            except Exception as e:
                duration = time.time() - start_time
                self._log_audit(agent, method, provider, model_name, prompt_text, "", duration, str(e))
                logger.warning(f"[Fallback Triggered] Model '{provider}' failed: {e}")
                errors.append(f"{provider}: {str(e)}")
                continue # Try the next provider in the chain
                
        # If the loop exhausts the chain without returning, the system completely failed.
        logger.error(f"All LLM Providers in the Fallback Chain failed. Errors: {errors}")
        raise RuntimeError(f"LLM Gateway Execution Failed. Chain exhausted: {errors}")

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

    def generate_poc(self, hypothesis_id: str, finding_description: str, cwe_id: str, location: str, language: str, trust_boundary: str, sink: str, target_function: str = "", source: str = "", context: str = "", sandbox_type: str = "subprocess", taint_trace: str = "") -> str:
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
                                  sandbox_type=sandbox_type,
                                  taint_trace=taint_trace)

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

    def generate_hypotheses(self, filename: str, source_code_context: str, route_info: str, language: str, security_profile: str, code_graph_summary: str = "", context: str = "") -> str:
        """
        Generates security hypotheses based on code metadata and trust boundaries.
        """
        return self._execute_prompt("threat_modeler", "analyze_risk",
                                  filename=filename,
                                  source_code_context=source_code_context,
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
                                  
    def evaluate_poc_output(
        self,
        cwe_id: str,
        description: str,
        poc_script: str,
        stdout: str,
        target_data: str = ""
    ) -> str:
        """
        Zero-shot LLM judge for logic bug PoCs (IDOR/Race/AuthZ).
        Returns 'YES' (exploit succeeded) or 'NO' (exploit failed).
        Truncates stdout to last 4000 chars to prevent token explosion.
        """
        truncated_stdout = stdout[-4000:] if len(stdout) > 4000 else stdout
        return self._execute_prompt(
            "verifier", "evaluate_poc",
            cwe_id=cwe_id,
            description=description,
            poc_script=poc_script,
            stdout=truncated_stdout,
            target_data=target_data
        )

    def generate_attack_chains(
        self,
        endpoints_summary: str,
        security_profile: str,
    ) -> str:
        """
        Cross-endpoint attack chain discovery.
        Sends a structured endpoint summary table to the LLM for chain-of-thought
        analysis, returning JSON array of potential multi-step exploit chains.
        """
        return self._execute_prompt(
            "threat_modeler", "analyze_chains",
            endpoints_summary=endpoints_summary,
            security_profile=security_profile
        )

    def get_usage_stats(self) -> dict:
        return {
            "tracker": self.tracker.get_current_usage(),
            "cache": self.cache.get_stats()
        }
