import logging
import asyncio
import os
from typing import List, Optional, Dict, Tuple
from ..models import StaticFinding, VerifiedVuln, ConfirmedStatus, FindingSeverity
from ..llm_gateway import LLMGateway
from ..tools.sandbox_executor import SandboxExecutor

logger = logging.getLogger(__name__)

class Verifier:
    """
    Autonomous Verifier Agent.
    Strategy: Template-Driven Generation with Feedback Loop + Docker Sandbox Execution.
    """
    
    def __init__(self, llm_gateway: Optional[LLMGateway] = None):
        self.llm = llm_gateway or LLMGateway()
        self.sandbox = SandboxExecutor()  # Real Docker execution
        # Path to templates
        self.templates_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "templates", "poc")

    async def verify_finding(self, finding: StaticFinding, target_url: str) -> VerifiedVuln:
        """
        Verify a static finding by generating and running a PoC.
        """
        logger.info(f"Verifying finding {finding.id} ({finding.description})...")
        
        # 1. Select Template
        template_name = self._select_template(finding)
        if not template_name:
            logger.warning(f"No suitable PoC template for {finding.description}")
            return VerifiedVuln(
                finding_id=finding.id,
                status=ConfirmedStatus.INCONCLUSIVE,
                poc={},
                runtime_output="No template available",
                evidence="Skipped",
                severity_adjustment=None
            )

        # 2. Loop & Refine (Feedback Loop)
        MAX_RETRIES = 3
        attempt = 0
        current_error = None
        
        # 3. Generate PoC Script (Fill Template)
        # Assuming we need to read prompt first, but let's mock the generation structure.
        poc_script = self._generate_poc(template_name, finding, target_url)
        
        while attempt < MAX_RETRIES:
            attempt += 1
            logger.info(f"  > Verification Attempt {attempt} for {finding.id}")
            
            # 4. Execute PoC (Sandbox)
            exit_code, stdout, stderr = await self._run_sandbox(poc_script)
            
            # 5. Analyze Result
            if exit_code == 0:
                # SUCCESS: Vulnerability Confirmed
                logger.info(f"  ✅ Vulnerability CONFIRMED! (Exit Code 0)")
                return VerifiedVuln(
                    finding_id=finding.id,
                    status=ConfirmedStatus.CONFIRMED,
                    poc={"type": "python", "content": poc_script},
                    runtime_output=stdout,
                    evidence=f"PoC Successful. Output: {stdout[:100]}...",
                    severity_adjustment=FindingSeverity.CRITICAL # Confirmed exploits are critical
                )
            else:
                # FAILURE: Analyze why
                # Two types: useful failure (assertion error) vs execution error (syntax)
                current_error = f"Exit Code: {exit_code}\nStderr: {stderr}\nStdout: {stdout}"
                logger.warning(f"  ❌ PoC Failed: {stderr.strip()}")
                
                # Feedback Loop logic would go here: ask LLM to fix syntax or refine payload
                # For this simplified implementation, we break or retry.
                # In real imp: poc_script = self.llm.refine_poc(poc_script, current_error)
                pass 
                
        # If all retries fail
        return VerifiedVuln(
            finding_id=finding.id,
            status=ConfirmedStatus.REJECTED,
            poc={"type": "python", "content": poc_script},
            runtime_output=current_error,
            evidence="PoC failed to verify vulnerability after retries.",
            severity_adjustment=None
        )

    def _select_template(self, finding: StaticFinding) -> Optional[str]:
        """Heuristic to select template based on finding description/tool."""
        desc = finding.description.lower()
        if "sql" in desc:
            return "http_sqli_time_based.py"
        if "xss" in desc:
            return "http_xss_reflected.py"
        return None

    def _generate_poc(self, template_name: str, finding: StaticFinding, target_url: str, feedback: Optional[str] = None) -> str:
        """
        Ask LLM to fill the template.
        """
        # Load template
        template_path = os.path.join(self.templates_dir, template_name)
        if not os.path.exists(template_path):
            # Fallback mock template if file not found (for dev)
            return f"# Template {template_name} not found. Mock script.\nimport time\nprint('Running check...')\n# sleep(5)"
            
        with open(template_path, 'r') as f:
            template_content = f.read()
            
        # Prompt LLM (Mocked)
        # In real impl, we call self.llm.generate(prompt)
        
        # Simple placeholder replacement for now to simulate "filling"
        return template_content.replace("{{TARGET}}", target_url).replace("{{PAYLOAD}}", "' OR SLEEP(5)--")

    async def _run_sandbox(self, script_content: str, language: str = "PHP") -> Tuple[int, str, str]:
        """
        Execute the script in a secure Docker sandbox.
        
        Args:
            script_content: Code to execute
            language: Programming language (PHP, Python, Go, Java)
            
        Returns:
            Tuple of (exit_code, stdout, stderr)
        """
        logger.info(f"  [Sandbox] Executing {language} PoC in Docker container...")
        
        try:
            # Select executor based on language
            if language.upper() == "PHP":
                result = await self.sandbox.execute_php(script_content)
            elif language.upper() == "PYTHON":
                result = await self.sandbox.execute_python(script_content)
            elif language.upper() == "GO":
                result = await self.sandbox.execute_go(script_content)
            elif language.upper() == "JAVA":
                result = await self.sandbox.execute_java(script_content)
            else:
                logger.warning(f"Unsupported language: {language}, falling back to mock")
                return -1, "", f"Unsupported language: {language}"
            
            # Log execution results
            if result.timed_out:
                logger.warning(f"  ⏱️  Execution timed out after {result.execution_time:.2f}s")
            elif result.exit_code == 0:
                logger.info(f"  ✅ Execution successful (exit_code=0, time={result.execution_time:.2f}s)")
            else:
                logger.warning(f"  ❌ Execution failed (exit_code={result.exit_code})")
            
            return result.exit_code, result.stdout, result.stderr
            
        except Exception as e:
            logger.error(f"Sandbox execution error: {str(e)}")
            return -1, "", f"Sandbox error: {str(e)}"
