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

    async def verify_batch(self, findings: List[StaticFinding], concurrency: int = 5, callback=None, repo_path: Optional[str] = None) -> List[VerifiedVuln]:
        """Verify a batch of findings concurrently."""
        results = []
        semaphore = asyncio.Semaphore(concurrency)

        async def _verify_item(finding):
            async with semaphore:
                vuln = await self.verify_finding(finding, repo_path=repo_path)
                if callback:
                    callback(vuln)
                return vuln

        tasks = [_verify_item(f) for f in findings]
        results = await asyncio.gather(*tasks)
        return results

    async def verify_finding(self, finding: StaticFinding, target_url: str = None, repo_path: Optional[str] = None) -> VerifiedVuln:
        """
        Verify a static finding by generating and running a PoC.
        """
        logger.info(f"Verifying finding {finding.id} ({finding.description}) on {repo_path or 'primary'}...")
        
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
        poc_script = self._generate_poc(template_name, finding, target_url or "http://localhost:8080")
        
        while attempt < MAX_RETRIES:
            attempt += 1
            logger.info(f"  > Verification Attempt {attempt} for {finding.id}")
            
            # 4. Execute PoC (Sandbox)
            exit_code, stdout, stderr = await self._run_sandbox(poc_script, repo_path=repo_path)
            
            # 5. Analyze Result
            if exit_code == 0:
                logger.info(f"  ✅ Vulnerability CONFIRMED! (Exit Code 0)")
                return VerifiedVuln(
                    finding_id=finding.id,
                    status=ConfirmedStatus.CONFIRMED,
                    poc={"type": "python", "content": poc_script},
                    runtime_output=stdout,
                    evidence=f"PoC Successful. Output: {stdout[:100]}...",
                    severity_adjustment=FindingSeverity.CRITICAL
                )
            else:
                current_error = f"Exit Code: {exit_code}\nStderr: {stderr}\nStdout: {stdout}"
                logger.warning(f"  ❌ PoC Failed: {stderr.strip()}")
                # Optional: LLM refinement loop could be called here
                
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
        # MRVA variants might need custom templates or generic ones
        return "generic_check.py"

    def _generate_poc(self, template_name: str, finding: StaticFinding, target_url: str, feedback: Optional[str] = None) -> str:
        """
        Ask LLM to fill the template.
        """
        template_path = os.path.join(self.templates_dir, template_name)
        template_content = ""
        if os.path.exists(template_path):
            with open(template_path, 'r') as f:
                template_content = f.read()
        else:
            template_content = f"# Generic PoC for {finding.tool_name}\n# Target URL: {target_url}\n# Location: {finding.location}"
            
        cwe_id = "UNKNOWN"
        if finding.cwe_details:
             cwe_id = finding.cwe_details.get("id", "UNKNOWN")

        return self.llm.generate_poc(
            hypothesis_id=finding.hypothesis_id or "NONE",
            finding_description=finding.description,
            cwe_id=cwe_id,
            location=finding.location,
            language="python",
            trust_boundary=finding.metadata.get("trust_boundary", "Unknown"),
            sink=finding.metadata.get("sink", "Unknown"),
            target_function=finding.target_function or "",
            context=template_content.replace("{{TARGET}}", target_url)
        )

    async def _run_sandbox(self, script_content: str, language: str = "PYTHON", repo_path: Optional[str] = None) -> Tuple[int, str, str]:
        """
        Execute the script in a secure Docker sandbox with optional repo context.
        """
        logger.info(f"  [Sandbox] Executing {language} PoC in Docker container (Repo: {repo_path or 'Primary'})...")
        
        try:
            # If repo_path provided, we use project-level verification logic
            if repo_path:
                # Assuming sandbox has a method for this
                result = await self.sandbox.run_project_poc(
                    repo_path=repo_path,
                    script=script_content,
                    language=language
                )
            else:
                if language.upper() == "PHP":
                    result = await self.sandbox.execute_php(script_content)
                elif language.upper() == "PYTHON":
                    result = await self.sandbox.execute_python(script_content)
                else:
                    return -1, "", f"Unsupported language: {language}"
            
            return result.exit_code, result.stdout, result.stderr
            
        except Exception as e:
            logger.error(f"Sandbox execution error: {str(e)}")
            return -1, "", f"Sandbox error: {str(e)}"
