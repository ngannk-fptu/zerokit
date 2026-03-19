"""
Autonomous Verifier Agent.
Strategy:
  HTTP-level vulns → Burp Suite MCP (BurpVerifier) — real HTTP, timing, OOB.
  Code-level vulns → Docker ISOLATED sandbox (unchanged path).
"""
import logging
import asyncio
import os
from enum import Enum
from typing import List, Optional, Dict, Tuple
from ..models import StaticFinding, VerifiedVuln, ConfirmedStatus, FindingSeverity
from ..llm_gateway import LLMGateway
from ..tools.sandbox_executor import SandboxExecutor

logger = logging.getLogger(__name__)

# CWE ID → PoC template mapping (most precise selection method)
CWE_TEMPLATE_MAP = {
    # Injection
    89:   "http_sqli_time_based.py",
    78:   "command_injection.py",
    77:   "command_injection.py",
    94:   "code_injection.py",
    # XSS
    79:   "http_xss_reflected.py",
    # File/Path
    22:   "path_traversal.py",
    434:  "file_upload.py",
    # Auth/Access
    639:  "idor_check.py",
    862:  "missing_authz_check.py",
    287:  "auth_bypass_check.py",
    # Deserialization/XXE
    502:  "deserialization.py",
    611:  "xxe.py",
    # SSRF
    918:  "ssrf_check.py",
    # Misc
    352:  "csrf_check.py",
    1321: "prototype_pollution.py",
}

# Non-crash CWEs: exit_code == 0 is NOT sufficient proof — need LLM stdout evaluation.
# IDOR, Race Condition, Business Logic, Crypto Weakness, Auth Bypass, AuthZ, CSRF, Info Exposure
LOGIC_CWES: set = {639, 362, 840, 310, 287, 862, 352, 200}

# ---------------------------------------------------------------------------
# Verification routing
# ---------------------------------------------------------------------------

class VerificationMode(str, Enum):
    """Controls which verification engine handles a finding."""
    HTTP_NATIVE = "http_native"  # Native python requests, curl equivalent logs
    DOCKER   = "docker"          # --network none sandbox — code-level execution

# CWE IDs routed to native HTTP Verifier
HTTP_MODE_CWES: set = {89, 79, 918, 639, 22, 434, 352, 862, 287}

# Trust boundary → fallback template
BOUNDARY_TEMPLATE_MAP = {
    "HTTP→Database":     "http_sqli_time_based.py",
    "HTTP→OS":           "command_injection.py",
    "HTTP→File":         "path_traversal.py",
    "HTTP→Template":     "code_injection.py",
    "HTTP→URL":          "ssrf_check.py",
    "HTTP→Deserialize":  "deserialization.py",
}

# Keyword → last-resort fallback
_KEYWORD_FALLBACKS = [
    ("sql",          "http_sqli_time_based.py"),
    ("xss",          "http_xss_reflected.py"),
    ("command",      "command_injection.py"),
    ("rce",          "command_injection.py"),
    ("path traversal", "path_traversal.py"),
    ("directory",    "path_traversal.py"),
    ("ssrf",         "ssrf_check.py"),
    ("deseriali",    "deserialization.py"),
    ("idor",         "idor_check.py"),
    ("ssti",         "code_injection.py"),
    ("template inj", "code_injection.py"),
    ("xxe",          "xxe.py"),
    ("prototype",    "prototype_pollution.py"),
]


class Verifier:
    """
    Orchestrates PoC verification.
    Routes HTTP-level CWEs to BurpVerifier, code-level CWEs to Docker sandbox.
    Falls back to Docker automatically if Burp is unavailable.
    """

    def __init__(self, llm: LLMGateway, sandbox: SandboxExecutor = None):
        self.llm = llm
        self.sandbox = sandbox or SandboxExecutor()
        self._http_available: bool = True   # Native HTTP checks are always safe/available

        # Lazy-initialise HttpVerifier to avoid circular imports at module load
        self._http_verifier = None
        self.templates_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            "templates", "poc",
        )

    @property
    def http_verifier(self):
        if self._http_verifier is None:
            from ..agents.http_verifier import HttpVerifier
            from ..adapters.http_adapter import HttpAdapter
            self._http_verifier = HttpVerifier(HttpAdapter())
        return self._http_verifier

    async def verify_batch(
        self,
        findings: List[StaticFinding],
        concurrency: int = 5,
        callback=None,
        repo_path: Optional[str] = None,
    ) -> List[VerifiedVuln]:
        """Verify a batch of findings concurrently."""
        semaphore = asyncio.Semaphore(concurrency)

        async def _verify_item(finding):
            async with semaphore:
                vuln = await self.verify_finding(finding, repo_path=repo_path)
                if callback:
                    callback(vuln)
                return vuln

        tasks = [_verify_item(f) for f in findings]
        return await asyncio.gather(*tasks)

    async def verify_finding(
        self,
        finding: StaticFinding,
        target_url: str = None,
        repo_path: Optional[str] = None,
    ) -> VerifiedVuln:
        """Verify a static finding — routes to Burp MCP or Docker based on CWE."""
        mode = self._select_mode(finding)
        logger.info(
            f"Verifying finding {finding.id} ({finding.description}) "
            f"[mode={mode}, path={repo_path or 'primary'}]..."
        )

        # --- NATIVE HTTP path (HTTP-level vulns) ---
        if mode == VerificationMode.HTTP_NATIVE:
            vuln = await self.http_verifier.verify(finding, target_url)
            if vuln.status != ConfirmedStatus.INCONCLUSIVE:
                return vuln
                
            logger.info(f"[{finding.id}] HttpVerifier INCONCLUSIVE. Escalating to Docker Sandbox via LLM.")
            mode = VerificationMode.DOCKER

        # --- DOCKER path ---
        template_name = self._select_template(finding)
        if not template_name:
            logger.warning(f"No suitable PoC template for {finding.description}")
            return VerifiedVuln(
                finding_id=finding.id,
                status=ConfirmedStatus.INCONCLUSIVE,
                poc={},
                runtime_output="No template available",
                evidence="Skipped",
                severity_adjustment=None,
            )

        cwe_id = self._extract_cwe_id(finding)
        is_logic_bug = cwe_id in LOGIC_CWES
        MAX_RETRIES = 3
        current_error = None
        logic_failure_hint = ""  # Feedback from LLM evaluator for smarter retries

        for attempt in range(1, MAX_RETRIES + 1):
            logger.info(f"  > Verification attempt {attempt} for {finding.id}")

            # Generate PoC — inject previous logic failure hint for smarter retries
            poc_script = self._generate_poc(
                template_name, finding,
                target_url or "http://localhost:8080",
                extra_context=logic_failure_hint
            )

            exit_code, stdout, stderr = await self._run_sandbox(
                poc_script, repo_path=repo_path
            )

            # ────────────────────────────────────────────────────────────────
            # 3-State Decision Logic
            # ────────────────────────────────────────────────────────────────

            # State 1: Hard Fail — script itself crashed or errored
            if exit_code != 0:
                current_error = f"Exit Code: {exit_code}\nStderr: {stderr}\nStdout: {stdout}"
                logger.warning(f"  ❌ Hard Fail (exit {exit_code}): {stderr.strip()[:200]}")
                continue

            # State 2: Binary Bug — exit 0 AND not a logic bug → CONFIRMED directly
            if not is_logic_bug:
                logger.info("  ✅ Vulnerability CONFIRMED! (Binary Bug — Exit Code 0)")
                return VerifiedVuln(
                    finding_id=finding.id,
                    status=ConfirmedStatus.CONFIRMED,
                    poc={"type": "python", "content": poc_script},
                    runtime_output=stdout,
                    evidence=f"PoC Successful. Output: {stdout[:200]}",
                    severity_adjustment=FindingSeverity.CRITICAL,
                )

            # State 3: Logic Bug — exit 0 BUT need LLM to evaluate stdout
            logger.info(f"  🔍 Logic Bug detected (CWE-{cwe_id}). Routing stdout to LLM Evaluator...")
            try:
                verdict_raw = self.llm.evaluate_poc_output(
                    cwe_id=str(cwe_id),
                    description=finding.description,
                    poc_script=poc_script,
                    stdout=stdout,
                    target_data=finding.metadata.get("target_data", "")
                )
                verdict = verdict_raw.strip().upper()[:3]  # Normalize: YES/NO/YES\n/yes./etc.

                if verdict == "YES":
                    logger.info("  ✅ [Evaluator] LLM judged PoC as SUCCESS based on stdout analysis.")
                    return VerifiedVuln(
                        finding_id=finding.id,
                        status=ConfirmedStatus.CONFIRMED,
                        poc={"type": "python", "content": poc_script},
                        runtime_output=stdout,
                        evidence=f"LLM Evaluator confirmed exploit success. Output: {stdout[:300]}",
                        severity_adjustment=FindingSeverity.CRITICAL,
                    )
                else:
                    logger.info("  ❌ [Evaluator] LLM judged PoC as FAILURE based on stdout analysis.")
                    # Provide reasoning context to next-attempt PoC generation
                    logic_failure_hint = (
                        f"Previous attempt FAILED. Stdout showed failure state: '{stdout[:300]}'. "
                        f"The exploit did NOT succeed (LLM verdict: NO). "
                        f"Use a DIFFERENT attack strategy or payload on the next attempt."
                    )
                    current_error = f"LLM Evaluator: exploit did not succeed.\nStdout: {stdout[:300]}"
                    continue

            except Exception as eval_err:
                logger.warning(f"  ⚠️ LLM Evaluator failed ({eval_err}). Treating as INCONCLUSIVE.")
                current_error = f"Evaluator error: {eval_err}"
                continue

        return VerifiedVuln(
            finding_id=finding.id,
            status=ConfirmedStatus.REJECTED,
            poc={"type": "python", "content": poc_script if 'poc_script' in dir() else ""},
            runtime_output=current_error,
            evidence="PoC failed to verify vulnerability after all retries.",
            severity_adjustment=None,
        )

    # -----------------------------------------------------------------
    # Template selection: CWE → trust_boundary → keyword → generic
    # -----------------------------------------------------------------

    def _select_template(self, finding: StaticFinding) -> Optional[str]:
        """Select PoC template using 3-tier fallback: CWE → boundary → keyword."""

        # Tier 1: CWE ID (most precise)
        cwe_id = self._extract_cwe_id(finding)
        if cwe_id and cwe_id in CWE_TEMPLATE_MAP:
            template = CWE_TEMPLATE_MAP[cwe_id]
            logger.debug(f"Template selected via CWE-{cwe_id}: {template}")
            return template

        # Tier 2: Trust boundary
        boundary = finding.metadata.get("trust_boundary", "")
        if boundary in BOUNDARY_TEMPLATE_MAP:
            template = BOUNDARY_TEMPLATE_MAP[boundary]
            logger.debug(f"Template selected via boundary '{boundary}': {template}")
            return template

        # Tier 3: Description keyword matching
        desc = finding.description.lower()
        for keyword, template in _KEYWORD_FALLBACKS:
            if keyword in desc:
                logger.debug(f"Template selected via keyword '{keyword}': {template}")
                return template

        # Ultimate fallback
        return "generic_check.py"

    def _select_mode(self, finding: StaticFinding) -> VerificationMode:
        """
        Determine which engine handles this finding.
        HTTP_NATIVE if CWE is in HTTP_MODE_CWES.
        Otherwise: Docker (safe fallback).
        """
        cwe_id = self._extract_cwe_id(finding)
        if getattr(self, '_http_available', True) and cwe_id in HTTP_MODE_CWES:
            return VerificationMode.HTTP_NATIVE
        return VerificationMode.DOCKER

    def _extract_cwe_id(self, finding: StaticFinding) -> Optional[int]:
        """Safely extract numeric CWE ID from finding."""
        if not finding.cwe_details:
            return None
        raw = finding.cwe_details.get("id")
        if raw is None:
            return None
        if isinstance(raw, int):
            return raw
        if isinstance(raw, str):
            # Handle "CWE-89" or "89" formats
            cleaned = raw.replace("CWE-", "").replace("cwe-", "").strip()
            return int(cleaned) if cleaned.isdigit() else None
        return None

    # -----------------------------------------------------------------
    # PoC generation via LLM
    # -----------------------------------------------------------------

    def _generate_poc(
        self,
        template_name: str,
        finding: StaticFinding,
        target_url: str,
        extra_context: str = "",
    ) -> str:
        """Ask LLM to generate PoC based on template + finding context."""
        template_path = os.path.join(self.templates_dir, template_name)
        if os.path.exists(template_path):
            with open(template_path, "r") as f:
                template_content = f.read()
        else:
            template_content = (
                f"# Generic PoC for {finding.tool_name}\n"
                f"# Target URL: {target_url}\n"
                f"# Location: {finding.location}"
            )

        # Inject logic failure feedback for smart retries
        if extra_context:
            template_content += f"\n\n# PREVIOUS ATTEMPT FEEDBACK:\n# {extra_context}"

        cwe_id = "UNKNOWN"
        if finding.cwe_details:
            cwe_id = finding.cwe_details.get("id", "UNKNOWN")

        # Format and truncate the Taint Trace for LLM context
        formatted_trace = ""
        if finding.taint_trace and isinstance(finding.taint_trace, list):
            trace = finding.taint_trace
            steps = []
            for i, step in enumerate(trace, 1):
                element = step.get('element', 'Unknown')
                loc = step.get('location', 'Unknown')
                steps.append(f"- Step {i}: {element} at {loc}")
            
            if len(steps) > 10:
                formatted_trace = "\n".join(steps[:3] + [f"- ... [{len(steps)-6} steps omitted] ..."] + steps[-3:])
            else:
                formatted_trace = "\n".join(steps)

        return self.llm.generate_poc(
            hypothesis_id=finding.hypothesis_id or "NONE",
            finding_description=finding.description,
            cwe_id=str(cwe_id),
            location=finding.location,
            language=finding.language or "python",
            trust_boundary=finding.metadata.get("trust_boundary", "Unknown"),
            sink=finding.metadata.get("sink", "Unknown"),
            target_function=finding.target_function or "",
            source=finding.metadata.get("source", ""),
            context=template_content.replace("{{TARGET}}", target_url),
            taint_trace=formatted_trace,
        )

    # -----------------------------------------------------------------
    # Sandbox execution
    # -----------------------------------------------------------------

    async def _run_sandbox(
        self,
        script_content: str,
        language: str = "PYTHON",
        repo_path: Optional[str] = None,
    ) -> Tuple[int, str, str]:
        """Execute PoC in Docker sandbox."""
        logger.info(
            f"  [Sandbox] Executing {language} PoC in Docker "
            f"(Repo: {repo_path or 'Primary'})..."
        )

        try:
            if repo_path:
                result = await self.sandbox.run_project_poc(
                    repo_path=repo_path,
                    script=script_content,
                    language=language,
                )
            else:
                lang = language.upper()
                if lang == "PHP":
                    result = await self.sandbox.execute_php(script_content)
                elif lang == "PYTHON":
                    result = await self.sandbox.execute_python(script_content)
                elif lang == "GO":
                    result = await self.sandbox.execute_go(script_content)
                elif lang == "JAVA":
                    result = await self.sandbox.execute_java(script_content)
                else:
                    return -1, "", f"Unsupported language: {language}"

            return result.exit_code, result.stdout, result.stderr

        except Exception as e:
            logger.error(f"Sandbox execution error: {str(e)}")
            return -1, "", f"Sandbox error: {str(e)}"
