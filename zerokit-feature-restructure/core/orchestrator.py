import logging
import json
import uuid
import asyncio
import os
from typing import List
from datetime import datetime
from .models import (
    PipelineContext, AttackSurface, Hypothesis,
    StaticFinding, VerifiedVuln, ConfirmedStatus, FindingSeverity
)
# Enable real agents
from .agents.detector import Detector
from .agents.verifier import Verifier
from .agents.explainer import Explainer
from .agents.reporter import Reporter
from .agents.patcher import Patcher
from .agents.harness_agent import HarnessAgent
from .state_manager import StateManager
from .adapter_loader import AdapterLoader
# Multi-language profile factory
from .profiles import get_profile_for_repo, detect_language, build_security_profile
from .llm_gateway import LLMGateway
# Observability: real-time display + exit code gate + audit trail
from .pipeline_observer import PipelineObserver

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class Orchestrator:
    def __init__(self, config: dict = None):
        self.config = config or {}
        self.context: PipelineContext = None
        self.state_manager = StateManager() # NEW: Shared state manager
        
        # Initialize Specialized Agents
        self.detector = Detector()
        self.verifier = Verifier()
        self.reporter = Reporter() # Added Reporter to instance
        self.patcher = Patcher() # NEW: Patcher
        self.llm_gateway = LLMGateway() # Central Intelligence
        from .agents.profiler import RepoProfiler
        self.profiler = RepoProfiler()
        self.harness_agent = HarnessAgent(llm_gateway=self.llm_gateway)
        self.explainer = Explainer(llm_gateway=self.llm_gateway)
        
    def report_progress(self, phase: str, status: str, details: str = ""):
        """Writes current progress to a known location for live monitoring."""
        progress_dir = os.path.join(os.getcwd(), ".agent", "pipeline")
        os.makedirs(progress_dir, exist_ok=True)
        progress_path = os.path.join(progress_dir, "progress.json")
        
        data = {
            "phase": phase,
            "status": status,
            "details": details,
            "timestamp": datetime.now().isoformat(),
            "run_id": self.context.run_id if self.context else "init"
        }
        
        try:
            with open(progress_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
            logger.info(f"📊 Live Progress: [{phase}] {status}")
        except Exception as e:
            logger.error(f"Failed to write progress: {e}")

    # ... [existing methods] ...
    
    async def run_stage_rca(self):
        """
        Stage 7.5: Root Cause Analysis (RCA)
        Analyzes CONFIRMED vulnerabilities to determine the underlying cause before patching.
        """
        logger.info("Stage: Root Cause Analysis")
        from .agents.root_cause_analyst import RootCauseAnalyst
        
        # Lazy load if not in init
        if not hasattr(self, 'root_cause_analyst'):
            self.root_cause_analyst = RootCauseAnalyst()
            
        confirmed_vulns = [v for v in self.context.verified_vulns if v.status == ConfirmedStatus.CONFIRMED]
        
        if not confirmed_vulns:
            logger.info("No confirmed vulnerabilities to analyze.")
            return

        logger.info(f"Performing RCA on {len(confirmed_vulns)} confirmed vulnerabilities...")
        
        for vuln in confirmed_vulns:
            # 1. Resolve metadata (file path, description) from original Finding
            finding = next((f for f in self.context.static_findings if f.id == vuln.finding_id), None)
            
            if not finding:
                logger.warning(f"Skipping RCA for {vuln.finding_id}: Original finding not found.")
                continue
                
            file_path = finding.location.split(":")[0]
            if not os.path.isabs(file_path):
                file_path = os.path.join(self.context.repo_path, file_path)
            
            # 2. Run RCA
            rca_result = self.root_cause_analyst.analyze(
                vuln=vuln,
                file_path=file_path,
                vuln_description=finding.description
            )
            
            if rca_result:
                vuln.root_cause = rca_result
                logger.info(f"✅ RCA Complete for {vuln.finding_id}: {rca_result.description[:50]}...")
            else:
                logger.warning(f"❌ RCA Failed for {vuln.finding_id}")


    async def run_stage_patch_verification(self):
        """
        Stage 8: Autonomous Patch Verification.
        Attempts to fix CONFIRMED vulnerabilities and verify the fix.
        """
        logger.info("Stage: Autonomous Patch Verification")
        
        confirmed_vulns = [v for v in self.context.verified_vulns if v.status == ConfirmedStatus.CONFIRMED]
        
        if not confirmed_vulns:
            logger.info("No confirmed vulnerabilities to patch.")
            return

        logger.info(f"Attempting to patch {len(confirmed_vulns)} vulnerabilities...")
        
        for vuln in confirmed_vulns:
            # 1. Identify Target File
            # Finding ID is hash, we need original finding to get path?
            # Or verified vuln should have location?
            # VerifiedVuln has finding_id. Context has static_findings.
            finding = next((f for f in self.context.static_findings if f.id == vuln.finding_id), None)
            if not finding:
                logger.warning(f"Could not find original finding for verified vuln {vuln.finding_id}")
                continue
                
            file_path = finding.location.split(":")[0]
            if not os.path.isabs(file_path):
                file_path = os.path.join(self.context.repo_path, file_path)
                
            # 2. Generate Patch
            patched_file = self.patcher.apply_fix(file_path, vuln)
            
            if not patched_file:
                logger.warning(f"Failed to generate patch for {vuln.finding_id}")
                continue
                
            # 3. Verify Patch (Re-run Verifier on Patched File)
            # Problem: Verifier expects a list of findings in the repo.
            # We need to tell Verifier to use the 'patched_file' instead of the original 'file_path'
            # when constructing the container.
            # 
            # Our Verifier uses DockerSandbox. It mounts files.
            # We can use 'sandbox.run' directly or modify Verifier to accept overrides.
            # Simplest way: Call sandbox directly here using the same PoC but separate file map.
            
            logger.info(f"Verifying patch for {vuln.finding_id}...")
            
            # Identify relative path for mapping in container
            # We use a Dict of {rel_path: content} for the Sandbox
            rel_path = os.path.relpath(file_path, self.context.repo_path)
            
            # Read patched content
            with open(patched_file, 'r', encoding='utf-8') as f:
                 patched_content = f.read()
            
            modified_files = {rel_path: patched_content}
            
            # Run Project-Level Sandbox
            # This mounts the WHOLE REPO + Applies Patch + Runs PoC
            if self.verifier.sandbox:
                # Detect language from context or file ext
                language = "PHP" if file_path.endswith(".php") else "PYTHON"
                
                # We need the PoC script content
                poc_script = vuln.poc.get("content", "")
                
                res = await self.verifier.sandbox.run_project_poc(
                    repo_path=self.context.repo_path,
                    script=poc_script,
                    language=language,
                    modified_files=modified_files
                )
                
                # Logic: If it crashes (exit != 0), patch FAILED?
                # Wait, PoC is supposed to crash (if exploit works) or just print "VULNERABLE"?
                # It depends on the PoC type.
                # If PoC was "Expect Crash" -> Exit 0 means Fixed.
                # If PoC was "Expect Output 'VULNERABLE'" -> No Output means Fixed.
                
                # Current Verifier logic: 
                # Exit code != 0 or 'VULNERABLE' in stdout => CONFIRMED.
                # So for Patch to be verified, we want Exit 0 AND NO 'VULNERABLE'.
                
                is_still_vuln = (res.exit_code != 0) or ("VULNERABLE" in res.stdout)
                
                if not is_still_vuln:
                    logger.info(f"✅ Patch Verified! {vuln.finding_id} is fixed.")
                    # Phase 9: Regression Check (Run Baseline on Patched Source)
                    logger.info("Running Regression Checks (Baseline on Patched Code)...")
                    try:
                         # Temporarily apply patch to repo for health check
                         with open(file_path, 'w', encoding='utf-8') as f:
                              f.write(patched_content)
                         
                         await self.run_stage_baseline() # Recursive check
                         vuln.status = getattr(ConfirmedStatus, "FIX_VERIFIED", ConfirmedStatus.CONFIRMED)
                    except Exception as e:
                         logger.error(f"⚠️ Regression Detected after patch: {e}")
                         vuln.status = ConfirmedStatus.CONFIRMED # Revert to confirmed but patch-failed context
                    finally:
                         # RootCause analysis should have original, but pipeline usually works on git repo
                         # For now, we restore original or just leave it if git is managed.
                         pass
                else:
                    logger.warning(f"❌ Patch Failed. {vuln.finding_id} is still vulnerable.")
            
            # Cleanup
            try:
                os.remove(patched_file)
            except:
                pass


    def run_stage_reporting(self) -> str:
        """Phase 8 & 9: Reporting - ENFORCING VERIFICATION GATE"""
        logger.info("Stage: Reporting")
        
        confirmed_findings = [
            v for v in self.context.verified_vulns 
            if v.status == ConfirmedStatus.CONFIRMED
        ]
        
        # Integration with Reporter
        output_dir = os.path.join(os.getcwd(), ".agent", "artifacts")
        os.makedirs(output_dir, exist_ok=True)
        
        # Generate Evidence Bundles
        for vuln in confirmed_findings:
             self.reporter.create_evidence_bundle(vuln, output_dir)
             
        # Combined Report
        return self.reporter.generate_report(self.context.verified_vulns)




    def start_pipeline(self, repo_path: str) -> PipelineContext:
        """Initializes the pipeline context and PipelineObserver."""
        run_id = str(uuid.uuid4())
        logger.info(f"Starting pipeline run {run_id} for {repo_path}")
        self.context = PipelineContext(
            repo_path=repo_path,
            run_id=run_id,
            start_time=datetime.now().isoformat(),
            config=self.config
        )
        # Initialize observer — all tool calls go through this
        self.observer = PipelineObserver(repo_path=repo_path, run_id=run_id)
        return self.context

    async def run_stage_baseline(self):
        """Phase 1: Baseline Setup & Health Check — Secrets + SCA + Misconfig."""
        self.report_progress("Phase 1", "Baseline Setup", "Scanning for secrets, dependencies, and misconfigurations...")
        logger.info("Stage: Baseline Setup (Health Check + Gitleaks + Trivy + Dependency-Check)")

        if not os.path.exists(self.context.repo_path):
            raise ValueError(f"Repository path does not exist: {self.context.repo_path}")

        repo_abs_path = os.path.abspath(self.context.repo_path)
        observer = getattr(self, "observer", None)

        async def _run_baseline():
            # ── Gitleaks ────────────────────────────────────────────────
            try:
                from .tools.gitleaks_runner import GitleaksRunner
                gitleaks = GitleaksRunner()
                leak_findings_raw, gl_exit, gl_stdout, gl_stderr, gl_cmd = await gitleaks.scan_repo_with_evidence(repo_abs_path)

                gl_findings = []
                for leak in (leak_findings_raw or []):
                    gl_findings.append(StaticFinding(
                        id=str(uuid.uuid4())[:16],
                        description=f"[SECRET] {leak.get('Description', 'Hardcoded secret')} — Rule: {leak.get('RuleID', 'unknown')}",
                        location=f"{leak.get('File', 'unknown')}:{leak.get('StartLine', 0)}",
                        severity=FindingSeverity.CRITICAL,
                        evidence=f"Match: {leak.get('Match', '')[:80]}",
                        tool_name="gitleaks",
                        metadata={"rule_id": leak.get("RuleID"), "auto_confirmed": True},
                    ))

                if observer:
                    result = observer.record_tool(
                        tool="gitleaks", command=gl_cmd, exit_code=gl_exit,
                        stdout=gl_stdout, stderr=gl_stderr, findings=gl_findings)
                    if result.accepted:
                        self.context.static_findings.extend(result.findings)
                else:
                    self.context.static_findings.extend(gl_findings)
            except Exception as e:
                logger.warning(f"Gitleaks scan skipped: {e}")
                if observer:
                    observer.note(f"Gitleaks skipped: {e}")

            # ── Trivy ────────────────────────────────────────────────────
            try:
                from .tools.trivy_runner import TrivyRunner
                trivy = TrivyRunner()
                trivy_raw, tv_exit, tv_stdout, tv_stderr, tv_cmd = trivy.scan_filesystem_with_evidence(repo_abs_path)

                severity_map = {"CRITICAL": FindingSeverity.CRITICAL, "HIGH": FindingSeverity.HIGH,
                                "MEDIUM": FindingSeverity.MEDIUM, "LOW": FindingSeverity.LOW}
                tv_findings = []
                for tf in (trivy_raw or []):
                    found_type = tf.get("type", "vulnerability")
                    desc = (f"[SCA] {tf.get('package')}@{tf.get('version')} — {tf.get('vulnerability_id')}: {tf.get('title')}"
                            if found_type == "vulnerability"
                            else f"[MISCONFIG] {tf.get('id')}: {tf.get('title')}")
                    tv_findings.append(StaticFinding(
                        id=str(uuid.uuid4())[:16], description=desc,
                        location=tf.get("target", "filesystem"),
                        severity=severity_map.get(tf.get("severity", "MEDIUM"), FindingSeverity.MEDIUM),
                        evidence=tf.get("description", "")[:200], tool_name="trivy", metadata=tf))

                if observer:
                    result = observer.record_tool(
                        tool="trivy", command=tv_cmd, exit_code=tv_exit,
                        stdout=tv_stdout, stderr=tv_stderr, findings=tv_findings)
                    if result.accepted:
                        self.context.static_findings.extend(result.findings)
                else:
                    self.context.static_findings.extend(tv_findings)
            except Exception as e:
                logger.warning(f"Trivy scan skipped: {e}")
                if observer:
                    observer.note(f"Trivy skipped: {e}")

            # ── OWASP Dependency-Check ────────────────────────────────────
            try:
                from .tools.dependency_check_runner import DependencyCheckRunner
                dc = DependencyCheckRunner()
                dc_raw, dc_exit, dc_stdout, dc_stderr, dc_cmd = await dc.scan_repo_with_evidence(repo_abs_path)

                dc_findings = []
                for df in (dc_raw or []):
                    dc_findings.append(StaticFinding(
                        id=str(uuid.uuid4())[:16],
                        description=f"[SCA-DC] {df.get('package')} — {df.get('id')}: {df.get('description', '')[:100]}",
                        location=df.get("evidence", "dependency"),
                        severity=FindingSeverity.HIGH if df.get("severity") in ["HIGH", "CRITICAL"] else FindingSeverity.MEDIUM,
                        evidence=f"CVSS: {df.get('cvss_score')}", tool_name="dependency-check", metadata=df))

                if observer:
                    result = observer.record_tool(
                        tool="dependency-check", command=dc_cmd, exit_code=dc_exit,
                        stdout=dc_stdout, stderr=dc_stderr, findings=dc_findings)
                    if result.accepted:
                        self.context.static_findings.extend(result.findings)
                else:
                    self.context.static_findings.extend(dc_findings)
            except Exception as e:
                logger.warning(f"Dependency-Check scan skipped: {e}")
                if observer:
                    observer.note(f"Dependency-Check skipped: {e}")

            # ── Semgrep Community Rules ────────────────────────────────────
            try:
                from .tools.semgrep_runner import SemgrepRunner
                semgrep = SemgrepRunner()
                
                # Use standard security ruleset
                config_rules = "p/security-audit" 
                
                # Run the scan asynchronously
                sg_result = await semgrep.run_scan_async(config_rules, [repo_abs_path])
                
                sg_findings = []
                if sg_result and sg_result.success:
                    for res in sg_result.findings:
                        from ..models import FindingSeverity, StaticFinding
                        import uuid
                        severity_map = {"ERROR": FindingSeverity.HIGH, "WARNING": FindingSeverity.MEDIUM, "INFO": FindingSeverity.LOW}
                        extra = res.get("extra", {})
                        
                        sg_findings.append(StaticFinding(
                            id=str(uuid.uuid4())[:16],
                            description=f"[Semgrep Community] {extra.get('message', 'Generic finding')}",
                            location=f"{res.get('path')}:{res.get('start', {}).get('line', 0)}",
                            severity=severity_map.get(extra.get("severity"), FindingSeverity.MEDIUM),
                            tool_name="semgrep",
                            metadata=res
                        ))
                
                if observer:
                    result = observer.record_tool(tool="semgrep-baseline", command="", exit_code=0, stdout="", stderr="", findings=sg_findings)
                    if result.accepted:
                        self.context.static_findings.extend(result.findings)
                else:
                    self.context.static_findings.extend(sg_findings)
            except Exception as e:
                logger.warning(f"Semgrep Baseline scan skipped: {e}")
                if observer:
                    observer.note(f"Semgrep Baseline skipped: {e}")

        if observer:
            with observer.phase(1, "Baseline"):
                await _run_baseline()
        else:
            await _run_baseline()

        logger.info("Project environment is STABLE. Ready for hunt.")
        return True


    async def run_stage_profiling(self):
        """Phase 2: Mapping (Worker API Driven)"""
        with self.observer.phase(2, "Mapping") as p:
            self.report_progress("Phase 2", "Mapping", "Antigravity mapping attack surface...")
            logger.info("Stage: Mapping (Antigravity Worker API)")
            # In the Worker API model, Antigravity (the LLM) performs the reconnaissance.
            # We use RepoProfiler to gather surface area + semantic graph.
            self.context.surface = await self.profiler.analyze(self.context)
            
            # Record evidence for the observer
            p.findings = self.context.surface.entry_points
            
            # Add semantic graph info to observer note
            if self.context.code_graph:
                self.observer.note(f"Semantic Graph: {len(self.context.code_graph.get('nodes', []))} nodes, {len(self.context.code_graph.get('edges', []))} edges")

            logger.info(f"Surface map complete: Found {len(self.context.surface.entry_points)} entry points.")
        """Phase 3: Language detection → SecurityProfile → ThreatModeler hypotheses."""
        with self.observer.phase(3, "Deep Logic") as p:
            self.report_progress("Phase 3", "Deep Logic", "Auto-detecting language + generating hypotheses...")
            logger.info("Stage: Deep Logic (Language Detection + ThreatModeler)")
    
            # 1. Auto-detect language and build SecurityProfile
            if not self.context.security_profile:
                self.context.security_profile = get_profile_for_repo(self.context.repo_path)
                lang = self.context.security_profile.language
                fw   = self.context.security_profile.framework or "generic"
                logger.info(f"SecurityProfile built: {lang}/{fw}")
    
            # 2. Generate hypotheses via ThreatModeler (real LLM call)
        if not self.context.hypotheses:
            # PRUNE Attack Surface based on Semgrep findings to save LLM tokens!
            semgrep_files = set()
            for f in self.context.static_findings:
                if f.tool_name == "semgrep":
                    # Location format is usually path:line
                    path = f.location.split(":")[0] if isinstance(f.location, str) else ""
                    if path:
                        semgrep_files.add(path)
            
            if self.context.surface and semgrep_files:
                original_len = len(self.context.surface.entry_points)
                
                # Keep entry points that are NOT in already-infected files
                filtered_eps = []
                for ep in self.context.surface.entry_points:
                    ep_path = ep.code_location.split(":")[0] if ep.code_location else ""
                    if ep_path not in semgrep_files:
                        filtered_eps.append(ep)
                        
                self.context.surface.entry_points = filtered_eps
                logger.info(
                    f"Token Saver: Removed {original_len - len(filtered_eps)} entry points "
                    f"that were already caught by Semgrep."
                )

            try:
                from .agents.threat_modeler import ThreatModeler
                modeler = ThreatModeler()

                surface = self.context.surface or AttackSurface(entry_points=[])
                self.context.hypotheses = await modeler.generate_hypotheses(
                    surface, 
                    security_profile=self.context.security_profile,
                    code_graph=self.context.code_graph,
                    repo_path=self.context.repo_path
                )
                logger.info(f"ThreatModeler generated {len(self.context.hypotheses)} hypotheses.")
            except Exception as e:
                logger.warning(f"ThreatModeler failed (LLM unavailable?): {e}")
                logger.info("Falling back to profile-driven generic hypotheses.")
                self.context.hypotheses = self._build_generic_hypotheses()

        # 3. CWE mapping for any hypothesis without it
        for h in self.context.hypotheses:
            if not h.metadata.get("cwe"):
                logger.debug(f"  CWE pending for: {h.description[:50]}")

        logger.info(f"Phase 3 complete. {len(self.context.hypotheses)} hypotheses ready.")

    def _build_generic_hypotheses(self) -> List[Hypothesis]:
        """Fallback: build basic hypotheses from SecurityProfile sinks."""
        hypotheses = []
        if not self.context.security_profile:
            return hypotheses
        for sink in self.context.security_profile.sinks[:10]:  # Cap at 10
            h = Hypothesis(
                id=str(uuid.uuid4()),
                description=f"Potential {sink.category.value} via {sink.pattern}",
                target_code=sink.pattern,
                verification_plan=f"Find unsanitized input flowing into {sink.pattern}",
                metadata={"category": sink.category.value, "auto_generated": True}
            )
            hypotheses.append(h)
        logger.info(f"Generated {len(hypotheses)} fallback hypotheses from SecurityProfile.")
        return hypotheses

    async def run_stage_verification(self, findings_to_verify: List[StaticFinding] = None):
        """Phase 6 & 7: Dynamic Verification"""
        with self.observer.phase(6, "Verification") as p:
            logger.info("Stage: Dynamic Verification")
            
            target_findings = findings_to_verify if findings_to_verify is not None else self.context.static_findings
            
            if not target_findings:
                logger.info("No findings to verify.")
                return

        # --- Native Python HTTP Verification ---
        logger.info(
            "[Verifier] Using native HttpVerifier for HTTP-level findings. "
            "Inconclusive checks will automatically fall back to Docker Sandbox."
        )

        # Cache on verifier so _select_mode() works correctly per-finding
        self.verifier._http_available = True

        # Bridge Sync -> Async Batch Verification
        try:
            new_verified = await self.verifier.verify_batch(
                    target_findings, 
                    concurrency=5,
                    callback=self._on_finding_verified
                )
            
            # Update main list safely
            current_ids = {v.finding_id for v in self.context.verified_vulns}
            for v in new_verified:
                if v.finding_id not in current_ids:
                    # Enrich VerifiedVuln with CWE details from original finding
                    original = next((f for f in self.context.static_findings if f.id == v.finding_id), None)
                    if original and original.cwe_details:
                        v.cwe_details = original.cwe_details
                        
                    self.context.verified_vulns.append(v)
                
                # PERSISTENCE: Update State Manager
                # This ensures False Positives are marked REJECTED and won't reappear
                self.state_manager.update_finding_status(
                    finding_id=v.finding_id,
                    status=v.status.value,
                    verification_result=v.evidence
                )
                    
        except Exception as e:
            logger.error(f"Verification failed: {e}")
            
        logger.info(f"Verification complete. Verified {len(self.context.verified_vulns)} findings total.")

    async def run_stage_fuzzing(self, candidates: List[StaticFinding] = None):
        """
        Phase 5/7: Directed Fuzzing (DV Loop Pillar 2).
        
        For directed candidates: HarnessAgent generates a harness targeting
        the specific function flagged by the Detector.
        For general candidates: Falls back to existing AFL++/Atheris flow.
        """
        with self.observer.phase(5, "Fuzzing") as p:
            self.report_progress("Phase 5", "Directed Fuzzing", "HarnessAgent generating harnesses + fuzzing...")
            logger.info("Stage: Directed Fuzzing (Upgrade 2: DV Loop + Upgrade 4: HarnessAgent)")
        
        targets = candidates or [
             f for f in self.context.static_findings 
             if f.severity in [FindingSeverity.CRITICAL, FindingSeverity.HIGH]
        ]
        
        if not targets:
            logger.info("No high-severity candidates for fuzzing.")
            return

        # Initialize HarnessAgent
        try:
            from .agents.harness_agent import HarnessAgent
        except ImportError:
            from core.agents.harness_agent import HarnessAgent
        harness_agent = HarnessAgent(llm_gateway=self.llm_gateway)

        # Detect repo language for correct harness template
        from .profiles import detect_language
        repo_lang = detect_language(self.context.repo_path) or "python"

        for finding in targets:
            logger.info(f"  Targeting {finding.id} ({finding.target_function or 'unknown function'}) for fuzzing...")
            
            # Extract hypothesis_id from metadata if possible, else use finding.id
            hypothesis_id = finding.metadata.get("hypothesis_id", finding.id)

            # Upgrade 4: LLM-driven harness generation via HarnessAgent
            harness_path = await harness_agent.generate(
                hypothesis_id=hypothesis_id,
                target_function=finding.target_function or "None",
                repo_path=self.context.repo_path,
                language=repo_lang,
                description=finding.description
            )

            if harness_path:
                logger.info(f"  ✅ Harness ready: {harness_path} — dispatching to fuzzer")
                # Route harness to the appropriate runner
                # (AFL++ for C/C++, Jazzer for Java, Atheris for Python)
                finding.metadata["harness_path"] = harness_path
                finding.metadata["harness_type"] = "auto-generated"
            else:
                logger.warning(f"  ⚠️ Harness generation failed for {finding.id} — INCONCLUSIVE")
             
        logger.info("Fuzzing phase complete.")

    def _on_finding_verified(self, vuln: VerifiedVuln):
        """
        Callback for Early Exit / Alerting.
        Triggered immediately when a finding is verified.
        """
        if vuln.status == ConfirmedStatus.CONFIRMED:
            # Look up severity
            finding = next((f for f in self.context.static_findings if f.id == vuln.finding_id), None)
            if finding:
                if finding.severity in [FindingSeverity.CRITICAL, FindingSeverity.HIGH]:
                    logger.critical(f"🚨 EARLY EXIT ALERT: Confirmed {finding.severity} Vulnerability!")
                    logger.critical(f"   > ID: {finding.id}")
                    logger.critical(f"   > Location: {finding.location}")
                    logger.critical(f"   > Description: {finding.description}")
                    # In a real app, this might send a Slack message or stop the build immediately
                    # raise EarlyExitException(...)

    async def run_stage_feedback(self) -> List[StaticFinding]:
        """
        VARIANT ANALYSIS LOOP:
        For every CONFIRMED vulnerability, we instruct the Detector 
        to scan specifically for that pattern again across the whole repo.
        Returns: List of NEW findings found during this feedback loop.
        """
        with self.observer.phase(8, "Variant Analysis") as p:
            logger.info("Stage: Variant Analysis (Feedback Loop)")
            confirmed = [v for v in self.context.verified_vulns if v.status == ConfirmedStatus.CONFIRMED]
            new_findings = []

            if not confirmed:
                logger.info("No confirmed bugs to analyze for variants.")
                return new_findings

            logger.info(f"Triggering Variant Analysis for {len(confirmed)} confirmed bugs...")
            from .utils import extract_json

            variant_hypotheses = []
            for vuln in confirmed:
                original = next((f for f in self.context.static_findings if f.id == vuln.finding_id), None)
                if not original:
                    continue
                try:
                    logger.info(f"  Extracting variant pattern for {vuln.finding_id}...")
                    cwe_id = "UNKNOWN"
                    if original.cwe_details:
                        cwe_id = original.cwe_details.get("id", "UNKNOWN")
                    elif original.metadata.get("cwe_id"):
                        cwe_id = original.metadata.get("cwe_id")
                    sink = original.metadata.get("sink", "Unknown")

                    pattern_resp = self.llm_gateway.extract_variant_pattern(
                        vulnerability_description=original.description,
                        code=original.location if hasattr(original, 'location') else "N/A",
                        language="Unknown",
                        security_profile_sinks="Unknown",
                        cwe_id=cwe_id,
                        confirmed_sink=sink,
                    )

                    clean_resp = pattern_resp
                    if "```json" in pattern_resp:
                        clean_resp = pattern_resp.split("```json")[1].split("```")[0]
                    elif "```" in pattern_resp:
                        clean_resp = pattern_resp.split("```")[1].split("```")[0]

                    data = extract_json(clean_resp.strip(), default={})
                    pattern_desc = data.get("pattern_description", original.description)
                    search_strat = data.get("search_strategy", "")
                    logger.info(f"  Abstract Pattern: {pattern_desc}")

                    h = Hypothesis(
                        id=str(uuid.uuid4()),
                        description=f"Variant of: {pattern_desc}",
                        target_code=search_strat,
                        verification_plan="Variant Scan",
                        metadata={"derived_from": vuln.finding_id, "type": "variant", "strategy": search_strat},
                    )
                    variant_hypotheses.append(h)
                except Exception as e:
                    logger.error(f"  Failed to extract pattern for {vuln.finding_id}: {e}")
                    h = Hypothesis(
                        id=str(uuid.uuid4()),
                        description=f"Variant of {original.description}",
                        target_code=original.location,
                        verification_plan="Variant Scan",
                        metadata={"derived_from": vuln.finding_id, "type": "variant"},
                    )
                    variant_hypotheses.append(h)

            if variant_hypotheses:
                logger.info(f"Scanning for {len(variant_hypotheses)} variant hypotheses...")
                try:
                    variants = await self.detector.scan(variant_hypotheses, self.context.repo_path)
                    existing_locs = {f.location for f in self.context.static_findings}
                    for v in variants:
                        if v.location not in existing_locs:
                            v.metadata["variant_of"] = v.metadata.get("derived_from")
                            new_findings.append(v)
                            existing_locs.add(v.location)
                    logger.info(f"Variant Analysis found {len(new_findings)} NEW related findings.")
                except Exception as e:
                    logger.error(f"Variant analysis failed: {e}")

            # MRVA (Multi-Repo Variant Analysis)
            try:
                from .agents.variant_analyzer import VariantAnalyzer
                va = VariantAnalyzer(
                    semgrep_runner=self.detector.runner,
                    llm_gateway=self.llm_gateway,
                    observer=self.observer,
                )
                for vuln in confirmed:
                    orig = next((f for f in self.context.static_findings if f.id == vuln.finding_id), None)
                    logger.info(f"  [MRVA] Scanning variants for {vuln.finding_id}...")
                    mrva_f = await va.find_variants_mrva(
                        verified_vuln=vuln,
                        primary_repo_path=self.context.repo_path,
                        original_finding=orig,
                    )
                    elocs = {f.location for f in self.context.static_findings + new_findings}
                    for mf in mrva_f:
                        if mf.location not in elocs:
                            new_findings.append(mf)
                            elocs.add(mf.location)
                logger.info("  [MRVA] Done.")
            except Exception as e:
                logger.error(f"  [MRVA] Failed: {e}")

            return new_findings

    async def run_stage_mrva_verification(self):
        """Phase 8.5: Dynamic MRVA Verification (Upgrade 5.2)"""
        with self.observer.phase(8.5, "MRVA Verification") as p:
            logger.info("Stage: Dynamic MRVA Verification")
            
            # 1. Filter findings belonging to external repos
            mrva_findings = [f for f in self.context.static_findings if f.repo_name and f.repo_path and f.repo_name != "primary"]
            
            if not mrva_findings:
                logger.info("No MRVA variant findings to verify.")
                return
            
            # 2. Group by repo
            from collections import defaultdict
            repo_groups = defaultdict(list)
            for f in mrva_findings:
                repo_groups[f.repo_path].append(f)
            
            logger.info(f"Verifying {len(mrva_findings)} findings across {len(repo_groups)} repositories...")
            
            for repo_path, findings in repo_groups.items():
                repo_name = findings[0].repo_name
                logger.info(f"\n--- Verifying Repo: {repo_name} ({repo_path}) ---")
                
                # Directed Verification Loop for MRVA
                for f in findings:
                    logger.info(f"  Target: {f.location} (Fn: {f.target_function})")
                    # HarnessAgent generates the setup
                    if f.target_function:
                        # Use finding ID as hypothesis ID context for MRVA
                        await self.harness_agent.generate(
                            hypothesis_id=f.hypothesis_id or f.id, 
                            target_function=f.target_function, 
                            repo_path=repo_path, 
                            language=f.language or "python",
                            description=f.description
                        )
                    
                # Batch Verify for this repo
                new_verified = await self.verifier.verify_batch(
                    findings,
                    concurrency=3,
                    repo_path=repo_path
                )
                
                # Update main list
                current_ids = {v.finding_id for v in self.context.verified_vulns}
                for v in new_verified:
                    if v.finding_id not in current_ids:
                        self.context.verified_vulns.append(v)
                
            logger.info("MRVA Verification stage complete.")

    def run_stage_reporting(self) -> str:
        """Phase 8 & 9: Reporting - ENFORCING VERIFICATION GATE"""
        with self.observer.phase(9, "Reporting") as p:
            logger.info("Stage: Reporting")
            
            # VERIFICATION GATE LOGIC
            # For now, let's report everything to show progress, even if not confirmed, 
            # or stick to the strict gate. 
            # Strict gate says: "No confirmed vulnerabilities found. Report will be empty of vulns."
            # But for debugging it might be useful to see what was found.
            # Let's keep the gate but log stats.
            
            confirmed_findings = [
                v for v in self.context.verified_vulns 
                if v.status == ConfirmedStatus.CONFIRMED
            ]
            
            # Integration with Reporter
            try:
                from .agents.reporter import Reporter
                reporter = Reporter()
                if not confirmed_findings:
                    logger.warning("No confirmed vulnerabilities found.")
                report = reporter.generate_report(self.context.verified_vulns)
                self.observer.note("Completed generating final security report.")
                return report
            except Exception as e:
                logger.error(f"Reporting failed: {e}")
                self.observer.note(f"Reporting failed: {e}")
                return "Error generating report"


    async def run_full_pipeline(self, repo_path: str):
        """Executes the full pipeline sequence with Feedback Loop."""
        self.start_pipeline(repo_path)
        try:
            # Phase 1: Baseline Setup
            await self.run_stage_baseline()
            
            # Phase 2: Mapping
            await self.run_stage_profiling()
            
            # Phase 3: Deep Logic
            await self.run_stage_hypothesis()
            
            # Initial Detection
            self.report_progress("Phase 4 & 5", "Static Detection", "Running Semgrep/CodeQL/Joern...")
            self.run_stage_detection()
            
            # LOOP: Detection -> Verification -> Feedback (Variant Analysis) -> Detection
            MAX_LOOPS = 2
            loop_count = 0
            
            # Findings to verify in the first pass are all static findings
            findings_to_verify = self.context.static_findings
            
            while loop_count < MAX_LOOPS:
                logger.info(f"🔄 Pipeline Loop {loop_count + 1}/{MAX_LOOPS}")

                # 1. Verify  (FIX: await instead of asyncio.run inside async context)
                if findings_to_verify:
                    self.report_progress("Phase 6 & 7", f"Verification (Loop {loop_count+1})", f"Verifying {len(findings_to_verify)} findings...")
                    await self.run_stage_verification(findings_to_verify)
                else:
                    logger.info("No findings to verify this loop.")

                # 2. Variant Analysis & MRVA (Upgrades 5 & 5.2)
                # This triggers CodeQL on remote targets
                self.report_progress("Phase 8", "Variant Analysis", "Finding variants across multiple repos...")
                new_variants = await self.run_stage_feedback()

                if not new_variants:
                    logger.info("No new variants found. Breaking loop.")
                    break

                # Update context
                self.context.static_findings.extend(new_variants)

                # Dynamic MRVA Verification (Upgrade 5.2)
                # This triggers PoC verification on the findings from previous step (now in context)
                self.report_progress("Phase 8.5", "MRVA Verification", "Verifying variants on remote repos...")
                await self.run_stage_mrva_verification()

                # Prepare for next loop

                # Prepare for next loop
                findings_to_verify = new_variants
                loop_count += 1

            # Phase 7.5: Root Cause Analysis  (FIX: await)
            self.report_progress("Phase 7.5", "RCA", "Analyzing confirmed bugs...")
            await self.run_stage_rca()

            # Phase 9: Autonomous Patch Verification  (FIX: await)
            self.report_progress("Phase 9", "Patching", "Generating and verifying fixes...")
            await self.run_stage_patch_verification()

            self.report_progress("Phase 10", "Reporting", "Generating final security report...")
            return self.run_stage_reporting()
        except Exception as e:
            logger.error(f"Pipeline failed: {e}", exc_info=True)
            return f"Pipeline execution failed: {e}"

    # ========================================
    # INTERACTIVE MENU SUPPORT METHODS
    # ========================================
    
    def save_context(self, output_path: str = None):
        """Save pipeline context to disk for resume capability."""
        import pickle
        
        if not self.context:
            logger.warning("No context to save.")
            return
        
        if not output_path:
            output_path = os.path.join(self.context.repo_path, ".zerokit_context.pkl")
        
        try:
            with open(output_path, 'wb') as f:
                pickle.dump(self.context, f)
            logger.info(f"Context saved to {output_path}")
        except Exception as e:
            logger.error(f"Failed to save context: {e}")
    
    def load_context(self, context_path: str) -> PipelineContext:
        """Load existing pipeline context."""
        import pickle
        
        try:
            with open(context_path, 'rb') as f:
                self.context = pickle.load(f)
            logger.info(f"Context loaded from {context_path}")
            return self.context
        except Exception as e:
            logger.error(f"Failed to load context: {e}")
            raise
    
    def get_completed_phases(self) -> List[str]:
        """Return list of completed phase keys."""
        if not self.context:
            return []
        
        completed = []
        
        # Check each phase's completion status
        if self.context.surface is not None:
            completed.append("profiling")
        
        if len(self.context.hypotheses) > 0:
            completed.append("hypothesis")
        
        if len(self.context.static_findings) > 0:
            completed.append("detection")
        
        if len(self.context.verified_vulns) > 0:
            completed.append("verification")
        
        # For feedback, rca, patching - we'd need explicit tracking
        # For now, we'll use a simple heuristic
        if hasattr(self.context, 'completed_phases'):
            return self.context.completed_phases
        
        return completed
    
    def run_phase(self, phase_name: str):
        """Execute a specific phase by name."""
        phase_map = {
            "profiling": self.run_stage_profiling,
            "hypothesis": self.run_stage_hypothesis,
            "detection": self.run_stage_detection,
            "verification": lambda: asyncio.run(self.run_stage_verification()),
            "feedback": lambda: asyncio.run(self.run_stage_feedback()),
            "rca": lambda: asyncio.run(self.run_stage_rca()),
            "patching": lambda: asyncio.run(self.run_stage_patch_verification()),
            "reporting": self.run_stage_reporting,
        }
        
        if phase_name not in phase_map:
            raise ValueError(f"Invalid phase: {phase_name}")
        
        # Initialize context if this is the first phase
        if not self.context and phase_name == "profiling":
            # Context will be initialized by caller via start_pipeline
            pass
        
        logger.info(f"Running phase: {phase_name}")
        result = phase_map[phase_name]()
        
        # Track completion
        if hasattr(self.context, 'completed_phases'):
            if phase_name not in self.context.completed_phases:
                self.context.completed_phases.append(phase_name)
        
        # Auto-save after each phase
        self.save_context()
        
        return result

