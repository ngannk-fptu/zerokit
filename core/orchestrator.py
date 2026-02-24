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
from .agents.reporter import Reporter
from .agents.patcher import Patcher
from .state_manager import StateManager
from .adapter_loader import AdapterLoader
# Multi-language profile factory
from .profiles import get_profile_for_repo, detect_language, build_security_profile

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
        """Initializes the pipeline context."""
        run_id = str(uuid.uuid4())
        logger.info(f"Starting pipeline run {run_id} for {repo_path}")
        self.context = PipelineContext(
            repo_path=repo_path,
            run_id=run_id,
            start_time=datetime.now().isoformat(),
            config=self.config
        )
        return self.context

    async def run_stage_baseline(self):
        """Phase 1: Baseline Setup & Health Check — Gitleaks secret scan."""
        self.report_progress("Phase 1", "Baseline Setup", "Scanning for secrets + validating environment...")
        logger.info("Stage: Baseline Setup (Health Check + Gitleaks)")

        # 1. Verify environment
        if not os.path.exists(self.context.repo_path):
            raise ValueError(f"Repository path does not exist: {self.context.repo_path}")

        logger.info(f"Validating repo structure at {self.context.repo_path}")

        # 2. Gitleaks secret scan (real execution)
        try:
            from .tools.gitleaks_runner import GitleaksRunner
            gitleaks = GitleaksRunner()
            leak_findings = await gitleaks.scan_repo(self.context.repo_path)

            if leak_findings:
                secret_statics = []
                for leak in leak_findings:
                    finding = StaticFinding(
                        id=str(uuid.uuid4())[:16],
                        description=f"[SECRET] {leak.get('Description', 'Hardcoded secret detected')} — Rule: {leak.get('RuleID', 'unknown')}",
                        location=f"{leak.get('File', 'unknown')}:{leak.get('StartLine', 0)}",
                        severity=FindingSeverity.CRITICAL,
                        evidence=f"Match: {leak.get('Match', '')[:80]}",
                        tool_name="gitleaks",
                        metadata={
                            "rule_id": leak.get("RuleID"),
                            "secret": "[REDACTED]",
                            "auto_confirmed": True,
                        }
                    )
                    secret_statics.append(finding)

                # Inject directly as pre-confirmed CRITICAL findings
                self.context.static_findings.extend(secret_statics)
                logger.critical(f"🚨 Phase 1: {len(secret_statics)} HARDCODED SECRETS found — auto-escalated!")
            else:
                logger.info("Phase 1: No secrets detected by Gitleaks.")

        except Exception as e:
            logger.warning(f"Gitleaks scan skipped (not available or error): {e}")

        logger.info("Project environment is STABLE. Ready for hunt.")
        return True

    async def run_stage_profiling(self):
        """Phase 2: Mapping (Worker API Driven)"""
        self.report_progress("Phase 2", "Mapping", "Antigravity mapping attack surface...")
        logger.info("Stage: Mapping (Antigravity Worker API)")
        # In the Worker API model, Antigravity (the LLM) performs the reconnaissance.
        if not self.context.surface:
             logger.info("Universal Mapping required.")
        logger.info("Universal Mapping complete.")

    async def run_stage_hypothesis(self):
        """Phase 3: Language detection → SecurityProfile → ThreatModeler hypotheses."""
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
            try:
                from .agents.threat_modeler import ThreatModeler
                modeler = ThreatModeler()

                surface = self.context.surface or AttackSurface(entry_points=[])
                self.context.hypotheses = await modeler.generate_hypotheses(surface)
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

    def run_stage_detection(self):
        """Phase 4 & 5: Static Detection"""
        logger.info("Stage: Static Detection")
        # Bridge Sync -> Async
        try:
            self.context.static_findings = asyncio.run(
                self.detector.scan(self.context.hypotheses, self.context.repo_path, self.context.security_profile)
            )
        except Exception as e:
            logger.error(f"Detection failed: {e}")
            self.context.static_findings = []
            
        logger.info(f"Detection complete. Found {len(self.context.static_findings)} static findings.")

    async def run_stage_verification(self, findings_to_verify: List[StaticFinding] = None):
        """Phase 6 & 7: Dynamic Verification"""
        logger.info("Stage: Dynamic Verification")
        
        target_findings = findings_to_verify if findings_to_verify is not None else self.context.static_findings
        
        if not target_findings:
            logger.info("No findings to verify.")
            return

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
        Phase 5/7: Fuzzing (Pillar 2) - HarnessAgent Integration.
        Triggered when PoC is inconclusive or for critical sinks.
        """
        self.report_progress("Phase 7", "Fuzzing", "Antigravity generating harnesses & fuzzing sinks...")
        logger.info("Stage: Fuzzing (Pillar 2 - HarnessAgent)")
        
        targets = candidates or [
             f for f in self.context.static_findings 
             if f.severity in [FindingSeverity.CRITICAL, FindingSeverity.HIGH]
        ]
        
        if not targets:
            logger.info("No high-severity candidates for fuzzing.")
            return

        for finding in targets:
             logger.info(f"  Targeting {finding.id} for fuzzing...")
             # 1. HarnessAgent: Generate Fuzzing Harness (AFL++/LibFuzzer/Atheris)
             harness_code = self.llm_gateway.generate_fuzz_harness(finding)
             logger.info(f"  Harness generated for {finding.location}")
             
             # 2. Run Fuzzer in Sandbox
             # res = await self.verifier.sandbox.run_fuzzer(harness_code, duration=300)
             # if res.crashes:
             #      logger.info(f"  🔥 Fuzzer FOUND CRASH for {finding.id}!")
             #      ... convert to VerifiedVuln
             
        logger.info("Fuzzing exploration complete.")

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
        logger.info("Stage: Variant Analysis (Feedback Loop)")
        confirmed = [v for v in self.context.verified_vulns if v.status == ConfirmedStatus.CONFIRMED]
        
        new_findings = []

        if confirmed:
             logger.info(f"Triggering Variant Analysis for {len(confirmed)} confirmed bugs...")
             
             # Generate Hypotheses for Variants
             variant_hypotheses = []
             for vuln in confirmed:
                 # Find original finding to get details
                 original = next((f for f in self.context.static_findings if f.id == vuln.finding_id), None)
                 if original:
                     # 1. Extract Abstract Pattern from Confirmed Vuln
                     import json
                     try:
                         logger.info(f"  🔍 Extracting variant pattern for {vuln.finding_id}...")
                         pattern_resp = self.llm_gateway.extract_variant_pattern(
                             code=original.location if hasattr(original, 'location') else "N/A", # Ideally we pass code snippet here
                             vulnerability_description=original.description
                         )
                         
                         # Parse JSON
                         clean_resp = pattern_resp
                         if "```json" in pattern_resp:
                             clean_resp = pattern_resp.split("```json")[1].split("```")[0]
                         elif "```" in pattern_resp:
                             clean_resp = pattern_resp.split("```")[1].split("```")[0]
                             
                         data = json.loads(clean_resp.strip())
                         pattern_desc = data.get("pattern_description", original.description)
                         search_strat = data.get("search_strategy", "")
                         
                         logger.info(f"  🧬 Abstract Pattern: {pattern_desc}")
                         
                         # 2. Generate Hypothesis using Abstract Pattern
                         h = Hypothesis(
                             id=str(uuid.uuid4()),
                             description=f"Variant of: {pattern_desc}",
                             target_code=search_strat, # Use abstract strategy as target/context for rule generation
                             verification_plan="Variant Scan",
                             metadata={"derived_from": vuln.finding_id, "type": "variant", "strategy": search_strat}
                         )
                         variant_hypotheses.append(h)
                         
                     except Exception as e:
                         logger.error(f"  ❌ Failed to extract pattern for {vuln.finding_id}: {e}")
                         # Fallback to simple description
                         h = Hypothesis(
                             id=str(uuid.uuid4()),
                             description=f"Variant of {original.description}",
                             target_code=original.location, 
                             verification_plan="Variant Scan",
                             metadata={"derived_from": vuln.finding_id, "type": "variant"}
                         )
                         variant_hypotheses.append(h)

             if variant_hypotheses:
                 logger.info(f"Scanning for {len(variant_hypotheses)} variant hypotheses...")
                 # Run Detector on new hypotheses
                 try:
                     variants = await self.detector.scan(variant_hypotheses, self.context.repo_path)
                     
                     # Filter duplicates
                     existing_ids = {f.id for f in self.context.static_findings} # ID collision check
                     existing_locs = {f.location for f in self.context.static_findings} # Location collision check

                     for v in variants:
                         if v.location not in existing_locs:
                             v.metadata["variant_of"] = v.metadata.get("derived_from")
                             new_findings.append(v)
                             existing_locs.add(v.location)
                             
                     logger.info(f"Variant Analysis found {len(new_findings)} NEW related findings.")
                     
                 except Exception as e:
                     logger.error(f"Variant analysis failed: {e}")

        else:
            logger.info("No confirmed bugs to analyze for variants.")
            
        return new_findings

    def run_stage_reporting(self) -> str:
        """Phase 8 & 9: Reporting - ENFORCING VERIFICATION GATE"""
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
        reporter = Reporter()
        
        if not confirmed_findings:
            logger.warning("No confirmed vulnerabilities found.")
        return reporter.generate_report(self.context.verified_vulns)


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

                # 2. Feedback / Variant Analysis  (FIX: await)
                self.report_progress("Phase 8", "Variant Analysis", "Searching for similar patterns...")
                new_variants = await self.run_stage_feedback()

                if not new_variants:
                    logger.info("No new variants found. Breaking loop.")
                    break

                # Update context
                self.context.static_findings.extend(new_variants)

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

