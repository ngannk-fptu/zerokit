import json
import logging
import asyncio
import uuid
import os
from typing import List, Optional, Dict
from ..models import Hypothesis, StaticFinding, FindingSeverity
from ..llm_gateway import LLMGateway
from ..config import config
from ..tools.semgrep_runner import SemgrepRunner
from ..tools.joern_runner import JoernRunner
try:
    from ..tools.codeql_runner import CodeQLRunner
    _CODEQL_AVAILABLE = True
except ImportError:
    _CODEQL_AVAILABLE = False
from ..tools.rule_generator import RuleGenerator  # NEW: SecurityProfile integration
from ..state_manager import StateManager # NEW
from ..tools.joern_queries import (
    QUERY_TEMPLATES, MEMORY_SAFETY_QUERIES, INJECTION_QUERIES,
    get_queries_for_language, ALL_QUERIES,
)

logger = logging.getLogger(__name__)

class Detector:
    def __init__(self, semgrep_runner: SemgrepRunner = None, joern_runner: JoernRunner = None):
        self.runner = semgrep_runner or SemgrepRunner()
        # CodeQL is optional — skipped if not installed or config missing
        self.codeql_runner = None
        if _CODEQL_AVAILABLE and hasattr(config, 'CODEQL_BIN'):
            try:
                self.codeql_runner = CodeQLRunner(codeql_path=config.CODEQL_BIN)
            except Exception:
                logger.info("CodeQL not available — skipping")
        self.joern_runner = joern_runner or JoernRunner() # Joern Integration
        self.rule_generator = RuleGenerator()  # NEW: Dynamic rule generation from SecurityProfile
        self.state_manager = StateManager() # NEW
        self.llm_gateway = LLMGateway() # Dynamic Intel
        self.enable_joern = True  # Can be configured via env var

    async def scan(self, hypotheses: List[Hypothesis], repo_path: str, security_profile: Optional["SecurityProfile"] = None) -> List[StaticFinding]:
        findings = []
        logger.info(f"Starting Static Analysis (Async) for {len(hypotheses)} hypotheses...")
        
        # Initialize Resource Pool
        from ..utils.resource_pool import ResourcePool
        pool = ResourcePool()
        
        # ---------------------------------------------------------
        # STEP 0: DIFFERENTIAL ANALYSIS (STATE MANAGER)
        # ---------------------------------------------------------
        all_files = []
        for root, _, files in os.walk(repo_path):
            for file in files:
                if ".git" in root: continue
                all_files.append(os.path.join(root, file))
        
        changed_files = []
        unchanged_files = []
        
        logger.info(f"Checking state for {len(all_files)} files...")
        for f_path in all_files:
            if self.state_manager.should_scan_file(f_path):
                changed_files.append(f_path)
            else:
                unchanged_files.append(f_path)
                
        logger.info(f"Differential Analysis: {len(changed_files)} changed, {len(unchanged_files)} unchanged.")
        
        # Load Cache
        cached_findings = []
        for f_path in unchanged_files:
            cached_findings.extend(self.state_manager.get_cached_findings(f_path))
        
        findings.extend(cached_findings)
        logger.info(f"Loaded {len(cached_findings)} cached findings.")
        
        if not changed_files and not cached_findings:
             logger.warning("Repo is empty or fully cached with 0 findings.")
        
        # ---------------------------------------------------------
        # STEP 1: PARALLEL START (HEAVY LIFTING)
        # ---------------------------------------------------------
        # Task 1: CodeQL DB Creation (IO Bound / Single Threaded mostly)
        # Task 2: Semgrep Scout (CPU Bound)
        
        # Allocation: 
        # Semgrep gets higher priority for CPU (scout needs to be fast)
        # CodeQL DB creation runs in background (low priority threads)
        semgrep_threads = pool.allocate(task_count=2, weight=2.0)
        codeql_threads = pool.allocate(task_count=2, weight=1.0)
        
        logger.info(f"Step 1: Launching Parallel Tasks (Semgrep: {semgrep_threads} threads, CodeQL DB: {codeql_threads} threads)")

        # Detect Languages for CodeQL (priority order: csharp, typescript/js, java, python)
        langs = []
        if glob_has_ext(repo_path, ".cs") or glob_has_ext(repo_path, ".csproj"):
            langs.append("csharp")
        if glob_has_ext(repo_path, ".ts") or glob_has_ext(repo_path, ".tsx"):
            langs.append("javascript")  # CodeQL uses 'javascript' for TS
        if glob_has_ext(repo_path, ".java"):
            langs.append("java")
        if glob_has_ext(repo_path, ".py"):
            langs.append("python")
        
        # Create CodeQL DB tasks (one per language)
        # NOTE: CodeQL usually needs full repo context, so we still run it on repo_path
        # Optimization: if changed_files is empty, maybe skip CodeQL?
        # ---------------------------------------------------------
        # SURGICAL CONTEXT EXPANSION
        # ---------------------------------------------------------
        surgical_targets = None
        if changed_files and len(changed_files) < 50:
            logger.info(f"Surgical Mode: Analyzing {len(changed_files)} changed files...")
            surgical_targets = self._expand_context(changed_files, repo_path)
            logger.info(f"Context Expanded: {len(surgical_targets)} files (Changes + Imports).")
        
        # Create CodeQL DB tasks (one per language)
        codeql_db_tasks = []
        if changed_files or surgical_targets: 
            # If surgical, we pass the list. CodeQLRunner will handle partial cloning.
            for lang in langs:
                codeql_db_tasks.append(
                    asyncio.create_task(
                        self.codeql_runner.create_database_async(
                            repo_path, 
                            lang, 
                            include_paths=surgical_targets,
                            threads=codeql_threads
                        )
                    )
                )
        else:
            logger.info("Skipping CodeQL DB creation (No changes detected).")

        # Prepare Semgrep
        # Retrieve profile if available (passed via context or we need to change signature)
        # For now, let's assume it's passed or we default to None. 
        # Actually, let's update the signature of scan in the next step.
        # Here we just use the variable `security_profile` which we will add to arguments.
        
        # Generate Semgrep rules dynamically from SecurityProfile
        if security_profile:
            config_rules = self.rule_generator.generate_rules(security_profile)
        else:
            # Fallback to old method if no profile (backward compat)
            config_rules = self._generate_semgrep_config(hypotheses, security_profile)

        
        # Define Async Tasks
        # Semgrep runs ONLY on changed_files if possible, or repo_path if changed_files is large/all
        semgrep_target = changed_files if changed_files else []
        
        task_semgrep = None
        if semgrep_target:
            # Chunking could be needed if too many files, but for now pass list
            task_semgrep = asyncio.create_task(
                self.runner.run_scan_async(config_rules, semgrep_target, jobs=semgrep_threads)
            )
        else:
            logger.info("Skipping Semgrep Scout (No changes detected).")

        # ---------------------------------------------------------
        # STEP 2: SYNC POINT & SIGNALS
        # ---------------------------------------------------------
        # ---------------------------------------------------------
        # STEP 2: SYNC POINT & SIGNALS
        # ---------------------------------------------------------
        # Wait for Semgrep (Scout) first to get signals
        semgrep_result = None
        if task_semgrep:
            semgrep_result = await task_semgrep
        
        signals = {"taint_sources": [], "suspicious_files": set()}
        scout_findings = []
        
        if semgrep_result and semgrep_result.success:
            for res in semgrep_result.findings:
                f = self._normalize_finding(res, "semgrep")
                if not f: continue
                
                # Signal Extraction
                tag = f.metadata.get("tag")
                if tag == "surface":
                    path = f.location.split(":")[0]
                    signals["suspicious_files"].add(path)
                else:
                    scout_findings.append(f)
                    if f.severity in [FindingSeverity.CRITICAL, FindingSeverity.HIGH]:
                        path = f.location.split(":")[0]
                        signals["suspicious_files"].add(path)
            
            findings.extend(scout_findings)
            logger.info(f"Semgrep Scout finished in {semgrep_result.duration_ms:.2f}ms. Found {len(signals['suspicious_files'])} suspicious files.")
        elif semgrep_result:
            logger.error(f"Semgrep failed: {semgrep_result.error_msg}")
        
        # Update State for changed files that were scanned successfully
        # Ideally we check per file, but here we assume batch success
        if semgrep_result and semgrep_result.success:
             for cf in changed_files:
                 self.state_manager.update_file_state(cf)

        # Wait for CodeQL DBs
        valid_dbs = {} # lang -> db_path
        if codeql_db_tasks:
            logger.info("Waiting for CodeQL DB creation...")
            db_results = await asyncio.gather(*codeql_db_tasks)
            
            for i, res in enumerate(db_results):
                if res.success:
                    valid_dbs[langs[i]] = res.db_path
                    logger.info(f"CodeQL DB ({langs[i]}) ready in {res.duration_ms:.2f}ms")
                else:
                    logger.error(f"CodeQL DB ({langs[i]}) failed: {res.error_msg}")
        
        # ---------------------------------------------------------
        # STEP 3: DEEP ENGINE (GUIDED)
        # ---------------------------------------------------------
        logger.info("Step 3: Deep Engine (Guided by Signals)...")
        
        deep_tasks = []
        
        # Joern Task (Only if changes)
        if self.enable_joern and self._is_c_cpp_project(repo_path) and changed_files:
             deep_tasks.append(asyncio.create_task(self.scan_with_joern_async(repo_path)))

        # CodeQL Tasks
        analysis_threads = pool.allocate(task_count=len(valid_dbs) + 1)
        
        for lang, db_path in valid_dbs.items():
            deep_tasks.append(
                asyncio.create_task(
                    self.codeql_runner.analyze_async(
                        db_path, 
                        query_suite="security-extended", 
                        output_name=f"{lang}_deep",
                        threads=analysis_threads
                    )
                )
            )

        if deep_tasks:
            results = await asyncio.gather(*deep_tasks)
            
            # Process Results
            for res in results:
                # Identify if it's CodeQL or Joern result
                if isinstance(res, list): # Joern returns list directly (legacy/wrapper) - wait, scan_with_joern_async returns List[StaticFinding]
                    findings.extend(res)
                elif hasattr(res, "findings"): # CodeQL AnalysisResult
                    if res.success:
                        logger.info(f"CodeQL Analysis finished in {res.duration_ms:.2f}ms")
                        for ql_f in res.findings:
                            f = self._normalize_codeql_finding(ql_f)
                            if f:
                                # Boost Severity if in Signals
                                path = f.location.split(":")[0]
                                if path in signals["suspicious_files"]:
                                    f.severity = FindingSeverity.CRITICAL
                                    f.metadata["collaborative_signal"] = "Semgrep->CodeQL"
                                    f.description = f"[HYBRID CONFIRMED] {f.description}"
                                findings.append(f)
                    else:
                        logger.error(f"CodeQL Analysis Error: {res.error_msg}")

        # ---------------------------------------------------------
        # STEP 3: DEEP GRAPH ANALYSIS (JOERN) [NEW]
        # ---------------------------------------------------------
        # Trigger only if Semgrep found specific high-severity issues
        if findings and self.enable_joern:
            # We filter for high severity to optimize performance
            high_sev_findings = [f for f in findings if f.severity in [FindingSeverity.HIGH, FindingSeverity.CRITICAL]]
            
            if high_sev_findings:
                logger.info(f"Step 3: Triggering Deep Graph Analysis (Joern) for {len(high_sev_findings)} high-severity findings...")
                try:
                    # Determine language for CPG (Simplistic check)
                    # In real-world multilang repos, we'd need a language map
                    cpg_lang = "c" # Default to C for now as per Joern strengths
                    if glob_has_ext(repo_path, ".php"): cpg_lang = "php"
                    if glob_has_ext(repo_path, ".java"): cpg_lang = "java"
                    
                    # Async Parse & Cache
                    cpg_path = await self.joern_runner.parse_code_async(repo_path, language=cpg_lang)
                    
                    # Run Analysis
                    # 1. Buffer Overflow check (if C/C++)
                    if cpg_lang in ["c", "cpp"]:
                        overflows = self.joern_runner.find_buffer_overflows(cpg_path)
                        for o in overflows:
                             findings.append(StaticFinding(
                                id=str(uuid.uuid4()),
                                file_path=o.get("file"),
                                line=int(o.get("line", -1)),
                                check_id="joern.buffer-overflow",
                                severity=FindingSeverity.CRITICAL,
                                description=f"Potential Buffer Overflow: {o.get('function')} (checked by Joern)",
                                tool_name="joern",
                                location=o.get("code")
                            ))
                            
                    logger.info(f"Joern Analysis complete. Buffer Overflows found: {len(overflows) if cpg_lang in ['c', 'cpp'] else 0}")

                except Exception as e:
                    logger.error(f"Joern analysis failed: {e}")

        # ---------------------------------------------------------
        # STEP 4: DYNAMIC QUERY GENERATION (SELF-CORRECTION LOOP)
        # ---------------------------------------------------------
        logger.info("Step 4: Dynamic Query Generation (Self-Correction Loop)...")
        
        # Identify hypotheses that need dynamic queries (e.g., specific variants)
        dynamic_hypotheses = [h for h in hypotheses if h.metadata.get("type") == "variant"]
        
        for h in dynamic_hypotheses:
            await self._run_dynamic_query_loop(h, repo_path, findings)

        # ---------------------------------------------------------
        # PERSISTENCE & FILTERING
        # ---------------------------------------------------------
        
        # 1. Filter out known False Positives (REJECTED)
        findings = self.state_manager.filter_rejected_findings(findings)
        
        # 2. Save new findings
        self.state_manager.save_findings(findings)
        
        # ---------------------------------------------------------
        # STEP 5: CWE ENRICHMENT [NEW]
        # ---------------------------------------------------------
        logger.info("Step 5: Enriching findings with CWE details...")
        from ..tools.cwe_manager import CweManager
        cwe_mgr = CweManager()
        
        for f in findings:
            # 1. Try to extract CWE ID from metadata
            cwe_id = f.metadata.get("cwe")
            if not cwe_id and "tags" in f.metadata:
                # Look for CWE-XX in tags
                for tag in f.metadata["tags"]:
                    if tag.startswith("external/cwe/cwe-"):
                        cwe_id = tag.split("cwe-")[1]
                        break
            
            if not cwe_id and f.tool_name == "semgrep":
                # Check for common CWE patterns in description
                if "CWE-89" in f.description: cwe_id = "89"
                elif "CWE-79" in f.description: cwe_id = "79"
            
            # 2. If ID found, enrich
            if cwe_id:
                # Normalize ID (remove 'CWE-' prefix if present)
                cwe_id = cwe_id.upper().replace("CWE-", "")
                f.cwe_details = cwe_mgr.get_cwe(cwe_id)
                if f.cwe_details:
                    logger.info(f"  Enriched finding {f.id} with CWE-{cwe_id}")
        
        return findings

    async def _run_dynamic_query_loop(self, hypothesis: Hypothesis, repo_path: str, findings: List[StaticFinding]):
        """
        Executes the Detection Loop: Write -> Run -> Error -> Fix -> Run
        """
        MAX_RETRIES = 3
        attempt = 0
        
        # Initial Query Generation (Intelligent)
        response = self.llm_gateway.generate_semgrep_rule(
            hypothesis_id=hypothesis.id,
            description=hypothesis.description,
            cwe_id=hypothesis.metadata.get("cwe_id", "UNKNOWN"),
            language="generic", # Can extract from repo later
            source=hypothesis.metadata.get("source", "Unknown"),
            sink=hypothesis.metadata.get("sink", "Unknown"),
            trust_boundary=hypothesis.metadata.get("trust_boundary", "Unknown"),
            target=hypothesis.target_code or "generic",
            context=hypothesis.target_code
        )
        
        # Parse JSON Response (Strategy + Content)
        from ..utils import extract_json
        query_content = ""
        strategy = ""
        
        try:
            # Cleanup markdown code blocks if present
            clean_resp = response
            if "```json" in response:
                clean_resp = response.split("```json")[1].split("```")[0]
            elif "```" in response:
                clean_resp = response.split("```")[1].split("```")[0]
                
            data = extract_json(clean_resp.strip(), default={"findings": []})
            query_content = data.get("rule_content", "")
            strategy = data.get("strategy", "No strategy provided")
            
            logger.info(f"  🧠 AI Strategy: {strategy}")
            
        except json.JSONDecodeError:
            # Fallback for legacy/plain YAML response
            logger.warning("  ⚠️ Failed to parse JSON strategy. Assuming raw YAML.")
            query_content = response

        while attempt < MAX_RETRIES:
            attempt += 1
            logger.info(f"  > Dynamic Scan Attempt {attempt} for {hypothesis.id}")
            
            # Write to temp file
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as tmp:
                tmp.write(query_content)
                tmp_path = tmp.name
            
            # Check Blacklist
            if self.state_manager.is_rule_blacklisted(query_content):
                last_err = self.state_manager.get_rule_error(query_content)
                logger.warning(f"  🚫 Skipping Blacklisted Rule (Hash: ...)")
                logger.info(f"     Reason: High Failure Rate. Last Error: {last_err}")
                
                # Regenerate with negative feedback if possible
                # For now, just try to fix it one last time or break?
                # Let's break to avoid infinite loops of bad rules
                logger.info("     Regenerating completely new rule...")
                query_content = self.llm_gateway.fix_semgrep_rule(
                    failed_rule=query_content, 
                    error_msg=f"PREVIOUS_FAILED_ATTEMPT: {last_err}. DO NOT use this pattern again.",
                    language="generic",
                    attempt_number=attempt,
                    hypothesis_id=hypothesis.id
                )
                # Continue to next attempt instead of breaking immediately
                # But we need to ensure we don't loop forever. 'attempt' loop handles that.
            
            try:
                # Run Semgrep on this single rule
                # We target REPO_PATH generally, or could target h.target_code specifically if it's a file
                result = await self.runner.run_scan_async(tmp_path, repo_path)
                
                if result.success:
                    logger.info(f"  ✅ Query Success! Found {len(result.findings)} results.")
                    self.state_manager.record_rule_execution(query_content, success=True)
                    
                    for res in result.findings:
                         f = self._normalize_finding(res, "semgrep")
                         if f: findings.append(f)
                    break # Success, exit loop
                
                else:
                    # SELF-CORRECTION LOGIC
                    logger.warning(f"  ❌ Query Failed: {result.error_msg}")
                    self.state_manager.record_rule_execution(query_content, success=False, error_msg=result.error_msg)
                    
                    # Only retry if syntax error
                    if "syntax" in result.error_msg.lower() or "yaml" in result.error_msg.lower():
                        logger.info("  🔧 Agent is attempting to FIX the query...")
                        fixed_resp = self.llm_gateway.fix_semgrep_rule(
                            failed_rule=query_content, 
                            error_msg=result.error_msg,
                            language="generic",
                            attempt_number=attempt,
                            hypothesis_id=hypothesis.id
                        )
                        
                        # Fix Rule might also return JSON now or just YAML? 
                        # Ideally fix_rule prompt should also be updated or we handle both.
                        # For now, let's assume fix_rule returns raw YAML or we parse it if it looks like JSON.
                        if "rule_content" in fixed_resp:
                             try:
                                 # Try parse again just in case
                                 clean_fix = fixed_resp
                                 if "```json" in fixed_resp:
                                     clean_fix = fixed_resp.split("```json")[1].split("```")[0]
                                 elif "```" in fixed_resp:
                                      clean_fix = fixed_resp.split("```")[1].split("```")[0]
                                 data = extract_json(clean_fix.strip(), default={})
                                 query_content = data.get("rule_content", "")
                                 logger.info(f"  🧠 AI Strategy (Fix): {data.get('strategy', 'N/A')}")
                             except:
                                 query_content = fixed_resp # Fallback
                        else:
                             query_content = fixed_resp
                    else:
                        break # Non-recoverable error
                    
            except Exception as e:
                logger.error(f"Loop Exception: {e}")
            finally:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)



    def _generate_semgrep_config(self, hypotheses: List[Hypothesis], security_profile: Optional["SecurityProfile"] = None) -> str:
        # Point to the real rules directory
        rules_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "rules", "semgrep")
        
        # If no profile or no sanitizers, return standard rules dir
        if not security_profile or not security_profile.sanitizers:
            if os.path.exists(rules_dir):
                return rules_dir
            return os.path.dirname(__file__)

        # Dynamic Rule Generation
        # We need to create a temporary rule file that includes sanitizer exclusions
        # For this PoC, we will generate a simple rule extending the base logic
        import yaml
        import tempfile
        
        generated_rules = {
            "rules": []
        }
        
        # Example: Inject Sanitizers into Generic Injection Rule
        # This is a simplified example. In reality, we would parse existing rules and append pattern-not-inside.
        # Here, we create a new comprehensive rule based on the profile.
        
        # Phase 5: Advanced WordPress Rules (Hardcoded Injection)
        if security_profile and "wordpress-core" in security_profile.framework_specific:
            # 1. Taint Propagation for apply_filters
            # This rule tells Semgrep that if arg2 is tainted, result is tainted.
            # Note: For strict Taint Mode, we need 'mode: taint'.
            # ZeroKit2 standard scan IS search-based. To support taint, we need to ensure the engine supports it.
            # For now, we rely on the search-based Critical Rule for unsafe prepare.
            
            unsafe_prepare_rule = {
                "id": "wordpress-unsafe-prepare",
                "languages": ["php"],
                "message": "CRITICAL: Unsafe use of wpdb->prepare (String concatenation detected). This bypasses SQLi protection.",
                "severity": "ERROR",
                "pattern-either": [
                    # Direct concatenation in prepare
                    {"pattern": "$WPDB->prepare(\"...\" . $VAR, ...)"},
                    {"pattern": "$WPDB->prepare($QUERY . $VAR, ...)"},
                    # Nested inside query/get_results/etc
                    {"pattern": "$WPDB->query($WPDB->prepare(\"...\" . $VAR, ...))"},
                    {"pattern": "$WPDB->get_results($WPDB->prepare(\"...\" . $VAR, ...))"},
                ],
                "metadata": {
                    "cwe": "CWE-89",
                    "owasp": "A03:2021-Injection",
                    "confidence": "HIGH"
                }
            }
            generated_rules["rules"].append(unsafe_prepare_rule)

        for vuln_type, sanitizers in security_profile.sanitizers.items():
            if not sanitizers: continue
            
            # Create a rule that flags sinks BUT ignores sanitizers
            # sink(...) and not sanitizer(...)
            
            sinks = security_profile.sinks.get(vuln_type, [])
            if not sinks: continue
            
            pattern_either = [{"pattern": f"{sink}(...)"} for sink in sinks]
            pattern_not_inside = [{"pattern": f"{san}(...)"} for san in sanitizers]
            
            rule = {
                "id": f"dynamic-{vuln_type}-check",
                "languages": ["php"] if "php" in security_profile.framework_specific else ["python", "javascript"],
                "message": f"Potential {vuln_type} detected (Dynamic Context)",
                "severity": "ERROR",
                "patterns": [
                    {"pattern-either": pattern_either},
                    {"pattern-not-inside": pattern_not_inside}
                ]
            }
            generated_rules["rules"].append(rule)
            
        if not generated_rules["rules"]:
             if os.path.exists(rules_dir): return rules_dir
             return os.path.dirname(__file__)
             
        # Write to temp file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as tmp:
            yaml.dump(generated_rules, tmp)
            logger.info(f"Generated Dynamic Rules at {tmp.name} based on Security Profile")
            return tmp.name

    def _normalize_codeql_finding(self, raw: Dict) -> Optional[StaticFinding]:
        """
        Convert CodeQL SARIF result to StaticFinding with strict severity mapping.
        Expects 'raw' to be a merged dictionary of Result + Rule Metadata.
        """
        # Extract Severity & Precision
        # Priority: problem.severity > level
        severity_str = raw.get("problem.severity", raw.get("severity", "warning")).lower()
        precision = raw.get("precision", "medium").lower()
        
        # Mapping Logic
        final_severity = FindingSeverity.MEDIUM # Default
        
        if severity_str == "recommendation":
            final_severity = FindingSeverity.LOW
        elif severity_str == "warning":
            final_severity = FindingSeverity.MEDIUM
        elif severity_str == "error":
            if precision in ["high", "very-high"]:
                final_severity = FindingSeverity.CRITICAL
            else:
                final_severity = FindingSeverity.HIGH
                
        # Extract Location
        # Handle SARIF location structure if present, or flattened keys
        file_path = raw.get("file", raw.get("location", {}).get("file", "unknown"))
        line = raw.get("line", raw.get("location", {}).get("start_line", 0))
        
        # Upgrade 2: DV Loop — extract function name from location for directed fuzzing
        location = f"{file_path}:{line}"
        target_fn = self._extract_function_from_location(location, file_path)
        is_directed = final_severity in (FindingSeverity.HIGH, FindingSeverity.CRITICAL)

        return StaticFinding(
            id=str(uuid.uuid4())[:16],
            description=raw.get("message", "CodeQL Finding"),
            location=location,
            severity=final_severity,
            tool_name="codeql",
            evidence=f"Rule: {raw.get('rule_id', 'unknown')} | Precision: {precision}",
            metadata={
                "raw_severity": severity_str,
                "precision": precision,
                "rule_id": raw.get("rule_id"),
                "tags": raw.get("tags", [])
            },
            target_function=target_fn,
            directed_fuzz_candidate=is_directed
        )

    def _normalize_finding(self, res: dict, tool_name: str) -> Optional[StaticFinding]:
        severity_map = {
            "ERROR": FindingSeverity.HIGH,
            "WARNING": FindingSeverity.MEDIUM,
            "INFO": FindingSeverity.LOW,
        }
        
        if tool_name == "semgrep":
            extra = res.get("extra", {})
            metadata = extra.get("metadata", {})
            tag = metadata.get("tag")
            
            import hashlib
            unique_str = f"{res.get('path')}:{extra.get('message')}:{extra.get('lines')}"
            stable_id = hashlib.sha256(unique_str.encode()).hexdigest()[:16]

            severity = severity_map.get(extra.get("severity"), FindingSeverity.MEDIUM)
            location = f"{res.get('path')}:{res.get('start', {}).get('line', 0)}"

            # Upgrade 2: DV Loop — extract function name from location for directed fuzzing
            target_fn = self._extract_function_from_location(location, res.get("path", ""))
            is_directed = severity in (FindingSeverity.HIGH, FindingSeverity.CRITICAL)

            return StaticFinding(
                id=stable_id,
                description=extra.get("message", "Semgrep Finding"),
                location=location,
                severity=severity,
                tool_name="semgrep",
                evidence=f"Lines: {extra.get('lines', '')}",
                metadata={"tag": tag, "type": metadata.get("type")},
                target_function=target_fn,
                directed_fuzz_candidate=is_directed,
            )
        return None

    def _extract_function_from_location(self, location: str, file_path: str) -> Optional[str]:
        """
        Best-effort extraction of function name from a file + line location.
        Used to populate target_function for directed fuzzing in Phase 5.
        """
        import re
        try:
            if not file_path or not os.path.exists(file_path):
                return None
            line_no = int(location.split(":")[-1]) if ":" in location else 0
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()

            # Search backwards from finding line for nearest function def
            fn_patterns = [
                re.compile(r"def\s+(\w+)\s*\("),                  # Python
                re.compile(r"(?:public|private|protected|static|\s)+\w+\s+(\w+)\s*\("),  # Java
                re.compile(r"\w[\w\s\*]+\s+(\w+)\s*\([^;{]*\{"),  # C/C++
                re.compile(r"(?:async\s+)?function\s+(\w+)\s*\("), # JS
            ]
            search_start = max(0, line_no - 50)
            for i in range(line_no - 1, search_start, -1):
                if i < len(lines):
                    line = lines[i]
                    for pat in fn_patterns:
                        m = pat.search(line)
                        if m:
                            return m.group(1)
        except Exception:
            pass
        return None

    def scan_with_joern(self, repo_path: str) -> List[StaticFinding]:
         # Valid legacy sync method if needed, but we rely on async now
         pass 

    async def scan_with_joern_async(self, repo_path: str) -> List[StaticFinding]:
        """Run Joern CPG analysis for C/C++ vulnerability detection (Async)."""
        findings = []
        
        try:
            logger.info("Parsing C/C++ code with Joern (Async)...")
            cpg_path = await self.joern_runner.parse_code_async(repo_path, language="c")
            
            for query_name in MEMORY_SAFETY_QUERIES:
                logger.debug(f"Running Joern query: {query_name}")
                query_template = QUERY_TEMPLATES[query_name]
                
                try:
                    results = await self.joern_runner.run_query_async(cpg_path, query_template)
                    
                    for res in results:
                        finding = self._normalize_joern_finding(res, query_name)
                        if finding:
                            findings.append(finding)
                
                except Exception as e:
                    logger.warning(f"Query {query_name} failed: {e}")
                    continue
            
            logger.info(f"Joern analysis complete: {len(findings)} findings")
        
        except Exception as e:
            logger.error(f"Joern scan error: {e}")
        
        return findings
    
    def _normalize_joern_finding(self, joern_res: dict, query_name: str) -> Optional[StaticFinding]:
        """Convert Joern query result to StaticFinding."""
        severity_map = {
            "CRITICAL": FindingSeverity.CRITICAL,
            "HIGH": FindingSeverity.HIGH,
            "MEDIUM": FindingSeverity.MEDIUM,
            "LOW": FindingSeverity.LOW,
        }
        
        severity = joern_res.get("severity", "MEDIUM")
        
        return StaticFinding(
            id=str(uuid.uuid4()),
            description=joern_res.get("description", "Joern finding"),
            location=f"{joern_res.get('file')}:{joern_res.get('line')}",
            severity=severity_map.get(severity, FindingSeverity.MEDIUM),
            evidence=joern_res.get("code", ""),
            tool_name=f"joern/{query_name}",
            metadata={
                "vulnerability_type": joern_res.get("vulnerability_type"),
                "function": joern_res.get("function"),
                "raw": joern_res
            }
        )
    
    def _is_c_cpp_project(self, repo_path: str) -> bool:
        """Check if repository contains C/C++ code."""
        c_extensions = [".c", ".cpp", ".cc", ".cxx", ".h", ".hpp"]
        
        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', '__pycache__']]
            
            for file in files:
                if any(file.endswith(ext) for ext in c_extensions):
                    logger.info(f"Detected C/C++ project (found {file})")
                    return True
        
        return False

    def _expand_context(self, files: List[str], repo_path: str) -> List[str]:
        """
        Expand list of files to include direct imports (Basic Regex).
        """
        expanded = set(files)
        import re
        
        # Simple Regex for efficient heuristic
        # Python: from x import y, import x
        # JS: import x from 'x'
        # PHP: require 'x'
        patterns = [
             re.compile(r'^(?:from|import)\s+([\w\.]+)'), # Py
             re.compile(r'import\s+.*\s+from\s+[\'"]([^\'"]+)[\'"]'), # JS/TS
             re.compile(r'(?:require|include|require_once|include_once)\s*[\(]?\s*[\'"]([^\'"]+)[\'"]') # PHP
        ]
        
        for fpath in files:
            if not os.path.exists(fpath): continue
            try:
                with open(fpath, 'r', errors='ignore') as f:
                    content = f.read()
                    
                for p in patterns:
                    for match in p.finditer(content):
                        # Try to resolve match to file
                        ref = match.group(1)
                        # Naive resolution: 
                        # 1. Check relative to file
                        # 2. Check relative to repo root
                        
                        base_dir = os.path.dirname(fpath)
                        candidates = [
                            os.path.join(base_dir, ref),
                            os.path.join(base_dir, ref + ".py"),
                            os.path.join(base_dir, ref + ".js"),
                            os.path.join(base_dir, ref + ".php"),
                            os.path.join(repo_path, ref),
                            os.path.join(repo_path, ref.replace(".", "/") + ".py")
                        ]
                        
                        for cand in candidates:
                            if os.path.isfile(cand):
                                expanded.add(cand)
                                break
            except Exception as e:
                logger.warning(f"PARTIAL_CONTEXT: Failed to parse {fpath}: {e}")

                
        return list(expanded)

# Helper for glob
def glob_has_ext(path, ext):
    for r, d, f in os.walk(path):
        for file in f:
            if file.endswith(ext): return True
    return False
