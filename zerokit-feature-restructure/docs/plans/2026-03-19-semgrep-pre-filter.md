# Semgrep Community Rules Pre-Filter Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Run Semgrep community rules in Phase 1 (Baseline) to find standard vulnerabilities reliably and for free. Then, filter out those vulnerable endpoints before they reach the token-heavy LLM ThreatModeler.

**Architecture:** Modifies `core/orchestrator.py` to invoke `SemgrepRunner` during `_run_baseline()`. Extracted findings are pushed to `static_findings`. In Phase 3, before passing the `AttackSurface` to the `ThreatModeler`, we strip out any `EntryPoint` whose file path matches a file already convicted by Semgrep.

**Tech Stack:** `SemgrepRunner`, Python Sets.

---

### Task 1: Add Semgrep Scan to Phase 1 (Baseline)

**Files:**
- Modify: `core/orchestrator.py` (around line 371 inside `_run_baseline`)

**Step 1: Write the failing test**
*(Omitted since this is procedural integration; no isolated test needed for the orchestrator boot sequence)*

**Step 2: Write minimal implementation**
Find the block labeled `OWASP Dependency-Check` in `run_stage_baseline` -> `_run_baseline`. Right underneath it, add the Semgrep Baseline logic:

```python
            # ── Semgrep Community Rules ────────────────────────────────────
            try:
                from .tools.semgrep_runner import SemgrepRunner
                semgrep = SemgrepRunner()
                
                # Use standard security ruleset 'p/security-audit'
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
```

**Step 3: Run pipeline test to verify no syntax errors**
Run: `pytest tests/ -k orchestrator --tb=short`

**Step 4: Commit**
```bash
git add core/orchestrator.py
git commit -m "feat(profiler): run semgrep community rules in pipeline baseline"
```

---

### Task 2: Filter the Attack Surface before Phase 3 (ThreatModeler)

**Files:**
- Modify: `core/orchestrator.py` (around line 415 in `run_stage_profiling` -> Phase 3 prep block)

**Step 1: Write minimal implementation**
Find the `if not self.context.hypotheses:` check where it prepares to instantiate the `ThreatModeler`. Inject logic to prune the `AttackSurface` using the Semgrep results we just gathered:

```python
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
```

**Step 2: Run pipeline test to verify no syntax errors**
Run: `pytest tests/ -k orchestrator --tb=short`

**Step 3: Commit (Final Integration)**
```bash
git add core/orchestrator.py
git commit -m "feat(orchestrator): filter attack surface using baseline semgrep intel"
```
