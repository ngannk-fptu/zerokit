# ZeroKit V3 — Combined Hardening + Vertical Slice Plan (Rev 3)

## Objective
Two-part plan: (1) Fix all P0 foundation issues from the Claude x Codex consensus review, (2) Build the Vertical Slice demo (Python + SQL injection, full 6-phase pipeline).

## Context
- Branch: `dev` (30 commits ahead of `main`, ~7.8K lines added)
- Existing in `tools/harness/`: detect_repo_profile.py, run_semgrep.py, run_gitleaks.py, run_joern.py, run_poc.py, merge_findings.py, validate_run_artifacts.py
- **NOT existing:** run_master_workflow.py, init_artifact_run.py (referenced in docs but not on disk — must be created)
- Design doc: APPROVED (Vertical Slice — Python + SQLi, all 6 phases, audit-quality report)
- Plan review: 3 rounds, 13 issues raised, all addressed in this revision

## Part 1: Foundation Hardening (D1–D6)

### D1: Context Detox — Purge Stale Legacy References
**Problem:** Multiple files contain stale ZeroKit2/legacy references that actively poison agent reasoning.

**Actions:**
1. Run repo-wide inventory FIRST: `rg -il` with all forbidden tokens across entire repo (not just .agent/ or *.md). Classify each hit as: delete, rewrite, or allowlist.
2. Delete files that are entirely obsolete (e.g., GEMINI.md, readiness_assessment.md, tool_checklist.md, skills/doc.md — if present)
3. Rewrite files that have stale references mixed with valid content (hunt-gitleaks, hunt-semgrep, hunt-threat-modeler SKILLs; ARCHITECTURE.md, BLUEPRINT.md)
4. Rewrite README.md + README_GITHUB.md with V3 harness reality, implemented vs planned matrix
5. Allowlist files that legitimately discuss forbidden patterns in "do not do" context (e.g., ci_guardrails_runbook.md, check_stale_references.py itself)
6. Re-run inventory after all changes to verify zero un-allowlisted matches

**Verification:** `tools/ci/check_stale_references.py` with:
- Forbidden tokens (case-insensitive for brands, exact for paths): `ZeroKit2`, `hunt_pipeline`, `hunt-pipeline`, `Antigravity`, `Gemini` (as LLM), `core/agents/`, `core/tools/`, `core/adapters/`, `test_vul`, `Piranha`, `bpost`, `SecOpsAgentKit`
- **Scan scope: entire repo** — excludes `.git/`, `node_modules/`, `__pycache__/`, `.codex-review/`
- Allowlist maintained in the checker script with one-line justification per entry
- `make check` includes this (it already does)

### D2: Reproducibility Baseline
**Problem:** External tool versions not pinned. Setup path incomplete.

**Actions:**
1. Verify `pyproject.toml` exists with `requires-python >=3.11`, dev deps (`pytest>=8.0,<9`, `ruff>=0.4,<1`)
2. Add `tools` optional dep group: `semgrep>=1.60`
3. Create `tool-versions.json` at repo root — **exact pinned** external tool versions for the demo:
   ```json
   {
     "python": "3.11",
     "semgrep": "1.60.0",
     "gitleaks": "8.18.4",
     "joern": "4.0.0",
     "docker": "24.0",
     "flask_fixture_base_image": "python:3.11-slim"
   }
   ```
   Note: `>=` ranges in pyproject.toml for dev flexibility; exact pins in tool-versions.json for demo reproducibility.
4. Document canonical setup in README: `pip install -e ".[dev,tools]"` then `make test`
5. D7 fixture includes `Flask==3.0.0` in its requirements.txt
6. D7 Dockerfile uses pinned base image from tool-versions.json

### D3: Shim Transparency
**Problem:** Shim artifacts look like real pipeline output.

**Actions:**
1. Add `"source": "orchestration-shim"` to all seeded artifacts
2. Keep `"inconclusive"` status (no new enum values — preserves contract compatibility)
3. Add `"simulated": true` to `run_state.json` for shim runs, `"simulated": false` for real runs
4. Add `"simulated": true` to dry-run stdout; `"simulated": false` when real phases execute
5. **Canonical source of truth:** `run_state.json` is authoritative. Stdout is a convenience mirror. Validators read `run_state.json`.
6. Update artifact contract: add optional `"source"` string + required `"simulated"` boolean on run_state (no enum changes)
7. Update `validate_run_artifacts.py` to: read `simulated` from `run_state.json`, report distinctly, warn if simulated run claims confirmed findings
8. Update artifact examples to show both `"simulated": true` and `"simulated": false` variants

### D4: Phase Config SSoT + Core Orchestrator Bootstrap
**Problem:** Phase definitions hardcoded in multiple consumers. Core orchestrator scripts (`run_master_workflow.py`, `init_artifact_run.py`) do not exist yet — they are documented but never created.

**Actions:**
1. Verify `phase_config.json` exists
2. Create shared loader `tools/harness/_phase_config.py` (if not already present)
3. **CREATE** `tools/harness/run_master_workflow.py` — the master orchestrator:
   - Reads phase config from `phase_config.json` via shared loader
   - Creates run directory structure (`init_artifact_run` logic built in)
   - Runs phases sequentially: intake, profile, static, verify, RCA, report
   - Emits `run_state.json` with phase status tracking
   - `--dry-run` mode seeds placeholders with `"simulated": true`
   - Real mode dispatches to phase scripts (D8-D11) with `"simulated": false`
4. **CREATE** `tools/harness/init_artifact_run.py` — standalone artifact run initializer:
   - Creates run directory with phase subdirs from `phase_config.json`
   - Writes initial `run_state.json`
5. **Full consumer inventory** (run `rg -n "01-intake|02-surface|03-static|04-verify|05-rca|06-report|phase-0[1-6]" tools tests .agent`):
   - `check_workflow_integrity.py` — migrate to loader
   - `validate_run_artifacts.py` — migrate to loader
   - Test files — import from loader or read phase_config.json
   - `.agent/agent.md` and methodology docs — static references; CI check that phase IDs match
6. Remove all hardcoded phase constants from executable code

### D5: Behavioral Tests for Foundation
**Problem:** Need tests for hardening changes.

**Actions:**
1. Tests for `detect_repo_profile.py`: fixture-based language detection
2. Tests for `validate_run_artifacts.py`: valid/invalid/malformed, simulated vs real detection
3. Tests for `run_master_workflow.py`: dry-run output, `simulated: true/false`, directory creation, duplicate run-id
4. Tests for `init_artifact_run.py`: directory structure, initial state
5. Tests for phase config: loader returns correct phases, all executable consumers use loader

### D6: CI Enforcement
**Problem:** New checks not in GitHub Actions. Must come LAST — after implementation surface is stable.

**Actions:**
1. Update `.github/workflows/harness-guardrails.yml`: add `pip install -e ".[dev]"`, `make lint`, `make test`
2. Add separate `make test-integration` step with Docker/tool setup for E2E tests
3. `make check` already includes `check_stale_references.py`
4. Runs on push to `dev`/`main` and on PR

## Part 2: Vertical Slice Demo (D7–D12)

### D7: Vulnerable Test Fixture
**Problem:** Need a realistic vulnerable Python app to demo against.

**Actions:**
1. Create `tests/fixtures/vuln-flask-app/` with:
   - `app.py`: Flask app with one SQL injection (string concat into SQLite), one path traversal (unsanitized), one false positive (parameterized query)
   - `requirements.txt`: Flask==3.0.0 (SQLite is stdlib)
   - `Dockerfile`: pinned `python:3.11-slim` base image, installs deps, exposes port 5000
   - `docker-compose.yml`: defines `vuln-app` service + shared `pentest-net` bridge network, publishes port 5000 to localhost
   - `README.md`: documents intentional vulns
2. App auto-creates SQLite DB on startup with seed data

### D8: Phase 03 Orchestrator — Static Detection
**Problem:** Need to wire existing tool connectors into a real Phase 03 pipeline.

**Actions:**
1. Create `tools/harness/run_phase03.py`:
   - Read repo profile from Phase 02 output
   - Select Semgrep rules based on detected languages (Python -> python security rules)
   - Run `run_semgrep.py` with selected rules
   - Run `run_gitleaks.py` for secrets
   - Feed both outputs to `merge_findings.py`
   - Write deduplicated candidates to `03-static/static_findings.json`
   - Write hypotheses to `03-static/hypotheses.json`
2. Output conforms to existing artifact contract

### D9: SQLi PoC Template + Phase 04 Orchestrator — Verification
**Problem:** Need to verify static findings with real exploitation attempts.

**Critical design decisions:**
- `run_poc.py` currently uses `--network none` — must extend for HTTP PoCs
- Fixture uses SQLite — **SQLite has no SLEEP()** — must use SQLite-compatible proof technique
- Health-check must run from correct network context

**Actions:**
1. **Fix network model:**
   - Extend `run_poc.py` to accept `--network <name>` parameter (default remains `none` for safety)
   - Phase 04 orchestrator passes `--network pentest-net` when verifying HTTP findings
   - PoC container joins the same Docker network as the target app
   - Non-HTTP PoCs (static analysis, file-based) keep `--network none`
2. **Target lifecycle:**
   - `run_phase04.py` starts the vuln-flask-app via `docker-compose up -d` before verification
   - Health-check: publish port 5000 to localhost in docker-compose.yml, check from host via `curl -f http://localhost:5000/` with retry loop (max 30s). Alternatively use `docker inspect --format='{{.State.Health.Status}}'` if Dockerfile has HEALTHCHECK.
   - PoC containers address target as `vuln-app:5000` (Docker DNS within `pentest-net`)
   - After all verifications: `docker-compose down`
   - On error/timeout: always tear down (try/finally)
3. **SQLi PoC — SQLite-compatible proof technique:**
   - Create `tools/harness/poc_templates/sqli_union_based.py` (NOT time-based — SQLite has no SLEEP):
     - Takes target URL + parameter name as env vars
     - Sends UNION SELECT payload to extract data (e.g., `' UNION SELECT sqlite_version(),null,null--`)
     - If response contains extracted data (sqlite version string) → confirmed
     - Also sends error-based payload (e.g., `' AND 1=CAST((SELECT sqlite_version()) AS INT)--`)
     - Returns evidence bundle: request, response body, extracted data, proof type
   - Create `tools/harness/poc_templates/path_traversal.py` for CWE-22
4. Create `tools/harness/run_phase04.py`:
   - For each static finding:
     - CWE-89 → `sqli_union_based.py` template
     - CWE-22 → `path_traversal.py` template
   - Start target if HTTP-based (lifecycle above)
   - Run PoC in Docker sandbox via `run_poc.py --network pentest-net`
   - Record evidence bundle
   - Set status: `confirmed` (extracted data or file content), `rejected` (no proof), `inconclusive` (error/timeout)
   - Write `04-verify/verification_evidence.json` and `04-verify/verified_findings.json`

### D10: Phase 05 is a new Joern integration (Codex finding — scope correction)
- `run_joern.py` currently runs ONE broad taint query and returns generic intermediate findings
- D10 requires per-finding Joern queries: for each confirmed finding from Phase 04, build a targeted CPG query
  - Input: confirmed finding with `path`, `line`, `cwe`, `sink` from `verified_findings.json`
  - Query: parameterized Joern CPG query scoped to that file/method, tracing source→sink
  - Output: real taint trace (entry point → data flow path → sink), not just a generic match
- Extend `run_joern.py` to accept `--query` parameter with a Joern Scala expression
- `run_phase05.py` constructs per-finding queries; calls `run_joern.py` once per confirmed finding
- Variant search: after taint trace confirmed, run a second query scanning for same sink pattern elsewhere in repo
- RCA bundle per finding: taint trace text + variant count + patch guidance
- Output: `05-rca/rca_and_variants.json` with per-finding RCA bundles

### D11: Phase 06 — Report Generator
**Problem:** Need audit-quality report from confirmed findings.

**Actions:**
1. Create `tools/harness/run_phase06.py`:
   - Read confirmed findings + evidence + RCA
   - Generate markdown report with:
     - Executive summary (N findings, severity distribution)
     - Per-finding: file/line, CWE, severity, evidence (PoC output), taint trace, remediation, variant status
   - **Confirmed findings only in main report body** (per methodology in agent.md)
   - **Inconclusive findings in separate appendix** (not in main findings section)
   - Write `06-report/final_report.md` + `06-report/final_report_items.json`

### D12: End-to-End Integration
**Problem:** Need to wire all phases together and prove the full pipeline works.

**Actions:**
1. Wire `run_master_workflow.py` to dispatch to real phase scripts:
   - Phase 01: intake logic (built into master workflow)
   - Phase 02: `detect_repo_profile.py` (exists)
   - Phase 03: `run_phase03.py` (new)
   - Phase 04: `run_phase04.py` (new)
   - Phase 05: `run_phase05.py` (new)
   - Phase 06: `run_phase06.py` (new)
   - Real runs emit `"simulated": false` in run_state.json
2. Create `tests/test_e2e_vertical_slice.py` marked as integration test:
   - Run full pipeline against vuln-flask-app fixture
   - Assert: at least 1 confirmed SQLi finding with UNION-based evidence
   - Assert: false positive (parameterized query) correctly rejected
   - Assert: report main body contains file/line, PoC output, RCA, remediation
   - Assert: inconclusives in appendix, not main body
   - Assert: all artifact contract schemas validate
   - Assert: `run_state.json` has `"simulated": false`
3. Wire into CI:
   - `make test` runs unit tests (no Docker required)
   - `make test-integration` runs E2E tests (requires Docker + tools)
   - CI workflow has separate job for integration with Docker setup
4. Ensure all existing tests still pass

## Sequencing (Final — CI last, bootstrap explicit)

```
Part 1 (Foundation):
  D1 (context detox) ──┐
  D2 (reproducibility)──┼── parallel
  D3 (shim markers)  ──┘
           |
           v
  D4 (phase config + orchestrator bootstrap) -- creates run_master_workflow.py + init_artifact_run.py
           |
           v
  D5 (foundation tests) -- needs D3 + D4
           |
           v
  D6 (CI enforcement) -- LAST in Part 1

Part 2 (Vertical Slice):
  D7 (test fixture + Docker network) -- can start parallel with Part 1
           |
           v
  D8 (Phase 03) -- needs D4 (orchestrator) + D7 (fixture)
           |
           v
  D9 (Phase 04 + network fix + SQLite-compatible PoC) -- needs D8 + D7
           |
           v
  D10 (Phase 05) -- needs D9
           |
           v
  D11 (Phase 06) -- needs D10
           |
           v
  D12 (E2E integration + CI wiring) -- needs D8-D11 + D5
```

## Learnings from v5.2 (teammate release)

Comparative analysis (`docs/research/teammate-release-zerokit2-v52-comparative-analysis.md`)
identified specific artifacts worth importing. We are NOT merging architectures — V3's
agent-centric model and v5.2's pipeline model are load-bearing opposites. But v5.2 has
concrete, importable knowledge-base assets that fill real gaps.

### Imported: PoC template library (8 new templates)

**Justification:** V3's Phase 04 requires the agent to write PoC scripts from scratch.
v5.2 ships 8 CWE-mapped templates we were missing (`auth_bypass_check`, `deserialization`,
`hardcoded_creds`, `info_disclosure`, `missing_auth`, `nosql_injection`, `open_redirect`,
`path_traversal`, `resource_exhaustion`). These are standalone Python scripts with
`{{TARGET}}`/`{{PAYLOAD}}` placeholders — no LLM coupling, no pipeline dependency.
They slot directly into `.agent/knowledge_base/templates/poc/` as agent reference material.
The agent reads these, adapts them to the target, and runs via `run_poc.py`.

### Imported: 3-strategy verification rotation (Phase 04 guidance)

**Justification:** V3's Phase 04 retries inconclusive findings but gives no structured
guidance on *what* to try next. v5.2's verifier rotates through 3 strategies:
1. **Standard** — direct payload (SQLi string, XSS tag, etc.)
2. **Time-based** — blind detection via delay injection (e.g. `SLEEP(5)`)
3. **Error-based** — trigger distinctive error messages revealing internals

This is a methodology improvement, not code. Added to `agent.md` Phase 04 as agent
guidance — the agent decides which strategy to apply, consistent with the V3 model.

### Planned: SARIF output format (D11)

**Justification:** v5.2 generates SARIF for GitHub Code Scanning integration. V3's
Phase 06 report generator (D11) should support SARIF as an optional output format
alongside the primary JSON report. Useful for CI/CD integration — GitHub, GitLab,
and Azure DevOps all consume SARIF natively. Added to D11 scope.

### Planned: Joern query library reference (D10)

**Justification:** v5.2's `core/tools/joern_queries.py` (400 LOC) has pre-defined CPG
patterns for C, Java, JS, Python, Go. V3's `run_joern.py` currently accepts arbitrary
Joern queries but ships no query library. Extracting v5.2's patterns as a reference
document in `.agent/knowledge_base/references/` gives the agent concrete taint queries
to use in Phase 05 instead of generating them from scratch.

### Deferred: Multi-repo variant analysis

**Justification:** v5.2's Phase 8 MRVA hunts patterns across multiple repos. V3's Phase 05
does single-repo variant search via Joern. MRVA is valuable but requires cross-repo
tooling infrastructure that is not in V3's current scope. Tracked for future consideration.

### NOT importing: autonomous orchestration, LLM-coupled tools, in-memory artifacts

These are v5.2's core architecture decisions and are incompatible with V3's agent-centric
model. Importing them would require choosing v5.2's philosophy and abandoning V3's. See
section 13 of the comparative analysis for detailed reasoning.

## Out of Scope
- Multi-language support (Java, Go, TS -- deferred)
- Scanner ingest / SARIF adapter (deferred — partial D11 SARIF planned)
- Async/concurrent execution model (deferred)
- Language profiling hardening (deferred)
- Production codebase testing (deferred)
- `init_artifact_run.py` external-agent invocation testing (standalone use deferred)
- Multi-repo variant analysis (v5.2 learning, deferred)

## Implementation Notes (from eng review)

### D1: CI checker scope
- `check_stale_references.py` must scan **entire repo** (not just `.agent/`, `docs/`, root `*.md`)
- Exclusions: `.git/`, `node_modules/`, `__pycache__/`, `.codex-review/`, `.venv/`

### D3: `simulated` is required, not optional
- Move `simulated` from `optional_fields` to `required_fields` in `artifact_contract.json` run_state section
- Every `run_state.json` must explicitly declare `"simulated": true` or `"simulated": false`
- `validate_run_artifacts.py` reads it as required; existing test fixtures need the field added

### D4: Required sequencing within the task
1. Create `_phase_config.py` shared loader first
2. Migrate `validate_run_artifacts.py` + `check_workflow_integrity.py` → loader (remove 7 hardcoded phase-dir strings)
3. Only then create `run_master_workflow.py` + `init_artifact_run.py` (both use loader)
- `init_artifact_run.py` stays as a standalone tool (can be invoked by agent independently)
- Critical gap to handle: missing `phase_config.json` → raise `FileNotFoundError` with clear message, not silent import crash
- Critical gap to handle: duplicate `run_id` → raise explicit error, do not silently overwrite

### D4: Phase 02 artifact gap (Codex finding)
- `artifact_contract.json` and `validate_run_artifacts.py` require `02-surface/attack_surface.json`
- But Phase 02 is `detect_repo_profile.py`, which produces `repository_profile.json` — not `attack_surface.json`
- Resolution: `run_phase03.py` (D8) is responsible for deriving `attack_surface.json` from the profile:
  - Reads `repository_profile.json`, extracts `entrypoints` + `high_risk_sinks`, writes `02-surface/attack_surface.json`
  - Phase 03 already has full context to do this (it reads the profile to select Semgrep rules)
- Update `run_master_workflow.py` to pass `repository_profile.json` path to `run_phase03.py`
- This is a one-time fix — do not change `detect_repo_profile.py` output schema

### D5: Test scope boundary
- `run_master_workflow.py` tests in D5 cover **dry-run mode only** (`--dry-run`, `"simulated": true`)
- Real-mode dispatch tests live in D12 (E2E) — not D5
- Add comment in test file: `# Real-mode dispatch tested in test_e2e_vertical_slice.py`

### D6: Already ~80% done
- `.github/workflows/harness-guardrails.yml` already has `pip install -e ".[dev]"`, `make lint`, `make test`
- Remaining: (1) add separate integration job with Docker setup, (2) verify `make check` is called as a target

### D8: Language→ruleset mapping (required, explicit)
- Add this mapping to `run_phase03.py`:
  ```python
  LANGUAGE_RULESETS = {
      "python": ["p/python", "p/security-audit"],
      "javascript": ["p/javascript", "p/security-audit"],
      "typescript": ["p/typescript", "p/security-audit"],
      "java": ["p/java", "p/security-audit"],
      "go": ["p/golang", "p/security-audit"],
  }
  DEFAULT_RULESETS = ["p/security-audit"]
  ```

### D7: Docker network name fix (Codex finding)
- `docker-compose.yml` MUST include an explicit `name: pentest-net` under the `networks` section
- Without this, Compose creates `<project>_pentest-net` (e.g. `vuln-flask-app_pentest-net`), not the literal `pentest-net`
- `run_poc.py --network pentest-net` and `docker network inspect pentest-net` both fail against the prefixed name
- Fix: add to docker-compose.yml:
  ```yaml
  networks:
    pentest-net:
      name: pentest-net   # force literal name, no project prefix
      driver: bridge
  ```

### D9: Critical implementation details
- Network name is guaranteed by D7 fix above — no runtime discovery needed
- `run_poc.py --network` flag requires env-var passthrough: add `--env KEY=VALUE` forwarding to `docker run` invocation
- Explicit check: if `docker network inspect pentest-net` fails → raise clear error before attempting PoC

### D12: Runtime assertion required
- E2E test must assert `elapsed < 300` (5-minute success criterion #10):
  ```python
  start = time.time()
  # ... run pipeline ...
  assert time.time() - start < 300, "Pipeline exceeded 5-minute limit"
  ```
- E2E test must use `try/finally` to tear down Docker containers even on failure

## Success Criteria
1. `make check` passes (includes stale reference check, contract validation)
2. `make test` passes with all unit/behavioral tests green
3. `make test-integration` passes with E2E test green (requires Docker)
4. `make lint` passes
5. Zero stale reference tokens — repo-wide scan (not just .agent/)
6. Pipeline produces audit-quality report from vuln-flask-app fixture
7. Report main body contains >= 1 confirmed SQLi with: file path, line number, UNION-based PoC output, taint trace, remediation
8. Inconclusives in appendix, not main report body
9. False positive in fixture correctly rejected
10. Total pipeline runtime < 5 minutes on fixture (asserted in E2E test)
11. Existing tests unchanged and passing
12. `run_state.json` shows `"simulated": false` for real runs (required field, not optional)

## Dependencies
- Docker + Docker Compose available for PoC sandbox and target lifecycle
- Semgrep CLI 1.60.0 installed
- Gitleaks 8.18.4 installed
- Joern server 4.0.0 available (Phase 05)
- Python 3.11+

## GSTACK REVIEW REPORT

| Review | Trigger | Why | Runs | Status | Findings |
|--------|---------|-----|------|--------|----------|
| CEO Review | `/plan-ceo-review` | Scope & strategy | 0 | — | — |
| Codex Review | `/codex review` | Independent 2nd opinion | 0 | — | — |
| Eng Review | `/plan-eng-review` | Architecture & tests (required) | 1 | issues_open (PLAN) | 8 issues, 3 critical gaps |
| Design Review | `/plan-design-review` | UI/UX gaps | 0 | — | — |

**OUTSIDE VOICE (Codex gpt-5.4 xhigh):** 13 findings — Docker network literal name bug, D10 scope understatement (new Joern integration required), Phase 02→03 `attack_surface.json` wiring gap, `tool-versions.json` not consumed anywhere, 5-min criterion unengineered for cold CI.

**CROSS-MODEL:** Codex and eng review agree on Docker network issue (5A) and D10 scope. Codex overrides eng review decision 3B — `init_artifact_run.py` standalone use is deferred; Codex argues no justified consumer exists yet. Kept as standalone per user decision but flagged.

**UNRESOLVED:** 0 unresolved decisions.

**VERDICT:** ENG REVIEW issues addressed in Implementation Notes. All cross-model tensions surfaced. Eng review required before ship.
