# Comparative Analysis: ZeroKit V3 (Dev) vs. ZeroKit2 v5.2 (Teammate Release)

**Date:** 2026-03-25
**Author:** Claude Code (research pass — parallel deep reads of both repositories)
**Scope:** Full technical comparison — architecture, methodology, implementation depth,
philosophy, and strategic alignment between the two codebases.

---

## 1. TL;DR

These are two different software artifacts pursuing the same security mission, built from
different starting assumptions, at dramatically different stages of maturity.

| Dimension | ZeroKit V3 (dev) | ZeroKit2 v5.2 (teammate) |
|-----------|-----------------|--------------------------|
| Identity | Harness / methodology layer | Autonomous pipeline engine |
| Primary abstraction | **Agent does the thinking** | **Code does the orchestration** |
| Phase count | 6 phases | 9 phases |
| LOC (Python) | ~8,000 (tools + tests) | ~41,000 |
| Test coverage | 8 files, targeted behavioral | 147+ tests, broad |
| LLM coupling | Zero — agent runtime is external | Deep — 3 LLM providers, gateway, cache |
| Artifact contracts | Formal JSON schema, CI-enforced | Implicit in Pydantic models |
| Entry point | Agent reads `.agent/agent.md`, decides | `python scripts/hunt_pipeline.py <target>` |
| Maturity | Foundation hardening in progress (W3) | Production-grade, active development |
| Core claim | "No proof, no vulnerability" | "No proof, no vulnerability" (shared) |

They share a lineage and a hard rule. They have taken opposite routes to get there.

---

## 2. Fundamental Philosophy Divergence

This is the most important thing to understand before comparing anything else.

### 2.1 ZeroKit V3 — Agent-Centric Harness

V3's core thesis (from `.agent/HARNESS_SCOPE.md`):

> The agent runtime IS the reasoning engine. The harness provides: methodology,
> tool connectors, artifact contracts, evidence gates, domain knowledge. The agent
> provides: reasoning, context, decisions, judgment — like a human pentester.

Under this model:
- The human-analogy is a **skilled consultant** who has been handed a well-organized toolkit
- The agent (OpenCode, Claude Code, Codex) reads the methodology, decides what to run, runs
  narrow tool executors, reads the output, and decides what to do next
- No tool invokes another tool automatically — there is no autonomous chain
- The harness enforces quality gates (artifact contracts, CI checks) but does not orchestrate
- The result is only as good as the agent's judgment

The consequence: V3 is essentially **a methodology and a set of tool adapters packaged for an
AI agent to wield**. The "product" is the harness layer, not a standalone binary.

### 2.2 ZeroKit2 v5.2 — Pipeline Orchestrator

v5.2's thesis (from `README.md`):

> ZeroKit2 is a powerful agentic security pipeline designed to map codebases,
> generate complex security hypotheses, and verify them using automated dynamic analysis.

Under this model:
- The orchestrator (`core/orchestrator.py`, 43 KB) is the brain
- It drives phases sequentially: threat model → detect → triage → verify → RCA → variant → patch
- LLM calls are embedded in each agent class (`threat_modeler.py`, `verifier.py`, etc.) via a
  gateway (`core/llm_gateway.py`)
- The pipeline can run end-to-end from a single CLI command with no human in the loop
- The result depends on how well the pipeline handles edge cases in its code

The consequence: v5.2 is a **standalone autonomous tool** that happens to accept LLM provider
configuration. The "product" is a working pipeline binary.

### 2.3 Judgment

Neither approach is wrong. They solve different problems:

- V3 is correct for **whitebox audit depth** — a human or agentic expert driving the
  investigation, with the harness providing structure and tooling
- v5.2 is correct for **automated coverage at scale** — scan many repos fast, catch the
  low-hanging fruit, free up humans for the hard cases

The risk of V3 without an excellent agent: shallow analysis due to agent reasoning limitations.
The risk of v5.2 without robust validation: false confidence — the pipeline ran, so it must be right.

Both repos share the "no proof, no vulnerability" rule. V3 enforces it via artifact contracts
and evidence gates. v5.2 enforces it via the verifier agent and PoC execution in Docker.

---

## 3. Methodology: 6-Phase vs. 9-Phase

### 3.1 V3 — 6 Phases

```
01 Intake      → run scope, constraints, assessment depth
02 Surface     → language detection, entrypoints, attack surface
03 Static      → threat model + Semgrep + Gitleaks + merge → static_findings.json
04 Verify      → PoC in Docker → verification_evidence.json + verified_findings.json
05 RCA         → Joern taint flow, variant search, patch guidance
06 Report      → confirmed findings only (inconclusives in appendix)
```

**Phase transitions are agent-driven.** The agent reads `static_findings.json`, decides which
findings to pursue in Phase 04, crafts PoC scripts, runs `run_poc.py`, reads the output, and
writes `verified_findings.json`. At each phase boundary, `validate_run_artifacts.py` checks
that required artifact fields are present.

The agent may also short-circuit or loop: skip Phase 05 if there are no confirmed findings,
revisit Phase 03 if a hypothesis reveals a new attack surface, escalate Phase 04 from
`--network none` to `--network pentest-net` for HTTP targets.

### 3.2 v5.2 — 9 Phases

```
Phase 1  Baseline Setup       → build checks, existing tests via Adapter Layers
Phase 2  Surface Mapping       → entry points, sinks via grep patterns
Phase 3  Threat Modeling       → CWE-mapped hypothesis generation (LLM call)
Phase 4  Hybrid Scanning       → Semgrep + CodeQL + Joern + Gitleaks + Trivy (parallel)
Phase 5  Intelligent Triage    → filter, classify, deduplicate findings (±5 lines, CWE grouping)
Phase 6  PoC Verification      → generate + execute repro.py in Docker (3-strategy rotation)
Phase 7  Root Cause Analysis   → crash dump analysis, faulty line identification (LLM call)
Phase 8  Variant Analysis      → extract patterns, hunt similar bugs across repo
Phase 9  Remediation + Report  → patch generation, JSON/HTML/SARIF/XML output
```

**Phase transitions are code-driven.** `core/orchestrator.py` calls each agent class in
sequence. Agents write to a shared `PipelineContext` object that is passed forward. There
is no artifact contract validation step — the pipeline continues as long as no exception
is raised.

### 3.3 Key Differences in Phase Structure

| Aspect | V3 | v5.2 |
|--------|----|------|
| Fuzzing | Planned (D7+ vertical slice) | Phase 1 baseline + dedicated `harness_agent.py` |
| Triage/dedup | `merge_findings.py` (Phase 03) | `finding_correlator.py` (Phase 5, ±5 line bucketing) |
| Variant analysis | Phase 05 (Joern, agent-driven) | Phase 8 (dedicated agent, LLM pattern extraction) |
| Patching | Phase 05 guidance only | Phase 9 `patcher.py` (LLM generates patch code) |
| Multi-repo hunting | Not yet (research notes mention it) | Phase 8 explicit MRVA support |
| Phase config | `phase_config.json` SSoT, shared loader | Code constants in `orchestrator.py` |
| Phase gating | Artifact contract validation (JSON schema) | Exception-based (pipeline fails or continues) |

---

## 4. Technical Architecture: Side by Side

### 4.1 Entry Points and Execution Model

**V3:**
```
Agent opens opencode-b, reads .agent/agent.md
Agent reads phase_config.json
Agent decides: "run Phase 02 on this target"
Agent runs: python tools/harness/detect_repo_profile.py --target ... --output ...
Agent reads repository_profile.json
Agent decides next step
```

**v5.2:**
```bash
python scripts/hunt_pipeline.py /path/to/target
  → core/orchestrator.py.__init__(target)
  → orchestrator.run_phase_1_baseline()
  → orchestrator.run_phase_2_surface_mapping()
  → orchestrator.run_phase_3_threat_modeling()
  → ... (each phase calls the relevant agent class)
  → report.generate()
```

### 4.2 LLM Integration

**V3:** Zero LLM coupling in the harness code. There are no LLM API calls anywhere in
`tools/harness/` or `tools/ci/`. The agent reads `.agent/knowledge_base/prompts/` templates
as guidance, but the prompts are markdown documents — they're reference material, not
programmatic calls. The agent runtime handles all inference.

**v5.2:** Deep LLM integration throughout:
- `core/llm_gateway.py` — central inference interface (~219 LOC)
- `core/llm_provider.py` — factory: `create_provider("antigravity"|"opencode"|"claude")`
- `core/llm_cache.py` — response caching
- `core/response_models.py` — Pydantic validation of LLM JSON responses
- Provider adapters: `antigravity_adapter.py` (file-based polling), `opencode_provider.py`,
  `claude_provider.py`
- Agents that make LLM calls: `threat_modeler.py`, `verifier.py`, `root_cause_analyst.py`,
  `patcher.py`, `variant_analyzer.py`, `harness_agent.py`

The v5.2 Antigravity provider is particularly interesting: it uses **file-based polling**
(write prompt to queue dir → poll response dir → read result). This decouples the pipeline
from API latency and allows any LLM runtime that can watch a directory to serve as the backend.
The V3 design essentially implements this at a higher level — the entire agent session IS the
"Antigravity worker."

### 4.3 Data Models

**V3** — JSON artifacts with formal contracts:
```json
// All artifacts validated against artifact_contract.json
{
  "run_id": "run-20250325-abc123",
  "generated_at": "2025-03-25T12:00:00Z",
  "items": [
    {
      "id": "sf-001",
      "tool": "semgrep",
      "severity": "high",
      "path": "src/api/users.py",
      "line": 42,
      "evidence": "...",
      "cwe": "CWE-89",
      "source": "orchestration-shim",
      "simulated": false
    }
  ]
}
```

**v5.2** — Python dataclasses/Pydantic models:
```python
class StaticFinding:
    tool: str           # "semgrep" | "codeql" | "joern" | ...
    location: str       # file:line
    severity: str       # "high" | "medium" | "low"
    cwe: str
    description: str

class VerifiedVuln:
    finding: StaticFinding
    poc_script: str
    status: str         # "confirmed" | "rejected" | "inconclusive"
    root_cause: str

class PipelineContext:
    repo: str
    findings: list[StaticFinding]
    hypotheses: list[Hypothesis]
    verified_vulns: list[VerifiedVuln]
    # ...passed through all phases
```

**Key difference:** V3 artifacts are language-agnostic JSON files on disk that any tool (or
human) can read and validate independently. v5.2 artifacts live in memory as Python objects;
they're serialized only for the final report. V3 artifacts are durable, inspectable, and
independently verifiable at every phase boundary. v5.2 artifacts are ephemeral within the
pipeline run.

### 4.4 Tool Runners

Both projects cover the same core tools, with different wrapping strategies:

| Tool | V3 Implementation | v5.2 Implementation |
|------|------------------|---------------------|
| Semgrep | `run_semgrep.py` (180 LOC) — subprocess, normalize to intermediate JSON | `tools/semgrep_runner.py` (180 LOC) — subprocess, returns `list[StaticFinding]` |
| Gitleaks | `run_gitleaks.py` (200 LOC) | `tools/gitleaks_runner.py` (150 LOC) |
| Joern | `run_joern.py` (280+ LOC, HTTP server mode) | `tools/joern_runner.py` (280 LOC) + `joern_queries.py` (400 LOC pre-defined CPG queries) |
| Docker | `run_poc.py` (sandbox executor, `--network none`) | `tools/sandbox_executor.py` (subprocess limits) |
| CodeQL | Not yet implemented (planned) | `tools/codeql_runner.py` (200 LOC) |
| Trivy | Not in scope | `tools/trivy_runner.py` (130 LOC) |
| Finding dedup | `merge_findings.py` (17 KB) — hypothesis linking + CWE dedup | `tools/finding_correlator.py` (200 LOC) — ±5 line bucketing + CWE grouping |

**V3 tool runners output JSON files.** The agent reads those files and decides what to do next.
**v5.2 tool runners return Python objects.** The orchestrator passes them to the next agent.

V3's approach is more **auditable** — every intermediate result is inspectable on disk,
even if the pipeline crashes mid-run. v5.2's approach is more **efficient** — no disk I/O
between phases, but if the pipeline crashes in Phase 7, you lose Phase 5 context unless
`state_manager.py` has checkpointed it.

### 4.5 Deduplication Logic

**V3 (`merge_findings.py`, 17 KB):**
- Groups by `(path, line, rule)` canonical key
- Links each finding to a hypothesis from `hypotheses.json` by path/line proximity
- Severity precedence: `critical > high > medium > low`
- Writes `static_findings.json` with `hypothesis_id` cross-references
- Produces deduplication report (how many merged, from which tools)

**v5.2 (`tools/finding_correlator.py`, ~200 LOC):**
- Line bucketing: findings within ±5 lines → same location
- CWE-aware grouping: same CWE at nearby locations → same vulnerability class
- Severity ranking: keeps highest severity representative
- Tool corroboration: tracks which tools confirmed the same finding
- Claims ~70% reduction in false positives

V3's dedup is **hypothesis-linked** — it knows which findings correspond to which threat model
hypothesis. v5.2's dedup is **proximity-based** — it's purely spatial/taxonomic. V3's approach
gives the agent better reasoning context ("this finding confirms hyp-002"); v5.2's approach is
more scalable for automated triage.

### 4.6 PoC Verification Strategy

**V3 (`run_poc.py`):**
- Agent writes the PoC script based on the finding
- `run_poc.py` executes it in Docker with `--network none`
- Output captured, exit code checked
- Agent reads the log and determines `confirmed | rejected | inconclusive`
- Phase D9 (planned) will add `--network pentest-net` for HTTP targets

**v5.2 (`core/agents/verifier.py`, 16 KB):**
- 3-strategy rotation for automated PoC generation:
  1. **Standard** — Direct malicious input (SQLi payload, XSS string, etc.)
  2. **Time-Based** — Timing analysis (detect blind SQLi via response delay)
  3. **Error-Based** — Trigger revealing error messages
- LLM generates the PoC script via `prompts/verifier/generate_poc.md` template
- Docker sandbox execution via `sandbox_executor.py`
- CWE-mapped PoC templates in `.agent/templates/poc/` (25+ templates: python, php, go)
- 3-attempt rotation: try strategy 1, if inconclusive try 2, if inconclusive try 3

V3's approach requires a skilled agent to write the PoC. v5.2's approach automates PoC
generation using LLM + templates. V3 produces higher-fidelity PoCs for complex targets;
v5.2 handles common CWE patterns automatically.

One critical observation: **v5.2 has 25+ CWE-mapped PoC templates in `.agent/templates/poc/`**.
These are in the `zerokit2` repo but completely absent in V3's `.agent/` directory. This is
a material gap in V3's knowledge base that should be evaluated for import.

---

## 5. Skills Catalog

### 5.1 V3 Skills (30 directories in `.agent/skills/`)

Organized around **pentest methodology**:
- Core: `hunt-semgrep`, `hunt-gitleaks`, `hunt-threat-modeler`, `sast-semgrep`
- Language packs: python, java, node, go, csharp, php security patterns
- Advanced: `variant-analysis`, `differential-analysis`, `cve-pattern-mining`
- API: `api-patterns` (10 sub-files: REST, GraphQL, tRPC, auth, rate-limiting)
- Fuzzing: `aflpp-testing`, `atheris-python-fuzzing`, `libfuzzer-patterns`, `oss-fuzz-integration`
- Utilities: `architecture-mapper`, `sarif-processing`, `entry-point-discovery`

These are **agent knowledge modules** — structured markdown that the agent reads to understand
how to use a tool or apply a technique. They are consumed by the agent at reasoning time.

### 5.2 v5.2 Skills (60+ directories in `skills/`)

Structured around **tool coverage and pipeline integration**:
- Mirrors V3 core skills but with additional entries:
  - `hunt-nuclei` (web scanning)
  - `parallel-agents` (multi-agent coordination)
  - `anthropic` (Anthropic API integrations)
  - `architecture-mapper`
  - `insecure-defaults-audit`
  - `target-acquisition`
- Also has `skills/zerokit/SKILL.md` — the Claude Code skill definition for the pipeline

The v5.2 skills catalog is **larger** (60+ vs 30) but structured differently — many entries
appear to be Claude Code workflow recipes (see `skills/zerokit/references/`) rather than
pure knowledge modules.

### 5.3 Assessment

V3's skills are more **conceptually coherent** — each directory represents a discrete
pentest capability. v5.2's skills mix workflow recipes, tool knowledge, and metadata.

However, v5.2 has meaningful additions that V3 lacks: `hunt-nuclei`, `parallel-agents`,
and `anthropic` integrations. These should be evaluated for V3 import.

---

## 6. Testing Philosophy

### 6.1 V3 — Behavioral + Contract Testing

**Strategy:** Test that each tool connector produces the correct output shape for given inputs.
Tests are independent of each other and do not require a full pipeline run.

```
tests/
  test_detect_repo_profile.py   → language detection, fixture validation
  test_merge_findings.py        → deduplication logic, hypothesis linking
  test_phase03_e2e.py           → Semgrep + Gitleaks + merge full Phase 03 flow
  test_run_semgrep.py           → severity normalization, path relativization
  test_run_gitleaks.py          → secret detection normalization
  test_run_joern.py             → CPG taint analysis
  test_run_poc.py               → Docker sandbox execution
  test_validate_run_artifacts.py → artifact contract validation
```

**Test count:** 8 files, estimated 400-600 individual test cases.
**Markers:** `@pytest.mark.integration` gates tests requiring external tools (Semgrep, Docker).
**Default run:** `make test` runs only non-integration tests.

**CI enforcement:** `tools/ci/` has 7 additional check scripts that run at CI time:
stale reference detection, scope boundary checks, workflow integrity, artifact contract
validation. These are NOT pytest tests — they are standalone scripts that exit non-zero
on violation.

### 6.2 v5.2 — Full Coverage Testing

**Strategy:** Test all components of the pipeline, including LLM interaction mocking,
provider selection, and edge cases.

```
tests/
  test_llm_provider.py          → multi-provider abstraction, factory pattern
  test_finding_correlator.py    → deduplication correctness
  test_joern_queries.py         → CPG query correctness
  test_verifier_strategies.py   → 3-strategy rotation logic
  test_response_models.py       → Pydantic validation
  test_threat_modeler.py        → hypothesis generation
  test_detector.py              → SAST orchestration
  test_integration.py           → pipeline integration
  ... (147+ total)
fixtures/
  xss.py, sqli.php, wp_advanced.php   → vulnerable target fixtures
```

**Test count:** 147+ across unit, integration, LLM, edge case categories.
**Distribution:**
- 35 unit (agents)
- 40 unit (tools)
- 25 integration (pipeline stages)
- 20 LLM (provider, validation, caching)
- 27 edge cases (errors, timeouts, malformed input)

### 6.3 Assessment

v5.2 has **significantly more test coverage** by raw count. However, V3's tests are more
**architecturally meaningful** — they test the exact integration points where the agent
hands off to tools. V3's CI check scripts (`tools/ci/`) have no equivalent in v5.2 — they
enforce methodology integrity, not just code correctness.

V3 has a gap: no tests for the master orchestrator (because it doesn't exist yet — D4 blocker).
v5.2 has a gap: no equivalent of V3's scope/stale-reference CI enforcement.

---

## 7. Language Support

| Language | V3 Support | v5.2 Support |
|----------|-----------|--------------|
| Python | Full (patterns, Semgrep, Joern) | Full (Django/Flask profiles, CodeQL) |
| Java | Semgrep + Joern (Spring patterns) | Full (Spring Boot, CodeQL, Joern) |
| JavaScript/TypeScript | Semgrep + patterns | Full (Express/Node, CodeQL) |
| Go | Semgrep + patterns | Full (CodeQL, Joern) |
| PHP | Semgrep + patterns | Full (WordPress, Joern) |
| C/C++ | Joern only | Joern + CodeQL |
| C# / .NET | Semgrep + patterns | Full (ASP.NET, CodeQL) |
| Ruby | Not in scope | CodeQL |

**v5.2 has deeper language support**, particularly for C/C++, Ruby, and C#. This is because
it ships `core/profiles.py` (410 LOC) — a language profile factory that builds `SecurityProfile`
objects with language-specific sources, sinks, sanitizers, and detection patterns. V3 handles
this via the `.agent/knowledge_base/adapters/` YAML files (4 frameworks: Spring, Express,
Flask, ASP.NET), but only for framework detection, not profiling.

V3's approach keeps the profile logic in agent-readable YAML. v5.2 compiles it into Python
code. The tradeoff: v5.2 profiles are more precise (code can be complex); V3 profiles are
more extensible (add a YAML file without a code change).

---

## 8. CI / Quality Enforcement

### 8.1 V3 CI Pipeline

**GitHub Actions:** `.github/workflows/harness-guardrails.yml`
**Makefile:** `make check`, `make test`, `make test-integration`, `make lint`

```
make check:
  python tools/ci/check_scope_boundaries.py
  python tools/ci/check_stale_references.py
  python tools/ci/validate_artifact_contract.py
  python tools/ci/validate_language_detector_contract.py
  python tools/ci/test_language_detector_fixtures.py

make test:
  python -m pytest tests/ -v (non-integration only)

make lint:
  python -m ruff check .
```

**What V3 CI catches that v5.2 does not:**
- Stale references to old architecture (ZeroKit2, hunt-pipeline, Antigravity)
- Scope boundary violations (files that should not be in-scope)
- Contract drift (artifact JSON schemas out of sync with what tools produce)

### 8.2 v5.2 CI Pipeline

No CI configuration found in the repository. Tests are run manually via pytest.
The `install.sh` script verifies external tool availability but there is no automated
CI enforcement equivalent to V3's `tools/ci/` suite.

**This is a significant quality gap in v5.2.** There is no automated gate preventing
contract drift, stale references, or scope violations.

---

## 9. DevContainer / Developer Experience

### 9.1 V3

- Full devcontainer with `mcr.microsoft.com/devcontainers/python:1-3.11-bookworm`
- **Two isolated OpenCode profiles**: Profile A (dev) and Profile B (product/testing)
- Profile isolation via `XDG_CONFIG_HOME/XDG_DATA_HOME/XDG_CACHE_HOME` per profile
- Profile switch commands: `opencode-a` / `opencode-b`
- Profile A: develop ZeroKit; Profile B: run ZeroKit against targets
- `postCreate.sh` creates XDG state dirs, symlinks all profile commands
- Profile B (`opencode.jsonc`) loads: `agent.md`, `HARNESS_SCOPE.md`, `phase_config.json`
- Tools installed in container: `uv`, `bun`, `semgrep`, `gitleaks`, `opencode`

### 9.2 v5.2

- No devcontainer configuration found
- `install.sh` script handles system-level setup (detects OS, installs deps, registers Claude skill)
- `.env` file for runtime configuration
- No profile isolation concept — single global environment

V3's dual-profile devcontainer is architecturally superior for the "two hammers" use case:
Profile A (work on ZeroKit) and Profile B (use ZeroKit as a pentester). v5.2 has no
equivalent because it's not designed to be developed and used in parallel isolation.

---

## 10. Report Output

### 10.1 V3

Report output is defined in `phase_config.json` and driven by the agent reading
`phase-06-report-regression.md`. The format is guided by methodology:
- **Main body:** Only `confirmed` findings with evidence refs
- **Appendix:** `inconclusive` findings (not in main body)
- **Rejected:** Not included at all
- Format: Agent-generated markdown/JSON, no hardcoded report renderer

The report generator (`run_phase06.py`) does not yet exist — it is Task D11 in the plan.

### 10.2 v5.2

`core/agents/reporter.py` generates structured reports. Supported formats:
- JSON (structured finding export)
- HTML (human-readable with severity colors)
- SARIF (GitHub Code Scanning compatible)
- XML (OWASP-compatible)

v5.2 has **significantly more mature report output** — four output formats, production-quality
HTML rendering. V3 has a better-defined separation of confirmed vs. inconclusive findings.

---

## 11. Specific V3 Gaps Identified by Comparison

Areas where v5.2 has concrete, importable value for V3:

### 11.1 PoC Templates (High Priority)

v5.2 has 25+ CWE-mapped PoC templates in `.agent/templates/poc/`:
- `python/`: SQLi, auth bypass, command injection, path traversal, SSRF, XXE, IDOR, RCE, SSTI
- `php/`: 15+ exploits including CSRF, deserialization, file upload, open redirect
- `go/`: SSRF and others

V3 has no PoC template library. The agent must write PoCs from scratch. Importing these
templates into V3's `.agent/knowledge_base/` would significantly improve V3's Phase 04
quality. License check required before import (v5.2 claims MIT, unverified).

### 11.2 3-Strategy Verification Rotation (Medium Priority)

v5.2's Standard → Time-Based → Error-Based rotation for PoC verification is a concrete
improvement over V3's single-attempt model. V3's Phase 04 specification should incorporate
this pattern, particularly for blind injection detection.

### 11.3 SARIF Output (Low Priority)

v5.2 generates SARIF output, enabling GitHub Code Scanning integration. V3's Phase 06
report generator (Task D11) should consider SARIF as an output option, especially for
CI/CD pipeline integration use cases.

### 11.4 Trivy Integration (Low Priority)

v5.2 includes `tools/trivy_runner.py` for container/OS vulnerability scanning. V3's scope
is source-code analysis, but Trivy fills a dependency-scanning gap that V3 currently has
no equivalent for (beyond Gitleaks secret detection).

### 11.5 Multi-Repo Variant Analysis (Medium Priority)

v5.2's Phase 8 MRVA (Multi-Repo Variant Analysis) is more mature than V3's Phase 05 variant
search. V3 uses Joern CPG queries to find variants within the target repo. v5.2 extracts
a pattern from the confirmed bug and can hunt it across multiple repos. V3's Phase 05
specification should consider this extension.

---

## 12. Specific v5.2 Weaknesses Identified by Comparison

### 12.1 No Artifact Contracts

v5.2 has no formal artifact contract system. Phase outputs are Python objects in memory.
If `threat_modeler.py` returns a `Hypothesis` with missing fields, the pipeline may fail
silently or produce incorrect downstream results. There is no independent validation step
between phases.

V3's artifact contracts + `validate_run_artifacts.py` catch these issues at every phase
boundary. This is a systematic quality advantage for V3.

### 12.2 No Phase Config SSoT

v5.2 hardcodes phase logic in `core/orchestrator.py`. Adding, reordering, or skipping a
phase requires modifying the orchestrator code. V3's `phase_config.json` SSoT allows
phase definitions to be modified in one place, with all consumers (scripts, CI, agent
instructions) reading from it.

### 12.3 No Stale Reference Enforcement

v5.2 has no equivalent of V3's `check_stale_references.py`. There is nothing preventing
the codebase from accumulating outdated references to old tool names, architectural terms,
or deprecated APIs over time.

### 12.4 Pipeline Crash = Lost State

If v5.2's orchestrator crashes in Phase 7, the Phase 5 findings are in memory and lost
(unless `state_manager.py` has checkpointed them). V3's disk-based artifacts are durable —
a crash in Phase 05 does not erase `verified_findings.json` from Phase 04.

The v5.2 `core/state_manager.py` exists to address this, but it adds complexity and is
a single point of failure. V3's approach (each phase writes to disk, validates before
proceeding) is more fault-tolerant by design.

### 12.5 Deep LLM Coupling = Testability Problems

v5.2's agents make LLM calls as a core part of their logic. Testing `threat_modeler.py`
requires either a live LLM provider or a mock. The test suite mitigates this with mocks,
but it means the tests verify mock behavior, not actual LLM response quality. V3's tools
have zero LLM coupling — they are pure CLI wrappers, testable without any LLM.

---

## 13. Strategic Conclusions

### 13.1 What V3 Should NOT Copy from v5.2

**Automated orchestration without agent judgment.** v5.2's pipeline runs end-to-end
automatically. V3's design principle (agent decides, scripts execute) is architecturally
sound and should be preserved. The moment V3 starts chaining tool calls automatically,
it loses the ability to handle unusual targets that don't fit the automated pattern.

**LLM coupling in tool runners.** V3's tool runners (`run_semgrep.py`, `run_poc.py`) are
LLM-agnostic. This is a feature, not a bug. They can be tested without a live LLM, run
in CI without API keys, and debugged without worrying about prompt drift.

**In-memory artifact passing.** V3's disk-based artifacts are more durable, auditable,
and independently verifiable. The agent can inspect any intermediate artifact. An auditor
reviewing the pentest can trace every finding back to raw tool output.

### 13.2 What V3 Should Evaluate for Import

1. **PoC template library** (`templates/poc/`) — 25+ CWE-mapped templates. High value.
   Needs license verification. Would go into `.agent/knowledge_base/templates/poc/`.

2. **3-strategy verification rotation** — The Standard/Time-Based/Error-Based pattern.
   Implement as agent guidance in `phase-04-verification-gate.md`, not as automation.

3. **Skills additions** — `hunt-nuclei`, `parallel-agents`, `anthropic` skills from v5.2's
   60-directory catalog. Evaluate relevance before importing.

4. **SARIF output format** — For Phase 06 report generator (Task D11). Useful for CI/CD
   integration.

5. **Joern queries** (`core/tools/joern_queries.py`, 400 LOC) — Pre-defined CPG patterns
   for C, Java, JS, Python, Go. These would complement V3's `run_joern.py` significantly.
   License: MIT (verify).

### 13.3 What V3 Has That v5.2 Should Adopt

If the teammate intends to continue v5.2 development, the following V3 innovations are
worth backporting:

1. **Artifact contracts with CI enforcement** — Add JSON schemas and a validation step
   between phases. This catches contract drift early.

2. **Stale reference CI check** — Automated enforcement prevents architectural terms
   from bleeding across version boundaries.

3. **Phase config SSoT** — Separate phase definitions from orchestrator code. Makes
   the pipeline easier to extend and reconfigure.

4. **Dual-profile devcontainer** — Profile A (develop the tool) + Profile B (use the tool).
   Essential for dogfooding without contaminating the dev environment.

---

## 14. Repository Metadata

| Metric | V3 (dev) | v5.2 (teammate) |
|--------|---------|-----------------|
| Git branch | (main dev branch) | `feature/restructure` |
| Python files | ~50 (tools + tests + CI) | 220 |
| Total LOC (Python) | ~8,000 | ~41,099 |
| Tests | 8 files | 147+ |
| Skills | 30 directories | 60+ directories |
| PoC templates | 0 | 25+ |
| LLM providers | 0 (external) | 3 (Antigravity, OpenCode, Claude) |
| Report formats | 0 (planned D11) | 4 (JSON, HTML, SARIF, XML) |
| CI enforcement scripts | 7 | 0 |
| Artifact contracts | Formal JSON schema | None (Pydantic models only) |
| Phase config | `phase_config.json` SSoT | Hardcoded in orchestrator |
| DevContainer | Full dual-profile | None |
| Version | 0.1.0 (early dev) | v5.2.1 (production) |

---

*Report generated 2026-03-25 via deep parallel read of both repos.*
*Both repos at: `/home/diabel/Desktop/ZeroKit-V3/zerokit-dev/` and `/home/diabel/Desktop/ZeroKit-V3/zerokit/`*
