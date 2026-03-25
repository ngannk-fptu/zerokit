# ZeroKit V3 — Next Steps, Tool Integration, Containers, Cross-Platform

*Generated: 2026-03-11*

---

## 1. Next Step in the Plan

The P0 hardening work (D1–D6) is done. The 8-week delivery plan (`IMPLEMENTATION_PLAN.md`) places us at the end of **Week 1 / start of Weeks 2–3**.

### Where we are

| Area | Status |
|---|---|
| Phase/artifact schemas frozen | Done |
| CI guardrails (stale refs, docs, scope, contract, fixtures) | Done |
| `pyproject.toml` + reproducible dev environment | Done |
| Behavioral test coverage (18 tests) | Done |
| Phase config single-sourced (`phase_config.json`) | Done |
| Shim transparency (`simulated`, `source` markers) | Done |
| README accurate for V3 | Done |
| GitHub Actions CI enforces all gates | Done |

### What the plan says comes next (Weeks 2–3): Orchestrator MVP

The shim currently seeds placeholder artifacts through all 6 phases but does **no real execution**. From `orchestrator-shim-scope.md`, the full orchestrator target adds:

1. **Real static scanner integration** (Semgrep first, then CodeQL/Joern)
2. **True attack-surface extraction** — move beyond regex language detection to actual entrypoint enumeration per language
3. **Finding normalization + deduplication** — multi-tool outputs → single `static_findings.json`
4. **Candidate handoff to Phase 04** with real `inconclusive` statuses (not seeds)

**The concrete next task is:** implement the Phase 03 Semgrep path end-to-end:
- Run `semgrep scan --config p/security-audit --json` against a target
- Parse SARIF/JSON output
- Normalize into `static_findings` artifact schema
- Deduplicate by `(path, line, rule_id)`
- Write to `03-static/static_findings.json`
- Pass to Phase 04 as real candidates

This is the minimum that makes the harness produce non-simulated output and completes the Weeks 2–3 DoD: *"intake → candidate findings repeatable."*

---

## 2. External Tools Required

These are tools ZeroKit calls as subprocesses or via HTTP API — not Python dependencies.

### Phase 03 — Static Detection

| Tool | Purpose | Phase | License | Notes |
|---|---|---|---|---|
| **Semgrep** | SAST pattern + taint scanning; primary detection engine | 03 | LGPL-2.1 (OSS rules free; Pro rules paid) | Declared in `pyproject.toml` tools group. `semgrep scan --json` gives normalized output. First to wire. |
| **Gitleaks** | Secret / credential detection | 03 | MIT | Single binary, no runtime deps. `gitleaks detect --report-format json` |
| **CodeQL** | Deep dataflow analysis for C#, Java, JS/TS, Python, Go | 03 | MIT (CLI free; Enterprise paid) | Requires `codeql database create` + `codeql query run`. Slower than Semgrep; run on high-priority targets. |
| **Joern** | CPG: taint analysis, source-sink reachability, data flow slices | 02/03/05 | Apache 2.0 | JVM-based. Official Docker image available. Server mode (`joern --server`) exposes HTTP on `:8080`. Best tool for confirming real taint paths that Semgrep misses. See `docs/research/copilot-research-joern-vs-gitnexus-analysis.md`. |

### Phase 04 — Verification

| Tool | Purpose | Phase | License | Notes |
|---|---|---|---|---|
| **Docker** | Isolated PoC execution environment | 04 | Apache 2.0 | Required for sandbox. PoC runs inside ephemeral containers against a clone of the target. Evidence = container stdout/stderr/exit code. |
| **curl / httpx / requests** | HTTP PoC execution for web vulns | 04 | Various (MIT/Apache) | Python `httpx` already available in stdlib-adjacent. For web findings (SQLi, XSS, SSRF). |
| **Python interpreter** | Running generated PoC scripts | 04 | PSF | Already available. PoCs in `.agent/knowledge_base/templates/poc/` are Python. |

### Phase 02 — Surface / Attack-Surface Mapping

| Tool | Purpose | Phase | License | Notes |
|---|---|---|---|---|
| **Tree-sitter** (Python binding) | Fast structural AST extraction for entrypoint discovery | 02 | MIT | Lighter than Joern for Phase 02 pass. `tree-sitter` Python bindings work across all target languages. Use for entrypoint regex → precise AST node replacement. |
| **Joern** (`joern-slice usages`) | Deep call graph + usage slices for high-value targets | 02 | Apache 2.0 | Batch output JSON. Use after Tree-sitter narrows scope. |

### Phase 05 — RCA / Variant / Patch

| Tool | Purpose | Phase | License | Notes |
|---|---|---|---|---|
| **Semgrep** (reused) | Variant scanning with generalized pattern from confirmed finding | 05 | LGPL-2.1 | Same binary. New rule derived from confirmed case, scanned across codebase. |
| **Joern** (reused) | Variant discovery via CPG query over confirmed sink pattern | 05 | Apache 2.0 | CPG already built in Phase 03. Re-query for variants. |
| **diff / patch** | Emit minimal patch diffs | 05 | GPL (system tool) | Standard. `difflib` in Python stdlib is sufficient for generating unified diffs. |

### Summary: External Tool Dependency Matrix

```
Phase 02 (Surface):    tree-sitter, [joern optional]
Phase 03 (Static):     semgrep, gitleaks, [codeql optional], [joern optional]
Phase 04 (Verify):     docker, python, httpx
Phase 05 (RCA):        semgrep (reuse), joern (reuse), difflib
Phase 06 (Report):     none (pure artifact aggregation)
```

---

## 3. Internal Tools (Already in Repo)

These exist in the skills catalog and need connectors wired into the orchestrator:

| Internal Component | Location | Current State | Needs |
|---|---|---|---|
| Semgrep skill | `.agent/skills/hunt-semgrep/SKILL.md` | Documented, no connector | Python connector: subprocess + JSON parse + normalize |
| Gitleaks skill | `.agent/skills/hunt-gitleaks/SKILL.md` | Documented, no connector | Python connector: subprocess + normalize |
| Threat modeler | `.agent/skills/hunt-threat-modeler/SKILL.md` | Documented, no connector | LLM call wrapper (hypothesis generation from surface JSON) |
| SARIF processing | `.agent/skills/sarif-processing/` | Script exists (`sarif_helpers.py`) | Import into normalizer |
| Dependency analysis | `.agent/skills/dependency-analysis/` | Skill doc only | Connector for `npm audit`, `pip-audit`, `dotnet list` |
| Variant analysis | `.agent/skills/variant-analysis/` | Skill doc only | Uses Semgrep with derived rule |
| Patch verification | `.agent/skills/patch-verification/` | Skill doc only | Re-run PoC post-patch |
| Language security patterns | `.agent/skills/{python,java,go,node,php,csharp}-security-patterns/` | Reference docs | Feed into hypothesis generation |
| PoC templates | `.agent/knowledge_base/templates/poc/` | Python templates exist | Parameterize + execute in Phase 04 sandbox |
| Phase prompts | `.agent/knowledge_base/prompts/{detector,verifier,rca,patcher}/` | Prompt templates | Wire to LLM gateway in Phase 03/04/05 |

---

## 4. Containerization

### Answer: Yes, containerize — but use separate containers per concern, not one monolith.

The tools have incompatible runtimes (JVM for Joern, Go binary for Gitleaks, Python for Semgrep, Node for any GitNexus-adjacent work). A monolith container is fragile and bloated. The right model is **sidecar containers** invoked by the Python orchestrator.

### Proposed Container Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Host / CI runner                                        │
│                                                          │
│  ┌──────────────────────────────────────────────────┐   │
│  │  zerokit-harness (Python orchestrator)           │   │
│  │  python:3.11-slim                                │   │
│  │  - run_master_workflow.py                        │   │
│  │  - artifact store on /runs volume                │   │
│  │  - calls sidecar containers via subprocess/HTTP  │   │
│  └──────────────────────────────────────────────────┘   │
│           │                  │                  │        │
│           ▼                  ▼                  ▼        │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │ zerokit-sast │  │ zerokit-cpg  │  │ zerokit-verif│  │
│  │              │  │              │  │  (sandbox)   │  │
│  │ semgrep      │  │ joern server │  │ docker-in-   │  │
│  │ gitleaks     │  │ (HTTP :8080) │  │ docker or    │  │
│  │ codeql       │  │ + joern-cli  │  │ gVisor/nsjail│  │
│  │              │  │              │  │              │  │
│  │ alpine +     │  │ joernio/joern│  │ python:slim  │  │
│  │ Go runtime   │  │ (AlmaLinux)  │  │ + target app │  │
│  └──────────────┘  └──────────────┘  └──────────────┘  │
│                                                          │
│  Shared volumes:                                         │
│    /target  (read-only mount of repo under test)         │
│    /runs    (artifact output, writable by orchestrator)  │
└─────────────────────────────────────────────────────────┘
```

### Container Specs

**`zerokit-sast`** (Phase 03 static scanners)
```dockerfile
FROM python:3.12-slim
RUN pip install semgrep
RUN apk add --no-cache curl && \
    curl -sSL https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_linux_amd64.tar.gz | tar -xz -C /usr/local/bin/
# CodeQL CLI optional: large (~500MB), add only when needed
# Mount: /target (read-only), /runs (writable)
```
*Est. image size: ~400MB*

**`zerokit-cpg`** (Joern CPG server — Phase 02/03/05)
```dockerfile
FROM ghcr.io/joernio/joern:latest
EXPOSE 8080
# Mount: /target (read-only), /workspace (joern scratch space)
ENTRYPOINT ["joern", "--server", "--server-host", "0.0.0.0", "--server-port", "8080"]
```
*Est. image size: ~1.5-2GB. Reuse across phases — keep alive between Phase 02 and 05.*

**`zerokit-verify`** (Phase 04 PoC sandbox)
```dockerfile
FROM python:3.11-slim
# Minimal: Python + httpx for PoC execution
# No network egress except to target
# Killed after each verification attempt
```
*Est. image size: ~200MB*

**`zerokit-harness`** (orchestrator — the Python runtime)
```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY pyproject.toml .
RUN pip install -e ".[tools]"
COPY tools/ ./tools/
COPY .agent/ ./.agent/
# Mount: /target (read-only), /runs (writable)
ENTRYPOINT ["python", "tools/harness/run_master_workflow.py"]
```
*Est. image size: ~200MB*

### `docker-compose.yml` sketch

```yaml
services:
  harness:
    build: .
    volumes:
      - ${TARGET_REPO}:/target:ro
      - ./runs:/runs:rw
    environment:
      - SAST_HOST=sast
      - CPG_HOST=cpg
    depends_on: [sast, cpg]

  sast:
    image: zerokit-sast
    volumes:
      - ${TARGET_REPO}:/target:ro
      - ./runs:/runs:rw

  cpg:
    image: zerokit-cpg
    ports: ["8080:8080"]
    volumes:
      - ${TARGET_REPO}:/target:ro
      - joern-workspace:/workspace:rw

volumes:
  joern-workspace:
```

### Portability notes on containerization

- All three scanner containers work on `linux/amd64` and `linux/arm64`.
- Joern's official image is AlmaLinux (amd64 only in practice; arm64 available but slower due to JVM JIT).
- `docker-in-docker` for Phase 04 verification needs `--privileged` or a rootless alternative (`gVisor`, `nsjail`). This is the main security consideration for CI runners.
- On macOS/Windows: Docker Desktop works. The `/target` mount should use absolute paths.

---

## 5. Cross-Platform Compatibility

### Current state

The Python harness (`tools/harness/`, `tools/ci/`) uses only stdlib + pathlib. It works on Linux, macOS, Windows with no changes. The 18 tests pass on all three (no platform-specific assumptions).

### Tool-level compatibility

| Tool | Linux | macOS | Windows | Notes |
|---|---|---|---|---|
| Python harness | ✅ | ✅ | ✅ | `pathlib` throughout, no hardcoded separators |
| Semgrep | ✅ | ✅ | ✅ (WSL recommended) | Native binaries on all platforms; Windows support is functional but slower |
| Gitleaks | ✅ | ✅ | ✅ | Prebuilt binaries for all three |
| CodeQL | ✅ | ✅ | ✅ | First-class on all three; GitHub Actions runners support all |
| Joern | ✅ | ✅ | ⚠️ | JVM works on Windows but Joern's scripting shell is bash-heavy; run in WSL2 or container on Windows |
| Docker | ✅ | ✅ | ✅ (Desktop/WSL2) | Phase 04 sandbox. On Windows: Docker Desktop + WSL2 backend required |
| Tree-sitter Python bindings | ✅ | ✅ | ✅ | Native C extension; pip installable on all three |

### Identified gaps

1. **`tools/ci/check_workflow_integrity.py`** uses `sys.path.insert` + `from _phase_config import ...`. This relies on directory-relative import that works on POSIX. On Windows, needs the same `try/except ImportError` pattern already in `run_master_workflow.py`. **Fix:** add `try/except ImportError` wrapper in `check_workflow_integrity.py`.

2. **Subprocess calls** in harness scripts use `["python", ...]`. On Windows this resolves to the wrong Python if multiple versions exist. **Fix:** use `sys.executable` consistently (already done in tests; needs audit in prod scripts).

3. **Joern server mode** on macOS can hit JVM file-descriptor limits on large repos. **Fix:** add `ulimit -n 65536` or `-Xss` JVM flag in the container entrypoint.

4. **Path separators in artifact JSON**: `detect_repo_profile.py` outputs paths from `pathlib.Path`. On Windows these would be backslash-separated. The artifact contract does not specify separator policy. **Fix:** normalize all paths in artifact output to forward-slash using `path.as_posix()`.

5. **`make` targets**: Makefile requires `make` (GNU Make). On Windows this requires Chocolatey/MSYS2/WSL. **Mitigation:** document WSL2 as the recommended Windows dev environment; add a `Justfile` or `tasks.py` as an alternative later.

### Recommended platform strategy

- **Primary development and CI**: Linux (GitHub Actions `ubuntu-latest`). All tools work best here.
- **macOS**: Fully supported. Joern + Docker Desktop add ~15s cold start overhead.
- **Windows**: Supported via WSL2 + Docker Desktop. Do not test on native Win32 Python in CI.
- **CI matrix** (when adding GitHub Actions test matrix): `ubuntu-latest` required, `macos-latest` recommended, `windows-latest` optional/nightly.

---

## 6. Summary

| Question | Answer |
|---|---|
| Next step | Implement Phase 03 Semgrep connector (subprocess → JSON parse → normalize → `static_findings.json`) |
| Primary external tools needed | Semgrep (Phase 03), Gitleaks (Phase 03), Joern (Phase 02/03/05), Docker (Phase 04) |
| Secondary/optional external | CodeQL (Phase 03 deep scan), Tree-sitter Python bindings (Phase 02 entrypoint discovery) |
| Internal tools to wire | Semgrep skill connector, Gitleaks skill connector, SARIF normalizer, PoC template runner |
| Container strategy | 4 separate images: `harness` (Python), `sast` (Semgrep+Gitleaks), `cpg` (Joern server), `verify` (PoC sandbox) |
| Cross-platform | Linux/macOS fully supported; Windows via WSL2; 4 minor code gaps identified |

### Open questions

1. **LLM gateway**: Phase 03 hypothesis generation and Phase 04 PoC synthesis both need an LLM. Which provider/model? A previous prototype used runtime integrations that are now retired. Current harness has no LLM integration. This needs a decision before Phases 03–05 can be fully autonomous.

2. **CodeQL licensing**: The free CLI supports all target languages but the full query suite requires GitHub Advanced Security for enterprise targets. Clarify whether ZeroKit targets public or private repos.

3. **Verification sandbox depth**: Docker-in-Docker in CI is straightforward. For sensitive engagements, a gVisor or nsjail sandbox is safer. How hardened does Phase 04 need to be?

4. **Tree-sitter vs regex for Phase 02**: Current `detect_repo_profile.py` uses regex against file patterns. Upgrading to Tree-sitter AST would catch more entrypoints (e.g., Django URL patterns, Spring `@RequestMapping`). Worth it for Weeks 2–3 scope?
