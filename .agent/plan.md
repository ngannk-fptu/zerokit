# ZeroKit V3 Implementation Plan -- Phase 03 Connectors

## Context

Scaffolding has been cut (1,288 LOC removed, 54%). `agent.md` is the
new master instruction file. Remaining codebase: 1,087 LOC of real tool
connectors, validators, and tests across 10 Python files.

## What Exists

- `.agent/agent.md` -- master agent instruction file (Phase 01-06 workflow, tool commands, artifact contracts)
- `tools/harness/detect_repo_profile.py` -- repo language/framework profiler (254 LOC)
- `tools/harness/validate_run_artifacts.py` -- artifact contract validator (197 LOC)
- 5 CI checks, 8 passing tests, lint clean
- `.agent/artifacts/contracts/artifact_contract.json` -- schema for all 7 artifact types

## Scope

This sprint delivers Phase 03 tool connectors only: Semgrep, Gitleaks,
and a findings merger. No run initializer, no Phase 04+, no Joern.

The agent creates run directories per `agent.md` instructions. This
sprint does not change that contract.

## Intermediate Schema

Connector outputs use a defined intermediate schema. This schema lives
in `.agent/artifacts/contracts/intermediate_finding.json` (new file,
created as part of this sprint).

```json
{
  "version": "1.0.0",
  "description": "Intermediate finding format emitted by tool connectors before merge",
  "required_fields": ["run_id", "generated_at", "items"],
  "item_required_fields": ["tool", "rule", "severity", "path", "line", "evidence", "cwe"]
}
```

- Connectors validate their own output against this schema before writing.
- The merger validates each input file against this schema before processing.
- Unit tests assert schema compliance for all connector outputs.

This is a staging format only. The merger transforms intermediates into
contract-valid `static_findings.json` (governed by `artifact_contract.json`).

## Runtime Prerequisites

**Required tools:**
- `semgrep` (any recent version; tested with 1.x)
- `gitleaks` (any recent version; tested with 8.x)

**Handling tool absence:**
- Each connector checks for the tool binary at startup via `shutil.which()`
- If missing: print diagnostic to stderr, exit with code 2
- Tests are split:
  - **Unit tests** (always run): mock subprocess, test normalization/dedup/schema logic
  - **Integration tests** (gated): marked `@pytest.mark.integration`, skipped if tool not installed
- CI runs unit tests always; integration tests only in environments with tools installed

## Data Flow

```
Agent reasons about attack surface (Phase 02 output)
  |
  v
Agent writes hypotheses.json (Phase 03, Step 1 -- agent reasoning, not a script)
  |
  v
run_semgrep.py ──> semgrep_intermediate.json (tool-specific, no IDs)
run_gitleaks.py ─> gitleaks_intermediate.json (tool-specific, no IDs)
  |
  v
merge_findings.py
  - loads intermediates + hypotheses.json
  - matches findings to hypotheses by (path, cwe)
  - assigns hypothesis_id or "unlinked" fallback
  - assigns final sequential IDs (sf-001, sf-002, ...)
  - deduplicates by canonical fingerprint: (path, line, rule_or_cwe)
  - keeps highest-severity duplicate
  - sorts by severity descending
  - writes static_findings.json (contract-valid)
```

**Key design decisions:**
1. Connectors emit intermediate format (no `id`, no `hypothesis_id`).
   The merger is the single owner of final IDs and hypothesis linking.
2. One canonical fingerprint for dedup: `(path, line, rule_or_cwe)`.
3. Hypotheses are agent-generated (written to `hypotheses.json` before
   running connectors). The merger reads them for linkage.

## Implementation Steps

### Step 1: Semgrep Connector
**File:** `tools/harness/run_semgrep.py`
**Interface:**
```
python tools/harness/run_semgrep.py \
  --target <repo-path> \
  --run-id <run-id> \
  --output 03-static/semgrep_intermediate.json \
  --rulesets p/security-audit,p/owasp-top-ten
```
**Behavior:**
- Check `shutil.which("semgrep")`; exit 2 if missing
- Split `--rulesets` on commas into separate `--config` flags
- Exact invocation:
  ```bash
  semgrep scan \
    --config p/security-audit \
    --config p/owasp-top-ten \
    --json \
    --quiet \
    --no-git-ignore \
    <target-path>
  ```
- Capture stdout (JSON output), ignore stderr
- Exit code 0 = no findings, exit code 1 = findings found (both success)
- Exit code >= 2 = real error, propagate
- Parse `results[]` from Semgrep JSON stdout
- Emit intermediate records (no id, no hypothesis_id):
  ```json
  {
    "tool": "semgrep",
    "rule": "python.lang.security.audit.dangerous-system-call",
    "severity": "high",
    "path": "src/api/users.py",
    "line": 42,
    "evidence": "Rule matched: dangerous system call",
    "cwe": "CWE-78"
  }
  ```
- Severity mapping: Semgrep ERROR -> high, WARNING -> medium, INFO -> low
- CWE normalization:
  - Semgrep `results[].extra.metadata.cwe` may be an array or absent
  - If array with 1+ entries: use first entry (e.g., "CWE-78")
  - If empty array or missing: use "CWE-unknown"
  - Always emit a single string, never an array
- Handle Semgrep exit code 1 (findings found) as success
- Write intermediate JSON with `run_id`, `generated_at`, `items`

**Tests:**
- Unit: mock subprocess output, verify normalization and severity mapping
- Integration (gated): scan fixture with known vuln, verify finding captured

### Step 2: Gitleaks Connector
**File:** `tools/harness/run_gitleaks.py`
**Interface:**
```
python tools/harness/run_gitleaks.py \
  --target <repo-path> \
  --run-id <run-id> \
  --output 03-static/gitleaks_intermediate.json
```
**Behavior:**
- Check `shutil.which("gitleaks")`; exit 2 if missing
- Write report to temp file, then parse
- Exact invocation:
  ```bash
  gitleaks detect \
    --source <target-path> \
    --report-format json \
    --report-path <tmpfile> \
    --no-git
  ```
- Exit code 0 = no leaks, exit code 1 = leaks found (both success)
- Exit code >= 2 = real error, propagate
- Parse findings array from report JSON file
- Emit intermediate records:
  ```json
  {
    "tool": "gitleaks",
    "rule": "generic-api-key",
    "severity": "high",
    "path": "config/settings.py",
    "line": 15,
    "evidence": "Secret detected: generic-api-key",
    "cwe": "CWE-798"
  }
  ```
- All secret findings default to severity "high", CWE-798 (hardcoded credentials)
- Handle Gitleaks exit code 1 (leaks found) as success

**Tests:**
- Unit: mock subprocess output, verify normalization
- Integration (gated): scan fixture with planted API key, verify detection

### Step 3: Findings Merger
**File:** `tools/harness/merge_findings.py`
**Interface:**
```
python tools/harness/merge_findings.py \
  --inputs semgrep_intermediate.json gitleaks_intermediate.json \
  --hypotheses hypotheses.json \
  --run-id <run-id> \
  --output 03-static/static_findings.json
```
**Behavior:**
- Load all intermediate JSON files
- Load hypotheses.json (optional; if missing, all findings get `hypothesis_id: "unlinked"`)
- Match findings to hypotheses using deterministic policy:
  1. Exact CWE match AND exact path match -> link
  2. Exact CWE match AND same directory -> link
  3. Exact CWE match AND any path -> link (lowest priority)
  4. No CWE match -> `hypothesis_id: "unlinked"`
  - Tie-breaker: if multiple hypotheses match at the same level,
    pick the hypothesis with the lowest ID (first defined wins)
  - Each finding links to exactly one hypothesis or "unlinked"
- Deduplicate by fingerprint `(path, line, rule_or_cwe)`:
  - Keep highest severity
  - Prefer finding with hypothesis linkage over unlinked
- Assign final IDs: sf-001, sf-002, ...
- Sort by severity descending (critical > high > medium > low)
- Write contract-valid `static_findings.json`

**Tests:**
- Unit: merge two files with one duplicate, verify dedup keeps highest severity
- Unit: merge with hypotheses.json, verify linkage
- Unit: merge without hypotheses.json, verify all get "unlinked"
- Unit: verify ID sequencing is gap-free

### Step 4: Update agent.md
**File:** `.agent/agent.md`
**Change:** Make connectors the canonical Phase 03 path. Raw CLI
commands move to a "Tool Reference (Manual)" appendix section, clearly
marked as reference-only for debugging. All Phase 03 instructions,
artifact names, and dedup guidance align to the connector flow.

## Sequencing

Steps 1-2 are independent. Step 3 depends on 1+2 (needs their
intermediate format defined). Step 4 depends on all.

```
Step 1 (semgrep) ──┐
                    ├── Step 3 (merge) ── Step 4 (agent.md update)
Step 2 (gitleaks) ─┘
```

## Out of Scope (This Sprint)

- Run initializer (agent creates dirs per agent.md)
- Joern integration (requires server setup)
- Docker PoC sandbox (Phase 04)
- RCA/variant tooling (Phase 05)
- Report generation (Phase 06)
- CodeQL integration

## Acceptance Criteria

1. `make check && make test && make lint` passes with all new code.
2. Unit tests verify: Semgrep output normalization, Gitleaks output
   normalization, merger dedup logic, hypothesis linkage, ID assignment,
   tool-missing exit behavior.
3. Each connector's output matches the intermediate schema (run_id,
   generated_at, items with tool/rule/severity/path/line/evidence/cwe).
4. Merger output matches `static_findings` artifact contract (run_id,
   generated_at, items with id/tool/severity/path/line/evidence/hypothesis_id).
5. Integration tests (when tools available) produce real findings from
   fixture repos.
6. agent.md Phase 03 uses connectors as the single canonical workflow.
   Raw CLI commands live in a "Tool Reference (Manual)" appendix only.
7. Zero new CI failures.
