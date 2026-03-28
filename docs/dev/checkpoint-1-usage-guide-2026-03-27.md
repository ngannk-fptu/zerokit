# ZeroKit V3 — Current Capabilities & User Flow

## What it is (in one sentence)

ZeroKit is a methodology + tool harness layer that you load into an AI agent runtime (OpenCode Profile B). The agent provides all reasoning. The harness provides structured workflow, tool connectors, and artifact validation. No automation pipeline: the agent IS the orchestrator.

---

## Current Capabilities (as of today, HEAD: `039070a`)

| Layer               | What's There                                                                                                                                             | Status                     |
| ------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------- |
| Agent methodology   | `agent.md` — full 6-phase instructions, decision logic, hard rules                                                                                       | ✅ Complete                 |
| Phase docs          | 6 `.md` files, one per phase, with step-by-step guidance                                                                                                 | ✅ Complete                 |
| 31 skill packs      | SAST, secrets, threat modeling, fuzzing, variant analysis, language-specific patterns                                                                    | ✅ Complete                 |
| 11 PoC templates    | CWE-mapped: SQLi, XSS, path traversal, SSRF, command injection, auth bypass, deserialization, NoSQL, open redirect, info disclosure, resource exhaustion | ✅ Complete                 |
| Repo profiler       | `detect_repo_profile.py` — detects language, frameworks, entrypoints, trust boundaries                                                                   | ✅ Complete                 |
| Run initializer     | `init_artifact_run.py` — creates run dir, writes valid `run_state.json`, enforces unique run-id                                                          | ✅ Complete                 |
| Semgrep connector   | `run_semgrep.py` — runs SAST, normalizes to intermediate finding schema                                                                                  | ✅ Complete                 |
| Gitleaks connector  | `run_gitleaks.py` — runs secrets scan, target-relative paths                                                                                             | ✅ Complete                 |
| Finding merger      | `merge_findings.py` — deduplicates, links to hypotheses, assigns IDs                                                                                     | ✅ Complete                 |
| PoC runner          | `run_poc.py` — Docker isolation, exit-code semantics, inconclusive for infra failures                                                                    | ✅ Complete                 |
| Joern connector     | `run_joern.py` — taint query, HTTP API, normalizes CPG results                                                                                           | ✅ Complete                 |
| Artifact validator  | `validate_run_artifacts.py` — validates all 7 phase artifacts + `run_state.json` against contract                                                        | ✅ Complete                 |
| CI guardrails       | 5 checks: stale refs, scope boundaries, artifact contract, language detectors, detector fixtures                                                         | ✅ Complete                 |
| Profile B           | OpenCode profile pre-configured with `agent.md` + methodology for pentest use                                                                            | ✅ Complete                 |
| Test fixture        | `tests/fixtures/vuln-flask-app` — SQLi (CWE-89), path traversal (CWE-22), false positive (safe parameterized query)                                      | ✅ Complete                 |
| Phase orchestrators | `run_phase03.py` through `run_phase06.py`                                                                                                                | ❌ Not built (D8–D11)       |
| Master orchestrator | `run_master_workflow.py`                                                                                                                                 | ❌ Not built (D4 remainder) |
| E2E test            | `test_e2e_vertical_slice.py`                                                                                                                             | ❌ Not built (D12)          |

Bottom line today: The agent can run a complete pentest manually — every tool works, artifacts are validated. What's missing is the automated "run it and walk away" pipeline. The agent does what the orchestrators would do.

---

## Installation

### Option A — DevContainer (zero config)

```bash
# 1. Clone
git clone <repo> zerokit-dev && cd zerokit-dev

# 2. Open in VS Code → "Reopen in Container"
# DevContainer installs: Python 3.11, uv, Semgrep, Gitleaks, Bun, OpenCode
# Takes ~2 min on first build

# 3. You now have two profiles:
opencode-a    # develop ZeroKit itself
opencode-b    # USE ZeroKit as a pentester ← this is the product
```

### Option B — Local

```bash
pip install -e ".[dev,tools]"
pip install semgrep
# Docker Desktop required for Phase 04 (PoC verification)
# Gitleaks: brew install gitleaks  /  apt install gitleaks
# Joern optional (Phase 05): https://joern.io

make check   # should print 5x "ok"
make test    # should print "53 passed"
```

---

## Full User Flow Walkthrough

### Setup: spin up the target

```bash
cd tests/fixtures/vuln-flask-app
docker-compose up --build
# App running at http://localhost:5000 on pentest-net network
```

### Launch Profile B

```bash
opencode-b
```

OpenCode loads `agent.md` (410 lines) plus all 31 skill packs and the methodology phases. The agent is now a whitebox pentester.

---

## Phase 01 — Intake

**What the agent does:** Asks you for scope, confirms the target, initializes the run directory.

**You say:**

> Run a whitebox pentest on `/home/diabel/Desktop/ZeroKit-V3/zerokit-dev/tests/fixtures/vuln-flask-app`  
> Scope: all routes. Time budget: 30 minutes. No prohibited actions.

**Agent does:**

```bash
python tools/harness/init_artifact_run.py \
  --target tests/fixtures/vuln-flask-app \
  --run-id run-20260327T1000Z
```

**What gets created:**

```text
.agent/artifacts/runs/run-20260327T1000Z/
  run_state.json          ← status: initialized, simulated: false
  01-intake/
  02-surface/
  03-static/
  04-verify/
  05-rca/
  06-report/
```

Agent then writes `01-intake/plan.json` itself (no tool for this — it's the agent's reasoning).

---

## Phase 02 — Surface

**Agent profiles the repo:**

```bash
python tools/harness/detect_repo_profile.py \
  --target tests/fixtures/vuln-flask-app \
  --run-id run-20260327T1000Z \
  --output .agent/artifacts/runs/run-20260327T1000Z/02-surface/repository_profile.json
```

**What it finds:**
- Language: python
- Framework: flask
- Entrypoints: `GET /user`, `GET /file`, `GET /item`
- Trust boundaries: `http-request`, `db-input`

Agent then reasons over the profile and writes `02-surface/attack_surface.json` itself — 3 items, one per route, with `confidence` and `notes` fields.

---

## Phase 03 — Static Detection

Agent writes `03-static/hypotheses.json` first (its reasoning: "what could go wrong at each entrypoint?"). Then runs both scanners:

```bash
# Semgrep — SAST
python tools/harness/run_semgrep.py \
  --target tests/fixtures/vuln-flask-app \
  --run-id run-20260327T1000Z \
  --output .agent/artifacts/runs/run-20260327T1000Z/03-static/semgrep_intermediate.json \
  --rulesets p/python,p/security-audit

# Gitleaks — secrets
python tools/harness/run_gitleaks.py \
  --target tests/fixtures/vuln-flask-app \
  --run-id run-20260327T1000Z \
  --output .agent/artifacts/runs/run-20260327T1000Z/03-static/gitleaks_intermediate.json

# Merge + deduplicate
python tools/harness/merge_findings.py \
  --inputs \
    .agent/artifacts/runs/.../semgrep_intermediate.json \
    .agent/artifacts/runs/.../gitleaks_intermediate.json \
  --hypotheses .agent/artifacts/runs/.../hypotheses.json \
  --run-id run-20260327T1000Z \
  --output .agent/artifacts/runs/.../static_findings.json
```

**Typical output for the `vuln-flask-app`:**

```text
sf-001  high    CWE-89   app.py:18   cursor.execute with f-string (semgrep)
sf-002  medium  CWE-22   app.py:31   os.path.join with user input (semgrep)
sf-003  medium  CWE-89   app.py:45   cursor.execute with variable (semgrep) ← FALSE POSITIVE
```

---

## Phase 04 — Verification

This is the critical gate. Agent inspects each finding's source code manually first, then builds PoCs. It uses the PoC template library as a starting point.

`sf-001` (SQLi): Agent reads `app.py:18`, confirms the f-string, grabs `http_sqli_time_based.py` template, adapts it to UNION-based (SQLite has no SLEEP), runs it:

```bash
python tools/harness/run_poc.py \
  --finding-id sf-001 \
  --poc-script /tmp/poc_sf001.py \
  --target tests/fixtures/vuln-flask-app \
  --network pentest-net \
  --run-id run-20260327T1000Z \
  --output .agent/artifacts/runs/.../04-verify/sf-001-evidence.json
```

PoC hits `http://localhost:5000/user?name=' UNION SELECT sqlite_version(), NULL, NULL--`. Exit code `0` → confirmed.

`sf-002` (Path traversal): PoC hits `/file?path=../app.py`. Returns app source code. Exit code `0` → confirmed.

`sf-003` (False positive — safe parameterized query): Agent reads `app.py:45`, sees `cursor.execute("SELECT * FROM items WHERE id=?", (item_id,))`. Code trace shows the `?` placeholder — input never touches the query string. Agent marks rejected without running a PoC (code analysis disproves exploitability).

**Agent writes:**
- `04-verify/verification_evidence.json` — one item per finding, command + output + exit code
- `04-verify/verified_findings.json` — status + reason per finding

---

## Phase 05 — Root Cause Analysis

For each confirmed finding, agent traces the taint flow and searches for variants:

```bash
python tools/harness/run_joern.py \
  --target tests/fixtures/vuln-flask-app \
  --run-id run-20260327T1000Z \
  --output .agent/artifacts/runs/.../05-rca/joern_taint.json \
  --port 8080
```

Writes `05-rca/rca_and_variants.json`:
- `sf-001`: root cause = no parameterized query; taint path = `request.args['name'] → cursor.execute(f"...")`; variant count = 1 (same pattern at line 18 only); patch = use `?` placeholder
- `sf-002`: root cause = no `os.path.realpath` boundary check; patch = `os.path.realpath` + assert inside `BASE_DIR`

---

## Phase 06 — Report

Agent synthesizes `06-report/final_report_items.json` from all confirmed findings:

```json
{
  "items": [
    {
      "finding_id": "sf-001",
      "status": "confirmed",
      "title": "UNION-based SQL injection in /user route",
      "affected_path": "app.py",
      "line": 18,
      "evidence_ref": "verification_evidence#sf-001",
      "remediation": "Replace f-string with parameterized query: cursor.execute('SELECT * FROM users WHERE name=?', (name,))",
      "regression_test": "tests/security/test_sqli.py::test_union_extraction_blocked"
    }
  ]
}
```

Then validates everything:

```bash
python tools/harness/validate_run_artifacts.py \
  --run-root .agent/artifacts/runs/run-20260327T1000Z
```

If any artifact is missing, malformed, or violates the contract → hard failure with specific error. All 7 artifacts + `run_state.json` must pass.

---

## Edge Cases You'll Hit

### 1. Docker not running / permission denied

**Symptom:** `run_poc.py` returns `status: inconclusive` (not rejected) with output `"permission denied while trying to connect to the docker API"`.

**Fix:** Start Docker daemon, or add your user to the docker group (`sudo usermod -aG docker $USER`). The PoC connector now correctly distinguishes infra failures (`exit 125/126/127 → inconclusive`) from actual PoC failures (`rejected`).

### 2. Joern server not running

**Symptom:** `run_joern.py` fails health check after retries, exits with error.

**What to do:** Phase 05 is genuinely optional for the first pass — if Joern isn't available, the agent marks Phase 05 as skipped and proceeds to Phase 06 with findings from Phase 04. The report still lists root cause based on code analysis alone.

### 3. Semgrep not installed

**Symptom:** `run_semgrep.py` exits with code `2` (tool missing) — distinct from exit `1` (findings found) and `0` (no findings).

**Fix:** `pip install semgrep`. The connector's exit code semantics are:
- `0` = no findings
- `1` = findings found (both are success)
- `2` = tool missing (hard failure)

### 4. run_id collision

**Symptom:** `init_artifact_run.py` refuses to start: `"output directory already exists"`.

**Why:** The uniqueness guard is intentional — silently overwriting a previous run would corrupt its artifacts. Use a new timestamped run-id: `run-20260327T1200Z`.

### 5. Semgrep flags `cursor.execute` with a variable (the false positive case)

**What happens:** `merge_findings.py` assigns it `sf-003`. During Phase 04, the agent reads the code, sees `?` placeholder parameterization, and marks it rejected in `verified_findings.json` without running a PoC. Final report excludes it. This is exactly the intended behavior — the "no proof, no vulnerability" hard rule filters it out.

### 6. Artifact validation fails mid-run

**Symptom:** `validate_run_artifacts.py` exits non-zero with something like:

> `04-verify/verification_evidence.json missing required fields: ['command']`

**What to do:** The agent re-inspects the file, adds the missing field, reruns validation. The validator is the source of truth — it tells you exactly what's wrong.

### 7. Monorepo target

`detect_repo_profile.py` now correctly walks subdirectories for manifests (`rglob` — Codex P2 fix). A monorepo with nested `package.json`, `pyproject.toml`, and `csproj` will correctly emit build/test hints for all three stacks, not just the root-level one.

---

## What's Coming (Next Checkpoint — D8–D12)

Once phase orchestrators are built, the flow above goes from:

> Agent manually calls each tool in sequence, reasons about the output, writes the next artifact

To:

```bash
python tools/harness/run_master_workflow.py \
  --target tests/fixtures/vuln-flask-app \
  --run-id run-20260327T1000Z
```

The orchestrator dispatches each phase script, validates artifacts between phases, and stops if any phase fails contract. The agent still reads the final output and writes the report — it's not removed from the loop, it just delegates the mechanical tool invocations.

That's the difference between Checkpoint 1 (current — agent-driven, fully functional) and Checkpoint 2 (D8–D12 — automated dispatch, agent reviews output).
