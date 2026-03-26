# ZeroKit V3

ZeroKit V3 is a plug-and-play skill and knowledge layer that turns any
capable AI agent into a professional whitebox pentester.

Drop this repo into OpenCode first. Claude Code, Codex, and GitHub
Copilot are secondary targets. The agent
gets structured pentesting methodology, tool connectors, artifact
contracts, and domain knowledge. It provides the reasoning, context,
and judgment -- like a human security researcher.

## How It Works

ZeroKit is **not** an automated scan chain. The agent decides what to
do at each phase. Scripts are narrow tool executors the agent calls.

```
Agent runtime (OpenCode first, other compatible runtimes second)
       |
       | reads methodology, skills, prompts
       | invokes tool wrappers (Semgrep, Gitleaks, Joern, Docker)
       | produces and validates artifacts
       v
ZeroKit harness layer
  .agent/methodology/  -- methodology (6-phase pentest flow)
  .agent/skills/       -- 30 pentest skill packs
  .agent/knowledge_base/ -- prompts, templates, references
  .agent/artifacts/    -- contracts, schemas, examples
  tools/harness/       -- tool connectors, profilers, validators
  tools/ci/            -- CI guardrails
  docs/research/       -- design notes and historical analysis
  .opencode/hooks/     -- OpenCode integration surface
```

## 6-Phase Workflow

`Intake > Surface > Static > Verify > RCA > Report`

Each phase exchanges structured artifacts. The agent reads the phase
doc, follows the methodology, uses the relevant skills and tools, and
writes contract-aligned output before moving to the next phase.

## Entry Point

Point your agent runtime at this repo and read `.agent/agent.md`.
That file contains the full methodology, commands, and decision logic
the agent needs to run a whitebox pentest.

## What the Agent Gets

| Layer | Contents |
|---|---|
| Methodology | 6 phase workflow docs with step-by-step guidance |
| Skills | Semgrep SAST, Gitleaks secrets, threat modeling, fuzzing, variant analysis, 25+ more |
| Tool connectors | Semgrep, Gitleaks, Joern (CPG/taint), Docker (PoC sandbox), CodeQL |
| Knowledge | CWE/OWASP references, language-specific security patterns, PoC templates, prompt templates |
| Artifact contracts | JSON schemas for every phase handoff, enforced by CI |
| Evidence gates | Hard rule: no proof, no vulnerability. Programmatically enforced. |

## Target Languages
.NET, TypeScript/JavaScript, Java, Go, Python

## Setup

### Option A: DevContainer (recommended)

Open in VS Code and select "Reopen in Container." The devcontainer
installs all dependencies automatically: Python 3.11, uv, Semgrep,
Gitleaks, Bun, OpenCode.

After the container builds:

```bash
# Profile A: develop ZeroKit
opencode-a

# Profile B: run ZeroKit as a pentester against a target
opencode-b
```

### Option B: Local install

```bash
# 1. Python dependencies
pip install -e ".[dev,tools]"

# 2. External tools (required for real runs)
pip install semgrep                               # SAST scanner
# Gitleaks: https://github.com/gitleaks/gitleaks
# Joern:    https://joern.io (optional, Phase 05)
# Docker:   required for PoC verification (Phase 04)

# 3. Verify
make check   # CI guardrails (5 checks)
make test    # unit tests
```

## Quick Start: Run a Pentest

```bash
# 1. Launch Profile B (or point any agent at .agent/agent.md)
opencode-b

# 2. Tell the agent what to pentest
> Run a whitebox pentest on tests/fixtures/vuln-flask-app

# The agent will:
#   - Initialize a run directory (init_artifact_run.py)
#   - Profile the target (detect_repo_profile.py)
#   - Run static analysis (run_semgrep.py + run_gitleaks.py)
#   - Merge and deduplicate findings (merge_findings.py)
#   - Verify with PoCs in Docker (run_poc.py)
#   - Analyze root causes with Joern (run_joern.py)
#   - Validate all artifacts (validate_run_artifacts.py)
```

### Test fixture

A vulnerable Flask app is included for testing:

```bash
cd tests/fixtures/vuln-flask-app
docker-compose up --build    # starts on localhost:5000
```

Contains: CWE-89 SQL injection, CWE-22 path traversal, and a safe
parameterized query (false positive test).

## Hard Rules
- No proof, no vulnerability.
- Agent decides; scripts execute.
- Artifact contracts are mandatory for phase handoff.
- OpenCode-first, portable to compatible agent runtimes.
