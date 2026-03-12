# ZeroKit V3

ZeroKit V3 is a plug-and-play skill and knowledge layer that turns any
capable AI agent into a professional whitebox pentester.

Drop this repo into Claude Code, Codex, GitHub Copilot, Antigravity, or
any agent runtime that can read files and run shell commands. The agent
gets structured pentesting methodology, tool connectors, artifact
contracts, and domain knowledge. It provides the reasoning, context,
and judgment -- like a human security researcher.

## How It Works

ZeroKit is **not** an automated scan chain. The agent decides what to
do at each phase. Scripts are narrow tool executors the agent calls.

```
Agent runtime (Claude Code, Codex, Copilot, etc.)
       |
       | reads workflows, skills, prompts
       | invokes tool wrappers (Semgrep, Gitleaks, Joern, Docker)
       | produces and validates artifacts
       v
ZeroKit harness layer
  .agent/workflows/    -- methodology (6-phase pentest flow)
  .agent/skills/       -- 30 pentest skill packs
  .agent/knowledge_base/ -- prompts, templates, references
  .agent/artifacts/    -- contracts, schemas, examples
  tools/harness/       -- tool connectors, profilers, validators
  tools/ci/            -- CI guardrails
```

## 6-Phase Workflow

`Intake > Surface > Static > Verify > RCA > Report`

Each phase exchanges structured artifacts. The agent reads the phase
doc, follows the methodology, uses the relevant skills and tools, and
writes contract-aligned output before moving to the next phase.

## Entry Point

Scaffold a run directory (simulated artifacts for now):

```bash
python tools/harness/run_master_workflow.py --target <repo>
```

For real pentesting, the agent follows `.agent/workflows/master-harness.md`
directly and uses the tool wrappers in each phase.

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
```bash
pip install -e ".[dev]"
make test
```

## Hard Rules
- No proof, no vulnerability.
- Agent decides; scripts execute.
- Artifact contracts are mandatory for phase handoff.
- Portable across agent runtimes by design.
