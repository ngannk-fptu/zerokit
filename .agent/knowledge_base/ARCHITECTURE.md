# Whitebox Pentest Agent Harness Architecture

## Core Model

ZeroKit is a plug-and-play agent harness — a skill and knowledge layer
that turns any capable AI agent into a whitebox pentester. The agent
runtime (Claude Code, Codex, Copilot, Antigravity, etc.) is the
reasoning engine. ZeroKit provides what the agent needs to think and
act like a professional pentester:

- **Methodology**: 6-phase workflow with step-by-step phase docs
- **Skills**: 30 pentest skill packs (detection, fuzzing, threat modeling, etc.)
- **Tool connectors**: subprocess wrappers for Semgrep, Gitleaks, Joern, Docker, CodeQL
- **Knowledge**: CWE/OWASP references, language security patterns, PoC templates, prompt templates
- **Evidence contracts**: JSON artifact schemas enforced at every phase gate

The agent decides what to do. Scripts are narrow tool executors.

## Current State

This repository currently provides a harness **operating layer**:
- workflow contracts (`.agent/workflows/`)
- pentest skill catalog (`.agent/skills/`)
- knowledge contracts and prompts (`.agent/knowledge_base/`)
- tool connectors and CI guardrails (`tools/`)

## Canonical Orchestration Surface

Use `.agent/workflows/master-harness.md` as the single entrypoint.

Phase order:
1. Intake and plan
2. Profile repository and map attack surface
3. Generate hypotheses and run static detection
4. Verification gate (`no proof, no vulnerability`)
5. Root cause, variants, and patch strategy
6. Final report and regression guidance

## Artifact Contract

All phases exchange structured artifacts. At minimum:
- `attack_surface`: normalized nodes with file/line context
- `hypotheses`: prioritized source-to-sink security hypotheses
- `static_findings`: deduplicated tool findings with evidence
- `verification_evidence`: command/output/exit/log path
- `verified_findings`: `confirmed`, `rejected`, or `inconclusive`
- `rca_and_variants`: root-cause notes plus variant candidates
- `final_report_items`: confirmed findings with remediation and regression guidance

## Design Rules

- Agent decides; scripts are narrow tool executors.
- No separate LLM gateway -- the agent runtime is the reasoning engine.
- Keep orchestration declarative and artifact-driven, not hardcoded end-to-end scripts.
- Keep language/tool behavior modular through skills and adapters.
- Maintain reproducibility and evidence quality over raw finding volume.

## Runtime Portability

The harness is portable across agent runtimes via:
- Shared workflow contracts (readable by any agent that can read markdown)
- Reusable skills (self-contained instructions + tool invocations)
- Stable artifact schema and phase gates (JSON, validated by CI)
- Tool connectors as plain subprocess calls (no SDK lock-in)

Tested runtimes: Claude Code, Codex. Compatible with any runtime that
can read files, execute shell commands, and follow structured instructions.
