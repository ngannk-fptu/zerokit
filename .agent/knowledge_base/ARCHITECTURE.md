# Whitebox Pentest Agent Harness Architecture

## Current State
This repository currently provides a harness **operating layer**:
- workflow contracts (`.agent/workflows/`)
- pentest skill catalog (`.agent/skills/`)
- knowledge contracts and prompts (`.agent/knowledge_base/`)

It does **not** ship a bundled executable pipeline runtime at this stage.

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
All phases should exchange structured artifacts. At minimum:
- `attack_surface`: normalized nodes with file/line context
- `hypotheses`: prioritized source-to-sink security hypotheses
- `static_findings`: deduplicated tool findings with evidence
- `verification_evidence`: command/output/exit/log path
- `verified_findings`: `confirmed`, `rejected`, or `inconclusive`
- `rca_and_variants`: root-cause notes plus variant candidates
- `final_report_items`: confirmed findings with remediation and regression guidance

## Design Rules
- Agent decides; scripts are narrow tool executors.
- Keep orchestration declarative and artifact-driven, not hardcoded end-to-end scripts.
- Keep language/tool behavior modular through skills and adapters.
- Maintain reproducibility and evidence quality over raw finding volume.

## Integration Direction
The harness is intended to be portable across agent runtimes (Codex, ClaudeCode, Gemini, Antigravity, others) via:
- shared workflow contracts
- reusable skills
- stable artifact schema and phase gates
