# Whitebox Pentest Harness Blueprint

## What ZeroKit Is

A plug-and-play skill layer that gives any AI agent the methodology,
tools, knowledge, and evidence discipline of a professional pentester.

The agent runtime provides reasoning. ZeroKit provides structure.

## Core Flow

1. Intake and planning
2. Profile repo and map attack surface
3. Generate hypotheses and run static detection
4. Verification gate with reproducible evidence
5. Root cause, variant analysis, and patching
6. Report and regression guidance

## Key Success Pattern

- Separation of orchestration (master workflow) from specialized subflows.
- Stage-by-stage artifacts and strict phase gates.
- Iterative verify/fix loop until findings are `confirmed` or `rejected`.
- Agent decides; scripts execute. No autonomous scan chain.

## Evidence Contract

Each confirmed finding must include:
- location (path + line)
- exploit path description
- execution evidence (command/output/exit)
- root cause
- patch guidance
- variant status

## Harness Structure

- `.agent/methodology/` -- phase methodology docs
- `.agent/skills/` -- 30 pentest skill packs
- `.agent/knowledge_base/` -- prompts, templates, references
- `.agent/artifacts/` -- contracts, schemas, examples
- `tools/harness/` -- tool connectors, profilers, validators
- `tools/ci/` -- CI guardrails

## Design Principle

Optimize for security signal quality, reproducibility, and low
false-positive noise. Never trade agent judgment for automation speed.
