# Whitebox Pentest Harness Blueprint

## Core Pipeline
1. Intake & planning
2. Profile repo and map attack surface
3. Generate hypotheses and run static detection
4. Verification gate with reproducible evidence
5. Root cause, variant analysis, and patching
6. Report and regression guidance

## Key Success Pattern
- Separation of orchestration (master workflow) from specialized subflows.
- Stage-by-stage artifacts and strict phase gates.
- Iterative verify/fix loop until findings are `confirmed` or `rejected`.

## Evidence Contract
Each confirmed finding must include:
- location (path + line)
- exploit path description
- execution evidence (command/output/exit)
- root cause
- patch guidance
- variant status

## Recommended Harness Structure (Target)
- `.agent/harness/orchestrator/`
- `.agent/harness/models/`
- `.agent/harness/adapters/`
- `.agent/harness/agents/`
- `.agent/harness/tools/`
- `.agent/harness/artifacts/`

## Design Principle
Optimize for security signal quality, reproducibility, and low false-positive noise.
