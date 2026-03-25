---
description: Intake and planning phase for the whitebox pentest harness.
---

1. Confirm target repository path and intended assessment depth (quick triage or deep audit).
2. Confirm language/framework scope with priority on `.NET`, `TypeScript/JavaScript`, `Java`, `Go`, `Python`.
3. Collect constraints:
- allowed tools
- time budget
- environment limits
- prohibited actions
4. Build a task list with explicit acceptance criteria per phase.
5. Define artifact contract for this run:
- `attack_surface`
- `hypotheses`
- `static_findings`
- `verification_evidence`
- `rca_notes`
- `variants`
- `patches`
- `final_report`
6. Continue only when scope, constraints, and acceptance criteria are clear.
