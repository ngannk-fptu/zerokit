---
description: Canonical whitebox pentest harness workflow. Use this as the single orchestration entrypoint for source-code security assessments.
---

1. Ask for the target repository path, scope boundaries, and priority language stacks (`.NET`, `TypeScript/JavaScript`, `Java`, `Go`, `Python`, others).
2. Run **Phase 01 Intake & Plan** from `workflows/phases/phase-01-intake-plan.md`.
3. Run **Phase 02 Profile & Surface** from `workflows/phases/phase-02-profile-surface.md`.
4. Run **Phase 03 Threat & Static Detection** from `workflows/phases/phase-03-threat-and-static.md`.
5. Run **Phase 04 Verification Gate** from `workflows/phases/phase-04-verification-gate.md`.
6. Run **Phase 05 RCA, Variant, Patch** from `workflows/phases/phase-05-rca-variant-patch.md`.
7. Run **Phase 06 Report & Regression** from `workflows/phases/phase-06-report-regression.md`.
8. If verification failed or evidence is incomplete, loop back to Phase 03 and iterate until each finding is `confirmed` or `rejected`.
9. Only allow final output when each reported issue has reproducible evidence, root-cause trace, and remediation guidance.

Operational rules:
- Treat this workflow as the only canonical orchestration surface. Other workflow files are either specialized subflows or compatibility aliases.
- Enforce `no proof, no vulnerability` as a hard gate.
- Keep artifacts structured per run (hypotheses, findings, PoCs, traces, patches, final report).
