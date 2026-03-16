# Whitebox Pentest Harness – Team Implementation Plan

## Goal
Deliver a plug-and-play agent harness that runs the 6-phase whitebox pentest workflow with strict evidence gates and supports .NET, TypeScript/JavaScript, Java, Go, and Python.

## Team Workstreams
- Architecture/Orchestration: master workflow runner, phase state machine, artifact contract enforcement.
- Language Coverage: per-language profiling and sink/source maps for .NET, TS/JS, Java, Go, Python.
- Detection/Verification: static connectors, dedupe, verification evidence runner.
- RCA/Patch/Reporting: RCA templates, variant search, remediation, regression guidance.
- DevEx/QA: CI checks, schema validation, dead-link/workflow integrity, fixtures.

## Timeline (8 Weeks)
- Week 1 – Foundation Lock: freeze phase/artifact schemas; normalize docs; add CI for links/schema/scope. DoD: single source of truth, CI green.
- Weeks 2-3 – Orchestrator MVP (Phases 01-03): runnable orchestrator; run context + artifact store; language detectors + attack-surface extraction; Semgrep + normalization/dedupe. DoD: intake→candidate findings repeatable.
- Weeks 4-5 – Verification Gate (Phase 04): strict statuses (`confirmed/rejected/inconclusive`); evidence collector (cmd/output/exit/log path); retry loop. DoD: no finding promoted without reproducible evidence.
- Week 6 – RCA / Variant / Patch (Phase 05): RCA template; generalized pattern + variant scan; patch proposal + verification. DoD: each confirmed finding has RCA + validated patch guidance.
- Week 7 – Reporting (Phase 06): final report from confirmed only; path/line, exploit summary, RCA, remediation, variant status, regression tests; unresolved inconclusive separated. DoD: audit-ready report.
- Week 8 – Hardening & Release: perf + FP reduction; per-language fixtures; artifact lineage; tag v1 and operator playbook. DoD: stable CI, reproducible e2e runs, release checklist done.

## Acceptance Criteria (Project)
- Single entrypoint runs all 6 phases end-to-end.
- Artifact schema validated at each gate.
- “No proof, no vulnerability” enforced programmatically.
- Language support: .NET, TS/JS, Java, Go, Python.
- Each confirmed finding: evidence bundle, RCA, remediation, regression guidance.

## Metrics
- Verification rate: % candidates resolved as confirmed/rejected.
- Evidence completeness: % findings with command/output/exit/log bundle.
- Signal quality: confirmed-to-candidate ratio.
- Cycle time: intake→final report.
- Regression stability: % patched findings with passing regression checks.

## Next Actions to Start
- Stand up CI guardrails (links, schema validation, scope checks).
- Implement orchestrator run context and artifact store.
- Add language detectors + attack-surface extraction for priority stacks.
- Wire Semgrep path with normalization/dedupe as first detection path.
