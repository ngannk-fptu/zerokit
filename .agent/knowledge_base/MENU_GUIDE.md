# Harness Workflow Menu Guide

## Canonical Entry
Use:

```bash
# from repository root
cat .agent/workflows/master-harness.md
```

Treat `master-harness` as the single orchestration surface.

## Phase Files
1. `.agent/workflows/phases/phase-01-intake-plan.md`
2. `.agent/workflows/phases/phase-02-profile-surface.md`
3. `.agent/workflows/phases/phase-03-threat-and-static.md`
4. `.agent/workflows/phases/phase-04-verification-gate.md`
5. `.agent/workflows/phases/phase-05-rca-variant-patch.md`
6. `.agent/workflows/phases/phase-06-report-regression.md`

## Specialized Subflows
- `.agent/workflows/hunt-fuzz.md`
- `.agent/workflows/hunt-deps.md`
- `.agent/workflows/hunt-diff.md`

These subflows must still obey the master verification gate and artifact contract.

## Compatibility Aliases
Legacy files (`hunt-pipeline`, `brainstorm`, `writing-plans`, `hunt-taint`) are compatibility routing stubs and should not define independent orchestration logic.
