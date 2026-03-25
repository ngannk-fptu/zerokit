# Harness Workflow Menu Guide

## Canonical Entry
Use:

```bash
# from repository root
cat .agent/methodology/master-harness.md
```

Treat `master-harness` as the single orchestration surface.

## Phase Files
1. `.agent/methodology/phases/phase-01-intake-plan.md`
2. `.agent/methodology/phases/phase-02-profile-surface.md`
3. `.agent/methodology/phases/phase-03-threat-and-static.md`
4. `.agent/methodology/phases/phase-04-verification-gate.md`
5. `.agent/methodology/phases/phase-05-rca-variant-patch.md`
6. `.agent/methodology/phases/phase-06-report-regression.md`

## Specialized Subflows
- `.agent/methodology/hunt-fuzz.md`
- `.agent/methodology/hunt-deps.md`
- `.agent/methodology/hunt-diff.md`

These subflows must still obey the master verification gate and artifact contract.

## Legacy Cleanup
Deprecated compatibility aliases were removed. Use the canonical methodology files only.
