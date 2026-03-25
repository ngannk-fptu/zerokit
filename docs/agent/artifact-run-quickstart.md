# Artifact Run Quickstart

This quickstart shows how to generate, inspect, and validate a harness run output.

## 1. Run Orchestration Shim

```bash
python tools/harness/run_master_workflow.py --target . --run-id run-demo-001
```

Expected output (example):

```json
{
  "run_id": "run-demo-001",
  "run_root": ".agent/artifacts/runs/run-demo-001",
  "status": "completed"
}
```

## 2. Validate Run Artifacts

```bash
python tools/harness/validate_run_artifacts.py --run-root .agent/artifacts/runs/run-demo-001
```

Expected output includes:
- `status: ok`
- `proof_gate: passed`

## 3. Run Full Guardrails

```bash
make harness-check
```

This executes:
- workflow integrity checks
- docs/scope checks
- contract checks
- language detector fixture tests
- harness utility smoke tests

## 4. Inspect Run State

Check phase diagnostics and metrics:

```bash
cat .agent/artifacts/runs/run-demo-001/run_state.json
```

Key fields:
- `phase_status`
- `summary`
- `artifact_metrics`
