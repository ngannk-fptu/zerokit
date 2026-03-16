# Artifact Store Contract

The harness stores phase handoff artifacts in a per-run directory:

- `.agent/artifacts/runs/<run_id>/01-intake/`
- `.agent/artifacts/runs/<run_id>/02-surface/`
- `.agent/artifacts/runs/<run_id>/03-static/`
- `.agent/artifacts/runs/<run_id>/04-verify/`
- `.agent/artifacts/runs/<run_id>/05-rca/`
- `.agent/artifacts/runs/<run_id>/06-report/`

Required artifact names are defined in `.agent/artifacts/contracts/artifact_contract.json`.

Rules:
- Every artifact file must include `run_id` and `generated_at`.
- Every phase output must be structured and machine-validated.
- `confirmed` findings must always have verification evidence.
