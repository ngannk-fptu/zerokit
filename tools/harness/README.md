# Harness Utilities

These scripts are narrow utilities that support workflow execution.

## `init_artifact_run.py`
Initializes a per-run artifact folder layout under `.agent/artifacts/runs/<run_id>/`.

Example:
```bash
python tools/harness/init_artifact_run.py --run-id run-20260303T120000Z
```

Dry-run:
```bash
python tools/harness/init_artifact_run.py --dry-run
```

## `detect_repo_profile.py`
Detects language/framework/profile signals for Phase 02 and emits contract-aligned JSON.

Example:
```bash
python tools/harness/detect_repo_profile.py --target . --run-id run-20260303T120000Z
```

Write output file:
```bash
python tools/harness/detect_repo_profile.py --target . --run-id run-20260303T120000Z --output /tmp/repo_profile.json
```

## `validate_run_artifacts.py`
Validates run artifact outputs against `.agent/artifacts/contracts/artifact_contract.json` and enforces proof-gate constraints for confirmed findings.

Example:
```bash
python tools/harness/validate_run_artifacts.py --run-root .agent/artifacts/runs/run-20260303T120000Z
```

## `run_master_workflow.py`
Runs a minimal orchestration shim for the canonical master workflow and materializes phase artifact placeholders plus repository profile output.

Example:
```bash
python tools/harness/run_master_workflow.py --target . --run-id run-20260303T120000Z
```

Dry-run:
```bash
python tools/harness/run_master_workflow.py --target . --run-id run-20260303T120000Z --dry-run
```
