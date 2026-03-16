# CI Guardrails Runbook

This runbook maps each harness guardrail check to likely failure causes and remediation actions.

## Local Command
Run all checks locally:

```bash
make harness-check
```

Run only smoke checks:

```bash
make harness-smoke
```

## Guardrail Checks

### `check_workflow_integrity.py`
Purpose:
- enforce canonical master workflow phase order
- ensure phase references resolve
- enforce `no proof, no vulnerability` statement in master workflow

Common failures:
- missing/renamed phase file
- phase order mismatch in `master-harness.md`
- removed proof-gate wording

Remediation:
- restore canonical phase references in `.agent/workflows/master-harness.md`
- restore missing phase files under `.agent/workflows/phases/`
- keep proof-gate wording present

### `check_docs_consistency.py`
Purpose:
- enforce consistency across core docs:
- `.agent/HARNESS_SCOPE.md`
- `.agent/knowledge_base/ARCHITECTURE.md`
- `.agent/knowledge_base/BLUEPRINT.md`
- `.agent/knowledge_base/MENU_GUIDE.md`

Common failures:
- required canonical phrases removed
- legacy/stale path references reintroduced

Remediation:
- re-add required architecture/contract language
- remove stale runtime path claims

### `check_scope_boundaries.py`
Purpose:
- block reintroduction of removed legacy runtime trees and forbidden skill families

Common failures:
- forbidden skill dirs re-added (for example `superpowers`, `anthropic`)
- legacy root paths reintroduced (for example `core/`, `adapters/`, `test_vul/`)

Remediation:
- remove out-of-scope directories
- keep skills constrained to whitebox harness mission

### `validate_artifact_contract.py`
Purpose:
- validate `.agent/artifacts/contracts/artifact_contract.json`
- validate example artifacts under `.agent/artifacts/examples/`
- enforce proof gate on confirmed final report items

Common failures:
- missing required fields in artifact examples
- invalid enum values (`status`, `priority`)
- confirmed report item without confirmed evidence/verified finding

Remediation:
- repair example JSON fields and values
- ensure final confirmed findings have matching confirmed verification evidence

### `validate_language_detector_contract.py`
Purpose:
- validate language detector contract and example profile

Common failures:
- missing required profile fields
- unsupported language labels
- malformed language signal lists

Remediation:
- align `detector_contract.json` and profile example field names/types
- keep `languages` within supported language set

### `smoke_harness_tools.py`
Purpose:
- run utility CLIs end-to-end
- validate example artifacts
- validate orchestrator-generated artifacts

Common failures:
- utility script runtime error
- orchestrator emits invalid artifact schema
- cross-artifact proof-gate mismatch

Remediation:
- run failing command locally and inspect stderr
- fix script output to match artifact contract
- rerun `make harness-check` until all checks pass

## Diagnostic Priority
If multiple checks fail, fix in this order:
1. workflow integrity
2. scope boundaries
3. contract validation
4. smoke harness tools
5. docs consistency

This order reduces cascading failures and shortens feedback loops.
