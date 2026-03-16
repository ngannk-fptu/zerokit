#!/usr/bin/env python3
"""Validate a harness run directory against artifact contract and proof gates."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONTRACT = REPO_ROOT / ".agent/artifacts/contracts/artifact_contract.json"

ARTIFACT_LOCATIONS = {
    "attack_surface": "02-surface/attack_surface.json",
    "hypotheses": "03-static/hypotheses.json",
    "static_findings": "03-static/static_findings.json",
    "verification_evidence": "04-verify/verification_evidence.json",
    "verified_findings": "04-verify/verified_findings.json",
    "rca_and_variants": "05-rca/rca_and_variants.json",
    "final_report_items": "06-report/final_report_items.json",
}
RUN_STATE_LOCATION = "run_state.json"


def fail(message: str) -> None:
    print(f"[validate-run-artifacts] {message}", file=sys.stderr)
    raise SystemExit(1)


def read_json(path: Path) -> dict:
    if not path.exists():
        fail(f"missing JSON file: {path}")
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except json.JSONDecodeError as exc:
        fail(f"invalid JSON in {path}: {exc}")


def ensure_required_fields(data: dict, required: List[str], label: str) -> None:
    missing = [field for field in required if field not in data]
    if missing:
        fail(f"{label} missing required fields: {missing}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate run artifacts against contract")
    parser.add_argument(
        "--run-root",
        required=True,
        help="Path to run root (example: .agent/artifacts/runs/run-20260303T120000Z)",
    )
    parser.add_argument(
        "--contract",
        default=str(DEFAULT_CONTRACT),
        help="Path to artifact contract JSON",
    )
    parser.add_argument(
        "--output",
        default="",
        help="Optional path to write validation report JSON",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    run_root = Path(args.run_root)
    contract_path = Path(args.contract)

    contract = read_json(contract_path)
    artifacts_contract = contract.get("artifacts", {})
    enums = contract.get("enums", {})

    verification_status = set(enums.get("verification_status", []))
    finding_status = set(enums.get("finding_status", []))
    priorities = set(enums.get("priority", []))
    if not verification_status or not finding_status or not priorities:
        fail("contract enums are incomplete")

    run_state_path = run_root / RUN_STATE_LOCATION
    run_state_present = run_state_path.exists()
    run_state: Dict[str, object] = {}
    run_state_run_id: str | None = None
    simulated_run = False
    run_mode = "REAL RUN"
    if run_state_present:
        loaded_run_state = read_json(run_state_path)
        if not isinstance(loaded_run_state, dict):
            fail("run_state.json must contain an object")
        run_state = loaded_run_state

        simulated_value = run_state.get("simulated")
        if simulated_value is not None and not isinstance(simulated_value, bool):
            fail("run_state.json field 'simulated' must be boolean when present")
        simulated_run = simulated_value is True
        run_mode = "SIMULATED RUN" if simulated_run else "REAL RUN"

        run_state_value = run_state.get("run_id")
        if run_state_value is not None:
            if not isinstance(run_state_value, str) or not run_state_value.strip():
                fail("run_state.json has invalid run_id")
            run_state_run_id = run_state_value

    loaded: Dict[str, dict] = {}
    run_ids = set()

    for artifact_name, rel_path in ARTIFACT_LOCATIONS.items():
        if artifact_name not in artifacts_contract:
            fail(f"missing contract section for artifact: {artifact_name}")

        artifact_path = run_root / rel_path
        data = read_json(artifact_path)
        loaded[artifact_name] = data

        rules = artifacts_contract[artifact_name]
        ensure_required_fields(data, rules.get("required_fields", []), artifact_name)

        items = data.get("items")
        if not isinstance(items, list):
            fail(f"{artifact_name}.items must be list")

        required_item_fields = rules.get("item_required_fields", [])
        for idx, item in enumerate(items):
            if not isinstance(item, dict):
                fail(f"{artifact_name}.items[{idx}] must be object")
            ensure_required_fields(item, required_item_fields, f"{artifact_name}.items[{idx}]")

            status = item.get("status")
            if status is not None and status not in (verification_status | finding_status):
                fail(f"{artifact_name}.items[{idx}] has invalid status: {status}")

            priority = item.get("priority")
            if priority is not None and priority not in priorities:
                fail(f"{artifact_name}.items[{idx}] has invalid priority: {priority}")

        run_id = data.get("run_id")
        if not isinstance(run_id, str) or not run_id.strip():
            fail(f"{artifact_name} has invalid run_id")
        run_ids.add(run_id)

    if len(run_ids) != 1:
        fail(f"run_id mismatch across artifacts: {sorted(run_ids)}")
    artifact_run_id = next(iter(run_ids))

    if run_state_run_id is not None and run_state_run_id != artifact_run_id:
        fail(
            "run_state run_id mismatch: "
            f"run_state={run_state_run_id} artifacts={artifact_run_id}"
        )

    evidence_by_finding = {
        item["finding_id"]: item for item in loaded["verification_evidence"].get("items", [])
    }
    verified_by_finding = {
        item["finding_id"]: item for item in loaded["verified_findings"].get("items", [])
    }

    confirmed_report_ids = []
    for item in loaded["final_report_items"].get("items", []):
        if item.get("status") != "confirmed":
            continue
        finding_id = item.get("finding_id")
        confirmed_report_ids.append(finding_id)

        evidence = evidence_by_finding.get(finding_id)
        if not evidence or evidence.get("status") != "confirmed":
            fail(f"confirmed report finding lacks confirmed evidence: {finding_id}")

        verified = verified_by_finding.get(finding_id)
        if not verified or verified.get("status") != "confirmed":
            fail(f"confirmed report finding lacks confirmed verified_finding: {finding_id}")

    result = {
        "status": "ok",
        "run_id": artifact_run_id,
        "run_root": str(run_root),
        "run_mode": run_mode,
        "simulated": simulated_run,
        "run_state_present": run_state_present,
        "artifacts_checked": sorted(ARTIFACT_LOCATIONS.keys()),
        "confirmed_report_findings": confirmed_report_ids,
        "proof_gate": "passed",
    }

    result_text = json.dumps(result, indent=2)
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(result_text + "\n", encoding="utf-8")
    print(result_text)


if __name__ == "__main__":
    main()
