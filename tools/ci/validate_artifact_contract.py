#!/usr/bin/env python3
"""Validate artifact contract examples and cross-artifact guardrails."""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CONTRACT_PATH = REPO_ROOT / ".agent/artifacts/contracts/artifact_contract.json"
EXAMPLES_DIR = REPO_ROOT / ".agent/artifacts/examples"



def fail(message: str) -> None:
    print(f"[artifact-contract] {message}", file=sys.stderr)
    raise SystemExit(1)


def read_json(path: Path) -> dict:
    if not path.exists():
        fail(f"missing JSON file: {path}")
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except json.JSONDecodeError as exc:
        fail(f"invalid JSON in {path}: {exc}")


def ensure_required_fields(data: dict, required: list[str], label: str) -> None:
    missing = [field for field in required if field not in data]
    if missing:
        fail(f"{label} missing required fields: {missing}")


def main() -> None:
    contract = read_json(CONTRACT_PATH)
    artifacts = contract.get("artifacts", {})
    enums = contract.get("enums", {})

    verification_status = set(enums.get("verification_status", []))
    finding_status = set(enums.get("finding_status", []))
    priorities = set(enums.get("priority", []))

    if not verification_status or not finding_status or not priorities:
        fail("contract enums are incomplete")

    loaded_examples: dict[str, dict] = {}
    run_ids: set[str] = set()

    for artifact_name, rules in artifacts.items():
        example_path = EXAMPLES_DIR / f"{artifact_name}.json"
        data = read_json(example_path)
        loaded_examples[artifact_name] = data

        ensure_required_fields(data, rules.get("required_fields", []), artifact_name)
        items = data.get("items")
        if not isinstance(items, list) or not items:
            fail(f"{artifact_name} must contain non-empty items list")

        required_item_fields = rules.get("item_required_fields", [])
        for index, item in enumerate(items):
            if not isinstance(item, dict):
                fail(f"{artifact_name}.items[{index}] must be object")
            ensure_required_fields(item, required_item_fields, f"{artifact_name}.items[{index}]")

            status = item.get("status")
            if status is not None and status not in verification_status | finding_status:
                fail(f"{artifact_name}.items[{index}] invalid status: {status}")

            priority = item.get("priority")
            if priority is not None and priority not in priorities:
                fail(f"{artifact_name}.items[{index}] invalid priority: {priority}")

        run_id = data.get("run_id")
        if not isinstance(run_id, str) or not run_id.strip():
            fail(f"{artifact_name} has invalid run_id")
        run_ids.add(run_id)

    if len(run_ids) != 1:
        fail(f"all examples must use same run_id, found: {sorted(run_ids)}")

    evidence_items = loaded_examples["verification_evidence"]["items"]
    evidence_by_finding = {item["finding_id"]: item for item in evidence_items}

    verified_items = loaded_examples["verified_findings"]["items"]
    verified_status = {item["finding_id"]: item["status"] for item in verified_items}

    final_report_items = loaded_examples["final_report_items"]["items"]
    for item in final_report_items:
        if item["status"] != "confirmed":
            continue
        finding_id = item["finding_id"]
        evidence = evidence_by_finding.get(finding_id)
        if not evidence or evidence.get("status") != "confirmed":
            fail(f"confirmed report item missing confirmed evidence: {finding_id}")
        if verified_status.get(finding_id) != "confirmed":
            fail(f"confirmed report item missing confirmed verified_finding: {finding_id}")

    print("[artifact-contract] ok")


if __name__ == "__main__":
    main()
