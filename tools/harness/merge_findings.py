#!/usr/bin/env python3
"""Merge intermediate scanner outputs into contract-valid static findings."""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_INTERMEDIATE_SCHEMA = REPO_ROOT / ".agent/artifacts/contracts/intermediate_finding.json"
DEFAULT_CONTRACT = REPO_ROOT / ".agent/artifacts/contracts/artifact_contract.json"

SEVERITY_RANK = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
}

HYPOTHESIS_PATH_PATTERN = re.compile(r"([A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+)(?::\d+)?")


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def fail(message: str, exit_code: int = 1) -> None:
    print(f"[merge-findings] {message}", file=sys.stderr)
    raise SystemExit(exit_code)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Merge intermediate finding files into static_findings.json")
    parser.add_argument("--inputs", nargs="+", required=True, help="One or more intermediate finding JSON files")
    parser.add_argument("--hypotheses", default="", help="Optional hypotheses.json path")
    parser.add_argument("--run-id", required=True, help="Run identifier")
    parser.add_argument("--output", required=True, help="Output path for static_findings.json")
    return parser.parse_args()


def read_json(path: Path) -> Any:
    if not path.exists():
        fail(f"missing JSON file: {path}")
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except json.JSONDecodeError as exc:
        fail(f"invalid JSON in {path}: {exc}")
    except OSError as exc:
        fail(f"failed reading {path}: {exc}")


def load_intermediate_schema() -> dict[str, Any]:
    schema = read_json(DEFAULT_INTERMEDIATE_SCHEMA)
    if not isinstance(schema, dict):
        fail(f"intermediate schema must be a JSON object: {DEFAULT_INTERMEDIATE_SCHEMA}")

    required_fields = schema.get("required_fields")
    item_required_fields = schema.get("item_required_fields")
    if not isinstance(required_fields, list) or not all(isinstance(field, str) for field in required_fields):
        fail(f"intermediate schema required_fields must be a list of strings: {DEFAULT_INTERMEDIATE_SCHEMA}")
    if not isinstance(item_required_fields, list) or not all(
        isinstance(field, str) for field in item_required_fields
    ):
        fail(f"intermediate schema item_required_fields must be a list of strings: {DEFAULT_INTERMEDIATE_SCHEMA}")
    return schema


def load_contract() -> dict[str, Any]:
    contract = read_json(DEFAULT_CONTRACT)
    if not isinstance(contract, dict):
        fail(f"artifact contract must be a JSON object: {DEFAULT_CONTRACT}")

    artifacts = contract.get("artifacts")
    enums = contract.get("enums")
    if not isinstance(artifacts, dict) or not isinstance(enums, dict):
        fail(f"artifact contract is missing required sections: {DEFAULT_CONTRACT}")
    if "hypotheses" not in artifacts or "static_findings" not in artifacts:
        fail(f"artifact contract is missing required artifact definitions: {DEFAULT_CONTRACT}")
    return contract


def ensure_required_fields(data: dict[str, Any], required: list[str], label: str) -> None:
    missing = [field for field in required if field not in data]
    if missing:
        fail(f"{label} missing required fields: {missing}")


def normalize_path(raw_path: str) -> str:
    path = raw_path.strip().replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    return path


def directory_for(path: str) -> str:
    parent = Path(path).parent.as_posix()
    return "" if parent == "." else parent


def validate_intermediate_payload(payload: dict[str, Any], schema: dict[str, Any], path: Path, run_id: str) -> None:
    ensure_required_fields(payload, schema["required_fields"], f"intermediate payload {path}")

    payload_run_id = payload.get("run_id")
    generated_at = payload.get("generated_at")
    items = payload.get("items")

    if not isinstance(payload_run_id, str) or not payload_run_id.strip():
        fail(f"intermediate payload {path} has invalid run_id")
    if payload_run_id != run_id:
        fail(f"intermediate payload {path} run_id mismatch: {payload_run_id} != {run_id}")
    if not isinstance(generated_at, str) or not generated_at.strip():
        fail(f"intermediate payload {path} has invalid generated_at")
    if not isinstance(items, list):
        fail(f"intermediate payload {path} items must be a list")

    for index, item in enumerate(items):
        if not isinstance(item, dict):
            fail(f"intermediate payload {path} item {index} must be an object")
        ensure_required_fields(item, schema["item_required_fields"], f"intermediate payload {path} item {index}")

        tool = item.get("tool")
        rule = item.get("rule")
        severity = item.get("severity")
        finding_path = item.get("path")
        line = item.get("line")
        evidence = item.get("evidence")
        cwe = item.get("cwe")

        if not isinstance(tool, str) or not tool.strip():
            fail(f"intermediate payload {path} item {index} has invalid tool")
        if not isinstance(rule, str) or not rule.strip():
            fail(f"intermediate payload {path} item {index} has invalid rule")
        if severity not in SEVERITY_RANK:
            fail(f"intermediate payload {path} item {index} has invalid severity: {severity}")
        if not isinstance(finding_path, str) or not finding_path.strip():
            fail(f"intermediate payload {path} item {index} has invalid path")
        if not isinstance(line, int) or line <= 0:
            fail(f"intermediate payload {path} item {index} has invalid line")
        if not isinstance(evidence, str) or not evidence.strip():
            fail(f"intermediate payload {path} item {index} has invalid evidence")
        if not isinstance(cwe, str) or not cwe.strip():
            fail(f"intermediate payload {path} item {index} has invalid cwe")


def extract_hypothesis_paths(hypothesis: dict[str, Any]) -> set[str]:
    candidates: set[str] = set()

    explicit_path = hypothesis.get("path")
    if isinstance(explicit_path, str) and explicit_path.strip():
        candidates.add(normalize_path(explicit_path))

    for field in ("source", "sink"):
        value = hypothesis.get(field)
        if not isinstance(value, str):
            continue
        for match in HYPOTHESIS_PATH_PATTERN.finditer(value):
            candidates.add(normalize_path(match.group(1)))

    return {candidate for candidate in candidates if candidate}


def validate_hypotheses_payload(payload: dict[str, Any], rules: dict[str, Any], path: Path, run_id: str) -> None:
    required_fields = rules.get("required_fields")
    item_required_fields = rules.get("item_required_fields")
    if not isinstance(required_fields, list) or not isinstance(item_required_fields, list):
        fail(f"hypotheses contract is malformed: {DEFAULT_CONTRACT}")

    ensure_required_fields(payload, required_fields, f"hypotheses payload {path}")

    payload_run_id = payload.get("run_id")
    generated_at = payload.get("generated_at")
    items = payload.get("items")

    if not isinstance(payload_run_id, str) or not payload_run_id.strip():
        fail(f"hypotheses payload {path} has invalid run_id")
    if payload_run_id != run_id:
        fail(f"hypotheses payload {path} run_id mismatch: {payload_run_id} != {run_id}")
    if not isinstance(generated_at, str) or not generated_at.strip():
        fail(f"hypotheses payload {path} has invalid generated_at")
    if not isinstance(items, list):
        fail(f"hypotheses payload {path} items must be a list")

    for index, item in enumerate(items):
        if not isinstance(item, dict):
            fail(f"hypotheses payload {path} item {index} must be an object")
        ensure_required_fields(item, item_required_fields, f"hypotheses payload {path} item {index}")

        for field in item_required_fields:
            value = item.get(field)
            if not isinstance(value, str) or not value.strip():
                fail(f"hypotheses payload {path} item {index} has invalid {field}")


def load_hypotheses(path: Path | None, contract: dict[str, Any], run_id: str) -> list[dict[str, Any]]:
    if path is None or not path.exists():
        return []

    payload = read_json(path)
    if not isinstance(payload, dict):
        fail(f"hypotheses payload must be a JSON object: {path}")

    rules = contract["artifacts"]["hypotheses"]
    validate_hypotheses_payload(payload, rules, path, run_id)

    hypotheses: list[dict[str, Any]] = []
    for item in payload["items"]:
        hypothesis = dict(item)
        hypothesis["_paths"] = extract_hypothesis_paths(hypothesis)
        hypothesis["_dirs"] = {directory_for(candidate) for candidate in hypothesis["_paths"]}
        hypotheses.append(hypothesis)
    return hypotheses


def load_intermediate_items(paths: list[Path], schema: dict[str, Any], run_id: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for path in paths:
        payload = read_json(path)
        if not isinstance(payload, dict):
            fail(f"intermediate payload must be a JSON object: {path}")
        validate_intermediate_payload(payload, schema, path, run_id)
        for item in payload["items"]:
            finding = dict(item)
            finding["path"] = normalize_path(finding["path"])
            findings.append(finding)
    return findings


def select_hypothesis_id(finding: dict[str, Any], hypotheses: list[dict[str, Any]]) -> str:
    same_cwe = [hypothesis for hypothesis in hypotheses if hypothesis.get("cwe") == finding["cwe"]]
    if not same_cwe:
        return "unlinked"

    finding_path = normalize_path(finding["path"])
    finding_dir = directory_for(finding_path)

    level_one = [hypothesis for hypothesis in same_cwe if finding_path in hypothesis["_paths"]]
    if level_one:
        return min(hypothesis["id"] for hypothesis in level_one)

    level_two = [hypothesis for hypothesis in same_cwe if hypothesis["_dirs"] and finding_dir in hypothesis["_dirs"]]
    if level_two:
        return min(hypothesis["id"] for hypothesis in level_two)

    return min(hypothesis["id"] for hypothesis in same_cwe)


def enrich_findings(findings: list[dict[str, Any]], hypotheses: list[dict[str, Any]]) -> list[dict[str, Any]]:
    enriched: list[dict[str, Any]] = []
    for finding in findings:
        enriched_finding = dict(finding)
        enriched_finding["hypothesis_id"] = (
            select_hypothesis_id(enriched_finding, hypotheses) if hypotheses else "unlinked"
        )
        enriched.append(enriched_finding)
    return enriched


def fingerprint_for(finding: dict[str, Any]) -> tuple[str, int, str]:
    rule_or_cwe = finding["rule"] if finding.get("rule") else finding["cwe"]
    return (finding["path"], finding["line"], rule_or_cwe)


def is_linked(finding: dict[str, Any]) -> bool:
    return finding.get("hypothesis_id") != "unlinked"


def should_replace(existing: dict[str, Any], candidate: dict[str, Any]) -> bool:
    existing_rank = SEVERITY_RANK[existing["severity"]]
    candidate_rank = SEVERITY_RANK[candidate["severity"]]
    if candidate_rank != existing_rank:
        return candidate_rank > existing_rank

    existing_linked = is_linked(existing)
    candidate_linked = is_linked(candidate)
    if candidate_linked != existing_linked:
        return candidate_linked

    existing_hypothesis = existing["hypothesis_id"]
    candidate_hypothesis = candidate["hypothesis_id"]
    if candidate_hypothesis != existing_hypothesis:
        return candidate_hypothesis < existing_hypothesis

    candidate_key = (candidate["tool"], candidate["evidence"])
    existing_key = (existing["tool"], existing["evidence"])
    return candidate_key < existing_key


def deduplicate_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: dict[tuple[str, int, str], dict[str, Any]] = {}
    for finding in findings:
        fingerprint = fingerprint_for(finding)
        existing = deduped.get(fingerprint)
        if existing is None or should_replace(existing, finding):
            deduped[fingerprint] = finding
    return list(deduped.values())


def sort_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        findings,
        key=lambda finding: (
            -SEVERITY_RANK[finding["severity"]],
            finding["path"],
            finding["line"],
            finding["tool"],
            finding["hypothesis_id"],
            finding["evidence"],
        ),
    )


def assign_ids(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for index, finding in enumerate(findings, start=1):
        items.append(
            {
                "id": f"sf-{index:03d}",
                "tool": finding["tool"],
                "severity": finding["severity"],
                "path": finding["path"],
                "line": finding["line"],
                "evidence": finding["evidence"],
                "hypothesis_id": finding["hypothesis_id"],
            }
        )
    return items


def validate_static_findings_payload(payload: dict[str, Any], contract: dict[str, Any], run_id: str) -> None:
    rules = contract["artifacts"]["static_findings"]
    required_fields = rules.get("required_fields")
    item_required_fields = rules.get("item_required_fields")
    priorities = set(contract.get("enums", {}).get("priority", []))
    if not isinstance(required_fields, list) or not isinstance(item_required_fields, list):
        fail(f"static findings contract is malformed: {DEFAULT_CONTRACT}")
    if not priorities:
        fail(f"artifact contract is missing severity enums: {DEFAULT_CONTRACT}")

    ensure_required_fields(payload, required_fields, "static_findings")

    payload_run_id = payload.get("run_id")
    generated_at = payload.get("generated_at")
    items = payload.get("items")

    if payload_run_id != run_id:
        fail(f"static_findings run_id mismatch: {payload_run_id} != {run_id}")
    if not isinstance(generated_at, str) or not generated_at.strip():
        fail("static_findings has invalid generated_at")
    if not isinstance(items, list):
        fail("static_findings items must be a list")

    for index, item in enumerate(items):
        if not isinstance(item, dict):
            fail(f"static_findings item {index} must be an object")
        ensure_required_fields(item, item_required_fields, f"static_findings item {index}")

        item_id = item.get("id")
        tool = item.get("tool")
        severity = item.get("severity")
        path = item.get("path")
        line = item.get("line")
        evidence = item.get("evidence")
        hypothesis_id = item.get("hypothesis_id")

        if not isinstance(item_id, str) or not item_id.startswith("sf-"):
            fail(f"static_findings item {index} has invalid id")
        if not isinstance(tool, str) or not tool.strip():
            fail(f"static_findings item {index} has invalid tool")
        if severity not in priorities:
            fail(f"static_findings item {index} has invalid severity: {severity}")
        if not isinstance(path, str) or not path.strip():
            fail(f"static_findings item {index} has invalid path")
        if not isinstance(line, int) or line <= 0:
            fail(f"static_findings item {index} has invalid line")
        if not isinstance(evidence, str) or not evidence.strip():
            fail(f"static_findings item {index} has invalid evidence")
        if not isinstance(hypothesis_id, str) or not hypothesis_id.strip():
            fail(f"static_findings item {index} has invalid hypothesis_id")


def write_output(payload: dict[str, Any], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def main() -> None:
    args = parse_args()

    schema = load_intermediate_schema()
    contract = load_contract()

    input_paths = [Path(raw_path) for raw_path in args.inputs]
    hypotheses_path = Path(args.hypotheses) if args.hypotheses else None
    output_path = Path(args.output)

    findings = load_intermediate_items(input_paths, schema, args.run_id)
    hypotheses = load_hypotheses(hypotheses_path, contract, args.run_id)
    enriched_findings = enrich_findings(findings, hypotheses)
    deduped_findings = deduplicate_findings(enriched_findings)
    sorted_findings = sort_findings(deduped_findings)

    payload = {
        "run_id": args.run_id,
        "generated_at": utc_now_iso(),
        "items": assign_ids(sorted_findings),
    }
    validate_static_findings_payload(payload, contract, args.run_id)
    write_output(payload, output_path)
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
