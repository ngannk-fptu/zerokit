#!/usr/bin/env python3
"""Run Gitleaks and emit normalized intermediate findings."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SCHEMA = REPO_ROOT / ".agent/artifacts/contracts/intermediate_finding.json"


def fail(message: str, exit_code: int = 2) -> None:
    print(f"[run-gitleaks] {message}", file=sys.stderr)
    raise SystemExit(exit_code)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run gitleaks and emit intermediate findings JSON")
    parser.add_argument("--target", required=True, help="Target repository or directory path")
    parser.add_argument("--run-id", required=True, help="Run identifier")
    parser.add_argument("--output", required=True, help="Output path for intermediate JSON")
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


def ensure_required_fields(data: dict[str, Any], required: list[str], label: str) -> None:
    missing = [field for field in required if field not in data]
    if missing:
        fail(f"{label} missing required fields: {missing}")


def load_schema() -> dict[str, Any]:
    schema = read_json(DEFAULT_SCHEMA)
    if not isinstance(schema, dict):
        fail(f"schema must be a JSON object: {DEFAULT_SCHEMA}")
    required_fields = schema.get("required_fields")
    item_required_fields = schema.get("item_required_fields")
    if not isinstance(required_fields, list) or not all(isinstance(field, str) for field in required_fields):
        fail(f"schema required_fields must be a list of strings: {DEFAULT_SCHEMA}")
    if not isinstance(item_required_fields, list) or not all(
        isinstance(field, str) for field in item_required_fields
    ):
        fail(f"schema item_required_fields must be a list of strings: {DEFAULT_SCHEMA}")
    return schema


def extract_findings(report: Any) -> list[dict[str, Any]]:
    if isinstance(report, list):
        findings = report
    elif isinstance(report, dict) and isinstance(report.get("findings"), list):
        findings = report["findings"]
    else:
        fail("unexpected gitleaks report format")

    normalized_findings: list[dict[str, Any]] = []
    for idx, finding in enumerate(findings):
        if not isinstance(finding, dict):
            fail(f"gitleaks report entry {idx} must be an object")
        normalized_findings.append(finding)
    return normalized_findings


def normalize_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for idx, finding in enumerate(findings):
        rule = finding.get("RuleID")
        path = finding.get("File")
        line = finding.get("StartLine")

        if not isinstance(rule, str) or not rule.strip():
            fail(f"gitleaks finding {idx} has invalid RuleID")
        if not isinstance(path, str) or not path.strip():
            fail(f"gitleaks finding {idx} has invalid File")
        if not isinstance(line, int) or line <= 0:
            fail(f"gitleaks finding {idx} has invalid StartLine")

        items.append(
            {
                "tool": "gitleaks",
                "rule": rule,
                "severity": "high",
                "path": path,
                "line": line,
                "evidence": f"Secret detected: {rule}",
                "cwe": "CWE-798",
            }
        )
    return items


def validate_output(payload: dict[str, Any], schema: dict[str, Any]) -> None:
    ensure_required_fields(payload, schema["required_fields"], "intermediate output")

    run_id = payload.get("run_id")
    generated_at = payload.get("generated_at")
    items = payload.get("items")

    if not isinstance(run_id, str) or not run_id.strip():
        fail("intermediate output has invalid run_id")
    if not isinstance(generated_at, str) or not generated_at.strip():
        fail("intermediate output has invalid generated_at")
    if not isinstance(items, list):
        fail("intermediate output items must be a list")

    for idx, item in enumerate(items):
        if not isinstance(item, dict):
            fail(f"intermediate output item {idx} must be an object")
        ensure_required_fields(item, schema["item_required_fields"], f"intermediate output item {idx}")

        if item.get("tool") != "gitleaks":
            fail(f"intermediate output item {idx} has invalid tool: {item.get('tool')}")
        if not isinstance(item.get("rule"), str) or not item["rule"].strip():
            fail(f"intermediate output item {idx} has invalid rule")
        if item.get("severity") != "high":
            fail(f"intermediate output item {idx} has invalid severity: {item.get('severity')}")
        if not isinstance(item.get("path"), str) or not item["path"].strip():
            fail(f"intermediate output item {idx} has invalid path")
        if not isinstance(item.get("line"), int) or item["line"] <= 0:
            fail(f"intermediate output item {idx} has invalid line")
        if not isinstance(item.get("evidence"), str) or not item["evidence"].strip():
            fail(f"intermediate output item {idx} has invalid evidence")
        if item.get("cwe") != "CWE-798":
            fail(f"intermediate output item {idx} has invalid cwe: {item.get('cwe')}")


def run_gitleaks(target: Path, report_path: Path) -> subprocess.CompletedProcess[str]:
    cmd = [
        "gitleaks",
        "detect",
        "--source",
        str(target),
        "--report-format",
        "json",
        "--report-path",
        str(report_path),
        "--no-git",
    ]
    return subprocess.run(cmd, capture_output=True, text=True)


def write_output(payload: dict[str, Any], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def main() -> None:
    args = parse_args()

    if shutil.which("gitleaks") is None:
        fail("gitleaks is not installed or not on PATH", exit_code=2)

    schema = load_schema()
    target = Path(args.target).resolve()
    output_path = Path(args.output)

    with tempfile.TemporaryDirectory(prefix="run-gitleaks-") as temp_dir:
        report_path = Path(temp_dir) / "gitleaks-report.json"
        proc = run_gitleaks(target, report_path)

        if proc.returncode >= 2:
            stderr = (proc.stderr or "").strip()
            if stderr:
                print(f"[run-gitleaks] {stderr}", file=sys.stderr)
            raise SystemExit(proc.returncode)

        findings = extract_findings(read_json(report_path))

    payload = {
        "run_id": args.run_id,
        "generated_at": utc_now_iso(),
        "items": normalize_findings(findings),
    }
    validate_output(payload, schema)
    write_output(payload, output_path)

    if proc.returncode == 1:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
