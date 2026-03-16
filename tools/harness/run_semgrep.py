#!/usr/bin/env python3
"""Run Semgrep and normalize results into the intermediate finding schema."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SCHEMA_PATH = REPO_ROOT / ".agent/artifacts/contracts/intermediate_finding.json"

SEVERITY_MAP = {
    "ERROR": "high",
    "WARNING": "medium",
    "INFO": "low",
}


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def fail(message: str, exit_code: int = 1) -> None:
    print(f"[run-semgrep] {message}", file=sys.stderr)
    raise SystemExit(exit_code)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run Semgrep and emit intermediate findings JSON")
    parser.add_argument("--target", required=True, help="Target repository path to scan")
    parser.add_argument("--run-id", required=True, help="Run identifier")
    parser.add_argument("--output", required=True, help="Output JSON path")
    parser.add_argument(
        "--rulesets",
        default="p/security-audit,p/owasp-top-ten",
        help="Comma-separated Semgrep config values",
    )
    return parser.parse_args()


def read_json(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except FileNotFoundError:
        fail(f"schema file not found: {path}")
    except json.JSONDecodeError as exc:
        fail(f"invalid JSON in {path}: {exc}")

    if not isinstance(data, dict):
        fail(f"JSON file must contain an object: {path}")
    return data


def normalize_rulesets(raw_rulesets: str) -> list[str]:
    rulesets = [value.strip() for value in raw_rulesets.split(",") if value.strip()]
    if not rulesets:
        fail("at least one Semgrep ruleset is required")
    return rulesets


def build_command(target: Path, rulesets: list[str]) -> list[str]:
    command = ["semgrep", "scan"]
    for ruleset in rulesets:
        command.extend(["--config", ruleset])
    command.extend(["--json", "--quiet", "--no-git-ignore", str(target)])
    return command


def run_semgrep(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, capture_output=True, text=True, check=False)


def normalize_severity(raw_severity: str | None) -> str:
    return SEVERITY_MAP.get((raw_severity or "").upper(), "low")


def normalize_cwe(raw_cwe: Any) -> str:
    if isinstance(raw_cwe, list):
        first = raw_cwe[0] if raw_cwe else ""
        return first if isinstance(first, str) and first else "CWE-unknown"
    if isinstance(raw_cwe, str) and raw_cwe:
        return raw_cwe
    return "CWE-unknown"


def normalize_path(raw_path: str, target: Path) -> str:
    path = Path(raw_path)
    base = target if target.is_dir() else target.parent

    if path.is_absolute():
        try:
            return str(path.relative_to(base))
        except ValueError:
            return str(path)
    if base.name and path.parts[:1] == (base.name,):
        stripped = Path(*path.parts[1:]).as_posix()
        return stripped if stripped != "." else path.as_posix()
    return path.as_posix()


def build_item(result: dict[str, Any], target: Path) -> dict[str, Any]:
    extra = result.get("extra")
    extra = extra if isinstance(extra, dict) else {}
    metadata = extra.get("metadata")
    metadata = metadata if isinstance(metadata, dict) else {}
    start = result.get("start")
    start = start if isinstance(start, dict) else {}

    rule = result.get("check_id")
    path = result.get("path")
    line = start.get("line", 1)
    evidence = extra.get("message") or f"Rule matched: {rule or 'unknown-rule'}"

    return {
        "tool": "semgrep",
        "rule": rule if isinstance(rule, str) and rule else "unknown-rule",
        "severity": normalize_severity(extra.get("severity")),
        "path": normalize_path(path, target) if isinstance(path, str) and path else "",
        "line": line if isinstance(line, int) else 1,
        "evidence": evidence if isinstance(evidence, str) and evidence else "Rule matched",
        "cwe": normalize_cwe(metadata.get("cwe")),
    }


def parse_results(stdout: str, target: Path) -> list[dict[str, Any]]:
    try:
        payload = json.loads(stdout or "{}")
    except json.JSONDecodeError as exc:
        fail(f"failed to parse Semgrep JSON output: {exc}")

    if not isinstance(payload, dict):
        fail("Semgrep JSON output must be an object")

    results = payload.get("results", [])
    if not isinstance(results, list):
        fail("Semgrep JSON output field 'results' must be a list")

    items = []
    for result in results:
        if not isinstance(result, dict):
            fail("Semgrep JSON output contains a non-object result")
        items.append(build_item(result, target))
    return items


def validate_payload(payload: dict[str, Any], schema: dict[str, Any]) -> None:
    required_fields = schema.get("required_fields", [])
    item_required_fields = schema.get("item_required_fields", [])

    if not isinstance(required_fields, list) or not isinstance(item_required_fields, list):
        fail("intermediate schema is missing required field definitions")

    missing = [field for field in required_fields if field not in payload]
    if missing:
        fail(f"payload missing required fields: {missing}")

    items = payload.get("items")
    if not isinstance(items, list):
        fail("payload field 'items' must be a list")

    for index, item in enumerate(items):
        if not isinstance(item, dict):
            fail(f"payload.items[{index}] must be an object")
        missing_item_fields = [field for field in item_required_fields if field not in item]
        if missing_item_fields:
            fail(f"payload.items[{index}] missing required fields: {missing_item_fields}")


def write_output(payload: dict[str, Any], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def main() -> None:
    args = parse_args()

    if shutil.which("semgrep") is None:
        fail("semgrep is not installed or not on PATH", exit_code=2)

    target = Path(args.target).resolve()
    output_path = Path(args.output)
    rulesets = normalize_rulesets(args.rulesets)
    command = build_command(target, rulesets)
    completed = run_semgrep(command)

    if completed.returncode >= 2:
        if completed.stderr.strip():
            print(completed.stderr.strip(), file=sys.stderr)
        fail(f"semgrep failed with exit code {completed.returncode}", exit_code=completed.returncode)

    items = parse_results(completed.stdout, target)
    payload = {
        "run_id": args.run_id,
        "generated_at": utc_now_iso(),
        "items": items,
    }

    schema = read_json(DEFAULT_SCHEMA_PATH)
    validate_payload(payload, schema)
    write_output(payload, output_path)
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
