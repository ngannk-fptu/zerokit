#!/usr/bin/env python3
"""Run Joern via HTTP API and normalize results into intermediate findings."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SCHEMA_PATH = REPO_ROOT / ".agent/artifacts/contracts/intermediate_finding.json"

TAINT_QUERY = (
    'cpg.method.parameter.evalType(".*(?i)(request|input|user|param|query|body|form|header|cookie|path|url).*")\n'
    '  .reachableBy(cpg.call.name(".*(?i)(exec|eval|system|popen|query|execute|write|send|open|read|load|deserialize|'
    "unserialize|pickle|yaml\\.load|fromstring|innerhtml|"
    'dangerouslysetinnerhtml).*))")\n'
    "  .l"
)

FINDING_RE = re.compile(r"(?P<path>[\w./\\-]+\.[A-Za-z0-9]+):(?P<line>\d+)")


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def fail(message: str, exit_code: int = 1) -> None:
    print(f"[run-joern] {message}", file=sys.stderr)
    raise SystemExit(exit_code)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run Joern HTTP API and emit intermediate findings JSON")
    parser.add_argument("--target", required=True, help="Target repository path to analyze")
    parser.add_argument("--run-id", required=True, help="Run identifier")
    parser.add_argument("--output", required=True, help="Output JSON path")
    parser.add_argument("--port", type=int, default=8080, help="Local Joern API port")
    parser.add_argument("--image", default="ghcr.io/joernio/joern", help="Joern container image")
    parser.add_argument("--timeout", type=int, default=60, help="Health-check timeout in seconds")
    return parser.parse_args()


def read_json(path: Path) -> dict[str, Any]:
    data: Any = {}
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


def severity_for_text(text: str) -> str:
    lowered = text.lower()
    if any(token in lowered for token in ("exec", "system", "popen", "eval")):
        return "critical"
    if any(token in lowered for token in ("query", "execute", "write")):
        return "high"
    if any(token in lowered for token in ("read", "load", "open")):
        return "medium"
    return "low"


def cwe_for_text(text: str) -> str:
    lowered = text.lower()
    if "eval" in lowered:
        return "CWE-94"
    if any(token in lowered for token in ("exec", "system", "popen")):
        return "CWE-78"
    if any(token in lowered for token in ("query", "execute")):
        return "CWE-89"
    if any(token in lowered for token in ("pickle", "yaml.load", "deserialize", "unserialize")):
        return "CWE-502"
    if any(token in lowered for token in ("innerhtml", "dangerouslysetinnerhtml", "fromstring")):
        return "CWE-79"
    return "CWE-unknown"


def parse_stdout(stdout: str, target: Path) -> list[dict[str, Any]]:
    lines = [line.strip() for line in stdout.splitlines() if line.strip()]
    items: list[dict[str, Any]] = []
    for line in lines:
        match = FINDING_RE.search(line)
        if match is None:
            continue
        raw_path = match.group("path")
        raw_line = match.group("line")
        line_number = int(raw_line) if raw_line.isdigit() else 1
        items.append(
            {
                "tool": "joern",
                "rule": "taint-flow",
                "severity": severity_for_text(line),
                "path": normalize_path(raw_path, target),
                "line": line_number,
                "evidence": line,
                "cwe": cwe_for_text(line),
            }
        )
    return items


def validate_payload(payload: dict[str, Any], schema: dict[str, Any]) -> None:
    required_fields = schema.get("required_fields", [])
    item_required_fields = schema.get("item_required_fields", [])

    if not isinstance(required_fields, list) or not isinstance(item_required_fields, list):
        fail("intermediate schema is missing required field definitions")

    missing = [field for field in required_fields if field not in payload]
    if missing:
        fail(f"payload missing required fields: {missing}")

    items = payload.get("items", [])
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


def wait_for_health_and_import(base_url: str, timeout_seconds: int) -> None:
    attempts = max(1, timeout_seconds // 5)
    for _ in range(attempts):
        try:
            request = urllib.request.Request(
                url=base_url + "/query-sync",
                data=json.dumps({"query": 'importCode("/app")'}).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=10) as response:
                if getattr(response, "status", 0) == 200:
                    return
        except (ConnectionError, urllib.error.URLError, TimeoutError):
            pass
        time.sleep(5)
    fail(f"Joern server did not become ready within {timeout_seconds}s", exit_code=2)


def query_taint(base_url: str) -> str:
    raw: bytes = b""
    request = urllib.request.Request(
        url=base_url + "/query-sync",
        data=json.dumps({"query": TAINT_QUERY}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read()
    except (ConnectionError, urllib.error.URLError, TimeoutError) as exc:
        fail(f"failed to query Joern API: {exc}", exit_code=2)

    payload_data: Any = {}
    try:
        payload_data = json.loads(raw)
    except json.JSONDecodeError as exc:
        fail(f"invalid Joern API JSON response: {exc}", exit_code=2)

    if not isinstance(payload_data, dict):
        fail("Joern API response must be a JSON object", exit_code=2)

    stdout = payload_data.get("stdout", "")
    if not isinstance(stdout, str):
        fail("Joern API response field 'stdout' must be a string", exit_code=2)
    return stdout


def main() -> None:
    args = parse_args()

    if shutil.which("docker") is None:
        fail("docker is not installed or not on PATH", exit_code=2)

    target = Path(args.target).resolve()
    output_path = Path(args.output)
    base_url = f"http://localhost:{args.port}"
    container_id = ""

    try:
        start = subprocess.run(
            [
                "docker",
                "run",
                "-d",
                "--rm",
                "-p",
                f"{args.port}:8080",
                "-v",
                f"{target}:/app:rw",
                "-w",
                "/app",
                args.image,
                "joern",
                "--server",
                "--server-host",
                "0.0.0.0",
                "--server-port",
                "8080",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if start.returncode != 0:
            stderr = start.stderr.strip()
            if stderr:
                print(stderr, file=sys.stderr)
            fail(f"failed to start Joern container (exit code {start.returncode})", exit_code=2)
        container_id = start.stdout.strip()
        if not container_id:
            fail("failed to read Joern container id from docker output", exit_code=2)

        wait_for_health_and_import(base_url, args.timeout)
        stdout = query_taint(base_url)
        items = parse_stdout(stdout, target)

        payload = {
            "run_id": args.run_id,
            "generated_at": utc_now_iso(),
            "items": items,
        }
        schema = read_json(DEFAULT_SCHEMA_PATH)
        validate_payload(payload, schema)
        write_output(payload, output_path)
        print(json.dumps(payload, indent=2))
    finally:
        if container_id:
            subprocess.run(["docker", "stop", container_id], check=False, capture_output=True, text=True)


if __name__ == "__main__":
    main()
