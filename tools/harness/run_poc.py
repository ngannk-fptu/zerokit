#!/usr/bin/env python3
"""Run a PoC script inside Docker and emit verification evidence."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def fail(message: str, exit_code: int = 1) -> None:
    print(f"[run-poc] {message}", file=sys.stderr)
    raise SystemExit(exit_code)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a PoC script inside Docker")
    parser.add_argument("--finding-id", required=True, help="Static finding identifier")
    parser.add_argument("--poc-script", required=True, help="Path to the PoC script")
    parser.add_argument("--target", required=True, help="Target directory to mount read-only")
    parser.add_argument("--run-id", required=True, help="Run identifier")
    parser.add_argument("--output", required=True, help="Output path for verification evidence JSON")
    parser.add_argument("--timeout", type=int, default=30, help="Docker execution timeout in seconds")
    return parser.parse_args()


def build_command(poc_script: Path, target: Path) -> list[str]:
    return [
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "--memory",
        "128m",
        "--cpus",
        "1",
        "--read-only",
        "-v",
        f"{target}:/target:ro",
        "-v",
        f"{poc_script}:/work/poc.py:ro",
        "python:3.11-slim",
        "python",
        "/work/poc.py",
    ]


def format_output(stdout: str, stderr: str) -> str:
    combined = "\n".join(part for part in (stdout.strip(), stderr.strip()) if part).strip()
    return combined[:1000] if combined else "No output captured"


def write_payload(output_path: Path, payload: dict[str, object], log_text: str) -> None:
    artifact_path = output_path.parent / f"{payload['items'][0]['finding_id']}.log"
    artifact_path.write_text(log_text + ("\n" if log_text and not log_text.endswith("\n") else ""), encoding="utf-8")
    payload["items"][0]["artifact_path"] = str(artifact_path)
    output_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def main() -> None:
    args = parse_args()

    if shutil.which("docker") is None:
        fail("docker is not installed or not on PATH", exit_code=2)

    poc_script = Path(args.poc_script).resolve()
    target = Path(args.target).resolve()
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    command = build_command(poc_script, target)

    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=args.timeout, check=False)
        log_text = format_output(completed.stdout, completed.stderr)
        # Infrastructure failures (daemon down, permission denied, image pull error) must
        # not be recorded as rejected — the PoC never ran, so the finding is inconclusive.
        # Docker exits 125 for daemon/setup errors, 126 for permission errors on the binary,
        # 127 for command not found. Any of these are environment failures, not PoC failures.
        if completed.returncode in (125, 126, 127):
            status = "inconclusive"
        else:
            status = "confirmed" if completed.returncode == 0 else "rejected"
        exit_code = completed.returncode
    except subprocess.TimeoutExpired as exc:
        status = "inconclusive"
        exit_code = 124
        stdout = exc.stdout if isinstance(exc.stdout, str) else ""
        stderr = exc.stderr if isinstance(exc.stderr, str) else ""
        timeout_message = f"Execution timeout after {args.timeout} seconds"
        log_text = format_output(stdout, "\n".join(part for part in (stderr, timeout_message) if part))

    payload = {
        "run_id": args.run_id,
        "generated_at": utc_now_iso(),
        "items": [
            {
                "finding_id": args.finding_id,
                "status": status,
                "command": " ".join(command),
                "exit_code": exit_code,
                "output_excerpt": log_text,
                "artifact_path": "",
            }
        ],
    }
    write_payload(output_path, payload, log_text)


if __name__ == "__main__":
    main()
