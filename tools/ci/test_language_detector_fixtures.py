#!/usr/bin/env python3
"""Fixture tests for repository language detector behavior."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_ROOT = REPO_ROOT / ".agent/harness/language-detectors/fixtures"



def fail(message: str) -> None:
    print(f"[language-detector-fixtures] {message}", file=sys.stderr)
    raise SystemExit(1)


def run_detector(target: Path, run_id: str) -> dict:
    cmd = [
        "python",
        "tools/harness/detect_repo_profile.py",
        "--target",
        str(target),
        "--run-id",
        run_id,
    ]
    proc = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True)
    if proc.returncode != 0:
        fail(f"detector failed for {target}: {proc.stderr}")
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        fail(f"invalid detector JSON for {target}: {exc}")


def assert_contains(actual: list[str], expected: list[str], label: str) -> None:
    missing = sorted(set(expected) - set(actual))
    if missing:
        fail(f"{label} missing expected values: {missing}; actual={actual}")


def assert_not_contains(actual: list[str], forbidden: list[str], label: str) -> None:
    present = sorted(set(forbidden) & set(actual))
    if present:
        fail(f"{label} unexpectedly contains: {present}; actual={actual}")


def main() -> None:
    mixed = run_detector(FIXTURE_ROOT / "mixed-monorepo", "fixture-mixed")
    assert_contains(mixed.get("languages", []), ["dotnet", "typescript", "javascript", "python"], "mixed languages")
    assert_contains(mixed.get("frameworks", []), ["aspnetcore", "express", "fastapi"], "mixed frameworks")

    nested = run_detector(FIXTURE_ROOT / "nested-java-go", "fixture-nested")
    assert_contains(nested.get("languages", []), ["java", "go"], "nested languages")
    assert_contains(nested.get("frameworks", []), ["spring", "gin"], "nested frameworks")

    ignored = run_detector(FIXTURE_ROOT / "ignored-internal-only", "fixture-ignored")
    assert_not_contains(ignored.get("languages", []), ["java", "python"], "ignored languages")

    print("[language-detector-fixtures] ok")


if __name__ == "__main__":
    main()
