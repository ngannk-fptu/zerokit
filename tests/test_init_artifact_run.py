"""Tests for tools/harness/init_artifact_run.py."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPO_ROOT / "tools/harness/init_artifact_run.py"

RUN_STATE_REQUIRED_FIELDS = {
    "run_id",
    "generated_at",
    "target",
    "master_workflow",
    "phase_refs",
    "phase_status",
    "status",
    "summary",
    "simulated",
}


def run_init(args: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCRIPT_PATH)] + args,
        cwd=cwd or REPO_ROOT,
        capture_output=True,
        text=True,
    )


def test_init_creates_run_directory_structure(tmp_path: Path) -> None:
    """init_artifact_run.py creates all 6 phase subdirectories."""
    output_dir = tmp_path / "test-run"
    result = run_init([
        "--target", str(tmp_path),
        "--run-id", "test-run",
        "--output-dir", str(output_dir),
    ])
    assert result.returncode == 0, result.stderr

    # Expect exactly 6 phase subdirectories
    subdirs = sorted(p.name for p in output_dir.iterdir() if p.is_dir())
    assert len(subdirs) == 6


def test_init_writes_valid_run_state_json(tmp_path: Path) -> None:
    """run_state.json has all required fields; simulated defaults to false."""
    output_dir = tmp_path / "state-run"
    result = run_init([
        "--target", str(tmp_path),
        "--run-id", "state-run",
        "--output-dir", str(output_dir),
    ])
    assert result.returncode == 0, result.stderr

    run_state = json.loads((output_dir / "run_state.json").read_text(encoding="utf-8"))
    assert RUN_STATE_REQUIRED_FIELDS.issubset(run_state.keys())
    assert run_state["simulated"] is False
    assert run_state["run_id"] == "state-run"
    assert run_state["status"] == "initialized"


def test_init_dry_run_sets_simulated_true(tmp_path: Path) -> None:
    """--dry-run flag sets simulated=true in run_state.json."""
    output_dir = tmp_path / "dry-run"
    result = run_init([
        "--target", str(tmp_path),
        "--run-id", "dry-run",
        "--output-dir", str(output_dir),
        "--dry-run",
    ])
    assert result.returncode == 0, result.stderr

    run_state = json.loads((output_dir / "run_state.json").read_text(encoding="utf-8"))
    assert run_state["simulated"] is True


def test_init_fails_on_duplicate_run_id(tmp_path: Path) -> None:
    """Running init twice with the same output dir must fail on the second run."""
    output_dir = tmp_path / "dup-run"
    first = run_init([
        "--target", str(tmp_path),
        "--run-id", "dup-run",
        "--output-dir", str(output_dir),
    ])
    assert first.returncode == 0, first.stderr

    second = run_init([
        "--target", str(tmp_path),
        "--run-id", "dup-run",
        "--output-dir", str(output_dir),
    ])
    assert second.returncode != 0


def test_init_help_exits_zero() -> None:
    """--help returns exit code 0."""
    result = run_init(["--help"])
    assert result.returncode == 0
