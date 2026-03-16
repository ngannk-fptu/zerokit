from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
VALIDATE_SCRIPT = REPO_ROOT / "tools/harness/validate_run_artifacts.py"
EXAMPLES_DIR = REPO_ROOT / ".agent/artifacts/examples"

ARTIFACT_FILES = {
    "attack_surface.json": "02-surface/attack_surface.json",
    "hypotheses.json": "03-static/hypotheses.json",
    "static_findings.json": "03-static/static_findings.json",
    "verification_evidence.json": "04-verify/verification_evidence.json",
    "verified_findings.json": "04-verify/verified_findings.json",
    "rca_and_variants.json": "05-rca/rca_and_variants.json",
    "final_report_items.json": "06-report/final_report_items.json",
}


def create_run_fixtures(run_root: Path) -> None:
    """Copy example artifacts into a run directory layout."""
    for source_name, dest_rel in ARTIFACT_FILES.items():
        source_path = EXAMPLES_DIR / source_name
        dest_path = run_root / dest_rel
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_path, dest_path)


def run_validator(run_root: Path) -> subprocess.CompletedProcess[str]:
    cmd = [
        sys.executable,
        str(VALIDATE_SCRIPT),
        "--run-root",
        str(run_root),
    ]
    return subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True)


def test_validate_run_artifacts_passes_for_complete_valid_run(tmp_path: Path) -> None:
    run_root = tmp_path / "run-valid"
    create_run_fixtures(run_root)

    proc = run_validator(run_root)

    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["status"] == "ok"
    assert payload["proof_gate"] == "passed"
    assert payload["run_root"] == str(run_root)


def test_validate_run_artifacts_fails_when_required_file_missing(tmp_path: Path) -> None:
    run_root = tmp_path / "run-missing"
    create_run_fixtures(run_root)
    (run_root / "03-static/hypotheses.json").unlink()

    proc = run_validator(run_root)

    assert proc.returncode != 0
    assert "missing JSON file" in proc.stderr


def test_validate_run_artifacts_fails_for_malformed_json(tmp_path: Path) -> None:
    run_root = tmp_path / "run-malformed"
    create_run_fixtures(run_root)
    (run_root / "04-verify/verified_findings.json").write_text(
        "{not: json}\n", encoding="utf-8"
    )

    proc = run_validator(run_root)

    assert proc.returncode != 0
    assert "invalid JSON" in proc.stderr
