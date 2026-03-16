from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPO_ROOT / "tools/harness/detect_repo_profile.py"
FIXTURE_ROOT = REPO_ROOT / ".agent/harness/language-detectors/fixtures"

REQUIRED_KEYS = {
    "run_id",
    "generated_at",
    "languages",
    "frameworks",
    "build_commands",
    "test_commands",
    "entrypoints",
    "trust_boundaries",
    "high_risk_sinks",
}


def run_detect_repo_profile(target: Path, output_path: Path, run_id: str) -> dict:
    cmd = [
        sys.executable,
        str(SCRIPT_PATH),
        "--target",
        str(target),
        "--run-id",
        run_id,
        "--output",
        str(output_path),
    ]
    proc = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    assert output_path.exists(), "detect_repo_profile did not write output JSON"

    return json.loads(output_path.read_text(encoding="utf-8"))


def assert_profile_shape(profile: dict) -> None:
    assert REQUIRED_KEYS.issubset(profile.keys())

    assert isinstance(profile["run_id"], str)
    assert isinstance(profile["generated_at"], str)
    assert isinstance(profile["languages"], list)
    assert isinstance(profile["frameworks"], list)
    assert isinstance(profile["build_commands"], list)
    assert isinstance(profile["test_commands"], list)
    assert isinstance(profile["entrypoints"], list)
    assert isinstance(profile["trust_boundaries"], list)
    assert isinstance(profile["high_risk_sinks"], list)

    for entry in profile["entrypoints"]:
        assert isinstance(entry, dict)
        assert {"kind", "path", "line"}.issubset(entry.keys())


def test_python_fixture_detects_python(tmp_path: Path) -> None:
    target = FIXTURE_ROOT / "mixed-monorepo/services/worker"
    output = tmp_path / "profile-python.json"

    profile = run_detect_repo_profile(target, output, run_id="detect-python")

    assert_profile_shape(profile)
    assert profile["run_id"] == "detect-python"
    assert "python" in profile["languages"]


def test_go_fixture_detects_go(tmp_path: Path) -> None:
    target = FIXTURE_ROOT / "nested-java-go/tools"
    output = tmp_path / "profile-go.json"

    profile = run_detect_repo_profile(target, output, run_id="detect-go")

    assert_profile_shape(profile)
    assert profile["run_id"] == "detect-go"
    assert "go" in profile["languages"]


def test_typescript_fixture_detects_typescript(tmp_path: Path) -> None:
    target = FIXTURE_ROOT / "mixed-monorepo/services/web"
    output = tmp_path / "profile-typescript.json"

    profile = run_detect_repo_profile(target, output, run_id="detect-typescript")

    assert_profile_shape(profile)
    assert profile["run_id"] == "detect-typescript"
    assert "typescript" in profile["languages"]


def test_empty_directory_detects_no_languages(tmp_path: Path) -> None:
    target = tmp_path / "empty"
    target.mkdir(parents=True)
    output = tmp_path / "profile-empty.json"

    profile = run_detect_repo_profile(target, output, run_id="detect-empty")

    assert_profile_shape(profile)
    assert profile["run_id"] == "detect-empty"
    assert profile["languages"] == []


def test_mixed_language_directory_detects_multiple_languages(tmp_path: Path) -> None:
    target = tmp_path / "mixed"
    target.mkdir(parents=True)
    (target / "service.py").write_text("print('hello')\n", encoding="utf-8")
    (target / "worker.go").write_text("package main\nfunc main() {}\n", encoding="utf-8")
    output = tmp_path / "profile-mixed.json"

    profile = run_detect_repo_profile(target, output, run_id="detect-mixed")

    assert_profile_shape(profile)
    assert profile["run_id"] == "detect-mixed"
    assert {"python", "go"}.issubset(set(profile["languages"]))
