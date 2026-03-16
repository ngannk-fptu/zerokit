from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

import tools.harness.run_semgrep as run_semgrep

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPO_ROOT / "tools/harness/run_semgrep.py"


def run_main(monkeypatch: pytest.MonkeyPatch, args: list[str]) -> None:
    monkeypatch.setattr(sys, "argv", ["run_semgrep.py", *args])
    run_semgrep.main()


def test_run_semgrep_normalizes_results_and_splits_rulesets(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    target = tmp_path / "repo"
    output = tmp_path / "semgrep.json"
    target.mkdir()

    semgrep_output = {
        "results": [
            {
                "check_id": "rule.error",
                "path": "src/error.py",
                "start": {"line": 10},
                "extra": {
                    "message": "Error severity finding",
                    "severity": "ERROR",
                    "metadata": {"cwe": ["CWE-78", "CWE-88"]},
                },
            },
            {
                "check_id": "rule.warning",
                "path": "src/warning.py",
                "start": {"line": 20},
                "extra": {
                    "message": "Warning severity finding",
                    "severity": "WARNING",
                    "metadata": {"cwe": []},
                },
            },
            {
                "check_id": "rule.info",
                "path": "src/info.py",
                "start": {"line": 30},
                "extra": {
                    "message": "Info severity finding",
                    "severity": "INFO",
                    "metadata": {},
                },
            },
        ]
    }

    captured_commands: list[list[str]] = []

    def fake_run(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        captured_commands.append(command)
        return subprocess.CompletedProcess(
            args=command,
            returncode=1,
            stdout=json.dumps(semgrep_output),
            stderr="ignored",
        )

    monkeypatch.setattr(run_semgrep.shutil, "which", lambda _: "/usr/bin/semgrep")
    monkeypatch.setattr(run_semgrep.subprocess, "run", fake_run)

    run_main(
        monkeypatch,
        [
            "--target",
            str(target),
            "--run-id",
            "run-semgrep",
            "--output",
            str(output),
            "--rulesets",
            "p/security-audit,p/owasp-top-ten",
        ],
    )

    payload = json.loads(output.read_text(encoding="utf-8"))
    assert [item["severity"] for item in payload["items"]] == ["high", "medium", "low"]
    assert [item["cwe"] for item in payload["items"]] == ["CWE-78", "CWE-unknown", "CWE-unknown"]
    assert all(item["tool"] == "semgrep" for item in payload["items"])
    assert captured_commands == [
        [
            "semgrep",
            "scan",
            "--config",
            "p/security-audit",
            "--config",
            "p/owasp-top-ten",
            "--json",
            "--quiet",
            "--no-git-ignore",
            str(target.resolve()),
        ]
    ]


@pytest.mark.parametrize(
    ("raw_cwe", "expected"),
    [
        (["CWE-79", "CWE-89"], "CWE-79"),
        ([], "CWE-unknown"),
        (None, "CWE-unknown"),
    ],
)
def test_normalize_cwe_handles_array_empty_and_missing(raw_cwe: object, expected: str) -> None:
    assert run_semgrep.normalize_cwe(raw_cwe) == expected


def test_run_semgrep_exits_with_code_two_when_tool_is_missing(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    output = tmp_path / "semgrep.json"

    monkeypatch.setattr(run_semgrep.shutil, "which", lambda _: None)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "run_semgrep.py",
            "--target",
            str(tmp_path),
            "--run-id",
            "run-semgrep",
            "--output",
            str(output),
        ],
    )

    with pytest.raises(SystemExit) as excinfo:
        run_semgrep.main()

    assert excinfo.value.code == 2
    assert "semgrep is not installed" in capsys.readouterr().err


@pytest.mark.parametrize("returncode", [0, 1])
def test_run_semgrep_treats_exit_codes_zero_and_one_as_success(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    returncode: int,
) -> None:
    output = tmp_path / f"semgrep-{returncode}.json"
    target = tmp_path / "repo"
    target.mkdir()

    stdout = json.dumps(
        {
            "results": [] if returncode == 0 else [
                {
                    "check_id": "rule.warning",
                    "path": "src/app.py",
                    "start": {"line": 7},
                    "extra": {"message": "warning", "severity": "WARNING", "metadata": {}},
                }
            ]
        }
    )

    def fake_run(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(args=command, returncode=returncode, stdout=stdout, stderr="")

    monkeypatch.setattr(run_semgrep.shutil, "which", lambda _: "/usr/bin/semgrep")
    monkeypatch.setattr(run_semgrep.subprocess, "run", fake_run)

    run_main(
        monkeypatch,
        [
            "--target",
            str(target),
            "--run-id",
            f"run-{returncode}",
            "--output",
            str(output),
        ],
    )

    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["run_id"] == f"run-{returncode}"
    assert isinstance(payload["items"], list)
    if returncode == 0:
        assert payload["items"] == []
    else:
        assert len(payload["items"]) == 1


def test_run_semgrep_exits_when_semgrep_returns_real_error(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    output = tmp_path / "semgrep-error.json"
    target = tmp_path / "repo"
    target.mkdir()

    def fake_run(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(args=command, returncode=2, stdout="", stderr="scan failed")

    monkeypatch.setattr(run_semgrep.shutil, "which", lambda _: "/usr/bin/semgrep")
    monkeypatch.setattr(run_semgrep.subprocess, "run", fake_run)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "run_semgrep.py",
            "--target",
            str(target),
            "--run-id",
            "run-error",
            "--output",
            str(output),
        ],
    )

    with pytest.raises(SystemExit) as excinfo:
        run_semgrep.main()

    assert excinfo.value.code == 2


@pytest.mark.integration
def test_run_semgrep_integration_detects_a_real_finding(tmp_path: Path) -> None:
    if shutil.which("semgrep") is None:
        pytest.skip("semgrep is not installed")

    target = tmp_path / "fixture"
    output = tmp_path / "semgrep-integration.json"
    target.mkdir()
    (target / "app.py").write_text(
        "import subprocess\n\n"
        "def run(cmd: str) -> None:\n"
        "    subprocess.call(cmd, shell=True)\n",
        encoding="utf-8",
    )

    proc = subprocess.run(
        [
            sys.executable,
            str(SCRIPT_PATH),
            "--target",
            str(target),
            "--run-id",
            "integration-semgrep",
            "--output",
            str(output),
            "--rulesets",
            "p/security-audit",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert proc.returncode == 0, proc.stderr
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["items"], "expected Semgrep to find at least one issue in the integration fixture"
    assert payload["items"][0]["tool"] == "semgrep"
