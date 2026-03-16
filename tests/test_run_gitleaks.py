from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPO_ROOT / "tools/harness/run_gitleaks.py"


def load_run_gitleaks_module():
    spec = importlib.util.spec_from_file_location("run_gitleaks", SCRIPT_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_run_gitleaks_normalizes_findings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_run_gitleaks_module()
    output_path = tmp_path / "gitleaks-intermediate.json"

    def fake_run(cmd: list[str], capture_output: bool, text: bool) -> subprocess.CompletedProcess[str]:
        assert capture_output is True
        assert text is True
        assert cmd[:2] == ["gitleaks", "detect"]
        assert "--report-format" in cmd
        assert "--report-path" in cmd
        report_path = Path(cmd[cmd.index("--report-path") + 1])
        report_path.write_text(
            json.dumps(
                [
                    {
                        "RuleID": "generic-api-key",
                        "File": "config/settings.py",
                        "StartLine": 15,
                    }
                ]
            ),
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(cmd, 1, "", "")

    monkeypatch.setattr(module.shutil, "which", lambda name: "/usr/bin/gitleaks")
    monkeypatch.setattr(module.subprocess, "run", fake_run)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            str(SCRIPT_PATH),
            "--target",
            str(tmp_path),
            "--run-id",
            "run-gitleaks-normalized",
            "--output",
            str(output_path),
        ],
    )

    with pytest.raises(SystemExit) as exc:
        module.main()

    assert exc.value.code == 1
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["run_id"] == "run-gitleaks-normalized"
    assert isinstance(payload["generated_at"], str)
    assert payload["items"] == [
        {
            "tool": "gitleaks",
            "rule": "generic-api-key",
            "severity": "high",
            "path": "config/settings.py",
            "line": 15,
            "evidence": "Secret detected: generic-api-key",
            "cwe": "CWE-798",
        }
    ]


def test_run_gitleaks_exits_2_when_tool_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    module = load_run_gitleaks_module()
    output_path = tmp_path / "gitleaks-intermediate.json"

    monkeypatch.setattr(module.shutil, "which", lambda name: None)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            str(SCRIPT_PATH),
            "--target",
            str(tmp_path),
            "--run-id",
            "run-gitleaks-missing",
            "--output",
            str(output_path),
        ],
    )

    with pytest.raises(SystemExit) as exc:
        module.main()

    assert exc.value.code == 2
    assert "gitleaks" in capsys.readouterr().err
    assert not output_path.exists()


def test_run_gitleaks_propagates_error_exit_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    module = load_run_gitleaks_module()
    output_path = tmp_path / "gitleaks-intermediate.json"

    def fake_run(cmd: list[str], capture_output: bool, text: bool) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(cmd, 3, "", "gitleaks failed")

    monkeypatch.setattr(module.shutil, "which", lambda name: "/usr/bin/gitleaks")
    monkeypatch.setattr(module.subprocess, "run", fake_run)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            str(SCRIPT_PATH),
            "--target",
            str(tmp_path),
            "--run-id",
            "run-gitleaks-error",
            "--output",
            str(output_path),
        ],
    )

    with pytest.raises(SystemExit) as exc:
        module.main()

    assert exc.value.code == 3
    assert "gitleaks failed" in capsys.readouterr().err
    assert not output_path.exists()


def test_run_gitleaks_writes_empty_findings_for_clean_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = load_run_gitleaks_module()
    output_path = tmp_path / "gitleaks-intermediate.json"

    def fake_run(cmd: list[str], capture_output: bool, text: bool) -> subprocess.CompletedProcess[str]:
        report_path = Path(cmd[cmd.index("--report-path") + 1])
        report_path.write_text("[]", encoding="utf-8")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(module.shutil, "which", lambda name: "/usr/bin/gitleaks")
    monkeypatch.setattr(module.subprocess, "run", fake_run)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            str(SCRIPT_PATH),
            "--target",
            str(tmp_path),
            "--run-id",
            "run-gitleaks-clean",
            "--output",
            str(output_path),
        ],
    )

    module.main()

    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["run_id"] == "run-gitleaks-clean"
    assert payload["items"] == []


@pytest.mark.integration
@pytest.mark.skipif(shutil.which("gitleaks") is None, reason="gitleaks not installed")
def test_run_gitleaks_integration_detects_secret(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "token.env").write_text(
        'GITHUB_TOKEN="ghp_123456789012345678901234567890123456"\n',
        encoding="utf-8",
    )
    output_path = tmp_path / "gitleaks-intermediate.json"

    cmd = [
        sys.executable,
        str(SCRIPT_PATH),
        "--target",
        str(target),
        "--run-id",
        "run-gitleaks-integration",
        "--output",
        str(output_path),
    ]
    proc = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True)

    assert proc.returncode == 1, proc.stderr
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["run_id"] == "run-gitleaks-integration"
    assert payload["items"]
    assert any(Path(item["path"]).name == "token.env" for item in payload["items"])
    assert all(item["tool"] == "gitleaks" for item in payload["items"])
    assert all(item["severity"] == "high" for item in payload["items"])
    assert all(item["cwe"] == "CWE-798" for item in payload["items"])
