from __future__ import annotations

# pyright: reportMissingImports=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportUnknownLambdaType=false, reportUnusedCallResult=false
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

import tools.harness.run_poc as run_poc

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPO_ROOT / "tools/harness/run_poc.py"


def run_main(monkeypatch: pytest.MonkeyPatch, args: list[str]) -> None:
    monkeypatch.setattr(sys, "argv", ["run_poc.py", *args])
    run_poc.main()


def test_run_poc_exits_with_code_two_when_docker_missing(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    output = tmp_path / "run-poc-output.json"

    monkeypatch.setattr(run_poc.shutil, "which", lambda _: None)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "run_poc.py",
            "--finding-id",
            "sf-001",
            "--poc-script",
            "/tmp/poc.py",
            "--target",
            "/tmp/target",
            "--run-id",
            "run-poc-test",
            "--output",
            str(output),
        ],
    )

    with pytest.raises(SystemExit) as excinfo:
        run_poc.main()

    assert excinfo.value.code == 2
    assert "docker is not installed" in capsys.readouterr().err


def test_run_poc_produces_confirmed_status_on_exit_zero(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    output = tmp_path / "out.json"

    def fake_run(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout="exploit confirmed\n",
            stderr="",
        )

    monkeypatch.setattr(run_poc.shutil, "which", lambda _: "/usr/bin/docker")
    monkeypatch.setattr(run_poc.subprocess, "run", fake_run)

    run_main(
        monkeypatch,
        [
            "--finding-id",
            "sf-001",
            "--poc-script",
            "/tmp/poc.py",
            "--target",
            "/tmp/target",
            "--run-id",
            "run-poc-test",
            "--output",
            str(output),
        ],
    )

    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["items"][0]["status"] == "confirmed"
    assert payload["items"][0]["exit_code"] == 0
    assert payload["items"][0]["finding_id"] == "sf-001"
    assert payload["items"][0]["output_excerpt"]


def test_run_poc_produces_rejected_status_on_exit_nonzero(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    output = tmp_path / "out-rejected.json"

    def fake_run(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            args=command,
            returncode=1,
            stdout="exploit failed\n",
            stderr="",
        )

    monkeypatch.setattr(run_poc.shutil, "which", lambda _: "/usr/bin/docker")
    monkeypatch.setattr(run_poc.subprocess, "run", fake_run)

    run_main(
        monkeypatch,
        [
            "--finding-id",
            "sf-001",
            "--poc-script",
            "/tmp/poc.py",
            "--target",
            "/tmp/target",
            "--run-id",
            "run-poc-test",
            "--output",
            str(output),
        ],
    )

    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["items"][0]["status"] == "rejected"
    assert payload["items"][0]["exit_code"] == 1


def test_run_poc_produces_inconclusive_status_on_timeout(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    output = tmp_path / "out-timeout.json"

    def fake_run(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(cmd=command, timeout=30)

    monkeypatch.setattr(run_poc.shutil, "which", lambda _: "/usr/bin/docker")
    monkeypatch.setattr(run_poc.subprocess, "run", fake_run)

    run_main(
        monkeypatch,
        [
            "--finding-id",
            "sf-001",
            "--poc-script",
            "/tmp/poc.py",
            "--target",
            "/tmp/target",
            "--run-id",
            "run-poc-test",
            "--output",
            str(output),
        ],
    )

    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["items"][0]["status"] == "inconclusive"
    assert "timeout" in payload["items"][0]["output_excerpt"].lower()


def test_run_poc_docker_command_includes_security_constraints(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    output = tmp_path / "out-command.json"
    captured_command: list[str] = []
    captured_timeout: int | None = None

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        nonlocal captured_timeout
        captured_command.extend(command)
        timeout_value = kwargs.get("timeout")
        if isinstance(timeout_value, int):
            captured_timeout = timeout_value
        return subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout="exploit confirmed\n",
            stderr="",
        )

    monkeypatch.setattr(run_poc.shutil, "which", lambda _: "/usr/bin/docker")
    monkeypatch.setattr(run_poc.subprocess, "run", fake_run)

    run_main(
        monkeypatch,
        [
            "--finding-id",
            "sf-001",
            "--poc-script",
            "/tmp/poc.py",
            "--target",
            "/tmp/target",
            "--run-id",
            "run-poc-test",
            "--output",
            str(output),
        ],
    )

    assert "--network" in captured_command
    assert "none" in captured_command
    assert "--memory" in captured_command
    assert "128m" in captured_command
    assert "--rm" in captured_command
    assert captured_timeout == 30


def test_run_poc_output_validates_against_contract(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    output = tmp_path / "out-contract.json"

    def fake_run(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout="exploit confirmed\n",
            stderr="",
        )

    monkeypatch.setattr(run_poc.shutil, "which", lambda _: "/usr/bin/docker")
    monkeypatch.setattr(run_poc.subprocess, "run", fake_run)

    run_main(
        monkeypatch,
        [
            "--finding-id",
            "sf-001",
            "--poc-script",
            "/tmp/poc.py",
            "--target",
            "/tmp/target",
            "--run-id",
            "run-poc-test",
            "--output",
            str(output),
        ],
    )

    payload = json.loads(output.read_text(encoding="utf-8"))
    required_fields = [
        "finding_id",
        "status",
        "command",
        "exit_code",
        "output_excerpt",
        "artifact_path",
    ]
    assert "run_id" in payload
    assert "generated_at" in payload
    for evidence_item in payload["items"]:
        for field_name in required_fields:
            assert field_name in evidence_item
        assert evidence_item["status"] in ["confirmed", "rejected", "inconclusive"]


@pytest.mark.integration
def test_run_poc_integration_real_docker_execution(tmp_path: Path) -> None:
    if shutil.which("docker") is None:
        pytest.skip("docker is not installed")

    poc_script = tmp_path / "poc.py"
    target_dir = tmp_path / "target"
    output = tmp_path / "out-integration.json"
    target_dir.mkdir()
    poc_script.write_text(
        "from __future__ import annotations\nimport sys\nprint('exploit confirmed')\nsys.exit(0)\n",
        encoding="utf-8",
    )

    proc = subprocess.run(
        [
            sys.executable,
            str(SCRIPT_PATH),
            "--finding-id",
            "sf-001",
            "--poc-script",
            str(poc_script),
            "--target",
            str(target_dir),
            "--run-id",
            "integration-run-poc",
            "--output",
            str(output),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert proc.returncode == 0, proc.stderr
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["items"][0]["status"] == "confirmed"
    required_fields = [
        "finding_id",
        "status",
        "command",
        "exit_code",
        "output_excerpt",
        "artifact_path",
    ]
    for field_name in required_fields:
        assert field_name in payload["items"][0]


@pytest.mark.integration
def test_run_poc_integration_phase03_fixture_with_cleanup(tmp_path: Path) -> None:
    if shutil.which("docker") is None:
        pytest.skip("docker not available")

    fixture_dir = REPO_ROOT / "tests/fixtures/phase03-e2e"
    output_path = tmp_path / "run-poc-phase03.json"
    poc_script = tmp_path / "poc.py"
    poc_script.write_text(
        "from __future__ import annotations\nimport sys\nprint('exploit confirmed')\nsys.exit(0)\n",
        encoding="utf-8",
    )

    before = subprocess.run(
        ["docker", "ps", "--filter", "ancestor=python:3.11-slim", "-q"],
        capture_output=True,
        text=True,
        check=False,
    )
    before_ids = {line.strip() for line in before.stdout.splitlines() if line.strip()}

    try:
        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "--finding-id",
                "sf-999",
                "--poc-script",
                str(poc_script),
                "--target",
                str(fixture_dir),
                "--run-id",
                "integration-poc-phase03",
                "--output",
                str(output_path),
            ],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )

        assert result.returncode == 0, result.stderr
        assert output_path.exists()

        payload = json.loads(output_path.read_text(encoding="utf-8"))
        assert payload["run_id"] == "integration-poc-phase03"
        evidence_item = payload["items"][0]
        assert evidence_item["status"] == "confirmed"
        assert evidence_item["finding_id"] == "sf-999"
        assert evidence_item["exit_code"] == 0
        assert "--network none" in evidence_item["command"]
        assert "--memory 128m" in evidence_item["command"]
        assert "--rm" in evidence_item["command"]
    finally:
        after = subprocess.run(
            ["docker", "ps", "--filter", "ancestor=python:3.11-slim", "-q"],
            capture_output=True,
            text=True,
            check=False,
        )
        after_ids = {line.strip() for line in after.stdout.splitlines() if line.strip()}
        for container_id in sorted(after_ids - before_ids):
            subprocess.run(
                ["docker", "rm", "-f", container_id],
                capture_output=True,
                text=True,
                check=False,
            )
        final_check = subprocess.run(
            ["docker", "ps", "--filter", "ancestor=python:3.11-slim", "-q"],
            capture_output=True,
            text=True,
            check=False,
        )
        final_ids = {line.strip() for line in final_check.stdout.splitlines() if line.strip()}
        assert final_ids - before_ids == set()
