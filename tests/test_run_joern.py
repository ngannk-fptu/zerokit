from __future__ import annotations

# pyright: reportMissingImports=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportUnknownLambdaType=false
import json
import shutil
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
import tools.harness.run_joern as run_joern

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPO_ROOT / "tools/harness/run_joern.py"


def run_main(monkeypatch: pytest.MonkeyPatch, args: list[str]) -> None:
    monkeypatch.setattr(sys, "argv", ["run_joern.py", *args])
    run_joern.main()


def _response(payload: dict[str, object], status: int = 200):
    class _Resp:
        def __init__(self, data: dict[str, object], http_status: int) -> None:
            self._data = json.dumps(data).encode("utf-8")
            self.status = http_status

        def __enter__(self) -> "_Resp":
            return self

        def __exit__(self, exc_type, exc, tb) -> None:
            return None

        def read(self) -> bytes:
            return self._data

    return _Resp(payload, status)


def test_run_joern_exits_with_code_two_when_docker_missing(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    output = tmp_path / "joern.json"
    target = tmp_path / "repo"
    target.mkdir()

    monkeypatch.setattr(run_joern.shutil, "which", lambda _: None)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "run_joern.py",
            "--target",
            str(target),
            "--run-id",
            "run-joern",
            "--output",
            str(output),
        ],
    )

    with pytest.raises(SystemExit) as excinfo:
        run_joern.main()

    assert excinfo.value.code == 2
    assert "docker is not installed" in capsys.readouterr().err


def test_run_joern_health_check_retries_then_succeeds(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    output = tmp_path / "joern-health-success.json"
    target = tmp_path / "repo"
    target.mkdir()

    commands: list[list[str]] = []
    sleeps: list[int | float] = []
    health_attempts = 0

    def fake_run(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        if command[:3] == ["docker", "run", "-d"]:
            return subprocess.CompletedProcess(args=command, returncode=0, stdout="joern-container\n", stderr="")
        return subprocess.CompletedProcess(args=command, returncode=0, stdout="", stderr="")

    def fake_sleep(seconds: int | float) -> None:
        sleeps.append(seconds)

    def fake_urlopen(request, timeout: int = 5):
        nonlocal health_attempts
        _ = timeout
        url = request if isinstance(request, str) else request.full_url
        if url == "http://localhost:8080/":
            health_attempts += 1
            if health_attempts < 3:
                raise ConnectionError("joern not ready")
            return _response({"ok": True}, status=200)
        if url == "http://localhost:8080/query":
            return _response(
                {
                    "stdout": "src/app.py:42:user_input reaches sink",
                    "stderr": "",
                },
                status=200,
            )
        raise AssertionError(f"Unexpected URL: {url}")

    monkeypatch.setattr(run_joern.shutil, "which", lambda _: "/usr/bin/docker")
    monkeypatch.setattr(run_joern.subprocess, "run", fake_run)
    monkeypatch.setattr(run_joern.time, "sleep", fake_sleep)

    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        run_main(
            monkeypatch,
            [
                "--target",
                str(target),
                "--run-id",
                "run-health-success",
                "--output",
                str(output),
            ],
        )

    assert health_attempts == 3
    assert sleeps == [5, 5]
    assert any(cmd[:3] == ["docker", "run", "-d"] for cmd in commands)


def test_run_joern_health_check_timeout_after_max_retries(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    output = tmp_path / "joern-health-timeout.json"
    target = tmp_path / "repo"
    target.mkdir()

    sleeps: list[int | float] = []
    health_attempts = 0

    def fake_run(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        if command[:3] == ["docker", "run", "-d"]:
            return subprocess.CompletedProcess(args=command, returncode=0, stdout="joern-container\n", stderr="")
        return subprocess.CompletedProcess(args=command, returncode=0, stdout="", stderr="")

    def fake_sleep(seconds: int | float) -> None:
        sleeps.append(seconds)

    def always_unavailable(request, timeout: int = 5):
        nonlocal health_attempts
        _ = request
        _ = timeout
        health_attempts += 1
        raise ConnectionError("still not ready")

    monkeypatch.setattr(run_joern.shutil, "which", lambda _: "/usr/bin/docker")
    monkeypatch.setattr(run_joern.subprocess, "run", fake_run)
    monkeypatch.setattr(run_joern.time, "sleep", fake_sleep)

    with patch("urllib.request.urlopen", side_effect=always_unavailable):
        with pytest.raises(SystemExit) as excinfo:
            run_main(
                monkeypatch,
                [
                    "--target",
                    str(target),
                    "--run-id",
                    "run-health-timeout",
                    "--output",
                    str(output),
                ],
            )

    assert excinfo.value.code == 2
    assert health_attempts == 12
    assert len(sleeps) == 12
    assert all(wait == 5 for wait in sleeps)


def test_run_joern_writes_intermediate_finding_items_for_taint_results(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    output = tmp_path / "joern-taint.json"
    target = tmp_path / "repo"
    target.mkdir()

    def fake_run(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        if command[:3] == ["docker", "run", "-d"]:
            return subprocess.CompletedProcess(args=command, returncode=0, stdout="joern-container\n", stderr="")
        return subprocess.CompletedProcess(args=command, returncode=0, stdout="", stderr="")

    def fake_urlopen(request, timeout: int = 5):
        _ = timeout
        url = request if isinstance(request, str) else request.full_url
        if url == "http://localhost:8080/":
            return _response({"ok": True}, status=200)
        if url == "http://localhost:8080/query":
            return _response(
                {
                    "stdout": "src/main.py:17 user_input -> subprocess.call(shell=True)",
                    "stderr": "",
                },
                status=200,
            )
        raise AssertionError(f"Unexpected URL: {url}")

    monkeypatch.setattr(run_joern.shutil, "which", lambda _: "/usr/bin/docker")
    monkeypatch.setattr(run_joern.subprocess, "run", fake_run)

    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        run_main(
            monkeypatch,
            [
                "--target",
                str(target),
                "--run-id",
                "run-taint-success",
                "--output",
                str(output),
            ],
        )

    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["items"]
    assert payload["items"][0]["tool"] == "joern"


def test_run_joern_handles_empty_taint_results(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    output = tmp_path / "joern-empty.json"
    target = tmp_path / "repo"
    target.mkdir()

    def fake_run(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        if command[:3] == ["docker", "run", "-d"]:
            return subprocess.CompletedProcess(args=command, returncode=0, stdout="joern-container\n", stderr="")
        return subprocess.CompletedProcess(args=command, returncode=0, stdout="", stderr="")

    def fake_urlopen(request, timeout: int = 5):
        _ = timeout
        url = request if isinstance(request, str) else request.full_url
        if url == "http://localhost:8080/":
            return _response({"ok": True}, status=200)
        if url == "http://localhost:8080/query":
            return _response({"stdout": "", "stderr": ""}, status=200)
        raise AssertionError(f"Unexpected URL: {url}")

    monkeypatch.setattr(run_joern.shutil, "which", lambda _: "/usr/bin/docker")
    monkeypatch.setattr(run_joern.subprocess, "run", fake_run)

    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        run_main(
            monkeypatch,
            [
                "--target",
                str(target),
                "--run-id",
                "run-taint-empty",
                "--output",
                str(output),
            ],
        )

    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["items"] == []


def test_run_joern_output_items_match_intermediate_finding_contract(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    output = tmp_path / "joern-contract.json"
    target = tmp_path / "repo"
    target.mkdir()

    def fake_run(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        if command[:3] == ["docker", "run", "-d"]:
            return subprocess.CompletedProcess(args=command, returncode=0, stdout="joern-container\n", stderr="")
        return subprocess.CompletedProcess(args=command, returncode=0, stdout="", stderr="")

    def fake_urlopen(request, timeout: int = 5):
        _ = timeout
        url = request if isinstance(request, str) else request.full_url
        if url == "http://localhost:8080/":
            return _response({"ok": True}, status=200)
        if url == "http://localhost:8080/query":
            return _response({"stdout": "src/app.py:9 taint flow", "stderr": ""}, status=200)
        raise AssertionError(f"Unexpected URL: {url}")

    monkeypatch.setattr(run_joern.shutil, "which", lambda _: "/usr/bin/docker")
    monkeypatch.setattr(run_joern.subprocess, "run", fake_run)

    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        run_main(
            monkeypatch,
            [
                "--target",
                str(target),
                "--run-id",
                "run-contract",
                "--output",
                str(output),
            ],
        )

    payload = json.loads(output.read_text(encoding="utf-8"))
    required_fields = ["tool", "rule", "severity", "path", "line", "evidence", "cwe"]
    assert "run_id" in payload
    assert "generated_at" in payload
    for item in payload["items"]:
        for field_name in required_fields:
            assert field_name in item


def test_run_joern_uses_configurable_port_for_docker_and_http(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    output = tmp_path / "joern-port.json"
    target = tmp_path / "repo"
    target.mkdir()

    commands: list[list[str]] = []
    urls: list[str] = []

    def fake_run(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        if command[:3] == ["docker", "run", "-d"]:
            return subprocess.CompletedProcess(args=command, returncode=0, stdout="joern-container\n", stderr="")
        return subprocess.CompletedProcess(args=command, returncode=0, stdout="", stderr="")

    def fake_urlopen(request, timeout: int = 5):
        _ = timeout
        url = request if isinstance(request, str) else request.full_url
        urls.append(url)
        if url == "http://localhost:9090/":
            return _response({"ok": True}, status=200)
        if url == "http://localhost:9090/query":
            return _response({"stdout": "", "stderr": ""}, status=200)
        raise AssertionError(f"Unexpected URL: {url}")

    monkeypatch.setattr(run_joern.shutil, "which", lambda _: "/usr/bin/docker")
    monkeypatch.setattr(run_joern.subprocess, "run", fake_run)

    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        run_main(
            monkeypatch,
            [
                "--target",
                str(target),
                "--run-id",
                "run-port",
                "--output",
                str(output),
                "--port",
                "9090",
            ],
        )

    docker_run_cmd = next(cmd for cmd in commands if cmd[:3] == ["docker", "run", "-d"])
    assert "-p" in docker_run_cmd
    assert "9090:8080" in docker_run_cmd
    assert "http://localhost:9090/" in urls
    assert "http://localhost:9090/query" in urls


@pytest.mark.integration
def test_run_joern_integration_real_container(tmp_path: Path) -> None:
    if shutil.which("docker") is None:
        pytest.skip("docker is not installed")

    target = tmp_path / "fixture"
    output = tmp_path / "joern-integration.json"
    target.mkdir()
    (target / "app.py").write_text(
        "from __future__ import annotations\n"
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
            "integration-joern",
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
    assert isinstance(payload["items"], list)
