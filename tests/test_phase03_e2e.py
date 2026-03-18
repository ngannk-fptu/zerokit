from __future__ import annotations

# pyright: reportMissingImports=false
import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

import tools.harness.merge_findings as merge_findings
import tools.harness.run_semgrep as run_semgrep

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = REPO_ROOT / "tests/fixtures/phase03-e2e"
RUN_SEMGREP_SCRIPT = REPO_ROOT / "tools/harness/run_semgrep.py"
RUN_GITLEAKS_SCRIPT = REPO_ROOT / "tools/harness/run_gitleaks.py"
MERGE_FINDINGS_SCRIPT = REPO_ROOT / "tools/harness/merge_findings.py"
INTERMEDIATE_SCHEMA = REPO_ROOT / ".agent/artifacts/contracts/intermediate_finding.json"
ARTIFACT_CONTRACT = REPO_ROOT / ".agent/artifacts/contracts/artifact_contract.json"


def run_main(monkeypatch: pytest.MonkeyPatch, args: list[str]) -> None:
    monkeypatch.setattr(sys, "argv", ["run_semgrep.py", *args])
    run_semgrep.main()


def load_run_gitleaks_module():
    spec = importlib.util.spec_from_file_location("run_gitleaks", RUN_GITLEAKS_SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def assert_required_fields(item: dict[str, Any], required_fields: list[str]) -> None:
    missing = [field for field in required_fields if field not in item]
    assert not missing, f"Missing required fields: {missing}"


def test_semgrep_produces_intermediate_findings_from_fixture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output_path = tmp_path / "semgrep.json"
    semgrep_output = {
        "results": [
            {
                "check_id": "python.lang.security.audit.subprocess-shell-true.subprocess-shell-true",
                "path": "vuln_app.py",
                "start": {"line": 7},
                "extra": {
                    "message": "subprocess call with shell=True",
                    "severity": "ERROR",
                    "metadata": {"cwe": ["CWE-78"]},
                },
            }
        ]
    }

    def fake_run(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            args=command,
            returncode=1,
            stdout=json.dumps(semgrep_output),
            stderr="",
        )

    monkeypatch.setattr(run_semgrep.shutil, "which", lambda _: "/usr/bin/semgrep")
    monkeypatch.setattr(run_semgrep.subprocess, "run", fake_run)

    run_main(
        monkeypatch,
        [
            "--target",
            str(FIXTURE_DIR),
            "--run-id",
            "fixture-phase03",
            "--output",
            str(output_path),
        ],
    )

    payload = json.loads(output_path.read_text(encoding="utf-8"))
    schema = json.loads(INTERMEDIATE_SCHEMA.read_text(encoding="utf-8"))

    assert payload["run_id"] == "fixture-phase03"
    assert isinstance(payload["items"], list)
    assert payload["items"]
    assert_required_fields(payload, schema["required_fields"])

    first_item = payload["items"][0]
    assert first_item["tool"] == "semgrep"
    assert first_item["cwe"] == "CWE-78"
    assert_required_fields(first_item, schema["item_required_fields"])


def test_gitleaks_produces_intermediate_findings_from_fixture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load_run_gitleaks_module()
    output_path = tmp_path / "gitleaks.json"

    def fake_run(cmd: list[str], capture_output: bool, text: bool) -> subprocess.CompletedProcess[str]:
        assert capture_output is True
        assert text is True
        report_path = Path(cmd[cmd.index("--report-path") + 1])
        report_path.write_text(
            json.dumps(
                [
                    {
                        "RuleID": "aws-access-token",
                        "File": "fake_secrets.txt",
                        "StartLine": 2,
                    }
                ]
            ),
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(cmd, 1, "", "")

    monkeypatch.setattr(module.shutil, "which", lambda _: "/usr/bin/gitleaks")
    monkeypatch.setattr(module.subprocess, "run", fake_run)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            str(RUN_GITLEAKS_SCRIPT),
            "--target",
            str(FIXTURE_DIR),
            "--run-id",
            "fixture-phase03",
            "--output",
            str(output_path),
        ],
    )

    with pytest.raises(SystemExit) as excinfo:
        module.main()

    assert excinfo.value.code == 1

    payload = json.loads(output_path.read_text(encoding="utf-8"))
    schema = json.loads(INTERMEDIATE_SCHEMA.read_text(encoding="utf-8"))

    assert payload["run_id"] == "fixture-phase03"
    assert isinstance(payload["items"], list)
    assert payload["items"]
    assert_required_fields(payload, schema["required_fields"])

    first_item = payload["items"][0]
    assert first_item["tool"] == "gitleaks"
    assert_required_fields(first_item, schema["item_required_fields"])


def test_merge_links_cwe78_finding_to_hypothesis(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    semgrep_json = tmp_path / "semgrep.json"
    gitleaks_json = tmp_path / "gitleaks.json"
    hypotheses_json = tmp_path / "hypotheses.json"
    output_path = tmp_path / "static_findings.json"

    semgrep_json.write_text(
        json.dumps(
            {
                "run_id": "fixture-phase03",
                "generated_at": "2026-01-01T00:00:00Z",
                "items": [
                    {
                        "tool": "semgrep",
                        "rule": "python.lang.security.audit.subprocess-shell-true.subprocess-shell-true",
                        "severity": "high",
                        "path": "vuln_app.py",
                        "line": 7,
                        "evidence": "subprocess call with shell=True",
                        "cwe": "CWE-78",
                    }
                ],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    gitleaks_json.write_text(
        json.dumps(
            {
                "run_id": "fixture-phase03",
                "generated_at": "2026-01-01T00:00:00Z",
                "items": [
                    {
                        "tool": "gitleaks",
                        "rule": "aws-access-token",
                        "severity": "high",
                        "path": "fake_secrets.txt",
                        "line": 2,
                        "evidence": "Secret detected: aws-access-token",
                        "cwe": "CWE-798",
                    }
                ],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    hypotheses_json.write_text((FIXTURE_DIR / "hypotheses.json").read_text(encoding="utf-8"), encoding="utf-8")

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "merge_findings.py",
            "--inputs",
            str(semgrep_json),
            str(gitleaks_json),
            "--hypotheses",
            str(hypotheses_json),
            "--run-id",
            "fixture-phase03",
            "--output",
            str(output_path),
        ],
    )
    merge_findings.main()

    payload = json.loads(output_path.read_text(encoding="utf-8"))
    contract = json.loads(ARTIFACT_CONTRACT.read_text(encoding="utf-8"))
    static_rules = contract["artifacts"]["static_findings"]

    assert payload["run_id"] == "fixture-phase03"
    assert isinstance(payload["items"], list)
    assert len(payload["items"]) >= 2
    assert_required_fields(payload, static_rules["required_fields"])

    tools = {item["tool"] for item in payload["items"]}
    assert {"semgrep", "gitleaks"}.issubset(tools)
    assert any(item["hypothesis_id"] == "hyp-001" for item in payload["items"])
    assert all(item["hypothesis_id"] != "" for item in payload["items"])

    for item in payload["items"]:
        assert_required_fields(item, static_rules["item_required_fields"])


@pytest.mark.integration
def test_full_pipeline_integration(tmp_path: Path) -> None:
    if shutil.which("semgrep") is None:
        pytest.skip("semgrep is not installed")
    if shutil.which("gitleaks") is None:
        pytest.skip("gitleaks is not installed")

    semgrep_out = tmp_path / "semgrep.json"
    gitleaks_out = tmp_path / "gitleaks.json"
    merged_out = tmp_path / "static_findings.json"

    semgrep_proc = subprocess.run(
        [
            sys.executable,
            str(RUN_SEMGREP_SCRIPT),
            "--target",
            str(FIXTURE_DIR),
            "--run-id",
            "fixture-phase03",
            "--output",
            str(semgrep_out),
            "--rulesets",
            "p/security-audit",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert semgrep_proc.returncode == 0, semgrep_proc.stderr

    gitleaks_proc = subprocess.run(
        [
            sys.executable,
            str(RUN_GITLEAKS_SCRIPT),
            "--target",
            str(FIXTURE_DIR),
            "--run-id",
            "fixture-phase03",
            "--output",
            str(gitleaks_out),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert gitleaks_proc.returncode in (0, 1), gitleaks_proc.stderr

    merge_proc = subprocess.run(
        [
            sys.executable,
            str(MERGE_FINDINGS_SCRIPT),
            "--inputs",
            str(semgrep_out),
            str(gitleaks_out),
            "--hypotheses",
            str(FIXTURE_DIR / "hypotheses.json"),
            "--run-id",
            "fixture-phase03",
            "--output",
            str(merged_out),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert merge_proc.returncode == 0, merge_proc.stderr

    payload = json.loads(merged_out.read_text(encoding="utf-8"))
    contract = json.loads(ARTIFACT_CONTRACT.read_text(encoding="utf-8"))
    rules = contract["artifacts"]["static_findings"]
    severities = set(contract["enums"]["priority"])

    assert_required_fields(payload, rules["required_fields"])
    assert payload["run_id"] == "fixture-phase03"
    assert payload["items"]

    for item in payload["items"]:
        assert_required_fields(item, rules["item_required_fields"])
        assert item["severity"] in severities


@pytest.mark.integration
def test_phase03_cross_tool_integration_with_joern_and_poc(tmp_path: Path) -> None:
    if shutil.which("docker") is None:
        pytest.skip("docker not available")
    if shutil.which("semgrep") is None:
        pytest.skip("semgrep is not installed")
    if shutil.which("gitleaks") is None:
        pytest.skip("gitleaks is not installed")

    run_joern_script = REPO_ROOT / "tools/harness/run_joern.py"
    run_poc_script = REPO_ROOT / "tools/harness/run_poc.py"

    run_id = "fixture-phase03-cross-tool"
    semgrep_out = tmp_path / "semgrep.json"
    gitleaks_out = tmp_path / "gitleaks.json"
    joern_out = tmp_path / "joern.json"
    merged_out = tmp_path / "static_findings.json"
    evidence_out = tmp_path / "verification_evidence.json"
    poc_script = tmp_path / "poc.py"
    poc_script.write_text(
        "from __future__ import annotations\nimport sys\nprint('exploit confirmed')\nsys.exit(0)\n",
        encoding="utf-8",
    )

    joern_before = subprocess.run(
        ["docker", "ps", "--filter", "ancestor=ghcr.io/joernio/joern", "-q"],
        capture_output=True,
        text=True,
        check=False,
    )
    joern_before_ids = {line.strip() for line in joern_before.stdout.splitlines() if line.strip()}
    poc_before = subprocess.run(
        ["docker", "ps", "--filter", "ancestor=python:3.11-slim", "-q"],
        capture_output=True,
        text=True,
        check=False,
    )
    poc_before_ids = {line.strip() for line in poc_before.stdout.splitlines() if line.strip()}

    try:
        semgrep_proc = subprocess.run(
            [
                sys.executable,
                str(RUN_SEMGREP_SCRIPT),
                "--target",
                str(FIXTURE_DIR),
                "--run-id",
                run_id,
                "--output",
                str(semgrep_out),
                "--rulesets",
                "p/security-audit",
            ],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        assert semgrep_proc.returncode == 0, semgrep_proc.stderr

        gitleaks_proc = subprocess.run(
            [
                sys.executable,
                str(RUN_GITLEAKS_SCRIPT),
                "--target",
                str(FIXTURE_DIR),
                "--run-id",
                run_id,
                "--output",
                str(gitleaks_out),
            ],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        assert gitleaks_proc.returncode in (0, 1), gitleaks_proc.stderr

        joern_proc = subprocess.run(
            [
                sys.executable,
                str(run_joern_script),
                "--target",
                str(FIXTURE_DIR),
                "--run-id",
                run_id,
                "--output",
                str(joern_out),
                "--timeout",
                "90",
            ],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
            timeout=180,
        )
        if joern_proc.returncode != 0:
            stderr = joern_proc.stderr.lower()
            if any(token in stderr for token in ("failed to resolve reference", "not found", "pull access denied")):
                pytest.skip("joern image not available")
        assert joern_proc.returncode == 0, joern_proc.stderr

        merge_proc = subprocess.run(
            [
                sys.executable,
                str(MERGE_FINDINGS_SCRIPT),
                "--inputs",
                str(semgrep_out),
                str(gitleaks_out),
                str(joern_out),
                "--run-id",
                run_id,
                "--output",
                str(merged_out),
            ],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        assert merge_proc.returncode == 0, merge_proc.stderr

        merged_payload = json.loads(merged_out.read_text(encoding="utf-8"))
        assert merged_payload["items"], "expected merged findings"
        toolset = {item["tool"] for item in merged_payload["items"]}
        assert {"semgrep", "gitleaks", "joern"}.issubset(toolset)

        finding_id = merged_payload["items"][0]["id"]
        poc_proc = subprocess.run(
            [
                sys.executable,
                str(run_poc_script),
                "--finding-id",
                finding_id,
                "--poc-script",
                str(poc_script),
                "--target",
                str(FIXTURE_DIR),
                "--run-id",
                run_id,
                "--output",
                str(evidence_out),
            ],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        assert poc_proc.returncode == 0, poc_proc.stderr

        evidence_payload = json.loads(evidence_out.read_text(encoding="utf-8"))
        contract = json.loads(ARTIFACT_CONTRACT.read_text(encoding="utf-8"))
        rules = contract["artifacts"]["verification_evidence"]
        assert_required_fields(evidence_payload, rules["required_fields"])
        assert evidence_payload["items"]
        assert_required_fields(evidence_payload["items"][0], rules["item_required_fields"])
        assert evidence_payload["items"][0]["finding_id"] == finding_id
        assert evidence_payload["items"][0]["status"] == "confirmed"
        assert evidence_payload["items"][0]["exit_code"] == 0
    finally:
        joern_after = subprocess.run(
            ["docker", "ps", "--filter", "ancestor=ghcr.io/joernio/joern", "-q"],
            capture_output=True,
            text=True,
            check=False,
        )
        joern_after_ids = {line.strip() for line in joern_after.stdout.splitlines() if line.strip()}
        for container_id in sorted(joern_after_ids - joern_before_ids):
            subprocess.run(
                ["docker", "rm", "-f", container_id],
                capture_output=True,
                text=True,
                check=False,
            )
        poc_after = subprocess.run(
            ["docker", "ps", "--filter", "ancestor=python:3.11-slim", "-q"],
            capture_output=True,
            text=True,
            check=False,
        )
        poc_after_ids = {line.strip() for line in poc_after.stdout.splitlines() if line.strip()}
        for container_id in sorted(poc_after_ids - poc_before_ids):
            subprocess.run(
                ["docker", "rm", "-f", container_id],
                capture_output=True,
                text=True,
                check=False,
            )
        joern_final = subprocess.run(
            ["docker", "ps", "--filter", "ancestor=ghcr.io/joernio/joern", "-q"],
            capture_output=True,
            text=True,
            check=False,
        )
        joern_final_ids = {line.strip() for line in joern_final.stdout.splitlines() if line.strip()}
        assert joern_final_ids - joern_before_ids == set()
        poc_final = subprocess.run(
            ["docker", "ps", "--filter", "ancestor=python:3.11-slim", "-q"],
            capture_output=True,
            text=True,
            check=False,
        )
        poc_final_ids = {line.strip() for line in poc_final.stdout.splitlines() if line.strip()}
        assert poc_final_ids - poc_before_ids == set()
