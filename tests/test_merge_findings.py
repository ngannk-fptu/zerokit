from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

import tools.harness.merge_findings as merge_findings


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def make_intermediate(run_id: str, items: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "run_id": run_id,
        "generated_at": "2026-03-15T00:00:00Z",
        "items": items,
    }


def make_hypotheses(run_id: str, items: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "run_id": run_id,
        "generated_at": "2026-03-15T00:00:00Z",
        "items": items,
    }


def run_main(monkeypatch: pytest.MonkeyPatch, args: list[str]) -> None:
    monkeypatch.setattr(sys, "argv", ["merge_findings.py", *args])
    merge_findings.main()


def test_merge_two_files_deduplicates_and_keeps_highest_severity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    semgrep_path = tmp_path / "semgrep.json"
    gitleaks_path = tmp_path / "gitleaks.json"
    output_path = tmp_path / "static_findings.json"

    write_json(
        semgrep_path,
        make_intermediate(
            "run-merge",
            [
                {
                    "tool": "semgrep",
                    "rule": "rule.duplicate",
                    "severity": "medium",
                    "path": "src/app.py",
                    "line": 12,
                    "evidence": "lower severity duplicate",
                    "cwe": "CWE-79",
                }
            ],
        ),
    )
    write_json(
        gitleaks_path,
        make_intermediate(
            "run-merge",
            [
                {
                    "tool": "semgrep",
                    "rule": "rule.duplicate",
                    "severity": "high",
                    "path": "src/app.py",
                    "line": 12,
                    "evidence": "higher severity duplicate",
                    "cwe": "CWE-79",
                }
            ],
        ),
    )

    run_main(
        monkeypatch,
        [
            "--inputs",
            str(semgrep_path),
            str(gitleaks_path),
            "--run-id",
            "run-merge",
            "--output",
            str(output_path),
        ],
    )

    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert len(payload["items"]) == 1
    assert payload["items"][0]["severity"] == "high"
    assert payload["items"][0]["evidence"] == "higher severity duplicate"


def test_merge_with_hypotheses_links_findings_at_each_level(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    input_path = tmp_path / "findings.json"
    hypotheses_path = tmp_path / "hypotheses.json"
    output_path = tmp_path / "static_findings.json"

    write_json(
        input_path,
        make_intermediate(
            "run-linking",
            [
                {
                    "tool": "semgrep",
                    "rule": "rule.exact",
                    "severity": "high",
                    "path": "src/exact.py",
                    "line": 10,
                    "evidence": "exact path finding",
                    "cwe": "CWE-79",
                },
                {
                    "tool": "semgrep",
                    "rule": "rule.same-dir",
                    "severity": "medium",
                    "path": "src/other.py",
                    "line": 20,
                    "evidence": "same directory finding",
                    "cwe": "CWE-89",
                },
                {
                    "tool": "gitleaks",
                    "rule": "rule.any-path",
                    "severity": "low",
                    "path": "config/secrets.env",
                    "line": 30,
                    "evidence": "any path finding",
                    "cwe": "CWE-798",
                },
                {
                    "tool": "semgrep",
                    "rule": "rule.unlinked",
                    "severity": "low",
                    "path": "misc/unlinked.py",
                    "line": 40,
                    "evidence": "unlinked finding",
                    "cwe": "CWE-22",
                },
            ],
        ),
    )
    write_json(
        hypotheses_path,
        make_hypotheses(
            "run-linking",
            [
                {
                    "id": "hyp-001",
                    "title": "Exact path hypothesis",
                    "cwe": "CWE-79",
                    "source": "request.body.name",
                    "sink": "render at src/exact.py:15",
                    "priority": "high",
                    "rationale": "Exact path should win",
                },
                {
                    "id": "hyp-002",
                    "title": "Same directory hypothesis",
                    "cwe": "CWE-89",
                    "source": "request.body.q",
                    "sink": "query builder at src/db.py:44",
                    "priority": "high",
                    "rationale": "Same directory should win",
                },
                {
                    "id": "hyp-003",
                    "title": "Any path hypothesis",
                    "cwe": "CWE-798",
                    "source": "environment variable",
                    "sink": "credential handling",
                    "priority": "medium",
                    "rationale": "No path data, should still match on CWE",
                },
            ],
        ),
    )

    run_main(
        monkeypatch,
        [
            "--inputs",
            str(input_path),
            "--hypotheses",
            str(hypotheses_path),
            "--run-id",
            "run-linking",
            "--output",
            str(output_path),
        ],
    )

    payload = json.loads(output_path.read_text(encoding="utf-8"))
    linked_by_rule = {item["tool"] + ":" + item["evidence"]: item["hypothesis_id"] for item in payload["items"]}
    assert linked_by_rule["semgrep:exact path finding"] == "hyp-001"
    assert linked_by_rule["semgrep:same directory finding"] == "hyp-002"
    assert linked_by_rule["gitleaks:any path finding"] == "hyp-003"
    assert linked_by_rule["semgrep:unlinked finding"] == "unlinked"


def test_merge_dedup_prefers_linked_finding_over_unlinked_when_severity_matches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    first_input = tmp_path / "first.json"
    second_input = tmp_path / "second.json"
    hypotheses_path = tmp_path / "hypotheses.json"
    output_path = tmp_path / "static_findings.json"

    write_json(
        first_input,
        make_intermediate(
            "run-linked-dedup",
            [
                {
                    "tool": "semgrep",
                    "rule": "rule.shared",
                    "severity": "high",
                    "path": "src/shared.py",
                    "line": 9,
                    "evidence": "linked version",
                    "cwe": "CWE-79",
                }
            ],
        ),
    )
    write_json(
        second_input,
        make_intermediate(
            "run-linked-dedup",
            [
                {
                    "tool": "semgrep",
                    "rule": "rule.shared",
                    "severity": "high",
                    "path": "src/shared.py",
                    "line": 9,
                    "evidence": "unlinked version",
                    "cwe": "CWE-22",
                }
            ],
        ),
    )
    write_json(
        hypotheses_path,
        make_hypotheses(
            "run-linked-dedup",
            [
                {
                    "id": "hyp-001",
                    "title": "Linked hypothesis",
                    "cwe": "CWE-79",
                    "source": "request.body.payload",
                    "sink": "render at src/shared.py:18",
                    "priority": "high",
                    "rationale": "Should keep the linked duplicate",
                }
            ],
        ),
    )

    run_main(
        monkeypatch,
        [
            "--inputs",
            str(first_input),
            str(second_input),
            "--hypotheses",
            str(hypotheses_path),
            "--run-id",
            "run-linked-dedup",
            "--output",
            str(output_path),
        ],
    )

    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert len(payload["items"]) == 1
    assert payload["items"][0]["hypothesis_id"] == "hyp-001"
    assert payload["items"][0]["evidence"] == "linked version"


def test_merge_without_hypotheses_marks_everything_unlinked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    input_path = tmp_path / "findings.json"
    output_path = tmp_path / "static_findings.json"

    write_json(
        input_path,
        make_intermediate(
            "run-unlinked",
            [
                {
                    "tool": "semgrep",
                    "rule": "rule.one",
                    "severity": "high",
                    "path": "src/app.py",
                    "line": 5,
                    "evidence": "first",
                    "cwe": "CWE-79",
                },
                {
                    "tool": "gitleaks",
                    "rule": "rule.two",
                    "severity": "high",
                    "path": "config/token.env",
                    "line": 8,
                    "evidence": "second",
                    "cwe": "CWE-798",
                },
            ],
        ),
    )

    run_main(
        monkeypatch,
        [
            "--inputs",
            str(input_path),
            "--hypotheses",
            str(tmp_path / "missing-hypotheses.json"),
            "--run-id",
            "run-unlinked",
            "--output",
            str(output_path),
        ],
    )

    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert {item["hypothesis_id"] for item in payload["items"]} == {"unlinked"}


def test_merge_assigns_gap_free_sequential_ids(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    input_path = tmp_path / "findings.json"
    output_path = tmp_path / "static_findings.json"

    write_json(
        input_path,
        make_intermediate(
            "run-ids",
            [
                {
                    "tool": "semgrep",
                    "rule": "rule.one",
                    "severity": "medium",
                    "path": "src/a.py",
                    "line": 1,
                    "evidence": "one",
                    "cwe": "CWE-79",
                },
                {
                    "tool": "semgrep",
                    "rule": "rule.two",
                    "severity": "low",
                    "path": "src/b.py",
                    "line": 2,
                    "evidence": "two",
                    "cwe": "CWE-89",
                },
                {
                    "tool": "gitleaks",
                    "rule": "rule.three",
                    "severity": "high",
                    "path": "config/c.env",
                    "line": 3,
                    "evidence": "three",
                    "cwe": "CWE-798",
                },
            ],
        ),
    )

    run_main(
        monkeypatch,
        [
            "--inputs",
            str(input_path),
            "--run-id",
            "run-ids",
            "--output",
            str(output_path),
        ],
    )

    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert [item["id"] for item in payload["items"]] == ["sf-001", "sf-002", "sf-003"]


def test_merge_sorts_findings_by_severity_descending(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    input_path = tmp_path / "findings.json"
    output_path = tmp_path / "static_findings.json"

    write_json(
        input_path,
        make_intermediate(
            "run-sort",
            [
                {
                    "tool": "semgrep",
                    "rule": "rule.low",
                    "severity": "low",
                    "path": "src/low.py",
                    "line": 1,
                    "evidence": "low finding",
                    "cwe": "CWE-79",
                },
                {
                    "tool": "semgrep",
                    "rule": "rule.critical",
                    "severity": "critical",
                    "path": "src/critical.py",
                    "line": 2,
                    "evidence": "critical finding",
                    "cwe": "CWE-89",
                },
                {
                    "tool": "gitleaks",
                    "rule": "rule.high",
                    "severity": "high",
                    "path": "src/high.py",
                    "line": 3,
                    "evidence": "high finding",
                    "cwe": "CWE-798",
                },
                {
                    "tool": "semgrep",
                    "rule": "rule.medium",
                    "severity": "medium",
                    "path": "src/medium.py",
                    "line": 4,
                    "evidence": "medium finding",
                    "cwe": "CWE-22",
                },
            ],
        ),
    )

    run_main(
        monkeypatch,
        [
            "--inputs",
            str(input_path),
            "--run-id",
            "run-sort",
            "--output",
            str(output_path),
        ],
    )

    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert [item["severity"] for item in payload["items"]] == ["critical", "high", "medium", "low"]


def test_merge_uses_lowest_hypothesis_id_for_same_level_tie_breaker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    input_path = tmp_path / "findings.json"
    hypotheses_path = tmp_path / "hypotheses.json"
    output_path = tmp_path / "static_findings.json"

    write_json(
        input_path,
        make_intermediate(
            "run-tie-breaker",
            [
                {
                    "tool": "semgrep",
                    "rule": "rule.tie",
                    "severity": "high",
                    "path": "src/tied.py",
                    "line": 11,
                    "evidence": "tie breaker finding",
                    "cwe": "CWE-79",
                }
            ],
        ),
    )
    write_json(
        hypotheses_path,
        make_hypotheses(
            "run-tie-breaker",
            [
                {
                    "id": "hyp-002",
                    "title": "Second hypothesis",
                    "cwe": "CWE-79",
                    "source": "request.body.value",
                    "sink": "render at src/tied.py:20",
                    "priority": "medium",
                    "rationale": "Matches at level 1",
                },
                {
                    "id": "hyp-001",
                    "title": "First hypothesis",
                    "cwe": "CWE-79",
                    "source": "request.body.value",
                    "sink": "render at src/tied.py:99",
                    "priority": "high",
                    "rationale": "Also matches at level 1 and should win",
                },
            ],
        ),
    )

    run_main(
        monkeypatch,
        [
            "--inputs",
            str(input_path),
            "--hypotheses",
            str(hypotheses_path),
            "--run-id",
            "run-tie-breaker",
            "--output",
            str(output_path),
        ],
    )

    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["items"][0]["hypothesis_id"] == "hyp-001"
