#!/usr/bin/env python3
"""Fail CI when stale legacy references reappear in docs and skills."""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
AGENT_DIR = REPO_ROOT / ".agent"

ALLOWLIST_BY_NAME = {
    "ci_guardrails_runbook.md": "Runbook intentionally documents forbidden legacy patterns.",
    "check_stale_references.py": "This checker embeds forbidden token definitions.",
}

CASE_INSENSITIVE_TOKENS = [
    "ZeroKit2",
    "hunt_pipeline",
    "hunt-pipeline",
    "SecOpsAgentKit",
]

CASE_SENSITIVE_PATH_FRAGMENTS = [
    "core/agents/",
    "core/tools/",
    "core/adapters/",
    "test_vul",
    "Piranha",
    "bpost",
]

GEMINI_PROVIDER_KEYWORDS = [
    "provider",
    "llm",
    "model",
    "api",
    "gateway",
    "runtime",
    "claude",
    "codex",
    "openai",
    "google",
]

CI_PATTERNS = [(token, re.compile(re.escape(token), re.IGNORECASE)) for token in CASE_INSENSITIVE_TOKENS]
GEMINI_PATTERN = re.compile(r"\bgemini\b", re.IGNORECASE)


def gather_scan_paths() -> list[Path]:
    paths = []
    if AGENT_DIR.exists():
        paths.extend(sorted(path for path in AGENT_DIR.rglob("*") if path.is_file()))
    paths.extend(sorted(REPO_ROOT.glob("*.md")))

    unique: list[Path] = []
    seen: set[Path] = set()
    for path in paths:
        resolved = path.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        unique.append(path)
    return unique


def gemini_is_provider_context(line: str) -> bool:
    lowered = line.lower()
    if not GEMINI_PATTERN.search(line):
        return False
    return any(keyword in lowered for keyword in GEMINI_PROVIDER_KEYWORDS)


def scan_line(line: str) -> list[str]:
    hits: list[str] = []

    for token, pattern in CI_PATTERNS:
        if pattern.search(line):
            hits.append(token)

    for fragment in CASE_SENSITIVE_PATH_FRAGMENTS:
        if fragment in line:
            hits.append(fragment)

    if gemini_is_provider_context(line):
        hits.append("Gemini(provider-context)")

    deduped: list[str] = []
    for hit in hits:
        if hit not in deduped:
            deduped.append(hit)
    return deduped


def main() -> None:
    violations: list[tuple[str, int, str, str]] = []

    for path in gather_scan_paths():
        if path.name in ALLOWLIST_BY_NAME:
            continue

        text = path.read_text(encoding="utf-8", errors="replace")
        relative = path.relative_to(REPO_ROOT).as_posix()

        for line_number, line in enumerate(text.splitlines(), start=1):
            for hit in scan_line(line):
                violations.append((relative, line_number, hit, line.strip()))

    if violations:
        print("[stale-references] stale legacy references detected", file=sys.stderr)
        for relative, line_number, hit, line in violations:
            excerpt = line if len(line) <= 180 else f"{line[:177]}..."
            print(
                f"[stale-references] {relative}:{line_number}: {hit} :: {excerpt}",
                file=sys.stderr,
            )
        raise SystemExit(1)

    print("[stale-references] ok")


if __name__ == "__main__":
    main()
