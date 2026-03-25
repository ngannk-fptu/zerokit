#!/usr/bin/env python3
"""Fail CI when stale legacy references reappear anywhere in the repo.

Scope: entire repo tree (minus exclusions below).
Previous scope was limited to .agent/, docs/, root *.md — expanded in D1.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

# Directory names excluded from scanning (matched against any path component)
EXCLUDED_DIRS = {
    ".git",
    "__pycache__",
    "node_modules",
    ".codex-review",
    "zerokit.egg-info",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
}

# Path prefixes excluded from scanning (relative to REPO_ROOT).
# These are runtime/cache directories that live inside the repo but are not source.
EXCLUDED_PATH_PREFIXES = [
    ".venv",                # Python virtual environment
    ".devcontainer/state",  # XDG cache for opencode profiles (uv, bun package caches)
    ".sisyphus",            # Agent planning/handoff state (runtime, not source)
    ".opencode/node_modules",  # OpenCode npm dependencies (third-party)
    ".claude",              # Claude session state
    ".context",             # Context window tracking
    ".agent/artifacts/runs",  # Generated pentest run output (runtime, not source)
]

# Files allowlisted by name — these legitimately reference forbidden tokens
# in a "do not do this" or "this is what we moved away from" context.
ALLOWLIST_BY_NAME: dict[str, str] = {
    # Runbook intentionally documents forbidden legacy patterns as examples.
    "ci_guardrails_runbook.md": "Runbook intentionally documents forbidden legacy patterns.",
    # This checker embeds token definitions — must be self-exempt.
    "check_stale_references.py": "This checker embeds forbidden token definitions.",
    # Scope boundary checker uses forbidden path strings as disallowed-path checks.
    "check_scope_boundaries.py": "Uses forbidden path strings as scope-check targets, not references.",
    # Research doc comparing V3 with ZeroKit2 v5.2 — mentions ZeroKit2 by name for comparison.
    "teammate-release-zerokit2-v52-comparative-analysis.md": (
        "Research comparison doc — ZeroKit2 mentioned as the external release being analyzed."
    ),
    # Gap analysis doc that documents old platform references to show what changed.
    "vision-alignment-gap-analysis.md": (
        "Documents legacy platform mentions (Antigravity, etc.) to show what was corrected."
    ),
    # Plan doc lists forbidden tokens as examples of what to purge.
    "plan.md": "Implementation plan lists forbidden tokens in the 'do not do' inventory section.",
}

# Case-insensitive brand/product tokens — match anywhere in a line
CASE_INSENSITIVE_TOKENS = [
    "ZeroKit2",
    "hunt_pipeline",
    "hunt-pipeline",
    "Antigravity",
    "SecOpsAgentKit",
]

# Case-sensitive path fragments — match as substrings
CASE_SENSITIVE_PATH_FRAGMENTS = [
    "core/agents/",
    "core/tools/",
    "core/adapters/",
    "test_vul",
    "Piranha",
    "bpost",
]

# Gemini context: only flag "gemini" when it appears as an LLM provider reference,
# not when it's a constellation, a person's name, or a general product mention.
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

CI_PATTERNS = [
    (token, re.compile(re.escape(token), re.IGNORECASE))
    for token in CASE_INSENSITIVE_TOKENS
]
GEMINI_PATTERN = re.compile(r"\bgemini\b", re.IGNORECASE)

# File extensions to scan (binary files are skipped by extension)
TEXT_EXTENSIONS = {
    ".py", ".md", ".txt", ".json", ".jsonc", ".yaml", ".yml",
    ".sh", ".bash", ".zsh", ".toml", ".cfg", ".ini", ".env",
    ".ts", ".js", ".mjs", ".cjs", ".tsx", ".jsx",
    ".html", ".css", ".scss",
    "",  # extensionless files (Makefile, Dockerfile, etc.)
}


def is_excluded(path: Path) -> bool:
    """Return True if path falls under an excluded directory or path prefix."""
    # Check excluded directory names (any path component)
    for part in path.parts:
        if part in EXCLUDED_DIRS:
            return True
    # Check excluded path prefixes (relative to REPO_ROOT)
    try:
        relative = path.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return False
    for prefix in EXCLUDED_PATH_PREFIXES:
        if relative == prefix or relative.startswith(prefix + "/"):
            return True
    return False


def is_text_file(path: Path) -> bool:
    """Return True if the file has a scannable extension."""
    return path.suffix.lower() in TEXT_EXTENSIONS


def gather_scan_paths() -> list[Path]:
    """Walk the entire repo and return all scannable files."""
    paths: list[Path] = []
    seen: set[Path] = set()

    for path in sorted(REPO_ROOT.rglob("*")):
        if not path.is_file():
            continue
        if is_excluded(path):
            continue
        if not is_text_file(path):
            continue
        resolved = path.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        paths.append(path)

    return paths


def gemini_is_provider_context(line: str) -> bool:
    """True when 'gemini' is used in an LLM-provider context."""
    if not GEMINI_PATTERN.search(line):
        return False
    lowered = line.lower()
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

    # Deduplicate preserving order
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

        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

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
