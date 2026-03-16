#!/usr/bin/env python3
"""Detect repository language/profile signals for harness phase 02."""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Tuple


@dataclass(frozen=True)
class EntrypointPattern:
    language: str
    kind: str
    regex: re.Pattern[str]


ENTRYPOINT_PATTERNS = [
    EntrypointPattern("typescript", "http", re.compile(r"(?:app|router)\.(?:get|post|put|delete|patch)\s*\(")),
    EntrypointPattern("javascript", "http", re.compile(r"(?:app|router)\.(?:get|post|put|delete|patch)\s*\(")),
    EntrypointPattern("python", "http", re.compile(r"@(?:app|router)\.(?:route|get|post|put|delete|patch)\(")),
    EntrypointPattern("java", "http", re.compile(r"@(GetMapping|PostMapping|PutMapping|DeleteMapping|RequestMapping)")),
    EntrypointPattern("go", "http", re.compile(r"(?:http\.HandleFunc|router\.(?:GET|POST|PUT|DELETE|PATCH))\(")),
    EntrypointPattern("dotnet", "http", re.compile(r"(?:\[Http(?:Get|Post|Put|Delete|Patch)\]|Map(?:Get|Post|Put|Delete|Patch)\()")),
]

TRUST_BOUNDARY_BY_LANG = {
    "dotnet": ["http-request", "jwt-claims", "db-input"],
    "typescript": ["http-request", "message-queue", "env-vars"],
    "javascript": ["http-request", "message-queue", "env-vars"],
    "java": ["http-request", "serialized-input", "db-input"],
    "go": ["http-request", "rpc-input", "env-vars"],
    "python": ["http-request", "template-context", "env-vars"],
}

RISKY_SINKS_BY_LANG = {
    "dotnet": ["sql-execution", "process-spawn", "deserialization", "file-write"],
    "typescript": ["sql-execution", "template-render", "process-spawn", "file-write"],
    "javascript": ["sql-execution", "template-render", "process-spawn", "file-write"],
    "java": ["sql-execution", "template-render", "process-spawn", "deserialization"],
    "go": ["sql-execution", "command-exec", "template-render", "file-write"],
    "python": ["sql-execution", "template-render", "subprocess-spawn", "pickle-deserialization"],
}

BUILD_TEST_HINTS = {
    "dotnet": ("dotnet build", "dotnet test"),
    "typescript": ("npm run build", "npm test"),
    "javascript": ("npm run build", "npm test"),
    "java": ("./gradlew build", "./gradlew test"),
    "go": ("go build ./...", "go test ./..."),
    "python": ("python -m build", "pytest"),
}

LANGUAGE_FILES = {
    "dotnet": ["*.sln", "*.csproj", "*.fsproj", "Program.cs"],
    "typescript": ["tsconfig.json", "*.ts", "*.tsx"],
    "javascript": ["package.json", "*.js", "*.cjs", "*.mjs"],
    "java": ["pom.xml", "build.gradle", "build.gradle.kts", "*.java"],
    "go": ["go.mod", "*.go"],
    "python": ["pyproject.toml", "requirements.txt", "setup.py", "*.py"],
}

FRAMEWORK_SIGNALS = {
    "express": re.compile(r'"express"\s*:'),
    "nestjs": re.compile(r'"@nestjs/core"\s*:'),
    "fastapi": re.compile(r"\bfastapi\b", re.IGNORECASE),
    "flask": re.compile(r"\bflask\b", re.IGNORECASE),
    "django": re.compile(r"\bdjango\b", re.IGNORECASE),
    "spring": re.compile(r"spring-boot|org\.springframework", re.IGNORECASE),
    "aspnetcore": re.compile(r"Microsoft\.AspNetCore", re.IGNORECASE),
    "gin": re.compile(r"github\.com/gin-gonic/gin", re.IGNORECASE),
}

EXCLUDED_DIRS = {
    ".git",
    ".agent",
    "node_modules",
    "vendor",
    "target",
    "dist",
    "build",
    ".venv",
    "venv",
    "__pycache__",
}


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Detect repository profile for harness phase 02")
    parser.add_argument("--target", default=".", help="Target repository path")
    parser.add_argument("--run-id", default="profile-run", help="Run identifier")
    parser.add_argument("--output", default="", help="Optional JSON output file path")
    return parser.parse_args()


def is_excluded(path: Path, target: Path) -> bool:
    try:
        relative_parts = path.relative_to(target).parts
    except ValueError:
        relative_parts = path.parts
    return any(part in EXCLUDED_DIRS for part in relative_parts)


def has_any(target: Path, patterns: List[str]) -> bool:
    for pattern in patterns:
        for path in target.rglob(pattern):
            if is_excluded(path, target):
                continue
            return True
    return False


def detect_languages(target: Path) -> List[str]:
    langs = []
    for language, patterns in LANGUAGE_FILES.items():
        if has_any(target, patterns):
            langs.append(language)
    return langs


def read_text_safely(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def detect_frameworks(target: Path) -> List[str]:
    candidate_files = []
    for pattern in [
        "package.json",
        "pyproject.toml",
        "requirements.txt",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "*.csproj",
        "go.mod",
    ]:
        for file_path in target.rglob(pattern):
            if is_excluded(file_path, target):
                continue
            candidate_files.append(file_path)

    frameworks = set()
    for file_path in candidate_files:
        text = read_text_safely(file_path)
        for framework, pattern in FRAMEWORK_SIGNALS.items():
            if pattern.search(text):
                frameworks.add(framework)
    return sorted(frameworks)


def detect_entrypoints(target: Path, languages: List[str], limit: int = 60) -> List[Dict[str, object]]:
    ext_by_lang = {
        "typescript": [".ts", ".tsx"],
        "javascript": [".js", ".mjs", ".cjs"],
        "python": [".py"],
        "java": [".java"],
        "go": [".go"],
        "dotnet": [".cs"],
    }

    entries: List[Dict[str, object]] = []
    patterns = [p for p in ENTRYPOINT_PATTERNS if p.language in languages]

    for pattern in patterns:
        exts = ext_by_lang.get(pattern.language, [])
        for file_path in target.rglob("*"):
            if len(entries) >= limit:
                return entries
            if not file_path.is_file() or file_path.suffix not in exts:
                continue
            if is_excluded(file_path, target):
                continue
            text = read_text_safely(file_path)
            if not text:
                continue
            for line_no, line in enumerate(text.splitlines(), start=1):
                if pattern.regex.search(line):
                    entries.append(
                        {
                            "kind": pattern.kind,
                            "path": str(file_path.relative_to(target)),
                            "line": line_no,
                        }
                    )
                    break
    return entries


def aggregate_lists(languages: List[str], mapping: Dict[str, List[str]]) -> List[str]:
    values = []
    for lang in languages:
        values.extend(mapping.get(lang, []))
    return sorted(set(values))


def build_test_commands(languages: List[str], target: Path) -> Tuple[List[str], List[str]]:
    build_commands: List[str] = []
    test_commands: List[str] = []

    for lang in languages:
        build_cmd, test_cmd = BUILD_TEST_HINTS[lang]
        if lang in ("typescript", "javascript") and not (target / "package.json").exists():
            continue
        if lang == "java" and not ((target / "pom.xml").exists() or (target / "build.gradle").exists() or (target / "build.gradle.kts").exists()):
            continue
        if lang == "python" and not ((target / "pyproject.toml").exists() or (target / "requirements.txt").exists() or (target / "setup.py").exists()):
            continue
        build_commands.append(build_cmd)
        test_commands.append(test_cmd)

    return sorted(set(build_commands)), sorted(set(test_commands))


def main() -> None:
    args = parse_args()
    target = Path(args.target).resolve()
    languages = detect_languages(target)
    frameworks = detect_frameworks(target)
    build_commands, test_commands = build_test_commands(languages, target)

    result = {
        "run_id": args.run_id,
        "generated_at": utc_now_iso(),
        "languages": languages,
        "frameworks": frameworks,
        "build_commands": build_commands,
        "test_commands": test_commands,
        "entrypoints": detect_entrypoints(target, languages),
        "trust_boundaries": aggregate_lists(languages, TRUST_BOUNDARY_BY_LANG),
        "high_risk_sinks": aggregate_lists(languages, RISKY_SINKS_BY_LANG),
    }

    output = json.dumps(result, indent=2)
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(output + "\n", encoding="utf-8")
    else:
        print(output)


if __name__ == "__main__":
    main()
