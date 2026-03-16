#!/usr/bin/env python3
"""Validate language detector contract and example profile."""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CONTRACT_PATH = REPO_ROOT / ".agent/harness/language-detectors/detector_contract.json"
EXAMPLE_PATH = REPO_ROOT / ".agent/harness/language-detectors/examples/repository_profile.json"



def fail(message: str) -> None:
    print(f"[language-detectors] {message}", file=sys.stderr)
    raise SystemExit(1)


def read_json(path: Path) -> dict:
    if not path.exists():
        fail(f"missing JSON file: {path}")
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except json.JSONDecodeError as exc:
        fail(f"invalid JSON in {path}: {exc}")


def ensure_list_of_strings(value: object, label: str) -> None:
    if not isinstance(value, list) or not value:
        fail(f"{label} must be a non-empty list")
    if not all(isinstance(item, str) and item for item in value):
        fail(f"{label} must contain non-empty strings")


def main() -> None:
    contract = read_json(CONTRACT_PATH)
    profile = read_json(EXAMPLE_PATH)

    supported = contract.get("supported_languages")
    signals = contract.get("language_signals", {})

    ensure_list_of_strings(supported, "supported_languages")

    for language in supported:
        patterns = signals.get(language)
        ensure_list_of_strings(patterns, f"language_signals[{language}]")

    required = contract["detector_outputs"]["repository_profile"]["required_fields"]
    missing = [field for field in required if field not in profile]
    if missing:
        fail(f"repository_profile example missing fields: {missing}")

    ensure_list_of_strings(profile["languages"], "repository_profile.languages")
    unknown_langs = sorted(set(profile["languages"]) - set(supported))
    if unknown_langs:
        fail(f"repository_profile.languages contains unsupported values: {unknown_langs}")

    for key in ["frameworks", "build_commands", "test_commands", "trust_boundaries", "high_risk_sinks"]:
        ensure_list_of_strings(profile[key], f"repository_profile.{key}")

    entrypoints = profile["entrypoints"]
    if not isinstance(entrypoints, list) or not entrypoints:
        fail("repository_profile.entrypoints must be non-empty list")
    for idx, item in enumerate(entrypoints):
        if not isinstance(item, dict):
            fail(f"entrypoints[{idx}] must be object")
        for field in ["kind", "path", "line"]:
            if field not in item:
                fail(f"entrypoints[{idx}] missing {field}")

    print("[language-detectors] ok")


if __name__ == "__main__":
    main()
