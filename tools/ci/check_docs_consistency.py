#!/usr/bin/env python3
"""Validate core harness docs remain consistent with the architecture baseline."""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DOCS = {
    "scope": REPO_ROOT / ".agent/HARNESS_SCOPE.md",
    "architecture": REPO_ROOT / ".agent/knowledge_base/ARCHITECTURE.md",
    "blueprint": REPO_ROOT / ".agent/knowledge_base/BLUEPRINT.md",
    "menu": REPO_ROOT / ".agent/knowledge_base/MENU_GUIDE.md",
}

LEGACY_TOKENS = [
    ".agent/pipeline/",
    "hunt_pipeline.py",
]



def fail(message: str) -> None:
    print(f"[docs-consistency] {message}", file=sys.stderr)
    raise SystemExit(1)


def load(path: Path) -> str:
    if not path.exists():
        fail(f"missing required document: {path}")
    return path.read_text(encoding="utf-8")


def contains_all(text: str, phrases: list[str], label: str) -> None:
    for phrase in phrases:
        if phrase not in text:
            fail(f"{label} missing phrase: {phrase}")


def main() -> None:
    scope = load(DOCS["scope"])
    architecture = load(DOCS["architecture"])
    blueprint = load(DOCS["blueprint"])
    menu = load(DOCS["menu"])

    contains_all(
        scope,
        [
            "No proof, no vulnerability.",
            ".NET / C#",
            "TypeScript / JavaScript",
            "Java",
            "Go",
            "Python",
        ],
        "HARNESS_SCOPE",
    )

    contains_all(
        architecture,
        [
            "Agent decides; scripts are narrow tool executors.",
            "Verification gate (`no proof, no vulnerability`)",
            "final_report_items",
        ],
        "ARCHITECTURE",
    )

    contains_all(
        blueprint,
        [
            "## Core Flow",
            "Separation of orchestration (master workflow) from specialized subflows.",
            "Verification gate with reproducible evidence",
            "Optimize for security signal quality",
        ],
        "BLUEPRINT",
    )

    contains_all(
        menu,
        [
            "master-harness",
            "phase-01-intake-plan.md",
            "phase-06-report-regression.md",
        ],
        "MENU_GUIDE",
    )

    combined = "\n".join([scope, architecture, blueprint, menu])
    for token in LEGACY_TOKENS:
        if token in combined:
            fail(f"legacy token found in core docs: {token}")

    print("[docs-consistency] ok")


if __name__ == "__main__":
    main()
