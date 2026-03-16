#!/usr/bin/env python3
"""Guard scope boundaries to keep repo aligned with harness mission."""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SKILLS_DIR = REPO_ROOT / ".agent/skills"

REQUIRED_PATHS = [
    REPO_ROOT / ".agent/HARNESS_SCOPE.md",
    REPO_ROOT / ".agent/knowledge_base/ARCHITECTURE.md",
    REPO_ROOT / ".agent/knowledge_base/BLUEPRINT.md",
    REPO_ROOT / ".agent/workflows/master-harness.md",
]

FORBIDDEN_SKILL_DIRS = {
    "anthropic",
    "superpowers",
    "skills",
    "rule-runner",
    "rules",
}

FORBIDDEN_ROOT_PATHS = [
    REPO_ROOT / "core",
    REPO_ROOT / "adapters",
    REPO_ROOT / "test_vul",
    REPO_ROOT / "hunt_pipeline.py",
    REPO_ROOT / "mass_hunt.py",
]



def fail(message: str) -> None:
    print(f"[scope-boundaries] {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    for path in REQUIRED_PATHS:
        if not path.exists():
            fail(f"required path missing: {path}")

    if not SKILLS_DIR.exists():
        fail("skills directory missing")

    current_skill_dirs = {p.name for p in SKILLS_DIR.iterdir() if p.is_dir()}
    bad = sorted(FORBIDDEN_SKILL_DIRS & current_skill_dirs)
    if bad:
        fail(f"forbidden skill directories detected: {bad}")

    for skill_dir in sorted(current_skill_dirs):
        skill_file = SKILLS_DIR / skill_dir / "SKILL.md"
        if not skill_file.exists():
            fail(f"missing SKILL.md in {skill_dir}")

    existing_forbidden_roots = [str(p) for p in FORBIDDEN_ROOT_PATHS if p.exists()]
    if existing_forbidden_roots:
        fail(f"legacy runtime paths reintroduced: {existing_forbidden_roots}")

    print("[scope-boundaries] ok")


if __name__ == "__main__":
    main()
