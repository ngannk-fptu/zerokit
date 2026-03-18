#!/usr/bin/env python3
"""Check workflow YAML for broken script references."""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_FILE = REPO_ROOT / ".github" / "workflows" / "harness-guardrails.yml"


def fail(message: str) -> None:
    print(f"[workflow-integrity] {message}", file=sys.stderr)


def extract_script_references_from_yaml(workflow_text: str) -> list[str]:
    """Extract all script references from workflow YAML text."""
    scripts = []

    # Parse run: directives with regex (simple approach, no YAML parser needed)
    # Pattern: "run: python tools/ci/script_name.py"
    matches = re.findall(r"run:\s+python\s+(tools/\S+\.py)", workflow_text)
    scripts.extend(matches)

    return scripts


def main() -> None:
    errors = []
    warnings = []

    # Check workflow file exists
    if not WORKFLOW_FILE.exists():
        fail(f"workflow file not found: {WORKFLOW_FILE}")
        sys.exit(1)

    # Read YAML
    try:
        with open(WORKFLOW_FILE) as f:
            workflow_text = f.read()
    except Exception as e:
        fail(f"failed to read workflow YAML: {e}")
        sys.exit(1)

    if not workflow_text.strip():
        fail("workflow YAML is empty")
        sys.exit(1)

    # Extract script references
    script_refs = extract_script_references_from_yaml(workflow_text)

    # Check each referenced script exists
    for script_ref in script_refs:
        script_path = REPO_ROOT / script_ref
        if not script_path.exists():
            errors.append(f"workflow references non-existent script: {script_ref}")

    # Check that all CI scripts are referenced (warn on unreferenced)
    ci_dir = REPO_ROOT / "tools" / "ci"
    if ci_dir.exists():
        all_ci_scripts = sorted([p.name for p in ci_dir.glob("*.py") if p.is_file()])
        for ci_script in all_ci_scripts:
            # Check if this script is referenced in workflow
            script_path = f"tools/ci/{ci_script}"
            if script_path not in script_refs:
                warnings.append(f"CI script not referenced in workflow: {ci_script}")

    # Report errors
    if errors:
        for error in errors:
            fail(error)
        sys.exit(1)

    # Report warnings
    if warnings:
        for warning in warnings:
            print(f"[workflow-integrity] warning: {warning}", file=sys.stderr)

    print("[workflow-integrity] ok")
    sys.exit(0)


if __name__ == "__main__":
    main()
