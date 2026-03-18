#!/usr/bin/env python3
"""Smoke test: verify all harness tools are importable and have required functions."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
HARNESS_DIR = REPO_ROOT / "tools" / "harness"

EXPECTED_HARNESS_SCRIPTS = [
    "detect_repo_profile",
    "run_semgrep",
    "run_gitleaks",
    "merge_findings",
    "validate_run_artifacts",
    "run_poc",
    "run_joern",
]


def fail(message: str) -> None:
    print(f"[smoke-harness] {message}", file=sys.stderr)


def main() -> None:
    errors = []

    # Check each expected harness script
    for script_name in EXPECTED_HARNESS_SCRIPTS:
        script_path = HARNESS_DIR / f"{script_name}.py"

        # Verify file exists
        if not script_path.exists():
            errors.append(f"missing harness script: {script_path}")
            continue

        # Try to import the module
        try:
            spec = importlib.util.spec_from_file_location(script_name, script_path)
            if spec is None:
                errors.append(f"cannot create module spec for {script_name}")
                continue
            if spec.loader is None:
                errors.append(f"cannot get loader for {script_name}")
                continue
            module = importlib.util.module_from_spec(spec)
            sys.modules[script_name] = module
            spec.loader.exec_module(module)
        except Exception as e:
            errors.append(f"import failed for {script_name}: {e}")
            continue

        # Verify main() function exists
        if not hasattr(module, "main"):
            errors.append(f"missing main() function in {script_name}")

        # Verify fail() function exists (optional for some scripts)
        if not hasattr(module, "fail"):
            # Don't fail here, just note it. Some scripts may not have fail().
            pass

    if errors:
        for error in errors:
            fail(error)
        sys.exit(1)

    print("[smoke-harness] ok")
    sys.exit(0)


if __name__ == "__main__":
    main()
