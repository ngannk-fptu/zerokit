#!/usr/bin/env python3
"""Initialize a per-run artifact directory structure.

CLI:
    python tools/harness/init_artifact_run.py \\
        --target <path> \\
        --run-id <id> \\
        [--output-dir <path>]   # default: .agent/artifacts/runs/<run-id>
        [--dry-run]             # sets simulated=true in run_state.json
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

# Import from sibling module — no hardcoded phase dirs.
sys.path.insert(0, str(REPO_ROOT))
from tools.harness._phase_config import load_phase_config  # noqa: E402


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Initialize a per-run artifact directory structure"
    )
    parser.add_argument(
        "--target",
        required=True,
        help="Absolute or relative path to the analysis target",
    )
    parser.add_argument(
        "--run-id",
        required=True,
        help="Unique run identifier (e.g. run-20260303T120000Z)",
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Output directory (default: .agent/artifacts/runs/<run-id>)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Set simulated=true in run_state.json",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)

    # Resolve output directory
    if args.output_dir:
        output_dir = Path(args.output_dir)
    else:
        output_dir = REPO_ROOT / ".agent/artifacts/runs" / args.run_id

    # Duplicate run-id guard
    if output_dir.exists():
        print(
            f"[init-artifact-run] output directory already exists: {output_dir}",
            file=sys.stderr,
        )
        raise SystemExit(1)

    # Load phase config (fail-fast if missing / malformed)
    config = load_phase_config()

    # Create phase subdirectories
    for phase in config.phases:
        (output_dir / phase.dir).mkdir(parents=True, exist_ok=True)

    # Build run_state.json
    run_state = {
        "run_id": args.run_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": str(Path(args.target).resolve()),
        "master_workflow": "init_artifact_run",
        "phase_refs": {phase.id: phase.doc for phase in config.phases},
        "phase_status": {phase.id: "pending" for phase in config.phases},
        "status": "initialized",
        "summary": "",
        "simulated": args.dry_run,
    }

    run_state_path = output_dir / "run_state.json"
    run_state_path.write_text(
        json.dumps(run_state, indent=2) + "\n", encoding="utf-8"
    )

    print(f"[init-artifact-run] initialized: {output_dir}")


if __name__ == "__main__":
    main()
