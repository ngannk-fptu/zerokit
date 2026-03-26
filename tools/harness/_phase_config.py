#!/usr/bin/env python3
"""Shared phase config loader — reads .agent/methodology/phase_config.json.

Usage (as a module):
    from tools.harness._phase_config import load_phase_config
    config = load_phase_config()  # uses default path
    for phase in config.phases:
        print(phase.id, phase.dir, phase.doc)

Fail-fast: raises FileNotFoundError if JSON missing, ValueError if malformed.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import List

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PATH = REPO_ROOT / ".agent/methodology/phase_config.json"


@dataclass
class PhaseEntry:
    """A single phase entry from phase_config.json."""

    id: str
    dir: str
    doc: str


@dataclass
class PhaseConfig:
    """Typed wrapper around the full phase configuration."""

    phases: List[PhaseEntry]


def load_phase_config(path: Path | str | None = None) -> PhaseConfig:
    """Load and validate phase_config.json, returning a typed PhaseConfig.

    Args:
        path: Path to the JSON file. Defaults to
              ``REPO_ROOT / ".agent/methodology/phase_config.json"``.

    Raises:
        FileNotFoundError: If the JSON file does not exist.
        ValueError: If the JSON is malformed or missing required keys.
    """
    config_path = Path(path) if path is not None else DEFAULT_PATH

    if not config_path.exists():
        raise FileNotFoundError(
            f"Phase config not found: {config_path}"
        )

    try:
        raw = json.loads(config_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Malformed JSON in {config_path}: {exc}") from exc

    if not isinstance(raw, dict) or "phases" not in raw:
        raise ValueError(
            f"Phase config must be a JSON object with a 'phases' key: {config_path}"
        )

    phases_raw = raw["phases"]
    if not isinstance(phases_raw, list):
        raise ValueError(f"'phases' must be a list: {config_path}")

    entries: List[PhaseEntry] = []
    for idx, item in enumerate(phases_raw):
        if not isinstance(item, dict):
            raise ValueError(f"phases[{idx}] must be an object: {config_path}")
        for key in ("id", "dir", "doc"):
            if key not in item:
                raise ValueError(
                    f"phases[{idx}] missing required key '{key}': {config_path}"
                )
        entries.append(PhaseEntry(id=item["id"], dir=item["dir"], doc=item["doc"]))

    return PhaseConfig(phases=entries)


def get_phase_dirs(path: Path | str | None = None) -> List[str]:
    """Convenience: return ordered list of phase directory names."""
    config = load_phase_config(path)
    return [phase.dir for phase in config.phases]
