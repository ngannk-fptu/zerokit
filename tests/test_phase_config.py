"""Tests for tools/harness/_phase_config.py."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from tools.harness._phase_config import get_phase_dirs, load_phase_config  # noqa: E402


def test_load_phase_config_returns_correct_structure() -> None:
    """Load the real phase_config.json and assert expected structure."""
    config = load_phase_config()

    assert len(config.phases) == 6
    assert config.phases[0].id == "01"

    for phase in config.phases:
        assert isinstance(phase.dir, str) and phase.dir
        assert isinstance(phase.doc, str) and phase.doc


def test_load_phase_config_fails_fast_on_missing_file() -> None:
    """Passing a nonexistent path must raise FileNotFoundError."""
    with pytest.raises(FileNotFoundError):
        load_phase_config("/nonexistent/path/phase_config.json")


def test_load_phase_config_fails_fast_on_malformed_json(tmp_path: Path) -> None:
    """A JSON file missing the 'phases' key must raise ValueError."""
    bad_file = tmp_path / "bad_config.json"
    bad_file.write_text(json.dumps({"not_phases": []}), encoding="utf-8")

    with pytest.raises(ValueError):
        load_phase_config(bad_file)


def test_get_phase_dirs_returns_ordered_list() -> None:
    """get_phase_dirs returns a list of 6 non-empty strings."""
    dirs = get_phase_dirs()

    assert isinstance(dirs, list)
    assert len(dirs) == 6
    for d in dirs:
        assert isinstance(d, str) and d
