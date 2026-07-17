"""Tests for idempotent unknown-batch history generation."""

from __future__ import annotations

import json
from pathlib import Path

import update_unknown_analysis_history as history


def summary_fixture() -> dict:
    """Return one supported and one unclassified case fixture."""
    return {"cases": [
        {
            "sha256": "a" * 64,
            "source": {"file_type": "jar"},
            "attribution": {"family": "irahook", "confidence": "medium"},
        },
        {
            "sha256": "b" * 64,
            "source": {"file_type": "exe"},
            "attribution": {"family": "unknown", "confidence": "low"},
        },
    ]}


def test_render_and_idempotent_append(tmp_path: Path) -> None:
    """Render conservative C2-empty entries and append every hash once."""
    entries = history.render_history_entries(summary_fixture(), "analysis-results/unclassified/batch", "2026-07-17")
    assert len(entries) == 2
    assert 'malware_type: "irahook"' in entries[0][1]
    assert "c2: []" in entries[0][1]
    path = tmp_path / "analysis_history.yaml"
    path.write_text("analyses:\n", encoding="utf-8")
    assert history.append_missing_entries(path, entries) == 2
    assert history.append_missing_entries(path, entries) == 0
    assert path.read_text(encoding="utf-8").count("sample_sha256:") == 2


def test_cli(tmp_path: Path) -> None:
    """Exercise JSON input parsing and command-line dispatch."""
    summary = tmp_path / "summary.json"
    summary.write_text(json.dumps(summary_fixture()), encoding="utf-8")
    output = tmp_path / "analysis_history.yaml"
    output.write_text("analyses:\n", encoding="utf-8")
    assert history.main([
        "--summary", str(summary), "--history", str(output),
        "--result-root", "analysis-results/unclassified/batch",
        "--analyzed-at", "2026-07-17",
    ]) == 0
