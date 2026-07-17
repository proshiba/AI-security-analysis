"""Tests for deterministic new-family scaffolding."""

from __future__ import annotations

import json
from pathlib import Path
import sys

COMMON = Path(__file__).parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import scaffold_family_expansion as scaffold  # noqa: E402


def test_grouping_renderers_and_parser() -> None:
    """Normalize requested signatures and render documented definitions."""
    profiles = {"asyncrat": {"aliases": ["async-rat"], "display_name": "AsyncRAT", "markers": ["a", "b", "c"], "category": "rat", "transport": "tcp", "confirmation": "decode"}}
    grouped = scaffold.family_items({"items": [{"requested_signature": "Async-RAT", "sha256": "a" * 64}]}, profiles)
    assert list(grouped) == ["asyncrat"]
    assert "def detect" in scaffold.detector_source("asyncrat", "AsyncRAT")
    assert "fallback_pipeline" in scaffold.malware_definition("asyncrat", profiles["asyncrat"])
    assert "static.unpack.inspect" in scaffold.workflow_definition("asyncrat", profiles["asyncrat"])
    assert "share" in scaffold.family_readme(profiles["asyncrat"]).lower()
    assert scaffold.build_parser().parse_args(["--manifest", "x.json"]).manifest == Path("x.json")


def test_scaffold_writes_reviewed_hashes(tmp_path: Path, monkeypatch) -> None:
    """Generate a complete thin family module without copying sample bytes."""
    repository = tmp_path / "repo"
    profile_path = repository / "extractors" / "profiles" / "windows_family_profiles.json"
    profile_path.parent.mkdir(parents=True)
    profile_path.write_text("{}", encoding="utf-8")
    profile = {"display_name": "AsyncRAT", "category": "rat", "aliases": [], "markers": ["a", "b", "c"], "transport": "tcp", "confirmation": "decode"}
    monkeypatch.setattr(scaffold, "load_profiles", lambda _path: {"asyncrat": profile})
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"items": [{"requested_signature": "AsyncRAT", "sha256": "b" * 64}]}), encoding="utf-8")
    result = scaffold.scaffold(manifest, repository)
    registry = json.loads((repository / "analysis-framework" / "malware" / "asyncrat" / "campaigns.json").read_text())
    assert result == {"families": 1, "samples": 1, "family_counts": {"asyncrat": 1}}
    assert registry["known_sample_sha256"] == ["b" * 64]
    destination = tmp_path / "nested" / "text.txt"
    scaffold.write_text(destination, "x")
    assert destination.read_text() == "x"
    monkeypatch.setattr(scaffold, "scaffold", lambda manifest, repo: {"families": 0})
    assert scaffold.main(["--manifest", str(manifest), "--repository", str(repository)]) == 0
