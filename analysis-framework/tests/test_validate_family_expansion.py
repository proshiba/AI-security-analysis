"""Tests for offline profile-family batch validation."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

COMMON = Path(__file__).parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import validate_family_expansion as validator  # noqa: E402


def _fixture_tree(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path, Path, str]:
    data = b"fixture"
    digest = hashlib.sha256(data).hexdigest()
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"items": [{"requested_signature": "AsyncRAT", "sha256": digest, "zip_path": "fixture.zip"}]}), encoding="utf-8")
    cache = tmp_path / "cache"
    (cache / "cases" / digest).mkdir(parents=True)
    (cache / "cases" / digest / "case.json").write_text("{}", encoding="utf-8")
    output = tmp_path / "results"
    case = output / "asyncrat" / "run" / "cases" / digest
    case.mkdir(parents=True)
    (case / "README.md").write_text("# case", encoding="utf-8")
    (case / "IOC-LIST.md").write_text("# IOC", encoding="utf-8")
    safe = {"family": "asyncrat", "executed": False, "network_contacted": False}
    for name in ("config.json", "c2-observation-plan.json", "indicators.json"):
        (case / name).write_text(json.dumps(safe), encoding="utf-8")
    monkeypatch.setattr(validator, "read_single_aes_zip_member", lambda path: SimpleNamespace(data=data, name="fixture.exe"))
    monkeypatch.setattr(validator, "detect_family", lambda family, payload, path: {"matched": True, "observations": {"family": family}})
    monkeypatch.setattr(validator, "get_extractor", lambda family: lambda payload, name: {"family": family, "executed": False, "network_contacted": False, "findings": [], "config": {}})
    return manifest, cache, output, digest


def test_validate_accepts_complete_offline_case(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Accept a hash-verified, detector-routed, publish-safe case tree."""
    manifest, cache, output, _ = _fixture_tree(tmp_path, monkeypatch)
    result = validator.validate(manifest, cache, output, "run")
    assert result["status"] == "valid" and result["cases"] == 1
    assert result["sample_executed"] is False and result["infrastructure_contacted"] is False


def test_validate_rejects_executable_results(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Reject accidentally published executable or archive artifacts."""
    manifest, cache, output, digest = _fixture_tree(tmp_path, monkeypatch)
    (output / "asyncrat" / "run" / "cases" / digest / "payload.exe").write_bytes(b"MZ")
    with pytest.raises(ValueError, match="forbidden result artifact"):
        validator.validate(manifest, cache, output, "run")


def test_parser_and_main(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Cover command-line parsing and deterministic summary output."""
    manifest, cache, output, _ = _fixture_tree(tmp_path, monkeypatch)
    args = ["--manifest", str(manifest), "--cache", str(cache), "--output-root", str(output), "--run-id", "run"]
    assert validator.build_parser().parse_args(args).run_id == "run"
    assert validator.main(args) == 0
