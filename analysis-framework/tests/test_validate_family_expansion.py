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
    case = (
        output / "malware" / "asyncrat" / "versions" / "unknown" / "cases" / digest
    )
    case.mkdir(parents=True)
    (case / "README.md").write_text("# case", encoding="utf-8")
    (case / "IOC-LIST.md").write_text(validator.ioc_markdown([digest], []), encoding="utf-8")
    safe = {"family": "asyncrat", "executed": False, "network_contacted": False}
    for name in ("config.json", "c2-observation-plan.json"):
        (case / name).write_text(json.dumps(safe), encoding="utf-8")
    canonical_path = case.relative_to(output.parent).as_posix()
    (case / "metadata.json").write_text(
        json.dumps(
            {
                "case_id": f"sha256:{digest}",
                "family": "asyncrat",
                "case_kind": "malware",
                "canonical_path": canonical_path,
            }
        ),
        encoding="utf-8",
    )
    indicators = {
        "family": "asyncrat",
        "source": {"sha256": digest},
        "static_analysis": {"findings": []},
        "sample_executed": False,
        "network_contacted": False,
    }
    (case / "indicators.json").write_text(json.dumps(indicators), encoding="utf-8")
    (output / "catalog").mkdir(parents=True)
    (output / "catalog" / "cases.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "cases": {
                    digest: {
                        "case_id": f"sha256:{digest}",
                        "family": "asyncrat",
                        "case_kind": "malware",
                        "version_key": "unknown",
                        "canonical_path": canonical_path,
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    source = output / "collections" / "run" / "sources" / "asyncrat"
    source.mkdir(parents=True)
    (source / "IOC-LIST.md").write_text(
        validator.ioc_markdown([digest], []), encoding="utf-8"
    )
    (output / "collections" / "run" / "manifest.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "collection_id": "run",
                "family_sources": [
                    {"family": "asyncrat", "path": "sources/asyncrat"}
                ],
                "cases": [{"case_id": f"sha256:{digest}"}],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(validator, "read_single_aes_zip_member", lambda path: SimpleNamespace(data=data, name="fixture.exe"))
    monkeypatch.setattr(validator, "detect_family", lambda family, payload, path: {"matched": True, "observations": {"family": family}})
    monkeypatch.setattr(validator, "get_extractor", lambda family: lambda payload, name: {"family": family, "executed": False, "network_contacted": False, "findings": [], "config": {}})
    return manifest, cache, output, digest


def test_validate_accepts_complete_offline_case(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Accept a hash-verified, detector-routed, publish-safe case tree."""
    manifest, cache, output, _ = _fixture_tree(tmp_path, monkeypatch)
    result = validator.validate(manifest, cache, output, "run")
    assert result["status"] == "valid" and result["cases"] == 1
    assert result["ioc_lists_validated"] == 2
    assert result["sample_executed"] is False and result["infrastructure_contacted"] is False


def test_validate_rejects_executable_results(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Reject accidentally published executable or archive artifacts."""
    manifest, cache, output, digest = _fixture_tree(tmp_path, monkeypatch)
    (
        output
        / "malware"
        / "asyncrat"
        / "versions"
        / "unknown"
        / "cases"
        / digest
        / "payload.exe"
    ).write_bytes(b"MZ")
    with pytest.raises(ValueError, match="forbidden result artifact"):
        validator.validate(manifest, cache, output, "run")


def test_validate_rejects_missing_and_stale_ioc_content(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Reject a standard-looking case list missing its hash and an old aggregate list."""
    manifest, cache, output, digest = _fixture_tree(tmp_path, monkeypatch)
    case = (
        output / "malware" / "asyncrat" / "versions" / "unknown" / "cases" / digest
    )
    (case / "IOC-LIST.md").write_text(validator.ioc_markdown([], []), encoding="utf-8")
    with pytest.raises(ValueError, match="missing expected IOC content"):
        validator.validate(manifest, cache, output, "run")

    (case / "IOC-LIST.md").write_text(validator.ioc_markdown([digest], []), encoding="utf-8")
    (
        output / "collections" / "run" / "sources" / "asyncrat" / "IOC-LIST.md"
    ).write_text("# IOC 一覧\n\n## SHA-256\n", encoding="utf-8")
    with pytest.raises(ValueError, match="stale aggregate IOC content"):
        validator.validate(manifest, cache, output, "run")


def test_ioc_content_validation_preserves_windows_file_paths(tmp_path: Path) -> None:
    """Markdown row parsing must not consume literal Windows path separators."""
    findings = [
        {
            "value": r"C:\ProgramData\reviewed-stage.dll",
            "role": "file_ioc",
            "confidence": "confirmed",
            "source": "fixture",
        }
    ]
    path = tmp_path / "IOC-LIST.md"
    path.write_text(validator.ioc_markdown([], findings), encoding="utf-8")

    assert validator.validate_ioc_content(path, [], findings, "fixture", exact=True) == []


def test_ioc_content_validation_rejects_secret_bearing_url(tmp_path: Path) -> None:
    """Committed IOC rows must already have userinfo, query, and fragment removed."""
    path = tmp_path / "IOC-LIST.md"
    path.write_text(
        "# IOC 一覧\n\n"
        "| 種別 (Type) | 値 (Value) | 役割 (Role) | 確度 (Confidence) | 根拠 (Source) |\n"
        "|---|---|---|---|---|\n"
        "| url | https://user:pw@c2.example.org/gate?token=x#fragment | c2_candidate | candidate | fixture |\n",
        encoding="utf-8",
    )

    assert validator.validate_ioc_content(path, [], [], "fixture") == [
        "fixture: unsafe or non-normalized IOC value at line 5"
    ]


def test_parser_and_main(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Cover command-line parsing and deterministic summary output."""
    manifest, cache, output, _ = _fixture_tree(tmp_path, monkeypatch)
    args = ["--manifest", str(manifest), "--cache", str(cache), "--output-root", str(output), "--run-id", "run"]
    assert validator.build_parser().parse_args(args).run_id == "run"
    assert validator.main(args) == 0
