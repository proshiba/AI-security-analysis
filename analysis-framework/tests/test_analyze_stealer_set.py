"""Tests for stealer-manifest orchestration."""

from __future__ import annotations

import json
from pathlib import Path
import sys
import zipfile

import pyzipper
import pytest

COMMON = Path(__file__).parents[1] / "common"
sys.path.insert(0, str(COMMON))

import analyze_stealer_set as batch  # noqa: E402

DEFINITIONS = Path(__file__).parents[1] / "definitions"


def encrypted_archive(path: Path, name: str, data: bytes) -> None:
    """Write a MalwareBazaar-shaped encrypted single-member ZIP fixture."""
    with pyzipper.AESZipFile(path, "w", compression=zipfile.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as archive:
        archive.setpassword(b"infected")
        archive.setencryption(pyzipper.WZ_AES, nbits=256)
        archive.writestr(name, data)


def test_family_and_campaign_helpers() -> None:
    """Cover exact signature mapping and campaign-shape routing."""
    assert batch.family_id("Formbook") == "formbook"
    assert batch.family_id("ValleyRAT") == "valleyrat"
    assert batch.family_id("AgentTesla") == "agenttesla"
    assert batch.family_id("RemcosRAT") == "remcosrat"
    assert batch.family_id("VenomRAT") == "venomrat"
    with pytest.raises(ValueError):
        batch.family_id("unknown")
    assert batch.campaign_hint("amosstealer", "x.macho", b"\xcf\xfa\xed\xfe", {}) == "direct_macho"
    assert batch.campaign_hint("remusstealer", "x.7z", b"7z\xbc\xaf'\x1c", {}) == "encrypted_7z_delivery"
    assert batch.campaign_hint("agenttesla", "x.js", b"text", {"format": "script"}) == "script_delivery"
    assert batch.campaign_hint("valleyrat", "x.xls", b"data", {"format": "ole"}) == "macro_office_delivery"
    assert (
        batch.campaign_hint("venomrat", "x.bin", b"data", {"format": "data"})
        == "unknown_or_nested_delivery"
    )


def test_item_manifest_and_cli(tmp_path: Path) -> None:
    """Exercise per-case, manifest, parser, and CLI orchestration."""
    archive = tmp_path / "sample.zip"
    encrypted_archive(archive, "sample.osascript", b'tell application "Finder"\nhttps://evil.example/ledger/id')
    case = batch.analyze_item("amosstealer", archive, tmp_path / "case", DEFINITIONS)
    assert case["c2_assessment"] == "probable" and case["sample_executed"] is False
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps({"signature": "AmosStealer", "items": [{"sha256": case["sha256"], "zip_path": str(archive)}]}),
        encoding="utf-8",
    )
    summary = batch.analyze_manifest(manifest, tmp_path / "batch", DEFINITIONS)
    assert summary["counts"]["total"] == 1
    args = ["--manifest", str(manifest), "--output", str(tmp_path / "cli"), "--definitions", str(DEFINITIONS)]
    assert batch.build_parser().parse_args(args).manifest == manifest
    assert batch.main(args) == 0
