"""Tests for stealer-manifest orchestration."""

from __future__ import annotations

import hashlib
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


def test_manifest_rejects_noncanonical_or_mismatched_inner_hash(tmp_path: Path) -> None:
    """Fail before analysis writes when a manifest identity is malformed or false."""
    storage = tmp_path / "storage"
    storage.mkdir()
    archive = storage / "sample.zip"
    encrypted_archive(archive, "sample.bin", b"authenticated payload")
    manifest = storage / "manifest.json"
    output = tmp_path / "output"

    for claimed in ("A" * 64, "../escape"):
        manifest.write_text(
            json.dumps({"signature": "AmosStealer", "items": [{"sha256": claimed, "zip_path": str(archive)}]}),
            encoding="utf-8",
        )
        with pytest.raises(ValueError, match="64 lowercase hexadecimal"):
            batch.analyze_manifest(manifest, output, DEFINITIONS)
        assert not output.exists()

    manifest.write_text(
        json.dumps({"signature": "AmosStealer", "items": [{"sha256": "0" * 64, "zip_path": str(archive)}]}),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="authenticated inner SHA-256 mismatch"):
        batch.analyze_manifest(manifest, output, DEFINITIONS)
    assert not output.exists()


def test_manifest_archive_must_remain_below_manifest_root(tmp_path: Path) -> None:
    """Reject absolute, traversal, and symlink paths that escape storage."""
    storage = tmp_path / "storage"
    storage.mkdir()
    archive = tmp_path / "outside.zip"
    payload = b"authenticated payload"
    encrypted_archive(archive, "sample.bin", payload)
    manifest = storage / "manifest.json"
    for zip_path in (str(archive), "../outside.zip"):
        manifest.write_text(
            json.dumps({
                "signature": "AmosStealer",
                "items": [{
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "zip_path": zip_path,
                }],
            }),
            encoding="utf-8",
        )
        with pytest.raises(ValueError, match="escapes manifest storage root"):
            batch.analyze_manifest(manifest, tmp_path / "output", DEFINITIONS)


def test_manifest_rejects_duplicate_identity_before_writes(tmp_path: Path) -> None:
    """Reject duplicate case identities before the first analysis can write."""
    storage = tmp_path / "storage"
    storage.mkdir()
    payload = b"authenticated payload"
    archive = storage / "sample.zip"
    encrypted_archive(archive, "sample.bin", payload)
    digest = hashlib.sha256(payload).hexdigest()
    manifest = storage / "manifest.json"
    item = {"sha256": digest, "zip_path": str(archive)}
    manifest.write_text(
        json.dumps({"signature": "AmosStealer", "items": [item, item]}),
        encoding="utf-8",
    )
    output = tmp_path / "output"
    with pytest.raises(ValueError, match="duplicate manifest SHA-256"):
        batch.analyze_manifest(manifest, output, DEFINITIONS)
    assert not output.exists()
