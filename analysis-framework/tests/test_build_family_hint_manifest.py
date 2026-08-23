"""publication summaryからstrict family hint manifestを生成する処理を検証する。"""

from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

COMMON = Path(__file__).resolve().parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

manifest_module = importlib.import_module("build_family_hint_manifest")
build_collection_manifest = manifest_module.build_collection_manifest
build_collection_manifest_document = manifest_module.build_collection_manifest_document
build_manifest = manifest_module.build_manifest
write_manifest = manifest_module.write_manifest

SHA256 = "a" * 64


def test_collection_document_api_is_pure_and_path_independent() -> None:
    manifest = build_collection_manifest_document(
        {
            "items": [
                {
                    "found": True,
                    "sha256": SHA256,
                    "metadata": {
                        "sha256_hash": SHA256,
                        "signature": "AsyncRAT",
                    },
                }
            ]
        },
        source="in_memory_fixture",
    )

    assert list(manifest["samples"]) == [SHA256]
    assert manifest["samples"][SHA256][0]["family"] == "asyncrat"
    assert manifest["samples"][SHA256][0]["source"] == "in_memory_fixture"


def test_build_and_write_manifest(short_tmp: Path) -> None:
    summary_path = short_tmp / "publication-summary.json"
    output_path = short_tmp / "family-hints.json"
    summary_path.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "sha256": SHA256,
                        "family": "nanocore",
                        "reported_signature": "NanoCore",
                        "attribution_basis": "malwarebazaar_reported_signature",
                    },
                    {
                        "sha256": "b" * 64,
                        "family": "unclassified",
                        "attribution_basis": "no_supported_family_evidence",
                    },
                ]
            }
        ),
        encoding="utf-8",
    )

    manifest = build_manifest(summary_path, source="fixture_publication")
    write_manifest(output_path, manifest)

    persisted = json.loads(output_path.read_text(encoding="utf-8"))
    assert list(persisted["samples"]) == [SHA256]
    assert persisted["samples"][SHA256][0]["family"] == "nanocore"
    assert persisted["samples"][SHA256][0]["source"] == "fixture_publication"


def test_output_is_deterministic(short_tmp: Path) -> None:
    output_path = short_tmp / "family-hints.json"
    manifest = {
        "schema_version": 1,
        "samples": {
            SHA256: [
                {
                    "family": "valleyrat",
                    "source": "fixture",
                    "provenance": "exact-sha256",
                    "confidence": "unverified",
                }
            ]
        },
    }
    write_manifest(output_path, manifest)
    first = output_path.read_bytes()
    write_manifest(output_path, manifest)
    assert output_path.read_bytes() == first


def test_collection_metadata_builds_verification_only_candidates(short_tmp: Path) -> None:
    path = short_tmp / "manifest.json"
    path.write_text(
        json.dumps(
            {
                "acquisition_items": [
                    {
                        "sha256": SHA256,
                        "metadata": {
                            "sha256_hash": SHA256,
                            "signature": "RemusStealer",
                            "tags": ["remusstealer", "exe", "vidar", "dropped-by-parent"],
                            "first_seen": "2026-08-20 00:00:00",
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    manifest = build_collection_manifest(path, source="fixture_collection")

    assert [hint["family"] for hint in manifest["samples"][SHA256]] == [
        "remusstealer",
        "vidar",
    ]
    assert {
        hint["provenance"] for hint in manifest["samples"][SHA256]
    } == {
        "metadata-manifest:direct_tag",
        "metadata-manifest:reported_signature",
    }
    assert all(
        hint["confidence"] == "unverified"
        for hint in manifest["samples"][SHA256]
    )


def test_private_lookup_uses_provider_sha256_and_skips_not_found(short_tmp: Path) -> None:
    path = short_tmp / "malwarebazaar-lookups.json"
    path.write_text(
        json.dumps(
            {
                "items": [
                    {
                        "found": True,
                        "metadata": {
                            "sha256_hash": SHA256,
                            "signature": "NanoCore",
                            "tags": "NanoCore",
                        },
                    },
                    {
                        "found": False,
                        "sha256": "b" * 64,
                        "metadata": {
                            "sha256_hash": "b" * 64,
                            "signature": "ValleyRAT",
                            "tags": [],
                        },
                    },
                ]
            }
        ),
        encoding="utf-8",
    )

    manifest = build_collection_manifest(path, source="fixture_lookup")

    assert list(manifest["samples"]) == [SHA256]
    assert manifest["samples"][SHA256][0]["family"] == "nanocore"


def test_collection_metadata_rejects_mismatched_sha256(short_tmp: Path) -> None:
    path = short_tmp / "manifest.json"
    path.write_text(
        json.dumps(
            {
                "acquisition_items": [
                    {
                        "sha256": SHA256,
                        "metadata": {
                            "sha256_hash": "b" * 64,
                            "signature": "ValleyRAT",
                            "tags": [],
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    try:
        build_collection_manifest(path, source="fixture_collection")
    except ValueError as exc:
        assert "do not match" in str(exc)
    else:
        raise AssertionError("mismatched SHA-256 was accepted")


def test_collection_metadata_rejects_ambiguous_item_fields(short_tmp: Path) -> None:
    path = short_tmp / "manifest.json"
    path.write_text(
        json.dumps({"acquisition_items": [], "items": []}),
        encoding="utf-8",
    )

    try:
        build_collection_manifest(path, source="fixture_collection")
    except ValueError as exc:
        assert "exactly one item list" in str(exc)
    else:
        raise AssertionError("ambiguous item fields were accepted")


def test_same_sample_multi_hash_queries_deduplicate_exact_hint() -> None:
    metadata = {
        "sha256_hash": SHA256,
        "signature": "NanoCore",
        "tags": ["nanocore"],
    }
    document = {
        "items": [
            {"found": True, "sha256": SHA256, "metadata": dict(metadata)},
            {"found": True, "sha1": "b" * 40, "metadata": dict(metadata)},
            {"found": True, "md5": "c" * 32, "metadata": dict(metadata)},
        ]
    }

    manifest = manifest_module.build_collection_manifest_document(
        document,
        source="fixture_multi_hash",
    )

    assert len(manifest["samples"][SHA256]) == 1
    assert manifest["samples"][SHA256][0]["family"] == "nanocore"


def test_distinct_family_evidence_is_retained_deterministically() -> None:
    document = {
        "items": [
            {
                "found": True,
                "metadata": {"sha256_hash": SHA256, "signature": "ValleyRAT", "tags": []},
            },
            {
                "found": True,
                "metadata": {"sha256_hash": SHA256, "signature": "NanoCore", "tags": []},
            },
        ]
    }

    first = manifest_module.build_collection_manifest_document(document, source="fixture")
    second = manifest_module.build_collection_manifest_document(
        {"items": list(reversed(document["items"]))},
        source="fixture",
    )

    assert first == second
    assert {value["family"] for value in first["samples"][SHA256]} == {
        "nanocore",
        "valleyrat",
    }
