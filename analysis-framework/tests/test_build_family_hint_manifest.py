"""publication summaryからstrict family hint manifestを生成する処理を検証する。"""

from __future__ import annotations

import json
import sys
from pathlib import Path

COMMON = Path(__file__).resolve().parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

from build_family_hint_manifest import build_manifest, write_manifest

SHA256 = "a" * 64


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
