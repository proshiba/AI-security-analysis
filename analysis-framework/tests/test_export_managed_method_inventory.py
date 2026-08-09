"""RedLine全MethodDef正本エクスポータの回帰テスト。"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

COMMON_ROOT = Path(__file__).resolve().parents[1] / "common"
if str(COMMON_ROOT) not in sys.path:
    sys.path.insert(0, str(COMMON_ROOT))
_spec = importlib.util.spec_from_file_location(
    "redline_managed_method_inventory_export_tests",
    COMMON_ROOT / "export_managed_method_inventory.py",
)
assert _spec is not None and _spec.loader is not None
exporter = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(exporter)

SAMPLE_SHA256 = "1" * 64
ARCHIVE_URI = (
    "s3://malware-analysis-datastore-720232834682/"
    "analysis-targets/redline-fixture/fixture.zip"
)


def _source(*, duplicate_token: bool = False) -> bytes:
    methods = [
        {
            "method_token": "0x06000001",
            "owner": "Program",
            "name": "Main",
            "has_cil_body": True,
            "normalized_fingerprint_sha256": "4" * 64,
        }
    ]
    if duplicate_token:
        methods.append(dict(methods[0]))
    report = {
        "candidates": [
            {
                "terminal": True,
                "sha256": "2" * 64,
                "cil_semantic_sha256": "3" * 64,
                "identity": {"mvid": "11111111-2222-3333-4444-555555555555"},
                "managed_methods": {
                    "metadata_method_count": len(methods),
                    "cil_body_count": len(methods),
                    "inventory": methods,
                },
            }
        ]
    }
    return (json.dumps(report, ensure_ascii=False) + "\n").encode()


def test_inventory_keeps_private_logical_provenance_without_local_path() -> None:
    result = exporter.build_inventory(
        _source(),
        sample_sha256=SAMPLE_SHA256,
        source_logical_id="redline-static-report",
        source_availability="private_s3_archive",
        source_archive_uri=ARCHIVE_URI,
    )
    assert result["summary"]["method_definition_count"] == 1
    assert result["summary"]["parsed_cil_body_count"] == 1
    assert result["summary"]["raw_cil_included"] is False
    assert result["source"]["logical_id"] == "redline-static-report"
    assert result["source"]["availability"] == "private_s3_archive"
    assert result["source"]["archive_uri"] == ARCHIVE_URI
    assert "path" not in result["source"]


def test_duplicate_method_token_fails_closed() -> None:
    with pytest.raises(exporter.InventoryError, match="識別子または型"):
        exporter.build_inventory(
            _source(duplicate_token=True),
            sample_sha256=SAMPLE_SHA256,
            source_logical_id="redline-static-report",
            source_availability="private_s3_archive",
            source_archive_uri=ARCHIVE_URI,
        )
