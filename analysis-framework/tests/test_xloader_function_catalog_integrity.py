"""XLoader関数カタログが古い像や改変reportを拒否することを検証する。"""

from __future__ import annotations

import hashlib
import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "analysis-framework" / "malware" / "formbook_loader" / "function_catalog.py"
SPEC = importlib.util.spec_from_file_location("xloader_function_catalog_integrity", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
CATALOG = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CATALOG
SPEC.loader.exec_module(CATALOG)


def _fixture() -> tuple[bytes, dict[str, object]]:
    image = bytearray(b"\x90" * 0x100)
    body = b"\x55\x8b\xec\x33\xc0\xc3"
    image[0x20 : 0x20 + len(body)] = body
    image_bytes = bytes(image)
    report: dict[str, object] = {
        "schema_version": 1,
        "analysis_type": "xloader_static_recovery_reconcile",
        "output_sha256": hashlib.sha256(image_bytes).hexdigest(),
        "wrapper_count": 1,
        "recovered_count": 1,
        "unresolved_count": 0,
        "safety": {
            "sample_executed": False,
            "network_contacted": False,
        },
        "functions": [
            {
                "wrapper_start": 0x80,
                "protected_target": 0x20,
                "function_start": 0x20,
                "function_end": 0x20 + len(body),
                "body_sha256": hashlib.sha256(body).hexdigest(),
                "method": "caller_dataflow",
            }
        ],
        "unresolved": [],
    }
    return image_bytes, report


def test_catalog_rejects_stale_output_image_hash() -> None:
    image, report = _fixture()
    report["output_sha256"] = "0" * 64

    with pytest.raises(CATALOG.FunctionCatalogError, match="output SHA-256"):
        CATALOG.build_catalog(image, report, {}, sample_sha256="a" * 64)


def test_catalog_rejects_stale_function_body_hash() -> None:
    image, report = _fixture()
    report["functions"][0]["body_sha256"] = "0" * 64

    with pytest.raises(CATALOG.FunctionCatalogError, match="bodyのSHA-256"):
        CATALOG.build_catalog(image, report, {}, sample_sha256="a" * 64)


def test_catalog_rejects_duplicate_wrapper_across_statuses() -> None:
    image, report = _fixture()
    report["wrapper_count"] = 2
    report["unresolved_count"] = 1
    report["unresolved"] = [{"wrapper_start": 0x80, "protected_target": 0x70}]

    with pytest.raises(CATALOG.FunctionCatalogError, match="重複wrapper_start"):
        CATALOG.build_catalog(image, report, {}, sample_sha256="a" * 64)
