"""Go復元の追加が他familyの隔離importを壊さないことを検証する。"""

import sys
from pathlib import Path

import pytest

COMMON = Path(__file__).resolve().parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import handler_catalog as catalog


@pytest.mark.parametrize("handler_id", [
    "vidar:extractors.vidar.extractor.py:extract",
    "vidar:extractors.vidar.integrated.py:extract",
])
def test_vidar_verified_import_pins_full_go_dependency_closure(handler_id):
    """無害なimport-only確認で、manifest外module/dataへのfallbackを防ぐ。"""
    spec = next(item for item in catalog.discover_handlers() if item.id == handler_id)
    preflight = catalog.preflight_handler_for_assessment(spec, actual_format="pe", input_size=1024)
    assert preflight["eligible"] is True, preflight["blockers"]
    audit = preflight["dependency_audit"]
    paths = {item["path"] for item in audit["files"]}
    bindings = {item["name"] for item in audit["module_bindings"]}
    for name in ("go_embedded_pe", "go_decoder_shape", "go_decoder_profiles"):
        assert "unpackers/" + name + ".py" in paths
        assert "unpackers." + name in bindings
    assert audit["data_files"] == []
    imported = catalog.preflight_handler_runtime_import(spec, static_preflight=preflight, timeout_seconds=60)
    assert imported["eligible"] is True, imported["blockers"]
    assert imported["handler_imported"] is True
    assert imported["sample_execution_allowed"] is False
    assert imported["network_allowed"] is False
    assert imported["filesystem_write_allowed"] is False
