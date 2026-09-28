"""managed参照の未走査を再帰PE summaryのcompleteへ昇格しないことを検証する。"""

from __future__ import annotations

from pathlib import Path
import struct
import sys

import pytest

from unpackers import static_unpacker

_FRAMEWORK = Path(__file__).resolve().parents[2] / "analysis-framework"
if str(_FRAMEWORK) not in sys.path:
    sys.path.insert(0, str(_FRAMEWORK))


def _pe_shape(*, managed: bool = True) -> bytes:
    """実行コードと実CLR bodyを持たない、静的parser用のPE外形。"""

    data = bytearray(0x400)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x14C, 1, 0, 0, 0, 0xE0, 0x102)
    struct.pack_into("<H", data, 0x98, 0x10B)
    struct.pack_into("<I", data, 0x98 + 28, 0x400000)
    struct.pack_into("<II", data, 0x98 + 32, 0x1000, 0x200)
    struct.pack_into("<II", data, 0x98 + 56, 0x2000, 0x200)
    struct.pack_into("<I", data, 0x98 + 92, 16)
    if managed:
        struct.pack_into("<II", data, 0x98 + 96 + 14 * 8, 0x1100, 72)
    data[0x178:0x180] = b".text\0\0\0"
    struct.pack_into("<IIII", data, 0x180, 0x200, 0x1000, 0x200, 0x200)
    struct.pack_into("<I", data, 0x178 + 36, 0x60000020)
    return bytes(data)


def _summary(monkeypatch, triage: dict):
    monkeypatch.setattr(static_unpacker, "analyze_managed_pe", lambda _data: triage.copy())
    monkeypatch.setattr(static_unpacker, "analyze_managed_protector", lambda _data: {"status": "fixture"})
    summary, _artifacts = static_unpacker.pe_summary(_pe_shape())
    return summary


@pytest.mark.parametrize("triage", [
    {"status": "analyzed"},
    {"status": "analyzed", "reference_coverage": {"body_scan_complete": False},
     "reference_metadata_coverage": {"complete": True}},
    {"status": "analyzed", "reference_coverage": {"body_scan_complete": True},
     "reference_metadata_coverage": {"complete": False}},
    {"status": "analyzed_partial_budget", "reference_coverage": {"body_scan_complete": True},
     "reference_metadata_coverage": {"complete": True}},
    {"status": "analyzed", "reference_coverage": {"body_scan_complete": 1},
     "reference_metadata_coverage": {"complete": True}},
])
def test_missing_incomplete_and_nonboolean_coverage_stays_partial(monkeypatch, triage) -> None:
    """statusだけがanalyzedでも、body/metadata全走査がなければ未完了とする。"""

    from common.analyze_sample import _static_layer_issues

    summary = _summary(monkeypatch, triage)
    assert summary["analysis_coverage"]["status"] == "partial"
    assert summary["analysis_coverage"]["managed_lexical_references_complete"] is False
    issues = _static_layer_issues({"steps": [{"report": {"pe": summary}}]})
    assert any("analysis_coverage.status:partial" in issue for issue in issues)


def test_complete_lexical_scan_does_not_claim_runtime_targets(monkeypatch) -> None:
    """runtime参照解決は別境界であり、静的全走査の意味を拡大しない。"""

    summary = _summary(monkeypatch, {
        "status": "analyzed", "reference_coverage": {
            "body_scan_complete": True, "runtime_targets_complete": False, "unresolved_retained": 1},
        "reference_metadata_coverage": {"complete": True},
    })
    assert summary["analysis_coverage"]["status"] == "complete"
    assert summary["analysis_coverage"]["managed_lexical_references_complete"] is True
    assert summary["managed_il_triage"]["reference_coverage"]["runtime_targets_complete"] is False


def test_nonmanaged_pe_does_not_require_managed_coverage(monkeypatch) -> None:
    """native PEへmanaged completeness条件を適用しない。"""

    monkeypatch.setattr(static_unpacker, "analyze_managed_pe", lambda _data: pytest.fail("native PEです"))
    summary, _artifacts = static_unpacker.pe_summary(_pe_shape(managed=False))
    assert summary["analysis_coverage"]["status"] == "complete"
    assert summary["analysis_coverage"]["managed_lexical_references_complete"] is None
