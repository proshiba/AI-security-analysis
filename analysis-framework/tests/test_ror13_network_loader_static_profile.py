"""汎用ROR13 loaderの静的自動検出と候補境界を検証する。"""

from __future__ import annotations

import copy
from pathlib import Path
import struct
import sys

import pytest

FRAMEWORK = Path(__file__).resolve().parents[1]
if str(FRAMEWORK) not in sys.path:
    sys.path.insert(0, str(FRAMEWORK))

from malware.ror13_network_loader import static_profile  # noqa: E402
from malware.ror13_network_loader.detect import detect  # noqa: E402
from malware.ror13_network_loader.extract_config import extract_config  # noqa: E402


def _inert_pe(*, dll: bool = False) -> bytes:
    """実行コードを持たない、PE構造検証だけのメモリ内fixture。"""

    data = bytearray(0x400)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x14C, 1, 0, 0, 0, 0xE0, 0x2102 if dll else 0x0102)
    struct.pack_into("<H", data, 0x98, 0x10B)
    struct.pack_into("<III", data, 0xA8, 0x1000, 0x1000, 0x2000)
    struct.pack_into("<I", data, 0xB4, 0x400000)
    struct.pack_into("<II", data, 0xB8, 0x1000, 0x200)
    struct.pack_into("<II", data, 0xD0, 0x2000, 0x200)
    data[0x178:0x180] = b".text\0\0\0"
    struct.pack_into("<IIIIIIHHI", data, 0x180, 0x100, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020)
    return bytes(data)


def _review_report() -> dict[str, object]:
    parts = ["34.9", "2.22", "5.25"]
    return {
        "sha256": "a" * 64,
        "status": "pattern_observed",
        "resolver_va": "0x401300",
        "call_count": 10,
        "matched_count": 10,
        "matches": [{"exports": [name]} for name in sorted(static_profile.REQUIRED_EXPORTS)],
        "route_fragments": [
            {"address": f"0x{0x401100 + 0x10 * index:x}", "text": part}
            for index, part in enumerate(parts)
        ],
        "sockaddr_port_candidates": [{"address": "0x401200", "port": 8084}],
        "endpoint_candidate": {
            "host": "34.92.225.25",
            "port": 8084,
            "transport": "tcp",
            "confidence": "static_candidate_dataflow_review_required",
            "evidence": {"stack_fragments": parts},
        },
        "memory_xor_byte_constants": ["0x99"],
    }


def test_inert_pe_profile_is_route_only(monkeypatch: pytest.MonkeyPatch) -> None:
    data = _inert_pe()
    monkeypatch.setattr(static_profile, "review_bytes", lambda _data: _review_report())
    observation = detect(data)
    assert observation["matched"] is True
    assert observation["supports_family_attribution"] is False
    assert observation["campaigns"][0]["attribution_scope"] == "component_handler_route"
    result = extract_config(data)
    assert result["network_candidates"][0]["host"] == "34.92.225.25"
    assert result["network_candidates"][0]["role"] == "network_destination_candidate"
    assert result["network_candidates"][0]["evidence"]["dataflow_to_connect_verified"] is False
    assert result["c2"] == []
    assert result["supports_family_attribution"] is False
    assert result["terminal_family_confirmed"] is False
    assert result["safety"] == {
        "sample_executed": False, "network_contacted": False, "stage_fetched": False,
    }


@pytest.mark.parametrize("damage", ["missing_api", "ambiguous_hash", "distant_fragment", "port_before", "no_xor"])
def test_incomplete_or_ambiguous_static_evidence_is_rejected(
    monkeypatch: pytest.MonkeyPatch, damage: str
) -> None:
    report = copy.deepcopy(_review_report())
    if damage == "missing_api":
        report["matches"] = report["matches"][:-1]
    elif damage == "ambiguous_hash":
        report["matches"][0]["exports"].append("other.dll!SameHash")
    elif damage == "distant_fragment":
        report["route_fragments"][1]["address"] = "0x401180"
    elif damage == "port_before":
        report["sockaddr_port_candidates"][0]["address"] = "0x401010"
    else:
        report["memory_xor_byte_constants"] = []
    monkeypatch.setattr(static_profile, "review_bytes", lambda _data: report)
    assert detect(_inert_pe())["matched"] is False
    with pytest.raises(ValueError):
        extract_config(_inert_pe())


def test_non_pe_dll_and_oversized_input_are_not_disassembled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_if_called(_data: bytes) -> object:
        raise AssertionError("disassembly should not be reached")

    monkeypatch.setattr(static_profile, "review_bytes", fail_if_called)
    for data in (b"not PE", _inert_pe(dll=True), b"MZ" + b"\0" * static_profile.MAX_INPUT_BYTES):
        assert detect(data)["matched"] is False


def test_builtin_export_dictionary_requires_no_windows_dll() -> None:
    from recover_ror13_peb_api_hashes import api_hash, load_export_map

    mapping = load_export_map(Path("/nonexistent/windows/system32"))
    assert mapping[api_hash("ws2_32.dll", "connect")] == ["ws2_32.dll!connect"]


def test_auto_handler_is_discoverable_and_static_preflight_eligible() -> None:
    from handler_catalog import discover_handlers, preflight_handler_for_assessment

    specs = [spec for spec in discover_handlers() if spec.family == "ror13_network_loader"]
    handler = next(spec for spec in specs if spec.callable_name == "extract_config")
    assert handler.automatic is True
    assert handler.input_formats == ("pe",)
    result = preflight_handler_for_assessment(handler, actual_format="pe", input_size=4096)
    assert result["eligible"] is True, result["blockers"]
    assert result["sample_execution_allowed"] is False
    assert result["network_allowed"] is False
    assert result["filesystem_write_allowed"] is False
