"""Prometei Windowsの静的section復元とC2誤昇格防止を検証する。"""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys

import pytest


ROOT = Path(__file__).resolve().parents[2]
PROMETEI = ROOT / "analysis-framework" / "malware" / "prometei"
if str(PROMETEI) not in sys.path:
    sys.path.insert(0, str(PROMETEI))


def load(relative: str, name: str):
    path = ROOT / relative
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def build_synthetic_pe(
    unpacker,
    *,
    controller: str = "192.168.0.201",
    trailing: bytes = b",",
    include_validation_markers: bool = True,
) -> tuple[bytes, bytes, bytes]:
    step = 0x31
    clear_text = (
        bytes.fromhex("8b442408c70041000000b8c0364300c3")
        + b"\x90" * (0x200 - 16)
    )
    clear_data = bytearray(b"\0" * 0x800)
    markers = (
        b"OK - valid code\n",
        b"NtQuerySystemInformation",
        b"HashPowerProject",
        b"EncryptedMachineKeyId",
        b"sqhost.exe",
        b"svchost2.exe",
        b"Dcomsvc",
        b"UPlugPlay",
        b"System32\\cmd.exe",
    )
    if include_validation_markers:
        cursor = 0x80
        for marker in markers:
            clear_data[cursor : cursor + len(marker)] = marker
            cursor += len(marker) + 17

    encrypted_text = unpacker.rolling_xor_decode(clear_text, step)
    encrypted_data = unpacker.rolling_xor_decode(bytes(clear_data), step)
    raw_text = 0x200
    raw_data = 0x400
    overlay_offset = 0xC00
    image = bytearray(overlay_offset)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x80)
    image[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HH", image, 0x84, 0x14C, 2)
    struct.pack_into("<H", image, 0x94, 0xE0)
    struct.pack_into("<H", image, 0x98, 0x10B)

    section_table = 0x80 + 24 + 0xE0
    sections = (
        (b".text", 0x200, 0x1000, 0x200, raw_text),
        (b".data", 0x800, 0x2000, 0x800, raw_data),
    )
    for index, (name, virtual_size, virtual_address, raw_size, raw_offset) in enumerate(sections):
        offset = section_table + index * 40
        image[offset : offset + 8] = name.ljust(8, b"\0")
        struct.pack_into(
            "<IIII",
            image,
            offset + 8,
            virtual_size,
            virtual_address,
            raw_size,
            raw_offset,
        )
    image[raw_text : raw_text + len(encrypted_text)] = encrypted_text
    image[raw_data : raw_data + len(encrypted_data)] = encrypted_data
    config = {
        "config": 1,
        "id": "ref",
        "ParentId": "parent",
        "ip": controller,
        "ParentHostname": "lab",
    }
    image.extend(json.dumps(config, separators=(",", ":")).encode("utf-8"))
    image.extend(trailing)
    return bytes(image), clear_text, bytes(clear_data)


def test_windows_rolling_xor_recovers_unique_sections_without_publishing_step() -> None:
    unpacker = load(
        "analysis-framework/malware/prometei/windows_static_unpack.py",
        "prometei_unpack_positive",
    )
    sample, clear_text, clear_data = build_synthetic_pe(unpacker)

    result = unpacker.analyze_packed_sections(sample, enforce_reviewed_hash=False)

    assert result["candidate_count"] == 1
    assert result["step_published"] is False
    assert "step" not in result
    assert result["decoded_section_hashes"] == {
        ".text": hashlib.sha256(clear_text).hexdigest(),
        ".data": hashlib.sha256(clear_data).hexdigest(),
    }
    assert result["terminal_payload_recovered"] is True
    assert result["terminal_payload_kind"] == "in_place_decrypted_sections"
    assert result["reconstructed_payload_published"] is False
    assert result["sample_executed"] is False
    assert result["network_contacted"] is False


def test_windows_rolling_xor_fails_closed_for_zero_or_multiple_candidates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unpacker = load(
        "analysis-framework/malware/prometei/windows_static_unpack.py",
        "prometei_unpack_fail_closed",
    )
    sample, _clear_text, clear_data = build_synthetic_pe(
        unpacker,
        include_validation_markers=False,
    )
    with pytest.raises(ValueError, match="candidate_count=0"):
        unpacker.analyze_packed_sections(sample, enforce_reviewed_hash=False)

    monkeypatch.setattr(
        unpacker,
        "_candidate_steps",
        lambda _source: [(1, clear_data), (2, clear_data)],
    )
    with pytest.raises(ValueError, match="candidate_count=2"):
        unpacker.analyze_packed_sections(sample, enforce_reviewed_hash=False)


def test_private_controller_and_generic_pe_json_are_not_promoted() -> None:
    unpacker = load(
        "analysis-framework/malware/prometei/windows_static_unpack.py",
        "prometei_unpack_private",
    )
    extractor = load(
        "analysis-framework/malware/prometei/extract_config.py",
        "prometei_extract_private",
    )
    detector = load(
        "analysis-framework/malware/prometei/detect.py",
        "prometei_detect_generic_pe",
    )
    sample, _clear_text, _clear_data = build_synthetic_pe(unpacker)

    report = extractor.extract_config(sample)
    detection = detector.detect(sample)

    assert report["config"]["controller_scope"] == "rfc1918_private"
    assert report["config"]["monitor_eligible"] is False
    assert report["c2"] == []
    assert report["operational_c2_recovered"] is False
    assert detection["matched"] is False
    assert detection["observations"]["generic_pe_json_rejected"] is True


def test_global_controller_is_config_candidate_but_not_live_confirmed() -> None:
    unpacker = load(
        "analysis-framework/malware/prometei/windows_static_unpack.py",
        "prometei_unpack_global",
    )
    extractor = load(
        "analysis-framework/malware/prometei/extract_config.py",
        "prometei_extract_global",
    )
    sample, _clear_text, _clear_data = build_synthetic_pe(
        unpacker,
        controller="8.8.8.8",
    )

    report = extractor.extract_config(sample)

    assert report["config"]["controller_scope"] == "globally_routable"
    assert report["c2"] == [{
        "host": "8.8.8.8",
        "port": None,
        "role": "controller",
        "confidence": "confirmed_config_host_only",
        "monitor_eligible": True,
    }]
    assert report["safety"]["network_contacted"] is False


def test_overlay_single_comma_is_allowed_but_arbitrary_tail_is_rejected() -> None:
    unpacker = load(
        "analysis-framework/malware/prometei/windows_static_unpack.py",
        "prometei_unpack_overlay",
    )
    extractor = load(
        "analysis-framework/malware/prometei/extract_config.py",
        "prometei_extract_overlay",
    )
    accepted, _clear_text, _clear_data = build_synthetic_pe(unpacker, trailing=b",\0\r\n")
    assert extractor.extract_config(accepted)["config"]["json_trailing_size"] == 4

    rejected, _clear_text, _clear_data = build_synthetic_pe(unpacker, trailing=b",BAD")
    with pytest.raises(ValueError, match="許可していない"):
        extractor.extract_config(rejected)


def test_c2_detector_excludes_private_controller_before_event_correlation() -> None:
    detector = load(
        "analysis-framework/malware/prometei/c2_detector.py",
        "prometei_c2_private",
    )
    event = {
        "host": "192.168.0.201",
        "port": 12345,
        "prometei_process_or_hash_correlation": True,
    }
    private = detector.detect_events(
        [event],
        {"config": {"controller_ip": "192.168.0.201"}},
    )
    assert private["matched"] is False
    assert private["reason"] == "configured_controller_is_not_globally_routable"
    assert private["network_contacted"] is False

    global_report = detector.detect_events(
        [{**event, "host": "8.8.8.8"}],
        {"config": {"controller_ip": "8.8.8.8"}},
    )
    assert global_report["matched"] is True
    assert global_report["c2_confirmed"] is False
    assert global_report["network_contacted"] is False
