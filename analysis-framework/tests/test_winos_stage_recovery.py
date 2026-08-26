from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MODULE_ROOT = ROOT / "malware" / "valleyrat" / "campaigns" / "signed_proxy_sideload"
sys.path.insert(0, str(MODULE_ROOT))
spec = importlib.util.spec_from_file_location("winos_stage_recovery", MODULE_ROOT / "winos_stage_recovery.py")
assert spec and spec.loader
MODULE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(MODULE)
PROTOCOL = importlib.import_module("winos_protocol")


def minimal_pe() -> bytes:
    image = bytearray(0x600)
    image[:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\0\0"
    image[0x86:0x88] = (1).to_bytes(2, "little")
    image[0x94:0x96] = (0xE0).to_bytes(2, "little")
    optional = 0x98
    image[optional : optional + 2] = (0x10B).to_bytes(2, "little")
    image[optional + 60 : optional + 64] = (0x200).to_bytes(4, "little")
    section = optional + 0xE0
    image[section + 16 : section + 20] = (0x400).to_bytes(4, "little")
    image[section + 20 : section + 24] = (0x200).to_bytes(4, "little")
    return bytes(image)


def test_embedded_pe_candidate_uses_section_raw_extent() -> None:
    image = minimal_pe()
    candidates = MODULE.embedded_pe_candidates(b"prefix" + image + b"trailing")
    assert len(candidates) == 1
    record, recovered = candidates[0]
    assert record["offset"] == 6
    assert record["size"] == 0x600
    assert recovered == image


def test_false_mz_is_rejected() -> None:
    assert MODULE.embedded_pe_candidates(b"MZ" + b"x" * 200) == []


def test_artifact_output_must_be_outside_repository() -> None:
    with pytest.raises(ValueError, match="repository外"):
        MODULE.outside_repository(ROOT / "malware")


@pytest.mark.parametrize(
    "cipher_mode",
    [
        PROTOCOL.CipherMode.ROLLING_HEADER_PLUS_0X36,
        PROTOCOL.CipherMode.FIXED_XOR_CC,
    ],
)
def test_recover_streams_uses_explicit_ca01_cipher_mode(cipher_mode) -> None:
    image = minimal_pe()
    payload = b"\x05" + image
    header = bytes.fromhex("3800000000000000ca01")
    frame = PROTOCOL.build_frame(
        payload,
        header,
        cipher_mode=cipher_mode,
    )
    row = "4|1|170.62.130.47|449|10.0.0.9|53000|" + frame.hex()

    candidates = MODULE.recover_streams(
        [row],
        [("170.62.130.47", 449)],
        cipher_mode=cipher_mode,
    )

    assert len(candidates) == 1
    record, recovered = candidates[0]
    assert recovered == image
    assert record["frame_command"] == 0x05
    assert record["cipher_mode"] == cipher_mode.value


def test_stage_recovery_rejects_auto_mode_and_cli_requires_explicit_enum() -> None:
    with pytest.raises(ValueError, match="unsupported cipher mode"):
        MODULE.recover_streams([], [], cipher_mode="auto")

    parsed = MODULE.build_parser().parse_args(
        [
            "fixture.pcap",
            "--endpoint",
            "170.62.130.47:449",
            "--output-root",
            "offline-output",
            "--cipher-mode",
            "fixed_xor_cc",
        ]
    )
    assert parsed.cipher_mode == "fixed_xor_cc"
