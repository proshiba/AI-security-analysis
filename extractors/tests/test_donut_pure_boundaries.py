"""Unit tests for Donut delivery and PureHVNC terminal-family boundaries."""

from __future__ import annotations

import struct

import pytest

from extractors.donutloader.extractor import extract as extract_donut, inspect_chain, layer_markers
from extractors.purehvnc.extractor import extract as extract_pure, extract_native_config, native_endpoint_candidates


def donut_fixture() -> bytes:
    """Build a minimal modern Donut shellcode fixture for extractor tests."""
    payload = b"MZterminal"
    module = bytearray(1320 + len(payload))
    struct.pack_into("<III", module, 0, 2, 0, 1)
    module[12:22] = b"v4.0.30319"
    struct.pack_into("<II", module, 1312, len(payload), len(payload))
    module[1320:] = payload
    instance = bytearray(0xDB0 + len(module))
    struct.pack_into("<I", instance, 0x234, 0)
    struct.pack_into("<I", instance, 0x290, 3)
    instance[0x294:0x2A0] = b"ole32;wininet"
    struct.pack_into("<I", instance, 0x974, 2)
    struct.pack_into("<Q", instance, 0xDA8, len(module))
    instance[0xDB0:] = module
    return b"\xe8" + struct.pack("<I", len(instance)) + instance + b"YU\x48\x89\xe5"


def test_native_endpoint_association_rejects_registry_false_positive() -> None:
    """Keep adjacent C2 port 8080 and reject WOW6432Node as a port."""
    strings = ["config.dat", "8080", "154.82.93.206", "START_SCREEN", r"SOFTWARE\WOW6432Node\Microsoft"]
    assert native_endpoint_candidates(strings) == ["154.82.93.206:8080"]
    config = extract_native_config(b"10FX\0" + b"\0".join(value.encode() for value in strings))
    assert config["endpoints"] == ["154.82.93.206:8080"]
    with pytest.raises(ValueError):
        native_endpoint_candidates(strings, adjacency=-1)


def test_delivery_and_terminal_classification_remain_separate() -> None:
    """Confirm strict Donut evidence without inventing a terminal family."""
    shellcode = donut_fixture()
    assert "strict_donut_shellcode" in layer_markers(shellcode)
    analysis = inspect_chain(shellcode, deep=False)
    assert analysis["donut_confirmed"] is True
    assert analysis["terminal_configs"] == []
    result = extract_donut(shellcode, "fixture", deep=False)
    assert result["family"] == "donutloader"
    assert result["config"]["delivery_profile"] == "embedded_donut"


def test_pure_extractor_keeps_unrecognized_input_explicit() -> None:
    """Return unverified status when neither terminal profile is present."""
    result = extract_pure(b"unrelated", "fixture")
    assert result["config"]["variant"] == "unrecognized"
    assert result["findings"] == []
    for literal in (b"CHRD", b"MZ CHRD", b"PayloadSource.zip", b"v4.0.30319"):
        pure = extract_pure(literal, "single-literal")
        assert pure["config"]["variant"] == "unrecognized"
        assert pure["findings"] == []
        donut = extract_donut(literal, "single-literal", deep=False)
        assert donut["config"]["delivery_profile"] == "unrecognized"
        assert donut["config"]["donut_confirmed"] is False
