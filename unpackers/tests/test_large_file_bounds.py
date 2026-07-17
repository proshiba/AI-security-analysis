"""Tests for bounded analysis of inflated or otherwise large inputs."""

from __future__ import annotations

from types import SimpleNamespace

import unpackers.static_unpacker as unpacker


def test_entropy_uses_deterministic_three_window_sample(monkeypatch) -> None:
    """Use first, middle, and last windows when the full-input bound is exceeded."""
    monkeypatch.setattr(unpacker, "ENTROPY_FULL_LIMIT", 8)
    monkeypatch.setattr(unpacker, "ENTROPY_SAMPLE_WINDOW", 2)
    value = b"\0\0" + b"\xff" * 8 + b"\0\0"
    sampled = value[:2] + value[5:7] + value[-2:]
    monkeypatch.setattr(unpacker, "ENTROPY_FULL_LIMIT", 999)
    expected = unpacker.entropy(sampled)
    monkeypatch.setattr(unpacker, "ENTROPY_FULL_LIMIT", 8)
    assert unpacker.entropy(value) == expected


def test_pe_section_entropy_uses_bounded_helper(monkeypatch) -> None:
    """Route PE section entropy through the shared bounded sampler."""
    section_data = b"A" * 32

    class Section:
        Name = b".text\0\0\0"
        SizeOfRawData = len(section_data)
        Misc_VirtualSize = len(section_data)
        Characteristics = 0x60000020
        VirtualAddress = 0x1000

        @staticmethod
        def get_data() -> bytes:
            return section_data

        @staticmethod
        def get_entropy() -> float:
            raise AssertionError("pefile's unbounded entropy must not be used")

    directories = [SimpleNamespace(VirtualAddress=0, Size=0) for _ in range(15)]
    image = SimpleNamespace(
        sections=[Section()],
        OPTIONAL_HEADER=SimpleNamespace(DATA_DIRECTORY=directories, AddressOfEntryPoint=0x1000),
        FILE_HEADER=SimpleNamespace(Machine=0x14C),
        get_overlay_data_start_offset=lambda: None,
    )
    monkeypatch.setattr(unpacker.pefile, "PE", lambda **_kwargs: image)
    observed: list[bytes] = []
    monkeypatch.setattr(unpacker, "entropy", lambda value: observed.append(value) or 1.25)

    summary, artifacts = unpacker.pe_summary(b"MZ" + b"\0" * 64)
    assert observed == [section_data]
    assert summary["sections"][0]["entropy"] == 1.25
    assert artifacts == []


def test_protected_pe_routes_to_bounded_cfg_without_block_bloat(monkeypatch) -> None:
    """Attach summarized CFG evidence only when PE protection is suspected."""
    class Section:
        Name = b".text\0\0\0"
        SizeOfRawData = 0x2000
        Misc_VirtualSize = 0x2000
        Characteristics = 0x60000020
        VirtualAddress = 0x1000

        @staticmethod
        def get_data() -> bytes:
            return b"X" * 0x2000

    directories = [SimpleNamespace(VirtualAddress=0, Size=0) for _ in range(15)]
    image = SimpleNamespace(
        sections=[Section()],
        OPTIONAL_HEADER=SimpleNamespace(DATA_DIRECTORY=directories, AddressOfEntryPoint=0x1000),
        FILE_HEADER=SimpleNamespace(Machine=0x14C),
        get_overlay_data_start_offset=lambda: None,
    )
    monkeypatch.setattr(unpacker.pefile, "PE", lambda **_kwargs: image)
    monkeypatch.setattr(unpacker, "entropy", lambda _value: 7.8)
    monkeypatch.setattr(
        unpacker,
        "analyze_pe_control_flow",
        lambda _data: {
            "status": "analyzed",
            "blocks": [{"address": "0x1000"}],
            "static_context": {
                "sections": [{"name": ".text"}],
                "import_names": ["VirtualProtect"],
            },
            "metrics": {"basic_blocks": 1},
            "techniques": {},
        },
    )
    summary, _ = unpacker.pe_summary(b"MZ" + b"\0" * 64)
    triage = summary["control_flow_triage"]
    assert summary["classification"] == "suspected_packed"
    assert "blocks" not in triage
    assert "sections" not in triage["static_context"]
    assert triage["metrics"]["basic_blocks"] == 1


def test_managed_pe_routes_to_bounded_il_summary(monkeypatch) -> None:
    """Keep managed counts and evidence while omitting large token inventories."""
    class Section:
        Name = b".text\0\0\0"
        SizeOfRawData = 16
        Misc_VirtualSize = 16
        Characteristics = 0x60000020
        VirtualAddress = 0x1000

        @staticmethod
        def get_data() -> bytes:
            return b"A" * 16

    directories = [SimpleNamespace(VirtualAddress=0, Size=0) for _ in range(15)]
    directories[14].VirtualAddress = 0x2000
    image = SimpleNamespace(
        sections=[Section()],
        OPTIONAL_HEADER=SimpleNamespace(
            DATA_DIRECTORY=directories,
            AddressOfEntryPoint=0x1000,
        ),
        FILE_HEADER=SimpleNamespace(Machine=0x14C),
        get_overlay_data_start_offset=lambda: None,
    )
    monkeypatch.setattr(unpacker.pefile, "PE", lambda **_kwargs: image)
    monkeypatch.setattr(unpacker, "entropy", lambda _value: 1.0)
    monkeypatch.setattr(
        unpacker,
        "analyze_managed_pe",
        lambda _data: {
            "status": "analyzed",
            "types": [{"token": "0x02000001"}],
            "methods": [{"token": "0x06000001"}],
            "counts": {"methods_parsed": 1},
            "resources": [{"sha256": "0" * 64}],
            "malformed_method_bodies": [],
            "techniques": {},
        },
    )
    summary, _ = unpacker.pe_summary(b"MZ" + b"\0" * 64)
    managed = summary["managed_il_triage"]
    assert summary["is_dotnet"] is True
    assert managed["status"] == "analyzed"
    assert managed["counts"]["methods_parsed"] == 1
    assert "types" not in managed and "methods" not in managed
