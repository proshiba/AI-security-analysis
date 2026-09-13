"""family-neutral opaque native dispatch probeの回帰試験。"""

from __future__ import annotations

import struct
from types import SimpleNamespace

import pytest

from extractors.valleyrat import opaque_native_dispatch as opaque


def _encrypt_control(plaintext: bytes, key: int) -> bytes:
    key_bytes = (key ^ 0x9E3779B97F4A7C15).to_bytes(8, "little")
    return bytes(
        value ^ ((key_bytes[index & 7] + 27 * index - 0x5B) & 0xFF)
        for index, value in enumerate(plaintext)
    )


def _synthetic_view(*, mutate_control: bool = False) -> tuple[bytes, object]:
    base = 0x140000000
    text_rva, text_raw, text_size = 0x1000, 0x200, 0x1000
    data_rva, data_raw, data_size = 0x2000, 0x1200, 0x1000
    control_rva, control_raw, control_size = 0x4000, 0x2200, 0x1000
    material = bytearray(0x3200)
    material[:2] = b"MZ"
    resolver = base + text_rva + 0xF00
    for index in range(64):
        code_offset = text_raw + index * 16
        code_address = base + text_rva + index * 16
        descriptor_address = base + data_rva + index * 56
        displacement = descriptor_address - (code_address + 7)
        call_displacement = resolver - (code_address + 12)
        struct.pack_into("<3sI", material, code_offset, b"\x48\x8d\x0d", displacement)
        struct.pack_into("<BI", material, code_offset + 7, 0xE8, call_displacement)
        material[code_offset + 12 : code_offset + 16] = b"\x90\x90\x90\xc3"

        descriptor_offset = data_raw + index * 56
        control_address = base + control_rva + index * 8
        key = 0x1020304050607080 ^ index
        plaintext = b"\x00\x10\x40\x00\x00\xff"
        ciphertext = bytearray(_encrypt_control(plaintext, key))
        if mutate_control:
            ciphertext[2] ^= 0x7F
        material[
            control_raw + index * 8 : control_raw + index * 8 + len(ciphertext)
        ] = ciphertext
        next_address = descriptor_address + 56 if index < 63 else 0
        target = base + text_rva + 0xC00 + (index % 16) * 4
        initializer = base + text_rva + 0xB00 + (index % 16) * 4
        struct.pack_into(
            "<7Q",
            material,
            descriptor_offset,
            initializer,
            next_address,
            target,
            key,
            control_address,
            len(plaintext),
            0x1000 + index,
        )

    def section(rva: int, raw: int, size: int, executable: bool) -> object:
        return SimpleNamespace(
            VirtualAddress=rva,
            PointerToRawData=raw,
            SizeOfRawData=size,
            Characteristics=0x20000000 if executable else 0x40000000,
        )

    image = SimpleNamespace(
        FILE_HEADER=SimpleNamespace(Machine=0x8664),
        OPTIONAL_HEADER=SimpleNamespace(ImageBase=base, Magic=0x20B),
        sections=[
            section(text_rva, text_raw, text_size, True),
            section(data_rva, data_raw, data_size, False),
            section(control_rva, control_raw, control_size, False),
        ],
        DIRECTORY_ENTRY_IMPORT=[],
    )
    return bytes(material), image


def test_control_decoder_requires_complete_small_bytecode() -> None:
    key = 0x1122334455667788
    plaintext = b"\x00\x20\x00\x40\xff"
    ciphertext = _encrypt_control(plaintext, key)
    assert opaque.decode_control_bytecode(ciphertext, key) == plaintext
    assert opaque.decode_control_bytecode(b"", key) is None
    assert opaque.decode_control_bytecode(ciphertext + b"\x00", key) is None


@pytest.mark.parametrize(
    "plaintext",
    [
        b"\x00\x10\x7f\x40\xff",
        b"\x00\x10\x00\xff",
        b"\x00\x40\x00\xff",
        b"\x10\x20\x40\xff",
        b"\x10\x40\xff\xff",
    ],
)
def test_control_decoder_rejects_opcode_and_semantic_mutations(
    plaintext: bytes,
) -> None:
    key = 0x8877665544332211
    assert opaque.decode_control_bytecode(_encrypt_control(plaintext, key), key) is None


def test_probe_recovers_route_without_promoting_family_or_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    material, image = _synthetic_view()
    monkeypatch.setattr(opaque.pefile, "PE", lambda **_kwargs: image)
    result = opaque.probe_opaque_native_dispatch(material)
    assert result["status"] == "opaque_native_dispatch_recovered"
    assert result["matched"] is True
    assert result["static_analysis_route_recovered"] is True
    assert result["supports_family_attribution"] is False
    assert result["terminal_family_confirmed"] is False
    assert result["static_config_recovered"] is False
    assert result["network_lineage_proven"] is False
    dispatch = result["evidence"]["opaque_dispatch"]
    assert dispatch["descriptor_count"] == 64
    assert dispatch["referenced_descriptor_count"] == 64
    assert dispatch["unique_target_count"] == 16
    assert dispatch["dominant_resolver_reference_count"] == 64


def test_probe_rejects_mutated_control_programs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    material, image = _synthetic_view(mutate_control=True)
    monkeypatch.setattr(opaque.pefile, "PE", lambda **_kwargs: image)
    result = opaque.probe_opaque_native_dispatch(material)
    assert result["matched"] is False
    assert result["terminal_family_confirmed"] is False
    assert result["static_config_recovered"] is False
    assert result["evidence"]["opaque_dispatch"]["descriptor_count"] == 0


def test_probe_handles_capstone_skipdata_without_operand_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    material, image = _synthetic_view()
    mutated = bytearray(material)
    mutated[0x200:0x204] = b"\x0f\x0f\x0f\x0f"
    monkeypatch.setattr(opaque.pefile, "PE", lambda **_kwargs: image)
    result = opaque.probe_opaque_native_dispatch(bytes(mutated))
    assert result["status"] == "opaque_native_dispatch_recovered"
    assert result["evidence"]["opaque_dispatch"][
        "referenced_descriptor_count"
    ] == 63


def test_probe_is_bounded_before_parser(monkeypatch: pytest.MonkeyPatch) -> None:
    def unexpected_parser(**_kwargs: object) -> object:
        raise AssertionError("oversized input must be rejected before PE parsing")

    monkeypatch.setattr(opaque.pefile, "PE", unexpected_parser)
    material = b"MZ" + b"\0" * (opaque.MAXIMUM_SAMPLE_SIZE - 1)
    result = opaque.probe_opaque_native_dispatch(material)
    assert result["status"] == "budget_exceeded"
    assert result["matched"] is False


def test_public_result_contains_no_addresses_or_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    material, image = _synthetic_view()
    monkeypatch.setattr(opaque.pefile, "PE", lambda **_kwargs: image)
    serialized = repr(opaque.probe_opaque_native_dispatch(material))
    assert "0x1400" not in serialized
    assert "sha256" not in serialized.casefold()
    assert "endpoint" not in serialized.casefold()
