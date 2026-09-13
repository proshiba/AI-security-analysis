from __future__ import annotations

import json
import struct
from types import SimpleNamespace

import pytest

from extractors.valleyrat import export_funnel

_IMAGE_BASE = 0x400000
_RAW_START = 0x100
_VIRTUAL_START = 0x2000
_WRITABLE_DATA = 0xC0000040
_EXECUTABLE_DATA = 0xE0000040
_EXECUTABLE_CODE = 0x60000020


def _wide_hex(material: bytes, *, odd: bool = False) -> bytes:
    text = material.hex().upper()
    if odd:
        text = "A" + text
    return text.encode("utf-16le") + b"\0\0"


def _image_for(
    payload: bytes,
    *,
    characteristics: int = _WRITABLE_DATA,
    raw_size: int | None = None,
) -> tuple[SimpleNamespace, bytes]:
    size = raw_size if raw_size is not None else max(0x800, len(payload) + 0x80)
    data = bytearray(_RAW_START + size)
    data[_RAW_START : _RAW_START + len(payload)] = payload
    section = SimpleNamespace(
        PointerToRawData=_RAW_START,
        SizeOfRawData=size,
        Misc_VirtualSize=size,
        VirtualAddress=_VIRTUAL_START,
        Characteristics=characteristics,
    )
    image = SimpleNamespace(
        OPTIONAL_HEADER=SimpleNamespace(ImageBase=_IMAGE_BASE),
        sections=[section],
    )
    return image, bytes(data)


def _source_use_fixture(
    *,
    branch_before_stage: bool = False,
    terminal_root_branch: str | None = None,
    cleanup_size: int = 0x10,
    split_transform_path: bool = False,
    overwrite_destination: bool = False,
    alternate_transform: bool = False,
    destination_characteristics: int = _WRITABLE_DATA,
    extra_raw_reference: bool = False,
    arbitrary_four_byte_decoy: bool = False,
    source_encoding: str = "push_imm",
    candidate_offset: int = 0,
    invalid_prefix_before_entry: bool = False,
    dead_local_caller: bool = False,
    extra_local_caller: bool = False,
    transform_read: str = "staged",
    transform_store: str = "byte",
    transform_pointer_update: str = "none",
    unresolved_transform_call: bool = False,
    identity_transform: bool = False,
    wide_formatter_copy: bool = False,
    destination_encoding: str = "register",
    overlapping_destination: bool = False,
) -> tuple[SimpleNamespace, bytes, export_funnel.OpaqueWideHexCandidate]:
    """値に依存しないsynthetic x86の同一path証拠を組み立てる。"""

    text_raw = 0x100
    text_virtual = 0x1000
    text_size = 0x400
    data_raw = text_raw + text_size
    data_virtual = 0x3000
    data_raw_size = 0x800
    data_virtual_size = 0x800
    destination_virtual = 0x5000
    candidate_address = _IMAGE_BASE + data_virtual + candidate_offset
    destination_address = (
        candidate_address + 2
        if overlapping_destination
        else _IMAGE_BASE + destination_virtual + 0x100
    )
    format_address = _IMAGE_BASE + text_virtual + 0x300
    material = bytes(range(256))
    payload = _wide_hex(material, odd=True)

    text = bytearray(b"\xcc" * text_size)
    entry_offset = (
        0x30
        if extra_local_caller
        else (0x20 if invalid_prefix_before_entry else 6)
    )

    def emit_call(code: bytearray, target_offset: int) -> None:
        call_offset = entry_offset + len(code)
        displacement = target_offset - (call_offset + 5)
        code.extend(b"\xe8" + struct.pack("<i", displacement))

    zero_target = 0xC0
    staging_target = 0x100
    transform_target = 0x140
    caller_displacement = entry_offset - 5
    text[:6] = b"\xe8" + struct.pack("<i", caller_displacement) + b"\xc3"
    if invalid_prefix_before_entry:
        invalid_offset = 6
        if dead_local_caller:
            text[:8] = (
                b"\xeb\x05\xe8"
                + struct.pack("<i", entry_offset - 7)
                + b"\xc3"
            )
            invalid_offset = 8
        text[invalid_offset : invalid_offset + 2] = b"\x0f\x04"
        if extra_local_caller:
            text[8:14] = (
                b"\xc3\xe8"
                + struct.pack("<i", entry_offset - 14)
            )
            text[14] = 0xC3

    code = bytearray(b"\x51\x53\x56")
    code.extend(b"\x68\x00\x10\x00\x00\x6a\x00")
    code.extend(b"\xbe" + struct.pack("<I", destination_address) + b"\x56")
    emit_call(code, zero_target)
    code.extend(b"\x83\xc4\x0c")
    if source_encoding == "push_imm":
        code.extend(b"\x68" + struct.pack("<I", candidate_address))
    elif source_encoding == "mov_reg":
        code.extend(b"\xb8" + struct.pack("<I", candidate_address) + b"\x50")
    elif source_encoding == "lea_reg":
        code.extend(b"\x8d\x05" + struct.pack("<I", candidate_address) + b"\x50")
    elif source_encoding == "mov_rva":
        code.extend(
            b"\xb8"
            + struct.pack("<I", candidate_address - _IMAGE_BASE)
            + b"\x50"
        )
    elif source_encoding == "mov_base_add_rva":
        code.extend(
            b"\xb8"
            + struct.pack("<I", _IMAGE_BASE)
            + b"\x05"
            + struct.pack("<I", candidate_address - _IMAGE_BASE)
            + b"\x50"
        )
    elif source_encoding == "mov_rva_add_base":
        code.extend(
            b"\xb8"
            + struct.pack("<I", candidate_address - _IMAGE_BASE)
            + b"\xbb"
            + struct.pack("<I", _IMAGE_BASE)
            + b"\x01\xd8\x50"
        )
    elif source_encoding == "section_base_add_offset":
        code.extend(
            b"\xb8"
            + struct.pack("<I", _IMAGE_BASE + data_virtual)
            + b"\x05"
            + struct.pack("<I", candidate_offset)
            + b"\x50"
        )
    elif source_encoding == "section_base_lea_offset":
        code.extend(
            b"\xb8"
            + struct.pack("<I", _IMAGE_BASE + data_virtual)
            + b"\x8d\x80"
            + struct.pack("<I", candidate_offset)
            + b"\x50"
        )
    elif source_encoding == "pic_add_offset":
        next_address = (
            _IMAGE_BASE + text_virtual + entry_offset + len(code) + 5
        )
        code.extend(
            b"\xe8\x00\x00\x00\x00\x58\x05"
            + struct.pack("<I", candidate_address - next_address)
            + b"\x50"
        )
    elif source_encoding == "known_register_alias":
        code.extend(
            b"\xb8"
            + struct.pack("<I", _IMAGE_BASE)
            + b"\x05"
            + struct.pack("<I", candidate_address - _IMAGE_BASE)
            + b"\x89\xc7\x57"
        )
    elif source_encoding == "memory_alias":
        alias_address = destination_address + 0x100
        code.extend(
            b"\xb8"
            + struct.pack("<I", _IMAGE_BASE)
            + b"\x05"
            + struct.pack("<I", candidate_address - _IMAGE_BASE)
            + b"\xa3"
            + struct.pack("<I", alias_address)
            + b"\xff\x35"
            + struct.pack("<I", alias_address)
        )
    elif source_encoding == "wrapped_rva_then_base":
        code.extend(
            b"\xb8\xf0\xff\xff\xff"
            + b"\xba\x10\x30\x00\x00"
            + b"\x01\xd0"
            + b"\xbb"
            + struct.pack("<I", _IMAGE_BASE)
            + b"\x01\xd8\x50"
        )
    elif source_encoding == "wrapped_sub_candidate":
        code.extend(
            b"\xb8"
            + struct.pack("<I", _IMAGE_BASE)
            + b"\x2d\x00\xd0\xff\xff\x50"
        )
    elif source_encoding == "overlap_mov_prefix":
        code.extend(
            b"\x2e\xb8"
            + struct.pack("<I", candidate_address)
            + b"\x50"
        )
    else:
        raise ValueError("unsupported synthetic source encoding")
    if branch_before_stage:
        code.extend(b"\x75\x00")
    code.extend(b"\x68" + struct.pack("<I", format_address))
    code.extend(b"\x68\x00\x08\x00\x00")
    if destination_encoding == "register":
        code.extend(b"\x56")
    elif destination_encoding == "partial_push":
        code.extend(b"\x66\x56")
    elif destination_encoding == "partial_lea":
        code.extend(
            b"\x66\x8d\x35"
            + struct.pack("<I", destination_address)
            + b"\x56"
        )
    else:
        raise ValueError("unsupported synthetic destination encoding")
    emit_call(code, staging_target)
    code.extend(b"\x83\xc4" + bytes([cleanup_size]))
    code.extend(b"\x8a\xcb")
    emit_call(code, transform_target)
    root_branch_target = 0x500 if terminal_root_branch == "non_file_backed" else 0x220
    if terminal_root_branch is not None:
        branch_offset = entry_offset + len(code)
        code.extend(
            b"\x0f\x85"
            + struct.pack("<i", root_branch_target - (branch_offset + 6))
        )
    code.extend(b"\x5e\x5b\x59\xc3")
    text[entry_offset : entry_offset + len(code)] = code
    text[zero_target] = 0xC3
    if wide_formatter_copy:
        helper_target = 0x180
        staging = bytearray(
            b"\x55\x8b\xec\x8d\x45\x14\x50\x6a\x00"
            b"\xff\x75\x14\xff\x75\x10\xff\x75\x0c"
        )
        helper_call = staging_target + len(staging)
        staging.extend(
            b"\xe8"
            + struct.pack("<i", helper_target - (helper_call + 5))
            + b"\x83\xc4\x14\x5d\xc3"
        )
        text[staging_target : staging_target + len(staging)] = staging
        wide_copy_helper = (
            b"\x55\x8b\xec\x56\x57"
            b"\x8b\x7d\x08\x8b\x75\x0c\x8b\x4d\x10"
            b"\xf3\x66\xa5\x90\x31\xc0\x66\x8b\x06"
            b"\x66\x89\x07\x8b\x45\x08\x5f\x5e\x5d\xc3"
        )
        text[helper_target : helper_target + len(wide_copy_helper)] = (
            wide_copy_helper
        )
        text[0x300:0x308] = "%ls\0".encode("utf-16le")
        transform_read = "frame"
        transform_store = "dword_outside"
    else:
        text[staging_target] = 0xC3

    if transform_read == "staged":
        transform = bytearray(b"\x0f\xb6\x0e")
    elif transform_read == "source_absolute":
        transform = bytearray(
            b"\x0f\xb6\x0d" + struct.pack("<I", candidate_address)
        )
    elif transform_read == "frame":
        transform = bytearray(b"\x0f\xb6\x4d\x00")
    else:
        raise ValueError("unsupported synthetic transform read")
    if unresolved_transform_call:
        call_offset = transform_target + len(transform)
        transform.extend(
            b"\xe8" + struct.pack("<i", zero_target - (call_offset + 5))
        )
    if identity_transform:
        transform.extend(b"\x80\xf1\x00\x80\xe9\x00\xc0\xc9\x08")
    else:
        transform.extend(b"\x32\xcb")
    if split_transform_path:
        transform.extend(b"\x75\x06")
    if identity_transform:
        pass
    elif alternate_transform:
        transform.extend(b"\x00\xd9\xc0\xc1\x03\x80\xf1\x5a")
    else:
        transform.extend(b"\x80\xe9\x31\xd0\xc9")
    if overwrite_destination:
        transform.extend(b"\xbe\x00\x20\x40\x00")
    if transform_pointer_update == "fixed_alias":
        transform.extend(b"\x8d\x7e\x01")
    elif transform_pointer_update == "wrap":
        transform.extend(b"\x83\xc6\xff")
    elif transform_pointer_update == "partial_alias":
        transform.extend(b"\x66\x89\xc6")
    elif transform_pointer_update != "none":
        raise ValueError("unsupported synthetic pointer update")
    if transform_store == "byte":
        transform.extend(b"\x88\x0e")
    elif transform_store == "fixed_alias":
        transform.extend(b"\x88\x0f")
    elif transform_store == "dword":
        transform.extend(b"\x89\x0e")
    elif transform_store == "outside":
        transform.extend(b"\x88\x8e" + struct.pack("<I", len(payload)))
    elif transform_store == "unknown_index":
        transform.extend(b"\x88\x0c\x3e")
    elif transform_store == "dword_outside":
        transform.extend(b"\x89\x4e\xfc")
    else:
        raise ValueError("unsupported synthetic transform store")
    transform.extend(b"\xc3")
    text[transform_target : transform_target + len(transform)] = transform
    if terminal_root_branch == "empty":
        text[root_branch_target] = 0xC3
    elif terminal_root_branch == "second_source":
        second_source = (
            b"\xb8"
            + struct.pack("<I", _IMAGE_BASE)
            + b"\x05"
            + struct.pack("<I", candidate_address - _IMAGE_BASE)
            + b"\x50\xc3"
        )
        text[
            root_branch_target : root_branch_target + len(second_source)
        ] = second_source
    elif terminal_root_branch == "non_file_backed":
        pass
    elif terminal_root_branch is not None:
        raise ValueError("unsupported synthetic terminal root branch")
    if extra_raw_reference:
        text[0x200:0x205] = b"\x68" + struct.pack("<I", candidate_address)
    if arbitrary_four_byte_decoy:
        text[0x200:0x206] = (
            b"\xa1" + struct.pack("<I", candidate_address) + b"\xc3"
        )

    raw = bytearray(data_raw + data_raw_size)
    raw[text_raw : text_raw + text_size] = text
    raw[
        data_raw + candidate_offset : data_raw + candidate_offset + len(payload)
    ] = payload
    sections = [
        SimpleNamespace(
            PointerToRawData=text_raw,
            SizeOfRawData=text_size,
            Misc_VirtualSize=text_size,
            VirtualAddress=text_virtual,
            Characteristics=_EXECUTABLE_CODE,
        ),
        SimpleNamespace(
            PointerToRawData=data_raw,
            SizeOfRawData=data_raw_size,
            Misc_VirtualSize=data_virtual_size,
            VirtualAddress=data_virtual,
            Characteristics=_WRITABLE_DATA,
        ),
        SimpleNamespace(
            PointerToRawData=data_raw + data_raw_size,
            SizeOfRawData=0,
            Misc_VirtualSize=0x1000,
            VirtualAddress=destination_virtual,
            Characteristics=destination_characteristics,
        ),
    ]
    image = SimpleNamespace(
        OPTIONAL_HEADER=SimpleNamespace(ImageBase=_IMAGE_BASE),
        sections=sections,
    )
    data = bytes(raw)
    inventory = export_funnel.collect_opaque_wide_hex_candidates(image, data)
    assert inventory is not None
    assert len(inventory.candidates) == 1
    return image, data, inventory.candidates[0]


def _resource_runtime_fixture(
    *,
    locator_name_id: int = 0x123,
    include_size: bool = True,
    source_transfer: str = "register",
    partial_destination_push: bool = False,
) -> tuple[
    SimpleNamespace,
    bytes,
    export_funnel.OpaqueWideHexCandidate,
    export_funnel._ResourceLeaf,
    dict[int, str],
    int,
]:
    """resource API戻り値を保存してdecoderへ渡すsynthetic x86を作る。"""

    text_raw = 0x100
    text_virtual = 0x1000
    text_size = 0x500
    data_raw = text_raw + text_size
    data_virtual = 0x4000
    data_size = 0xC00
    root_offset = 0x20
    staging_offset = 0x200
    transform_offset = 0x240
    root = _IMAGE_BASE + text_virtual + root_offset
    destination = _IMAGE_BASE + data_virtual + 0x600
    candidate_address = _IMAGE_BASE + data_virtual
    iat = {
        0x407000: "findresourcew",
        0x407004: "sizeofresource",
        0x407008: "loadresource",
        0x40700C: "lockresource",
    }
    text = bytearray(b"\xcc" * text_size)

    def api_call(address: int) -> bytes:
        return b"\xff\x15" + struct.pack("<I", address)

    def direct_call(code: bytearray, target_offset: int) -> None:
        call_address = root + len(code)
        target = _IMAGE_BASE + text_virtual + target_offset
        code.extend(b"\xe8" + struct.pack("<i", target - (call_address + 5)))

    code = bytearray()
    code.extend(b"\x68" + struct.pack("<I", 0xBEEF))
    code.extend(b"\x68" + struct.pack("<I", locator_name_id))
    code.extend(b"\x6a\x00" + api_call(0x407000) + b"\x89\xc3")
    if include_size:
        code.extend(b"\x53\x6a\x00" + api_call(0x407004) + b"\x89\xc5")
    code.extend(b"\x53\x6a\x00" + api_call(0x407008))
    code.extend(b"\x50" + api_call(0x40700C))
    if source_transfer == "register":
        code.extend(b"\x89\xc7")
    elif source_transfer == "partial_register":
        code.extend(b"\x66\x89\xc7")
    elif source_transfer == "overlap_memory":
        code.extend(b"\x89\x45\xfc\xc6\x45\xfd\x00\x8b\x7d\xfc")
    else:
        raise ValueError("unsupported synthetic resource source transfer")
    code.extend(b"\xbe" + struct.pack("<I", destination))
    code.extend(b"\x57\x55\x68\x00\x10\x40\x00")
    code.extend(b"\x66\x56" if partial_destination_push else b"\x56")
    direct_call(code, staging_offset)
    code.extend(b"\x83\xc4\x10")
    direct_call(code, transform_offset)
    code.extend(b"\xc3")
    text[root_offset : root_offset + len(code)] = code
    text[staging_offset] = 0xC3
    transform = b"\x0f\xb6\x0f\x32\xcb\x80\xe9\x31\xd0\xc9\x88\x0e\xc3"
    text[transform_offset : transform_offset + len(transform)] = transform

    payload = _wide_hex(bytes(range(256)), odd=True)
    raw = bytearray(data_raw + data_size)
    raw[text_raw : text_raw + text_size] = text
    raw[data_raw : data_raw + len(payload)] = payload
    sections = [
        SimpleNamespace(
            PointerToRawData=text_raw,
            SizeOfRawData=text_size,
            Misc_VirtualSize=text_size,
            VirtualAddress=text_virtual,
            Characteristics=_EXECUTABLE_CODE,
        ),
        SimpleNamespace(
            PointerToRawData=data_raw,
            SizeOfRawData=data_size,
            Misc_VirtualSize=data_size,
            VirtualAddress=data_virtual,
            Characteristics=_WRITABLE_DATA,
        ),
    ]
    image = SimpleNamespace(
        OPTIONAL_HEADER=SimpleNamespace(ImageBase=_IMAGE_BASE),
        sections=sections,
    )
    data = bytes(raw)
    candidates = export_funnel.collect_opaque_wide_hex_candidates(image, data)
    assert candidates is not None and len(candidates.candidates) == 1
    candidate = candidates.candidates[0]
    leaf = export_funnel._ResourceLeaf(
        address=candidate_address,
        size=len(payload),
        entropy=7.5,
        custom_type=True,
        type_id=0xBEEF,
        name_id=0x123,
    )
    return image, data, candidate, leaf, iat, root


@pytest.mark.parametrize(
    "material",
    (bytes(range(256)), bytes(reversed(range(256)))),
)
def test_opaque_wide_hex_inventory_is_value_agnostic(material: bytes) -> None:
    """内容を変えても構造で回収し、raw値を結果に保持しない。"""

    raw = _wide_hex(material, odd=True)
    image, data = _image_for(raw)

    inventory = export_funnel.collect_opaque_wide_hex_candidates(image, data)

    assert inventory is not None
    assert inventory.candidate_set_complete is True
    assert inventory.candidate_set_truncated is False
    assert len(inventory.candidates) == 1
    candidate = inventory.candidates[0]
    assert candidate.address == _IMAGE_BASE + _VIRTUAL_START
    assert candidate.character_count == 513
    assert candidate.normalized_byte_count == 257
    assert candidate.odd_nibble_count == 1
    assert candidate.normalized_entropy >= export_funnel.MIN_OPAQUE_WIDE_HEX_ENTROPY
    serialized = json.dumps(candidate.__dict__, sort_keys=True)
    assert material.hex().upper() not in serialized


@pytest.mark.parametrize(
    ("payload", "characteristics"),
    (
        ("a" * 512 + "\0", _WRITABLE_DATA),
        (("A" * 512) + "X", _WRITABLE_DATA),
        ((bytes(range(256)).hex().upper()) + "\0", 0x40000040),
        ((bytes(range(256)).hex().upper()) + "\0", _EXECUTABLE_DATA),
    ),
)
def test_opaque_wide_hex_inventory_rejects_unsafe_or_invalid_sources(
    payload: str,
    characteristics: int,
) -> None:
    """lowercase、非hex終端、read-only、実行sectionを候補にしない。"""

    image, data = _image_for(
        payload.encode("utf-16le"),
        characteristics=characteristics,
    )

    inventory = export_funnel.collect_opaque_wide_hex_candidates(image, data)

    assert inventory is not None
    assert inventory.candidates == ()


def test_opaque_wide_hex_inventory_candidate_cap_is_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """候補上限を超えた集合を一意候補として扱わない。"""

    monkeypatch.setattr(export_funnel, "MAX_OPAQUE_WIDE_HEX_CANDIDATES", 2)
    material = bytes(range(256))
    payload = b"\x01\x01".join(_wide_hex(material) for _ in range(3))
    image, data = _image_for(payload, raw_size=len(payload) + 0x40)

    inventory = export_funnel.collect_opaque_wide_hex_candidates(image, data)

    assert inventory is not None
    assert len(inventory.candidates) == 2
    assert inventory.candidate_set_complete is False
    assert inventory.candidate_set_truncated is True


def test_opaque_wide_hex_inventory_scan_budget_is_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """scan byte上限超過を空の完全走査として扱わない。"""

    monkeypatch.setattr(export_funnel, "MAX_OPAQUE_WIDE_HEX_SCAN_BYTES", 0x100)
    image, data = _image_for(_wide_hex(bytes(range(256))))

    inventory = export_funnel.collect_opaque_wide_hex_candidates(image, data)

    assert inventory is not None
    assert inventory.candidate_set_complete is False
    assert inventory.candidate_set_truncated is True
    assert inventory.candidates == ()


@pytest.mark.parametrize(
    ("alternate_transform", "expected_operations"),
    (
        (False, {"ror", "sub", "xor"}),
        (True, {"add", "rol", "xor"}),
    ),
)
def test_opaque_wide_hex_use_proves_only_bounded_same_path_semantics(
    alternate_transform: bool,
    expected_operations: set[str],
) -> None:
    """source、staging、変換命令が同一pathに揃う場合だけ局所証拠を返す。"""

    image, data, candidate = _source_use_fixture(
        alternate_transform=alternate_transform
    )

    inventory = export_funnel.collect_opaque_wide_hex_use_evidence(
        image,
        data,
        candidate,
    )

    assert inventory is not None
    assert inventory.reference_set_complete is True
    assert inventory.reference_set_truncated is False
    assert inventory.bounded_analysis_complete is True
    assert inventory.raw_reference_count == 1
    assert inventory.source_operand_reference_count == 1
    assert inventory.anchored_source_reference_count == 1
    assert inventory.staging_call_chain_count == 1
    assert inventory.semantic_transform_chain_count == 1
    assert len(inventory.source_roots) == 1
    assert set(inventory.transform_operation_kinds) == expected_operations

    summary = export_funnel._public_opaque_source_use_summary(inventory)
    assert summary["unique_same_path_transform_chain"] is True
    assert summary["transform_reads_candidate_or_staged_object_byte"] is True
    assert summary["connected_in_bounds_destination_byte_store"] is True
    assert summary["concrete_decoder_recovered"] is False
    assert summary["decoded_plaintext_recovered"] is False
    assert summary["config_parser_proven"] is False
    assert summary["runtime_endpoint_to_connect_proven"] is False
    assert summary["same_socket_send_receive_proven"] is False
    assert summary["raw_values_included"] is False
    assert summary["raw_addresses_included"] is False


def test_transform_gate_accepts_checked_in_bounds_affine_store() -> None:
    """direct callerからstaged byteを読み、object内aliasへ書く場合は受理する。"""

    image, data, candidate = _source_use_fixture(
        transform_pointer_update="fixed_alias",
        transform_store="fixed_alias",
    )

    inventory = export_funnel.collect_opaque_wide_hex_use_evidence(
        image,
        data,
        candidate,
    )

    assert inventory is not None
    assert inventory.reference_set_complete is True
    assert inventory.bounded_analysis_complete is True
    assert inventory.anchored_source_reference_count == 1
    assert inventory.staging_call_chain_count == 1
    assert inventory.semantic_transform_chain_count == 1
    assert set(inventory.transform_operation_kinds) == {"ror", "sub", "xor"}


def test_transform_gate_accepts_absolute_candidate_byte_read() -> None:
    """candidate object originのabsolute byte readも同一taintへ接続する。"""

    image, data, candidate = _source_use_fixture(
        transform_read="source_absolute",
    )

    inventory = export_funnel.collect_opaque_wide_hex_use_evidence(
        image,
        data,
        candidate,
    )

    assert inventory is not None
    assert inventory.reference_set_complete is True
    assert inventory.bounded_analysis_complete is True
    assert inventory.anchored_source_reference_count == 1
    assert inventory.staging_call_chain_count == 1
    assert inventory.semantic_transform_chain_count == 1
    assert set(inventory.transform_operation_kinds) == {"ror", "sub", "xor"}


@pytest.mark.parametrize(
    ("fixture_options", "expected_complete"),
    (
        ({"transform_read": "frame"}, True),
        ({"transform_store": "dword"}, True),
        ({"transform_store": "outside"}, False),
        ({"transform_store": "unknown_index"}, False),
        ({"transform_pointer_update": "wrap"}, False),
        ({"transform_pointer_update": "partial_alias"}, False),
        ({"unresolved_transform_call": True}, False),
        ({"identity_transform": True}, True),
        ({"overlapping_destination": True}, False),
    ),
)
def test_transform_gate_rejects_disconnected_or_unbounded_shapes(
    fixture_options: dict[str, object],
    expected_complete: bool,
) -> None:
    """frame読取、誤幅／範囲、未知alias、wrap、未解決callを拒否する。"""

    image, data, candidate = _source_use_fixture(**fixture_options)

    inventory = export_funnel.collect_opaque_wide_hex_use_evidence(
        image,
        data,
        candidate,
    )

    assert inventory is not None
    assert inventory.reference_set_complete is True
    assert inventory.anchored_source_reference_count == 1
    assert inventory.staging_call_chain_count == 1
    assert inventory.semantic_transform_chain_count == 0
    assert inventory.transform_operation_kinds == ()
    assert inventory.bounded_analysis_complete is expected_complete
    assert export_funnel._unique_opaque_source_use(inventory) is False


def test_transform_gate_rejects_wide_copy_with_outside_metadata_store() -> None:
    """wide formatter copyとstaged範囲外dword storeをbyte変換と誤認しない。"""

    image, data, candidate = _source_use_fixture(wide_formatter_copy=True)

    inventory = export_funnel.collect_opaque_wide_hex_use_evidence(
        image,
        data,
        candidate,
    )

    assert inventory is not None
    assert inventory.reference_set_complete is True
    assert inventory.bounded_analysis_complete is False
    assert inventory.anchored_source_reference_count == 1
    assert inventory.staging_call_chain_count == 1
    assert inventory.semantic_transform_chain_count == 0
    assert inventory.transform_operation_kinds == ()
    assert export_funnel._unique_opaque_source_use(inventory) is False


@pytest.mark.parametrize(
    "destination_encoding",
    ("partial_push", "partial_lea"),
)
def test_direct_staging_rejects_partial_width_destination_provenance(
    destination_encoding: str,
) -> None:
    """16-bit push／LEAを32-bit staged object originへ昇格しない。"""

    image, data, candidate = _source_use_fixture(
        destination_encoding=destination_encoding,
    )

    inventory = export_funnel.collect_opaque_wide_hex_use_evidence(
        image,
        data,
        candidate,
    )

    assert inventory is not None
    assert inventory.reference_set_complete is True
    assert inventory.anchored_source_reference_count == 1
    assert inventory.staging_call_chain_count == 0
    assert inventory.semantic_transform_chain_count == 0
    assert export_funnel._unique_opaque_source_use(inventory) is False


def test_resource_runtime_pointer_and_size_reach_same_decoder_path() -> None:
    """resource locatorからLock pointer/Size lengthを同一decoderまで追跡する。"""

    image, data, candidate, leaf, imports, root = _resource_runtime_fixture()

    inventory = export_funnel.collect_opaque_wide_hex_use_evidence(
        image,
        data,
        candidate,
        external_roots=(root,),
        resource_leaf=leaf,
        import_addresses=imports,
    )

    assert inventory is not None
    assert inventory.raw_reference_count == 0
    assert inventory.source_operand_reference_count == 0
    assert inventory.resource_locator_match_count == 1
    assert inventory.resource_handle_chain_count == 1
    assert inventory.resource_pointer_size_chain_count == 1
    assert inventory.resource_runtime_source_count == 1
    assert inventory.resource_runtime_analysis_complete is True
    assert inventory.resource_runtime_truncated is False
    assert inventory.semantic_transform_chain_count == 1
    assert export_funnel._unique_opaque_source_use(inventory) is True
    summary = export_funnel._public_opaque_source_use_summary(inventory)
    runtime = summary["resource_runtime_pointer_lineage"]
    assert runtime["root_strategy"] == "export_tls_verified_direct_call_graph"
    assert runtime["resource_identifiers_included"] is False
    assert runtime["raw_resource_pointer_included"] is False
    assert runtime["raw_addresses_included"] is False
    assert summary["config_parser_proven"] is False
    assert summary["runtime_endpoint_to_connect_proven"] is False


@pytest.mark.parametrize(
    "fixture_options",
    (
        {"source_transfer": "partial_register"},
        {"source_transfer": "overlap_memory"},
        {"partial_destination_push": True},
    ),
)
def test_resource_runtime_rejects_partial_pointer_provenance(
    fixture_options: dict[str, object],
) -> None:
    """partial register／stack cellをresource pointer chainへ昇格しない。"""

    image, data, candidate, leaf, imports, root = _resource_runtime_fixture(
        **fixture_options
    )

    inventory = export_funnel.collect_opaque_wide_hex_use_evidence(
        image,
        data,
        candidate,
        external_roots=(root,),
        resource_leaf=leaf,
        import_addresses=imports,
    )

    assert inventory is not None
    assert inventory.resource_runtime_source_count == 1
    assert inventory.resource_pointer_size_chain_count == 0
    assert inventory.semantic_transform_chain_count == 0
    assert export_funnel._unique_opaque_source_use(inventory) is False


def test_resource_runtime_merge_preserves_direct_inventory_fields() -> None:
    """direct証拠併存時はruntime欄だけを更新し既存の解析台帳を保持する。"""

    inventory = export_funnel.OpaqueWideHexUseInventory(
        source_roots=(0x401000,),
        raw_reference_count=2,
        source_operand_reference_count=1,
        anchored_source_reference_count=1,
        staging_call_chain_count=1,
        semantic_transform_chain_count=1,
        transform_operation_kinds=("ror", "sub", "xor"),
        reference_set_complete=True,
        reference_set_truncated=True,
        bounded_analysis_complete=False,
        scanned_byte_count=123,
        decoded_literal_reference_count=2,
        scanned_instruction_count=47,
        anchored_window_count=3,
        anchored_scanned_byte_count=96,
        anchored_scanned_instruction_count=12,
        resource_locator_match_count=101,
        resource_handle_chain_count=102,
        resource_pointer_size_chain_count=103,
        resource_runtime_source_count=104,
        resource_runtime_analysis_complete=False,
        resource_runtime_truncated=True,
        resource_runtime_scanned_instruction_count=105,
        root_derived_source_reference_count=6,
        root_address_lineage_analysis_complete=True,
        root_address_lineage_truncated=False,
        root_address_lineage_root_count=7,
        root_address_lineage_function_count=8,
        root_address_lineage_scanned_byte_count=9,
        root_address_lineage_scanned_instruction_count=10,
        reference_scan_mode="raw_unique_local_resynchronization",
        raw_candidate_occurrence_count=11,
        local_literal_instruction_start_count=12,
        local_direct_caller_count=13,
        local_scanned_byte_count=14,
    )
    runtime = export_funnel._ResourceRuntimeInventory(
        chains=(),
        locator_match_count=1,
        handle_chain_count=2,
        pointer_size_chain_count=3,
        source_count=4,
        analysis_complete=True,
        truncated=False,
        scanned_instruction_count=5,
    )

    merged = export_funnel._with_resource_runtime_use(inventory, runtime)

    preserved_fields = (
        "source_roots",
        "raw_reference_count",
        "source_operand_reference_count",
        "anchored_source_reference_count",
        "staging_call_chain_count",
        "semantic_transform_chain_count",
        "transform_operation_kinds",
        "reference_set_complete",
        "reference_set_truncated",
        "bounded_analysis_complete",
        "scanned_byte_count",
        "decoded_literal_reference_count",
        "scanned_instruction_count",
        "anchored_window_count",
        "anchored_scanned_byte_count",
        "anchored_scanned_instruction_count",
        "root_derived_source_reference_count",
        "root_address_lineage_analysis_complete",
        "root_address_lineage_truncated",
        "root_address_lineage_root_count",
        "root_address_lineage_function_count",
        "root_address_lineage_scanned_byte_count",
        "root_address_lineage_scanned_instruction_count",
        "reference_scan_mode",
        "raw_candidate_occurrence_count",
        "local_literal_instruction_start_count",
        "local_direct_caller_count",
        "local_scanned_byte_count",
    )
    assert {name: getattr(merged, name) for name in preserved_fields} == {
        name: getattr(inventory, name) for name in preserved_fields
    }
    assert (
        merged.resource_locator_match_count,
        merged.resource_handle_chain_count,
        merged.resource_pointer_size_chain_count,
        merged.resource_runtime_source_count,
        merged.resource_runtime_analysis_complete,
        merged.resource_runtime_truncated,
        merged.resource_runtime_scanned_instruction_count,
    ) == (1, 2, 3, 4, True, False, 5)


@pytest.mark.parametrize(
    ("fixture_options", "root_is_reachable"),
    (
        ({"locator_name_id": 0x124}, True),
        ({"include_size": False}, True),
        ({}, False),
    ),
)
def test_resource_runtime_path_rejects_wrong_locator_missing_size_or_dead_code(
    fixture_options: dict[str, object],
    root_is_reachable: bool,
) -> None:
    """API名だけ、誤locator、未到達codeをcandidate lineageへ昇格しない。"""

    image, data, candidate, leaf, imports, root = _resource_runtime_fixture(
        **fixture_options
    )
    roots = (root,) if root_is_reachable else (_IMAGE_BASE + 0x1000,)

    inventory = export_funnel.collect_opaque_wide_hex_use_evidence(
        image,
        data,
        candidate,
        external_roots=roots,
        resource_leaf=leaf,
        import_addresses=imports,
    )

    assert inventory is not None
    assert export_funnel._unique_opaque_source_use(inventory) is False
    assert inventory.semantic_transform_chain_count == 0


@pytest.mark.parametrize(
    ("source_encoding", "candidate_offset"),
    (
        ("mov_base_add_rva", 0),
        ("mov_rva_add_base", 0),
        ("section_base_add_offset", 0x40),
        ("section_base_lea_offset", 0x40),
        ("pic_add_offset", 0x40),
        ("known_register_alias", 0x40),
    ),
)
def test_root_derived_candidate_va_reaches_same_path_staging_argument(
    source_encoding: str,
    candidate_offset: int,
) -> None:
    """検証済みroot上のbase＋offsetだけをexact candidate VAへ復元する。"""

    image, data, candidate = _source_use_fixture(
        source_encoding=source_encoding,
        candidate_offset=candidate_offset,
    )

    inventory = export_funnel.collect_opaque_wide_hex_use_evidence(
        image,
        data,
        candidate,
        external_roots=(_IMAGE_BASE + 0x1000,),
    )

    assert inventory is not None
    assert inventory.reference_set_complete is True
    assert inventory.raw_reference_count == 0
    assert inventory.decoded_literal_reference_count == 0
    assert inventory.root_derived_source_reference_count == 1
    assert inventory.source_operand_reference_count == 1
    assert inventory.anchored_source_reference_count == 1
    assert inventory.root_address_lineage_analysis_complete is True
    assert inventory.root_address_lineage_truncated is False
    assert inventory.root_address_lineage_root_count == 1
    assert inventory.root_address_lineage_function_count >= 4
    assert inventory.staging_call_chain_count == 1
    assert inventory.semantic_transform_chain_count == 1
    assert export_funnel._unique_opaque_source_use(inventory) is True

    summary = export_funnel._public_opaque_source_use_summary(inventory)
    assert summary["unique_same_path_transform_chain"] is True
    assert summary["reference_scan"]["exact_candidate_va_operands_only"] is False
    assert summary["reference_scan"]["candidate_rva_used_as_reference"] is False
    lineage = summary["root_address_lineage"]
    assert lineage["derived_source_reference_count"] == 1
    assert lineage["analysis_complete"] is True
    assert lineage["memory_aliases_followed"] is False
    assert lineage["arithmetic_wrap_allowed"] is False
    assert summary["config_parser_proven"] is False
    assert summary["runtime_endpoint_to_connect_proven"] is False
    assert summary["same_socket_send_receive_proven"] is False


@pytest.mark.parametrize(
    "source_encoding",
    (
        "mov_rva",
        "memory_alias",
        "wrapped_rva_then_base",
        "wrapped_sub_candidate",
    ),
)
def test_root_address_lineage_rejects_rva_alias_and_wrap_decoys(
    source_encoding: str,
) -> None:
    """bare RVA、memory alias、32-bit wrapをsource証拠へ昇格しない。"""

    image, data, candidate = _source_use_fixture(
        source_encoding=source_encoding,
    )

    inventory = export_funnel.collect_opaque_wide_hex_use_evidence(
        image,
        data,
        candidate,
        external_roots=(_IMAGE_BASE + 0x1000,),
    )

    assert inventory is not None
    assert inventory.raw_reference_count == 0
    assert inventory.root_derived_source_reference_count == 0
    assert inventory.source_operand_reference_count == 0
    assert inventory.semantic_transform_chain_count == 0
    assert export_funnel._unique_opaque_source_use(inventory) is False


def test_root_address_lineage_rejects_unknown_branch_before_staging() -> None:
    """address完成後でも未知の条件分岐を越えてstagingへ結合しない。"""

    image, data, candidate = _source_use_fixture(
        source_encoding="mov_base_add_rva",
        branch_before_stage=True,
    )

    inventory = export_funnel.collect_opaque_wide_hex_use_evidence(
        image,
        data,
        candidate,
        external_roots=(_IMAGE_BASE + 0x1000,),
    )

    assert inventory is not None
    assert inventory.root_derived_source_reference_count == 1
    assert inventory.anchored_source_reference_count == 1
    assert inventory.semantic_transform_chain_count == 0
    assert export_funnel._unique_opaque_source_use(inventory) is False


def test_root_address_lineage_traverses_branch_target_and_fallthrough() -> None:
    """条件分岐の両edgeが閉じればroot-derived一意性を維持する。"""

    image, data, candidate = _source_use_fixture(
        source_encoding="mov_base_add_rva",
        terminal_root_branch="empty",
    )

    inventory = export_funnel.collect_opaque_wide_hex_use_evidence(
        image,
        data,
        candidate,
        external_roots=(_IMAGE_BASE + 0x1000,),
    )

    assert inventory is not None
    assert inventory.root_address_lineage_analysis_complete is True
    assert inventory.root_address_lineage_function_count >= 6
    assert inventory.root_derived_source_reference_count == 1
    assert export_funnel._unique_opaque_source_use(inventory) is True


def test_root_address_lineage_branch_target_cannot_hide_second_source() -> None:
    """target側だけにある第2sourceも列挙し、一意候補へ誤昇格しない。"""

    image, data, candidate = _source_use_fixture(
        source_encoding="mov_base_add_rva",
        terminal_root_branch="second_source",
    )

    inventory = export_funnel.collect_opaque_wide_hex_use_evidence(
        image,
        data,
        candidate,
        external_roots=(_IMAGE_BASE + 0x1000,),
    )

    assert inventory is not None
    assert inventory.root_address_lineage_analysis_complete is True
    assert inventory.root_derived_source_reference_count == 2
    assert export_funnel._unique_opaque_source_use(inventory) is False


def test_root_address_lineage_unmapped_branch_target_is_incomplete() -> None:
    """片edgeをfile-backed codeとして走査できなければ一意性を閉じない。"""

    image, data, candidate = _source_use_fixture(
        source_encoding="mov_base_add_rva",
        terminal_root_branch="non_file_backed",
    )

    inventory = export_funnel.collect_opaque_wide_hex_use_evidence(
        image,
        data,
        candidate,
        external_roots=(_IMAGE_BASE + 0x1000,),
    )

    assert inventory is not None
    assert inventory.root_derived_source_reference_count == 1
    assert inventory.root_address_lineage_analysis_complete is False
    assert inventory.bounded_analysis_complete is False
    assert export_funnel._unique_opaque_source_use(inventory) is False


@pytest.mark.parametrize(
    "root",
    (
        _IMAGE_BASE + 0x10C0,
        _IMAGE_BASE + 0x5000,
    ),
)
def test_root_address_lineage_rejects_unreachable_or_non_file_backed_root(
    root: int,
) -> None:
    """到達不能codeとvirtual tail rootからraw命令列を拾わない。"""

    image, data, candidate = _source_use_fixture(
        source_encoding="mov_base_add_rva",
    )

    inventory = export_funnel.collect_opaque_wide_hex_use_evidence(
        image,
        data,
        candidate,
        external_roots=(root,),
    )

    assert inventory is not None
    assert inventory.root_derived_source_reference_count == 0
    assert inventory.source_operand_reference_count == 0
    assert inventory.semantic_transform_chain_count == 0
    assert export_funnel._unique_opaque_source_use(inventory) is False
    if root == _IMAGE_BASE + 0x5000:
        assert inventory.root_address_lineage_analysis_complete is False


def test_exact_and_root_derived_candidate_sources_are_not_merged() -> None:
    """exact VA decoyとroot-derived sourceの併存を一意参照に丸めない。"""

    image, data, candidate = _source_use_fixture(
        source_encoding="mov_base_add_rva",
        extra_raw_reference=True,
    )

    inventory = export_funnel.collect_opaque_wide_hex_use_evidence(
        image,
        data,
        candidate,
        external_roots=(_IMAGE_BASE + 0x1000,),
    )

    assert inventory is not None
    assert inventory.raw_reference_count == 1
    assert inventory.root_derived_source_reference_count == 1
    assert inventory.source_operand_reference_count == 2
    assert inventory.semantic_transform_chain_count == 1
    assert export_funnel._unique_opaque_source_use(inventory) is False


def test_root_derived_reference_cap_is_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """derived参照も既存の参照総数上限に含める。"""

    image, data, candidate = _source_use_fixture(
        source_encoding="mov_base_add_rva",
    )
    monkeypatch.setattr(export_funnel, "MAX_OPAQUE_WIDE_HEX_REFERENCE_MATCHES", 0)

    inventory = export_funnel.collect_opaque_wide_hex_use_evidence(
        image,
        data,
        candidate,
        external_roots=(_IMAGE_BASE + 0x1000,),
    )

    assert inventory is not None
    assert inventory.reference_set_complete is False
    assert inventory.reference_set_truncated is True
    assert inventory.semantic_transform_chain_count == 0
    assert export_funnel._unique_opaque_source_use(inventory) is False


@pytest.mark.parametrize("non_file_backed_root", (False, True))
def test_exact_source_rejects_incomplete_root_lineage(
    monkeypatch: pytest.MonkeyPatch,
    non_file_backed_root: bool,
) -> None:
    """exact参照と併存し得る不完全なroot走査を一意集合とみなさない。"""

    image, data, candidate = _source_use_fixture()
    if non_file_backed_root:
        root = _IMAGE_BASE + 0x5000
    else:
        root = _IMAGE_BASE + 0x1000
        monkeypatch.setattr(
            export_funnel,
            "MAX_OPAQUE_WIDE_HEX_ROOT_LINEAGE_FUNCTIONS",
            0,
        )

    inventory = export_funnel.collect_opaque_wide_hex_use_evidence(
        image,
        data,
        candidate,
        external_roots=(root,),
    )

    assert inventory is not None
    assert inventory.raw_reference_count == 1
    assert inventory.source_operand_reference_count == 1
    assert inventory.root_address_lineage_analysis_complete is False
    assert inventory.bounded_analysis_complete is False
    assert export_funnel._unique_opaque_source_use(inventory) is False


@pytest.mark.parametrize("source_encoding", ("push_imm", "mov_reg", "lea_reg"))
def test_decode_incomplete_uses_unique_raw_local_reference_fallback(
    source_encoding: str,
) -> None:
    """先行invalid bytes後も一意raw operandとcaller pathだけを局所再同期する。"""

    image, data, candidate = _source_use_fixture(
        source_encoding=source_encoding,
        invalid_prefix_before_entry=True,
    )

    inventory = export_funnel.collect_opaque_wide_hex_use_evidence(
        image,
        data,
        candidate,
    )

    assert inventory is not None
    assert inventory.reference_set_complete is True
    assert inventory.reference_set_truncated is False
    assert inventory.reference_scan_mode == "raw_unique_local_resynchronization"
    assert inventory.raw_candidate_occurrence_count == 1
    assert inventory.local_literal_instruction_start_count == 1
    assert inventory.local_direct_caller_count == 1
    assert inventory.local_scanned_byte_count > 0
    assert inventory.scanned_byte_count > 0x400
    assert inventory.raw_reference_count == 1
    assert inventory.source_operand_reference_count == 1
    assert inventory.anchored_source_reference_count == 1
    assert inventory.semantic_transform_chain_count == 1
    assert export_funnel._unique_opaque_source_use(inventory) is True

    summary = export_funnel._public_opaque_source_use_summary(inventory)
    reference = summary["reference_scan"]
    assert reference["mode"] == "raw_unique_local_resynchronization"
    assert reference["raw_candidate_va_occurrence_count"] == 1
    assert reference["local_literal_instruction_start_count"] == 1
    assert reference["local_direct_caller_count"] == 1
    assert reference["local_scanned_bytes"] == (
        inventory.local_scanned_byte_count
    )
    assert reference["arbitrary_four_byte_matches_used_as_evidence"] is False
    assert summary["config_parser_proven"] is False
    assert summary["runtime_endpoint_to_connect_proven"] is False
    assert summary["same_socket_send_receive_proven"] is False


@pytest.mark.parametrize(
    "fixture_options",
    (
        {"extra_raw_reference": True},
        {
            "source_encoding": "mov_rva",
            "arbitrary_four_byte_decoy": True,
        },
        {"source_encoding": "overlap_mov_prefix"},
        {"dead_local_caller": True},
        {"extra_local_caller": True},
        {"branch_before_stage": True},
    ),
)
def test_local_reference_fallback_rejects_decoys_and_ambiguous_paths(
    fixture_options: dict[str, object],
) -> None:
    """raw重複／非operand／overlap／dead caller／分岐を拒否する。"""

    image, data, candidate = _source_use_fixture(
        invalid_prefix_before_entry=True,
        **fixture_options,
    )

    inventory = export_funnel.collect_opaque_wide_hex_use_evidence(
        image,
        data,
        candidate,
    )

    assert inventory is not None
    assert inventory.reference_scan_mode == "raw_unique_local_resynchronization"
    assert export_funnel._unique_opaque_source_use(inventory) is False
    assert inventory.semantic_transform_chain_count == 0


def test_local_reference_fallback_rejects_invalid_source_path_decode() -> None:
    """唯一operand後の局所decode失敗をsource chainへ使用しない。"""

    image, data, candidate = _source_use_fixture(
        invalid_prefix_before_entry=True,
    )
    mutable = bytearray(data)
    occurrence = mutable.find(struct.pack("<I", candidate.address))
    assert occurrence >= 0
    mutable[occurrence + 4 : occurrence + 6] = b"\x0f\x04"

    inventory = export_funnel.collect_opaque_wide_hex_use_evidence(
        image,
        bytes(mutable),
        candidate,
    )

    assert inventory is not None
    assert inventory.reference_scan_mode == "raw_unique_local_resynchronization"
    assert inventory.raw_candidate_occurrence_count == 1
    assert inventory.local_direct_caller_count == 0
    assert inventory.source_operand_reference_count == 0
    assert export_funnel._unique_opaque_source_use(inventory) is False


@pytest.mark.parametrize(
    "limit_name",
    (
        "MAX_OPAQUE_WIDE_HEX_LOCAL_CALLER_CANDIDATES",
        "MAX_OPAQUE_WIDE_HEX_LOCAL_SCAN_BYTES",
    ),
)
def test_local_reference_fallback_budget_is_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
    limit_name: str,
) -> None:
    """local caller候補上限で部分的な再同期結果を採用しない。"""

    image, data, candidate = _source_use_fixture(
        invalid_prefix_before_entry=True,
    )
    monkeypatch.setattr(export_funnel, limit_name, 0)

    inventory = export_funnel.collect_opaque_wide_hex_use_evidence(
        image,
        data,
        candidate,
    )

    assert inventory is not None
    assert inventory.reference_set_complete is False
    assert inventory.reference_set_truncated is True
    assert inventory.reference_scan_mode == "raw_unique_local_resynchronization"
    if limit_name == "MAX_OPAQUE_WIDE_HEX_LOCAL_SCAN_BYTES":
        assert inventory.local_scanned_byte_count > 0
        assert inventory.scanned_byte_count > 0x400
    assert inventory.semantic_transform_chain_count == 0
    assert export_funnel._unique_opaque_source_use(inventory) is False


@pytest.mark.parametrize("source_encoding", ("mov_reg", "lea_reg"))
def test_opaque_wide_hex_register_source_is_instruction_bounded_and_anchored(
    source_encoding: str,
) -> None:
    """即値由来registerは同一anchored block内のpushまでだけ追跡する。"""

    image, data, candidate = _source_use_fixture(
        source_encoding=source_encoding,
    )

    inventory = export_funnel.collect_opaque_wide_hex_use_evidence(
        image,
        data,
        candidate,
    )

    assert inventory is not None
    assert inventory.reference_set_complete is True
    assert inventory.reference_set_truncated is False
    assert inventory.raw_reference_count == 1
    assert inventory.decoded_literal_reference_count == 1
    assert inventory.source_operand_reference_count == 1
    assert inventory.anchored_source_reference_count == 1
    assert inventory.semantic_transform_chain_count == 1
    assert inventory.scanned_instruction_count > 0
    assert inventory.anchored_window_count == 1
    assert export_funnel._unique_opaque_source_use(inventory) is True
    summary = export_funnel._public_opaque_source_use_summary(inventory)
    assert summary["reference_scan"]["mode"] == (
        "capstone_x86_instruction_boundaries"
    )
    assert summary["reference_scan"]["exact_candidate_va_operands_only"] is True
    assert (
        summary["reference_scan"]["arbitrary_four_byte_matches_used_as_evidence"]
        is False
    )
    assert summary["reference_scan"]["candidate_rva_used_as_reference"] is False


def test_opaque_wide_hex_memory_operand_four_byte_decoy_is_not_reference() -> None:
    """同じ4 bytesを含むmemory readはpointer定数生成として数えない。"""

    image, data, candidate = _source_use_fixture(
        arbitrary_four_byte_decoy=True,
    )
    assert data.count(struct.pack("<I", candidate.address)) == 2

    inventory = export_funnel.collect_opaque_wide_hex_use_evidence(
        image,
        data,
        candidate,
    )

    assert inventory is not None
    assert inventory.raw_reference_count == 1
    assert inventory.decoded_literal_reference_count == 1
    assert inventory.source_operand_reference_count == 1
    assert inventory.semantic_transform_chain_count == 1
    assert export_funnel._unique_opaque_source_use(inventory) is True


def test_opaque_wide_hex_rva_register_decoy_is_not_candidate_va() -> None:
    """candidate RVAだけを入れたregister pushはVA source証拠へ昇格しない。"""

    image, data, candidate = _source_use_fixture(source_encoding="mov_rva")

    inventory = export_funnel.collect_opaque_wide_hex_use_evidence(
        image,
        data,
        candidate,
    )

    assert inventory is not None
    assert inventory.raw_reference_count == 0
    assert inventory.decoded_literal_reference_count == 0
    assert inventory.source_operand_reference_count == 0
    assert inventory.anchored_source_reference_count == 0
    assert inventory.semantic_transform_chain_count == 0
    assert export_funnel._unique_opaque_source_use(inventory) is False


def test_opaque_wide_hex_instruction_scan_cap_is_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """命令数上限で打ち切った参照集合をchain証拠へ使用しない。"""

    image, data, candidate = _source_use_fixture(source_encoding="mov_reg")
    monkeypatch.setattr(
        export_funnel,
        "MAX_OPAQUE_WIDE_HEX_REFERENCE_SCAN_INSTRUCTIONS",
        1,
    )

    inventory = export_funnel.collect_opaque_wide_hex_use_evidence(
        image,
        data,
        candidate,
    )

    assert inventory is not None
    assert inventory.reference_set_complete is False
    assert inventory.reference_set_truncated is True
    assert inventory.bounded_analysis_complete is False
    assert inventory.scanned_instruction_count == 1
    assert inventory.source_operand_reference_count == 0
    assert inventory.semantic_transform_chain_count == 0
    assert export_funnel._unique_opaque_source_use(inventory) is False


def test_opaque_wide_hex_instruction_scan_byte_cap_is_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """命令境界を途中までしか覆えないbyte上限では参照集合を採用しない。"""

    image, data, candidate = _source_use_fixture(source_encoding="lea_reg")
    monkeypatch.setattr(
        export_funnel,
        "MAX_OPAQUE_WIDE_HEX_REFERENCE_SCAN_BYTES",
        4,
    )

    inventory = export_funnel.collect_opaque_wide_hex_use_evidence(
        image,
        data,
        candidate,
    )

    assert inventory is not None
    assert inventory.reference_set_complete is False
    assert inventory.reference_set_truncated is True
    assert inventory.scanned_byte_count == 0
    assert inventory.source_operand_reference_count == 0
    assert inventory.semantic_transform_chain_count == 0
    assert export_funnel._unique_opaque_source_use(inventory) is False


def test_opaque_wide_hex_anchored_window_cap_is_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """anchor解析総数上限を超えた場合は見えているchainも採用しない。"""

    image, data, candidate = _source_use_fixture(source_encoding="mov_reg")
    monkeypatch.setattr(
        export_funnel,
        "MAX_OPAQUE_WIDE_HEX_ANCHORED_WINDOWS",
        0,
    )

    inventory = export_funnel.collect_opaque_wide_hex_use_evidence(
        image,
        data,
        candidate,
    )

    assert inventory is not None
    assert inventory.reference_set_complete is False
    assert inventory.reference_set_truncated is True
    assert inventory.anchored_window_count == 0
    assert inventory.semantic_transform_chain_count == 0
    assert export_funnel._unique_opaque_source_use(inventory) is False


@pytest.mark.parametrize(
    "fixture_options",
    (
        {"branch_before_stage": True},
        {"cleanup_size": 0x0C},
        {"split_transform_path": True},
        {"overwrite_destination": True},
        {"destination_characteristics": _EXECUTABLE_DATA},
    ),
)
def test_opaque_wide_hex_use_does_not_merge_or_relax_required_evidence(
    fixture_options: dict[str, object],
) -> None:
    """別branch、stack不一致、分割semantics、unsafe destinationを拒否する。"""

    image, data, candidate = _source_use_fixture(**fixture_options)

    inventory = export_funnel.collect_opaque_wide_hex_use_evidence(
        image,
        data,
        candidate,
    )

    assert inventory is not None
    assert inventory.semantic_transform_chain_count == 0
    assert export_funnel._unique_opaque_source_use(inventory) is False
    summary = export_funnel._public_opaque_source_use_summary(inventory)
    assert summary["unique_same_path_transform_chain"] is False
    assert summary["transform_reads_candidate_or_staged_object_byte"] is False
    assert summary["connected_in_bounds_destination_byte_store"] is False
    assert not any(summary["byte_transform_operations"].values())


def test_opaque_wide_hex_use_reference_cap_is_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """candidate address出現数の上限超過時は部分的なchainを採用しない。"""

    image, data, candidate = _source_use_fixture(extra_raw_reference=True)
    monkeypatch.setattr(export_funnel, "MAX_OPAQUE_WIDE_HEX_REFERENCE_MATCHES", 1)

    inventory = export_funnel.collect_opaque_wide_hex_use_evidence(
        image,
        data,
        candidate,
    )

    assert inventory is not None
    assert inventory.reference_set_complete is False
    assert inventory.reference_set_truncated is True
    assert inventory.source_roots == ()
    assert inventory.staging_call_chain_count == 0
    assert inventory.semantic_transform_chain_count == 0
    assert export_funnel._unique_opaque_source_use(inventory) is False


def test_opaque_wide_hex_literal_without_anchored_source_push_is_rejected() -> None:
    """同じaddress literalでもmov即値だけならsource引数と解釈しない。"""

    image, data, candidate = _source_use_fixture()
    mutable = bytearray(data)
    source = mutable.find(b"\x68" + struct.pack("<I", candidate.address))
    assert source >= 0
    mutable[source] = 0xB8

    inventory = export_funnel.collect_opaque_wide_hex_use_evidence(
        image,
        bytes(mutable),
        candidate,
    )

    assert inventory is not None
    assert inventory.raw_reference_count == 1
    assert inventory.source_operand_reference_count == 0
    assert inventory.anchored_source_reference_count == 0
    assert inventory.semantic_transform_chain_count == 0
    assert export_funnel._unique_opaque_source_use(inventory) is False


def test_opaque_wide_hex_transform_instruction_cap_is_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """変換命令window上限では見えている一部opcodeをchain証拠にしない。"""

    image, data, candidate = _source_use_fixture()
    monkeypatch.setattr(export_funnel, "MAX_OPAQUE_WIDE_HEX_TRANSFORM_INSTRUCTIONS", 3)

    inventory = export_funnel.collect_opaque_wide_hex_use_evidence(
        image,
        data,
        candidate,
    )

    assert inventory is not None
    assert inventory.bounded_analysis_complete is False
    assert inventory.staging_call_chain_count == 1
    assert inventory.semantic_transform_chain_count == 0
    assert inventory.transform_operation_kinds == ()
    assert export_funnel._unique_opaque_source_use(inventory) is False


def test_export_funnel_publishes_candidate_boundary_without_raw_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """route出力は候補の存在だけを示し、strict family/configへ上げない。"""

    material = bytes(range(256))
    image, data = _image_for(_wide_hex(material, odd=True))
    data = b"MZ" + data[2:]
    image.FILE_HEADER = SimpleNamespace(Machine=0x14C, Characteristics=0x2000)
    roots = export_funnel.ExternalCodeRoots(
        roots=(0x401000,),
        export_roots=(0x401000,),
        tls_roots=(),
        export_count=8,
        export_target_count=1,
        export_funnel=True,
        tls_directory_present=True,
    )
    resources = (
        export_funnel._ResourceLeaf(0x402000, 0x5000, 7.5, True),
        export_funnel._ResourceLeaf(0x408000, 0x6000, 7.6, True),
    )
    resource_groups = {name: True for name in export_funnel._RESOURCE_GROUPS}
    network_groups = {name: True for name in export_funnel._NETWORK_GROUPS}
    called_names = {
        next(iter(names))
        for names in (
            *export_funnel._RESOURCE_GROUPS.values(),
            *export_funnel._NETWORK_GROUPS.values(),
        )
    }
    flow = {
        "status": "incomplete_terminal_network_lineage",
        "analysis_complete": False,
        "terminal_network_lineage_proven": False,
        "proof": {"config_source_to_connect": False},
        "missing_proof_codes": ["native_flow_config_to_connect_unproven"],
        "coverage": {"referenced_source_count": 0, "source_count": 1},
    }
    use_inventory = export_funnel.OpaqueWideHexUseInventory(
        source_roots=(0x401234,),
        raw_reference_count=1,
        source_operand_reference_count=1,
        anchored_source_reference_count=1,
        staging_call_chain_count=1,
        semantic_transform_chain_count=1,
        transform_operation_kinds=("rol", "sub", "xor"),
        reference_set_complete=True,
        reference_set_truncated=False,
        bounded_analysis_complete=True,
        scanned_byte_count=0x100,
        root_address_lineage_analysis_complete=True,
    )
    analyzed_roots: list[tuple[int, ...]] = []

    def fake_flow(*_args: object, **kwargs: object) -> dict[str, object]:
        analyzed_roots.append(tuple(kwargs["roots"]))
        return flow

    monkeypatch.setattr(export_funnel.pefile, "PE", lambda **_kwargs: image)
    monkeypatch.setattr(export_funnel, "collect_external_code_roots", lambda *_: roots)
    monkeypatch.setattr(export_funnel, "_resource_leaves", lambda *_: resources)
    monkeypatch.setattr(
        export_funnel,
        "_imports",
        lambda *_: ({0x410000: "socket"}, resource_groups, network_groups),
    )
    monkeypatch.setattr(export_funnel, "_iat_calls", lambda *_: called_names)
    monkeypatch.setattr(export_funnel, "analyze_x86_pe_dataflow", fake_flow)
    monkeypatch.setattr(
        export_funnel,
        "collect_opaque_wide_hex_use_evidence",
        lambda *_args, **_kwargs: use_inventory,
    )

    result = export_funnel.probe_export_funnel_route(data)
    serialized = json.dumps(result, sort_keys=True)

    assert result["matched"] is True
    assert result["encoded_config_candidate_observed"] is True
    assert result["decoded_config_recovered"] is False
    assert result["candidate_config_recovered"] is False
    assert result["supports_family_attribution"] is False
    assert result["terminal_family_confirmed"] is False
    assert result["terminal_network_lineage_proven"] is False
    assert result["recovery_status"] == "opaque_candidate_transform_path_only"
    assert analyzed_roots == [(0x401000,), (0x401234,)]
    candidate = result["evidence"]["opaque_wide_hex_candidate"]
    assert candidate["unique_candidate"] is True
    assert candidate["raw_values_included"] is False
    assert candidate["raw_addresses_included"] is False
    source_use = result["evidence"]["opaque_wide_hex_source_use"]
    assert source_use["unique_same_path_transform_chain"] is True
    assert source_use["concrete_decoder_recovered"] is False
    assert source_use["config_parser_proven"] is False
    assert source_use["runtime_endpoint_to_connect_proven"] is False
    assert source_use["same_socket_send_receive_proven"] is False
    assert source_use["raw_values_included"] is False
    assert source_use["raw_addresses_included"] is False
    assert material.hex().upper() not in serialized
