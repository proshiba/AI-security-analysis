"""Go包装の数学復元を、実行しない無害な合成PEで検証する。"""

from __future__ import annotations

import hashlib
import json
import struct
import time

import pytest
from unpackers import go_decoder_shape
from unpackers import go_embedded_pe as recovery


@pytest.fixture(autouse=True)
def reviewed_harmless_shape(monkeypatch: pytest.MonkeyPatch) -> None:
    """試験だけで、無害fixtureの固定decoder本文をレビュー済み登録する。"""
    import pefile

    image, _ = _fixture()
    pe = pefile.PE(data=image, fast_load=True)
    functions = recovery._functions(image, pe, time.monotonic() + 10, time.monotonic)
    decoder = next(f for f in functions if f.name == "main.syntheticDecode")
    instructions = recovery._disassemble(image, decoder, time.monotonic() + 10, time.monotonic)
    shape = go_decoder_shape.function_shape(
        [
            {
                "va": i.address,
                "bytes": image[
                    decoder.offset + i.address - decoder.va : decoder.offset + i.address - decoder.va + i.size
                ].hex(),
                "mnemonic": i.mnemonic,
                "operands": i.operands,
            }
            for i in instructions
        ],
        {"va": decoder.va, "size": decoder.size},
        [{"va": f.va, "size": f.size, "name": f.name} for f in functions],
    )
    monkeypatch.setattr(go_decoder_shape, "REVIEWED_SHAPES", [{**shape, "profile_id": "reviewed-harmless-test-shape"}])


# レビュー済み演算だけの命令列。検体、実API呼出し、通信、process生成を含まない。
MATH_BLOCKS = (
    (
        "48b8d504e3adec73484d4989d048f7e948c1fa044989c948c1f93f4829ca486bca35"
        "4c89ca4929c94429ce4889d948c1e3044801cb29de4088340f"
    ),
    (
        "48b8e9a8c017573fe8a84989d048f7e94801ca48c1fa064989c948c1f93f4829ca"
        "486bca614c89ca4929c94131f14889d948c1e3054829cb4431cb881c0f"
    ),
    "0fb63c1040883c1a4088340248ffc348ffc8",
    "0fb65c0201881c1040887402014883c202",
    "0fb634034889cf48c1ff0829fe488d3c5b29fe40883418",
    "0fb6340331ce488d3c9b31f740883c18",
)


def _minimal_pe(*, padding: int = 6, parent: bool = False) -> bytes:
    count = 2 if parent else 1
    image = bytearray(0x3200 if parent else 0x400 + padding)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x80)
    image[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", image, 0x84, 0x8664, count, 0, 0, 0, 0xF0, 0x22)
    optional = 0x98
    struct.pack_into("<H", image, optional, 0x20B)
    struct.pack_into("<I", image, optional + 16, 0x1000)
    struct.pack_into("<I", image, optional + 20, 0x1000)
    struct.pack_into("<Q", image, optional + 24, 0x400000)
    struct.pack_into("<II", image, optional + 32, 0x1000, 0x200)
    struct.pack_into("<HH", image, optional + 40, 6, 0)
    struct.pack_into("<II", image, optional + 56, 0x6000 if parent else 0x2000, 0x200)
    struct.pack_into("<H", image, optional + 68, 3)
    struct.pack_into("<I", image, optional + 108, 16)
    section = optional + 0xF0
    image[section : section + 8] = b".text\0\0\0"
    raw_size = 0x1000 if parent else 0x200
    struct.pack_into("<IIII", image, section + 8, raw_size, 0x1000, raw_size, 0x200)
    struct.pack_into("<I", image, section + 36, 0x60000020)
    image[0x200 : 0x200 + raw_size] = b"\xcc" * raw_size
    image[0x200] = 0xC3
    if parent:
        section += 40
        image[section : section + 8] = b".rdata\0\0"
        struct.pack_into("<IIII", image, section + 8, 0x2000, 0x3000, 0x2000, 0x1200)
        struct.pack_into("<I", image, section + 36, 0x40000040)
    return bytes(image)


def _encode(payload: bytes, key: int) -> bytes:
    data = bytearray(payload)
    for index, value in enumerate(data):
        data[index] = ((value ^ key ^ (5 * index)) + (key >> 8) + 3 * index) & 255
    for index in range(0, len(data) - 1, 2):
        data[index], data[index + 1] = data[index + 1], data[index]
    data.reverse()
    for index, value in enumerate(data):
        data[index] = (
            ((value + key % 53 + 17 * index) & 255) if index % 2 == 0 else ((value ^ (key % 97) ^ (31 * index)) & 255)
        )
    return bytes(data)


def _fixture(*, key: int = 123456, prefix_size: int = 6, payload: bytes | None = None) -> tuple[bytes, bytes]:
    if payload is None:
        payload = _minimal_pe(padding=prefix_size)
    encoded = _encode(payload, key)
    assert (len(encoded) - prefix_size) % 8 == 0
    image = bytearray(_minimal_pe(parent=True))
    math = b"".join(bytes.fromhex(block) for block in MATH_BLOCKS) + b"\xc3"
    main = bytearray()
    literal = (encoded[:prefix_size] + bytes(16))[:16]
    main.extend(b"\x48\xb8" + literal[:8])
    main.extend(b"\x48\x89\x84\x24" + struct.pack("<I", 0x100))
    if prefix_size > 8:
        main.extend(b"\x48\xba" + literal[8:16])
        main.extend(b"\x48\x89\x94\x24" + struct.pack("<I", 0x108))
    main.extend(b"\x48\x8d\xbc\x24" + struct.pack("<I", 0x100 + prefix_size))
    # 明示されたRIP参照だけをparseし、CPU命令は実行しない。
    next_rip = 0x401000 + len(main) + 7
    main.extend(b"\x48\x8d\x35" + struct.pack("<i", 0x403400 - next_rip))
    main.extend(b"\xb9" + struct.pack("<I", (len(encoded) - prefix_size) // 8))
    main.extend(b"\xf3\x48\xa5")
    main.extend(b"\x48\x8d\x84\x24" + struct.pack("<I", 0x100))
    main.extend(b"\xbb" + struct.pack("<I", len(encoded)))
    main.extend(b"\xbf" + struct.pack("<I", key))
    next_rip = 0x401000 + len(main) + 5
    main.extend(b"\xe8" + struct.pack("<i", 0x401200 - next_rip))
    main.extend(b"\xc3")
    image[0x200 : 0x200 + len(main)] = main
    image[0x400 : 0x400 + len(math)] = math
    table = 0x1200
    image[table : table + 8] = recovery.PCLNTAB_MAGIC
    struct.pack_into("<8Q", image, table + 8, 2, 1, 0x401000, 72, 128, 128, 128, 144)
    names = b"main.main\0main.syntheticDecode\0"
    image[table + 72 : table + 72 + len(names)] = names
    struct.pack_into("<6I", image, table + 144, 0, 24, 0x200, 32, 0x200 + len(math), 0)
    struct.pack_into("<IiIi", image, table + 168, 0, 0, 0x200, 10)
    image[0x1400 : 0x1400 + len(recovery.BUILDINFO_MAGIC)] = recovery.BUILDINFO_MAGIC
    image[0x140E:0x1410] = bytes([8, 2])
    image[0x1420:0x142A] = b"\x08go1.21.9\x00"
    image[0x1600 : 0x1600 + len(encoded) - prefix_size] = encoded[prefix_size:]
    return bytes(image), payload


@pytest.mark.parametrize("key", [0, 1, 255, 123456, 0x1234567, 0x7FFFFFFF])
@pytest.mark.parametrize("prefix_size", [1, 2, 5, 6, 10, 14, 15, 16])
def test_recovers_synthetic_payload_without_sha_or_key_special_case(key: int, prefix_size: int) -> None:
    image, payload = _fixture(key=key, prefix_size=prefix_size)
    report, artifacts = recovery.recover_go_embedded_pe(image)
    assert report["status"] == "recovered", report
    assert artifacts == [("go-five-stage-decoded-pe", payload)]
    assert report["parent_sha256"] == hashlib.sha256(image).hexdigest()
    assert report["recovered_sha256"] == hashlib.sha256(payload).hexdigest()
    assert len(report["math_evidence_rvas"]) == 6
    assert report["sample_executed"] is False
    assert report["instruction_emulation_performed"] is False
    assert report["network_contacted"] is False
    assert report["family_attribution_allowed"] is False
    assert report["c2_confirmation_allowed"] is False
    assert report["terminal_promotion_eligible"] is False
    assert "prefix" not in report and "key" not in report
    assert "syntheticDecode" not in json.dumps(report)


def test_does_not_recover_regular_pe_or_non_pe() -> None:
    for data in (b"hello", _minimal_pe()):
        report, artifacts = recovery.recover_go_embedded_pe(data)
        assert report["status"] == "not_candidate"
        assert not artifacts


def test_regular_go_without_explicit_decoder_is_not_promoted() -> None:
    image, _ = _fixture()
    changed = bytearray(image)
    changed[0x200:0x400] = b"\xc3" + b"\xcc" * 511
    report, artifacts = recovery.recover_go_embedded_pe(bytes(changed))
    assert report["status"] == "not_candidate"
    assert report["copy_candidate_count"] == 0
    assert not artifacts


@pytest.mark.parametrize(
    "needle,replacement",
    [("48c1e304", "48c1e303"), ("486bca35", "486bca34"), ("48c1ff08", "48c1ff09"), ("488d3c9b", "488d3c5b")],
)
def test_math_mutation_is_rejected(needle: str, replacement: str) -> None:
    image, _ = _fixture()
    mutated = image.replace(bytes.fromhex(needle), bytes.fromhex(replacement), 1)
    report, artifacts = recovery.recover_go_embedded_pe(mutated)
    assert report["status"] == "rejected"
    assert report["reason"] == "decoder_profile_mismatch"
    assert not artifacts


def test_invalid_decoded_pe_is_rejected() -> None:
    image, _ = _fixture(payload=bytes(1030))
    report, artifacts = recovery.recover_go_embedded_pe(image)
    assert report["reason"] == "decoded_pe_structure_invalid"
    assert not artifacts


def test_decoded_entry_must_be_executable() -> None:
    payload = bytearray(_minimal_pe())
    struct.pack_into("<I", payload, 0x98 + 0xF0 + 36, 0x40000040)
    image, _ = _fixture(payload=bytes(payload))
    report, artifacts = recovery.recover_go_embedded_pe(image)
    assert report["reason"] == "decoded_pe_entry_not_executable"
    assert not artifacts


def test_copy_cannot_escape_file_backed_section() -> None:
    image, _ = _fixture()
    changed = bytearray(image)
    offset = changed.index(b"\x48\x8d\x35", 0x200, 0x400)
    struct.pack_into("<i", changed, offset + 3, 0x7FFFFFFF)
    report, artifacts = recovery.recover_go_embedded_pe(bytes(changed))
    assert report["reason"] == "unmapped_or_ambiguous_range"
    assert not artifacts


def test_corrupt_function_record_is_rejected() -> None:
    image, _ = _fixture()
    changed = bytearray(image)
    struct.pack_into("<I", changed, 0x1200 + 168, 1)
    report, artifacts = recovery.recover_go_embedded_pe(bytes(changed))
    assert report["reason"] == "pclntab_missing_or_ambiguous"
    assert not artifacts


def test_function_count_has_hard_limit() -> None:
    image, _ = _fixture()
    changed = bytearray(image)
    struct.pack_into("<Q", changed, 0x1200 + 8, recovery.MAX_FUNCTIONS + 1)
    report, artifacts = recovery.recover_go_embedded_pe(bytes(changed))
    assert report["reason"] == "function_count_limit"
    assert not artifacts


def test_input_and_output_bounds_are_enforced(monkeypatch: pytest.MonkeyPatch) -> None:
    image, _ = _fixture()
    monkeypatch.setattr(recovery, "MAX_INPUT_BYTES", len(image) - 1)
    report, artifacts = recovery.recover_go_embedded_pe(image)
    assert report["status"] == "input_limit_exceeded" and not artifacts
    monkeypatch.setattr(recovery, "MAX_INPUT_BYTES", len(image))
    monkeypatch.setattr(recovery, "MAX_OUTPUT_BYTES", 1000)
    report, artifacts = recovery.recover_go_embedded_pe(image)
    assert report["reason"] == "output_size_limit" and not artifacts


def test_elapsed_time_is_enforced_during_table_parse() -> None:
    image, _ = _fixture()
    calls = iter([0.0, 0.0, 11.0, 11.0])
    report, artifacts = recovery.recover_go_embedded_pe(image, clock=lambda: next(calls))
    assert report["reason"] == "elapsed_time_limit"
    assert not artifacts


def test_function_disassembly_bound_is_enforced(monkeypatch: pytest.MonkeyPatch) -> None:
    image, _ = _fixture()
    monkeypatch.setattr(recovery, "MAX_FUNCTION_BYTES", 511)
    report, artifacts = recovery.recover_go_embedded_pe(image)
    assert report["reason"] == "function_byte_limit"
    assert not artifacts


def test_duplicate_valid_function_tables_are_rejected() -> None:
    image, _ = _fixture()
    changed = bytearray(image)
    changed[0x2000:0x20C0] = image[0x1200:0x12C0]
    report, artifacts = recovery.recover_go_embedded_pe(bytes(changed))
    assert report["reason"] == "pclntab_missing_or_ambiguous"
    assert not artifacts


def test_pclntab_candidate_count_has_hard_limit() -> None:
    image, _ = _fixture()
    changed = image + recovery.PCLNTAB_MAGIC * recovery.MAX_TABLE_CANDIDATES
    report, artifacts = recovery.recover_go_embedded_pe(changed)
    assert report["reason"] == "pclntab_candidate_limit"
    assert not artifacts


def test_ambiguous_copy_calls_are_rejected() -> None:
    image, _ = _fixture()
    changed = bytearray(image)
    calls = changed.index(b"\xe8", 0x200, 0x280)
    body = bytearray(changed[0x200 : calls + 5])
    lea = body.index(b"\x48\x8d\x35")
    displacement = struct.unpack_from("<i", body, lea + 3)[0]
    struct.pack_into("<i", body, lea + 3, displacement - 0x100)
    struct.pack_into("<i", body, len(body) - 4, struct.unpack_from("<i", body, len(body) - 4)[0] - 0x100)
    changed[0x300 : 0x300 + len(body)] = body
    report, artifacts = recovery.recover_go_embedded_pe(bytes(changed))
    assert report["reason"] == "ambiguous_copy_candidates"
    assert not artifacts


def test_byte_decoder_time_budget_is_enforced() -> None:
    with pytest.raises(recovery.GoRecoveryError, match="elapsed_time_limit"):
        recovery._decode(bytes(10000), 123, 1.0, lambda: 2.0)


def test_large_regular_pe_is_not_a_go_budget_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    data = _minimal_pe()
    monkeypatch.setattr(recovery, "MAX_INPUT_BYTES", 1000)
    report, artifacts = recovery.recover_go_embedded_pe(data)
    assert report["status"] == "not_candidate"
    assert not artifacts


def test_register_width_mutation_is_not_accepted() -> None:
    lines = "\n".join(
        [
            recovery._EVEN_BLOCKS[0],
            recovery._ODD_BLOCKS[0],
            recovery._REVERSE_BLOCK,
            recovery._PAIR_BLOCK,
            recovery._SUBTRACT_BLOCK,
            recovery._XOR_BLOCKS[0],
        ]
    )
    lines = lines.replace("sub esi, r9d", "sub rsi, r9", 1)
    instructions = [
        recovery._Instruction(n, 1, line.split(" ", 1)[0], line.split(" ", 1)[1])
        for n, line in enumerate(lines.splitlines())
    ]
    with pytest.raises(recovery.GoRecoveryError, match="decoder_profile_mismatch"):
        recovery._math_profile(instructions, time.monotonic() + 10, time.monotonic)


def test_all_reviewed_register_allocations_have_same_profile() -> None:
    for even, odd in zip(recovery._EVEN_BLOCKS, recovery._ODD_BLOCKS):
        for xor in recovery._XOR_BLOCKS:
            text = (
                f"{even}\n{odd}\n{recovery._REVERSE_BLOCK}\n{recovery._PAIR_BLOCK}\n{recovery._SUBTRACT_BLOCK}\n{xor}"
            )
            instructions = [
                recovery._Instruction(n, 1, line.split(" ", 1)[0], line.split(" ", 1)[1])
                for n, line in enumerate(text.splitlines())
            ]
            evidence = recovery._math_profile(instructions, time.monotonic() + 10, time.monotonic)
            assert len(evidence) == 6


def test_static_pipeline_uses_go_recovery() -> None:
    from unpackers.static_unpacker import unpack_bytes

    image, payload = _fixture()
    report, artifacts = unpack_bytes(image, name="harmless-fixture.bin")
    assert report["go_embedded_pe"]["status"] == "recovered"
    assert ("go-five-stage-decoded-pe", payload) in artifacts
    assert report["executed"] is False and report["network_contacted"] is False


def test_unknown_full_decoder_body_rejects_valid_pe(monkeypatch: pytest.MonkeyPatch) -> None:
    image, _ = _fixture()
    monkeypatch.setattr(go_decoder_shape, "REVIEWED_SHAPES", [])
    report, artifacts = recovery.recover_go_embedded_pe(image)
    assert report["reason"] == "unreviewed_or_ambiguous_decoder_shape"
    assert not artifacts


@pytest.mark.parametrize("mutation", [b"\x90\x90", b"\xeb\x7f", b"\x30\x07"])
def test_added_opcode_or_math_skip_branch_is_rejected(mutation: bytes) -> None:
    image, _ = _fixture()
    # 全math blockはそのままで、追加opcode又はmathをskipするbranchを挿入する。
    changed = bytearray(image)
    decoder = b"".join(bytes.fromhex(block) for block in MATH_BLOCKS) + b"\xc3"
    altered = mutation + decoder
    changed[0x400 : 0x400 + len(altered)] = altered
    struct.pack_into("<I", changed, 0x1200 + 160, 0x200 + len(altered))
    report, artifacts = recovery.recover_go_embedded_pe(bytes(changed))
    assert report["status"] == "rejected"
    assert report["reason"] in {"unreviewed_or_ambiguous_decoder_shape", "branch_target_not_instruction_boundary"}
    assert not artifacts


@pytest.mark.parametrize("implicit_register,replacement", [("rax", "r10"), ("rdx", "r11")])
def test_implicit_multiply_register_role_is_not_aliased(implicit_register: str, replacement: str) -> None:
    changed = recovery._EVEN_BLOCKS[0].replace(implicit_register, replacement)
    assert recovery._canonical_block(changed) != recovery._canonical_block(recovery._EVEN_BLOCKS[0])
