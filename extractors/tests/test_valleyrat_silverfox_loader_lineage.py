from __future__ import annotations

import struct

import pytest
from capstone import CS_ARCH_X86, CS_MODE_64, Cs

from extractors.valleyrat import silverfox_loader_lineage as lineage


def _encoded_route_record() -> bytes:
    record = bytearray(lineage.ROUTE_RECORD_SIZE)
    record[0:4] = bytes((0x11, 0x22, 0x33, 0x44))
    record[4:6] = (4_321).to_bytes(2, "little")
    record[8:18] = b"ABCDEFGHIJ"
    record[20:22] = bytes((0x03, 0x02))
    record[24:29] = b"route"
    return lineage.ROUTE_MARKER + bytes(value ^ 0xFE for value in record)


def _synthetic_feedback_stage() -> tuple[bytes, bytes, int]:
    stage = bytearray(2_048)
    key = 7
    count = 1_024
    base = 28
    main_offset = 1_200
    bootstrap = (
        b"\xb0"
        + bytes((key,))
        + b"\x48\xc7\xc1"
        + count.to_bytes(4, "little")
        + b"\x48\x8d\x1d"
        + (base - 21).to_bytes(4, "little", signed=True)
        + b"\x30\x04\x0b"
        + b"\x02\x04\x0b"
        + b"\xe2\xf8"
    )
    assert len(bootstrap) == 24
    stage[5:29] = bootstrap
    decoded = bytearray(stage)
    decoded[29:31] = b"\xeb\x02"
    decoded[31:33] = b"\x90\x90"
    decoded[33] = 0xE9
    struct.pack_into("<i", decoded, 34, main_offset - 38)
    decoded[main_offset : main_offset + 4] = b"TEST"

    encoded = bytearray(decoded)
    running_key = key
    for index in range(count, 0, -1):
        offset = base + index
        encoded[offset] = decoded[offset] ^ running_key
        running_key = (running_key + decoded[offset]) & 0xFF
    return bytes(encoded), bytes(decoded), main_offset


def _outer_stage(seed: int = 0) -> lineage._OuterStage:
    return lineage._OuterStage(
        data=bytes((seed,)) * 4_096,
        source_rva=0x2_000 + seed,
        size=4_096,
        allocation_call_rva=0x1_000 + seed,
        copy_kind="rep_movsb",
        hook_trampoline_proven=True,
    )


def _feedback_stage(seed: int = 0) -> lineage._FeedbackLayer:
    return lineage._FeedbackLayer(
        data=bytes((seed,)) * 4_096,
        main_offset=0x200,
        patch_operation_count=4,
        feedback_count=2_048,
    )


def _component_stage(seed: int = 0) -> lineage._ComponentLayer:
    return lineage._ComponentLayer(
        data=b"component-" + bytes((seed,)),
        source_offset=0x40,
        key_length=20,
        main_offset=0x200,
    )


def _validated_profile() -> dict[str, object]:
    return {
        "profile": "silverfox_style_infection_downloader_component",
        "wininet_get_read_retry_lineage_proven": True,
        "file_write_and_process_capability_proven": True,
        "registry_handoff_structure_proven": True,
        "valleyrat_socket_api_marker_count": 0,
        "endpoint_values_included": False,
        "raw_command_values_included": False,
    }


def test_route_record_accepts_structured_non_text_secondary_value() -> None:
    encoded = _encoded_route_record()

    assert lineage._route_record_count(b"prefix" + encoded + b"suffix") == 1


@pytest.mark.parametrize(
    ("offset", "replacement"),
    [
        (4 + 6, 0x41),
        (4 + 18, 0x41),
        (4 + 22, 0x41),
        (4 + 31, 0x41),
    ],
)
def test_route_record_rejects_broken_separators(
    offset: int,
    replacement: int,
) -> None:
    encoded = bytearray(_encoded_route_record())
    encoded[offset] = replacement ^ 0xFE

    assert lineage._route_record_count(bytes(encoded)) == 0


def test_route_record_reports_ambiguity_without_merging() -> None:
    encoded = _encoded_route_record()

    assert lineage._route_record_count(encoded + b"gap" + encoded) == 2


def test_route_record_rejects_empty_address_field() -> None:
    encoded = bytearray(_encoded_route_record())
    encoded[4:8] = b"\xfe" * 4

    assert lineage._route_record_count(bytes(encoded)) == 0


def test_patch_bootstrap_interprets_only_bounded_dword_operations() -> None:
    stage = bytearray(256)
    target = 192
    struct.pack_into("<Bi", stage, 0, 0xE8, target - 5)
    expected = b"0123456789ABCDEF"
    for offset in range(0, len(expected), 4):
        value = int.from_bytes(expected[offset : offset + 4], "little")
        stage[5 + offset : 9 + offset] = ((value - 1) & 0xFFFFFFFF).to_bytes(
            4,
            "little",
        )
    tail = bytearray(b"\x59\x4d\x85\xd2\x4d\x0f\xa3\xff")
    for offset in range(0, len(expected), 4):
        tail.extend(b"\x81")
        tail.extend(b"\x01" if offset == 0 else b"\x41" + bytes((offset,)))
        tail.extend((1).to_bytes(4, "little"))
    tail.extend(b"\xff\xe1")
    stage[target : target + len(tail)] = tail

    result = lineage._patch_bootstrap(bytes(stage))

    assert result is not None
    patched, operation_count = result
    assert patched[5:21] == expected
    assert operation_count == 4


def test_patch_bootstrap_rejects_unbounded_or_incomplete_tail() -> None:
    assert lineage._patch_bootstrap(b"\xe8" + b"\0" * 62) is None
    stage = bytearray(256)
    struct.pack_into("<Bi", stage, 0, 0xE8, 187)
    stage[192:195] = b"\x59\xff\xe1"

    assert lineage._patch_bootstrap(bytes(stage)) is None


def test_feedback_layer_decodes_reverse_chain_and_near_jump(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    encoded, decoded, main_offset = _synthetic_feedback_stage()
    monkeypatch.setattr(lineage, "_patch_bootstrap", lambda _data: (encoded, 4))

    result = lineage._feedback_layer(b"ignored")

    assert result is not None
    assert result.main_offset == main_offset
    assert result.feedback_count == 1_024
    assert result.data == decoded


def test_feedback_layer_rejects_missing_feedback_add(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    encoded, _decoded, _main_offset = _synthetic_feedback_stage()
    malformed = bytearray(encoded)
    malformed[24:27] = b"\x90\x90\x90"
    monkeypatch.setattr(
        lineage,
        "_patch_bootstrap",
        lambda _data: (bytes(malformed), 4),
    )

    assert lineage._feedback_layer(b"ignored") is None


def test_load_pe_rejects_type_signature_and_size_before_parsing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert lineage._load_pe(bytearray(b"MZ")) is None  # type: ignore[arg-type]
    assert lineage._load_pe(b"not-a-pe") is None
    monkeypatch.setattr(lineage, "MAXIMUM_INPUT_SIZE", 4)
    assert lineage._load_pe(b"MZ123") is None


def test_relative_edge_inventory_is_complete_at_cap_and_rejected_above(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """E8/E9 edgeの上限超過時に先頭部分だけを返さない。"""

    monkeypatch.setattr(lineage, "MAXIMUM_RELATIVE_EDGES", 3)
    exact = [(0x1000, b"\xe8\0\0\0\0" * 3)]
    edges = lineage._relative_edges(exact)
    assert edges is not None
    assert len(edges) == 3

    overflow = [(0x1000, b"\xe8\0\0\0\0" * 4)]
    assert lineage._relative_edges(overflow) is None


def test_component_disassembly_is_bounded_and_fails_closed_on_overflow() -> None:
    """component全体をmaterializeせず、上限+1命令で切捨てを検出する。"""

    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    exact = lineage._bounded_disassembly(
        decoder,
        b"\x90" * 4,
        0,
        maximum_instructions=4,
    )
    assert exact is not None
    assert len(exact) == 4
    assert (
        lineage._bounded_disassembly(
            decoder,
            b"\x90" * 5,
            0,
            maximum_instructions=4,
        )
        is None
    )


def test_component_profile_rejects_marker_free_data() -> None:
    assert lineage._component_profile(b"\0" * 4_096) is None


def test_validated_loader_remains_non_terminal_valleyrat(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outer = _outer_stage()
    feedback = _feedback_stage()
    component = _component_stage()
    monkeypatch.setattr(lineage, "_load_pe", lambda _data: object())
    monkeypatch.setattr(lineage, "_outer_stage_candidates", lambda _context: (outer,))
    monkeypatch.setattr(lineage, "_route_record_count", lambda _data: 1)
    monkeypatch.setattr(lineage, "_feedback_layer", lambda _stage: feedback)
    monkeypatch.setattr(lineage, "_component_layer", lambda _layer: component)
    monkeypatch.setattr(
        lineage, "_component_profile", lambda _data: _validated_profile()
    )

    result = lineage.analyze_silverfox_loader_lineage(b"MZ")

    assert result is not None
    assert result.recovered_component == component.data
    assert (
        result.observation["status"]
        == "validated_silverfox_style_infection_loader_lineage"
    )
    assert result.observation["supports_family_attribution"] is False
    assert result.observation["terminal_family_confirmed"] is False
    assert result.observation["terminal_network_lineage_proven"] is False
    assert result.observation["candidate_only"] is True
    assert result.observation["hash_or_filename_rule_used"] is False
    assert result.observation["external_label_used"] is False
    assert result.observation["endpoint_values_included"] is False
    decoders = result.observation["decoders"]
    assert isinstance(decoders, dict)
    assert decoders["decoded_component_hash_included"] is False
    assert "decoded_component_sha256" not in decoders


def test_ambiguous_outer_stage_never_recovers_component(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(lineage, "_load_pe", lambda _data: object())
    monkeypatch.setattr(
        lineage,
        "_outer_stage_candidates",
        lambda _context: (_outer_stage(1), _outer_stage(2)),
    )
    monkeypatch.setattr(lineage, "_route_record_count", lambda _data: 1)

    result = lineage.analyze_silverfox_loader_lineage(b"MZ")

    assert result is not None
    assert result.recovered_component is None
    assert result.observation["candidate_only"] is True
    assert (
        "multiple_outer_stage_interpretations_ambiguous"
        in result.observation["missing_proof_codes"]
    )


def test_no_outer_stage_match_returns_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(lineage, "_load_pe", lambda _data: object())
    monkeypatch.setattr(lineage, "_outer_stage_candidates", lambda _context: ())
    monkeypatch.setattr(lineage, "_route_record_count", lambda _data: 0)

    assert lineage.analyze_silverfox_loader_lineage(b"MZ") is None
