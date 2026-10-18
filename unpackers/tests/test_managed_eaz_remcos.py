"""Eazfuscator系Remcos loader専用静的復元器の境界回帰。"""

from __future__ import annotations

import struct
import time
from types import SimpleNamespace

import pytest

from unpackers import managed_eaz_remcos as recovery


def _write_7bit(value: int) -> bytes:
    result = bytearray()
    while value >= 0x80:
        result.append((value & 0x7F) | 0x80)
        value >>= 7
    result.append(value)
    return bytes(result)


def _binary_string(value: str, encoding: str) -> bytes:
    encoded = value.encode(encoding)
    return _write_7bit(len(encoded)) + encoded


def _resource_set_many(
    entries: list[tuple[str, bytes]],
) -> tuple[bytes, int, int]:
    ordered = sorted(
        entries, key=lambda item: recovery._fast_resource_name_hash(item[0])
    )
    header = _binary_string(
        "System.Resources.ResourceReader, mscorlib", "utf-8"
    ) + _binary_string("System.Resources.RuntimeResourceSet, mscorlib", "utf-8")
    raw = bytearray(struct.pack("<Iii", recovery.RESOURCE_MAGIC, 1, len(header)))
    raw.extend(header)
    raw.extend(struct.pack("<iii", 2, len(ordered), 0))
    while len(raw) % 8:
        raw.append(0)
    hash_offset = len(raw)
    for name, _value in ordered:
        raw.extend(struct.pack("<i", recovery._fast_resource_name_hash(name)))
    name_records = []
    data_records = []
    data_offset = 0
    name_offset = 0
    for name, value in ordered:
        record = _binary_string(name, "utf-16le") + struct.pack("<i", data_offset)
        name_records.append(record)
        raw.extend(struct.pack("<i", name_offset))
        name_offset += len(record)
        data = _write_7bit(32) + struct.pack("<I", len(value)) + value
        data_records.append(data)
        data_offset += len(data)
    data_section_field = len(raw)
    raw.extend(b"\0\0\0\0")
    data_section = len(raw) + sum(map(len, name_records))
    struct.pack_into("<i", raw, data_section_field, data_section)
    for record in name_records:
        raw.extend(record)
    for record in data_records:
        raw.extend(record)
    return bytes(raw), data_section_field, hash_offset


def _resource_set(name: str, value: bytes) -> tuple[bytes, int]:
    raw, data_section_field, _hash_offset = _resource_set_many([(name, value)])
    return raw, data_section_field


def _resource(body: bytes) -> recovery._ManifestResource:
    return recovery._ManifestResource(
        token=0x28000001,
        name="private-name",
        body_offset=128,
        body=body,
    )


def _deadline() -> float:
    return time.monotonic() + 1


def test_b0_uses_inclusive_n_plus_one_loop_before_resize() -> None:
    source = bytes((4, 9, 16, 25, 36))
    key = b"abc"
    expected = bytearray(source)
    length = len(expected)
    for counter in range(length + 1):
        index = counter % length
        mixed = expected[index] ^ key[counter % len(key)]
        expected[index] = (mixed - expected[(counter + 1) % length] + 256) % 256
    del expected[-1:]

    recovered = recovery._apply_b0(
        source,
        key,
        deadline=_deadline(),
        clock=time.monotonic,
    )

    assert recovered == bytes(expected)
    assert len(recovered) == len(source) - 1


@pytest.mark.parametrize("remainder", [0, 1, 2, 3])
def test_modsquare_transform_handles_partial_words(remainder: int) -> None:
    arrays = recovery._ArrayRecipe(
        key=bytes(range(32)),
        mask=bytes(range(16)),
        traced_states=1,
        key_store_count=32,
        mask_store_count=16,
    )
    clear = bytes(range(1, 21 + remainder))
    constants = (0x12345678, 0x87654321, 0x10203040, 0x50607080)
    encrypted = recovery._decrypt_string_table(
        clear,
        arrays,
        constants,
        deadline=_deadline(),
        clock=time.monotonic,
    )

    assert (
        recovery._decrypt_string_table(
            encrypted,
            arrays,
            constants,
            deadline=_deadline(),
            clock=time.monotonic,
        )
        == clear
    )


def test_string_table_requires_exact_utf16_extent() -> None:
    first = "alpha".encode("utf-16le")
    second = "日本語".encode("utf-16le")
    clear = (
        struct.pack("<i", len(first)) + first + struct.pack("<i", len(second)) + second
    )

    entries = recovery._parse_string_table(
        clear,
        deadline=_deadline(),
        clock=time.monotonic,
    )

    assert [(entry.offset, entry.value) for entry in entries] == [
        (0, "alpha"),
        (4 + len(first), "日本語"),
    ]
    with pytest.raises(recovery.RemcosEazRecoveryError, match="length_truncated"):
        recovery._parse_string_table(
            clear + b"\0",
            deadline=_deadline(),
            clock=time.monotonic,
        )


def test_string_table_deadline_is_typed_incomplete() -> None:
    with pytest.raises(recovery.RemcosEazIncompleteError) as failure:
        recovery._parse_string_table(
            struct.pack("<i", 0),
            deadline=0,
            clock=lambda: 1,
        )
    assert failure.value.incomplete_type == "deadline"
    assert failure.value.stage == "string_table_parse"


def test_resource_set_requires_exact_name_and_data_sections() -> None:
    raw, data_section_field = _resource_set("entry", b"payload")
    values = recovery._parse_resource_set(
        _resource(raw),
        deadline=_deadline(),
        clock=time.monotonic,
    )
    assert len(values) == 1
    assert values[0].value == b"payload"

    changed = bytearray(raw)
    data_section = struct.unpack_from("<i", changed, data_section_field)[0]
    changed[data_section:data_section] = b"\0"
    struct.pack_into("<i", changed, data_section_field, data_section + 1)
    with pytest.raises(
        recovery.RemcosEazRecoveryError,
        match="resource_name_section_not_exact",
    ):
        recovery._parse_resource_set(
            _resource(bytes(changed)),
            deadline=_deadline(),
            clock=time.monotonic,
        )


def test_resource_set_rejects_hash_mismatch_and_unsorted_hashes() -> None:
    raw, _data_section_field, hash_offset = _resource_set_many(
        [("alpha", b"a"), ("omega", b"b")]
    )
    changed = bytearray(raw)
    stored = struct.unpack_from("<i", changed, hash_offset)[0]
    struct.pack_into("<i", changed, hash_offset, stored + 1)
    with pytest.raises(recovery.RemcosEazRecoveryError, match="hash_mismatch"):
        recovery._parse_resource_set(
            _resource(bytes(changed)),
            deadline=_deadline(),
            clock=time.monotonic,
        )

    changed = bytearray(raw)
    first, second = struct.unpack_from("<ii", changed, hash_offset)
    struct.pack_into("<ii", changed, hash_offset, second, first)
    with pytest.raises(recovery.RemcosEazRecoveryError, match="hashes_not_sorted"):
        recovery._parse_resource_set(
            _resource(bytes(changed)),
            deadline=_deadline(),
            clock=time.monotonic,
        )


def _normalized_instruction(opcode: str) -> SimpleNamespace:
    return SimpleNamespace(
        offset=0,
        opcode=opcode,
        local=None,
        user_string=None,
        token=None,
        resolved="",
        integer=None,
    )


def _method(opcode: str) -> SimpleNamespace:
    return SimpleNamespace(
        token=0x06000001,
        signature=b"\x00\x00\x01",
        is_static=True,
        is_public=False,
        is_special_name=False,
        is_runtime_special_name=False,
        instructions=(_normalized_instruction(opcode),),
    )


@pytest.mark.parametrize(
    ("opcode", "operand", "reason"),
    [
        ("br", 99, "cil_branch_target_out_of_bounds"),
        ("switch", [0, 99], "cil_switch_target_out_of_bounds"),
    ],
)
def test_canonical_profile_rejects_external_control_flow_targets(
    monkeypatch: pytest.MonkeyPatch,
    opcode: str,
    operand: object,
    reason: str,
) -> None:
    decoded = SimpleNamespace(
        instructions=(SimpleNamespace(offset=0, opcode=opcode, operand=operand),),
        exception_handler_count=0,
        has_extra_sections=False,
    )
    monkeypatch.setattr(
        recovery, "_decode_selected_method", lambda *_args, **_kwargs: decoded
    )

    with pytest.raises(recovery.RemcosEazRecoveryError, match=reason):
        recovery._canonical_method_digest(
            b"fixture",
            object(),
            _method(opcode),
            {},
            {},
            opaque_large_constants=False,
            deadline=_deadline(),
            clock=time.monotonic,
        )


def _eh_fixture(try_end: int = 2) -> tuple[SimpleNamespace, SimpleNamespace]:
    handler = SimpleNamespace(
        exception_type=0,
        try_start=0,
        try_end=try_end,
        handler_start=2,
        handler_end=4,
        filter_start=-1,
        catch_type=SimpleNamespace(value=0x01000001),
    )
    body = SimpleNamespace(
        size=64,
        code_size=4,
        header_size=12,
        instructions=(object(), object(), object(), object()),
        exception_handlers=(handler,),
        exception_handlers_size=16,
        flags=SimpleNamespace(MoreSects=True),
    )
    decoded = SimpleNamespace(
        code_size=4,
        instructions=tuple(SimpleNamespace(offset=value) for value in range(12, 16)),
        exception_handler_count=1,
        has_extra_sections=True,
    )
    return body, decoded


def test_exception_handlers_are_normalized_to_instruction_indices(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    body, decoded = _eh_fixture()
    monkeypatch.setattr(recovery, "_bounded_method_body_data", lambda *_args: b"body")
    monkeypatch.setattr(recovery, "read_method_body_from_bytes", lambda _raw: body)
    pe = SimpleNamespace(
        net=SimpleNamespace(
            mdtables=SimpleNamespace(
                MethodDef=SimpleNamespace(rows=[SimpleNamespace(Rva=1)])
            )
        ),
        get_offset_from_rva=lambda _rva: 0,
    )
    method = SimpleNamespace(token=0x06000001, body_size=64)

    handlers, extra = recovery._canonical_exception_handlers(
        b"fixture",
        pe,
        method,
        decoded,
        {value: index for index, value in enumerate(range(12, 16))},
        {0x01000001: "System.Exception"},
        {},
    )

    assert handlers == [[0, 0, 2, 2, 4, None, ["framework", "System.Exception"]]]
    assert extra is True


def test_exception_handler_boundary_out_of_bounds_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    body, decoded = _eh_fixture(try_end=5)
    monkeypatch.setattr(recovery, "_bounded_method_body_data", lambda *_args: b"body")
    monkeypatch.setattr(recovery, "read_method_body_from_bytes", lambda _raw: body)
    pe = SimpleNamespace(
        net=SimpleNamespace(
            mdtables=SimpleNamespace(
                MethodDef=SimpleNamespace(rows=[SimpleNamespace(Rva=1)])
            )
        ),
        get_offset_from_rva=lambda _rva: 0,
    )
    with pytest.raises(recovery.RemcosEazRecoveryError, match="boundary_out_of_bounds"):
        recovery._canonical_exception_handlers(
            b"fixture",
            pe,
            SimpleNamespace(token=0x06000001, body_size=64),
            decoded,
            {value: index for index, value in enumerate(range(12, 16))},
            {0x01000001: "System.Exception"},
            {},
        )


def test_delegate_argument_order_requires_delegate_then_original_arguments() -> None:
    correct = [
        SimpleNamespace(opcode="ldarg.2", operand=None),
        SimpleNamespace(opcode="ldarg.0", operand=None),
        SimpleNamespace(opcode="ldarg.1", operand=None),
    ]
    recovery._validate_delegate_argument_order(correct, 2)

    incorrect = [correct[1], correct[0], correct[2]]
    with pytest.raises(recovery.RemcosEazRecoveryError, match="permutation_mismatch"):
        recovery._validate_delegate_argument_order(incorrect, 2)


@pytest.mark.parametrize(
    ("handler_count", "has_extra"),
    [(1, True), (0, True), (1, False)],
)
def test_delegate_wrapper_rejects_exception_sections(
    handler_count: int, has_extra: bool
) -> None:
    with pytest.raises(
        recovery.RemcosEazRecoveryError,
        match="wrapper_exception_shape",
    ):
        recovery._validate_delegate_wrapper_exception_shape(
            SimpleNamespace(
                exception_handler_count=handler_count,
                has_extra_sections=has_extra,
            )
        )


def test_proxy_graph_ignores_dead_call_block() -> None:
    decoded = SimpleNamespace(
        instructions=(
            SimpleNamespace(offset=0, opcode="br", operand=2),
            SimpleNamespace(offset=1, opcode="call", operand=0x0A000001),
            SimpleNamespace(offset=2, opcode="ret", operand=None),
        ),
        exception_handler_count=0,
        has_extra_sections=False,
    )

    assert recovery._reachable_instruction_indices(decoded) == {0, 2}


def test_proxy_analysis_receives_only_remaining_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, float] = {}

    def analyze(*_args: object, **kwargs: object) -> dict[str, object]:
        observed["maximum"] = float(kwargs["max_elapsed_seconds"])
        return {
            "status": "matched",
            "source_coverage_verified": True,
            "candidates": [
                {
                    "records": [
                        {
                            "valid": True,
                            "field_token": "0x04000001",
                            "target_token": "0x06000001",
                            "call_kind": "call",
                        }
                    ]
                }
            ],
        }

    monkeypatch.setattr(recovery, "analyze_modsquare_proxy_profile", analyze)
    records = recovery._proxy_records(
        b"fixture",
        object(),
        object(),
        object(),
        deadline=10,
        clock=lambda: 4,
    )

    assert records == {0x04000001: (0x06000001, "call")}
    assert observed["maximum"] == 6


def test_proxy_analysis_deadline_is_typed_incomplete(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        recovery,
        "analyze_modsquare_proxy_profile",
        lambda *_args, **_kwargs: {
            "status": "partial_budget",
            "source_coverage_verified": True,
            "candidates": [],
            "budget_exhausted": ["managed_proxy_profile_deadline_exceeded"],
        },
    )
    with pytest.raises(recovery.RemcosEazIncompleteError) as failure:
        recovery._proxy_records(
            b"fixture",
            object(),
            object(),
            object(),
            deadline=10,
            clock=lambda: 4,
        )
    assert failure.value.incomplete_type == "deadline"
    assert failure.value.stage == "proxy_analysis"


def test_public_api_rejects_nonbytes_without_parser_entry() -> None:
    report, artifacts = recovery.recover_managed_eaz_remcos(bytearray(b"MZ"))

    assert report == {"status": "rejected", "reason": "input_not_exact_bytes"}
    assert artifacts == []


def test_manifest_resource_inventory_rejects_zero_rows_before_directory_quota(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ManifestResource 0件を空directoryのbyte上限と誤分類しない。"""

    snapshot = SimpleNamespace(
        coverage=lambda: {
            "status": "complete",
            "inventory_complete": True,
            "embedded_scan_complete": True,
            "input_binding_verified": True,
            "reason_counts": {},
        }
    )
    monkeypatch.setattr(
        recovery,
        "prepare_resource_snapshot",
        lambda *_args, **_kwargs: (snapshot, object(), 0),
    )
    monkeypatch.setattr(
        recovery,
        "revalidated_resource_scan",
        lambda _data, current: current,
    )
    pe = SimpleNamespace(
        net=SimpleNamespace(
            mdtables=SimpleNamespace(
                ManifestResource=SimpleNamespace(rows=[]),
            ),
            struct=SimpleNamespace(ResourcesRva=0, ResourcesSize=2**63),
        )
    )

    with pytest.raises(
        recovery.RemcosEazRecoveryError, match="manifest_resources_missing"
    ):
        recovery._manifest_resources(
            b"MZ fixture",
            pe,
            deadline=10.0,
            clock=lambda: 0.0,
        )
