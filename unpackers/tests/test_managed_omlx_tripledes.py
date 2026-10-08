"""OMLX→TripleDES/GZip静的復元器の合成fixture回帰。"""

from __future__ import annotations

import base64
import json
import struct
from collections.abc import Callable
from contextlib import nullcontext
from types import SimpleNamespace

import pytest
from malware.purehvnc.managed_resource_recovery import (
    OmlxInstruction,
    OmlxMethod,
    OmlxStaticInitializer,
    decrypt_keyed_eaz_resource,
)

from unpackers import managed_omlx_tripledes as recovery


def _item(index: int, opcode: int, operand: int | None = None) -> OmlxInstruction:
    return OmlxInstruction(
        index=index,
        record_offset=index,
        opcode_id=opcode,
        operand_kind=1 if operand is not None else 0,
        operand=operand,
    )


def _synthetic_transform_method(
    key: bytes,
    mask: bytes,
    encrypted_size: int,
    transform_token: int,
) -> OmlxMethod:
    records: list[tuple[int, int | None]] = []

    def emit(opcode: int, operand: int | None = None) -> None:
        records.append((opcode, operand))

    emit(173, len(key))
    emit(29)
    emit(148, 0)
    for index, value in enumerate(key):
        emit(7, 0)
        emit(173, index)
        emit(173, value)
        emit(138)
    emit(173, len(mask))
    emit(29)
    emit(148, 1)
    for index, value in enumerate(mask):
        emit(7, 1)
        emit(173, index)
        emit(173, value)
        emit(138)
    emit(150, 0x0600008A)
    emit(7, 0)
    emit(7, 1)
    emit(156, 0)
    emit(150, 0x060000D9)
    emit(173, encrypted_size)
    emit(134, 0x060000B6)
    emit(134, transform_token)
    emit(110)
    return OmlxMethod(
        method_index=0,
        metadata_token=0x06000001,
        type_count=0,
        exception_clause_count=0,
        type_descriptors=(),
        instructions=tuple(
            _item(index, opcode, operand)
            for index, (opcode, operand) in enumerate(records)
        ),
        exception_clauses=(),
    )


def test_bounded_omlx_dataflow_recovers_only_the_verified_no_mask_transform() -> None:
    clear = struct.pack("<i", 4) + "ok".encode("utf-16le")
    key = bytes(range(32))
    mask = bytes(reversed(range(16)))
    seed = 659_796_207
    addend = 957_243_902
    encrypted = decrypt_keyed_eaz_resource(
        clear,
        key,
        seed=seed,
        addend=addend,
        allow_partial_word=True,
    )
    transform_token = 0x06000022
    method = _synthetic_transform_method(
        key,
        mask,
        len(encrypted),
        transform_token,
    )
    recipe = recovery._TransformRecipe(
        transform_token,
        seed,
        addend,
        (10, 20),
    )

    work_budget = recovery._TerminalWorkBudget()
    result = recovery._recover_table(
        method,
        encrypted,
        {transform_token: recipe},
        entrypoint_token=0x06000002,
        deadline=10.0,
        clock=lambda: 0.0,
        work_budget=work_budget,
    )

    assert result.clear == clear
    assert result.key == key
    assert result.mask == mask
    assert work_budget.table_transform_work_bytes == len(encrypted)
    assert recovery._decode_table(
        result.clear,
        deadline=10.0,
        clock=lambda: 0.0,
    ) == ((0, "ok"),)


def test_omlx_dataflow_rejects_an_unverified_transform_token() -> None:
    key = bytes(range(32))
    mask = bytes(range(16))
    method = _synthetic_transform_method(key, mask, 4, 0x06000022)
    with pytest.raises(recovery.OmlxTripledesError, match="call_out_of_profile"):
        recovery._recover_table(
            method,
            b"\0" * 4,
            {},
            entrypoint_token=0x06000002,
            deadline=10.0,
            clock=lambda: 0.0,
            work_budget=recovery._TerminalWorkBudget(),
        )


def test_fixed_candidate_search_checks_deadline_before_parsing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        recovery,
        "parse_omlx_header",
        lambda _blob: pytest.fail("deadline後にOMLX headerを解析してはいけません"),
    )

    with pytest.raises(recovery.OmlxTripledesError, match="elapsed_time_limit"):
        recovery._find_omlx_candidate(
            (("omlx", b"blob"),),
            deadline=1.0,
            clock=lambda: 2.0,
        )


def test_table_dataflow_and_decoder_check_deadline_inside_loops() -> None:
    method = _synthetic_transform_method(
        bytes(range(32)),
        bytes(range(16)),
        4,
        0x06000022,
    )
    with pytest.raises(recovery.OmlxTripledesError, match="elapsed_time_limit"):
        recovery._recover_table(
            method,
            b"data",
            {},
            entrypoint_token=0x06000002,
            deadline=1.0,
            clock=lambda: 2.0,
            work_budget=recovery._TerminalWorkBudget(),
        )
    with pytest.raises(recovery.OmlxTripledesError, match="elapsed_time_limit"):
        recovery._decode_table(
            struct.pack("<i", 2) + "x".encode("utf-16le"),
            deadline=1.0,
            clock=lambda: 2.0,
        )


def test_table_transform_work_budget_is_cumulative() -> None:
    key = bytes(range(32))
    mask = bytes(range(16))
    encrypted = b"data"
    transform_token = 0x06000022
    method = _synthetic_transform_method(
        key,
        mask,
        len(encrypted),
        transform_token,
    )
    recipe = recovery._TransformRecipe(transform_token, 1, 2, (10, 20))

    with pytest.raises(recovery.OmlxTripledesError, match="table_transform_work_limit"):
        recovery._recover_table(
            method,
            encrypted,
            {transform_token: recipe},
            entrypoint_token=0x06000002,
            deadline=10.0,
            clock=lambda: 0.0,
            work_budget=recovery._TerminalWorkBudget(
                max_table_transform_work_bytes=len(encrypted) - 1
            ),
        )


def test_decoder_elapsed_errors_are_hard_limits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_pe = SimpleNamespace(
        net=SimpleNamespace(
            mdtables=SimpleNamespace(MethodDef=SimpleNamespace(rows=(object(),)))
        )
    )
    monkeypatch.setattr(recovery, "_system_byte_tokens", lambda _pe: frozenset())
    monkeypatch.setattr(
        recovery,
        "_decode_method",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            recovery.RecoveryError("elapsed_time_limit")
        ),
    )

    with pytest.raises(recovery.OmlxTripledesError, match="elapsed_time_limit"):
        recovery._verified_transform_recipes(
            b"parent",
            fake_pe,
            deadline=10.0,
            clock=lambda: 0.0,
        )

    monkeypatch.setattr(
        recovery,
        "_framework_references",
        lambda *_args: (
            {1: "System.Reflection.Assembly::GetManifestResourceStream"},
            {},
            {},
        ),
    )
    with pytest.raises(recovery.OmlxTripledesError, match="elapsed_time_limit"):
        recovery._find_bound_resource(
            b"parent",
            fake_pe,
            0x06000001,
            {},
            deadline=10.0,
            clock=lambda: 0.0,
        )

    references = {
        1: "System.Security.Cryptography.TripleDES::Create",
        2: "System.IO.Compression.GZipStream::.ctor",
        3: "System.Reflection.Assembly::Load",
    }
    with pytest.raises(recovery.OmlxTripledesError, match="elapsed_time_limit"):
        recovery._verify_sink_api_calls(
            b"parent",
            fake_pe,
            references,
            deadline=10.0,
            clock=lambda: 0.0,
        )


def test_dynamic_semantic_elapsed_error_is_a_hard_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    header = SimpleNamespace(
        feature_flag=False,
        opcode_map=tuple(range(58)),
        strings=(),
        method_offsets=(124, 256),
        body_offset=124,
    )
    raw_method = _dynamic_fixture_method()
    initializer = OmlxMethod(
        method_index=1,
        metadata_token=0x06000096,
        type_count=0,
        exception_clause_count=0,
        type_descriptors=(),
        instructions=tuple(_item(index, index) for index in range(13)),
        exception_clauses=(),
    )
    monkeypatch.setattr(recovery, "parse_omlx_header", lambda _blob: header)
    monkeypatch.setattr(
        recovery,
        "parse_omlx_method",
        lambda _blob, _header, index, **_kwargs: (
            raw_method if index == 0 else initializer
        ),
    )
    monkeypatch.setattr(
        recovery,
        "extract_omlx_handler_shapes",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            recovery.OmlxSemanticError("elapsed_time_limit")
        ),
    )

    with pytest.raises(recovery.OmlxTripledesError, match="elapsed_time_limit"):
        recovery._find_dynamic_omlx_candidate(
            b"parent",
            object(),
            (("omlx", b"blob"),),
            deadline=10.0,
            clock=lambda: 0.0,
        )


def test_dynamic_mapping_does_not_swallow_table_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        recovery,
        "_recover_table",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            recovery._OmlxHardLimitError("elapsed_time_limit")
        ),
    )

    with pytest.raises(recovery.OmlxTripledesError, match="elapsed_time_limit"):
        recovery._recover_dynamic_outputs(
            _dynamic_fixture_method(),
            ({5: 1},),
            b"encrypted",
            {},
            b"child",
            entrypoint_token=0x06000001,
            deadline=10.0,
            clock=lambda: 0.0,
            work_budget=recovery._TerminalWorkBudget(),
        )


def test_nested_eaz_deadline_is_preserved_in_public_rejection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_pe = SimpleNamespace(net=SimpleNamespace())
    monkeypatch.setattr(recovery, "has_clr_metadata", lambda _data: True)
    monkeypatch.setattr(recovery, "_contained_parser_diagnostics", nullcontext)
    monkeypatch.setattr(recovery.dnfile, "dnPE", lambda **_kwargs: fake_pe)
    monkeypatch.setattr(recovery, "_metadata_row_count", lambda _pe: 1)
    monkeypatch.setattr(recovery, "_resource_blobs", lambda _pe: [("x", b"x")])
    monkeypatch.setattr(
        recovery,
        "recover_managed_eaz_resource",
        lambda *_args, **_kwargs: (
            {"status": "rejected", "reason": "elapsed_time_limit"},
            [],
        ),
    )

    report, artifacts = recovery.recover_managed_omlx_tripledes(
        b"MZparent",
        clock=lambda: 0.0,
    )

    assert artifacts == []
    assert report["status"] == "rejected"
    assert report["reason"] == "elapsed_time_limit"


def test_static_initializer_selectors_resolve_exact_string_boundaries() -> None:
    fields = (
        (0x04000143, 1_071_284_645),
        (0x0400014B, 1_384_898_113),
        (0x0400014E, 1_770_037_520),
    )
    initializer = OmlxStaticInitializer(
        metadata_token=0x06000002,
        constructor_token=0x06000003,
        singleton_field_token=0x04000001,
        field_values=fields,
    )
    assert recovery._selectors(initializer, recovery._PROFILES[0]) == (0, 52, 262)

    with pytest.raises(recovery.OmlxTripledesError, match="selector_field_missing"):
        recovery._selectors(
            SimpleNamespace(field_values=fields[:2]),
            recovery._PROFILES[0],
        )


def test_common_v2_initializer_selectors_resolve_exact_string_boundaries() -> None:
    initializer = SimpleNamespace(
        field_values=(
            (0x04000167, 915_005_550),
            (0x0400013D, 733_373_671),
            (0x04000155, 352_781_929),
        )
    )

    assert recovery._selectors(initializer, recovery._PROFILES[1]) == (0, 52, 262)


def test_common_v2_method_opcode_profile_is_explicit_and_fail_closed() -> None:
    method = OmlxMethod(
        method_index=0,
        metadata_token=0x06000095,
        type_count=0,
        exception_clause_count=0,
        type_descriptors=(),
        instructions=(
            _item(0, 21, 7),
            _item(1, 22),
            _item(2, 118),
        ),
        exception_clauses=(),
    )
    translated = recovery._canonicalize_omlx_method(
        method,
        recovery._PROFILES[1].method_opcode_map,
    )
    assert [item.opcode_id for item in translated.instructions] == [173, 96, 110]

    malformed = OmlxMethod(
        method_index=0,
        metadata_token=0x06000095,
        type_count=0,
        exception_clause_count=0,
        type_descriptors=(),
        instructions=(_item(0, 255),),
        exception_clauses=(),
    )
    with pytest.raises(recovery.OmlxTripledesError, match="opcode_out_of_profile:255"):
        recovery._canonicalize_omlx_method(
            malformed,
            recovery._PROFILES[1].method_opcode_map,
        )


def test_terminal_binding_requires_one_typed_resource_crypto_chain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key = base64.b64encode(bytes(range(16))).decode("ascii")
    iv = base64.b64encode(bytes(range(8))).decode("ascii")
    table = ((0, key), (52, iv), (80, "payload.bin"), (108, "noise"))

    monkeypatch.setattr(
        recovery,
        "_child_resource_entries",
        lambda _child, **_kwargs: (("payload.bin", b"ciphertext"),),
    )

    def decrypt(ciphertext: bytes, key_value: str, iv_value: str) -> bytes:
        if (ciphertext, key_value, iv_value) != (b"ciphertext", key, iv):
            raise ValueError("unexpected candidate")
        return b"clear"

    monkeypatch.setattr(
        recovery,
        "decrypt_tripledes_cbc_pkcs7_base64",
        decrypt,
    )
    monkeypatch.setattr(
        recovery,
        "inflate_length_prefixed_gzip",
        lambda clear, **_kwargs: b"MZmanaged" if clear == b"clear" else b"",
    )
    monkeypatch.setattr(
        recovery,
        "inspect_structural_pe_extent",
        lambda payload, **_kwargs: SimpleNamespace(extent=len(payload)),
    )
    monkeypatch.setattr(
        recovery, "has_clr_metadata", lambda payload: payload == b"MZmanaged"
    )

    binding = recovery._select_terminal_binding(
        table,
        b"child",
        deadline=10.0,
        clock=lambda: 0.0,
        work_budget=recovery._TerminalWorkBudget(),
    )

    assert (
        binding.key_offset,
        binding.iv_offset,
        binding.resource_name_offset,
    ) == (0, 52, 80)
    assert binding.payload == b"MZmanaged"


def test_terminal_binding_rejects_multiple_complete_managed_pe_candidates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key = base64.b64encode(bytes(range(16))).decode("ascii")
    iv = base64.b64encode(bytes(range(8))).decode("ascii")
    table = ((0, key), (52, iv), (80, "one"), (92, "two"))
    monkeypatch.setattr(
        recovery,
        "_child_resource_entries",
        lambda _child, **_kwargs: (("one", b"a"), ("two", b"b")),
    )
    monkeypatch.setattr(
        recovery,
        "decrypt_tripledes_cbc_pkcs7_base64",
        lambda *_args: b"clear",
    )
    monkeypatch.setattr(
        recovery,
        "inflate_length_prefixed_gzip",
        lambda *_args, **_kwargs: b"MZmanaged",
    )
    monkeypatch.setattr(
        recovery,
        "inspect_structural_pe_extent",
        lambda payload, **_kwargs: SimpleNamespace(extent=len(payload)),
    )
    monkeypatch.setattr(recovery, "has_clr_metadata", lambda _payload: True)

    with pytest.raises(
        recovery.OmlxTripledesError,
        match="terminal_binding_candidate_ambiguous",
    ):
        recovery._select_terminal_binding(
            table,
            b"child",
            deadline=10.0,
            clock=lambda: 0.0,
            work_budget=recovery._TerminalWorkBudget(),
        )


def test_terminal_binding_deadline_stops_before_resource_parsing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        recovery,
        "_child_resource_entries",
        lambda _child, **_kwargs: pytest.fail(
            "deadline後にchild resourceを解析してはいけません"
        ),
    )

    with pytest.raises(recovery.OmlxTripledesError, match="elapsed_time_limit"):
        recovery._select_terminal_binding(
            (),
            b"child",
            deadline=1.0,
            clock=lambda: 2.0,
            work_budget=recovery._TerminalWorkBudget(),
        )


def test_terminal_binding_candidate_budget_is_shared_across_attempts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key = base64.b64encode(bytes(range(16))).decode("ascii")
    iv = base64.b64encode(bytes(range(8))).decode("ascii")
    table = ((0, key), (52, iv), (80, "one"), (92, "two"))
    monkeypatch.setattr(
        recovery,
        "_child_resource_entries",
        lambda _child, **_kwargs: (("one", b"12345678"), ("two", b"abcdefgh")),
    )
    decrypt_calls = 0

    def reject_candidate(*_args: object) -> bytes:
        nonlocal decrypt_calls
        decrypt_calls += 1
        raise ValueError("invalid")

    monkeypatch.setattr(
        recovery,
        "decrypt_tripledes_cbc_pkcs7_base64",
        reject_candidate,
    )

    with pytest.raises(
        recovery.OmlxTripledesError,
        match="terminal_validation_candidate_limit",
    ):
        recovery._select_terminal_binding(
            table,
            b"child",
            deadline=10.0,
            clock=lambda: 0.0,
            work_budget=recovery._TerminalWorkBudget(
                max_candidate_count=1,
                max_ciphertext_work_bytes=16,
                max_inflated_work_bytes=16,
            ),
        )

    assert decrypt_calls == 1


def test_terminal_binding_ciphertext_work_is_cumulative(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key = base64.b64encode(bytes(range(16))).decode("ascii")
    iv = base64.b64encode(bytes(range(8))).decode("ascii")
    table = ((0, key), (52, iv), (80, "one"), (92, "two"))
    monkeypatch.setattr(
        recovery,
        "_child_resource_entries",
        lambda _child, **_kwargs: (("one", b"12345678"), ("two", b"abcdefgh")),
    )
    decrypt_calls = 0

    def reject_candidate(*_args: object) -> bytes:
        nonlocal decrypt_calls
        decrypt_calls += 1
        raise ValueError("invalid")

    monkeypatch.setattr(
        recovery,
        "decrypt_tripledes_cbc_pkcs7_base64",
        reject_candidate,
    )

    with pytest.raises(
        recovery.OmlxTripledesError,
        match="terminal_ciphertext_work_limit",
    ):
        recovery._select_terminal_binding(
            table,
            b"child",
            deadline=10.0,
            clock=lambda: 0.0,
            work_budget=recovery._TerminalWorkBudget(
                max_candidate_count=2,
                max_ciphertext_work_bytes=8,
                max_inflated_work_bytes=16,
            ),
        )

    assert decrypt_calls == 1


def test_terminal_binding_inflated_work_is_reserved_before_inflate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key = base64.b64encode(bytes(range(16))).decode("ascii")
    iv = base64.b64encode(bytes(range(8))).decode("ascii")
    table = ((0, key), (52, iv), (80, "one"), (92, "two"))
    monkeypatch.setattr(
        recovery,
        "_child_resource_entries",
        lambda _child, **_kwargs: (("one", b"12345678"), ("two", b"abcdefgh")),
    )
    monkeypatch.setattr(
        recovery,
        "decrypt_tripledes_cbc_pkcs7_base64",
        lambda *_args: struct.pack("<i", 6) + b"gzip",
    )
    inflate_calls = 0

    def inflate(*_args: object, **_kwargs: object) -> bytes:
        nonlocal inflate_calls
        inflate_calls += 1
        return b"not-pe"

    monkeypatch.setattr(recovery, "inflate_length_prefixed_gzip", inflate)
    monkeypatch.setattr(
        recovery,
        "inspect_structural_pe_extent",
        lambda payload, **_kwargs: SimpleNamespace(extent=len(payload)),
    )
    monkeypatch.setattr(recovery, "has_clr_metadata", lambda _payload: False)

    with pytest.raises(
        recovery.OmlxTripledesError,
        match="terminal_inflated_work_limit",
    ):
        recovery._select_terminal_binding(
            table,
            b"child",
            deadline=10.0,
            clock=lambda: 0.0,
            work_budget=recovery._TerminalWorkBudget(
                max_candidate_count=2,
                max_ciphertext_work_bytes=16,
                max_inflated_work_bytes=7,
            ),
        )

    assert inflate_calls == 1


def test_terminal_binding_rejects_second_distinct_match_immediately(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key = base64.b64encode(bytes(range(16))).decode("ascii")
    iv = base64.b64encode(bytes(range(8))).decode("ascii")
    table = (
        (0, key),
        (52, iv),
        (80, "one"),
        (92, "two"),
        (104, "three"),
    )
    monkeypatch.setattr(
        recovery,
        "_child_resource_entries",
        lambda _child, **_kwargs: (
            ("one", b"a"),
            ("two", b"b"),
            ("three", b"c"),
        ),
    )
    decrypt_calls = 0

    def decrypt(*_args: object) -> bytes:
        nonlocal decrypt_calls
        decrypt_calls += 1
        return b"clear"

    monkeypatch.setattr(
        recovery,
        "decrypt_tripledes_cbc_pkcs7_base64",
        decrypt,
    )
    monkeypatch.setattr(
        recovery,
        "inflate_length_prefixed_gzip",
        lambda *_args, **_kwargs: b"MZmanaged",
    )
    monkeypatch.setattr(
        recovery,
        "inspect_structural_pe_extent",
        lambda payload, **_kwargs: SimpleNamespace(extent=len(payload)),
    )
    monkeypatch.setattr(recovery, "has_clr_metadata", lambda _payload: True)

    with pytest.raises(
        recovery.OmlxTripledesError,
        match="terminal_binding_candidate_ambiguous",
    ):
        recovery._select_terminal_binding(
            table,
            b"child",
            deadline=10.0,
            clock=lambda: 0.0,
            work_budget=recovery._TerminalWorkBudget(),
        )

    assert decrypt_calls == 2


def test_terminal_binding_collapses_identical_duplicate_candidates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key = base64.b64encode(bytes(range(16))).decode("ascii")
    iv = base64.b64encode(bytes(range(8))).decode("ascii")
    table = (
        (0, key),
        (0, key),
        (52, iv),
        (52, iv),
        (80, "payload.bin"),
        (80, "payload.bin"),
    )
    monkeypatch.setattr(
        recovery,
        "_child_resource_entries",
        lambda _child, **_kwargs: (("payload.bin", b"ciphertext"),),
    )
    monkeypatch.setattr(
        recovery,
        "decrypt_tripledes_cbc_pkcs7_base64",
        lambda *_args: b"clear",
    )
    monkeypatch.setattr(
        recovery,
        "inflate_length_prefixed_gzip",
        lambda *_args, **_kwargs: b"MZmanaged",
    )
    monkeypatch.setattr(
        recovery,
        "inspect_structural_pe_extent",
        lambda payload, **_kwargs: SimpleNamespace(extent=len(payload)),
    )
    monkeypatch.setattr(recovery, "has_clr_metadata", lambda _payload: True)

    binding = recovery._select_terminal_binding(
        table,
        b"child",
        deadline=10.0,
        clock=lambda: 0.0,
        work_budget=recovery._TerminalWorkBudget(),
    )

    assert binding.payload == b"MZmanaged"


def _dynamic_fixture_method() -> OmlxMethod:
    return OmlxMethod(
        method_index=0,
        metadata_token=0x06000095,
        type_count=0,
        exception_clause_count=0,
        type_descriptors=(),
        instructions=(_item(0, 5),),
        exception_clauses=(),
    )


def _dynamic_fixture_table_recovery(clear: bytes) -> recovery._TableRecovery:
    return recovery._TableRecovery(
        clear=clear,
        key=b"k" * 32,
        mask=b"m" * 16,
        transform=recovery._TransformRecipe(0x06000022, 1, 2, (3, 4)),
        steps=1,
    )


def _dynamic_fixture_binding(payload: bytes) -> recovery._TerminalBinding:
    return recovery._TerminalBinding(
        key_offset=0,
        iv_offset=52,
        resource_name_offset=80,
        key_base64=base64.b64encode(bytes(range(16))).decode("ascii"),
        iv_base64=base64.b64encode(bytes(range(8))).decode("ascii"),
        resource_name="payload.bin",
        ciphertext=b"ciphertext",
        payload=payload,
    )


def test_dynamic_opcode_candidates_accept_only_one_distinct_terminal_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    shared = _dynamic_fixture_table_recovery(b"same")
    monkeypatch.setattr(recovery, "_recover_table", lambda *_args, **_kwargs: shared)
    monkeypatch.setattr(
        recovery,
        "decrypt_keyed_eaz_resource",
        lambda *_args, **_kwargs: b"same",
    )
    monkeypatch.setattr(
        recovery,
        "_decode_table",
        lambda _clear, **_kwargs: ((0, "same"),),
    )
    monkeypatch.setattr(
        recovery,
        "_select_terminal_binding",
        lambda _table, _child, **_kwargs: _dynamic_fixture_binding(b"MZsame"),
    )

    result = recovery._recover_dynamic_outputs(
        _dynamic_fixture_method(),
        ({5: 1}, {5: 7}),
        b"encrypted",
        {},
        b"child",
        entrypoint_token=0x06000001,
        deadline=10.0,
        clock=lambda: 0.0,
        work_budget=recovery._TerminalWorkBudget(),
    )

    assert result.candidate_count == 2
    assert result.viable_candidate_count == 2
    assert result.viable_mapping_mode_candidate_count == 4
    assert result.key_mask_modes == ("none", "xor16")
    assert result.terminal_binding.payload == b"MZsame"


def test_dynamic_opcode_candidates_share_one_terminal_work_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    shared = _dynamic_fixture_table_recovery(b"same")
    monkeypatch.setattr(recovery, "_recover_table", lambda *_args, **_kwargs: shared)
    monkeypatch.setattr(
        recovery,
        "decrypt_keyed_eaz_resource",
        lambda *_args, **_kwargs: b"same",
    )
    monkeypatch.setattr(
        recovery,
        "_decode_table",
        lambda _clear, **_kwargs: ((0, "same"),),
    )
    validation_calls = 0

    def select(
        _table: tuple[tuple[int, str], ...],
        _child: bytes,
        *,
        work_budget: recovery._TerminalWorkBudget,
        **_kwargs: object,
    ) -> recovery._TerminalBinding:
        nonlocal validation_calls
        work_budget.charge_candidate(1)
        validation_calls += 1
        return _dynamic_fixture_binding(b"MZsame")

    monkeypatch.setattr(recovery, "_select_terminal_binding", select)

    with pytest.raises(
        recovery.OmlxTripledesError,
        match="terminal_validation_candidate_limit",
    ):
        recovery._recover_dynamic_outputs(
            _dynamic_fixture_method(),
            ({5: 1}, {5: 7}),
            b"encrypted",
            {},
            b"child",
            entrypoint_token=0x06000001,
            deadline=10.0,
            clock=lambda: 0.0,
            work_budget=recovery._TerminalWorkBudget(
                max_candidate_count=3,
                max_ciphertext_work_bytes=3,
                max_inflated_work_bytes=1,
            ),
        )

    assert validation_calls == 3


def test_dynamic_opcode_candidates_reject_second_distinct_output_immediately(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recovered_opcodes: list[int] = []

    def recover_table(method: OmlxMethod, *_args: object, **_kwargs: object) -> object:
        opcode = method.instructions[0].opcode_id
        recovered_opcodes.append(opcode)
        return _dynamic_fixture_table_recovery(bytes((opcode,)))

    monkeypatch.setattr(recovery, "_recover_table", recover_table)
    monkeypatch.setattr(
        recovery,
        "decrypt_keyed_eaz_resource",
        lambda _encrypted, key, **_kwargs: bytes((key[0] - ord("k") + 1,)),
    )

    def select(
        table: tuple[tuple[int, str], ...],
        _child: bytes,
        **_kwargs: object,
    ) -> recovery._TerminalBinding:
        return _dynamic_fixture_binding(b"MZ" + table[0][1].encode("ascii"))

    monkeypatch.setattr(
        recovery,
        "_decode_table",
        lambda clear, **_kwargs: ((0, clear.hex()),),
    )
    monkeypatch.setattr(recovery, "_select_terminal_binding", select)

    with pytest.raises(recovery.OmlxTripledesError, match="dynamic_output_ambiguous"):
        recovery._recover_dynamic_outputs(
            _dynamic_fixture_method(),
            ({5: 1}, {5: 7}, {5: 15}),
            b"encrypted",
            {},
            b"child",
            entrypoint_token=0x06000001,
            deadline=10.0,
            clock=lambda: 0.0,
            work_budget=recovery._TerminalWorkBudget(),
        )

    assert recovered_opcodes == [1, 7]


@pytest.mark.parametrize(
    ("valid_clear", "expected_mode"),
    [(b"none", "none"), (b"xor16", "xor16")],
)
def test_dynamic_opcode_candidates_record_only_the_valid_mask_mode(
    monkeypatch: pytest.MonkeyPatch,
    valid_clear: bytes,
    expected_mode: str,
) -> None:
    base = _dynamic_fixture_table_recovery(b"none")
    monkeypatch.setattr(recovery, "_recover_table", lambda *_args, **_kwargs: base)
    monkeypatch.setattr(
        recovery,
        "decrypt_keyed_eaz_resource",
        lambda *_args, **_kwargs: b"xor16",
    )

    def decode(clear: bytes, **_kwargs: object) -> tuple[tuple[int, str], ...]:
        if clear != valid_clear:
            raise recovery.OmlxTripledesError("string_table_invalid")
        return ((0, valid_clear.decode("ascii")),)

    monkeypatch.setattr(recovery, "_decode_table", decode)
    monkeypatch.setattr(
        recovery,
        "_select_terminal_binding",
        lambda _table, _child, **_kwargs: _dynamic_fixture_binding(b"MZterminal"),
    )

    result = recovery._recover_dynamic_outputs(
        _dynamic_fixture_method(),
        ({5: 1},),
        b"encrypted",
        {},
        b"child",
        entrypoint_token=0x06000001,
        deadline=10.0,
        clock=lambda: 0.0,
        work_budget=recovery._TerminalWorkBudget(),
    )

    assert result.viable_candidate_count == 1
    assert result.viable_mapping_mode_candidate_count == 1
    assert result.key_mask_modes == (expected_mode,)


def test_dynamic_opcode_candidates_reject_distinct_mask_mode_outputs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    base = _dynamic_fixture_table_recovery(b"none")
    monkeypatch.setattr(recovery, "_recover_table", lambda *_args, **_kwargs: base)
    monkeypatch.setattr(
        recovery,
        "decrypt_keyed_eaz_resource",
        lambda *_args, **_kwargs: b"xor16",
    )
    monkeypatch.setattr(
        recovery,
        "_decode_table",
        lambda clear, **_kwargs: ((0, clear.decode("ascii")),),
    )
    monkeypatch.setattr(
        recovery,
        "_select_terminal_binding",
        lambda table, _child, **_kwargs: _dynamic_fixture_binding(
            b"MZ" + table[0][1].encode("ascii")
        ),
    )

    with pytest.raises(recovery.OmlxTripledesError, match="dynamic_output_ambiguous"):
        recovery._recover_dynamic_outputs(
            _dynamic_fixture_method(),
            ({5: 1},),
            b"encrypted",
            {},
            b"child",
            entrypoint_token=0x06000001,
            deadline=10.0,
            clock=lambda: 0.0,
            work_budget=recovery._TerminalWorkBudget(),
        )


def test_dynamic_opcode_candidates_reject_distinct_terminal_outputs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        recovery,
        "_recover_table",
        lambda method, *_args, **_kwargs: _dynamic_fixture_table_recovery(
            bytes([method.instructions[0].opcode_id])
        ),
    )
    monkeypatch.setattr(
        recovery,
        "_decode_table",
        lambda clear, **_kwargs: ((0, clear.hex()),),
    )
    monkeypatch.setattr(
        recovery,
        "_select_terminal_binding",
        lambda table, _child, **_kwargs: _dynamic_fixture_binding(
            b"MZ" + table[0][1].encode("ascii")
        ),
    )

    with pytest.raises(recovery.OmlxTripledesError, match="dynamic_output_ambiguous"):
        recovery._recover_dynamic_outputs(
            _dynamic_fixture_method(),
            ({5: 1}, {5: 7}),
            b"encrypted",
            {},
            b"child",
            entrypoint_token=0x06000001,
            deadline=10.0,
            clock=lambda: 0.0,
            work_budget=recovery._TerminalWorkBudget(),
        )


def test_dynamic_recovery_report_publishes_only_secret_hashes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw_method = _dynamic_fixture_method()
    key_base64 = base64.b64encode(bytes(range(16))).decode("ascii")
    iv_base64 = base64.b64encode(bytes(range(8))).decode("ascii")
    table_recovery = _dynamic_fixture_table_recovery(b"table")
    binding = recovery._TerminalBinding(
        key_offset=0,
        iv_offset=52,
        resource_name_offset=80,
        key_base64=key_base64,
        iv_base64=iv_base64,
        resource_name="payload.bin",
        ciphertext=b"ciphertext",
        payload=b"MZterminal",
    )
    dynamic = recovery._DynamicOmlxCandidate(
        resource_name="omlx.bin",
        resource_blob=b"omlx",
        raw_method0=raw_method,
        method1_token=0x06000096,
        dispatcher=recovery.OmlxDispatcherFingerprint(
            method_token=0x0600038A,
            switch_target_count=176,
            handlers=(),
        ),
        opcode_maps=({5: 1},),
    )
    output = recovery._RecoveredDynamicOutput(
        method0=raw_method,
        table_recovery=table_recovery,
        table=((0, key_base64), (52, iv_base64), (80, "payload.bin")),
        terminal_binding=binding,
        candidate_count=48,
        viable_candidate_count=4,
        viable_mapping_mode_candidate_count=4,
        key_mask_modes=("xor16",),
    )
    fake_pe = SimpleNamespace(
        net=SimpleNamespace(struct=SimpleNamespace(EntryPointTokenOrRva=0x06000001))
    )
    monkeypatch.setattr(recovery, "has_clr_metadata", lambda _data: True)
    monkeypatch.setattr(recovery, "_contained_parser_diagnostics", nullcontext)
    monkeypatch.setattr(recovery.dnfile, "dnPE", lambda **_kwargs: fake_pe)
    monkeypatch.setattr(recovery, "_metadata_row_count", lambda _pe: 1)
    monkeypatch.setattr(
        recovery,
        "_resource_blobs",
        lambda _pe: [("encrypted.bin", b"encrypted")],
    )
    monkeypatch.setattr(
        recovery,
        "recover_managed_eaz_resource",
        lambda *_args, **_kwargs: (
            {"status": "recovered_managed_resource"},
            [("managed-eaz-resource-pe", b"child")],
        ),
    )

    def fixed_missing(_resources: object, **_kwargs: object) -> object:
        raise recovery.OmlxTripledesError("omlx_candidate_missing")

    monkeypatch.setattr(recovery, "_find_omlx_candidate", fixed_missing)
    monkeypatch.setattr(
        recovery,
        "_find_dynamic_omlx_candidate",
        lambda *_args, **_kwargs: dynamic,
    )
    monkeypatch.setattr(
        recovery,
        "_find_bound_resource",
        lambda *_args, **_kwargs: (
            "encrypted.bin",
            b"encrypted",
            0x06000020,
            {"metadata_complete": True},
            {},
        ),
    )
    monkeypatch.setattr(
        recovery, "_verified_transform_recipes", lambda *_args, **_kwargs: {}
    )
    monkeypatch.setattr(
        recovery,
        "_recover_dynamic_outputs",
        lambda *_args, **_kwargs: output,
    )
    sink_verified = False
    deadline_checked_after_sink = False
    original_check_time = recovery._check_time

    def checked_time(deadline: float, clock: Callable[[], float]) -> None:
        nonlocal deadline_checked_after_sink
        if sink_verified:
            deadline_checked_after_sink = True
        original_check_time(deadline, clock)

    def verify_sink(*_args: object, **_kwargs: object) -> dict[str, int]:
        nonlocal sink_verified
        sink_verified = True
        return {
            "System.Security.Cryptography.TripleDES::Create": 1,
            "System.IO.Compression.GZipStream::.ctor": 1,
            "System.Reflection.Assembly::Load": 1,
        }

    monkeypatch.setattr(recovery, "_check_time", checked_time)
    monkeypatch.setattr(recovery, "_verify_sink_api_calls", verify_sink)

    report, artifacts = recovery.recover_managed_omlx_tripledes(b"MZparent")

    assert report["status"] == "recovered_managed_omlx_tripledes"
    assert artifacts == [("managed-omlx-tripledes-gzip-pe", b"MZterminal")]
    assert report["encrypted_string_table"]["selected_key_mask_modes"] == ["xor16"]
    assert report["encrypted_string_table"]["mask_material_published"] is False
    assert report["encrypted_string_table"]["raw_key_published"] is False
    assert report["encrypted_string_table"]["raw_iv_published"] is False
    assert deadline_checked_after_sink is True
    encoded = json.dumps(report, sort_keys=True)
    assert key_base64 not in encoded
    assert iv_base64 not in encoded
    assert bytes(range(16)).hex() not in encoded
    assert bytes(range(8)).hex() not in encoded
    assert (b"m" * 16).hex() not in encoded


@pytest.mark.parametrize(
    "malformed",
    [b"", struct.pack("<i", 3) + b"a\0", struct.pack("<i", -2)],
)
def test_string_table_rejects_empty_truncated_or_negative_records(
    malformed: bytes,
) -> None:
    with pytest.raises(recovery.OmlxTripledesError):
        recovery._decode_table(
            malformed,
            deadline=10.0,
            clock=lambda: 0.0,
        )
