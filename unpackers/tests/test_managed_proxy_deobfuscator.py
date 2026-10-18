"""managed動的プロキシ静的復号器のテスト。"""

from __future__ import annotations

import struct
import time
from types import SimpleNamespace

import pytest

from unpackers import managed_proxy_deobfuscator as proxy
from unpackers.managed_proxy_deobfuscator import (
    _modsquare_initializer_digest,
    _modsquare_initializer_recipe,
    _normalized_control_flow,
    _validate_modsquare_proxy_records,
    analyze_proxy_resources,
    decrypt_eaz_proxy_modsquare_table,
    decrypt_eaz_proxy_table,
    parse_modsquare_proxy_records,
    parse_proxy_records,
    resource_summary,
)


def _clear_table() -> bytes:
    records = [(0x04000100 + index, 0x06000100 + index) for index in range(8)]
    records.append((0x04000108, 0x46000108))
    return b"".join(struct.pack("<II", *record) for record in records)


def test_proxy_transform_is_symmetric_and_records_are_valid() -> None:
    clear = _clear_table()
    encrypted = decrypt_eaz_proxy_table(clear)
    assert decrypt_eaz_proxy_table(encrypted) == clear
    records = parse_proxy_records(clear)
    assert all(record["valid"] for record in records)
    assert records[-1]["call_kind"] == "callvirt"
    assert records[-1]["target_token"] == "0x06000108"


def test_modsquare_proxy_transform_is_symmetric() -> None:
    clear = _clear_table()
    constants = (1_760_565_385, 837_265_500, 800_528_157, 1_555_124_663)
    encrypted = decrypt_eaz_proxy_modsquare_table(clear, constants=constants)
    assert encrypted != clear
    assert decrypt_eaz_proxy_modsquare_table(encrypted, constants=constants) == clear
    assert all(record["valid"] for record in parse_modsquare_proxy_records(clear))


def test_modsquare_proxy_records_reject_reserved_bit_and_duplicates() -> None:
    reserved = struct.pack("<II", 0x04000001, 0x86000001) * 8
    records = parse_modsquare_proxy_records(reserved)
    assert not all(record["valid"] for record in records)
    assert "reserved_target_flag_set" in records[0]["invalid_reasons"]
    assert "duplicate_field_mapping" in records[0]["invalid_reasons"]


def _instruction(
    opcode: str = "nop",
    *,
    local: int | None = None,
    integer: int | None = None,
    token: int | None = None,
    resolved: str = "",
    user_string: str | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        opcode=opcode,
        local=local,
        integer=integer,
        token=token,
        resolved=resolved,
        user_string=user_string,
    )


def _synthetic_initializer(local_base: int = 0) -> SimpleNamespace:
    instructions = [_instruction() for _ in range(624)]
    for index, value in zip(
        (151, 153, 155, 157),
        (1_760_565_385, 837_265_500, 800_528_157, 1_555_124_663),
        strict=True,
    ):
        instructions[index] = _instruction("ldc.i4", integer=value)
        instructions[index + 1] = _instruction("stloc", local=local_base + index)
    for index, api in enumerate(sorted(proxy._MODSQUARE_REQUIRED_APIS)):
        instructions[index] = _instruction(
            "call",
            token=0x0A000001 + index,
            resolved=api,
        )
    instructions[20] = _instruction("ldstr", user_string="synthetic.resource")
    return SimpleNamespace(
        token=0x06000100,
        name="initializer",
        rva=1,
        body_size=1_712,
        body_sha256="0" * 64,
        is_static=True,
        signature=proxy._MODSQUARE_INITIALIZER_SIGNATURE,
        instructions=tuple(instructions),
    )


def _initializer_body_details() -> dict[str, object]:
    return {
        "control_flow_sha256": proxy._MODSQUARE_INITIALIZER_CONTROL_FLOW_SHA256,
        "exception_handler_count": 3,
        "has_extra_sections": True,
        "header_size": 12,
        "code_size": 1_624,
    }


def _cctor_body_details() -> dict[str, object]:
    return {
        "control_flow_sha256": "0" * 64,
        "exception_handler_count": 0,
        "has_extra_sections": False,
        "header_size": 1,
        "code_size": 11,
    }


def test_modsquare_initializer_extracts_only_four_build_constants(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    method = _synthetic_initializer()
    digest = _modsquare_initializer_digest(method)
    monkeypatch.setattr(proxy, "_MODSQUARE_INITIALIZER_CANONICAL_SHA256", digest)
    recipe = _modsquare_initializer_recipe(
        method,
        body_details=_initializer_body_details(),
    )
    assert recipe is not None
    assert recipe["constants"] == (
        1_760_565_385,
        837_265_500,
        800_528_157,
        1_555_124_663,
    )
    assert recipe["resource_literal"] == "synthetic.resource"
    renumbered = _synthetic_initializer(local_base=10_000)
    assert _modsquare_initializer_digest(renumbered) == digest

    changed = _initializer_body_details()
    changed["control_flow_sha256"] = "f" * 64
    assert _modsquare_initializer_recipe(method, body_details=changed) is None


def _raw_instruction(
    name: str,
    operand_type: object,
    offset: int,
    size: int,
    operand: object = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        opcode=SimpleNamespace(name=name, operand_type=operand_type),
        offset=offset,
        size=size,
        operand=operand,
    )


def test_modsquare_control_flow_binds_branch_and_switch_targets() -> None:
    branch = SimpleNamespace(
        header_size=0,
        code_size=5,
        instructions=(
            _raw_instruction("br.s", proxy.OperandType.ShortInlineBrTarget, 0, 2, 4),
            _raw_instruction("nop", proxy.OperandType.InlineNone, 2, 1),
            _raw_instruction("nop", proxy.OperandType.InlineNone, 3, 1),
            _raw_instruction("ret", proxy.OperandType.InlineNone, 4, 1),
        ),
    )
    redirected = SimpleNamespace(
        **{
            **vars(branch),
            "instructions": (*branch.instructions[:1], *branch.instructions[1:]),
        }
    )
    redirected.instructions = (
        _raw_instruction("br.s", proxy.OperandType.ShortInlineBrTarget, 0, 2, 3),
        *branch.instructions[1:],
    )
    assert _normalized_control_flow(branch) != _normalized_control_flow(redirected)

    switch = SimpleNamespace(
        header_size=0,
        code_size=15,
        instructions=(
            _raw_instruction("switch", proxy.OperandType.InlineSwitch, 0, 13, [13, 14]),
            _raw_instruction("nop", proxy.OperandType.InlineNone, 13, 1),
            _raw_instruction("ret", proxy.OperandType.InlineNone, 14, 1),
        ),
    )
    reordered = SimpleNamespace(
        **{
            **vars(switch),
            "instructions": (
                _raw_instruction(
                    "switch", proxy.OperandType.InlineSwitch, 0, 13, [14, 13]
                ),
                *switch.instructions[1:],
            ),
        }
    )
    assert _normalized_control_flow(switch) != _normalized_control_flow(reordered)


class _ResolvedMetadata:
    def coverage(self) -> dict[str, bool]:
        return {"complete": True}

    def resolve(self, _token: int, *, kind: str = "method") -> dict[str, str]:
        return {"status": "resolved", "kind": kind}


class _IncompleteMetadata(_ResolvedMetadata):
    def coverage(self) -> dict[str, bool]:
        return {"complete": False}


def _strict_proxy_model() -> tuple[SimpleNamespace, list[SimpleNamespace], list[dict]]:
    field_rows = [
        SimpleNamespace(Flags=SimpleNamespace(fdStatic=True)) for _ in range(8)
    ]
    type_rows = [
        SimpleNamespace(FieldList=[SimpleNamespace(row_index=index)])
        for index in range(1, 9)
    ]
    method_rows = [
        SimpleNamespace(Flags=SimpleNamespace(mdStatic=False)) for _ in range(8)
    ]
    tables = SimpleNamespace(
        Field=SimpleNamespace(rows=field_rows),
        TypeDef=SimpleNamespace(rows=type_rows),
        MethodDef=SimpleNamespace(rows=method_rows),
        MemberRef=SimpleNamespace(rows=[]),
    )
    pe = SimpleNamespace(net=SimpleNamespace(mdtables=tables))
    initializer = 0x06000100
    methods = []
    for index in range(1, 9):
        owner = 0x02000000 | index
        field = 0x04000000 | index
        methods.append(
            SimpleNamespace(
                name=".cctor",
                rva=index,
                body_size=12,
                owner_token=owner,
                signature=b"\x00\x00\x01",
                is_static=True,
                is_special_name=True,
                is_runtime_special_name=True,
                instructions=(
                    _instruction("ldtoken", token=owner),
                    _instruction("call", token=initializer),
                    _instruction("ret"),
                ),
            )
        )
        methods.append(
            SimpleNamespace(
                name="use",
                owner_token=owner,
                instructions=(_instruction("ldsfld", token=field),),
            )
        )
    clear = b"".join(
        struct.pack("<II", 0x04000000 | index, 0x46000000 | index)
        for index in range(1, 9)
    )
    return pe, methods, parse_modsquare_proxy_records(clear)


def test_modsquare_record_validation_requires_owner_cctor_and_use_site(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        proxy, "_method_body_details", lambda *_args: _cctor_body_details()
    )
    pe, methods, records = _strict_proxy_model()
    result = _validate_modsquare_proxy_records(
        b"synthetic-managed-pe",
        pe,
        methods,
        0x06000100,
        records,
        _ResolvedMetadata(),
        deadline=time.monotonic() + 1,
        clock=time.monotonic,
    )
    assert result == {
        "field_count": 8,
        "target_count": 8,
        "owner_cctor_count": 8,
        "used_field_count": 8,
        "ldsfld_use_count": 8,
        "call_count": 0,
        "callvirt_count": 8,
    }

    methods[0].instructions = (_instruction("ret"),)
    with pytest.raises(ValueError, match="proxy_owner_cctor_shape_mismatch"):
        _validate_modsquare_proxy_records(
            b"synthetic-managed-pe",
            pe,
            methods,
            0x06000100,
            records,
            _ResolvedMetadata(),
            deadline=time.monotonic() + 1,
            clock=time.monotonic,
        )

    pe, methods, records = _strict_proxy_model()
    methods[0].is_runtime_special_name = False
    with pytest.raises(ValueError, match="proxy_owner_cctor_shape_mismatch"):
        _validate_modsquare_proxy_records(
            b"synthetic-managed-pe",
            pe,
            methods,
            0x06000100,
            records,
            _ResolvedMetadata(),
            deadline=time.monotonic() + 1,
            clock=time.monotonic,
        )

    pe, methods, records = _strict_proxy_model()
    monkeypatch.setattr(
        proxy,
        "_method_body_details",
        lambda *_args: {**_cctor_body_details(), "has_extra_sections": True},
    )
    with pytest.raises(ValueError, match="proxy_owner_cctor_body_mismatch"):
        _validate_modsquare_proxy_records(
            b"synthetic-managed-pe",
            pe,
            methods,
            0x06000100,
            records,
            _ResolvedMetadata(),
            deadline=time.monotonic() + 1,
            clock=time.monotonic,
        )


def _synthetic_profile_inputs(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[SimpleNamespace, list[SimpleNamespace], bytes]:
    pe, methods, records = _strict_proxy_model()
    initializer = _synthetic_initializer()
    digest = _modsquare_initializer_digest(initializer)
    monkeypatch.setattr(proxy, "_MODSQUARE_INITIALIZER_CANONICAL_SHA256", digest)
    monkeypatch.setattr(
        proxy,
        "_normalize_methods",
        lambda *_args: [initializer, *methods],
    )
    monkeypatch.setattr(
        proxy,
        "_method_body_details",
        lambda _data, _pe, method: (
            _cctor_body_details()
            if getattr(method, "name", None) == ".cctor"
            else _initializer_body_details()
        ),
    )
    clear = b"".join(
        struct.pack(
            "<II",
            int(record["field_token"], 16),
            int(record["target_token"], 16) | 0x40000000,
        )
        for record in records
    )
    constants = (1_760_565_385, 837_265_500, 800_528_157, 1_555_124_663)
    return (
        pe,
        methods,
        decrypt_eaz_proxy_modsquare_table(
            clear,
            constants=constants,
        ),
    )


def test_modsquare_profile_requires_unique_resource_and_complete_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pe, _methods, encrypted = _synthetic_profile_inputs(monkeypatch)
    resources = [("synthetic.resource", encrypted)]
    matched = proxy._analyze_modsquare_proxy_profile_resources(
        b"synthetic-managed-pe",
        pe,
        resources,
        _ResolvedMetadata(),
    )
    assert matched["status"] == "matched"
    assert matched["candidate_count"] == 1
    assert matched["raw_resource_name_published"] is False
    candidate = matched["candidates"][0]
    assert candidate["build_constants_returned"] is False
    assert "build_constants" not in candidate

    duplicate = proxy._analyze_modsquare_proxy_profile_resources(
        b"synthetic-managed-pe",
        pe,
        resources * 2,
        _ResolvedMetadata(),
    )
    assert duplicate["status"] == "rejected"
    assert duplicate["reason"] == "initializer_resource_ambiguous_or_missing"

    incomplete = proxy._analyze_modsquare_proxy_profile_resources(
        b"synthetic-managed-pe",
        pe,
        resources,
        _IncompleteMetadata(),
    )
    assert incomplete["status"] == "partial_budget"
    assert incomplete["reason"] == "proxy_record_metadata_incomplete"


def test_modsquare_public_profile_requires_source_bound_complete_inventory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pe, _methods, encrypted = _synthetic_profile_inputs(monkeypatch)
    resources = [("synthetic.resource", encrypted)]
    complete = SimpleNamespace(
        coverage=lambda: {
            "inventory_complete": True,
            "embedded_scan_complete": True,
            "input_binding_verified": True,
            "work": {"shared_snapshot_reused": True},
        }
    )
    monkeypatch.setattr(
        proxy,
        "_resource_blob_scope",
        lambda _data, _pe, *, resource_scan: (resources, complete),
    )
    matched = proxy.analyze_modsquare_proxy_profile(
        b"synthetic-managed-pe",
        pe,
        object(),
        _ResolvedMetadata(),
    )
    assert matched["status"] == "matched"
    assert matched["source_coverage_verified"] is True

    incomplete = SimpleNamespace(
        coverage=lambda: {
            "inventory_complete": False,
            "embedded_scan_complete": False,
            "input_binding_verified": True,
            "work": {"shared_snapshot_reused": True},
        }
    )
    monkeypatch.setattr(
        proxy,
        "_resource_blob_scope",
        lambda _data, _pe, *, resource_scan: (resources, incomplete),
    )
    rejected = proxy.analyze_modsquare_proxy_profile(
        b"synthetic-managed-pe",
        pe,
        object(),
        _ResolvedMetadata(),
    )
    assert rejected["status"] == "partial_budget"
    assert rejected["candidate_count"] == 0
    assert rejected["source_coverage_verified"] is False


def test_modsquare_profile_reports_resource_quota_and_transform_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pe, _methods, encrypted = _synthetic_profile_inputs(monkeypatch)
    resources = [("noise", b"\0" * 8)] * (proxy.MAX_RESOURCE_COUNT + 1)
    quota = proxy._analyze_modsquare_proxy_profile_resources(
        b"synthetic-managed-pe",
        pe,
        resources,
        _ResolvedMetadata(),
    )
    assert quota["status"] == "partial_budget"
    assert quota["reason"] == "resource_count_limit"

    ticks = iter((0.0, 2.0))
    with pytest.raises(TimeoutError, match="managed_proxy_profile_deadline_exceeded"):
        decrypt_eaz_proxy_modsquare_table(
            encrypted,
            constants=(1_760_565_385, 837_265_500, 800_528_157, 1_555_124_663),
            clock=lambda: next(ticks),
            max_elapsed_seconds=1.0,
        )


def test_analyze_proxy_resources_selects_only_consistent_candidate() -> None:
    clear = _clear_table()
    report = analyze_proxy_resources(
        [("noise", b"A" * 72), ("proxy.data", decrypt_eaz_proxy_table(clear))],
        include_records=True,
    )
    assert report["status"] == "matched"
    assert report["profile"] == "eazfuscator_dynamic_proxy_multi_variant"
    candidate = report["candidates"][0]
    assert candidate["transform_profile"] == "eazfuscator_dynamic_proxy_v1"
    assert candidate["record_count"] == 9
    assert candidate["valid_record_ratio"] == 1.0
    assert candidate["callvirt_count"] == 1


def test_analyze_proxy_resources_supports_second_transform_variant() -> None:
    clear = _clear_table()
    encrypted = decrypt_eaz_proxy_table(clear, seed=1_039_778_284, addend=1_651_518_254)
    assert (
        decrypt_eaz_proxy_table(
            encrypted,
            seed=1_039_778_284,
            addend=1_651_518_254,
        )
        == clear
    )
    report = analyze_proxy_resources(
        [("proxy-v2.data", encrypted)], include_records=True
    )
    assert report["status"] == "matched"
    candidate = report["candidates"][0]
    assert candidate["transform_profile"] == "eazfuscator_dynamic_proxy_v2"
    assert candidate["record_count"] == 9
    assert candidate["valid_record_ratio"] == 1.0


def test_analyze_proxy_resources_supports_third_transform_variant() -> None:
    clear = _clear_table()
    encrypted = decrypt_eaz_proxy_table(
        clear,
        seed=305_765_753,
        addend=489_775_852,
    )
    assert (
        decrypt_eaz_proxy_table(
            encrypted,
            seed=305_765_753,
            addend=489_775_852,
        )
        == clear
    )
    report = analyze_proxy_resources(
        [("proxy-v3.data", encrypted)],
        include_records=True,
    )
    assert report["status"] == "matched"
    candidate = report["candidates"][0]
    assert candidate["transform_profile"] == "eazfuscator_dynamic_proxy_v3"
    assert candidate["record_count"] == 9
    assert candidate["valid_record_ratio"] == 1.0


def test_analyze_proxy_resources_accepts_bounded_static_recipe_transform() -> None:
    clear = _clear_table()
    seed, addend = 659_796_207, 957_243_902
    encrypted = decrypt_eaz_proxy_table(clear, seed=seed, addend=addend)
    report = analyze_proxy_resources(
        [("proxy-derived.data", encrypted)],
        transforms=(
            {
                "profile": "eazfuscator_dynamic_proxy_derived_static_recipe",
                "seed": seed,
                "addend": addend,
            },
        ),
    )
    assert report["status"] == "matched"
    assert report["candidates"][0]["transform_profile"] == (
        "eazfuscator_dynamic_proxy_derived_static_recipe"
    )


def test_oversized_non_proxy_resource_is_negative_not_partial() -> None:
    """全既知変換で先頭recordが不正な大容量resourceは適用外とする。"""

    report = analyze_proxy_resources(
        [("bitmap.resources", b"\0" * ((proxy.MAX_PROXY_RECORDS + 1) * 8))],
        metadata_resolver=_ResolvedMetadata(),
    )

    assert report["status"] == "not_matched"
    assert report["budget_exhausted"] == []


def test_oversized_proxy_prefix_remains_partial() -> None:
    """proxy構造が成立する大容量resourceの未走査は隠さない。"""

    clear_prefix = _clear_table()[:64]
    encrypted_prefix = decrypt_eaz_proxy_table(clear_prefix)
    oversized = encrypted_prefix + b"\0" * (
        (proxy.MAX_PROXY_RECORDS + 1) * 8 - len(encrypted_prefix)
    )

    report = analyze_proxy_resources(
        [("proxy.data", oversized)],
        metadata_resolver=_ResolvedMetadata(),
    )

    assert report["status"] == "partial_budget"
    assert report["budget_exhausted"] == ["proxy_records"]


@pytest.mark.parametrize(
    "transform",
    [
        {},
        {"profile": "", "seed": 1, "addend": 2},
        {"profile": "x", "seed": -1, "addend": 2},
        {"profile": "x", "seed": 1, "addend": 1 << 32},
        {"profile": "x", "seed": True, "addend": 2},
    ],
)
def test_proxy_transform_inputs_fail_closed(transform) -> None:
    with pytest.raises(ValueError):
        analyze_proxy_resources([("data", b"A" * 64)], transforms=(transform,))


@pytest.mark.parametrize("value", [b"", b"123", b"12345678x"])
def test_invalid_proxy_table_length_is_rejected(value: bytes) -> None:
    with pytest.raises(ValueError):
        parse_proxy_records(value)


def test_resource_summary_flags_high_entropy_candidate() -> None:
    report = resource_summary("protected.bin", bytes(range(256)) * 4)
    assert report["size"] == 1024
    assert report["entropy"] == 8.0
    assert report["protected_candidate"] is True


def test_resource_summary_does_not_flag_repetitive_data() -> None:
    report = resource_summary("plain.bin", b"A" * 1024)
    assert report["entropy"] == 0.0
    assert report["protected_candidate"] is False
