"""managed CIL CFGとPureRAT semantic evidenceを人工命令だけで検証する。"""

from __future__ import annotations

from types import SimpleNamespace

import unpackers.managed_purerat_cache_frontend as cache_frontend
from unpackers import managed_cil_cfg
from unpackers.managed_cil_cfg import (
    CilInstruction,
    CilMethod,
    analyze_byte_array_sink_reaching_definitions,
    analyze_purerat_method_semantics,
    build_bounded_cfg,
    classify_exact_constant_proxy,
    fold_exact_branch,
    fold_metadata_public_key_null_branch,
    verify_length_prefixed_utf16_cache_shape,
)


def ins(offset: int, opcode: str, **values) -> CilInstruction:
    return CilInstruction(offset=offset, opcode=opcode, **values)


def method(token: int, instructions: list[CilInstruction]) -> CilMethod:
    return CilMethod(
        token=token,
        owner="Synthetic.Type",
        name=f"m_{token:08x}",
        body_sha256=f"{token:064x}"[-64:],
        instructions=tuple(instructions),
    )


def test_cfg_preserves_switch_targets_and_fallthrough() -> None:
    cfg = build_bounded_cfg(
        (
            ins(0, "ldc.i4.0", integer=0),
            ins(1, "switch", switch_targets=(10, 20)),
            ins(2, "ret"),
            ins(10, "ret"),
            ins(20, "ret"),
        )
    )

    assert cfg["status"] == "complete"
    assert cfg["branch_operands_preserved"] is True
    assert cfg["branch_target_count"] == 2
    assert cfg["unique_branch_target_count"] == 2
    assert {edge["kind"] for edge in cfg["edges"]} == {
        "switch",
        "switch_default",
    }
    assert [edge["switch_index"] for edge in cfg["edges"] if edge["kind"] == "switch"] == [0, 1]


def test_cfg_rejects_non_instruction_branch_target() -> None:
    cfg = build_bounded_cfg(
        (
            ins(0, "br", branch_target=99),
            ins(1, "ret"),
        )
    )

    assert cfg["status"] == "rejected"
    assert cfg["reason"] == "branch_target_not_instruction_boundary"
    assert cfg["invalid_targets"] == [99]


def test_cfg_rejects_branch_without_preserved_operand() -> None:
    cfg = build_bounded_cfg((ins(0, "brtrue"), ins(1, "ret")))

    assert cfg["status"] == "rejected"
    assert cfg["reason"] == "branch_operand_missing"


def test_constant_proxy_acceptance_is_exact() -> None:
    true_proxy = method(
        0x06000001,
        [ins(0, "ldnull"), ins(1, "ldnull"), ins(2, "ceq"), ins(3, "ret")],
    )
    false_proxy = method(0x06000002, [ins(0, "ldnull"), ins(1, "ret")])
    side_effect = method(
        0x06000003,
        [
            ins(0, "ldnull"),
            ins(1, "call", resolved="System.Console::WriteLine"),
            ins(2, "ret"),
        ],
    )

    assert classify_exact_constant_proxy(true_proxy) == "constant_true"
    assert classify_exact_constant_proxy(false_proxy) == "constant_false"
    assert classify_exact_constant_proxy(side_effect) is None
    assert fold_exact_branch("brtrue", "constant_true") is True
    assert fold_exact_branch("brfalse", "constant_false") is True
    assert fold_exact_branch("beq", "constant_true") is None
    assert fold_metadata_public_key_null_branch("brtrue", "absent") is True
    assert fold_metadata_public_key_null_branch("brfalse", "present") is True
    assert fold_metadata_public_key_null_branch("brtrue", "ambiguous") is None


def _array_sink_method(conflict: bool = False) -> CilMethod:
    instructions = [
        ins(0, "newobj", resolved="System.Security.Cryptography.AesCryptoServiceProvider::.ctor"),
        ins(1, "ldc.i4.2", integer=2),
        ins(2, "newarr", resolved="System.Byte"),
        ins(3, "stloc.0", local=0),
        ins(4, "ldloc.0", local=0),
        ins(5, "ldc.i4.0", integer=0),
        ins(6, "ldc.i4.s", integer=11),
        ins(7, "stelem.i1"),
        ins(8, "ldloc.0", local=0),
        ins(9, "ldc.i4.1", integer=1),
        ins(10, "ldc.i4.s", integer=22),
        ins(11, "stelem.i1"),
    ]
    if conflict:
        instructions.extend(
            [
                ins(12, "ldloc.0", local=0),
                ins(13, "ldc.i4.1", integer=1),
                ins(14, "ldc.i4.s", integer=23),
                ins(15, "stelem.i1"),
            ]
        )
        base = 16
    else:
        base = 12
    instructions.extend(
        [
            ins(base, "ldc.i4.2", integer=2),
            ins(base + 1, "newarr", resolved="System.Byte"),
            ins(base + 2, "stloc.1", local=1),
            ins(base + 3, "ldloc.1", local=1),
            ins(base + 4, "ldc.i4.0", integer=0),
            ins(base + 5, "ldc.i4.s", integer=33),
            ins(base + 6, "stelem.i1"),
            ins(base + 7, "ldloc.1", local=1),
            ins(base + 8, "ldc.i4.1", integer=1),
            ins(base + 9, "ldc.i4.s", integer=44),
            ins(base + 10, "stelem.i1"),
            ins(base + 11, "ldloc.0", local=0),
            ins(base + 12, "ldloc.1", local=1),
            ins(
                base + 13,
                "callvirt",
                resolved="System.Security.Cryptography.SymmetricAlgorithm::CreateDecryptor",
            ),
            ins(base + 14, "ret"),
        ]
    )
    return method(0x06000020, instructions)


def test_reaching_definition_requires_complete_unique_array_writes() -> None:
    result = analyze_byte_array_sink_reaching_definitions(
        _array_sink_method(),
        required_lengths=(2, 2),
    )

    assert result["status"] == "recovered"
    assert result["sink"]["kind"] == "create_decryptor"
    assert all(item["complete_unique_write_set"] for item in result["sink"]["arrays"])
    assert all(item["sha256"] for item in result["sink"]["arrays"])
    assert result["raw_array_values_published"] is False


def test_reaching_definition_rejects_conflicting_write() -> None:
    result = analyze_byte_array_sink_reaching_definitions(
        _array_sink_method(conflict=True),
        required_lengths=(2, 2),
    )

    assert result["status"] == "rejected"
    assert result["reason"] == "byte_array_sink_binding_missing"
    assert any(item["conflicting_index_count"] == 1 for item in result["arrays"])


def test_reaching_definition_rejects_duplicate_same_value_write() -> None:
    sample = _array_sink_method()
    instructions = list(sample.instructions)
    insertion = [
        ins(12, "ldloc.0", local=0),
        ins(13, "ldc.i4.1", integer=1),
        ins(14, "ldc.i4.s", integer=22),
        ins(15, "stelem.i1"),
    ]
    shifted = [
        CilInstruction(
            offset=item.offset + 4,
            opcode=item.opcode,
            token=item.token,
            resolved=item.resolved,
            integer=item.integer,
            local=item.local,
            user_string_sha256=item.user_string_sha256,
            user_string_length=item.user_string_length,
            branch_target=item.branch_target,
            switch_targets=item.switch_targets,
        )
        for item in instructions[12:]
    ]
    duplicate = method(sample.token, instructions[:12] + insertion + shifted)

    result = analyze_byte_array_sink_reaching_definitions(
        duplicate,
        required_lengths=(2, 2),
    )

    assert result["status"] == "rejected"
    assert any(item["duplicate_write_index_count"] == 1 for item in result["arrays"])


def test_length_prefixed_utf16_cache_shape_is_order_sensitive() -> None:
    cache = method(
        0x06000030,
        [
            ins(0, "callvirt", resolved="System.Reflection.Assembly::GetManifestResourceStream"),
            ins(1, "call", token=0x06000031, resolved="Synthetic.Decoder::Transform"),
            ins(2, "call", resolved="System.BitConverter::ToInt32"),
            ins(3, "call", resolved="System.Array::Copy"),
            ins(4, "call", resolved="System.Text.Encoding::get_Unicode"),
            ins(5, "callvirt", resolved="System.Text.Encoding::GetString"),
            ins(6, "callvirt", resolved="Synthetic.Cache::Add"),
            ins(7, "callvirt", resolved="Synthetic.OffsetCache::Add"),
            ins(8, "call", resolved="System.BitConverter::GetBytes"),
            ins(9, "call", resolved="System.Array::Copy"),
            ins(10, "ret"),
        ],
    )

    result = verify_length_prefixed_utf16_cache_shape(cache)

    assert result["status"] == "matched"
    assert result["resource_to_internal_decoder_call"] is True
    assert result["cache_prefix_rewrite_observed"] is True
    assert result["raw_strings_published"] is False


def test_purerat_semantics_are_corroboration_not_family_confirmation() -> None:
    entry = method(
        0x06000001,
        [
            ins(0, "call", token=0x06000010),
            ins(1, "call", token=0x06000011),
            ins(2, "ret"),
        ],
    )
    config = method(
        0x06000010,
        [
            ins(0, "call", resolved="System.Convert::FromBase64String"),
            ins(1, "newobj", resolved="System.Security.Cryptography.X509Certificates.X509Certificate2::.ctor"),
            ins(2, "call", resolved="System.Convert::FromBase64String"),
            ins(3, "call", token=0x06000020),
            ins(4, "castclass"),
            ins(5, "stsfld"),
            ins(6, "ret"),
        ],
    )
    tls = method(
        0x06000011,
        [
            ins(0, "callvirt", resolved="System.Net.Sockets.Socket::get_RemoteEndPoint"),
            ins(1, "newobj", resolved="System.Net.Sockets.NetworkStream::.ctor"),
            ins(2, "newobj", resolved="System.Net.Security.SslStream::.ctor"),
            ins(3, "call", resolved="System.Net.Security.SslStream::AuthenticateAsClient"),
            ins(4, "ret"),
        ],
    )
    deserialize = method(0x06000020, [ins(0, "ret")])

    result = analyze_purerat_method_semantics(
        [entry, config, tls, deserialize],
        entry_token=entry.token,
    )

    assert result["status"] == "matched"
    assert result["reason"] == "purerat_terminal_semantic_profile_correlated"
    assert result["family_corroboration_allowed"] is True
    assert result["family_confirmation_allowed"] is False
    assert result["c2_confirmation_allowed"] is False
    assert result["provider_or_protector_label_used"] is False


def test_purerat_semantics_do_not_match_without_tls_role() -> None:
    entry = method(0x06000001, [ins(0, "call", token=0x06000010), ins(1, "ret")])
    config = method(
        0x06000010,
        [
            ins(0, "call", resolved="System.Convert::FromBase64String"),
            ins(1, "newobj", resolved="System.Security.Cryptography.X509Certificates.X509Certificate2::.ctor"),
            ins(2, "call", resolved="System.Convert::FromBase64String"),
            ins(3, "call", token=0x06000020),
            ins(4, "castclass"),
            ins(5, "stsfld"),
            ins(6, "ret"),
        ],
    )

    result = analyze_purerat_method_semantics(
        [entry, config, method(0x06000020, [ins(0, "ret")])],
        entry_token=entry.token,
    )

    assert result["status"] == "not_matched"
    assert result["reason"] == "tls_transport_semantics_missing"
    assert result["family_corroboration_allowed"] is False


def test_purerat_dll_uses_one_unreferenced_root_for_both_roles() -> None:
    root = method(
        0x06000001,
        [ins(0, "call", token=0x06000010), ins(1, "call", token=0x06000011), ins(2, "ret")],
    )
    config = method(
        0x06000010,
        [
            ins(0, "call", resolved="System.Convert::FromBase64String"),
            ins(1, "newobj", resolved="System.Security.Cryptography.X509Certificates.X509Certificate2::.ctor"),
            ins(2, "call", resolved="System.Convert::FromBase64String"),
            ins(3, "call", token=0x06000020),
            ins(4, "castclass"),
            ins(5, "stsfld"),
            ins(6, "ret"),
        ],
    )
    tls = method(
        0x06000011,
        [
            ins(0, "callvirt", resolved="System.Net.Sockets.Socket::get_RemoteEndPoint"),
            ins(1, "newobj", resolved="System.Net.Sockets.NetworkStream::.ctor"),
            ins(2, "newobj", resolved="System.Net.Security.SslStream::.ctor"),
            ins(3, "callvirt", resolved="System.Net.Security.SslStream::AuthenticateAsClient"),
            ins(4, "ret"),
        ],
    )

    result = analyze_purerat_method_semantics(
        [root, config, tls, method(0x06000020, [ins(0, "ret")])],
        entry_token=None,
    )

    assert result["status"] == "matched"
    assert result["semantic_root_strategy"] == "unreferenced_internal_call_root"
    assert result["entry_reachable_config_initializers"] == []
    assert len(result["correlated_semantic_roots"]) == 1


def test_terminal_semantics_publish_only_sanitized_partial_cache_recovery(
    monkeypatch,
) -> None:
    program = SimpleNamespace(
        input_sha256="a" * 64,
        entry_token=None,
        assembly_public_key_state="absent",
        methods=(),
    )
    semantic = {
        "schema_version": 1,
        "status": "matched",
        "reason": "purerat_terminal_semantic_profile_correlated",
        "length_prefixed_utf16_cache_methods": [{"status": "matched"}],
        "family_corroboration_allowed": True,
        "family_confirmation_allowed": False,
        "c2_confirmation_allowed": False,
    }
    recovery = {
        "schema_version": 1,
        "status": "recovered_complete_managed_utf16_cache",
        "reason": "secondary_string_transform_not_recovered",
        "recipe": "real_cil_ordered_key_reverse_mask_eaz_complete_utf16_v1",
        "decoder": {
            "ordered_overwrite_semantics_verified": True,
            "reverse_mask_verified": True,
            "exact_16_iteration_key_xor_verified": True,
        },
        "transform": {"partial_word_profile_verified": True},
        "cache": {
            "complete_table_consumed": True,
            "complete_table_entry_count": 3,
        },
    }
    monkeypatch.setattr(managed_cil_cfg, "parse_managed_program", lambda _: program)
    monkeypatch.setattr(
        managed_cil_cfg,
        "analyze_purerat_method_semantics",
        lambda *args, **kwargs: dict(semantic),
    )
    monkeypatch.setattr(
        cache_frontend,
        "recover_managed_purerat_cache_frontend",
        lambda _: (recovery, ((0, "private-config-value"),)),
    )

    result = managed_cil_cfg.analyze_purerat_terminal_semantics(b"managed")

    summary = result["managed_utf16_cache_recovery"]
    assert summary["status"] == "recovered_complete_managed_utf16_cache"
    assert summary["reason"] == "secondary_string_transform_not_recovered"
    assert summary["complete_table_entry_count"] == 3
    assert summary["secondary_string_transform_recovered"] is False
    assert summary["strict_terminal_schema_confirmed"] is False
    assert summary["family_confirmation_allowed"] is False
    assert summary["c2_confirmation_allowed"] is False
    assert "private-config-value" not in repr(result)
