"""OMLX同一assembly ResourceSet復元経路の合成fixture回帰。"""

from __future__ import annotations

import base64
import gzip
import json
from contextlib import nullcontext
from types import SimpleNamespace

import pytest
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from malware.purehvnc.managed_resource_recovery import (
    Instruction,
    OmlxInstruction,
    OmlxMethod,
)

from unpackers import managed_omlx_direct_tripledes as recovery
from unpackers.managed_eaz_resource import RecoveryError
from unpackers.managed_omlx_tripledes import _TerminalWorkBudget


def _encrypt_terminal(payload: bytes, key: bytes, iv: bytes) -> bytes:
    clear = len(payload).to_bytes(4, "little", signed=True) + gzip.compress(
        payload, mtime=0
    )
    padder = padding.PKCS7(64).padder()
    padded = padder.update(clear) + padder.finalize()
    encryptor = Cipher(TripleDES(key), modes.CBC(iv)).encryptor()
    return encryptor.update(padded) + encryptor.finalize()


def _table(rows: list[object]) -> SimpleNamespace:
    return SimpleNamespace(num_rows=len(rows), rows=rows)


def _framework_member_fixture(
    *,
    namespace: str = "System.IO",
    owner: str = "Stream",
    member: str = "get_Length",
    signature: bytes = b"\x20\x00\x0a",
) -> tuple[SimpleNamespace, SimpleNamespace, SimpleNamespace]:
    """厳密なmscorlib AssemblyRefへ結ばれたMemberRef fixtureを作る。"""

    assembly = SimpleNamespace(
        Name="mscorlib",
        Culture="",
        PublicKey=SimpleNamespace(value=bytes.fromhex("b77a5c561934e089")),
        MajorVersion=4,
        MinorVersion=0,
        BuildNumber=0,
        RevisionNumber=0,
        struct=SimpleNamespace(Flags=0),
    )
    assembly_table = _table([assembly])
    type_row = SimpleNamespace(
        TypeNamespace=namespace,
        TypeName=owner,
        ResolutionScope=SimpleNamespace(table=assembly_table, row_index=1),
    )
    type_table = _table([type_row])
    member_row = SimpleNamespace(
        Name=member,
        Class=SimpleNamespace(table=type_table, row_index=1),
        Signature=SimpleNamespace(value=signature),
    )
    member_table = _table([member_row])
    pe = SimpleNamespace(
        net=SimpleNamespace(
            mdtables=SimpleNamespace(
                TypeRef=type_table,
                MemberRef=member_table,
                AssemblyRef=assembly_table,
            )
        )
    )
    return pe, type_row, member_row


def test_memberref_api_requires_reviewed_bcl_scope_and_complete_signature() -> None:
    """owner名だけでなくAssemblyRef identityと完全signatureを照合する。"""

    pe, _type_row, _member_row = _framework_member_fixture()

    assert recovery._memberref_api(pe, 0x0A000001) == ("System.IO.Stream::get_Length")


def test_memberref_api_resolves_reviewed_typeref_in_signature() -> None:
    """戻値TypeRefも同一のreview済みmscorlib identityへ結ぶ。"""

    pe, owner_row, member_row = _framework_member_fixture(
        owner="BinaryReader",
        member="get_BaseStream",
        signature=b"\x20\x00\x12\x09",
    )
    stream_row = SimpleNamespace(
        TypeNamespace="System.IO",
        TypeName="Stream",
        ResolutionScope=owner_row.ResolutionScope,
    )
    pe.net.mdtables.TypeRef.rows.append(stream_row)
    pe.net.mdtables.TypeRef.num_rows = 2
    member_row.Class.row_index = 1

    assert recovery._memberref_api(pe, 0x0A000001) == (
        "System.IO.BinaryReader::get_BaseStream"
    )


def test_memberref_api_rejects_declared_reference_row_budget_without_iteration() -> (
    None
):
    """過大な宣言行数はrows列挙前に拒否する。"""

    class Rows:
        def __iter__(self):
            raise AssertionError("宣言上限を超えたtableを列挙してはいけません")

    oversized = SimpleNamespace(
        num_rows=recovery.MAX_FRAMEWORK_REFERENCE_ROWS + 1,
        rows=Rows(),
    )
    pe = SimpleNamespace(
        net=SimpleNamespace(
            mdtables=SimpleNamespace(
                TypeRef=oversized,
                MemberRef=_table([]),
                AssemblyRef=_table([]),
            )
        )
    )

    assert recovery._memberref_api(pe, 0x0A000001) is None


def test_memberref_api_rejects_resolution_scope_spoof() -> None:
    """同じ行を持つ別table objectはAssemblyRef scopeとして受理しない。"""

    pe, type_row, _member_row = _framework_member_fixture()
    type_row.ResolutionScope = SimpleNamespace(
        table=_table(list(pe.net.mdtables.AssemblyRef.rows)),
        row_index=1,
    )

    assert recovery._memberref_api(pe, 0x0A000001) is None


def test_memberref_api_rejects_signature_mismatch() -> None:
    """同名APIでも戻値・引数が異なるMemberRefをrole証拠にしない。"""

    pe, _type_row, member_row = _framework_member_fixture()
    member_row.Signature.value = b"\x20\x00\x08"

    assert recovery._memberref_api(pe, 0x0A000001) is None


def test_memberref_api_rejects_unreviewed_assembly_identity() -> None:
    """private assembly内の同名TypeRef/MemberRefをBCL APIと誤認しない。"""

    pe, _type_row, _member_row = _framework_member_fixture()
    pe.net.mdtables.AssemblyRef.rows[0].Name = "private-framework"

    assert recovery._memberref_api(pe, 0x0A000001) is None


def test_helper_api_set_follows_short_wrapper_without_using_names(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """短いMethodDef wrapperをMemberRef API終端まで静的に追跡する。"""

    helper = 0x06000001
    member = 0x0A000001
    pe = SimpleNamespace(
        net=SimpleNamespace(
            mdtables=SimpleNamespace(
                MethodDef=SimpleNamespace(rows=[object()]),
            )
        )
    )
    monkeypatch.setattr(
        recovery,
        "_memberref_api",
        lambda _pe, token, **_kwargs: (
            "System.IO.Stream::get_Length" if token == member else None
        ),
    )
    monkeypatch.setattr(
        recovery,
        "_decode_method",
        lambda *_args, **_kwargs: SimpleNamespace(
            instructions=(
                Instruction(0, "ldarg.0"),
                Instruction(1, "callvirt", member),
                Instruction(2, "ret"),
            )
        ),
    )

    assert recovery._helper_api_set(
        b"fixture",
        pe,
        helper,
        deadline=10.0,
        clock=lambda: 0.0,
        cache={},
    ) == {"System.IO.Stream::get_Length"}


def test_helper_api_set_skips_one_unreachable_invalid_call_prefix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """entry branchで飛ばされる単一のinvalid callだけをwrapperから除外する。"""

    helper = 0x06000001
    member = 0x0A000001
    pe = SimpleNamespace(
        net=SimpleNamespace(
            mdtables=SimpleNamespace(
                MethodDef=SimpleNamespace(rows=[SimpleNamespace(Name="method")]),
            )
        )
    )
    monkeypatch.setattr(
        recovery,
        "_memberref_api",
        lambda _pe, token, **_kwargs: (
            "System.IO.BinaryReader::get_BaseStream" if token == member else None
        ),
    )
    monkeypatch.setattr(
        recovery,
        "_decode_method",
        lambda *_args, **_kwargs: SimpleNamespace(
            instructions=(
                Instruction(1, "br.s", 8),
                Instruction(3, "call", 0x5B123456),
                Instruction(8, "ldarg.0"),
                Instruction(9, "ldfld", 0x04000001),
                Instruction(14, "callvirt", member),
                Instruction(19, "ret"),
            )
        ),
    )

    assert recovery._helper_api_set(
        b"fixture",
        pe,
        helper,
        deadline=10.0,
        clock=lambda: 0.0,
        cache={},
    ) == {"System.IO.BinaryReader::get_BaseStream"}


@pytest.mark.parametrize(
    ("branch_target", "decoy_operand"),
    (
        (14, 0x5B123456),
        (8, 0x0A000002),
        (True, 0x5B123456),
    ),
)
def test_helper_api_set_rejects_unreviewed_branch_prefix(
    monkeypatch: pytest.MonkeyPatch,
    branch_target: int,
    decoy_operand: int,
) -> None:
    """別targetまたは有効metadata callを隠すprefixは除去しない。"""

    pe = SimpleNamespace(
        net=SimpleNamespace(
            mdtables=SimpleNamespace(
                MethodDef=SimpleNamespace(rows=[SimpleNamespace(Name="method")]),
            )
        )
    )
    monkeypatch.setattr(recovery, "_memberref_api", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        recovery,
        "_decode_method",
        lambda *_args, **_kwargs: SimpleNamespace(
            instructions=(
                Instruction(1, "br.s", branch_target),
                Instruction(3, "call", decoy_operand),
                Instruction(8, "ldarg.0"),
                Instruction(9, "ret"),
            )
        ),
    )

    with pytest.raises(recovery.DirectOmlxError, match="cil_shape_not_reviewed"):
        recovery._helper_api_set(
            b"fixture",
            pe,
            0x06000001,
            deadline=10.0,
            clock=lambda: 0.0,
            cache={},
        )


@pytest.mark.parametrize(
    ("extra_sections", "handler_count", "reason"),
    (
        (True, 0, "extra_section_not_reviewed"),
        (False, 1, "exception_handler_not_reviewed"),
    ),
)
def test_helper_api_set_rejects_exception_control_flow(
    monkeypatch: pytest.MonkeyPatch,
    extra_sections: bool,
    handler_count: int,
    reason: str,
) -> None:
    """例外sectionのあるhelperはdecoy callの到達不能性を仮定しない。"""

    pe = SimpleNamespace(
        net=SimpleNamespace(
            mdtables=SimpleNamespace(
                MethodDef=SimpleNamespace(rows=[SimpleNamespace(Name="method")]),
            )
        )
    )
    monkeypatch.setattr(recovery, "_memberref_api", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        recovery,
        "_decode_method",
        lambda *_args, **_kwargs: SimpleNamespace(
            instructions=(Instruction(0, "ret"),),
            has_extra_sections=extra_sections,
            exception_handler_count=handler_count,
        ),
    )

    with pytest.raises(recovery.DirectOmlxError, match=reason):
        recovery._helper_api_set(
            b"fixture",
            pe,
            0x06000001,
            deadline=10.0,
            clock=lambda: 0.0,
            cache={},
        )


def test_helper_api_set_rejects_calls_after_an_intermediate_return(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """中間ret後の到達不能APIをrole証拠へ数えない。"""

    object_ctor = 0x0A000001
    reader_ctor = 0x0A000002
    pe = SimpleNamespace(
        net=SimpleNamespace(
            mdtables=SimpleNamespace(
                MethodDef=SimpleNamespace(rows=[SimpleNamespace(Name=".ctor")]),
            )
        )
    )
    monkeypatch.setattr(
        recovery,
        "_memberref_api",
        lambda _pe, token, **_kwargs: {
            object_ctor: "System.Object::.ctor",
            reader_ctor: "System.IO.BinaryReader::.ctor",
        }.get(token),
    )
    monkeypatch.setattr(
        recovery,
        "_decode_method",
        lambda *_args, **_kwargs: SimpleNamespace(
            instructions=(
                Instruction(0, "ldarg.0"),
                Instruction(1, "call", object_ctor),
                Instruction(6, "ret"),
                Instruction(7, "ldarg.0"),
                Instruction(8, "newobj", reader_ctor),
                Instruction(13, "stfld", 0x04000001),
                Instruction(18, "ret"),
            )
        ),
    )

    with pytest.raises(recovery.DirectOmlxError, match="cil_shape_not_reviewed"):
        recovery._helper_api_set(
            b"fixture",
            pe,
            0x06000001,
            deadline=10.0,
            clock=lambda: 0.0,
            cache={},
        )


def test_helper_api_set_rejects_wrapper_with_unreviewed_side_effect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """field書込み以外の副作用を含むwrapperはfail-closedにする。"""

    pe = SimpleNamespace(
        net=SimpleNamespace(
            mdtables=SimpleNamespace(MethodDef=SimpleNamespace(rows=[object()]))
        )
    )
    monkeypatch.setattr(recovery, "_memberref_api", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        recovery,
        "_decode_method",
        lambda *_args, **_kwargs: SimpleNamespace(
            instructions=(Instruction(0, "stsfld", 0x04000001), Instruction(1, "ret"))
        ),
    )

    with pytest.raises(recovery.DirectOmlxError, match="cil_shape_not_reviewed"):
        recovery._helper_api_set(
            b"fixture",
            pe,
            0x06000001,
            deadline=10.0,
            clock=lambda: 0.0,
            cache={},
        )


def test_helper_api_set_rejects_duplicate_general_role_calls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """同じBCL APIを2回呼ぶ一般wrapperを単一roleへ縮約しない。"""

    member = 0x0A000001
    pe = SimpleNamespace(
        net=SimpleNamespace(
            mdtables=SimpleNamespace(
                MethodDef=SimpleNamespace(rows=[SimpleNamespace(Name="method")]),
            )
        )
    )
    monkeypatch.setattr(
        recovery,
        "_memberref_api",
        lambda _pe, token, **_kwargs: (
            "System.IO.Stream::get_Length" if token == member else None
        ),
    )
    monkeypatch.setattr(
        recovery,
        "_decode_method",
        lambda *_args, **_kwargs: SimpleNamespace(
            instructions=(
                Instruction(0, "ldarg.0"),
                Instruction(1, "callvirt", member),
                Instruction(6, "ldarg.0"),
                Instruction(7, "callvirt", member),
                Instruction(12, "ret"),
            )
        ),
    )

    with pytest.raises(recovery.DirectOmlxError, match="general_call_count"):
        recovery._helper_api_set(
            b"fixture",
            pe,
            0x06000001,
            deadline=10.0,
            clock=lambda: 0.0,
            cache={},
        )


def test_runtime_roles_are_derived_from_api_sets_not_fixed_rids(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """buildごとに異なるRIDをframework API終端と定数CILから導く。"""

    roles = list(recovery._ROLE_APIS.items())
    role_tokens = {role: 0x06000010 + index for index, (role, _) in enumerate(roles)}
    reader_ctor = 0x06000030
    transform_ctor = 0x06000031
    true_token = 0x06000032
    false_token = 0x06000033
    transform_token = 0x06000034
    all_tokens = [
        *role_tokens.values(),
        reader_ctor,
        transform_ctor,
        true_token,
        false_token,
        transform_token,
    ]
    method = OmlxMethod(
        method_index=0,
        metadata_token=0x06000001,
        type_count=0,
        exception_clause_count=0,
        type_descriptors=(),
        instructions=tuple(
            OmlxInstruction(index, index, 134, 1, token)
            for index, token in enumerate(all_tokens)
        ),
        exception_clauses=(),
    )
    rows = [SimpleNamespace(Name="method") for _ in range(0x34)]
    rows[(transform_ctor & 0xFFFFFF) - 1].Name = ".ctor"
    pe = SimpleNamespace(
        net=SimpleNamespace(
            mdtables=SimpleNamespace(MethodDef=SimpleNamespace(rows=rows))
        )
    )
    api_by_token = {role_tokens[role]: frozenset({api}) for role, api in roles}
    api_by_token[reader_ctor] = frozenset(
        {"System.Object::.ctor", "System.IO.BinaryReader::.ctor"}
    )
    api_by_token[transform_ctor] = frozenset({"System.Object::.ctor"})
    monkeypatch.setattr(
        recovery,
        "_helper_api_set",
        lambda _data, _pe, token, **_kwargs: api_by_token.get(token, frozenset()),
    )
    monkeypatch.setattr(
        recovery,
        "_method_owner_tokens",
        lambda _pe: {
            transform_ctor & 0xFFFFFF: 0x02000009,
            transform_token & 0xFFFFFF: 0x02000009,
        },
    )

    def decode(_data, _pe, _row, token, **_kwargs):
        if token == true_token:
            instructions = (
                Instruction(0, "ldnull"),
                Instruction(1, "ldnull"),
                Instruction(2, "ceq"),
                Instruction(3, "ret"),
            )
        elif token == false_token:
            instructions = (Instruction(0, "ldnull"), Instruction(1, "ret"))
        else:
            raise RecoveryError("not_constant")
        return SimpleNamespace(instructions=instructions)

    monkeypatch.setattr(recovery, "_decode_method", decode)

    result, evidence = recovery._discover_runtime_tokens(
        b"fixture",
        pe,
        method,
        {transform_token: object()},
        deadline=10.0,
        clock=lambda: 0.0,
    )

    assert {role: result[role] for role in role_tokens} == role_tokens
    assert result["reader_ctor"] == reader_ctor
    assert result["resource_transform_ctor"] == transform_ctor
    assert result["true"] == true_token
    assert result["false"] == false_token
    assert evidence["obfuscated_names_used"] is False


def test_runtime_role_helper_elapsed_error_is_a_hard_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """wrapper decodeの期限超過を候補不一致へ変換しない。"""

    method = OmlxMethod(
        method_index=0,
        metadata_token=0x06000002,
        type_count=0,
        exception_clause_count=0,
        type_descriptors=(),
        instructions=(OmlxInstruction(0, 0, 134, 1, 0x06000001),),
        exception_clauses=(),
    )
    monkeypatch.setattr(
        recovery,
        "_helper_api_set",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            RecoveryError("elapsed_time_limit")
        ),
    )

    with pytest.raises(recovery.OmlxTripledesError, match="elapsed_time_limit"):
        recovery._discover_runtime_tokens(
            b"fixture",
            object(),
            method,
            {},
            deadline=10.0,
            clock=lambda: 0.0,
        )


def test_runtime_role_helper_checks_deadline_after_candidate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """最後のwrapper候補処理中の期限超過もhard-limitにする。"""

    expired = False
    method = OmlxMethod(
        method_index=0,
        metadata_token=0x06000002,
        type_count=0,
        exception_clause_count=0,
        type_descriptors=(),
        instructions=(OmlxInstruction(0, 0, 134, 1, 0x06000001),),
        exception_clauses=(),
    )

    def inspect(*_args: object, **_kwargs: object) -> frozenset[str]:
        nonlocal expired
        expired = True
        return frozenset()

    monkeypatch.setattr(recovery, "_helper_api_set", inspect)

    with pytest.raises(recovery.OmlxTripledesError, match="elapsed_time_limit"):
        recovery._discover_runtime_tokens(
            b"fixture",
            object(),
            method,
            {},
            deadline=1.0,
            clock=lambda: 2.0 if expired else 0.0,
        )


def test_runtime_constant_elapsed_error_is_a_hard_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """定数wrapper decodeの期限超過をrole曖昧性へ変換しない。"""

    token = 0x06000001
    method = OmlxMethod(
        method_index=0,
        metadata_token=0x06000002,
        type_count=0,
        exception_clause_count=0,
        type_descriptors=(),
        instructions=(OmlxInstruction(0, 0, 134, 1, token),),
        exception_clauses=(),
    )
    pe = SimpleNamespace(
        net=SimpleNamespace(
            mdtables=SimpleNamespace(
                MethodDef=SimpleNamespace(rows=[SimpleNamespace(Name=".ctor")])
            )
        )
    )
    unique = iter(range(0x06000100, 0x06000200))
    monkeypatch.setattr(recovery, "_helper_api_set", lambda *_a, **_k: frozenset())
    monkeypatch.setattr(recovery, "_unique_token", lambda *_args: next(unique))
    monkeypatch.setattr(recovery, "_method_owner_tokens", lambda _pe: {1: 0x02000001})
    monkeypatch.setattr(
        recovery,
        "_decode_method",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            RecoveryError("elapsed_time_limit")
        ),
    )

    with pytest.raises(recovery.OmlxTripledesError, match="elapsed_time_limit"):
        recovery._discover_runtime_tokens(
            b"fixture",
            pe,
            method,
            {token: object()},
            deadline=10.0,
            clock=lambda: 0.0,
        )


def test_parent_resourceset_terminal_is_selected_through_full_recipe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """key/IV/resourceを推測せず暗号・圧縮・managed PEまで一意化する。"""

    key = bytes(range(1, 17))
    iv = bytes(range(21, 29))
    payload = b"MZ synthetic managed PE fixture"
    ciphertext = _encrypt_terminal(payload, key, iv)
    table = (
        (0, base64.b64encode(key).decode("ascii")),
        (64, base64.b64encode(iv).decode("ascii")),
        (96, "not-a-secret"),
    )
    monkeypatch.setattr(
        "unpackers.managed_omlx_tripledes._child_resource_entries",
        lambda *_args, **_kwargs: (("payload", ciphertext),),
    )
    monkeypatch.setattr(recovery, "has_clr_metadata", lambda value: value == payload)
    monkeypatch.setattr(
        recovery,
        "inspect_structural_pe_extent",
        lambda value, **_kwargs: SimpleNamespace(extent=len(value)),
    )

    selected = recovery._select_direct_terminal_binding(
        table,
        b"MZ parent",
        deadline=10.0,
        clock=lambda: 0.0,
        work_budget=_TerminalWorkBudget(),
    )

    assert selected.resource_name == "payload"
    assert selected.payload == payload
    assert selected.key_offset == 0
    assert selected.iv_offset == 64


def test_all_zero_key_reaches_crypto_validation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """全ゼロ16-byte値もtruthinessで候補列挙から脱落させない。"""

    attempted = False

    def reject_weak_key(*_args: object) -> bytes:
        nonlocal attempted
        attempted = True
        raise ValueError("weak key")

    monkeypatch.setattr(
        "unpackers.managed_omlx_tripledes._child_resource_entries",
        lambda *_args, **_kwargs: (("payload", b"ciphertext"),),
    )
    monkeypatch.setattr(
        recovery,
        "decrypt_tripledes_cbc_pkcs7_base64",
        reject_weak_key,
    )

    with pytest.raises(recovery.DirectOmlxError, match="binding_missing"):
        recovery._select_direct_terminal_binding(
            (
                (0, base64.b64encode(bytes(16)).decode("ascii")),
                (64, base64.b64encode(bytes(range(8))).decode("ascii")),
            ),
            b"MZ parent",
            deadline=10.0,
            clock=lambda: 0.0,
            work_budget=_TerminalWorkBudget(),
        )

    assert attempted is True


def test_direct_terminal_binding_preserves_inflated_work_hard_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """展開work上限を候補不一致として握りつぶさない。"""

    key = base64.b64encode(bytes(16)).decode("ascii")
    iv = base64.b64encode(bytes(8)).decode("ascii")
    monkeypatch.setattr(
        "unpackers.managed_omlx_tripledes._child_resource_entries",
        lambda *_args, **_kwargs: (("payload", b"ciphertext"),),
    )
    monkeypatch.setattr(
        recovery,
        "decrypt_tripledes_cbc_pkcs7_base64",
        lambda *_args: (64).to_bytes(4, "little", signed=True),
    )
    monkeypatch.setattr(
        recovery,
        "inflate_length_prefixed_gzip",
        lambda *_args, **_kwargs: pytest.fail("work上限後に展開してはいけません"),
    )

    with pytest.raises(recovery.OmlxTripledesError, match="inflated_work_limit"):
        recovery._select_direct_terminal_binding(
            ((0, key), (64, iv)),
            b"MZ parent",
            deadline=10.0,
            clock=lambda: 0.0,
            work_budget=_TerminalWorkBudget(max_inflated_work_bytes=16),
        )


def test_direct_terminal_binding_checks_deadline_after_decrypt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """復号中に期限を越えた候補を終端として採用しない。"""

    key = base64.b64encode(bytes(16)).decode("ascii")
    iv = base64.b64encode(bytes(8)).decode("ascii")
    decrypted = False

    def decrypt(*_args: object) -> bytes:
        nonlocal decrypted
        decrypted = True
        return (1).to_bytes(4, "little", signed=True) + b"x"

    monkeypatch.setattr(
        "unpackers.managed_omlx_tripledes._child_resource_entries",
        lambda *_args, **_kwargs: (("payload", b"ciphertext"),),
    )
    monkeypatch.setattr(recovery, "decrypt_tripledes_cbc_pkcs7_base64", decrypt)

    with pytest.raises(recovery.OmlxTripledesError, match="elapsed_time_limit"):
        recovery._select_direct_terminal_binding(
            ((0, key), (64, iv)),
            b"MZ parent",
            deadline=1.0,
            clock=lambda: 2.0 if decrypted else 0.0,
            work_budget=_TerminalWorkBudget(),
        )


def test_dynamic_output_charges_table_transform_work_before_masking(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """opcode候補ごとのmasked table変換を共有累積上限で止める。"""

    method = OmlxMethod(
        method_index=0,
        metadata_token=0x06000001,
        type_count=0,
        exception_clause_count=0,
        type_descriptors=(),
        instructions=(),
        exception_clauses=(),
    )
    candidate = recovery._DynamicOmlxCandidate(
        resource_name="omlx",
        resource_blob=b"omlx",
        raw_method0=method,
        method1_token=0x06000002,
        dispatcher=SimpleNamespace(),
        opcode_maps=({},),
    )
    table_recovery = SimpleNamespace(
        clear=b"clear",
        key=1,
        mask=2,
        transform=SimpleNamespace(seed=3, addend=4),
        steps=(),
    )
    monkeypatch.setattr(
        recovery,
        "_canonicalize_omlx_method",
        lambda *_args, **_kwargs: method,
    )
    monkeypatch.setattr(
        recovery,
        "_recover_table",
        lambda *_args, **_kwargs: table_recovery,
    )
    monkeypatch.setattr(
        recovery,
        "decrypt_keyed_eaz_resource",
        lambda *_args, **_kwargs: pytest.fail("work上限後に変換してはいけません"),
    )

    with pytest.raises(recovery.OmlxTripledesError, match="table_transform_work_limit"):
        recovery._recover_dynamic_output(
            candidate,
            b"encrypted",
            {},
            b"MZ parent",
            {},
            entrypoint_token=0x06000003,
            deadline=10.0,
            clock=lambda: 0.0,
            work_budget=_TerminalWorkBudget(max_table_transform_work_bytes=0),
        )


def test_public_recovery_checks_deadline_before_format_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """開始時点で期限を越えた入力をparserへ渡さない。"""

    monkeypatch.setattr(
        recovery,
        "has_clr_metadata",
        lambda _data: pytest.fail("期限超過後にformat probeしてはいけません"),
    )
    ticks = iter((0.0, 2.0))

    report, artifacts = recovery.recover_managed_omlx_direct_tripledes(
        b"MZ fixture",
        clock=lambda: next(ticks),
        max_elapsed_seconds=1.0,
    )

    assert report["status"] == "rejected"
    assert report["reason"] == "elapsed_time_limit"
    assert artifacts == []


def test_public_recovery_checks_deadline_after_negative_format_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """期限を越えたnegative probeをnot_applicableとして返さない。"""

    probed = False

    def probe(_data: bytes) -> bool:
        nonlocal probed
        probed = True
        return False

    monkeypatch.setattr(recovery, "has_clr_metadata", probe)

    report, artifacts = recovery.recover_managed_omlx_direct_tripledes(
        b"MZ fixture",
        clock=lambda: 2.0 if probed else 0.0,
        max_elapsed_seconds=1.0,
    )

    assert report["status"] == "rejected"
    assert report["reason"] == "elapsed_time_limit"
    assert artifacts == []


def test_public_recovery_checks_deadline_after_managed_parse(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """managed metadata parse中の期限超過を後続列挙前に拒否する。"""

    parsed = False

    def parse(**_kwargs: object) -> object:
        nonlocal parsed
        parsed = True
        return object()

    monkeypatch.setattr(recovery, "has_clr_metadata", lambda _data: True)
    monkeypatch.setattr(recovery.dnfile, "dnPE", parse)
    monkeypatch.setattr(
        recovery,
        "_metadata_row_count",
        lambda _pe: pytest.fail("期限超過後にmetadata rowを列挙してはいけません"),
    )

    report, artifacts = recovery.recover_managed_omlx_direct_tripledes(
        b"MZ fixture",
        clock=lambda: 2.0 if parsed else 0.0,
        max_elapsed_seconds=1.0,
    )

    assert report["status"] == "rejected"
    assert report["reason"] == "elapsed_time_limit"
    assert artifacts == []


def test_public_recovery_treats_empty_parent_resources_as_not_applicable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """resource 0件はquota超過ではなくdirect OMLX recipeの適用外とする。"""

    fake_pe = SimpleNamespace(net=SimpleNamespace())
    monkeypatch.setattr(recovery, "has_clr_metadata", lambda _data: True)
    monkeypatch.setattr(recovery, "_contained_parser_diagnostics", nullcontext)
    monkeypatch.setattr(recovery.dnfile, "dnPE", lambda **_kwargs: fake_pe)
    monkeypatch.setattr(recovery, "_metadata_row_count", lambda _pe: 1)
    monkeypatch.setattr(recovery, "_resource_blobs", lambda _pe: [])
    monkeypatch.setattr(
        recovery,
        "_find_omlx_candidate",
        lambda *_args, **_kwargs: pytest.fail(
            "resource 0件でOMLX候補を走査してはいけません"
        ),
    )

    report, artifacts = recovery.recover_managed_omlx_direct_tripledes(
        b"MZ parent fixture",
        clock=lambda: 0.0,
    )

    assert report == {
        "status": "not_applicable",
        "reason": "parent_resources_missing",
    }
    assert artifacts == []


def test_public_recovery_reports_bounded_static_result_without_raw_secrets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """top-level成功時もResourceSetを結び、生key/IVをreportへ出さない。"""

    key = bytes(range(1, 17))
    iv = bytes(range(21, 29))
    key_base64 = base64.b64encode(key).decode("ascii")
    iv_base64 = base64.b64encode(iv).decode("ascii")
    ciphertext = b"ciphertext fixture"
    payload = b"MZ managed terminal fixture"
    container = b"synthetic ResourceSet container"
    terminal = recovery._TerminalBinding(
        key_offset=4,
        iv_offset=40,
        resource_name_offset=-1,
        key_base64=key_base64,
        iv_base64=iv_base64,
        resource_name="payload",
        ciphertext=ciphertext,
        payload=payload,
    )
    pe = SimpleNamespace(
        net=SimpleNamespace(
            struct=SimpleNamespace(EntryPointTokenOrRva=0x06000001),
            resources=[
                SimpleNamespace(
                    name="fixture.Properties.Resources.resources",
                    data=SimpleNamespace(
                        entries=[SimpleNamespace(name="payload", value=ciphertext)],
                        _data=container,
                    ),
                )
            ],
        )
    )
    method = OmlxMethod(
        method_index=0,
        metadata_token=0x06000002,
        type_count=0,
        exception_clause_count=0,
        type_descriptors=(),
        instructions=(),
        exception_clauses=(),
    )
    table_recovery = SimpleNamespace(
        clear=b"clear table",
        transform=SimpleNamespace(token=0x06000003, seed=4, addend=5),
        steps=6,
    )

    monkeypatch.setattr(recovery, "has_clr_metadata", lambda _data: True)
    monkeypatch.setattr(recovery.dnfile, "dnPE", lambda **_kwargs: pe)
    monkeypatch.setattr(recovery, "_metadata_row_count", lambda _pe: 1)
    monkeypatch.setattr(
        recovery,
        "_resource_blobs",
        lambda _pe: (("omlx", b"omlx"), ("encrypted", b"encrypted")),
    )
    monkeypatch.setattr(
        recovery,
        "_find_omlx_candidate",
        lambda *_args, **_kwargs: (
            "omlx",
            b"omlx",
            method,
            SimpleNamespace(metadata_token=0x06000004),
            SimpleNamespace(profile_id="synthetic-profile"),
        ),
    )
    monkeypatch.setattr(
        recovery,
        "_find_bound_resource",
        lambda *_args, **_kwargs: (
            "encrypted",
            b"encrypted",
            0x06000005,
            {"metadata_complete": True},
            {},
        ),
    )
    monkeypatch.setattr(recovery, "_verified_transform_recipes", lambda *_a, **_k: {})
    monkeypatch.setattr(
        recovery,
        "_discover_runtime_tokens",
        lambda *_args, **_kwargs: (
            {"reader_ctor": 0x06000006},
            {
                "derivation": "synthetic",
                "resolved_role_count": 1,
                "obfuscated_names_used": False,
            },
        ),
    )
    monkeypatch.setattr(
        recovery,
        "_recover_table",
        lambda *_args, **_kwargs: table_recovery,
    )
    monkeypatch.setattr(
        recovery,
        "_decode_table",
        lambda *_args, **_kwargs: ((4, key_base64), (40, iv_base64)),
    )
    monkeypatch.setattr(
        recovery,
        "_select_direct_terminal_binding",
        lambda *_args, **_kwargs: terminal,
    )

    report, artifacts = recovery.recover_managed_omlx_direct_tripledes(
        b"MZ parent fixture",
        clock=lambda: 0.0,
    )

    assert report["status"] == "recovered_managed_omlx_direct_tripledes"
    assert report["terminal_resource"]["container"]["name"] == (
        "fixture.Properties.Resources.resources"
    )
    assert report["family_attribution_allowed"] is False
    assert report["sample_execution"] is False
    assert report["external_communication"] is False
    assert artifacts == [("managed-omlx-direct-tripledes-gzip-pe", payload)]
    encoded = json.dumps(report, sort_keys=True)
    assert key_base64 not in encoded
    assert iv_base64 not in encoded
    assert payload.hex() not in encoded


def test_terminal_container_metadata_rejects_ambiguous_resourcesets() -> None:
    """同じciphertext entryを持つResourceSetが複数ならfail-closedにする。"""

    ciphertext = b"ciphertext"
    terminal = recovery._TerminalBinding(
        key_offset=0,
        iv_offset=32,
        resource_name_offset=-1,
        key_base64="key",
        iv_base64="iv",
        resource_name="payload",
        ciphertext=ciphertext,
        payload=b"MZ payload",
    )
    resources = [
        SimpleNamespace(
            name=f"container-{index}",
            data=SimpleNamespace(
                entries=[SimpleNamespace(name="payload", value=ciphertext)],
                _data=f"container-{index}".encode("ascii"),
            ),
        )
        for index in range(2)
    ]
    pe = SimpleNamespace(net=SimpleNamespace(resources=resources))

    with pytest.raises(recovery.DirectOmlxError, match="container_ambiguous"):
        recovery._terminal_container_metadata(pe, terminal)
