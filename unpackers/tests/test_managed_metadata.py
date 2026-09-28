"""非実行の合成CLR metadataとtoken参照の回帰試験。"""

from __future__ import annotations

import json
import struct
from types import SimpleNamespace as NS

import pytest

from unpackers.managed_metadata import MetadataResolver, token_value
from unpackers.managed_proxy_deobfuscator import analyze_proxy_resources, decrypt_eaz_proxy_table, parse_proxy_records


def table(name: str, rows: list[object]) -> NS:
    return NS(name=name, rows=rows, num_rows=len(rows))


def fixture() -> tuple[object, MetadataResolver]:
    types = table("TypeRef", [NS()])
    fields = table("Field", [NS(Signature=b"\x06\x08") for _ in range(9)])
    methods = table("MethodDef", [NS(Signature=b"\x10\x01\x00\x01") for _ in range(9)])
    parent = NS(table=types, row_index=1)
    members = table("MemberRef", [NS(Signature=b"\x10\x01\x00\x01", Class=parent),
                                  NS(Signature=b"\x06\x08", Class=parent)])
    specs = table("MethodSpec", [NS(Method=NS(table=methods, row_index=1), Instantiation=b"\x0a\x01\x08"),
                                 NS(Method=NS(table=members, row_index=1), Instantiation=b"\x0a\x01\x08")])
    pe = NS(net=NS(mdtables=NS(TypeRef=types, Field=fields, MethodDef=methods,
                               MemberRef=members, MethodSpec=specs,
                               StandAloneSig=table("StandAloneSig", [NS(Signature=b"\x00\x00\x01")]))))
    return pe, MetadataResolver(pe)


def test_methodspec_resolves_internal_and_memberref_declarations() -> None:
    _, resolver = fixture()
    internal = resolver.resolve(NS(value=0x2B000001))
    external = resolver.resolve(0x2B000002)
    assert internal["status"] == external["status"] == "resolved"
    assert internal["definition_token"] == "0x06000001"
    assert external["definition_token"] == "0x0a000001"
    assert internal["generic_argument_count"] == 1
    assert internal["resolution_scope"] == "metadata_declaration_only"
    assert "Instantiation" not in json.dumps(internal)


@pytest.mark.parametrize(("token", "kind", "reason"), [
    (0x06000000, "method", "zero_rid"),
    (0x0600000A, "method", "rid_out_of_range"),
    (0x04000001, "method", "wrong_reference_table"),
    (0x0A000002, "method", "memberref_is_field_not_method"),
    (0x0A000001, "field", "memberref_is_not_field"),
    (0x7F000001, "method", "unsupported_table"),
    (0x11000001, "indirect_signature", "indirect_call_target_not_statically_known"),
])
def test_unknown_and_wrong_kind_tokens_remain_unresolved(token: int, kind: str, reason: str) -> None:
    _, resolver = fixture()
    result = resolver.resolve(token, kind=kind)
    assert result["status"] == "unresolved"
    assert result["reason"] == reason
    assert result["token"] == f"0x{token:08x}"


@pytest.mark.parametrize("data", [b"", b"\x0a", b"\x0a\x01", b"\x0a\x01\x08\x08",
                                   b"\x0a\x01\x01", b"\x0a\x02\x08\x08", b"\x0a\x80\x01\x08"])
def test_methodspec_rejects_corrupt_signature_and_arity(data: bytes) -> None:
    pe, _ = fixture()
    pe.net.mdtables.MethodSpec.rows[0].Instantiation = data
    result = MetadataResolver(pe).resolve(0x2B000001)
    assert result["status"] == "unresolved"
    assert "reason" in result


def test_methodspec_cannot_reference_field_or_another_spec() -> None:
    pe, _ = fixture()
    specs = pe.net.mdtables.MethodSpec
    specs.rows[0].Method = NS(table=specs, row_index=1)
    assert MetadataResolver(pe).resolve(0x2B000001)["reason"] == "invalid_coded_reference"
    specs.rows[0].Method = NS(table=pe.net.mdtables.MemberRef, row_index=2)
    assert MetadataResolver(pe).resolve(0x2B000001)["reason"] == "methodspec_definition_memberref_is_field_not_method"


def test_metadata_limits_are_checked_before_unbounded_iteration() -> None:
    pe, _ = fixture()
    reads = []

    def endless():
        while True:
            reads.append(1)
            yield NS(Signature=b"\x00\x00\x01")

    pe.net.mdtables.MethodDef.rows = endless()
    resolver = MetadataResolver(pe, max_rows=2, max_total_rows=5)
    assert len(reads) <= 3
    assert not resolver.coverage()["complete"]
    assert resolver.resolve(0x06000009)["reason"] == "metadata_row_budget_exceeded"
    with pytest.raises(ValueError):
        MetadataResolver(pe, max_rows=False)


def test_row_parse_exception_does_not_publish_its_message() -> None:
    pe, _ = fixture()

    class Broken:
        @property
        def Signature(self):
            raise ValueError("private-secret-blob")

    pe.net.mdtables.MethodDef.rows[0] = Broken()
    result = MetadataResolver(pe).resolve(0x06000001)
    assert result["reason"] == "metadata_row_parse_error"
    assert result["parse_error"] == "ValueError"
    assert "private-secret" not in json.dumps(result)


def test_recursive_types_and_declared_generic_counts_are_bounded() -> None:
    pe, _ = fixture()
    method = pe.net.mdtables.MethodSpec.rows[0]
    method.Instantiation = b"\x0a\x01" + b"\x1d" * 33 + b"\x08"
    assert MetadataResolver(pe).resolve(0x2B000001)["reason"] == "signature_type_budget_exceeded"
    method.Instantiation = b"\x0a\x84\x01"
    assert MetadataResolver(pe).resolve(0x2B000001)["reason"] == "signature_item_budget_exceeded"


def test_zero_and_duplicate_proxy_field_tokens_are_not_valid() -> None:
    records = parse_proxy_records(struct.pack("<IIII", 0x04000000, 0x06000001, 0x04000000, 0x06000001))
    assert not any(record["valid"] for record in records)
    assert all("duplicate_field_mapping" in record["invalid_reasons"] for record in records)


def test_proxy_metadata_validation_accepts_methodspec_and_rejects_forged_rid() -> None:
    _, resolver = fixture()
    clear = b"".join(struct.pack("<II", 0x04000001 + index,
                                 0x2B000001 if index == 0 else 0x06000001 + index) for index in range(9))
    encrypted = decrypt_eaz_proxy_table(clear)
    report = analyze_proxy_resources([("synthetic", encrypted)], include_records=True, metadata_resolver=resolver)
    assert report["status"] == "matched"
    candidate = report["candidates"][0]
    assert candidate["validation_level"] == "metadata_declaration_validated_candidate"
    assert not candidate["runtime_dispatch_verified"]
    assert candidate["records"][0]["target_resolution"]["definition_token"] == "0x06000001"
    forged = bytearray(clear)
    struct.pack_into("<I", forged, 4, 0x0600FFFF)
    forged_result = analyze_proxy_resources([("forged", decrypt_eaz_proxy_table(bytes(forged)))], metadata_resolver=resolver)
    assert forged_result["status"] == "not_matched"
    assert forged_result["rejected_candidates"][0]["reason_counts"] == {"rid_out_of_range": 1}


def test_proxy_rejects_a_95_percent_table_with_one_invalid_record() -> None:
    clear = b"".join(struct.pack("<II", 0x04000001 + index, 0x06000001 + index) for index in range(20))
    clear = clear[:-8] + struct.pack("<II", 0x04000000, 0x06000001)
    result = analyze_proxy_resources([("synthetic", decrypt_eaz_proxy_table(clear))])
    assert result["status"] == "not_matched"
    assert result["rejected_candidates"][0]["reason_counts"] == {"invalid_field_token": 1}


def test_transform_byte_limit_is_preallocation(monkeypatch: pytest.MonkeyPatch) -> None:
    from unpackers import managed_proxy_deobfuscator as proxy

    monkeypatch.setattr(proxy, "MAX_PROXY_RECORDS", 8)
    with pytest.raises(ValueError, match="安全上限"):
        proxy.decrypt_eaz_proxy_table(b"\0" * 72)
    result = proxy.analyze_proxy_resources([("oversized", b"\0" * 72)])
    assert result["status"] == "partial_budget"
    assert result["budget_exhausted"] == ["proxy_records"]


def test_token_operand_does_not_coerce_strings_or_bools() -> None:
    assert token_value(True) is None
    assert token_value("100663297") is None
    assert token_value(-1) is None


def test_missing_declared_rows_are_not_mislabeled_as_budget_exhaustion() -> None:
    pe, _ = fixture()
    pe.net.mdtables.MethodDef.rows = pe.net.mdtables.MethodDef.rows[:1]
    resolver = MetadataResolver(pe)
    assert resolver.resolve(0x06000002)["reason"] == "metadata_row_missing"
    assert not resolver.coverage()["complete"]
    assert resolver.coverage()["tables"]["MethodDef"]["missing_rows"]


def test_coded_reference_must_belong_to_this_pe_metadata_table() -> None:
    pe, _ = fixture()
    pe.net.mdtables.MethodSpec.rows[0].Method = NS(table=table("MethodDef", [NS()]), row_index=1)
    assert MetadataResolver(pe).resolve(0x2B000001)["reason"] == "invalid_coded_reference"


@pytest.mark.parametrize(("declared", "status"), [(None, "missing"), (True, "invalid_type"),
                                                   ("9", "invalid_type"), (-1, "negative")])
def test_invalid_declared_row_counts_are_not_replaced_by_retained_count(declared: object, status: str) -> None:
    pe, _ = fixture()
    pe.net.mdtables.MethodDef.num_rows = declared
    resolver = MetadataResolver(pe)
    coverage = resolver.coverage()["tables"]["MethodDef"]
    assert coverage["declared"] is None
    assert coverage["declared_status"] == status
    assert not resolver.coverage()["complete"]
    assert resolver.resolve(0x06000001)["reason"] == "metadata_declared_row_count_" + status


def test_extra_rows_and_absent_table_are_distinct_from_valid_empty_table() -> None:
    pe, _ = fixture()
    pe.net.mdtables.MethodDef.num_rows = 1
    resolver = MetadataResolver(pe)
    assert resolver.coverage()["tables"]["MethodDef"]["row_count_mismatch"]
    assert resolver.resolve(0x06000001)["reason"] == "metadata_row_count_mismatch"
    absent = resolver.coverage()["tables"]["TypeSpec"]
    assert not absent["present"] and absent["declared_status"] == "absent"
    pe.net.mdtables.TypeSpec = table("TypeSpec", [])
    empty = MetadataResolver(pe).coverage()["tables"]["TypeSpec"]
    assert empty["present"] and empty["declared_status"] == "valid" and empty["declared"] == 0


@pytest.mark.parametrize("budgets", [{"max_rows": 20_001}, {"max_total_rows": 80_001}])
def test_metadata_hard_limits_only_allow_lowering(budgets: dict[str, int]) -> None:
    pe, _ = fixture()
    with pytest.raises(ValueError):
        MetadataResolver(pe, **budgets)


def test_parser_exception_type_name_has_fixed_character_and_size_limits() -> None:
    pe, _ = fixture()
    hostile = type("秘密" * 100, (ValueError,), {})

    class Broken:
        @property
        def Signature(self):
            raise hostile("private-secret")

    pe.net.mdtables.MethodDef.rows[0] = Broken()
    result = MetadataResolver(pe).resolve(0x06000001)
    assert result["parse_error"] == "MetadataParseError"
    assert "秘密" not in json.dumps(result, ensure_ascii=False)


ASCII_GETTER_PROFILE = "system_text_encoding_get_ascii_v1"
ASCII_BYTES_PROFILE = "system_text_encoding_get_bytes_string_v1"


def framework_fixture() -> tuple[object, MetadataResolver]:
    """mscorlib参照宣言だけを持つ非実行の合成metadataを作る。"""
    assembly = NS(Name=NS(value="mscorlib"), PublicKey=NS(value=bytes.fromhex("b77a5c561934e089")),
                  Culture=NS(value=""), struct=NS(Flags=0),
                  MajorVersion=4, MinorVersion=0, BuildNumber=0, RevisionNumber=0)
    assemblies = table("AssemblyRef", [assembly])
    scope = NS(table=assemblies, row_index=1)
    types = table("TypeRef", [NS(TypeNamespace=NS(value="System.Text"), TypeName=NS(value=name),
                                ResolutionScope=scope) for name in ("Encoding", "ASCIIEncoding", "Decoy")])
    members = table("MemberRef", [
        NS(Name=NS(value="get_ASCII"), Signature=NS(value=b"\x00\x00\x12\x05"),
           Class=NS(table=types, row_index=1)),
        NS(Name=NS(value="GetBytes"), Signature=NS(value=b"\x20\x01\x1d\x05\x0e"),
           Class=NS(table=types, row_index=1)),
        NS(Name=NS(value="GetBytes"), Signature=NS(value=b"\x20\x01\x1d\x05\x0e"),
           Class=NS(table=types, row_index=2)),
    ])
    pe = NS(net=NS(mdtables=NS(AssemblyRef=assemblies, TypeRef=types, MemberRef=members,
                               MethodDef=table("MethodDef", [NS(Name="get_ASCII", Signature=b"\x00\x00\x01")]))))
    return pe, MetadataResolver(pe)


@pytest.mark.parametrize(("token", "profile", "declaring_type"), [
    (0x0A000001, ASCII_GETTER_PROFILE, "system_text_encoding"),
    (0x0A000002, ASCII_BYTES_PROFILE, "system_text_encoding"),
    (0x0A000003, ASCII_BYTES_PROFILE, "system_text_ascii_encoding"),
])
def test_framework_profiles_match_declarations_not_runtime_purity(token: int, profile: str, declaring_type: str) -> None:
    _, resolver = framework_fixture()
    result = resolver.match_framework_member(NS(value=token), profile)
    assert result["status"] == "matched_declaration"
    assert result["assembly_version"] == [4, 0, 0, 0]
    assert result["declaring_type_profile"] == declaring_type
    assert result["resolution_scope"] == "reviewed_framework_metadata_declaration_only"
    assert not any(result[name] for name in ("runtime_assembly_integrity_verified", "runtime_dispatch_verified",
                                            "receiver_dataflow_verified", "side_effect_free_verified", "nonthrowing_verified"))
    assert "System.Text" not in json.dumps(result)
    assert "signature_sha256" in result


@pytest.mark.parametrize("signature", [
    b"\x00\x01\x1d\x05\x0e",  # instanceをstaticへ変更
    b"\x20\x01\x1d\x05\x1d\x05",  # GetBytes(byte[])という同名別signature
    b"\x20\x02\x1d\x05\x0e\x08",  # 追加引数
    b"\x20\x01\x08\x0e",  # 別の戻値
    b"\x30\x01\x01\x1d\x05\x0e",  # generic数1
    b"\x25\x01\x1d\x05\x0e",  # vararg
    b"\x20\x01\x1d\x05\x10\x0e",  # byref string
    b"\x20\x01\x1d\x05\x0e\x00",  # signature後の余剰byte
    b"\x06\x08",  # field MemberRef
])
def test_framework_member_requires_full_reviewed_signature(signature: bytes) -> None:
    pe, _ = framework_fixture()
    pe.net.mdtables.MemberRef.rows[1].Signature = signature
    result = MetadataResolver(pe).match_framework_member(0x0A000002, ASCII_BYTES_PROFILE)
    assert result["status"] == "unresolved"
    assert result["reason"]


@pytest.mark.parametrize(("field", "value", "reason"), [
    ("Name", "System", "framework_assembly_identity_pair_not_reviewed"),
    ("PublicKey", bytes.fromhex("b03f5f7f11d50a3a"), "framework_assembly_identity_pair_not_reviewed"),
    ("Culture", "en-US", "framework_assembly_culture_not_neutral"),
    ("MajorVersion", 9, "framework_assembly_version_not_reviewed"),
    ("MajorVersion", True, "framework_assembly_version_invalid"),
])
def test_framework_assembly_uses_exact_identity_pair_and_version(field: str, value: object, reason: str) -> None:
    pe, _ = framework_fixture()
    setattr(pe.net.mdtables.AssemblyRef.rows[0], field, value)
    result = MetadataResolver(pe).match_framework_member(0x0A000001, ASCII_GETTER_PROFILE)
    assert result["status"] == "unresolved"
    assert result["reason"] == reason


@pytest.mark.parametrize("flags", [True, 1, 0x100, 0x10, None])
def test_full_public_key_retargetable_and_unknown_flags_are_not_reviewed(flags: object) -> None:
    pe, _ = framework_fixture()
    pe.net.mdtables.AssemblyRef.rows[0].struct.Flags = flags
    assert MetadataResolver(pe).match_framework_member(0x0A000001, ASCII_GETTER_PROFILE)["reason"] == "framework_assembly_flags_not_reviewed"


def test_framework_same_name_local_method_and_typedef_are_not_accepted() -> None:
    pe, resolver = framework_fixture()
    assert resolver.match_framework_member(0x06000001, ASCII_GETTER_PROFILE)["reason"] == "framework_member_not_memberref"
    local = table("TypeDef", [NS(TypeNamespace="System.Text", TypeName="Encoding")])
    pe.net.mdtables.TypeDef = local
    pe.net.mdtables.MemberRef.rows[0].Class = NS(table=local, row_index=1)
    assert MetadataResolver(pe).match_framework_member(0x0A000001, ASCII_GETTER_PROFILE)["reason"] == "invalid_coded_reference"


def test_framework_scope_cycle_unknown_owner_and_member_name_are_rejected() -> None:
    pe, _ = framework_fixture()
    types = pe.net.mdtables.TypeRef
    types.rows[0].TypeNamespace = ""
    types.rows[0].ResolutionScope = NS(table=types, row_index=1)
    assert MetadataResolver(pe).match_framework_member(0x0A000001, ASCII_GETTER_PROFILE)["reason"] == "framework_typeref_scope_cycle"
    pe, _ = framework_fixture()
    pe.net.mdtables.MemberRef.rows[0].Class.row_index = 3
    result = MetadataResolver(pe).match_framework_member(0x0A000001, ASCII_GETTER_PROFILE)
    assert result["reason"] == "framework_member_owner_not_reviewed"
    assert "declaring_type_profile" not in result
    pe, _ = framework_fixture()
    pe.net.mdtables.MemberRef.rows[0].Name = "get_UTF8"
    assert MetadataResolver(pe).match_framework_member(0x0A000001, ASCII_GETTER_PROFILE)["reason"] == "framework_member_name_mismatch"


def test_framework_getter_return_type_has_its_own_assembly_identity_check() -> None:
    pe, _ = framework_fixture()
    types = pe.net.mdtables.TypeRef
    assemblies = pe.net.mdtables.AssemblyRef
    other = NS(**vars(assemblies.rows[0]))
    other.MajorVersion = 2
    assemblies.rows.append(other)
    assemblies.num_rows = 2
    types.rows[1] = NS(TypeNamespace="System.Text", TypeName="Encoding",
                       ResolutionScope=NS(table=assemblies, row_index=2))
    pe.net.mdtables.MemberRef.rows[0].Signature = b"\x00\x00\x12\x09"
    assert MetadataResolver(pe).match_framework_member(0x0A000001, ASCII_GETTER_PROFILE)["reason"] == "framework_signature_assembly_identity_mismatch"


def test_framework_scope_depth_and_metadata_row_budget_are_bounded() -> None:
    pe, _ = framework_fixture()
    types = pe.net.mdtables.TypeRef
    scope = types.rows[0].ResolutionScope
    types.rows = [NS(TypeNamespace="", TypeName="Encoding", ResolutionScope=NS(table=types, row_index=index + 2))
                  for index in range(8)]
    types.rows.append(NS(TypeNamespace="System.Text", TypeName="Encoding", ResolutionScope=scope))
    types.num_rows = len(types.rows)
    resolver = MetadataResolver(pe)
    assert resolver.match_framework_member(0x0A000001, ASCII_GETTER_PROFILE)["reason"] == "framework_typeref_scope_depth_exceeded"
    pe, _ = framework_fixture()
    resolver = MetadataResolver(pe, max_rows=1)
    assert resolver.match_framework_member(0x0A000003, ASCII_BYTES_PROFILE)["reason"] == "framework_member_metadata_row_budget_exceeded"


def test_framework_unknown_profile_and_long_identity_diagnostics_do_not_leak() -> None:
    pe, resolver = framework_fixture()
    result = resolver.match_framework_member(0x0A000001, "private-secret-profile")
    assert result["reason"] == "framework_profile_unknown"
    assert "private-secret" not in json.dumps(result)
    pe.net.mdtables.AssemblyRef.rows[0].Name = "private-secret" * 100
    result = MetadataResolver(pe).match_framework_member(0x0A000001, ASCII_GETTER_PROFILE)
    assert result["reason"] == "framework_identity_text_invalid_or_oversized"
    assert "private-secret" not in json.dumps(result)


def test_framework_signature_changes_after_generic_resolution_are_not_accepted() -> None:
    pe, resolver = framework_fixture()
    assert resolver.resolve(0x0A000002)["status"] == "resolved"
    pe.net.mdtables.MemberRef.rows[1].Signature = b"\x20\x01\x08\x0e"
    assert resolver.match_framework_member(0x0A000002, ASCII_BYTES_PROFILE)["reason"] == "framework_signature_changed_since_resolution"
