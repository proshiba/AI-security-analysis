"""managed RAT設定の構文限定回収とfail-closed境界を合成データで検証する。"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import sys
from functools import lru_cache
from pathlib import Path
from types import SimpleNamespace as NS

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

COMMON = Path(__file__).parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import dotnet_rat_config as config  # noqa: E402


def _instruction(opcode: str, operand: object = None) -> NS:
    return NS(opcode=NS(name=opcode), operand=NS(value=operand))


def _metadata(monkeypatch, instructions, *, methods=1, handlers=()) -> NS:
    fields = [
        NS(Name=name, Signature=NS(value=b"\x06\x0e"), Flags=NS(fdStatic=True, fdLiteral=False))
        for name in ("First", "Second", "Third")
    ]
    rows = [NS(Name=".cctor", Rva=1, Signature=NS(value=b"\x00\x00\x01"),
               Flags=NS(mdStatic=True), struct=NS(Flags=0x10, ImplFlags=0)) for _ in range(methods)]
    typedef = NS(
        TypeNamespace="Client",
        TypeName="Settings",
        FieldList=[NS(row_index=index) for index in range(1, 4)],
        MethodList=[NS(row_index=index) for index in range(1, methods + 1)],
    )
    pe = NS(net=NS(
        mdtables=NS(TypeDef=NS(rows=[typedef], num_rows=1), Field=NS(rows=fields, num_rows=3),
                    MethodDef=NS(rows=rows, num_rows=len(rows))),
        user_strings=NS(get=lambda index: {1: NS(value="fixture-value")}[index]),
    ))
    for offset, instruction in enumerate(instructions):
        instruction.offset = offset
        instruction.size = 1
    monkeypatch.setattr(config.dnfile, "dnPE", lambda **_kwargs: pe)
    monkeypatch.setattr(config, "read_bounded_method_body", lambda *_args: NS(
        instructions=instructions, exception_handlers=list(handlers),
        offset=0, header_size=0, code_size=len(instructions),
    ))
    return pe


def _direct() -> list[NS]:
    return [_instruction("ldstr", 0x70000001), _instruction("stsfld", 0x04000001)]


def test_adjacent_same_initializer_constant_reference_is_recovered(monkeypatch) -> None:
    _metadata(monkeypatch, [
        *_direct(), _instruction("nop"), _instruction("ldsfld", 0x04000001),
        _instruction("nop"), _instruction("stsfld", 0x04000002),
        _instruction("ldsfld", 0x04000002), _instruction("stsfld", 0x04000003),
        _instruction("ret"),
    ])
    assert config.settings_literals(b"synthetic-metadata") == {
        "First": "fixture-value", "Second": "fixture-value", "Third": "fixture-value",
    }


@pytest.mark.parametrize("instructions", [
    [_instruction("ldsfld", 0x04000001), _instruction("stsfld", 0x04000002), *_direct(), _instruction("ret")],
    [*_direct(), *_direct(), _instruction("ret")],
    [*_direct(), _instruction("br.s", 12), _instruction("ret")],
    [*_direct(), _instruction("switch", [12]), _instruction("ret")],
    [_instruction("ldstr", 0x06000001), _instruction("stsfld", 0x04000001), _instruction("ret")],
    [_instruction("ldstr", 0x70000000), _instruction("stsfld", 0x04000001), _instruction("ret")],
    [_instruction("ldstr", 0x70000001), _instruction("stsfld", 0x04000000), _instruction("ret")],
    [_instruction("ldstr", 0x70000001), _instruction("stsfld", 0x04000004), _instruction("ret")],
    [_instruction("ldstr", 0x70000001), _instruction("ldstr", 0x70000001), _instruction("stsfld", 0x04000001), _instruction("ret")],
    [*_direct(), _instruction("ret"), _instruction("ldstr", 0x70000001)],
    [*_direct()],
    [*_direct(), _instruction("call", 0x0A000001), _instruction("ldsfld", 0x04000001), _instruction("stsfld", 0x04000002), _instruction("ret")],
    [_instruction("call", 0x0A000001), *_direct(), _instruction("ret")],
])
def test_unresolved_ambiguous_or_malformed_syntax_fails_closed(monkeypatch, instructions) -> None:
    _metadata(monkeypatch, instructions)
    with pytest.raises(config.ConfigRecoveryError):
        config.settings_literals(b"synthetic-metadata")


@pytest.mark.parametrize("methods,handlers", [(2, ()), (1, (object(),))])
def test_ambiguous_cctor_and_exception_handler_are_rejected(monkeypatch, methods, handlers) -> None:
    _metadata(monkeypatch, [*_direct(), _instruction("ret")], methods=methods, handlers=handlers)
    with pytest.raises(config.ConfigRecoveryError):
        config.settings_literals(b"synthetic-metadata")


@pytest.mark.parametrize("signature,static", [(b"\x06\x08", True), (b"\x06\x0e", False)])
def test_literal_assignment_requires_static_string_field(monkeypatch, signature, static) -> None:
    pe = _metadata(monkeypatch, [*_direct(), _instruction("ret")])
    pe.net.mdtables.Field.rows[0].Signature.value = signature
    pe.net.mdtables.Field.rows[0].Flags.fdStatic = static
    with pytest.raises(config.ConfigRecoveryError, match="static string"):
        config.settings_literals(b"synthetic-metadata")


def test_initializer_instruction_limit(monkeypatch) -> None:
    _metadata(monkeypatch, [*_direct(), _instruction("ret")])
    monkeypatch.setattr(config, "MAX_INITIALIZER_INSTRUCTIONS", 2)
    with pytest.raises(config.ConfigRecoveryError, match="上限"):
        config.settings_literals(b"synthetic-metadata")


def test_other_type_field_assignment_and_metadata_owner_conflict(monkeypatch) -> None:
    pe = _metadata(monkeypatch, [*_direct(), _instruction("ret")])
    owner = pe.net.mdtables.TypeDef.rows[0]
    owner.FieldList = [NS(row_index=2), NS(row_index=3)]
    pe.net.mdtables.TypeDef.rows.append(NS(
        TypeNamespace="Other", TypeName="Settings", FieldList=[NS(row_index=1)], MethodList=[],
    ))
    with pytest.raises(config.ConfigRecoveryError, match="別型"):
        config.settings_literals(b"synthetic-metadata")
    pe.net.mdtables.TypeDef.rows[0].FieldList.append(NS(row_index=1))
    with pytest.raises(config.ConfigRecoveryError, match="所有型"):
        config.settings_literals(b"synthetic-metadata")


def test_same_qualified_name_does_not_merge_type_identity(monkeypatch) -> None:
    pe = _metadata(monkeypatch, [*_direct(), _instruction("ret")])
    pe.net.mdtables.TypeDef.rows.append(NS(
        TypeNamespace="Client", TypeName="Settings", FieldList=[], MethodList=[],
    ))
    with pytest.raises(config.ConfigRecoveryError, match="所有型"):
        config.settings_literals(b"synthetic-metadata")


@lru_cache(maxsize=128)
def _encrypt(value: str) -> str:
    key = "fixture-key"
    salt = config.PROFILES["asyncrat"]["salt"]
    material = hashlib.pbkdf2_hmac("sha1", key.encode(), salt, 50_000, 96)
    iv = bytes(range(16))
    padder = PKCS7(128).padder()
    padded = padder.update(value.encode()) + padder.finalize()
    encryptor = Cipher(algorithms.AES(material[:32]), modes.CBC(iv)).encryptor()
    body = iv + encryptor.update(padded) + encryptor.finalize()
    return base64.b64encode(hmac.new(material[32:], body, hashlib.sha256).digest() + body).decode()


def _literals(overrides=None) -> dict[str, str]:
    plain = {
        "ports": "443", "hosts": "c2.example.test", "version": "fixture",
        "install": "false", "anti": "true", "group": "fixture",
        "pastebin": "null", "certificate": base64.b64encode(b"fixture-certificate").decode(),
    }
    plain.update(overrides or {})
    names = config.PROFILES["asyncrat"]["fields"]
    return {"Key": base64.b64encode(b"fixture-key").decode(), **{
        names[name]: _encrypt(value) for name, value in plain.items()
    }}


@pytest.mark.parametrize("overrides", [
    {"ports": "443,invalid"}, {"ports": "0"}, {"ports": "65536"},
    {"ports": "４４３"}, {"hosts": "https://c2.example.test/path"},
    {"hosts": "c2.example.test,broken"}, {"hosts": "null"},
    {"hosts": "c2.example.test,null"}, {"ports": "443,null"},
    {"version": ""}, {"install": "yes"}, {"certificate": ""},
    {"group": "x" * 513}, {"pastebin": "file:///private"},
])
def test_authenticated_but_invalid_config_is_not_success(monkeypatch, overrides) -> None:
    monkeypatch.setattr(config, "settings_literals", lambda *_args: _literals(overrides))
    with pytest.raises(config.ConfigRecoveryError):
        config.recover(b"synthetic-managed-client", "asyncrat")


def test_config_recovery_derives_keys_once_and_removes_dynamic_url_secrets(monkeypatch) -> None:
    values = _literals({"pastebin": "https://user:password@resolver.example.test/invite/SECRET?q=TOKEN#PRIVATE"})
    monkeypatch.setattr(config, "settings_literals", lambda *_args: values)
    original = config._derive
    calls = []
    monkeypatch.setattr(config, "_derive", lambda *args: (calls.append(True), original(*args))[1])
    result = config.recover(b"synthetic-managed-client", "asyncrat")
    assert len(calls) == 1
    assert result["dynamic_config_url"] == "https://resolver.example.test/"
    assert result["dynamic_config_url_scope"] == "origin_only"
    assert not any(secret in repr(result) for secret in ("password", "SECRET", "TOKEN", "PRIVATE", "fixture-key"))
    assert result["executed"] is False and result["network_contacted"] is False


def test_required_field_is_not_silently_omitted(monkeypatch) -> None:
    values = _literals()
    values.pop("Hosts")
    monkeypatch.setattr(config, "settings_literals", lambda *_args: values)
    with pytest.raises(config.ConfigRecoveryError, match="必須field"):
        config.recover(b"synthetic-managed-client", "asyncrat")


def test_endpoint_cross_product_limit_and_ciphertext_limit(monkeypatch) -> None:
    with pytest.raises(config.ConfigRecoveryError, match="上限"):
        config._validated_endpoints(
            ",".join(f"c{index}.example.test" for index in range(9)),
            ",".join(str(1000 + index) for index in range(8)),
        )
    monkeypatch.setattr(config, "MAX_ENCODED_SETTING_CHARS", 8)
    monkeypatch.setattr(config, "_derive", lambda *_args: pytest.fail("上限判定前に鍵導出してはいけません"))
    with pytest.raises(config.ConfigRecoveryError, match="上限"):
        config.decrypt_setting("A" * 12, "fixture-key", b"fixture-salt")


def test_input_limit_rejected_before_parser(monkeypatch) -> None:
    monkeypatch.setattr(config, "MAX_INPUT_BYTES", 8)
    monkeypatch.setattr(config.dnfile, "dnPE", lambda **_kwargs: pytest.fail("上限判定前にparseしてはいけません"))
    with pytest.raises(config.ConfigRecoveryError, match="上限"):
        config.recover(b"x" * 9, "asyncrat")


@pytest.mark.parametrize("invalid", [None, b"", "!not-base64!", "A" * 12])
def test_ciphertext_damage_is_rejected_before_key_derivation(monkeypatch, invalid) -> None:
    monkeypatch.setattr(config, "_derive", lambda *_args: pytest.fail("不正形式で鍵導出してはいけません"))
    with pytest.raises(config.ConfigRecoveryError):
        config.decrypt_setting(invalid, "fixture-key", b"fixture-salt")


def test_chacha_encoded_limit_precedes_decode(monkeypatch) -> None:
    monkeypatch.setattr(config, "MAX_ENCODED_SETTING_CHARS", 8)
    with pytest.raises(config.ConfigRecoveryError, match="上限"):
        config.decrypt_obfuscated_chacha_setting("A" * 12, "fixture-key")


@pytest.mark.parametrize("table_name", ["TypeDef", "Field", "MethodDef"])
def test_missing_metadata_table_is_normalized_to_recovery_error(monkeypatch, table_name) -> None:
    pe = _metadata(monkeypatch, [*_direct(), _instruction("ret")])
    setattr(pe.net.mdtables, table_name, None)
    with pytest.raises(config.ConfigRecoveryError, match="CLR table"):
        config.settings_literals(b"synthetic-metadata")


def _assessment(monkeypatch, instructions, *, handlers=()):
    pe = _metadata(monkeypatch, instructions, handlers=handlers)
    return pe, config.assess_settings_literals(b"synthetic-metadata")


def _known_unknown_call(pe, *, signature=b"\x00\x00\x01") -> int:
    """宣言だけ正しい合成method。副作用の無害性は指定しない。"""

    pe.net.mdtables.MethodDef.rows.append(NS(Name="Unknown", Rva=2, Signature=NS(value=signature)))
    pe.net.mdtables.MethodDef.num_rows += 1
    pe.net.mdtables.TypeDef.rows[0].MethodList.append(NS(row_index=2))
    return 0x06000002


def test_assessment_complete_copy_provenance_and_independent_projection(monkeypatch) -> None:
    instructions = [*_direct(), _instruction("nop"), _instruction("ldsfld", 0x04000001),
                    _instruction("stsfld", 0x04000002), _instruction("ret")]
    _pe, assessment = _assessment(monkeypatch, instructions)
    diagnostic = config.settings_literal_diagnostics(assessment)
    assert assessment.status == "complete"
    assert diagnostic["effects_unresolved"] is False
    assert diagnostic["counts"] == {"fields": 2, "assignments": 2, "instructions": 6}
    assert diagnostic["fields"][1]["dependency_tokens"] == ["0x04000001"]
    assert diagnostic["fields"][1]["assignments"] == [{
        "assignment_offset": 4, "source_offset": 3, "kind": "prior_field_copy",
        "dependency_token": "0x04000001",
    }]
    assert all(field["status"] == "proven_literal" for field in diagnostic["fields"])
    diagnostic["fields"][0]["status"] = "external-change"
    assert config.settings_literal_diagnostics(assessment)["fields"][0]["status"] == "proven_literal"


@pytest.mark.parametrize("opcode", ["call", "callvirt", "newobj", "ldftn", "ldvirtftn"])
def test_assessment_unknown_call_keeps_observations_but_not_final_values(monkeypatch, opcode) -> None:
    instructions = [*_direct(), _instruction(opcode, 0x06000002),
                    _instruction("ldsfld", 0x04000001), _instruction("stsfld", 0x04000002), _instruction("ret")]
    pe = _metadata(monkeypatch, instructions)
    _known_unknown_call(pe)
    assessment = config.assess_settings_literals(b"synthetic-metadata")
    diagnostic = config.settings_literal_diagnostics(assessment)
    assert assessment.status == "partial"
    assert diagnostic["effects_unresolved"] is True
    assert diagnostic["effects"] == [{"offset": 2, "reason": "call_effects_unresolved",
                                      "reference_token": "0x06000002"}]
    assert {field["status"] for field in diagnostic["fields"]} == {"observed_literal"}
    assert "fixture-value" not in repr(diagnostic)
    assert assessment._private_literals == {"0x04000001": "fixture-value", "0x04000002": "fixture-value"}
    if opcode in {"call", "callvirt", "newobj"}:
        with pytest.raises(config.ConfigRecoveryError):
            config.settings_literals(b"synthetic-metadata")


@pytest.mark.parametrize("opcode,operand", [("ldsflda", 0x04000001), ("ldloca.s", 0),
                                           ("stind.i4", None), ("cpblk", None)])
def test_assessment_address_or_indirect_write_is_method_wide_unknown(monkeypatch, opcode, operand) -> None:
    _pe, assessment = _assessment(monkeypatch, [*_direct(), _instruction(opcode, operand), _instruction("ret")])
    diagnostic = config.settings_literal_diagnostics(assessment)
    assert diagnostic["status"] == "partial" and diagnostic["effects_unresolved"] is True
    assert diagnostic["fields"][0]["status"] == "observed_literal"
    assert diagnostic["effects"][0]["reason"] in {"address_escape_unresolved", "indirect_write_unresolved"}


def test_assessment_branch_candidates_are_observations_without_path_interpretation(monkeypatch) -> None:
    _pe, assessment = _assessment(monkeypatch, [_instruction("br.s", 3), *_direct(), _instruction("ret")])
    diagnostic = config.settings_literal_diagnostics(assessment)
    assert diagnostic["status"] == "partial"
    assert diagnostic["fields"][0]["status"] == "observed_literal"
    assert diagnostic["effects"][0]["reason"] == "control_flow_not_interpreted"
    with pytest.raises(config.ConfigRecoveryError):
        config.settings_literals(b"synthetic-metadata")


def test_assessment_valid_eh_is_observation_only_and_malformed_eh_rejected(monkeypatch) -> None:
    handler = NS(try_start=0, try_end=2, handler_start=2, handler_end=3, exception_type=2, filter_start=-1)
    pe, assessment = _assessment(monkeypatch, [*_direct(), _instruction("ret")], handlers=[handler])
    assert assessment.status == "partial"
    assert config.settings_literal_diagnostics(assessment)["effects"] == [
        {"offset": None, "reason": "exception_flow_not_interpreted"},
    ]
    handler.handler_end = 99
    assert config.assess_settings_literals(b"synthetic-metadata").status == "rejected"


def test_assessment_duplicate_write_invalidates_all_dependent_fields(monkeypatch) -> None:
    instructions = [*_direct(), _instruction("ldsfld", 0x04000001), _instruction("stsfld", 0x04000002),
                    _instruction("ldsfld", 0x04000002), _instruction("stsfld", 0x04000003),
                    *_direct(), _instruction("ret")]
    _pe, assessment = _assessment(monkeypatch, instructions)
    diagnostic = config.settings_literal_diagnostics(assessment)
    assert diagnostic["status"] == "partial"
    assert all(field["status"] == "invalidated" for field in diagnostic["fields"])
    assert diagnostic["fields"][0]["reasons"] == ["duplicate_assignment"]
    assert diagnostic["fields"][2]["reasons"] == ["dependency_invalidated"]
    assert assessment._private_literals == {}


def test_assessment_forward_dependency_invalidates_only_affected_field(monkeypatch) -> None:
    _pe, assessment = _assessment(monkeypatch, [
        _instruction("ldsfld", 0x04000001), _instruction("stsfld", 0x04000002),
        *_direct(), _instruction("ret"),
    ])
    fields = config.settings_literal_diagnostics(assessment)["fields"]
    assert fields[0]["status"] == "invalidated"
    assert fields[0]["reasons"] == ["forward_or_unresolved_dependency"]
    assert fields[1]["status"] == "proven_literal"
    assert config.settings_literal_diagnostics(assessment)["effects_unresolved"] is False
    assert assessment._private_literals == {"0x04000001": "fixture-value"}


def test_assessment_same_named_field_candidates_are_not_merged(monkeypatch) -> None:
    pe = _metadata(monkeypatch, [*_direct(), _instruction("ret")])
    pe.net.mdtables.Field.rows[1].Name = "First"
    assessment = config.assess_settings_literals(b"synthetic-metadata")
    assert assessment.status == "partial"
    assert config.settings_literal_diagnostics(assessment)["fields"][0]["reasons"] == ["field_name_collision"]
    assert assessment._private_literals == {}


@pytest.mark.parametrize("damage", ["token", "signature", "offset", "branch", "rowcount", "body"])
def test_assessment_corruption_is_rejected_not_partial(monkeypatch, damage) -> None:
    instructions = [*_direct(), _instruction("call", 0x06000002), _instruction("ret")]
    pe = _metadata(monkeypatch, instructions)
    _known_unknown_call(pe)
    if damage == "token":
        instructions[2].operand.value = 0x06000003
    elif damage == "signature":
        pe.net.mdtables.MethodDef.rows[1].Signature.value = b"\x00\x01"
    elif damage == "offset":
        instructions[1].offset = 99
    elif damage == "branch":
        instructions[2].opcode.name = "br.s"
        instructions[2].operand.value = 99
    elif damage == "rowcount":
        pe.net.mdtables.Field.num_rows = 4
    else:
        monkeypatch.setattr(config, "read_bounded_method_body", lambda *_args: (_ for _ in ()).throw(ValueError("SECRET_BODY")))
    assessment = config.assess_settings_literals(b"synthetic-metadata")
    assert assessment.status == "rejected"
    assert assessment._private_literals == {}
    diagnostic = config.settings_literal_diagnostics(assessment)
    assert diagnostic["fields"] == [] and diagnostic["effects"] == []
    assert "SECRET_BODY" not in repr(diagnostic)


@pytest.mark.parametrize("limit", ["MAX_ASSESSMENT_FIELDS", "MAX_ASSESSMENT_ASSIGNMENTS", "MAX_INITIALIZER_INSTRUCTIONS"])
def test_assessment_limits_reject_without_partial_candidates(monkeypatch, limit) -> None:
    _metadata(monkeypatch, [*_direct(), _instruction("ldsfld", 0x04000001),
                           _instruction("stsfld", 0x04000002), _instruction("ret")])
    monkeypatch.setattr(config, limit, 1)
    assessment = config.assess_settings_literals(b"synthetic-metadata")
    assert assessment.status == "rejected" and assessment._private_literals == {}
    assert config.settings_literal_diagnostics(assessment)["fields"] == []


def test_assessment_literal_and_field_name_never_enter_public_serializers(monkeypatch) -> None:
    pe = _metadata(monkeypatch, [*_direct(), _instruction("ret")])
    pe.net.user_strings.get = lambda _index: NS(value="PRIVATE_LITERAL_TOKEN")
    pe.net.mdtables.Field.rows[0].Name = "PRIVATE_FIELD_NAME"
    assessment = config.assess_settings_literals(b"synthetic-metadata")
    assert not hasattr(assessment, "__dict__")
    public = (repr(assessment), str(assessment), json.dumps(assessment, default=str),
              json.dumps(assessment.__getstate__()), json.dumps(config.settings_literal_diagnostics(assessment)))
    assert all("PRIVATE_LITERAL_TOKEN" not in value and "PRIVATE_FIELD_NAME" not in value for value in public)
    with pytest.raises(TypeError):
        json.dumps(assessment)


def test_assessment_partial_is_not_a_recovery_input(monkeypatch) -> None:
    pe = _metadata(monkeypatch, [*_direct(), _instruction("call", 0x06000002), _instruction("ret")])
    _known_unknown_call(pe)
    assert config.assess_settings_literals(b"synthetic-metadata").status == "partial"
    monkeypatch.setattr(config, "_recover_obfuscated_chacha_asyncrat", lambda *_args: pytest.fail("DCRatに別回復器を使ってはいけません"))
    with pytest.raises(config.ConfigRecoveryError):
        config.recover(b"synthetic-metadata", "dcrat")


def test_assessment_unrelated_getfolderpath_is_not_ignored_as_pure(monkeypatch) -> None:
    instructions = [*_direct(), _instruction("ldc.i4.0"), _instruction("call", 0x06000002),
                    _instruction("stsfld", 0x04000002), _instruction("ldstr", 0x70000001),
                    _instruction("stsfld", 0x04000003), _instruction("ret")]
    pe = _metadata(monkeypatch, instructions)
    _known_unknown_call(pe, signature=b"\x00\x01\x0e\x08")
    pe.net.mdtables.MethodDef.rows[1].Name = "GetFolderPath"
    assessment = config.assess_settings_literals(b"synthetic-metadata")
    diagnostic = config.settings_literal_diagnostics(assessment)
    assert diagnostic["status"] == "partial" and diagnostic["effects_unresolved"] is True
    assert [field["status"] for field in diagnostic["fields"]] == [
        "observed_literal", "invalidated", "observed_literal",
    ]
    assert assessment._private_literals == {"0x04000001": "fixture-value", "0x04000003": "fixture-value"}
    assert "GetFolderPath" not in repr(diagnostic)
    with pytest.raises(config.ConfigRecoveryError):
        config.settings_literals(b"synthetic-metadata")


def test_assessment_cross_type_assignment_is_field_invalid_and_effect_unknown(monkeypatch) -> None:
    pe = _metadata(monkeypatch, [*_direct(), _instruction("ret")])
    pe.net.mdtables.TypeDef.rows[0].FieldList = [NS(row_index=2), NS(row_index=3)]
    pe.net.mdtables.TypeDef.rows.append(NS(TypeNamespace="Other", TypeName="Settings",
        FieldList=[NS(row_index=1)], MethodList=[]))
    pe.net.mdtables.TypeDef.num_rows = 2
    assessment = config.assess_settings_literals(b"synthetic-metadata")
    diagnostic = config.settings_literal_diagnostics(assessment)
    assert diagnostic["status"] == "partial" and diagnostic["effects_unresolved"] is True
    assert diagnostic["fields"][0]["reasons"] == ["cross_type_assignment"]
    assert diagnostic["effects"][0]["reason"] == "cross_type_static_access_unresolved"
    assert assessment._private_literals == {}


def test_assessment_multiple_producers_are_invalidated_without_stack_evaluation(monkeypatch) -> None:
    _pe, assessment = _assessment(monkeypatch, [_instruction("ldstr", 0x70000001),
        *_direct(), _instruction("ret")])
    assert assessment.status == "partial"
    assert config.settings_literal_diagnostics(assessment)["fields"][0]["reasons"] == ["multiple_lexical_producers"]
    assert assessment._private_literals == {}


def test_assessment_calli_signature_is_not_a_concrete_call_target(monkeypatch) -> None:
    pe = _metadata(monkeypatch, [*_direct(), _instruction("calli", 0x11000001), _instruction("ret")])
    pe.net.mdtables.StandAloneSig = NS(num_rows=1, rows=[NS(Signature=NS(value=b"\x00\x00\x01"))])
    assessment = config.assess_settings_literals(b"synthetic-metadata")
    assert assessment.status == "partial"
    assert config.settings_literal_diagnostics(assessment)["effects"][0]["reference_token"] == "0x11000001"


@pytest.mark.parametrize("opcode", ["stobj", "box", "constrained.", "ldtoken"])
def test_assessment_malformed_type_tokens_are_rejected(monkeypatch, opcode) -> None:
    _pe, assessment = _assessment(monkeypatch, [*_direct(), _instruction(opcode, 0x02000002), _instruction("ret")])
    assert assessment.status == "rejected" and assessment._private_literals == {}


def test_assessment_unknown_opcode_is_rejected_before_observations(monkeypatch) -> None:
    _pe, assessment = _assessment(monkeypatch, [*_direct(), _instruction("unknown-malformed-opcode"), _instruction("ret")])
    assert assessment.status == "rejected" and assessment._private_literals == {}


def test_assessment_effect_limit_includes_eh_summary(monkeypatch) -> None:
    handler = NS(try_start=0, try_end=2, handler_start=2, handler_end=4, exception_type=2, filter_start=-1)
    _metadata(monkeypatch, [*_direct(), _instruction("ldloca.s", 0), _instruction("ret")], handlers=[handler])
    monkeypatch.setattr(config, "MAX_ASSESSMENT_ASSIGNMENTS", 1)
    assessment = config.assess_settings_literals(b"synthetic-metadata")
    assert assessment.status == "rejected" and assessment._private_literals == {}
    assert config.settings_literal_diagnostics(assessment)["reasons"] == ["assessment_limit_exceeded"]


@pytest.mark.parametrize("api", [config.settings_literals, config.assess_settings_literals])
def test_literal_reader_gets_one_user_string_once_per_cctor(monkeypatch, api) -> None:
    instructions = [*_direct(), _instruction("ldstr", 0x70000001), _instruction("stsfld", 0x04000002),
        _instruction("ldsfld", 0x04000002), _instruction("stsfld", 0x04000003), _instruction("ret")]
    pe = _metadata(monkeypatch, instructions)
    value = "FIXTURE_IMMUTABLE_VALUE"
    calls = []
    pe.net.user_strings.get = lambda index: (calls.append(index), NS(value=value))[1]
    result = api(b"synthetic-metadata")
    assert calls == [1]
    values = result.values() if isinstance(result, dict) else result._private_literals.values()
    assert all(candidate is value for candidate in values)


def test_literal_reader_utf8_budget_counts_japanese_and_rejects_before_cache(monkeypatch) -> None:
    pe = _metadata(monkeypatch, [*_direct(), _instruction("ret")])
    pe.net.user_strings.get = lambda index: NS(value={1: "日本", 2: "語"}[index])
    monkeypatch.setattr(config, "MAX_LITERAL_UTF8_BYTES", 8)
    reader = config._LiteralReader(pe)
    assert reader.read(0x70000001) == "日本" and reader._utf8_bytes == 6
    with pytest.raises(config.ConfigRecoveryError, match="UTF-8総保持量"):
        reader.read(0x70000002)
    assert reader._cache == {0x70000001: "日本"} and reader._utf8_bytes == 6


@pytest.mark.parametrize("budget", ["MAX_LITERAL_COUNT", "MAX_LITERAL_UTF8_BYTES"])
def test_literal_budget_exhaustion_rejects_strict_and_discards_partial(monkeypatch, budget) -> None:
    pe = _metadata(monkeypatch, [*_direct(), _instruction("ldstr", 0x70000002),
        _instruction("stsfld", 0x04000002), _instruction("ret")])
    calls = []
    pe.net.user_strings.get = lambda index: (calls.append(index), NS(value={1: "ab", 2: "cd"}[index]))[1]
    monkeypatch.setattr(config, budget, 1 if budget == "MAX_LITERAL_COUNT" else 3)
    with pytest.raises(config.ConfigRecoveryError, match="上限"):
        config.settings_literals(b"synthetic-metadata")
    assert calls == ([1] if budget == "MAX_LITERAL_COUNT" else [1, 2])
    calls.clear()
    assessment = config.assess_settings_literals(b"synthetic-metadata")
    assert assessment.status == "rejected" and assessment._private_literals == {}
    assert config.settings_literal_diagnostics(assessment)["reasons"] == ["literal_retention_budget_exceeded"]
    assert calls == ([1] if budget == "MAX_LITERAL_COUNT" else [1, 2])


@pytest.mark.parametrize("invalid", [True, False, 0x70000000, 0x70000002, 0x170000001])
def test_literal_reader_invalid_heap_tokens_never_become_candidates(monkeypatch, invalid) -> None:
    pe = _metadata(monkeypatch, [_instruction("ldstr", invalid), _instruction("stsfld", 0x04000001), _instruction("ret")])
    assert config.assess_settings_literals(b"synthetic-metadata").status == "rejected"
    with pytest.raises(config.ConfigRecoveryError):
        config.settings_literals(b"synthetic-metadata")


def test_literal_reader_extreme_single_literal_and_invalid_unicode_are_rejected(monkeypatch) -> None:
    pe = _metadata(monkeypatch, [*_direct(), _instruction("ret")])
    monkeypatch.setattr(config, "MAX_ENCODED_SETTING_CHARS", 16)
    pe.net.user_strings.get = lambda _index: NS(value="a" * 17)
    assert config.assess_settings_literals(b"synthetic-metadata").status == "rejected"
    pe.net.user_strings.get = lambda _index: NS(value="\ud800")
    assert config.assess_settings_literals(b"synthetic-metadata").status == "rejected"


@pytest.mark.parametrize("signature,static", [
    (b"\x20\x00\x01", False), (b"\x00\x01\x01\x08", True),
    (b"\x00\x00\x08", True), (b"\x00\x00", True), (b"\x00\x00\x01", False),
    (b"\x00\x00\x01", 1),
])
def test_cctor_declaration_rejects_instance_arguments_returns_and_damage(monkeypatch, signature, static) -> None:
    pe = _metadata(monkeypatch, [*_direct(), _instruction("ret")])
    pe.net.mdtables.MethodDef.rows[0].Signature.value = signature
    pe.net.mdtables.MethodDef.rows[0].Flags.mdStatic = static
    with pytest.raises(config.ConfigRecoveryError, match="static cctor宣言"):
        config.settings_literals(b"synthetic-metadata")
    assert config.assess_settings_literals(b"synthetic-metadata").status == "rejected"


def _salt_metadata(monkeypatch, *, nops=False):
    instructions = [
        _instruction("call", 0x0A000001), _instruction("ldstr", 0x70000001),
        _instruction("callvirt", 0x0A000002), _instruction("stsfld", 0x04000001), _instruction("ret"),
    ]
    if nops:
        instructions = [instruction for item in instructions for instruction in (item, _instruction("nop"))]
    pe = _metadata(monkeypatch, instructions)
    table = pe.net.mdtables
    table.TypeDef.rows[0].TypeNamespace = "Client.Algorithm"
    table.TypeDef.rows[0].TypeName = "Aes256"
    table.Field.rows[0].Name = "Salt"
    table.Field.rows[0].Signature.value = b"\x06\x1d\x05"
    table.AssemblyRef = NS(num_rows=1, rows=[NS(
        Name="mscorlib", Culture="", PublicKey=NS(value=bytes.fromhex("b77a5c561934e089")),
        MajorVersion=4, MinorVersion=0, BuildNumber=0, RevisionNumber=0, struct=NS(Flags=0),
    )])
    table.TypeRef = NS(num_rows=1, rows=[NS(TypeNamespace="System.Text", TypeName="Encoding",
        ResolutionScope=NS(table=table.AssemblyRef, row_index=1))])
    table.MemberRef = NS(num_rows=2, rows=[
        NS(Name="get_ASCII", Class=NS(table=table.TypeRef, row_index=1), Signature=NS(value=b"\x00\x00\x12\x05")),
        NS(Name="GetBytes", Class=NS(table=table.TypeRef, row_index=1), Signature=NS(value=b"\x20\x01\x1d\x05\x0e")),
    ])
    pe.net.user_strings.get = lambda _index: NS(value="PRIVATE_FIXTURE_SALT")
    return pe, instructions


@pytest.mark.parametrize("nops", [False, True])
def test_static_salt_exact_declaration_and_adjacent_receiver_match(monkeypatch, nops) -> None:
    _salt_metadata(monkeypatch, nops=nops)
    assert config.static_salt(b"synthetic-metadata", "Client.Algorithm.Aes256") == b"PRIVATE_FIXTURE_SALT"


@pytest.mark.parametrize("damage", ["methoddef", "owner", "assembly", "publickey", "signature", "return",
    "scope", "fieldtype", "fieldstatic", "cctorstatic", "fieldduplicate", "token"])
def test_static_salt_leaf_names_do_not_override_exact_declaration(monkeypatch, damage) -> None:
    pe, instructions = _salt_metadata(monkeypatch)
    table = pe.net.mdtables
    if damage == "methoddef":
        table.MethodDef.rows.extend([
            NS(Name="get_ASCII", Signature=NS(value=b"\x00\x00\x12\x05")),
            NS(Name="GetBytes", Signature=NS(value=b"\x20\x01\x1d\x05\x0e")),
        ])
        table.MethodDef.num_rows = 3
        table.TypeDef.rows[0].MethodList.extend([NS(row_index=2), NS(row_index=3)])
        instructions[0].operand.value = 0x06000002
        instructions[2].operand.value = 0x06000003
    elif damage == "owner":
        table.TypeRef.rows[0].TypeName = "FakeEncoding"
    elif damage == "assembly":
        table.AssemblyRef.rows[0].Name = "SpoofedFramework"
    elif damage == "publickey":
        table.AssemblyRef.rows[0].PublicKey.value = b"\0" * 8
    elif damage == "signature":
        table.MemberRef.rows[1].Signature.value = b"\x20\x01\x1d\x05\x08"
    elif damage == "return":
        table.MemberRef.rows[0].Signature.value = b"\x00\x00\x1c"
    elif damage == "scope":
        table.TypeRef.rows[0].ResolutionScope.table = NS(rows=table.AssemblyRef.rows)
    elif damage == "fieldtype":
        table.Field.rows[0].Signature.value = b"\x06\x0e"
    elif damage == "fieldstatic":
        table.Field.rows[0].Flags.fdStatic = False
    elif damage == "cctorstatic":
        table.MethodDef.rows[0].Flags.mdStatic = False
    elif damage == "fieldduplicate":
        table.Field.rows[1].Name = "Salt"
    else:
        instructions[0].operand.value = True
    with pytest.raises(config.ConfigRecoveryError):
        config.static_salt(b"synthetic-metadata", "Client.Algorithm.Aes256")


@pytest.mark.parametrize("shape", ["literal_first", "extra_literal", "receiver_replaced", "local_alias",
                                   "duplicate_write", "unknown_call", "branch", "getbytes_call"])
def test_static_salt_receiver_binding_is_exact_lexical_template(monkeypatch, shape) -> None:
    _pe, instructions = _salt_metadata(monkeypatch)
    if shape == "literal_first":
        instructions[0], instructions[1] = instructions[1], instructions[0]
    elif shape == "extra_literal":
        instructions.insert(2, _instruction("ldstr", 0x70000001))
    elif shape == "receiver_replaced":
        instructions.insert(3, _instruction("call", 0x0A000001))
    elif shape == "local_alias":
        instructions[1:1] = [_instruction("stloc.0"), _instruction("ldloc.0")]
    elif shape == "duplicate_write":
        instructions.insert(4, _instruction("stsfld", 0x04000001))
    elif shape == "unknown_call":
        instructions.insert(4, _instruction("call", 0x06000001))
    elif shape == "branch":
        instructions.insert(2, _instruction("br.s", 3))
    else:
        instructions[2].opcode.name = "call"
    # 合成body境界は変更後のrecord列に一致させ、形状陰性の根拠を分離する。
    for offset, instruction in enumerate(instructions):
        instruction.offset, instruction.size = offset, 1
    with pytest.raises(config.ConfigRecoveryError):
        config.static_salt(b"synthetic-metadata", "Client.Algorithm.Aes256")


@pytest.mark.parametrize("difference", ["ascii_receiver", "assembly_version", "coverage"])
def test_static_salt_matching_members_must_share_receiver_and_assembly(monkeypatch, difference) -> None:
    pe, _instructions = _salt_metadata(monkeypatch)
    table = pe.net.mdtables
    if difference == "coverage":
        table.TypeRef.num_rows = 2
    else:
        assembly_index = 1
        if difference == "assembly_version":
            table.AssemblyRef.rows.append(NS(
                Name="mscorlib", Culture="", PublicKey=NS(value=bytes.fromhex("b77a5c561934e089")),
                MajorVersion=2, MinorVersion=0, BuildNumber=0, RevisionNumber=0, struct=NS(Flags=0),
            ))
            table.AssemblyRef.num_rows = 2
            assembly_index = 2
        table.TypeRef.rows.append(NS(TypeNamespace="System.Text",
            TypeName="ASCIIEncoding" if difference == "ascii_receiver" else "Encoding",
            ResolutionScope=NS(table=table.AssemblyRef, row_index=assembly_index)))
        table.TypeRef.num_rows = 2
        table.MemberRef.rows[1].Class.row_index = 2
        # 個々の宣言だけならreview済みだが、receiver/assemblyの結合は不成立。
        from unpackers.managed_metadata import MetadataResolver
        resolver = MetadataResolver(pe)
        assert resolver.match_framework_member(0x0A000001, "system_text_encoding_get_ascii_v1")["status"] == "matched_declaration"
        assert resolver.match_framework_member(0x0A000002, "system_text_encoding_get_bytes_string_v1")["status"] == "matched_declaration"
    with pytest.raises(config.ConfigRecoveryError):
        config.static_salt(b"synthetic-metadata", "Client.Algorithm.Aes256")


def test_fake_ascii_api_does_not_reach_hmac_recovery_or_publish_c2(monkeypatch) -> None:
    pe, _instructions = _salt_metadata(monkeypatch)
    pe.net.mdtables.TypeRef.rows[0].TypeName = "FakeEncoding"
    profile = config.PROFILES["dcrat"]
    values = {"Key": base64.b64encode(b"fixture-key").decode(), **{
        name: _encrypt("synthetic-authenticated-value") for name in profile["fields"].values()
    }}
    monkeypatch.setattr(config, "settings_literals", lambda *_args: values)
    monkeypatch.setattr(config, "_derive", lambda *_args: pytest.fail("偽ASCII宣言からHMAC設定復元へ進めてはいけません"))
    with pytest.raises(config.ConfigRecoveryError, match="framework member宣言"):
        config.recover(b"synthetic-metadata", "dcrat")


@pytest.mark.parametrize("flags,impl", [
    (True, 0), (0x10000, 0), (-1, 0), (0, 0), (0x410, 0), (0x2010, 0), (0x18, 0), (0x17, 0),
    (0x10, True), (0x10, -1), (0x10, 0x10000), (0x10, 1), (0x10, 2), (0x10, 3),
    (0x10, 4), (0x10, 0x10), (0x10, 0x1000), (0x10, 0x400), (0x10, 0x8000),
])
def test_cctor_raw_flags_reject_non_cil_and_unreviewed_declarations(monkeypatch, flags, impl) -> None:
    pe = _metadata(monkeypatch, [*_direct(), _instruction("ret")])
    pe.net.mdtables.MethodDef.rows[0].struct.Flags = flags
    pe.net.mdtables.MethodDef.rows[0].struct.ImplFlags = impl
    with pytest.raises(config.ConfigRecoveryError, match="cctor"):
        config.settings_literals(b"synthetic-metadata")
    assert config.assess_settings_literals(b"synthetic-metadata").status == "rejected"
    _salt_metadata(monkeypatch)
    pe = config.dnfile.dnPE(data=b"synthetic-metadata")
    pe.net.mdtables.MethodDef.rows[0].struct.Flags = flags
    pe.net.mdtables.MethodDef.rows[0].struct.ImplFlags = impl
    with pytest.raises(config.ConfigRecoveryError, match="cctor"):
        config.static_salt(b"synthetic-metadata", "Client.Algorithm.Aes256")


@pytest.mark.parametrize("impl", [0, 0x08, 0x20, 0x40, 0x80, 0x100, 0x200, 0x03E8])
def test_cctor_non_code_kind_implementation_flags_are_not_over_rejected(monkeypatch, impl) -> None:
    pe = _metadata(monkeypatch, [*_direct(), _instruction("ret")])
    pe.net.mdtables.MethodDef.rows[0].struct.ImplFlags = impl
    assert config.settings_literals(b"synthetic-metadata") == {"First": "fixture-value"}
    assert config.assess_settings_literals(b"synthetic-metadata").status == "complete"
