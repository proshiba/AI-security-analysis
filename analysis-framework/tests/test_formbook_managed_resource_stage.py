"""managed ResourceSet loaderの静的復号とfail-closed条件を検証する。"""

from __future__ import annotations

import hashlib
import json
import struct
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

FRAMEWORK = Path(__file__).parents[1]
COMMON = FRAMEWORK / "common"
REPOSITORY_ROOT = FRAMEWORK.parent
for trusted in (REPOSITORY_ROOT, FRAMEWORK, COMMON):
    if str(trusted) not in sys.path:
        sys.path.insert(0, str(trusted))

from unpackers.tests.resource_literal_pe_fixture import (
    resource_build_literal_pe,
)

from malware.formbook_loader import detect as detector
from malware.formbook_loader import extract_config as facade
from malware.formbook_loader import managed_resource_stage as managed

KEY_TEXT = "fixture-managed-key-01"
RESOURCE_NAME = "fixture_stage_blob"
SWAP_TOKEN = 0x06000002
MAIN_TOKEN = 0x06000003
METHOD_SIGNATURE = b"\x00\x00\x01"
SWAP_SIGNATURE = b"\x20\x02\x01\x10\x08\x10\x08"
UNSIGNED_SWAP_SIGNATURE = b"\x20\x02\x01\x10\x09\x10\x09"


def _instruction(opcode: str, **values: object) -> dict[str, object]:
    return {"opcode": opcode, **values}


def _local(opcode: str, index: int) -> dict[str, object]:
    return _instruction(opcode, operand=f"local(0x{index:04x})")


def _constant(value: int) -> dict[str, object]:
    return _instruction("ldc.i4", value=value)


def _call(api: str, *, opcode: str = "call", token: int | None = None) -> dict[str, object]:
    result = _instruction(opcode, resolved_api=api)
    if token is not None:
        result["token"] = token
    return result


def _method(
    token: int,
    instructions: list[dict[str, object]],
    *,
    signature: bytes = METHOD_SIGNATURE,
) -> managed._Method:
    normalized = []
    for index, instruction in enumerate(instructions):
        normalized.append({"offset": index * 2, **instruction})
    return managed._Method(token, 0x2000 + token, signature, tuple(normalized))


def _binding_prefix() -> list[dict[str, object]]:
    return [
        _instruction("ldtoken", resolved_type="Fixture.Loader"),
        _call("type_get_type_from_handle"),
        _call("component_resource_manager_ctor", opcode="newobj"),
        _local("stloc", 0),
        _local("ldloc", 0),
        _instruction("ldstr", string=RESOURCE_NAME),
        _call("resource_manager_get_object", opcode="callvirt"),
        _instruction("isinst", resolved_type="System.Byte[]"),
        _local("stloc", 1),
        _call("encoding_get_default"),
        _instruction("ldstr", string=KEY_TEXT),
        _call("encoding_get_bytes_string", opcode="callvirt"),
        _local("stloc", 2),
    ]


def _swap_helper(
    *,
    changed_opcode: str | None = None,
    unsigned: bool = False,
) -> managed._Method:
    instructions = [_instruction(opcode) for opcode in managed._SWAP_OPCODES]
    if changed_opcode is not None:
        instructions[2] = _instruction(changed_opcode)
    signature = UNSIGNED_SWAP_SIGNATURE if unsigned else SWAP_SIGNATURE
    return _method(SWAP_TOKEN, instructions, signature=signature)


def _swap_call(left: int, right: int) -> list[dict[str, object]]:
    return [
        _instruction("ldarg.0"),
        _local("ldloc", 3),
        _local("ldloc", left),
        _instruction("ldelema", resolved_type="System.Int32"),
        _local("ldloc", 3),
        _local("ldloc", right),
        _instruction("ldelema", resolved_type="System.Int32"),
        _call("", token=SWAP_TOKEN),
    ]


def _rc4_method() -> managed._Method:
    instructions = _binding_prefix()
    instructions.extend(
        [
            # S[0..255] = 0..255
            _constant(256),
            _instruction("newarr", resolved_type="System.Int32"),
            _local("stloc", 3),
            _constant(0),
            _local("stloc", 4),
            _local("ldloc", 3),
            _local("ldloc", 4),
            _local("ldloc", 4),
            _instruction("stelem.i4"),
            _local("ldloc", 4),
            _constant(1),
            _instruction("add"),
            _local("stloc", 4),
            _local("ldloc", 4),
            _constant(256),
            _instruction("blt.s", value=1),
            # KSA
            _constant(0),
            _local("stloc", 6),
            _constant(0),
            _local("stloc", 5),
            _local("ldloc", 5),
            _local("ldloc", 2),
            _local("ldloc", 6),
            _local("ldloc", 2),
            _instruction("ldlen"),
            _instruction("rem"),
            _instruction("ldelem.u1"),
            _instruction("add"),
            _local("ldloc", 3),
            _local("ldloc", 6),
            _instruction("ldelem.i4"),
            _instruction("add"),
            _constant(255),
            _instruction("and"),
            _local("stloc", 5),
        ]
    )
    instructions.extend(_swap_call(6, 5))
    instructions.extend(
        [
            _local("ldloc", 6),
            _constant(1),
            _instruction("add"),
            _local("stloc", 6),
            _local("ldloc", 6),
            _constant(256),
            _instruction("blt.s", value=1),
            # PRGA output
            _local("ldloc", 1),
            _instruction("ldlen"),
            _instruction("newarr", resolved_type="System.Byte"),
            _local("stloc", 9),
            _constant(0),
            _local("stloc", 7),
            _constant(0),
            _local("stloc", 8),
            _constant(0),
            _local("stloc", 10),
            _local("ldloc", 7),
            _constant(1),
            _instruction("add"),
            _constant(255),
            _instruction("and"),
            _local("stloc", 7),
            _local("ldloc", 8),
            _local("ldloc", 3),
            _local("ldloc", 7),
            _instruction("ldelem.i4"),
            _instruction("add"),
            _constant(255),
            _instruction("and"),
            _local("stloc", 8),
        ]
    )
    instructions.extend(_swap_call(7, 8))
    instructions.extend(
        [
            _local("ldloc", 9),
            _local("ldloc", 10),
            _local("ldloc", 1),
            _local("ldloc", 10),
            _instruction("ldelem.u1"),
            _local("ldloc", 3),
            _local("ldloc", 3),
            _local("ldloc", 7),
            _instruction("ldelem.i4"),
            _local("ldloc", 3),
            _local("ldloc", 8),
            _instruction("ldelem.i4"),
            _instruction("add"),
            _constant(255),
            _instruction("and"),
            _instruction("ldelem.i4"),
            _instruction("xor"),
            _instruction("stelem.i1"),
            _local("ldloc", 10),
            _constant(1),
            _instruction("add"),
            _local("stloc", 10),
            _local("ldloc", 10),
            _local("ldloc", 1),
            _instruction("ldlen"),
            _instruction("blt.s", value=1),
            # Type.InvokeMember("L:oad".Replace(":", ""), 256, ..., byte[])
            _instruction("ldtoken", resolved_type="System.Reflection.Assembly"),
            _call("type_get_type_from_handle"),
            _instruction("ldstr", string="L:oad"),
            _instruction("ldstr", string=":"),
            _instruction("ldstr", string=""),
            _call("string_replace_string_string", opcode="callvirt"),
            _constant(256),
            _instruction("ldnull"),
            _instruction("ldnull"),
            _constant(1),
            _instruction("newarr", resolved_type="System.Object"),
            _instruction("dup"),
            _constant(0),
            _local("ldloc", 9),
            _instruction("stelem.ref"),
            _call("type_invoke_member", opcode="callvirt"),
            _instruction("ret"),
        ]
    )
    return _method(MAIN_TOKEN, instructions)


def _rc4_unsigned_proxy_method() -> managed._Method:
    """UInt32 state、clt local、index localを使う匿名化fixture。"""

    source = [
        {key: value for key, value in item.items() if key != "offset"}
        for item in _rc4_method().instructions
    ]
    transformed: list[dict[str, object]] = []
    branch_index = 0
    swap_count = 0
    output_index_cached = False
    for item in source:
        if item.get("resolved_type") == "System.Int32":
            item["resolved_type"] = "System.UInt32"
        opcode = str(item.get("opcode") or "")
        if opcode.startswith("blt"):
            boolean_local = 11 + branch_index
            transformed.extend(
                [
                    _instruction("clt" if branch_index == 2 else "clt.un"),
                    _local("stloc", boolean_local),
                    _local("ldloc", boolean_local),
                    _instruction("brtrue.s", value=item.get("value")),
                ]
            )
            branch_index += 1
            continue
        transformed.append(item)
        if item.get("token") == SWAP_TOKEN:
            swap_count += 1
        elif (
            swap_count == 2
            and not output_index_cached
            and opcode == "and"
        ):
            transformed.extend([_local("stloc", 15), _local("ldloc", 15)])
            output_index_cached = True
    assert branch_index == 3
    assert output_index_cached is True
    return _method(MAIN_TOKEN, transformed)


def _feedback_method(*, counter_value: int = 0, reassign_counter: bool = False) -> managed._Method:
    instructions = _binding_prefix()
    instructions.extend(
        [
            _constant(counter_value),
            _local("stloc", 3),
        ]
    )
    if reassign_counter:
        instructions.extend([_constant(0), _local("stloc", 3)])
    instructions.extend(
        [
            _constant(0),
            _local("stloc", 4),
            _local("ldloc", 1),
            _local("ldloc", 4),
            _local("ldloc", 1),
            _instruction("ldlen"),
            _instruction("rem"),
            _local("ldloc", 1),
            _local("ldloc", 4),
            _local("ldloc", 1),
            _instruction("ldlen"),
            _instruction("rem"),
            _instruction("ldelem.u1"),
            _local("ldloc", 2),
            _local("ldloc", 4),
            _constant(len(KEY_TEXT)),
            _instruction("rem"),
            _instruction("ldelem.u1"),
            _instruction("xor"),
            _local("ldloc", 1),
            _local("ldloc", 4),
            _constant(1),
            _instruction("add"),
            _local("ldloc", 1),
            _instruction("ldlen"),
            _instruction("rem"),
            _instruction("ldelem.u1"),
            _instruction("sub"),
            _constant(256),
            _instruction("add"),
            _constant(256),
            _instruction("rem"),
            _instruction("conv.u1"),
            _instruction("stelem.i1"),
            _local("ldloc", 4),
            _constant(1),
            _instruction("add"),
            _local("stloc", 4),
            _local("ldloc", 4),
            _local("ldloc", 1),
            _instruction("ldlen"),
            _local("ldloc", 3),
            _constant(1),
            _instruction("add"),
            _instruction("mul"),
            _instruction("blt.s", value=1),
            _call("appdomain_get_current"),
            _local("ldloc", 1),
            _call("appdomain_load_bytes", opcode="callvirt"),
            _call("assembly_get_exported_types", opcode="callvirt"),
            _constant(5),
            _instruction("ldelem.ref"),
            _call("type_get_methods", opcode="callvirt"),
            _constant(3),
            _instruction("ldelem.ref"),
            _instruction("ldnull"),
            _instruction("ldnull"),
            _call("methodbase_invoke", opcode="callvirt"),
            _instruction("ret"),
        ]
    )
    return _method(MAIN_TOKEN, instructions)


def _feedback_proxy_method() -> managed._Method:
    """length／index／算術値／clt結果をlocalへ置く匿名化fixture。"""

    instructions = _binding_prefix()
    instructions.extend(
        [
            _constant(0),
            _local("stloc", 3),
            _local("ldloc", 1),
            _instruction("ldlen"),
            _local("stloc", 4),
            _constant(0),
            _local("stloc", 5),
            _local("ldloc", 5),
            _local("ldloc", 4),
            _instruction("rem"),
            _local("stloc", 9),
            _local("ldloc", 1),
            _local("ldloc", 9),
            _instruction("ldelem.u1"),
            _local("ldloc", 2),
            _local("ldloc", 5),
            _constant(len(KEY_TEXT)),
            _instruction("rem"),
            _instruction("ldelem.u1"),
            _instruction("xor"),
            _local("stloc", 10),
            _local("ldloc", 10),
            _local("ldloc", 1),
            _local("ldloc", 5),
            _constant(1),
            _instruction("add"),
            _local("ldloc", 4),
            _instruction("rem"),
            _instruction("ldelem.u1"),
            _instruction("sub"),
            _constant(256),
            _instruction("add"),
            _local("stloc", 11),
            _local("ldloc", 1),
            _local("ldloc", 9),
            _local("ldloc", 11),
            _constant(256),
            _instruction("rem"),
            _instruction("conv.u1"),
            _instruction("stelem.i1"),
            _local("ldloc", 5),
            _constant(1),
            _instruction("add"),
            _local("stloc", 5),
            _local("ldloc", 5),
            _local("ldloc", 4),
            _local("ldloc", 3),
            _constant(1),
            _instruction("add"),
            _instruction("mul"),
            _instruction("clt"),
            _local("stloc", 12),
            _local("ldloc", 12),
            _instruction("brtrue.s", value=0),
            _call("appdomain_get_current"),
            _local("ldloc", 1),
            _call("appdomain_load_bytes", opcode="callvirt"),
            _call("assembly_get_exported_types", opcode="callvirt"),
            _constant(5),
            _instruction("ldelem.ref"),
            _call("type_get_methods", opcode="callvirt"),
            _constant(3),
            _instruction("ldelem.ref"),
            _instruction("ldnull"),
            _instruction("ldnull"),
            _call("methodbase_invoke", opcode="callvirt"),
            _instruction("ret"),
        ]
    )
    return _method(MAIN_TOKEN, instructions)


def _resource(data: bytes) -> managed._ResourceValue:
    return managed._ResourceValue(
        RESOURCE_NAME,
        data,
        hashlib.sha256(data).hexdigest(),
    )


def _recover(
    method: managed._Method,
    encrypted: bytes,
    *,
    helper: managed._Method | None = None,
) -> tuple[dict[str, object], bytes]:
    methods = [method] if helper is None else [helper, method]
    return managed._recover_model(
        b"artificial-parent",
        methods,
        [_resource(encrypted)],
        {},
        deadline=time.monotonic() + 1.0,
    )


def _feedback_encrypt(plaintext: bytes, key: bytes) -> bytes:
    encrypted = bytearray(len(plaintext))
    encrypted[-1] = ((plaintext[-1] + plaintext[0]) % 256) ^ key[
        (len(plaintext) - 1) % len(key)
    ]
    for index in range(len(plaintext) - 2, -1, -1):
        encrypted[index] = (
            (plaintext[index] + encrypted[index + 1]) % 256
        ) ^ key[index % len(key)]
    return bytes(encrypted)


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


def _resource_set(name: str, value: bytes) -> bytes:
    header = _binary_string(
        "System.Resources.ResourceReader, mscorlib", "utf-8"
    ) + _binary_string(
        "System.Resources.RuntimeResourceSet, mscorlib", "utf-8"
    )
    raw = bytearray(struct.pack("<Iii", managed.RESOURCE_MAGIC, 1, len(header)))
    raw.extend(header)
    raw.extend(struct.pack("<iii", 2, 1, 0))
    while len(raw) % 8:
        raw.append(0)
    raw.extend(struct.pack("<I", 0))
    raw.extend(struct.pack("<i", 0))
    data_section_field = len(raw)
    raw.extend(b"\0\0\0\0")
    name_record = _binary_string(name, "utf-16le") + struct.pack("<i", 0)
    data_section = len(raw) + len(name_record)
    struct.pack_into("<i", raw, data_section_field, data_section)
    raw.extend(name_record)
    raw.extend(_write_7bit(32))
    raw.extend(struct.pack("<I", len(value)))
    raw.extend(value)
    return bytes(raw)


def test_rc4_recipe_recovers_one_managed_child_without_secret_metadata() -> None:
    child = resource_build_literal_pe().data
    key = KEY_TEXT.encode("ascii")
    encrypted = managed._rc4(child, key)

    report, recovered = _recover(_rc4_method(), encrypted, helper=_swap_helper())

    assert recovered == child
    assert report["variant"] == "managed_resource_standard_rc4_reflection_loader"
    assert report["supports_family_attribution"] is False
    assert report["terminal_family_confirmed"] is False
    assert report["key"] == {
        "length": len(key),
        "value_published": False,
        "hash_published": False,
    }
    assert report["resource"]["name_published"] is False
    assert report["recovered_child"]["overlay_size"] == 0
    published = json.dumps(report, sort_keys=True)
    assert KEY_TEXT not in published
    assert RESOURCE_NAME not in published


def test_rc4_recipe_rejects_changed_swap_helper_shape() -> None:
    child = resource_build_literal_pe().data
    encrypted = managed._rc4(child, KEY_TEXT.encode("ascii"))

    with pytest.raises(managed.ManagedResourceStageNoEvidence):
        _recover(
            _rc4_method(),
            encrypted,
            helper=_swap_helper(changed_opcode="ldind.i4"),
        )


def test_rc4_recipe_accepts_uint32_state_and_compiler_proxy_locals() -> None:
    child = resource_build_literal_pe().data
    encrypted = managed._rc4(child, KEY_TEXT.encode("ascii"))

    report, recovered = _recover(
        _rc4_unsigned_proxy_method(),
        encrypted,
        helper=_swap_helper(unsigned=True),
    )

    assert recovered == child
    assert report["variant"] == "managed_resource_standard_rc4_reflection_loader"


def test_feedback_recipe_retains_validated_one_byte_overlay() -> None:
    child = resource_build_literal_pe().data + b"\xa5"
    key = KEY_TEXT.encode("ascii")
    encrypted = _feedback_encrypt(child, key)
    assert managed._feedback(encrypted, key) == child

    report, recovered = _recover(_feedback_method(), encrypted)

    assert recovered == child
    assert report["variant"] == "managed_resource_feedback_xor_sub_appdomain_loader"
    assert report["recovered_child"]["structural_extent"] == len(child) - 1
    assert report["recovered_child"]["overlay_size"] == 1


def test_feedback_recipe_accepts_compiler_proxy_locals_and_clt_branch() -> None:
    child = resource_build_literal_pe().data
    key = KEY_TEXT.encode("ascii")
    encrypted = _feedback_encrypt(child, key)

    report, recovered = _recover(_feedback_proxy_method(), encrypted)

    assert recovered == child
    assert report["variant"] == "managed_resource_feedback_xor_sub_appdomain_loader"


@pytest.mark.parametrize(
    ("counter_value", "reassign_counter"),
    [(1, False), (0, True)],
)
def test_feedback_recipe_requires_single_literal_zero_counter(
    counter_value: int,
    reassign_counter: bool,
) -> None:
    child = resource_build_literal_pe().data
    encrypted = _feedback_encrypt(child, KEY_TEXT.encode("ascii"))

    with pytest.raises(managed.ManagedResourceStageNoEvidence):
        _recover(
            _feedback_method(
                counter_value=counter_value,
                reassign_counter=reassign_counter,
            ),
            encrypted,
        )


def test_managed_pe_rejects_large_overlay_without_truncating_small_overlay() -> None:
    child = resource_build_literal_pe().data

    assert managed._managed_pe_extent(child + b"x") == len(child)
    assert managed._managed_pe_extent(child + b"x" * 4_097) is None


def test_resource_set_parser_reads_only_bounded_byte_array() -> None:
    raw = _resource_set(RESOURCE_NAME, b"fixture-ciphertext")

    values = managed._parse_resource_set(raw)

    assert [(value.name, value.data) for value in values] == [
        (RESOURCE_NAME, b"fixture-ciphertext")
    ]
    with pytest.raises(managed.ManagedResourceStageNoEvidence):
        managed._parse_resource_set(raw[:-1])


def test_resource_enumeration_skips_only_unrelated_invalid_container(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unrelated = struct.pack("<I", managed.RESOURCE_MAGIC) + b"invalid"
    selected = _resource_set(RESOURCE_NAME, b"fixture-ciphertext")
    data = unrelated + selected
    coverage = {
        "status": "complete",
        "inventory_complete": True,
        "embedded_scan_complete": True,
        "input_binding_verified": True,
        "reason_counts": {},
        "executed": False,
        "clr_loaded": False,
        "network_contacted": False,
    }
    scan = SimpleNamespace(
        _coverage=coverage,
        _descriptors=(
            SimpleNamespace(
                kind="embedded",
                body_offset=0,
                body_size=len(unrelated),
            ),
            SimpleNamespace(
                kind="embedded",
                body_offset=len(unrelated),
                body_size=len(selected),
            ),
        ),
    )
    monkeypatch.setattr(
        managed,
        "revalidated_resource_scan",
        lambda original, candidate: candidate if original is data else None,
    )

    values, skipped = managed._resource_values(
        data,
        scan,
        frozenset({RESOURCE_NAME}),
    )

    assert [(value.name, value.data) for value in values] == [
        (RESOURCE_NAME, b"fixture-ciphertext")
    ]
    assert skipped == 1


def test_resource_enumeration_rejects_invalid_candidate_container(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = (
        struct.pack("<I", managed.RESOURCE_MAGIC)
        + RESOURCE_NAME.encode("utf-16le")
    )
    scan = SimpleNamespace(
        _coverage={
            "status": "complete",
            "inventory_complete": True,
            "embedded_scan_complete": True,
            "input_binding_verified": True,
            "reason_counts": {},
            "executed": False,
            "clr_loaded": False,
            "network_contacted": False,
        },
        _descriptors=(
            SimpleNamespace(kind="embedded", body_offset=0, body_size=len(raw)),
        ),
    )
    monkeypatch.setattr(
        managed,
        "revalidated_resource_scan",
        lambda original, candidate: candidate if original is raw else None,
    )

    with pytest.raises(managed.ManagedResourceStageNoEvidence):
        managed._resource_values(raw, scan, frozenset({RESOURCE_NAME}))


def test_method_normalization_skips_only_unrelated_unreviewed_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    signature = SimpleNamespace(value=METHOD_SIGNATURE)
    rows = [
        SimpleNamespace(Rva=1, Signature=signature),
        SimpleNamespace(Rva=2, Signature=signature),
    ]
    resolver = SimpleNamespace(tables={"MethodDef": {"rows": rows}})
    pe = SimpleNamespace()
    monkeypatch.setattr(
        managed,
        "_method_file_span",
        lambda _pe, _data, rva: (0 if rva == 1 else 4, 4),
    )

    def method_extent(_data: bytes, offset: int, _available: int) -> int:
        if offset == 0:
            raise managed._UnreviewedMethodSections(4)
        return 4

    monkeypatch.setattr(managed, "_method_extent", method_extent)
    monkeypatch.setattr(
        managed,
        "read_method_body_from_bytes",
        lambda _data: SimpleNamespace(instructions=()),
    )

    methods, skipped = managed._normalize_methods(
        pe,
        b"unrelated-method-body"[:8],
        resolver,
        {},
        {},
        time.monotonic() + 1.0,
    )

    assert [method.token for method in methods] == [0x06000002]
    assert skipped == 1


def test_method_normalization_rejects_unreviewed_candidate_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    signature = SimpleNamespace(value=METHOD_SIGNATURE)
    resolver = SimpleNamespace(
        tables={
            "MethodDef": {
                "rows": [SimpleNamespace(Rva=1, Signature=signature)],
            }
        }
    )
    references = {
        0x0A000001: "component_resource_manager_ctor",
        0x0A000002: "resource_manager_get_object",
        0x0A000003: "encoding_get_default",
        0x0A000004: "encoding_get_bytes_string",
        0x0A000005: "appdomain_load_bytes",
    }
    raw = b"".join(struct.pack("<I", token) for token in references)
    monkeypatch.setattr(
        managed,
        "_method_file_span",
        lambda _pe, _data, _rva: (0, len(raw)),
    )
    monkeypatch.setattr(
        managed,
        "_method_extent",
        lambda _data, _offset, _available: (_ for _ in ()).throw(
            managed._UnreviewedMethodSections(len(raw))
        ),
    )

    with pytest.raises(
        managed.ManagedResourceStageNoEvidence,
        match="candidate_method_sections_unreviewed",
    ):
        managed._normalize_methods(
            SimpleNamespace(),
            raw,
            resolver,
            references,
            {},
            time.monotonic() + 1.0,
        )


def test_constructor_preflight_rejects_before_dnfile_parse(monkeypatch: pytest.MonkeyPatch) -> None:
    data = resource_build_literal_pe().data
    parsed = False

    monkeypatch.setattr(managed, "has_clr_metadata", lambda _data: True)
    monkeypatch.setattr(
        managed,
        "preflight_clr_declarations",
        lambda *_args, **_kwargs: {"accepted": False},
    )

    def forbidden_parse(*_args: object, **_kwargs: object) -> None:
        nonlocal parsed
        parsed = True
        raise AssertionError("constructor前preflightの後だけparserを呼ぶ")

    monkeypatch.setattr(managed.dnfile, "dnPE", forbidden_parse)

    with pytest.raises(managed.ManagedResourceStageNoEvidence):
        managed.recover_managed_resource_stage(data)
    assert parsed is False


def _public_report(child: bytes) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "status": "managed_child_recovered",
        "variant": "fixture_variant",
        "supports_family_attribution": False,
        "terminal_family_confirmed": False,
        "static_config_recovered": False,
        "c2": [],
        "structural_evidence": ["fixture_shape"],
        "recovered_child": {
            "sha256": hashlib.sha256(child).hexdigest(),
            "size": len(child),
        },
        "safety": {"sample_executed": False},
    }


def test_facade_returns_nonterminal_private_fixed_point_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    child = resource_build_literal_pe().data
    report = _public_report(child)
    monkeypatch.setattr(
        facade,
        "recover_managed_resource_stage",
        lambda _data: (report, child),
    )

    result = facade._extract_managed_resource_stage(b"MZfixture")
    public = facade._public_result(result)

    assert result["recovered_payload"]["role"] == "recovered_payload"
    assert facade._private_payload_bytes(result) == child
    assert public["recovered_payload"]["data"] == {
        "content_exported": False,
        "sha256": hashlib.sha256(child).hexdigest(),
        "size": len(child),
    }
    assert public["terminal_payload_recovered"] is False
    assert public["supports_family_attribution"] is False


def test_detector_publishes_metadata_but_never_child_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = _public_report(b"MZchild")
    monkeypatch.setattr(detector, "probe_managed_resource_stage", lambda _data: report)

    result = detector.detect(b"MZfixture-BSJB", Path("fixture.exe"))

    campaign = next(
        item
        for item in result["campaigns"]
        if item["campaign_type"] == "formbook_managed_resource_static_child_route"
    )
    assert campaign["supports_family_attribution"] is False
    assert result["observations"]["managed_resource_stage"] == report
    assert not any(isinstance(value, bytes) for value in report.values())
