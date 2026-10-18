#!/usr/bin/env python3
"""OMLX文字列表と同一assemblyのResourceSetから終端PEを静的復元する。

この経路は検体、CLR、CIL、復元物を実行しない。OMLX dispatcher、
resource binding、keyed-word transform、CIL wrapperのframework API終端、
TripleDES-CBC/PKCS7、4-byte長付きGZip、完全なmanaged PEという独立条件が
全て一意に成立した場合だけ復元物を返す。metadata tokenや難読化名は
profileへ固定しない。
"""

from __future__ import annotations

import base64
import hashlib
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from itertools import islice
from typing import Any

import dnfile
from malware.purehvnc.managed_resource_recovery import (
    OmlxMethod,
    StaticRecoveryError,
    decrypt_keyed_eaz_resource,
    decrypt_tripledes_cbc_pkcs7_base64,
    inflate_length_prefixed_gzip,
    prove_constant_return,
)

from extractors.managed_pe import has_clr_metadata
from unpackers.bounded_pe_scan import inspect_structural_pe_extent
from unpackers.managed_eaz_resource import (
    RecoveryError,
    _contained_parser_diagnostics,
    _decode_method,
    _metadata_row_count,
    _resource_blobs,
)
from unpackers.managed_omlx_tripledes import (
    MAX_DYNAMIC_OPCODE_CANDIDATES,
    MAX_ELAPSED_SECONDS,
    MAX_INPUT_BYTES,
    MAX_OUTPUT_BYTES,
    MAX_RESOURCE_COUNT,
    MAX_TERMINAL_BINDING_CANDIDATES,
    OmlxTripledesError,
    _canonical_base64_of_size,
    _canonicalize_omlx_method,
    _check_time,
    _decode_table,
    _dynamic_output_identity,
    _DynamicOmlxCandidate,
    _find_bound_resource,
    _find_dynamic_omlx_candidate,
    _find_omlx_candidate,
    _OmlxHardLimitError,
    _raise_if_elapsed_time_limit,
    _recover_table,
    _terminal_binding_identity,
    _TerminalBinding,
    _TerminalWorkBudget,
    _verified_transform_recipes,
)

MAX_RUNTIME_HELPER_DEPTH = 4
MAX_RUNTIME_HELPERS = 64
MAX_FRAMEWORK_REFERENCE_ROWS = 16_384
MAX_FRAMEWORK_SIGNATURE_BYTES = 1_024

_CLASSIC_FRAMEWORK_ASSEMBLIES = {
    ("mscorlib", bytes.fromhex("b77a5c561934e089"), (2, 0, 0, 0)),
    ("mscorlib", bytes.fromhex("b77a5c561934e089"), (4, 0, 0, 0)),
}

# runtime roleへ使うAPIは、owner名だけでなく、has-this、戻値、全引数を
# 固定する。同名MemberRefや別overloadをrole証拠へ昇格しない。
_FRAMEWORK_API_SIGNATURES: Mapping[
    str, frozenset[tuple[bool, str, tuple[str, ...]]]
] = {
    "System.IO.BinaryReader::get_BaseStream": frozenset(
        {(True, "System.IO.Stream", ())}
    ),
    "System.IO.Stream::set_Position": frozenset(
        {(True, "System.Void", ("System.Int64",))}
    ),
    "System.IO.Stream::get_Length": frozenset({(True, "System.Int64", ())}),
    "System.IO.BinaryReader::ReadBytes": frozenset(
        {(True, "System.Byte[]", ("System.Int32",))}
    ),
    "System.IO.BinaryReader::Close": frozenset({(True, "System.Void", ())}),
    "System.Array::Reverse": frozenset({(False, "System.Void", ("System.Array",))}),
    "System.Reflection.Assembly::GetName": frozenset(
        {(True, "System.Reflection.AssemblyName", ())}
    ),
    "System.Reflection.AssemblyName::GetPublicKeyToken": frozenset(
        {(True, "System.Byte[]", ())}
    ),
    "System.Reflection.Assembly::get_EntryPoint": frozenset(
        {(True, "System.Reflection.MethodInfo", ())}
    ),
    "System.Reflection.MethodInfo::op_Equality": frozenset(
        {
            (
                False,
                "System.Boolean",
                ("System.Reflection.MethodInfo", "System.Reflection.MethodInfo"),
            )
        }
    ),
    "System.Object::.ctor": frozenset({(True, "System.Void", ())}),
    "System.IO.BinaryReader::.ctor": frozenset(
        {(True, "System.Void", ("System.IO.Stream",))}
    ),
}

_ROLE_APIS: Mapping[str, str] = {
    "reader_base_stream": "System.IO.BinaryReader::get_BaseStream",
    "stream_set_position": "System.IO.Stream::set_Position",
    "stream_get_length": "System.IO.Stream::get_Length",
    "reader_read_bytes": "System.IO.BinaryReader::ReadBytes",
    "reader_dispose": "System.IO.BinaryReader::Close",
    "array_reverse": "System.Array::Reverse",
    "assembly_get_name": "System.Reflection.Assembly::GetName",
    "assembly_name_public_key": ("System.Reflection.AssemblyName::GetPublicKeyToken"),
    "assembly_entrypoint": "System.Reflection.Assembly::get_EntryPoint",
    "object_equality": "System.Reflection.MethodInfo::op_Equality",
}


class DirectOmlxError(ValueError):
    """direct ResourceSet recipeから外れた入力を表す。"""


@dataclass(frozen=True)
class _DirectDynamicOutput:
    method: OmlxMethod
    table_recovery: Any
    table: tuple[tuple[int, str], ...]
    terminal_binding: _TerminalBinding
    opcode_candidate_count: int
    viable_candidate_count: int
    viable_mode_count: int
    selected_mask_modes: tuple[str, ...]


@dataclass(frozen=True)
class _FrameworkMetadataView:
    """runtime role照合に必要なCLR参照表だけを有界snapshot化する。"""

    type_ref_table: Any
    type_refs: tuple[Any, ...]
    member_refs: tuple[Any, ...]
    assembly_ref_table: Any
    assembly_refs: tuple[Any, ...]


@dataclass(frozen=True)
class _MetadataReference:
    table: Any
    row_index: int


def _metadata_rows(pe: Any, name: str) -> tuple[Any, tuple[Any, ...]]:
    table = getattr(getattr(getattr(pe, "net", None), "mdtables", None), name, None)
    if table is None:
        raise DirectOmlxError("framework_metadata_table_missing")
    declared = getattr(table, "num_rows", None)
    if (
        isinstance(declared, bool)
        or not isinstance(declared, int)
        or declared < 0
        or declared > MAX_FRAMEWORK_REFERENCE_ROWS
    ):
        raise DirectOmlxError("framework_metadata_incomplete_or_over_budget")
    rows = tuple(
        islice(
            iter(getattr(table, "rows", ()) or ()),
            MAX_FRAMEWORK_REFERENCE_ROWS + 1,
        )
    )
    if len(rows) > MAX_FRAMEWORK_REFERENCE_ROWS or declared != len(rows):
        raise DirectOmlxError("framework_metadata_incomplete_or_over_budget")
    return table, rows


def _framework_metadata_view(pe: Any) -> _FrameworkMetadataView:
    type_ref_table, type_refs = _metadata_rows(pe, "TypeRef")
    _member_ref_table, member_refs = _metadata_rows(pe, "MemberRef")
    assembly_ref_table, assembly_refs = _metadata_rows(pe, "AssemblyRef")
    return _FrameworkMetadataView(
        type_ref_table=type_ref_table,
        type_refs=type_refs,
        member_refs=member_refs,
        assembly_ref_table=assembly_ref_table,
        assembly_refs=assembly_refs,
    )


def _metadata_text(value: Any) -> str:
    value = getattr(value, "value", value)
    if (
        not isinstance(value, str)
        or len(value) > 512
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise DirectOmlxError("framework_identity_text_invalid")
    return value


def _coded_row(reference: Any, table: Any, rows: Sequence[Any]) -> Any:
    if getattr(reference, "table", None) is not table:
        raise DirectOmlxError("framework_reference_scope_not_reviewed")
    rid = getattr(reference, "row_index", None)
    if isinstance(rid, bool) or not isinstance(rid, int) or not 1 <= rid <= len(rows):
        raise DirectOmlxError("framework_reference_rid_invalid")
    return rows[rid - 1]


def _assembly_identity(row: Any) -> tuple[str, bytes, tuple[int, ...]]:
    name = _metadata_text(getattr(row, "Name", None))
    if _metadata_text(getattr(row, "Culture", None)):
        raise DirectOmlxError("framework_assembly_culture_not_neutral")
    flags = getattr(getattr(row, "struct", None), "Flags", None)
    if isinstance(flags, bool) or not isinstance(flags, int) or flags != 0:
        raise DirectOmlxError("framework_assembly_flags_not_reviewed")
    public_key = getattr(getattr(row, "PublicKey", None), "value", None)
    version = tuple(
        getattr(row, field, None)
        for field in ("MajorVersion", "MinorVersion", "BuildNumber", "RevisionNumber")
    )
    if (
        not isinstance(public_key, bytes)
        or len(public_key) != 8
        or any(
            isinstance(value, bool)
            or not isinstance(value, int)
            or not 0 <= value <= 0xFFFF
            for value in version
        )
        or (name, public_key, version) not in _CLASSIC_FRAMEWORK_ASSEMBLIES
    ):
        raise DirectOmlxError("framework_assembly_identity_not_reviewed")
    return name, public_key, version


def _typeref_identity(
    view: _FrameworkMetadataView, reference: Any
) -> tuple[str, tuple[str, bytes, tuple[int, ...]]]:
    row = _coded_row(reference, view.type_ref_table, view.type_refs)
    scope = getattr(row, "ResolutionScope", None)
    assembly_row = _coded_row(scope, view.assembly_ref_table, view.assembly_refs)
    assembly = _assembly_identity(assembly_row)
    namespace = _metadata_text(getattr(row, "TypeNamespace", None))
    name = _metadata_text(getattr(row, "TypeName", None))
    if not name:
        raise DirectOmlxError("framework_typeref_name_empty")
    return f"{namespace}.{name}".lstrip("."), assembly


def _compressed_uint(data: bytes, position: int) -> tuple[int, int]:
    if position >= len(data):
        raise DirectOmlxError("framework_signature_truncated")
    first = data[position]
    if first < 0x80:
        return first, position + 1
    if first < 0xC0 and position + 1 < len(data):
        value = ((first & 0x3F) << 8) | data[position + 1]
        if value >= 0x80:
            return value, position + 2
    elif first < 0xE0 and position + 3 < len(data):
        value = (
            ((first & 0x1F) << 24)
            | (data[position + 1] << 16)
            | (data[position + 2] << 8)
            | data[position + 3]
        )
        if value >= 0x4000:
            return value, position + 4
    raise DirectOmlxError("framework_signature_integer_invalid")


def _signature_type(
    data: bytes,
    position: int,
    view: _FrameworkMetadataView,
    owner_assembly: tuple[str, bytes, tuple[int, ...]],
    *,
    allow_void: bool,
    depth: int = 0,
) -> tuple[str, int]:
    if depth >= 4 or position >= len(data):
        raise DirectOmlxError("framework_signature_type_invalid")
    code = data[position]
    position += 1
    primitives = {
        0x01: "System.Void",
        0x02: "System.Boolean",
        0x05: "System.Byte",
        0x08: "System.Int32",
        0x0A: "System.Int64",
        0x0E: "System.String",
        0x1C: "System.Object",
    }
    if code in primitives:
        if code == 0x01 and not allow_void:
            raise DirectOmlxError("framework_signature_void_parameter")
        return primitives[code], position
    if code == 0x1D:
        inner, position = _signature_type(
            data,
            position,
            view,
            owner_assembly,
            allow_void=False,
            depth=depth + 1,
        )
        return inner + "[]", position
    if code != 0x12:
        raise DirectOmlxError("framework_signature_type_not_reviewed")
    encoded, position = _compressed_uint(data, position)
    if encoded & 3 != 1 or encoded >> 2 == 0:
        raise DirectOmlxError("framework_signature_typeref_invalid")
    reference = _MetadataReference(view.type_ref_table, encoded >> 2)
    name, assembly = _typeref_identity(view, reference)
    if assembly != owner_assembly:
        raise DirectOmlxError("framework_signature_assembly_identity_mismatch")
    return name, position


def _member_signature(
    row: Any,
    view: _FrameworkMetadataView,
    owner_assembly: tuple[str, bytes, tuple[int, ...]],
) -> tuple[bool, str, tuple[str, ...]]:
    data = getattr(getattr(row, "Signature", None), "value", None)
    if (
        not isinstance(data, bytes)
        or not data
        or len(data) > MAX_FRAMEWORK_SIGNATURE_BYTES
        or data[0] not in {0x00, 0x20}
    ):
        raise DirectOmlxError("framework_member_signature_not_reviewed")
    count, position = _compressed_uint(data, 1)
    if count > 4:
        raise DirectOmlxError("framework_member_parameter_count_limit")
    returned, position = _signature_type(
        data, position, view, owner_assembly, allow_void=True
    )
    parameters: list[str] = []
    for _ in range(count):
        parameter, position = _signature_type(
            data, position, view, owner_assembly, allow_void=False
        )
        parameters.append(parameter)
    if position != len(data):
        raise DirectOmlxError("framework_member_signature_trailing_bytes")
    return bool(data[0] & 0x20), returned, tuple(parameters)


def _metadata_token(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if value >> 24 in {0x06, 0x0A, 0x2B} and value & 0xFFFFFF else None


def _memberref_api(
    pe: Any,
    token: int,
    *,
    metadata_view: _FrameworkMetadataView | None = None,
    metadata_views: list[_FrameworkMetadataView] | None = None,
) -> str | None:
    """BCL identityと完全signatureを照合したMemberRefだけをAPI IDへする。"""

    if token >> 24 != 0x0A:
        return None
    try:
        view = metadata_view
        if view is None and metadata_views is not None:
            if not metadata_views:
                metadata_views.append(_framework_metadata_view(pe))
            view = metadata_views[0]
        if view is None:
            view = _framework_metadata_view(pe)
        rid = token & 0xFFFFFF
        if not 1 <= rid <= len(view.member_refs):
            return None
        row = view.member_refs[rid - 1]
        owner, assembly = _typeref_identity(view, getattr(row, "Class", None))
        name = _metadata_text(getattr(row, "Name", None))
        api = f"{owner}::{name}"
        profiles = _FRAMEWORK_API_SIGNATURES.get(api)
        if profiles is None or _member_signature(row, view, assembly) not in profiles:
            return None
        return api
    except (
        DirectOmlxError,
        AttributeError,
        IndexError,
        KeyError,
        OSError,
        OverflowError,
        RuntimeError,
        TypeError,
        ValueError,
    ):
        return None


def _method_owner_tokens(pe: Any) -> dict[int, int]:
    types = list(getattr(getattr(pe.net.mdtables, "TypeDef", None), "rows", ()) or ())
    result: dict[int, int] = {}
    for index, row in enumerate(types, 1):
        for reference in getattr(row, "MethodList", ()) or ():
            rid = getattr(reference, "row_index", None)
            if (
                isinstance(rid, bool)
                or not isinstance(rid, int)
                or not 1 <= rid <= 0xFFFFFF
                or rid in result
            ):
                raise DirectOmlxError("method_owner_ambiguous")
            result[rid] = 0x02000000 | index
    return result


def _reviewed_helper_instructions(
    instructions: Sequence[Any],
) -> tuple[Any, ...]:
    """到達不能な単一decoy callだけを除いたhelper CILを返す。"""

    reviewed = tuple(instructions)
    if not reviewed or reviewed[0].opcode not in {"br", "br.s"}:
        return reviewed
    branch_target = reviewed[0].operand
    if (
        len(reviewed) < 3
        or isinstance(branch_target, bool)
        or not isinstance(branch_target, int)
        or branch_target != reviewed[2].offset
        or reviewed[1].opcode != "call"
        or _metadata_token(reviewed[1].operand) is not None
    ):
        raise DirectOmlxError("runtime_helper_cil_shape_not_reviewed")
    return reviewed[2:]


def _helper_api_set(
    data: bytes,
    pe: Any,
    token: int,
    *,
    deadline: float,
    clock: Callable[[], float],
    cache: dict[int, frozenset[str]],
    metadata_views: list[_FrameworkMetadataView] | None = None,
    active: frozenset[int] = frozenset(),
    depth: int = 0,
) -> frozenset[str]:
    """side-effectを限定した短いwrapperのframework API終端を返す。"""

    _check_time(deadline, clock)
    if metadata_views is None:
        metadata_views = []
    direct = _memberref_api(pe, token, metadata_views=metadata_views)
    if direct is not None:
        return frozenset({direct})
    if token >> 24 != 0x06 or depth >= MAX_RUNTIME_HELPER_DEPTH:
        raise DirectOmlxError("runtime_helper_target_not_reviewed")
    if token in cache:
        return cache[token]
    if token in active or len(cache) >= MAX_RUNTIME_HELPERS:
        raise DirectOmlxError("runtime_helper_recursion_or_count_limit")
    rows = list(getattr(getattr(pe.net.mdtables, "MethodDef", None), "rows", ()) or ())
    rid = token & 0xFFFFFF
    if not 1 <= rid <= len(rows):
        raise DirectOmlxError("runtime_helper_method_missing")
    method = _decode_method(
        data,
        pe,
        rows[rid - 1],
        token,
        deadline=deadline,
        clock=clock,
    )
    if getattr(method, "has_extra_sections", False):
        raise DirectOmlxError("runtime_helper_extra_section_not_reviewed")
    if getattr(method, "exception_handler_count", 0):
        raise DirectOmlxError("runtime_helper_exception_handler_not_reviewed")
    instructions = _reviewed_helper_instructions(method.instructions)
    if (
        not instructions
        or len(instructions) > 16
        or instructions[-1].opcode != "ret"
        or sum(item.opcode == "ret" for item in instructions) != 1
    ):
        raise DirectOmlxError("runtime_helper_cil_shape_not_reviewed")
    method_name = str(getattr(rows[rid - 1], "Name", ""))
    allowed = {
        "nop",
        "ret",
        "ldarg",
        "ldarg.s",
        "ldarg.0",
        "ldarg.1",
        "ldarg.2",
        "ldarg.3",
        "ldfld",
        "stfld",
    }
    apis: set[str] = set()
    calls = 0
    for item in instructions:
        if item.opcode in {"call", "callvirt", "newobj"}:
            nested = _metadata_token(item.operand)
            if nested is None:
                raise DirectOmlxError("runtime_helper_call_token_invalid")
            calls += 1
            apis.update(
                _helper_api_set(
                    data,
                    pe,
                    nested,
                    deadline=deadline,
                    clock=clock,
                    cache=cache,
                    metadata_views=metadata_views,
                    active=active | {token},
                    depth=depth + 1,
                )
            )
        elif item.opcode not in allowed:
            raise DirectOmlxError("runtime_helper_cil_shape_not_reviewed")
        elif item.opcode == "stfld" and method_name != ".ctor":
            raise DirectOmlxError("runtime_helper_field_write_not_constructor")
    if not 1 <= calls <= 2 or not apis:
        raise DirectOmlxError("runtime_helper_api_missing")
    if method_name == ".ctor":
        if calls != len(apis):
            raise DirectOmlxError("runtime_helper_constructor_call_count_not_reviewed")
    elif calls != 1:
        raise DirectOmlxError("runtime_helper_general_call_count_not_reviewed")
    result = frozenset(apis)
    cache[token] = result
    return result


def _unique_token(matches: Sequence[int], reason: str) -> int:
    unique = sorted(set(matches))
    if len(unique) != 1:
        raise DirectOmlxError(reason)
    return unique[0]


def _discover_runtime_tokens(
    data: bytes,
    pe: Any,
    method: OmlxMethod,
    transforms: Mapping[int, Any],
    *,
    deadline: float,
    clock: Callable[[], float],
) -> tuple[dict[str, int], dict[str, Any]]:
    """難読化名やRIDではなくwrapper CIL/API終端からruntime roleを導く。"""

    candidates = sorted(
        {
            token
            for item in method.instructions
            if (token := _metadata_token(item.operand)) is not None
        }
    )
    if not candidates or len(candidates) > MAX_RUNTIME_HELPERS:
        raise DirectOmlxError("runtime_token_candidate_limit")
    cache: dict[int, frozenset[str]] = {}
    metadata_views: list[_FrameworkMetadataView] = []
    api_sets: dict[int, frozenset[str]] = {}
    for token in candidates:
        _check_time(deadline, clock)
        try:
            api_sets[token] = _helper_api_set(
                data,
                pe,
                token,
                deadline=deadline,
                clock=clock,
                cache=cache,
                metadata_views=metadata_views,
            )
            _check_time(deadline, clock)
        except (DirectOmlxError, RecoveryError) as exc:
            _raise_if_elapsed_time_limit(exc)
            continue
    _check_time(deadline, clock)
    result: dict[str, int] = {}
    for role, api in _ROLE_APIS.items():
        result[role] = _unique_token(
            [token for token, names in api_sets.items() if names == {api}],
            f"runtime_role_{role}_ambiguous",
        )

    reader_apis = {
        "System.Object::.ctor",
        "System.IO.BinaryReader::.ctor",
    }
    result["reader_ctor"] = _unique_token(
        [token for token, names in api_sets.items() if names == reader_apis],
        "runtime_role_reader_ctor_ambiguous",
    )

    rows = list(getattr(getattr(pe.net.mdtables, "MethodDef", None), "rows", ()) or ())
    owners = _method_owner_tokens(pe)
    transform_owners = {
        owners[token & 0xFFFFFF]
        for token in transforms
        if token >> 24 == 0x06 and (token & 0xFFFFFF) in owners
    }
    if len(transform_owners) != 1:
        raise DirectOmlxError("runtime_transform_owner_ambiguous")
    transform_owner = next(iter(transform_owners))
    result["resource_transform_ctor"] = _unique_token(
        [
            token
            for token, names in api_sets.items()
            if token >> 24 == 0x06
            and owners.get(token & 0xFFFFFF) == transform_owner
            and str(rows[(token & 0xFFFFFF) - 1].Name) == ".ctor"
            and names == {"System.Object::.ctor"}
        ],
        "runtime_role_transform_ctor_ambiguous",
    )

    constant_matches: dict[bool | None, list[int]] = {True: [], None: []}
    for token in candidates:
        _check_time(deadline, clock)
        if token >> 24 != 0x06:
            continue
        rid = token & 0xFFFFFF
        try:
            method_body = _decode_method(
                data,
                pe,
                rows[rid - 1],
                token,
                deadline=deadline,
                clock=clock,
            )
            value = prove_constant_return(method_body.instructions)
            _check_time(deadline, clock)
        except (IndexError, RecoveryError, StaticRecoveryError) as exc:
            _raise_if_elapsed_time_limit(exc)
            continue
        if value is True:
            constant_matches[True].append(token)
        elif value is None:
            constant_matches[None].append(token)
    _check_time(deadline, clock)
    result["true"] = _unique_token(
        constant_matches[True], "runtime_role_true_ambiguous"
    )
    result["false"] = _unique_token(
        constant_matches[None], "runtime_role_false_ambiguous"
    )
    if len(set(result.values())) != len(result):
        raise DirectOmlxError("runtime_role_token_alias")
    _check_time(deadline, clock)
    return result, {
        "derivation": "cil_wrapper_framework_api_terminal_v2",
        "framework_declaration_profile": "classic_mscorlib_scope_signature_v1",
        "assembly_ref_identity_verified": True,
        "memberref_signatures_verified": True,
        "candidate_token_count": len(candidates),
        "resolved_role_count": len(result),
        "helper_method_count": len(cache),
        "metadata_tokens_are_build_local": True,
        "obfuscated_names_used": False,
    }


def _select_direct_terminal_binding(
    table: Sequence[tuple[int, str]],
    parent: bytes,
    *,
    deadline: float,
    clock: Callable[[], float],
    work_budget: _TerminalWorkBudget,
) -> _TerminalBinding:
    """同一assembly内ResourceSetを暗号・圧縮・PE境界まで評価して一意化する。"""

    from unpackers.managed_omlx_tripledes import _child_resource_entries

    _check_time(deadline, clock)
    keys = [
        (offset, value)
        for offset, value in table
        if _canonical_base64_of_size(value, 16) is not None
    ]
    ivs = [
        (offset, value)
        for offset, value in table
        if _canonical_base64_of_size(value, 8) is not None
    ]
    entries = _child_resource_entries(parent, deadline=deadline, clock=clock)
    _check_time(deadline, clock)
    combinations = len(keys) * len(ivs) * len(entries)
    if combinations == 0:
        raise DirectOmlxError("direct_terminal_binding_missing")
    if combinations > MAX_TERMINAL_BINDING_CANDIDATES:
        raise _OmlxHardLimitError("direct_terminal_binding_candidate_limit")
    selected: _TerminalBinding | None = None
    selected_identity: tuple[Any, ...] | None = None
    for key_offset, key_base64 in keys:
        for iv_offset, iv_base64 in ivs:
            if key_offset == iv_offset:
                continue
            for resource_name, ciphertext in entries:
                _check_time(deadline, clock)
                work_budget.charge_candidate(len(ciphertext))
                try:
                    clear = decrypt_tripledes_cbc_pkcs7_base64(
                        ciphertext, key_base64, iv_base64
                    )
                    _check_time(deadline, clock)
                    declared = (
                        int.from_bytes(clear[:4], "little", signed=True)
                        if len(clear) >= 4
                        else 0
                    )
                    if not 0 < declared <= MAX_OUTPUT_BYTES:
                        continue
                    work_budget.charge_inflated_work(declared + 1)
                    payload = inflate_length_prefixed_gzip(
                        clear,
                        max_output_bytes=min(
                            MAX_OUTPUT_BYTES,
                            max(
                                1,
                                work_budget.remaining_inflated_work_bytes
                                + declared
                                + 1,
                            ),
                        ),
                    )
                    _check_time(deadline, clock)
                    extent = inspect_structural_pe_extent(
                        payload, max_extent=MAX_OUTPUT_BYTES
                    )
                    _check_time(deadline, clock)
                    if extent.extent != len(payload):
                        continue
                    if not has_clr_metadata(payload):
                        continue
                    _check_time(deadline, clock)
                except _OmlxHardLimitError:
                    raise
                except (StaticRecoveryError, ValueError, TypeError, IndexError) as exc:
                    _raise_if_elapsed_time_limit(exc)
                    continue
                candidate = _TerminalBinding(
                    key_offset=key_offset,
                    iv_offset=iv_offset,
                    resource_name_offset=-1,
                    key_base64=key_base64,
                    iv_base64=iv_base64,
                    resource_name=resource_name,
                    ciphertext=ciphertext,
                    payload=payload,
                )
                identity = _terminal_binding_identity(candidate)
                if selected is None:
                    selected, selected_identity = candidate, identity
                elif identity != selected_identity:
                    raise DirectOmlxError("direct_terminal_binding_ambiguous")
    if selected is None:
        raise DirectOmlxError("direct_terminal_binding_missing")
    return selected


def _recover_dynamic_output(
    candidate: _DynamicOmlxCandidate,
    encrypted: bytes,
    transforms: Mapping[int, Any],
    parent: bytes,
    runtime_tokens: Mapping[str, int],
    *,
    entrypoint_token: int,
    deadline: float,
    clock: Callable[[], float],
    work_budget: _TerminalWorkBudget,
) -> _DirectDynamicOutput:
    if (
        not candidate.opcode_maps
        or len(candidate.opcode_maps) > MAX_DYNAMIC_OPCODE_CANDIDATES
    ):
        raise DirectOmlxError("dynamic_opcode_candidate_limit")
    selected: (
        tuple[OmlxMethod, Any, tuple[tuple[int, str], ...], _TerminalBinding] | None
    ) = None
    selected_identity: tuple[Any, ...] | None = None
    modes: set[str] = set()
    viable_candidates = 0
    viable_modes = 0
    for opcode_map in candidate.opcode_maps:
        _check_time(deadline, clock)
        try:
            method = _canonicalize_omlx_method(candidate.raw_method0, opcode_map)
            base = _recover_table(
                method,
                encrypted,
                transforms,
                entrypoint_token=entrypoint_token,
                deadline=deadline,
                clock=clock,
                work_budget=work_budget,
                runtime_tokens=runtime_tokens,
            )
        except _OmlxHardLimitError:
            raise
        except (
            OmlxTripledesError,
            RecoveryError,
            StaticRecoveryError,
            ValueError,
        ) as exc:
            _raise_if_elapsed_time_limit(exc)
            continue
        _check_time(deadline, clock)
        work_budget.charge_table_transform(len(encrypted))
        masked = type(base)(
            clear=decrypt_keyed_eaz_resource(
                encrypted,
                base.key,
                key_mask=base.mask,
                seed=base.transform.seed,
                addend=base.transform.addend,
                allow_partial_word=True,
            ),
            key=base.key,
            mask=base.mask,
            transform=base.transform,
            steps=base.steps,
        )
        _check_time(deadline, clock)
        candidate_viable = False
        for mode, recovery in (("none", base), ("xor16", masked)):
            try:
                table = _decode_table(recovery.clear, deadline=deadline, clock=clock)
                terminal = _select_direct_terminal_binding(
                    table,
                    parent,
                    deadline=deadline,
                    clock=clock,
                    work_budget=work_budget,
                )
            except _OmlxHardLimitError:
                raise
            except (
                DirectOmlxError,
                OmlxTripledesError,
                StaticRecoveryError,
                ValueError,
            ) as exc:
                _raise_if_elapsed_time_limit(exc)
                continue
            if not candidate_viable:
                viable_candidates += 1
                candidate_viable = True
            viable_modes += 1
            identity = _dynamic_output_identity(recovery, table, terminal)
            if selected is None:
                selected = (method, recovery, table, terminal)
                selected_identity = identity
            elif identity != selected_identity:
                raise DirectOmlxError("dynamic_recovered_output_ambiguous")
            modes.add(mode)
    if selected is None:
        raise DirectOmlxError("dynamic_recovered_output_missing")
    method, recovery, table, terminal = selected
    return _DirectDynamicOutput(
        method=method,
        table_recovery=recovery,
        table=table,
        terminal_binding=terminal,
        opcode_candidate_count=len(candidate.opcode_maps),
        viable_candidate_count=viable_candidates,
        viable_mode_count=viable_modes,
        selected_mask_modes=tuple(sorted(modes)),
    )


def _terminal_container_metadata(
    pe: Any,
    terminal: _TerminalBinding,
) -> dict[str, Any]:
    """選択したentryを含むmanifest ResourceSet containerを一意に結ぶ。"""

    matches: list[tuple[str, bytes]] = []
    for resource in list(getattr(getattr(pe, "net", None), "resources", ()) or ()):
        entries = list(getattr(getattr(resource, "data", None), "entries", ()) or ())
        if any(
            str(getattr(entry, "name", "")) == terminal.resource_name
            and isinstance(getattr(entry, "value", None), (bytes, bytearray))
            and bytes(entry.value) == terminal.ciphertext
            for entry in entries
        ):
            name = str(getattr(resource, "name", ""))
            raw = getattr(getattr(resource, "data", None), "_data", None)
            if isinstance(raw, bytes) and raw:
                matches.append((name, raw))
    if len(matches) != 1:
        raise DirectOmlxError("terminal_resourceset_container_ambiguous")
    name, raw = matches[0]
    return {
        "name": name,
        "size": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def recover_managed_omlx_direct_tripledes(
    data: bytes,
    *,
    clock: Callable[[], float] = time.monotonic,
    max_elapsed_seconds: float = MAX_ELAPSED_SECONDS,
) -> tuple[dict[str, Any], list[tuple[str, bytes]]]:
    """同一managed PE内のOMLX table→ResourceSet終端を静的復元する。"""

    if not isinstance(data, bytes):
        return {"status": "rejected", "reason": "input_not_bytes"}, []
    if not data or len(data) > MAX_INPUT_BYTES:
        return {"status": "rejected", "reason": "input_byte_limit"}, []
    if (
        isinstance(max_elapsed_seconds, bool)
        or not isinstance(max_elapsed_seconds, (int, float))
        or not 0 < max_elapsed_seconds <= MAX_ELAPSED_SECONDS
    ):
        return {"status": "rejected", "reason": "elapsed_limit_invalid"}, []
    started = clock()
    deadline = started + float(max_elapsed_seconds)
    try:
        _check_time(deadline, clock)
        managed = has_clr_metadata(data)
        _check_time(deadline, clock)
        if not managed:
            return {"status": "not_applicable", "reason": "not_managed_pe"}, []
        with _contained_parser_diagnostics():
            pe = dnfile.dnPE(data=data, clr_lazy_load=False)
        _check_time(deadline, clock)
        _metadata_row_count(pe)
        _check_time(deadline, clock)
        resources_list = _resource_blobs(pe)
        _check_time(deadline, clock)
        if not resources_list:
            return {
                "status": "not_applicable",
                "reason": "parent_resources_missing",
            }, []
        if len(resources_list) > MAX_RESOURCE_COUNT:
            raise DirectOmlxError("parent_resource_count_limit")
        resources = dict(resources_list)
        if len(resources) != len(resources_list):
            raise DirectOmlxError("parent_resource_name_ambiguous")
        _check_time(deadline, clock)
        dynamic: _DynamicOmlxCandidate | None = None
        try:
            omlx_name, omlx_blob, method, initializer, profile = _find_omlx_candidate(
                resources_list, deadline=deadline, clock=clock
            )
        except OmlxTripledesError as fixed_error:
            if str(fixed_error) != "omlx_candidate_missing":
                raise
            dynamic = _find_dynamic_omlx_candidate(
                data, pe, resources_list, deadline=deadline, clock=clock
            )
            omlx_name = dynamic.resource_name
            omlx_blob = dynamic.resource_blob
            method = dynamic.raw_method0
            initializer = None
            profile = None
        (
            encrypted_name,
            encrypted,
            caller_token,
            declaration_validation,
            _references,
        ) = _find_bound_resource(
            data,
            pe,
            method.metadata_token,
            resources,
            deadline=deadline,
            clock=clock,
        )
        transforms = _verified_transform_recipes(
            data, pe, deadline=deadline, clock=clock
        )
        runtime_tokens, runtime_evidence = _discover_runtime_tokens(
            data,
            pe,
            method,
            transforms,
            deadline=deadline,
            clock=clock,
        )
        budget = _TerminalWorkBudget()
        entrypoint = int(getattr(pe.net.struct, "EntryPointTokenOrRva", 0) or 0)
        if dynamic is None:
            recovery = _recover_table(
                method,
                encrypted,
                transforms,
                entrypoint_token=entrypoint,
                deadline=deadline,
                clock=clock,
                work_budget=budget,
                runtime_tokens=runtime_tokens,
            )
            table = _decode_table(recovery.clear, deadline=deadline, clock=clock)
            terminal = _select_direct_terminal_binding(
                table, data, deadline=deadline, clock=clock, work_budget=budget
            )
            profile_id = profile.profile_id
            initializer_token = f"0x{initializer.metadata_token:08x}"
            opcode_candidates = viable_candidates = viable_modes = 1
            mask_modes = ["none"]
            dispatcher_token = None
        else:
            output = _recover_dynamic_output(
                dynamic,
                encrypted,
                transforms,
                data,
                runtime_tokens,
                entrypoint_token=entrypoint,
                deadline=deadline,
                clock=clock,
                work_budget=budget,
            )
            method = output.method
            recovery = output.table_recovery
            table = output.table
            terminal = output.terminal_binding
            profile_id = "omlx_dispatch_shape_inferred_direct_v1"
            initializer_token = f"0x{dynamic.method1_token:08x}"
            opcode_candidates = output.opcode_candidate_count
            viable_candidates = output.viable_candidate_count
            viable_modes = output.viable_mode_count
            mask_modes = list(output.selected_mask_modes)
            dispatcher_token = f"0x{dynamic.dispatcher.method_token:08x}"
        _check_time(deadline, clock)
        key = base64.b64decode(terminal.key_base64, validate=True)
        iv = base64.b64decode(terminal.iv_base64, validate=True)
        payload = terminal.payload
        _check_time(deadline, clock)
        terminal_container = _terminal_container_metadata(pe, terminal)
        _check_time(deadline, clock)
        report = {
            "status": "recovered_managed_omlx_direct_tripledes",
            "recipe": "omlx_table_parent_resourceset_tripledes_gzip_v1",
            "input": {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()},
            "omlx": {
                "profile_id": profile_id,
                "resource_name": omlx_name,
                "resource_size": len(omlx_blob),
                "resource_sha256": hashlib.sha256(omlx_blob).hexdigest(),
                "method_token": f"0x{method.metadata_token:08x}",
                "initializer_token": initializer_token,
                "dispatcher_token": dispatcher_token,
                "opcode_mapping_candidate_count": opcode_candidates,
                "viable_mapping_candidate_count": viable_candidates,
                "viable_mapping_mode_candidate_count": viable_modes,
                "distinct_recovered_output_count": 1,
                "all_viable_candidates_same_output": True,
                "selected_key_mask_modes": mask_modes,
                "static_dataflow_steps": recovery.steps,
            },
            "runtime_helper_derivation": {
                **runtime_evidence,
                "roles": {
                    role: f"0x{token:08x}"
                    for role, token in sorted(runtime_tokens.items())
                },
            },
            "encrypted_string_table": {
                "resource_name": encrypted_name,
                "resource_size": len(encrypted),
                "resource_sha256": hashlib.sha256(encrypted).hexdigest(),
                "caller_token": f"0x{caller_token:08x}",
                "transform_token": f"0x{recovery.transform.token:08x}",
                "transform_seed": recovery.transform.seed,
                "transform_addend": recovery.transform.addend,
                "clear_sha256": hashlib.sha256(recovery.clear).hexdigest(),
                "string_count": len(table),
                "key_offset": terminal.key_offset,
                "iv_offset": terminal.iv_offset,
                "raw_key_published": False,
                "raw_iv_published": False,
            },
            "terminal_resource": {
                "name": terminal.resource_name,
                "ciphertext_size": len(terminal.ciphertext),
                "ciphertext_sha256": hashlib.sha256(terminal.ciphertext).hexdigest(),
                "key_length": len(key),
                "key_sha256": hashlib.sha256(key).hexdigest(),
                "iv_length": len(iv),
                "iv_sha256": hashlib.sha256(iv).hexdigest(),
                "container": terminal_container,
            },
            "output": {
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "format": "managed_pe",
            },
            "framework_declaration_validation": declaration_validation,
            "sample_execution": False,
            "clr_load": False,
            "external_communication": False,
            "bounded_static_dataflow": True,
            "family_attribution_allowed": False,
            "terminal_config_markers_confirmed": False,
            "elapsed_seconds": round(max(0.0, clock() - started), 6),
        }
        _check_time(deadline, clock)
        return report, [("managed-omlx-direct-tripledes-gzip-pe", payload)]
    except (
        DirectOmlxError,
        OmlxTripledesError,
        StaticRecoveryError,
        RecoveryError,
        ValueError,
        TypeError,
        AttributeError,
        IndexError,
    ) as exc:
        reason = str(exc)
        return {
            "status": "rejected",
            "reason": reason,
            "input": {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()},
            "sample_execution": False,
            "external_communication": False,
            "family_attribution_allowed": False,
        }, []
