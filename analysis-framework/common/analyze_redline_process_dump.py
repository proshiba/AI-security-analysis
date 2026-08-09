#!/usr/bin/env python3
"""RedLineのprocess dumpからterminal .NET payloadを静的に復元・選別する。

入力は不活性なbyte列としてのみ扱う。CLR load、検体実行、CIL emulation、外部通信は
行わない。複数constructor・分岐・decoy assignmentをfield単位の候補として保持し、
一意または全同値の場合だけ設定値を確定する。
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import stat
import sys
from collections import defaultdict, deque
from collections.abc import Iterable
from pathlib import Path
from typing import Any

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
ANALYSIS_FRAMEWORK_ROOT = Path(__file__).resolve().parents[1]
for import_root in (REPOSITORY_ROOT, ANALYSIS_FRAMEWORK_ROOT):
    if str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))

from unpackers.dotnet_static_field_extractor import (
    iter_methods,
    load_managed_assembly,
    owner_maps,
    token_value,
)

from common.recover_process_dump_pe import recover_process_dump_bytes
from common.safe_artifact_io import (
    stable_file_identity,
    unlink_created_file_if_unchanged,
)

MAX_INPUT_BYTES = 512 * 1024 * 1024
MAX_INPUTS = 32
FRAMEWORK_NAMES = {
    "microsoft.csharp",
    "mscorlib",
    "netstandard",
    "system",
    "system.configuration",
    "system.core",
    "system.data",
    "system.dynamic",
    "system.management",
    "system.net.http",
    "system.numerics",
    "system.runtime.serialization",
    "system.servicemodel",
    "system.web",
    "system.web.extensions",
    "system.xml",
    "windowsbase",
}
MICROSOFT_PUBLIC_KEY_TOKENS = {
    "31bf3856ad364e35",
    "7cec85d7bea7798e",
    "b03f5f7f11d50a3a",
    "b77a5c561934e089",
    "cc7b13ffcd2ddd51",
}
REDLINE_REQUIRED_TYPES = {"EndpointConnection", "EntryPoint", "Program", "StringDecrypt"}
REDLINE_REQUIRED_METHODS = {
    "EndpointConnection.RequestConnection",
    "EndpointConnection.TryGetConnection",
    "Program.Execute",
    "Program.Main",
    "StringDecrypt.Decrypt",
}
REQUIRED_CONFIG_FIELDS = ("IP", "ID", "Message", "Key")
REPRESENTATIVE_METHODS = {
    "Program.Main": "entrypointとEntryPoint構築の起点",
    "Program.Execute": "接続、端末情報送信、task取得・完了通知を統括",
    "EntryPoint..ctor": "検体固有endpoint、build ID、message、keyの設定元",
    "EndpointConnection.RequestConnection": "endpoint構築とWCF channel生成",
    "EndpointConnection.TryGetConnection": "CheckConnectによる接続確認",
    "SystemInfoHelper.CreateBind": "BasicHttpBindingの制約、timeout、quota、security設定",
    "StringDecrypt.Decrypt": "Base64/XOR文字列復号と失敗時fallback",
    "CryptoHelper.DecryptBlob": "収集blobの暗号処理",
}
C2_VALUE = re.compile(r"^(?P<host>[A-Za-z0-9.-]+):(?P<port>[0-9]{1,5})$")
BRANCH_PREFIXES = (
    "br",
    "beq",
    "bge",
    "bgt",
    "ble",
    "blt",
    "bne",
    "leave",
)
UNCONDITIONAL_BRANCHES = {"br", "br.s", "leave", "leave.s"}
TERMINATORS = {"ret", "throw", "rethrow", "endfinally", "jmp"}
CALL_OPCODES = {"call", "callvirt", "newobj", "ldftn", "ldvirtftn"}


class StaticRecoveryError(ValueError):
    """安全境界または解析契約に反する入力を示す。"""


def _blob_bytes(value: Any) -> bytes:
    for candidate in (value, getattr(value, "value", None)):
        if isinstance(candidate, bytes):
            return candidate
        if isinstance(candidate, bytearray):
            return bytes(candidate)
    return b""


def _public_key_token(blob: bytes, *, full_public_key: bool) -> str:
    if not blob:
        return ""
    if not full_public_key:
        return blob.hex()
    return hashlib.sha1(blob).digest()[-8:][::-1].hex()


def _is_reparse(metadata: os.stat_result) -> bool:
    flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(flag and getattr(metadata, "st_file_attributes", 0) & flag)


def _file_identity(metadata: os.stat_result) -> tuple[int, int, int, int]:
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_size),
        int(getattr(metadata, "st_mtime_ns", int(metadata.st_mtime * 1_000_000_000))),
    )


def read_regular_file(path: Path, *, maximum: int = MAX_INPUT_BYTES) -> bytes:
    """linkとTOCTOUを拒否し、最大値+1まで読む。"""

    lexical = Path(path)
    try:
        before = lexical.lstat()
    except OSError as exc:
        raise StaticRecoveryError(f"入力をstatできません: {lexical}") from exc
    if not stat.S_ISREG(before.st_mode) or lexical.is_symlink() or _is_reparse(before):
        raise StaticRecoveryError("通常ファイル以外またはreparse pointは入力にできません")
    if int(getattr(before, "st_nlink", 1)) != 1:
        raise StaticRecoveryError("hardlink入力は使用できません")
    if before.st_size > maximum:
        raise StaticRecoveryError("入力サイズが上限を超えています")
    descriptor = os.open(str(lexical), os.O_RDONLY | getattr(os, "O_BINARY", 0))
    try:
        opened = os.fstat(descriptor)
        if _file_identity(before) != _file_identity(opened):
            raise StaticRecoveryError("入力がopen前に置き換えられました")
        if int(getattr(opened, "st_nlink", 1)) != 1:
            raise StaticRecoveryError("open後にhardlink化された入力は使用できません")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            data = handle.read(maximum + 1)
        after_fd = os.fstat(descriptor)
        after_path = lexical.lstat()
        if (
            _file_identity(opened) != _file_identity(after_fd)
            or _file_identity(opened) != _file_identity(after_path)
            or not stat.S_ISREG(after_fd.st_mode)
            or not stat.S_ISREG(after_path.st_mode)
            or int(getattr(after_fd, "st_nlink", 1)) != 1
            or int(getattr(after_path, "st_nlink", 1)) != 1
            or lexical.is_symlink()
            or _is_reparse(after_path)
        ):
            raise StaticRecoveryError("読取中に入力が変更されました")
    finally:
        os.close(descriptor)
    if len(data) > maximum:
        raise StaticRecoveryError("入力サイズが上限を超えています")
    return data


def write_new_json(path: Path, document: Any, *, root: Path | None = None) -> Path:
    """作業ルート内の既存directoryへJSONを排他的に新規保存する。"""

    root = (root or Path.cwd()).resolve(strict=True)
    raw = Path(path)
    if any(part == ".." for part in raw.parts):
        raise StaticRecoveryError("出力パスに'..'は使用できません")
    target = raw if raw.is_absolute() else root / raw
    try:
        parent = target.parent.resolve(strict=True)
        parent.relative_to(root)
    except (OSError, ValueError) as exc:
        raise StaticRecoveryError("出力先は作業ルート配下の既存directoryに限定されます") from exc
    current = root
    for part in parent.relative_to(root).parts:
        current = current / part
        metadata = current.lstat()
        if current.is_symlink() or _is_reparse(metadata) or not stat.S_ISDIR(metadata.st_mode):
            raise StaticRecoveryError("出力先にreparse pointまたは非directoryが含まれます")
    output_path = parent / target.name
    try:
        parent_before = parent.lstat()
    except OSError as exc:
        raise StaticRecoveryError("出力directoryをstatできません") from exc
    if (
        not stat.S_ISDIR(parent_before.st_mode)
        or parent.is_symlink()
        or _is_reparse(parent_before)
    ):
        raise StaticRecoveryError("出力先directoryを安全に使用できません")

    payload = (json.dumps(document, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    descriptor = os.open(
        str(output_path),
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
        0o600,
    )
    created_metadata: os.stat_result | None = None
    try:
        created_metadata = os.fstat(descriptor)
        parent_after_open = parent.lstat()
        path_after_open = output_path.lstat()
        if (
            not stat.S_ISREG(created_metadata.st_mode)
            or int(getattr(created_metadata, "st_nlink", 1)) != 1
            or stable_file_identity(parent_before)
            != stable_file_identity(parent_after_open)
            or not stat.S_ISDIR(parent_after_open.st_mode)
            or parent.is_symlink()
            or _is_reparse(parent_after_open)
            or not stat.S_ISREG(path_after_open.st_mode)
            or int(getattr(path_after_open, "st_nlink", 1)) != 1
            or output_path.is_symlink()
            or _is_reparse(path_after_open)
            or stable_file_identity(created_metadata)
            != stable_file_identity(path_after_open)
        ):
            raise StaticRecoveryError(
                "出力fileまたはdirectoryがopen中に置き換えられました"
            )

        view = memoryview(payload)
        written = 0
        while written < len(view):
            count = os.write(descriptor, view[written:])
            if count <= 0:
                raise StaticRecoveryError("出力を書き切れませんでした")
            written += count
        os.fsync(descriptor)
        final_fd = os.fstat(descriptor)
        final_parent = parent.lstat()
        final_path = output_path.lstat()
        if (
            not stat.S_ISREG(final_fd.st_mode)
            or int(getattr(final_fd, "st_nlink", 1)) != 1
            or stable_file_identity(final_fd)
            != stable_file_identity(created_metadata)
            or stable_file_identity(parent_before)
            != stable_file_identity(final_parent)
            or not stat.S_ISDIR(final_parent.st_mode)
            or parent.is_symlink()
            or _is_reparse(final_parent)
            or not stat.S_ISREG(final_path.st_mode)
            or int(getattr(final_path, "st_nlink", 1)) != 1
            or output_path.is_symlink()
            or _is_reparse(final_path)
            or stable_file_identity(final_path)
            != stable_file_identity(created_metadata)
        ):
            raise StaticRecoveryError(
                "出力完了時にfileまたはdirectoryのidentityが変化しました"
            )
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        if created_metadata is not None:
            unlink_created_file_if_unchanged(output_path, created_metadata)
        raise
    try:
        os.close(descriptor)
    except OSError:
        if created_metadata is not None:
            unlink_created_file_if_unchanged(output_path, created_metadata)
        raise
    return output_path


def assembly_identity(assembly: Any) -> dict[str, Any]:
    """Assembly/AssemblyRefのPublicKeyOrToken semanticsを保ったidentityを返す。"""

    assembly_rows = list(getattr(assembly.pe.net.mdtables.Assembly, "rows", ()) or ())
    module_rows = list(getattr(assembly.pe.net.mdtables.Module, "rows", ()) or ())
    assembly_row = assembly_rows[0] if assembly_rows else None
    module_row = module_rows[0] if module_rows else None
    public_key = _blob_bytes(getattr(assembly_row, "PublicKey", None)) if assembly_row else b""
    references: list[dict[str, str]] = []
    for row in getattr(assembly.pe.net.mdtables.AssemblyRef, "rows", ()) or ():
        flags = getattr(row, "Flags", None)
        is_full_key = bool(getattr(flags, "afPublicKey", False))
        token = _public_key_token(
            _blob_bytes(getattr(row, "PublicKey", None)),
            full_public_key=is_full_key,
        )
        references.append({"name": str(row.Name), "public_key_token": token})
    mvid = str(getattr(module_row, "Mvid", "")) if module_row else ""
    return {
        "assembly_name": str(getattr(assembly_row, "Name", "")) if assembly_row else "",
        "assembly_version": (
            ".".join(
                str(int(getattr(assembly_row, field, 0) or 0))
                for field in ("MajorVersion", "MinorVersion", "BuildNumber", "RevisionNumber")
            )
            if assembly_row
            else ""
        ),
        "public_key_token": _public_key_token(public_key, full_public_key=True),
        "module_name": str(getattr(module_row, "Name", "")) if module_row else "",
        "mvid": mvid,
        "assembly_references": sorted(
            references,
            key=lambda item: (item["name"].casefold(), item["public_key_token"]),
        ),
    }


def is_framework_identity(identity: dict[str, Any]) -> bool:
    """framework名とMicrosoft strong-name tokenの両方が一致した場合だけ除外する。"""

    name = str(identity.get("assembly_name", "")).casefold()
    token = str(identity.get("public_key_token", "")).casefold()
    return name in FRAMEWORK_NAMES and token in MICROSOFT_PUBLIC_KEY_TOKENS


def _type_and_method_topology(assembly: Any) -> tuple[set[str], set[str]]:
    types: set[str] = set()
    methods: set[str] = set()
    method_owners, _ = owner_maps(assembly.pe)
    for row in getattr(assembly.pe.net.mdtables.TypeDef, "rows", ()) or ():
        namespace = str(row.TypeNamespace)
        name = str(row.TypeName)
        types.add(".".join(part for part in (namespace, name) if part))
        types.add(name)
    for index, row in enumerate(getattr(assembly.pe.net.mdtables.MethodDef, "rows", ()) or (), 1):
        owner = method_owners.get(index, "")
        methods.add(f"{owner}.{row.Name}" if owner else str(row.Name))
    return types, methods


def classify_candidate(
    identity: dict[str, Any],
    types: set[str],
    methods: set[str],
    sha256: str,
    excluded: set[str],
) -> dict[str, Any]:
    """framework、外層copy、RedLine terminalをfail-closedに分類する。"""

    if sha256 in excluded:
        return {"classification": "excluded_root_copy", "terminal": False, "reasons": ["excluded_sha256_match"]}
    if is_framework_identity(identity):
        return {
            "classification": "framework_dependency",
            "terminal": False,
            "reasons": ["framework_name_and_strong_name_token"],
        }
    type_hits = sorted(REDLINE_REQUIRED_TYPES & types)
    method_hits = sorted(REDLINE_REQUIRED_METHODS & methods)
    terminal = len(type_hits) == len(REDLINE_REQUIRED_TYPES) and len(method_hits) == len(REDLINE_REQUIRED_METHODS)
    return {
        "classification": "redline_terminal" if terminal else "unclassified_managed_candidate",
        "terminal": terminal,
        "reasons": ["required_type_and_method_topology"] if terminal else ["insufficient_redline_topology"],
        "type_hits": type_hits,
        "method_hits": method_hits,
    }


def _user_string(assembly: Any, operand: Any) -> str | None:
    token = token_value(operand)
    try:
        return str(assembly.pe.net.user_strings.get(token & 0xFFFFFF))
    # malformed third-party metadataは候補単位でfail closedにする。
    except Exception:  # noqa: BLE001
        return None


def _opcode(instruction: Any) -> str:
    return str(getattr(getattr(instruction, "opcode", None), "name", "")).casefold()


def _offset(instruction: Any, fallback: int) -> int:
    try:
        return int(instruction.offset)
    except (AttributeError, TypeError, ValueError):
        return fallback


def _branch_targets(operand: Any) -> list[int]:
    values = operand if isinstance(operand, (list, tuple)) else [operand]
    output = []
    for value in values:
        candidate = getattr(value, "value", value)
        try:
            output.append(int(candidate))
        except (TypeError, ValueError):
            continue
    return output


def _cfg(instructions: list[Any]) -> tuple[set[int], dict[int, str], list[dict[str, Any]]]:
    """通常分岐を保守的に辿り、reachable offsetとbasic blockを返す。"""

    if not instructions:
        return set(), {}, []
    offsets = [_offset(instruction, index) for index, instruction in enumerate(instructions)]
    offset_set = set(offsets)
    next_offset = {offsets[index]: offsets[index + 1] for index in range(len(offsets) - 1)}
    leaders = {offsets[0]}
    edges: dict[int, set[int]] = defaultdict(set)
    branch_rows: list[dict[str, Any]] = []
    for index, instruction in enumerate(instructions):
        current = offsets[index]
        opcode = _opcode(instruction)
        target_values = [value for value in _branch_targets(getattr(instruction, "operand", None)) if value in offset_set]
        is_branch = opcode == "switch" or opcode.startswith(BRANCH_PREFIXES)
        if is_branch:
            for target in target_values:
                edges[current].add(target)
                leaders.add(target)
            if opcode not in UNCONDITIONAL_BRANCHES and current in next_offset:
                edges[current].add(next_offset[current])
            if current in next_offset:
                leaders.add(next_offset[current])
            branch_rows.append({"offset": f"0x{current:04x}", "opcode": opcode, "targets": [f"0x{x:04x}" for x in target_values]})
        elif opcode not in TERMINATORS and current in next_offset:
            edges[current].add(next_offset[current])
        elif current in next_offset:
            leaders.add(next_offset[current])
    reachable: set[int] = set()
    queue = deque([offsets[0]])
    while queue:
        current = queue.popleft()
        if current in reachable:
            continue
        reachable.add(current)
        queue.extend(sorted(edges.get(current, ())))
    sorted_leaders = sorted(leaders)
    block_map: dict[int, str] = {}
    for current in offsets:
        leader = max(value for value in sorted_leaders if value <= current)
        block_map[current] = f"B{sorted_leaders.index(leader)}@0x{leader:04x}"
    return reachable, block_map, branch_rows


def extract_entrypoint_config(assembly: Any) -> dict[str, Any]:
    """EntryPoint constructor群のreachable assignmentを候補として集約する。"""

    _, field_owners = owner_maps(assembly.pe)
    fields = list(getattr(assembly.pe.net.mdtables.Field, "rows", ()) or ())
    candidates: dict[str, list[dict[str, Any]]] = defaultdict(list)
    blockers: list[dict[str, Any]] = []
    constructor_count = 0
    for method_index, owner, row, instructions in iter_methods(assembly):
        if owner != "EntryPoint" or str(row.Name) != ".ctor":
            continue
        constructor_count += 1
        reachable, block_map, _ = _cfg(instructions)
        pending: dict[str, Any] | None = None
        for position, instruction in enumerate(instructions):
            current = _offset(instruction, position)
            if current not in reachable:
                continue
            opcode = _opcode(instruction)
            if opcode == "ldstr":
                pending = {
                    "value": _user_string(assembly, getattr(instruction, "operand", None)),
                    "source_offset": current,
                    "transforms": [],
                }
                continue
            if opcode in {"call", "callvirt"} and pending is not None:
                pending["transforms"].append(f"0x{token_value(getattr(instruction, 'operand', None)):08x}")
                continue
            if opcode == "stfld" and pending is not None:
                token = token_value(getattr(instruction, "operand", None))
                rid = token & 0xFFFFFF
                if token >> 24 == 0x04 and 0 < rid <= len(fields) and field_owners.get(rid, "") == "EntryPoint":
                    field_name = str(fields[rid - 1].Name)
                    record = {
                        "method_token": f"0x06{method_index:06x}",
                        "method": "EntryPoint..ctor",
                        "field_token": f"0x{token:08x}",
                        "field": field_name,
                        "value": pending["value"],
                        "basic_block": block_map.get(current, "unknown"),
                        "source_offset": f"0x{pending['source_offset']:04x}",
                        "store_offset": f"0x{current:04x}",
                        "reachable": True,
                        "transforms": list(pending["transforms"]),
                    }
                    candidates[field_name].append(record)
                    if pending["transforms"]:
                        blockers.append(
                            {
                                "field": field_name,
                                "method_token": record["method_token"],
                                "basic_block": record["basic_block"],
                                "reason": "decrypt_or_transform_call_between_literal_and_store",
                            }
                        )
                pending = None
                continue
            if opcode not in {"ldarg.0", "nop", "dup"}:
                pending = None
    fields_result: dict[str, Any] = {}
    for field_name in REQUIRED_CONFIG_FIELDS:
        field_candidates = candidates.get(field_name, [])
        unsupported = any(item["transforms"] or item["value"] is None for item in field_candidates)
        values = sorted({item["value"] for item in field_candidates if item["value"] is not None})
        if field_candidates and not unsupported and len(values) == 1:
            status = "confirmed"
            value = values[0]
        elif field_candidates:
            status = "ambiguous"
            value = None
        else:
            status = "not_recovered"
            value = None
        fields_result[field_name] = {
            "status": status,
            "value": value,
            "all_equivalent": bool(field_candidates) and len(values) == 1 and not unsupported,
            "candidates": field_candidates,
        }
    status = (
        "confirmed"
        if all(fields_result[name]["status"] == "confirmed" for name in REQUIRED_CONFIG_FIELDS)
        else "ambiguous"
        if any(fields_result[name]["status"] == "ambiguous" for name in REQUIRED_CONFIG_FIELDS)
        else "partial"
    )
    return {
        "status": status,
        "constructor_count": constructor_count,
        "fields": fields_result,
        "blockers": blockers,
    }


def _row_name(row: Any) -> str:
    namespace = str(getattr(row, "TypeNamespace", ""))
    type_name = str(getattr(row, "TypeName", ""))
    name = str(getattr(row, "Name", ""))
    return ".".join(value for value in (namespace, type_name or name) if value)


def _cil_int_constant(instruction: Any) -> int | None:
    opcode = _opcode(instruction)
    fixed = {
        "ldc.i4.m1": -1,
        "ldc.i4.0": 0,
        "ldc.i4.1": 1,
        "ldc.i4.2": 2,
        "ldc.i4.3": 3,
        "ldc.i4.4": 4,
        "ldc.i4.5": 5,
        "ldc.i4.6": 6,
        "ldc.i4.7": 7,
        "ldc.i4.8": 8,
    }
    if opcode in fixed:
        return fixed[opcode]
    if opcode not in {"ldc.i4", "ldc.i4.s"}:
        return None
    operand = getattr(instruction, "operand", None)
    value = getattr(operand, "value", operand)
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _decode_compressed_uint(blob: bytes, offset: int) -> tuple[int, int] | None:
    if offset >= len(blob):
        return None
    first = blob[offset]
    if first & 0x80 == 0:
        return first, offset + 1
    if first & 0xC0 == 0x80 and offset + 1 < len(blob):
        return ((first & 0x3F) << 8) | blob[offset + 1], offset + 2
    if first & 0xE0 == 0xC0 and offset + 3 < len(blob):
        return (
            ((first & 0x1F) << 24)
            | (blob[offset + 1] << 16)
            | (blob[offset + 2] << 8)
            | blob[offset + 3],
            offset + 4,
        )
    return None


def _type_def_or_ref_name(assembly: Any, encoded: int) -> str:
    table_ids = {0: 0x02, 1: 0x01, 2: 0x1B}
    table_id = table_ids.get(encoded & 0x03)
    rid = encoded >> 2
    if not table_id or rid <= 0:
        return ""
    return _token_name(assembly, (table_id << 24) | rid)


def _typespec_generic_types(assembly: Any, rid: int) -> list[str]:
    rows = list(getattr(assembly.pe.net.mdtables.TypeSpec, "rows", ()) or ())
    if not 0 < rid <= len(rows):
        return []
    blob = _blob_bytes(getattr(rows[rid - 1], "Signature", None))
    if len(blob) < 4 or blob[0] != 0x15 or blob[1] not in {0x11, 0x12}:
        return []
    base = _decode_compressed_uint(blob, 2)
    if base is None:
        return []
    encoded_base, cursor = base
    count_value = _decode_compressed_uint(blob, cursor)
    if count_value is None:
        return []
    count, cursor = count_value
    output = [_type_def_or_ref_name(assembly, encoded_base)]
    for _ in range(count):
        if cursor >= len(blob) or blob[cursor] not in {0x11, 0x12}:
            return []
        encoded_argument = _decode_compressed_uint(blob, cursor + 1)
        if encoded_argument is None:
            return []
        encoded, cursor = encoded_argument
        output.append(_type_def_or_ref_name(assembly, encoded))
    return output


def _token_name(assembly: Any, token: int, method_owners: dict[int, str] | None = None) -> str:
    if not token:
        return ""
    table_id = token >> 24
    rid = token & 0xFFFFFF
    table_names = {0x01: "TypeRef", 0x02: "TypeDef", 0x04: "Field", 0x06: "MethodDef", 0x0A: "MemberRef", 0x1B: "TypeSpec"}
    table_name = table_names.get(table_id)
    table = getattr(assembly.pe.net.mdtables, table_name, None) if table_name else None
    rows = list(getattr(table, "rows", ()) or ())
    if not 0 < rid <= len(rows):
        return f"token:0x{token:08x}"
    row = rows[rid - 1]
    if table_id == 0x06:
        method_owners = method_owners or owner_maps(assembly.pe)[0]
        owner = method_owners.get(rid, "")
        return f"{owner}.{row.Name}" if owner else str(row.Name)
    if table_id == 0x0A:
        parent = getattr(row, "Class", None)
        parent_row = getattr(parent, "row", None)
        parent_name = _row_name(parent_row) if parent_row is not None else type(parent_row).__name__
        if not parent_name:
            parent_name = f"{type(parent_row).__name__}#{getattr(parent, 'row_index', '?')}"
        return f"{parent_name}.{row.Name}"
    if table_id == 0x04:
        _, field_owners = owner_maps(assembly.pe)
        owner = field_owners.get(rid, "")
        return f"{owner}.{row.Name}" if owner else str(row.Name)
    if table_id == 0x1B:
        return f"TypeSpec#{rid}"
    return _row_name(row) or f"token:0x{token:08x}"


def _normalized_method_fingerprint(assembly: Any, instructions: list[Any]) -> str:
    method_owners, _ = owner_maps(assembly.pe)
    normalized: list[list[str]] = []
    for instruction in instructions:
        opcode = _opcode(instruction)
        if opcode == "ldstr":
            operand = "string"
        elif opcode in CALL_OPCODES or opcode in {"ldfld", "stfld", "ldsfld", "stsfld", "ldtoken", "newarr", "isinst", "castclass"}:
            operand = _token_name(assembly, token_value(getattr(instruction, "operand", None)), method_owners)
        elif opcode == "switch" or opcode.startswith(BRANCH_PREFIXES):
            operand = "branch-target"
        else:
            raw = getattr(instruction, "operand", None)
            operand = "none" if raw is None else type(raw).__name__
        normalized.append([opcode, operand])
    encoded = json.dumps(normalized, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _method_analysis(assembly: Any) -> dict[str, Any]:
    method_owners, _ = owner_maps(assembly.pe)
    method_rows = list(getattr(assembly.pe.net.mdtables.MethodDef, "rows", ()) or ())
    parsed = {index: (owner, row, instructions) for index, owner, row, instructions in iter_methods(assembly)}
    callers: dict[int, set[int]] = defaultdict(set)
    callees: dict[int, set[int]] = defaultdict(set)
    inventory: list[dict[str, Any]] = []
    for index, row in enumerate(method_rows, 1):
        owner = method_owners.get(index, "")
        instructions = parsed.get(index, (owner, row, []))[2]
        for instruction in instructions:
            if _opcode(instruction) in CALL_OPCODES:
                token = token_value(getattr(instruction, "operand", None))
                if token >> 24 == 0x06 and 0 < (token & 0xFFFFFF) <= len(method_rows):
                    target = token & 0xFFFFFF
                    callers[target].add(index)
                    callees[index].add(target)
        inventory.append(
            {
                "method_token": f"0x06{index:06x}",
                "owner": owner,
                "name": str(row.Name),
                "has_cil_body": bool(instructions),
                "normalized_fingerprint_sha256": _normalized_method_fingerprint(assembly, instructions) if instructions else None,
            }
        )
    representative: list[dict[str, Any]] = []
    for index, (owner, row, instructions) in sorted(parsed.items()):
        full_name = f"{owner}.{row.Name}" if owner else str(row.Name)
        if full_name not in REPRESENTATIVE_METHODS:
            continue
        _, _, branches = _cfg(instructions)
        representative.append(
            {
                "method_token": f"0x06{index:06x}",
                "method": full_name,
                "selection_reason": REPRESENTATIVE_METHODS[full_name],
                "instruction_count": len(instructions),
                "branch_count": len(branches),
                "branches": branches,
                "callers": [
                    _token_name(assembly, 0x06000000 | value, method_owners)
                    for value in sorted(callers.get(index, ()))
                ],
                "callees": [
                    _token_name(assembly, 0x06000000 | value, method_owners)
                    for value in sorted(callees.get(index, ()))
                ],
                "normalized_fingerprint_sha256": _normalized_method_fingerprint(assembly, instructions),
            }
        )
    return {
        "metadata_method_count": len(method_rows),
        "cil_body_count": len(parsed),
        "inventory": inventory,
        "representative_methods": representative,
    }


def _attribute_type_name(row: Any) -> str:
    attribute_type = getattr(row, "Type", None)
    member = getattr(attribute_type, "row", None)
    parent = getattr(member, "Class", None)
    return _row_name(getattr(parent, "row", None))


def _protocol_profile(assembly: Any) -> dict[str, Any]:
    method_owners, _ = owner_maps(assembly.pe)
    parsed = {
        index: (owner, row, instructions)
        for index, owner, row, instructions in iter_methods(assembly)
    }
    selected: set[int] = {
        index
        for index, (owner, row, _) in parsed.items()
        if owner == "EndpointConnection" and str(row.Name) == "RequestConnection"
    }
    # RequestConnectionが呼ぶbinding builderを1段だけ追い、helper名だけの一致で
    # BasicHttpBindingを確定しない。実際のnewobj/setterを後段で要求する。
    for index in tuple(selected):
        for instruction in parsed[index][2]:
            token = token_value(getattr(instruction, "operand", None))
            if _opcode(instruction) in {"call", "callvirt"} and token >> 24 == 0x06:
                target = token & 0xFFFFFF
                target_row = parsed.get(target)
                if target_row and target_row[0] == "SystemInfoHelper" and str(target_row[1].Name) == "CreateBind":
                    selected.add(target)
    refs = []
    for method_index in sorted(selected):
        owner, row, instructions = parsed[method_index]
        for position, instruction in enumerate(instructions):
            if _opcode(instruction) not in CALL_OPCODES | {"callvirt"}:
                continue
            token = token_value(getattr(instruction, "operand", None))
            generic_types: list[str] = []
            if token >> 24 == 0x0A:
                member_rows = list(getattr(assembly.pe.net.mdtables.MemberRef, "rows", ()) or ())
                member_rid = token & 0xFFFFFF
                if 0 < member_rid <= len(member_rows):
                    parent = getattr(member_rows[member_rid - 1], "Class", None)
                    if type(getattr(parent, "row", None)).__name__ == "TypeSpecRow":
                        generic_types = _typespec_generic_types(
                            assembly, int(getattr(parent, "row_index", 0) or 0)
                        )
            previous_int = _cil_int_constant(instructions[position - 1]) if position else None
            refs.append(
                {
                    "method_token": f"0x06{method_index:06x}",
                    "method": f"{owner}.{row.Name}",
                    "offset": f"0x{_offset(instruction, position):04x}",
                    "opcode": _opcode(instruction),
                    "token": f"0x{token:08x}",
                    "resolved": _token_name(assembly, token, method_owners),
                    "generic_types": generic_types,
                    "previous_int32": previous_int,
                }
            )
    resolved = [item["resolved"] for item in refs]
    endpoint_address = any("System.ServiceModel.EndpointAddress..ctor" in value for value in resolved)
    expected_generic = {"System.ServiceModel.ChannelFactory`1", "IRemoteEndpoint"}
    factory_ctor = any(
        item["resolved"].endswith("..ctor") and expected_generic <= set(item["generic_types"])
        for item in refs
    )
    create_channel = any(
        item["resolved"].endswith(".CreateChannel") and expected_generic <= set(item["generic_types"])
        for item in refs
    )
    basic_binding_ctor = any("BasicHttpBinding..ctor" in value for value in resolved)
    transfer_setter = any(
        item["resolved"].endswith(".set_TransferMode") and item["previous_int32"] == 0
        for item in refs
    )
    security_mode_none = any(
        item["resolved"].endswith("BasicHttpSecurity.set_Mode") and item["previous_int32"] == 0
        for item in refs
    )
    security_attached = any(item["resolved"].endswith("BasicHttpBinding.set_Security") for item in refs)

    service_contract = False
    operation_contract = False
    service_name = False
    operation_name = False
    namespace_explicit = False
    for row in getattr(assembly.pe.net.mdtables.CustomAttribute, "rows", ()) or ():
        parent = getattr(getattr(row, "Parent", None), "row", None)
        parent_type = type(parent).__name__
        parent_name = str(getattr(parent, "TypeName", getattr(parent, "Name", "")))
        attribute_name = _attribute_type_name(row)
        blob = _blob_bytes(getattr(row, "Value", None))
        if parent_type == "TypeDefRow" and parent_name == "IRemoteEndpoint" and attribute_name.endswith("ServiceContractAttribute"):
            service_contract = True
            service_name = b"Endpoint" in blob and b"Name" in blob
            namespace_explicit = b"Namespace" in blob
        if parent_type == "MethodDefRow" and parent_name == "CheckConnect" and attribute_name.endswith("OperationContractAttribute"):
            operation_contract = True
            operation_name = b"CheckConnect" in blob and b"Name" in blob
    evidence = {
        "endpoint_address_constructor": endpoint_address,
        "channel_factory_irremoteendpoint_constructor": factory_ctor,
        "channel_create": create_channel,
        "basic_http_binding_constructor": basic_binding_ctor,
        "transfer_mode_buffered": transfer_setter,
        "security_mode_none": security_mode_none,
        "security_attached_to_binding": security_attached,
        "service_contract_attribute": service_contract,
        "service_contract_name_endpoint": service_name,
        "operation_contract_attribute": operation_contract,
        "operation_contract_name_checkconnect": operation_name,
        "contract_namespace_explicit": namespace_explicit,
    }
    required = (
        endpoint_address,
        factory_ctor,
        create_channel,
        basic_binding_ctor,
        transfer_setter,
        security_mode_none,
        security_attached,
        service_contract,
        service_name,
        operation_contract,
        operation_name,
    )
    status = "confirmed_static_structure" if all(required) else "candidate_static_structure"
    blockers = [key for key, value in evidence.items() if key != "contract_namespace_explicit" and not value]
    if not namespace_explicit:
        blockers.append("contract_namespace_is_WCF_default_inference")
    return {
        "status": status,
        "scheme": "http",
        "binding": "System.ServiceModel.BasicHttpBinding" if basic_binding_ctor else "WCF HTTP channel candidate",
        "security_mode": "None" if security_mode_none and security_attached else "not_statically_proven",
        "transfer_mode": "Buffered" if transfer_setter else "not_statically_proven",
        "request_builder": "http:// + EntryPoint.IP + /",
        "endpoint_path": "/",
        "contract_type": "IRemoteEndpoint",
        "contract_name": "Endpoint" if service_name else "candidate",
        "contract_namespace": "http://tempuri.org/",
        "contract_namespace_basis": "explicit_attribute" if namespace_explicit else "WCF_default_inference",
        "operations": {
            "CheckConnect": {"parameters": [], "return_type": "System.Boolean"},
            "EnvironmentSettings": {"method": "GetArguments"},
            "SetEnvironment": {"method": "VerifyScanRequest"},
            "GetUpdates": {"method": "GetUpdates"},
            "VerifyUpdate": {"method": "VerifyUpdate"},
        },
        "wire_format": {
            "http_method": "POST",
            "content_type": "text/xml; charset=utf-8",
            "soap_version": "SOAP 1.1",
            "soap_action": "http://tempuri.org/Endpoint/CheckConnect",
            "request_body_element": "{http://tempuri.org/}CheckConnect",
            "response_body_element": "{http://tempuri.org/}CheckConnectResponse",
            "result_element": "{http://tempuri.org/}CheckConnectResult",
            "result_type": "xsd:boolean",
            "basis": "WCF contract convention; historical Triage transcriptで別途実測",
        },
        "evidence": evidence,
        "member_references": refs,
        "blockers": blockers,
        "active_probe_status": "request_shape_recovered_but_not_sent",
    }


def cil_semantic_hash(assembly: Any) -> str:
    """配置addressに依存しない全CIL opcode/operand列のSHA-256を返す。"""

    records: list[list[Any]] = []
    for method_index, owner, row, instructions in iter_methods(assembly):
        normalized: list[list[Any]] = []
        for instruction in instructions:
            opcode = _opcode(instruction)
            if opcode == "ldstr":
                operand: Any = _user_string(assembly, getattr(instruction, "operand", None))
            else:
                token = token_value(getattr(instruction, "operand", None))
                if token:
                    operand = f"token:0x{token:08x}"
                elif isinstance(getattr(instruction, "operand", None), (int, float, str, type(None))):
                    operand = getattr(instruction, "operand", None)
                else:
                    operand = type(getattr(instruction, "operand", None)).__name__
            normalized.append([opcode, operand])
        records.append([f"0x06{method_index:06x}", owner, str(row.Name), normalized])
    encoded = json.dumps(records, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def parse_c2(value: str) -> dict[str, Any] | None:
    match = C2_VALUE.fullmatch(value.strip())
    if not match:
        return None
    host = match.group("host").rstrip(".").casefold()
    port = int(match.group("port"))
    if not 1 <= port <= 65535:
        return None
    try:
        ipaddress.ip_address(host)
        host_type = "ip"
    except ValueError:
        if "." not in host or any(not label or len(label) > 63 for label in host.split(".")):
            return None
        host_type = "domain"
    return {
        "host": host,
        "host_type": host_type,
        "port": port,
        "transport": "http",
        "base_url": f"http://{host}:{port}/",
        "confidence": "confirmed_static_config",
        "source": "EntryPoint constructorのreachable field IP",
    }


def analyze_payload(payload: bytes, *, excluded: set[str], source: dict[str, Any]) -> dict[str, Any]:
    sha256 = hashlib.sha256(payload).hexdigest()
    record: dict[str, Any] = {"sha256": sha256, "size": len(payload), "source": source}
    try:
        assembly = load_managed_assembly(payload)
    # parserが返す例外型はmetadata破損箇所ごとに異なるため候補単位で隔離する。
    except Exception as exc:  # noqa: BLE001
        record.update({"classification": "not_managed", "terminal": False, "error": type(exc).__name__})
        return record
    identity = assembly_identity(assembly)
    types, methods = _type_and_method_topology(assembly)
    classification = classify_candidate(identity, types, methods, sha256, excluded)
    record.update({"identity": identity, "cil_semantic_sha256": cil_semantic_hash(assembly), **classification})
    if classification["terminal"]:
        config = extract_entrypoint_config(assembly)
        method_analysis = _method_analysis(assembly)
        ip_field = config["fields"]["IP"]
        c2 = parse_c2(str(ip_field["value"])) if ip_field["status"] == "confirmed" else None
        record["config"] = config
        record["c2"] = [c2] if c2 else []
        record["protocol_profile"] = _protocol_profile(assembly)
        record["managed_methods"] = method_analysis
    return record


def analyze_inputs(paths: Iterable[Path], *, excluded: set[str]) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    seen_payloads: set[str] = set()
    inputs = list(paths)
    if not 1 <= len(inputs) <= MAX_INPUTS:
        raise StaticRecoveryError(f"入力数は1から{MAX_INPUTS}件に制限されています")
    for path in inputs:
        data = read_regular_file(path)
        recovered, recovery = recover_process_dump_bytes(data, source_name=str(path), mapped_mode="auto")
        for item in recovered:
            sha256 = hashlib.sha256(item.payload).hexdigest()
            if sha256 in seen_payloads:
                continue
            seen_payloads.add(sha256)
            records.append(analyze_payload(item.payload, excluded=excluded, source=item.metadata))
        if not recovered and data.startswith(b"MZ"):
            sha256 = hashlib.sha256(data).hexdigest()
            if sha256 not in seen_payloads:
                seen_payloads.add(sha256)
                records.append(
                    analyze_payload(
                        data,
                        excluded=excluded,
                        source={"input": str(path), "recovery": recovery["summary"]},
                    )
                )
    terminals = [item for item in records if item.get("terminal")]
    equivalence_groups: dict[tuple[str, str, str, str], list[str]] = defaultdict(list)
    for item in terminals:
        identity = item["identity"]
        key = (
            identity.get("mvid", ""),
            identity.get("assembly_name", ""),
            identity.get("module_name", ""),
            item.get("cil_semantic_sha256", ""),
        )
        equivalence_groups[key].append(item["sha256"])
    terminal_equivalence = [
        {
            "mvid": key[0],
            "assembly_name": key[1],
            "module_name": key[2],
            "cil_semantic_sha256": key[3],
            "memory_variant_sha256": sorted(values),
            "config_source_sha256": min(values),
            "canonical_file_layout": None,
            "canonical_status": "memory snapshotのみのため配置依存領域を推測せずsemantic identityで統合",
        }
        for key, values in sorted(equivalence_groups.items())
    ]
    confirmed_static_c2 = sum(len(item.get("c2", [])) for item in terminals)
    return {
        "schema_version": 2,
        "analysis": "redline_process_dump_static_recovery",
        "status": "terminal_config_recovered" if confirmed_static_c2 else "partial",
        "summary": {
            "inputs": len(inputs),
            "unique_pe_candidates": len(records),
            "terminal_candidates": len(terminals),
            "confirmed_static_c2": confirmed_static_c2,
        },
        "candidates": records,
        "terminal_equivalence": terminal_equivalence,
        "safety": {"executed": False, "emulated": False, "network_contacted": False},
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", action="append", required=True, type=Path, help="process dumpまたは復元済みPE。複数指定可能")
    parser.add_argument("--exclude-sha256", action="append", default=[], help="外層copyとして除外するSHA-256")
    parser.add_argument("--output", required=True, type=Path, help="新規JSON出力先")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    excluded = {value.casefold() for value in args.exclude_sha256 if re.fullmatch(r"[0-9a-fA-F]{64}", value)}
    result = analyze_inputs(args.input, excluded=excluded)
    write_new_json(args.output, result)
    print(json.dumps(result["summary"], ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
