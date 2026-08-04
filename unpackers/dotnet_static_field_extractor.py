#!/usr/bin/env python3
"""破損したCLRヘッダーにも対応する、非実行の.NET静的フィールド抽出器。"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import struct
from typing import Any, Iterator
import warnings

import dnfile
from dncil.cil.body.reader import read_method_body_from_bytes
import pefile


MAX_INPUT_SIZE = 512 * 1024 * 1024
MAX_METADATA_ROOTS = 64
MAX_METADATA_STREAMS = 32
MAX_METHOD_BYTES = 256 * 1024


class ManagedMetadataError(ValueError):
    """安全に解析できる.NETメタデータを確立できなかったことを示す。"""


@dataclass(frozen=True)
class MetadataRoot:
    file_offset: int
    rva: int
    size: int
    streams: tuple[str, ...]


@dataclass(frozen=True)
class ManagedAssembly:
    data: bytes
    pe: Any
    recovery: dict[str, Any]


def _metadata_root(data: bytes, offset: int) -> tuple[int, tuple[str, ...]]:
    """BSJBメタデータルートを検証し、全streamを含む大きさを返す。"""

    if offset < 0 or offset + 20 > len(data) or data[offset : offset + 4] != b"BSJB":
        raise ManagedMetadataError("BSJBメタデータルートではありません")
    version_length = struct.unpack_from("<I", data, offset + 12)[0]
    if not 1 <= version_length <= 512 or offset + 16 + version_length > len(data):
        raise ManagedMetadataError("CLRバージョン文字列の範囲が不正です")
    cursor = (offset + 16 + version_length + 3) & ~3
    if cursor + 4 > len(data):
        raise ManagedMetadataError("メタデータstreamヘッダーが切れています")
    stream_count = struct.unpack_from("<H", data, cursor + 2)[0]
    if not 1 <= stream_count <= MAX_METADATA_STREAMS:
        raise ManagedMetadataError("メタデータstream数が不正です")
    cursor += 4
    names: list[str] = []
    maximum_end = cursor - offset
    for _ in range(stream_count):
        if cursor + 8 > len(data):
            raise ManagedMetadataError("メタデータstream記述が切れています")
        relative_offset, size = struct.unpack_from("<II", data, cursor)
        cursor += 8
        terminator = data.find(b"\0", cursor, min(len(data), cursor + 64))
        if terminator < 0:
            raise ManagedMetadataError("メタデータstream名が不正です")
        try:
            name = data[cursor:terminator].decode("ascii")
        except UnicodeDecodeError as exc:
            raise ManagedMetadataError("メタデータstream名がASCIIではありません") from exc
        cursor = (terminator + 4) & ~3
        if not name.startswith("#") or relative_offset > len(data) - offset:
            raise ManagedMetadataError("メタデータstreamの範囲が不正です")
        end = relative_offset + size
        if end < relative_offset or end > len(data) - offset:
            raise ManagedMetadataError("メタデータstreamが入力範囲外です")
        maximum_end = max(maximum_end, end)
        names.append(name)
    if not ({"#~", "#-"} & set(names)) or "#Strings" not in names:
        raise ManagedMetadataError("必須メタデータstreamがありません")
    return maximum_end, tuple(names)


def _find_metadata_roots(data: bytes, pe: pefile.PE) -> list[MetadataRoot]:
    roots: list[MetadataRoot] = []
    cursor = 0
    while len(roots) < MAX_METADATA_ROOTS:
        cursor = data.find(b"BSJB", cursor)
        if cursor < 0:
            break
        try:
            size, streams = _metadata_root(data, cursor)
            rva = int(pe.get_rva_from_offset(cursor))
            roots.append(MetadataRoot(cursor, rva, size, streams))
        except (ManagedMetadataError, pefile.PEFormatError, ValueError):
            pass
        cursor += 4
    return roots


def _clr_header_offset(pe: pefile.PE, data_size: int) -> int:
    directories = getattr(pe.OPTIONAL_HEADER, "DATA_DIRECTORY", ())
    if len(directories) <= 14:
        raise ManagedMetadataError("CLR data directoryがありません")
    rva = int(directories[14].VirtualAddress)
    size = int(directories[14].Size)
    if rva <= 0 or size < 0x48:
        raise ManagedMetadataError("CLR data directoryが不正です")
    try:
        offset = int(pe.get_offset_from_rva(rva))
    except pefile.PEFormatError as exc:
        raise ManagedMetadataError("CLR header RVAをfile offsetへ変換できません") from exc
    if offset < 0 or offset + 0x48 > data_size:
        raise ManagedMetadataError("CLR headerが入力範囲外です")
    return offset


def prepare_managed_view(data: bytes) -> tuple[bytes, dict[str, Any]]:
    """CLRヘッダーが上書きされたmemory PEに、解析専用header viewを合成する。"""

    if not data.startswith(b"MZ") or not 1 <= len(data) <= MAX_INPUT_SIZE:
        raise ManagedMetadataError("入力は許容範囲内のPEではありません")
    try:
        pe = pefile.PE(data=data, fast_load=False)
    except pefile.PEFormatError as exc:
        raise ManagedMetadataError("PEヘッダーを解析できません") from exc
    clr_offset = _clr_header_offset(pe, len(data))
    roots = _find_metadata_roots(data, pe)
    if not roots:
        raise ManagedMetadataError("検証可能な.NETメタデータルートがありません")

    header_valid = False
    selected: MetadataRoot | None = None
    if struct.unpack_from("<I", data, clr_offset)[0] == 0x48:
        metadata_rva, metadata_size = struct.unpack_from("<II", data, clr_offset + 8)
        try:
            metadata_offset = int(pe.get_offset_from_rva(metadata_rva))
        except pefile.PEFormatError:
            metadata_offset = -1
        for root in roots:
            if root.file_offset == metadata_offset and metadata_size >= root.size:
                selected = root
                header_valid = True
                break
    if selected is None:
        if len(roots) != 1:
            raise ManagedMetadataError("複数の.NETメタデータルートがあり自動選択できません")
        selected = roots[0]

    if header_valid:
        return data, {
            "status": "original_clr_header_valid",
            "header_repaired_for_static_view": False,
            "metadata_rva": selected.rva,
            "metadata_size": selected.size,
            "metadata_streams": list(selected.streams),
        }

    repaired = bytearray(data)
    repaired[clr_offset : clr_offset + 0x48] = b"\0" * 0x48
    struct.pack_into(
        "<IHHIIII",
        repaired,
        clr_offset,
        0x48,
        2,
        5,
        selected.rva,
        selected.size,
        1,
        0,
    )
    return bytes(repaired), {
        "status": "clr_header_recovered_for_static_view",
        "header_repaired_for_static_view": True,
        "metadata_rva": selected.rva,
        "metadata_size": selected.size,
        "metadata_streams": list(selected.streams),
        "note": "入力ファイルは変更せず、dnfile解析用のmemory copyだけを修復しました。",
    }


def load_managed_assembly(data: bytes) -> ManagedAssembly:
    view, recovery = prepare_managed_view(data)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        try:
            parsed = dnfile.dnPE(data=view, fast_load=False)
        except Exception as exc:
            raise ManagedMetadataError(".NETメタデータを解析できません") from exc
    if not getattr(parsed, "net", None) or not getattr(parsed.net, "mdtables", None):
        raise ManagedMetadataError("有効な.NETメタデータテーブルがありません")
    return ManagedAssembly(view, parsed, recovery)


def token_value(operand: Any) -> int:
    try:
        return int(getattr(operand, "value"))
    except (AttributeError, TypeError, ValueError):
        return 0


def owner_maps(pe: Any) -> tuple[dict[int, str], dict[int, str]]:
    methods: dict[int, str] = {}
    fields: dict[int, str] = {}
    for row in getattr(pe.net.mdtables.TypeDef, "rows", ()):
        owner = ".".join(
            value
            for value in (str(row.TypeNamespace), str(row.TypeName))
            if value
        )
        for reference in getattr(row, "MethodList", ()) or ():
            methods[int(reference.row_index)] = owner
        for reference in getattr(row, "FieldList", ()) or ():
            fields[int(reference.row_index)] = owner
    return methods, fields


def method_instructions(assembly: ManagedAssembly, row: Any) -> list[Any]:
    rva = int(getattr(row, "Rva", 0) or 0)
    if rva <= 0:
        return []
    try:
        offset = int(assembly.pe.get_offset_from_rva(rva))
    except Exception as exc:
        raise ManagedMetadataError("CIL method RVAを変換できません") from exc
    data = assembly.data
    if offset < 0 or offset >= len(data):
        raise ManagedMetadataError("CIL methodが入力範囲外です")
    first = data[offset]
    if first & 3 == 2:
        header_size, code_size = 1, first >> 2
    elif first & 3 == 3 and offset + 12 <= len(data):
        flags = struct.unpack_from("<H", data, offset)[0]
        header_size = ((flags >> 12) & 0xF) * 4
        code_size = struct.unpack_from("<I", data, offset + 4)[0]
    else:
        raise ManagedMetadataError("CIL method headerが不正です")
    minimum = header_size + code_size
    if header_size < 1 or minimum > MAX_METHOD_BYTES or offset + minimum > len(data):
        raise ManagedMetadataError("CIL methodの宣言範囲が不正です")
    window = min(MAX_METHOD_BYTES, len(data) - offset)
    body = read_method_body_from_bytes(data[offset : offset + window])
    return list(getattr(body, "instructions", ()) or ())


def iter_methods(assembly: ManagedAssembly) -> Iterator[tuple[int, str, Any, list[Any]]]:
    method_owners, _ = owner_maps(assembly.pe)
    rows = getattr(assembly.pe.net.mdtables.MethodDef, "rows", ())
    for index, row in enumerate(rows, 1):
        try:
            instructions = method_instructions(assembly, row)
        except ManagedMetadataError:
            continue
        if instructions:
            yield index, method_owners.get(index, ""), row, instructions


def _constant(assembly: ManagedAssembly, instruction: Any) -> tuple[bool, Any, str]:
    name = str(getattr(getattr(instruction, "opcode", None), "name", "")).lower()
    if name == "ldstr":
        token = token_value(instruction.operand)
        try:
            return True, str(assembly.pe.net.user_strings.get(token & 0xFFFFFF)), "string"
        except Exception:
            return False, None, ""
    if name == "ldnull":
        return True, None, "null"
    if name == "ldc.i4.m1":
        return True, -1, "int32"
    if name.startswith("ldc.i4.") and name[-1:].isdigit():
        return True, int(name[-1]), "int32"
    if name in {"ldc.i4", "ldc.i4.s"}:
        return True, int(instruction.operand), "int32"
    return False, None, ""


def extract_static_assignments(data: bytes) -> dict[str, Any]:
    assembly = load_managed_assembly(data)
    _, field_owners = owner_maps(assembly.pe)
    fields = getattr(assembly.pe.net.mdtables.Field, "rows", ())
    assignments: list[dict[str, Any]] = []
    for method_index, owner, row, instructions in iter_methods(assembly):
        if str(row.Name) != ".cctor":
            continue
        pending: tuple[Any, str] | None = None
        order = 0
        for instruction in instructions:
            present, value, value_type = _constant(assembly, instruction)
            if present:
                pending = (value, value_type)
                continue
            opcode = str(instruction.opcode.name).lower()
            if opcode == "stsfld" and pending is not None:
                token = token_value(instruction.operand)
                if token >> 24 == 0x04:
                    rid = token & 0xFFFFFF
                    if 0 < rid <= len(fields):
                        order += 1
                        assignments.append(
                            {
                                "method_token": f"0x06{method_index:06x}",
                                "owner": owner,
                                "order": order,
                                "field_token": f"0x{token:08x}",
                                "field_owner": field_owners.get(rid, ""),
                                "field_name": str(fields[rid - 1].Name),
                                "value_type": pending[1],
                                "value": pending[0],
                            }
                        )
                pending = None
            elif opcode not in {"nop", "conv.i4", "conv.u4"}:
                pending = None
    return {
        "schema_version": 1,
        "analysis": "dotnet_static_field_extraction",
        "sha256": hashlib.sha256(data).hexdigest(),
        "status": "analyzed",
        "recovery": assembly.recovery,
        "assignments": assignments,
        "executed": False,
        "emulated": False,
        "network_contacted": False,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.input.resolve() == args.output.resolve():
        raise ValueError("inputとoutputには異なるパスを指定してください")
    result = extract_static_assignments(args.input.read_bytes())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps({"output": str(args.output), "assignments": len(result["assignments"])}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
