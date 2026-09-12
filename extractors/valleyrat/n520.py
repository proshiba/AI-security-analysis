"""N520型managed ValleyRATの設定を実行せずに静的復元する。

単なる ``N520`` 文字列やBase64文字列だけでは受理しない。CLR metadata、
名前非依存の ``RuntimeHelpers.InitializeArray`` 鍵初期化列、SHA-256／AES／
Base64復号APIの参照、厳密なPKCS#7 paddingをすべて検証した場合だけ設定復元を
成立させる。公開要約には生鍵、暗号文、任意の復号文字列を含めない。
"""

from __future__ import annotations

import base64
import hashlib
import re
import struct
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import dnfile
from Cryptodome.Cipher import AES
from dncil.cil.body.reader import read_method_body_from_bytes

from extractors.common import endpoint_candidates, url_candidates
from extractors.managed_pe import has_clr_metadata
from extractors.valleyrat.nvml_dat import (
    normalize_host,
    parse_endpoint,
    render_authority,
    render_endpoint,
)

MAXIMUM_INPUT_SIZE = 64 * 1024 * 1024
MAXIMUM_METHOD_COUNT = 65_536
MAXIMUM_METHOD_BODY_SIZE = 2 * 1024 * 1024
MAXIMUM_INSTRUCTIONS_PER_METHOD = 100_000
MAXIMUM_TOTAL_INSTRUCTIONS = 1_000_000
MAXIMUM_BASE64_CANDIDATES = 256
MAXIMUM_BASE64_TEXT_LENGTH = 8_192
MAXIMUM_DECODED_CANDIDATE_SIZE = 8_192
MAXIMUM_PLAINTEXT_SIZE = 4_096
MAXIMUM_DATA_FLOW_DISTANCE = 96
MINIMUM_KEY_SIZE = 8
MAXIMUM_KEY_SIZE = 64

_BASE64 = re.compile(r"[A-Za-z0-9+/]{30,}={0,2}\Z")
_SENSITIVE_PATH_SEGMENT = re.compile(
    r"(?i)(?:token|secret|password|passwd|api[_-]?key|auth)[=_:-]"
)
_OPAQUE_PATH_SEGMENT = re.compile(
    r"[A-Za-z0-9_-]{32,}(?:\.[A-Za-z0-9]{1,10})?\Z"
)


class N520ConfigError(ValueError):
    """N520設定の構造、境界または一意性を検証できない場合の例外。"""


@dataclass(frozen=True)
class N520ConfigRecovery:
    """復元済み設定から公開可能な要約だけを保持する。"""

    key_size: int
    key_sha256: str
    encrypted_candidate_count: int
    decrypted_value_count: int
    urls: tuple[str, ...]
    endpoints: tuple[str, ...]
    opaque_value_count: int
    initializer_proof: dict[str, object]
    structural_evidence: dict[str, object]

    def public_summary(self) -> dict[str, object]:
        """鍵、暗号文、任意plaintextを除外した設定要約を返す。"""

        return public_recovery_summary(self)


def public_recovery_summary(recovery: N520ConfigRecovery) -> dict[str, object]:
    """自動handlerから静的追跡できる形で公開可能な要約を構築する。"""

    return {
        "status": "decoded_static_config",
        "configuration_style": "n520_managed_aes_cbc",
        "key": {
            "size": recovery.key_size,
            "sha256": recovery.key_sha256,
            "raw_value_included": False,
        },
        "initializer_proof": recovery.initializer_proof,
        "structural_evidence": recovery.structural_evidence,
        "encrypted_candidate_count": recovery.encrypted_candidate_count,
        "decrypted_value_count": recovery.decrypted_value_count,
        "public_network_value_count": len(recovery.urls) + len(recovery.endpoints),
        "opaque_value_count": recovery.opaque_value_count,
        "urls": list(recovery.urls),
        "endpoints": list(recovery.endpoints),
        "raw_ciphertexts_included": False,
        "raw_plaintexts_included": False,
        "sample_executed": False,
        "network_contacted": False,
    }


def _rows(image: dnfile.dnPE, table_name: str) -> list[Any]:
    try:
        tables = image.net.mdtables
    except AttributeError:
        return []
    try:
        if table_name == "TypeRef":
            table = tables.TypeRef
        elif table_name == "TypeDef":
            table = tables.TypeDef
        elif table_name == "Field":
            table = tables.Field
        elif table_name == "MethodDef":
            table = tables.MethodDef
        elif table_name == "MemberRef":
            table = tables.MemberRef
        elif table_name == "FieldRva":
            table = tables.FieldRva
        else:
            raise N520ConfigError("未対応のCLR metadata tableです")
        return list(table.rows or ())
    except AttributeError:
        return []


def _operand(instruction: object) -> object:
    try:
        value = instruction.operand
    except AttributeError:
        return None
    try:
        return value.value
    except AttributeError:
        return value


def _opcode_name(instruction: object) -> str:
    try:
        return str(instruction.opcode.name)
    except AttributeError:
        return ""


def _strict_token(value: object, table: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise N520ConfigError("CIL tokenの型が不正です")
    if value <= 0 or (value & 0xFFFFFF) == 0:
        raise N520ConfigError("CIL tokenのRIDが不正です")
    if table is not None and value >> 24 != table:
        raise N520ConfigError("CIL tokenのtableが不正です")
    return value


def _row_owner(row: object) -> str:
    try:
        owner = row.Class.row
    except AttributeError:
        return ""
    try:
        namespace = str(owner.TypeNamespace)
    except AttributeError:
        namespace = ""
    try:
        name = str(owner.TypeName)
    except AttributeError:
        name = ""
    return ".".join(item for item in (namespace, name) if item)


def _token_name(image: dnfile.dnPE, value: object) -> str:
    try:
        token = _strict_token(value)
    except N520ConfigError:
        return ""
    table_names = {
        0x01: "TypeRef",
        0x02: "TypeDef",
        0x04: "Field",
        0x06: "MethodDef",
        0x0A: "MemberRef",
    }
    table_name = table_names.get(token >> 24)
    if table_name is None:
        return ""
    rows = _rows(image, table_name)
    index = token & 0xFFFFFF
    if not 1 <= index <= len(rows):
        return ""
    row = rows[index - 1]
    try:
        name = str(row.Name)
    except AttributeError:
        name = ""
    if not name:
        try:
            name = str(row.TypeName)
        except AttributeError:
            name = ""
    owner = _row_owner(row)
    return ".".join(item for item in (owner, name) if item)


def _method_instructions(
    image: dnfile.dnPE,
    data: bytes,
    row: object,
) -> list[object]:
    try:
        rva = row.Rva
    except AttributeError:
        rva = None
    if isinstance(rva, bool) or not isinstance(rva, int) or rva <= 0:
        raise N520ConfigError("managed method RVAが不正です")
    offset = image.get_offset_from_rva(rva)
    if isinstance(offset, bool) or not isinstance(offset, int) or not 0 <= offset < len(data):
        raise N520ConfigError("managed methodのfile offsetが不正です")
    window = data[offset : min(len(data), offset + MAXIMUM_METHOD_BODY_SIZE)]
    try:
        instructions = list(read_method_body_from_bytes(window).instructions)
    except Exception as exc:
        raise N520ConfigError("managed method本文を解析できません") from exc
    if len(instructions) > MAXIMUM_INSTRUCTIONS_PER_METHOD:
        raise N520ConfigError("managed methodの命令数が上限を超えています")
    return instructions


def _constant_i4(instruction: object) -> int | None:
    name = _opcode_name(instruction)
    if name == "ldc.i4.m1":
        return -1
    match = re.fullmatch(r"ldc\.i4\.([0-8])", name)
    if match:
        return int(match.group(1))
    if name in {"ldc.i4", "ldc.i4.s"}:
        value = _operand(instruction)
        if isinstance(value, int) and not isinstance(value, bool):
            return value
    return None


def _open_managed_image(data: bytes) -> dnfile.dnPE:
    if len(data) > MAXIMUM_INPUT_SIZE:
        raise N520ConfigError("入力が64 MiB上限を超えています")
    if not has_clr_metadata(data):
        raise N520ConfigError("有効なPE／CLR metadataがありません")
    try:
        image = dnfile.dnPE(data=data)
    except Exception as exc:
        raise N520ConfigError("PE／CLR metadataを解析できません") from exc
    try:
        net = image.net
    except AttributeError:
        net = None
    if net is None:
        raise N520ConfigError("CLR metadataがありません")
    methods = _rows(image, "MethodDef")
    if not methods or len(methods) > MAXIMUM_METHOD_COUNT:
        raise N520ConfigError("MethodDef件数が許容範囲外です")
    return image


def _metadata_names(image: dnfile.dnPE) -> set[str]:
    values: set[str] = set()
    for table_name in ("TypeRef", "TypeDef", "MethodDef", "MemberRef"):
        for row in _rows(image, table_name):
            try:
                name = str(row.Name).strip()
            except AttributeError:
                name = ""
            try:
                type_name = str(row.TypeName).strip()
            except AttributeError:
                type_name = ""
            if name:
                values.add(name.casefold())
            if type_name:
                values.add(type_name.casefold())
    return values


def _structural_evidence_from_image(image: dnfile.dnPE) -> dict[str, object]:
    methods = _rows(image, "MethodDef")
    get_key_name_hint_count = 0
    for row in methods:
        try:
            if str(row.Name) == "GetConfigKey":
                get_key_name_hint_count += 1
        except AttributeError:
            continue
    names = _metadata_names(image)
    groups = {
        "runtime_array_initializer": any("initializearray" in item for item in names),
        "base64_decoder": any("frombase64string" in item for item in names),
        "sha256_key_derivation": any("sha256" in item or "computehash" in item for item in names),
        "aes_cbc_decryptor": (
            any("aes" in item or "rijndael" in item for item in names)
            and any("createdecryptor" in item or "transformfinalblock" in item for item in names)
        ),
    }
    matched = bool(all(groups.values()))
    return {
        "matched": matched,
        "managed_metadata_validated": True,
        "get_config_key_name_hint_count": get_key_name_hint_count,
        "key_method_name_required": False,
        "key_method_identification": "validated_cil_initializer_data_flow",
        "crypto_api_groups": groups,
        "required_crypto_group_count": len(groups),
        "matched_crypto_group_count": sum(groups.values()),
        "sample_executed": False,
        "network_contacted": False,
    }


def structural_evidence(data: bytes) -> dict[str, object]:
    """N520設定復元を開始できるmanaged code構造か判定する。"""

    try:
        image = _open_managed_image(data)
        return _structural_evidence_from_image(image)
    except N520ConfigError as exc:
        return {
            "matched": False,
            "managed_metadata_validated": False,
            "reason": str(exc),
            "sample_executed": False,
            "network_contacted": False,
        }


def _field_rva(image: dnfile.dnPE, field_index: int) -> int:
    matches: list[int] = []
    for row in _rows(image, "FieldRva"):
        try:
            referenced = int(row.Field.row_index)
            rva = int(row.Rva)
        except (AttributeError, TypeError, ValueError):
            continue
        if referenced == field_index and rva > 0:
            matches.append(rva)
    if len(set(matches)) != 1:
        raise N520ConfigError("key initializer backing fieldのRVAが一意ではありません")
    return matches[0]


def _contains_opcode_sequence(instructions: list[object], expected: tuple[str, ...]) -> bool:
    """CIL opcodeの短い連続列を境界内で検索する。"""

    names = [_opcode_name(item) for item in instructions]
    width = len(expected)
    return any(tuple(names[index : index + width]) == expected for index in range(len(names) - width + 1))


def _int32_to_byte_conversion_validated(
    image: dnfile.dnPE,
    instructions: list[object],
) -> bool:
    """Int32初期化配列をconv.u1でbyte配列へ移すloopを厳密に検証する。"""

    byte_array_present = any(
        _opcode_name(item) == "newarr"
        and _token_name(image, _operand(item)).casefold().endswith((".byte", "byte"))
        for item in instructions
    )
    copy_loop_present = _contains_opcode_sequence(
        instructions,
        (
            "ldloc.1",
            "ldloc.2",
            "ldloc.0",
            "ldloc.2",
            "ldelem.i4",
            "conv.u1",
            "stelem.i1",
        ),
    )
    increment_present = _contains_opcode_sequence(
        instructions,
        ("ldloc.2", "ldc.i4.1", "add", "stloc.2"),
    )
    bound_check_present = _contains_opcode_sequence(
        instructions,
        ("ldloc.2", "ldloc.0", "ldlen", "conv.i4", "blt.s"),
    ) or _contains_opcode_sequence(
        instructions,
        ("ldloc.2", "ldloc.0", "ldlen", "conv.i4", "blt"),
    )
    return bool(
        byte_array_present
        and copy_loop_present
        and increment_present
        and bound_check_present
    )


def _recover_key(
    image: dnfile.dnPE,
    data: bytes,
    *,
    method_bodies: dict[int, list[object]] | None = None,
) -> tuple[bytes, dict[str, object]]:
    bodies = method_bodies if method_bodies is not None else _method_bodies(image, data)
    method_tokens = _key_initializer_method_tokens(image, bodies)
    if len(method_tokens) != 1:
        raise N520ConfigError("key initializer列を持つmethodが一意ではありません")
    instructions = bodies[next(iter(method_tokens))]
    if not any(
        _opcode_name(item) == "ret"
        for item in instructions
    ):
        raise N520ConfigError("key initializer methodにretがありません")
    candidates: set[tuple[int, int, str]] = set()
    for index, instruction in enumerate(instructions):
        opcode = _opcode_name(instruction)
        if opcode != "newarr" or index == 0:
            continue
        length = _constant_i4(instructions[index - 1])
        type_name = _token_name(image, _operand(instruction)).casefold()
        if length is None or not MINIMUM_KEY_SIZE <= length <= MAXIMUM_KEY_SIZE:
            continue
        if type_name.endswith((".int32", "int32")):
            if not _int32_to_byte_conversion_validated(image, instructions):
                continue
            representation = "System.Int32_to_Byte_conv_u1"
        elif type_name.endswith((".byte", "byte")):
            representation = "System.Byte"
        else:
            continue
        tail = instructions[index + 1 : index + 9]
        for relative, item in enumerate(tail):
            item_opcode = _opcode_name(item)
            if item_opcode != "ldtoken":
                continue
            try:
                field_token = _strict_token(_operand(item), 0x04)
            except N520ConfigError:
                continue
            following = tail[relative + 1 : relative + 5]
            if not any(
                _opcode_name(candidate) in {"call", "callvirt"}
                and _token_name(image, _operand(candidate)).casefold().endswith(
                    "initializearray"
                )
                for candidate in following
            ):
                continue
            candidates.add((length, field_token & 0xFFFFFF, representation))
    if len(candidates) != 1:
        raise N520ConfigError("key initializer列を一意に検証できません")
    length, field_index, representation = next(iter(candidates))
    rva = _field_rva(image, field_index)
    offset = image.get_offset_from_rva(rva)
    required = length * 4 if representation.startswith("System.Int32") else length
    if (
        isinstance(offset, bool)
        or not isinstance(offset, int)
        or offset < 0
        or required > len(data) - offset
    ):
        raise N520ConfigError("key initializer backing fieldがfile境界を超えています")
    if representation.startswith("System.Int32"):
        integers = struct.unpack_from(f"<{length}I", data, offset)
        if any(value > 0xFF for value in integers):
            raise N520ConfigError("key initializer backing fieldの上位24 bitが未対応です")
        key = bytes(integers)
    else:
        key = data[offset : offset + length]
    if len(set(key)) < 2:
        raise N520ConfigError("key initializerが退化した値です")
    return key, {
        "method_identification": "validated_cil_initializer_data_flow",
        "method_name_required": False,
        "source_array_type": representation,
        "returned_array_type": "System.Byte",
        "int32_to_byte_conversion_validated": representation.startswith("System.Int32"),
        "initializer": "RuntimeHelpers.InitializeArray",
        "field_rva_present": True,
        "key_size": len(key),
        "raw_key_included": False,
    }


def _user_string(image: dnfile.dnPE, value: object) -> str:
    token = _strict_token(value, 0x70)
    try:
        text = image.net.user_strings.get(token & 0xFFFFFF).value
    except Exception as exc:
        raise N520ConfigError("managed user stringを取得できません") from exc
    if not isinstance(text, str) or len(text) > MAXIMUM_BASE64_TEXT_LENGTH:
        raise N520ConfigError("managed user stringの長さが上限外です")
    return text


def _local_slot(instruction: object, operation: str) -> int | None:
    """短縮形を含むlocal load/storeからslot番号を取得する。"""

    name = _opcode_name(instruction)
    compact = re.fullmatch(rf"{operation}\.([0-3])", name)
    if compact:
        return int(compact.group(1))
    if name not in {operation, f"{operation}.s"}:
        return None
    value = _operand(instruction)
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    match = re.search(r"0x([0-9a-fA-F]+)", str(value))
    return int(match.group(1), 16) if match else None


def _previous_instruction(instructions: list[object], index: int) -> tuple[int, object] | None:
    for position in range(index - 1, -1, -1):
        if _opcode_name(instructions[position]) != "nop":
            return position, instructions[position]
    return None


def _next_instruction(instructions: list[object], index: int) -> tuple[int, object] | None:
    for position in range(index + 1, len(instructions)):
        if _opcode_name(instructions[position]) != "nop":
            return position, instructions[position]
    return None


def _method_bodies(image: dnfile.dnPE, data: bytes) -> dict[int, list[object]]:
    """全MethodDefをtoken付きで一度だけ読み、総命令数を制限する。"""

    bodies: dict[int, list[object]] = {}
    instruction_total = 0
    for rid, row in enumerate(_rows(image, "MethodDef"), 1):
        if not hasattr(row, "Rva") or not row.Rva:
            continue
        try:
            instructions = _method_instructions(image, data, row)
        except N520ConfigError:
            continue
        instruction_total += len(instructions)
        if instruction_total > MAXIMUM_TOTAL_INSTRUCTIONS:
            raise N520ConfigError("managed命令の総数が上限を超えています")
        bodies[0x06000000 | rid] = instructions
    return bodies


def _key_initializer_method_tokens(
    image: dnfile.dnPE,
    bodies: dict[int, list[object]],
) -> set[int]:
    """名前ではなくInitializeArrayと変換loopで鍵生成methodを識別する。"""

    matched: set[int] = set()
    for method_token, instructions in bodies.items():
        initializer_count = 0
        for index, instruction in enumerate(instructions):
            if _opcode_name(instruction) != "newarr" or index == 0:
                continue
            length = _constant_i4(instructions[index - 1])
            type_name = _token_name(image, _operand(instruction)).casefold()
            if length is None or not MINIMUM_KEY_SIZE <= length <= MAXIMUM_KEY_SIZE:
                continue
            if type_name.endswith((".int32", "int32")):
                if not _int32_to_byte_conversion_validated(image, instructions):
                    continue
            elif not type_name.endswith((".byte", "byte")):
                continue
            tail = instructions[index + 1 : index + 9]
            initializer_found = False
            for offset, item in enumerate(tail):
                if _opcode_name(item) != "ldtoken":
                    continue
                try:
                    _strict_token(_operand(item), 0x04)
                except N520ConfigError:
                    continue
                if any(
                    _opcode_name(call) in {"call", "callvirt"}
                    and _token_name(image, _operand(call)).casefold().endswith(
                        "initializearray"
                    )
                    for call in tail[offset + 1 : offset + 5]
                ):
                    initializer_found = True
                    break
            if initializer_found:
                initializer_count += 1
        if initializer_count == 1 and any(
            _opcode_name(item) == "ret" for item in instructions
        ):
            matched.add(method_token)
    return matched


def _call_records(
    image: dnfile.dnPE,
    instructions: list[object],
) -> list[tuple[int, int, str]]:
    records: list[tuple[int, int, str]] = []
    for index, instruction in enumerate(instructions):
        if _opcode_name(instruction) not in {"call", "callvirt"}:
            continue
        try:
            token = _strict_token(_operand(instruction))
        except N520ConfigError:
            continue
        records.append((index, token, _token_name(image, token).casefold()))
    return records


def _ordered_decrypt_calls(
    records: list[tuple[int, int, str]],
    key_tokens: set[int],
) -> list[tuple[int, int, str]] | None:
    expected = (
        ".aes.create",
        ".sha256.create",
        None,
        ".computehash",
        ".set_key",
        ".set_iv",
        ".createdecryptor",
        ".transformfinalblock",
        ".get_utf8",
        ".getstring",
    )
    for start in range(len(records)):
        selected: list[tuple[int, int, str]] = []
        cursor = start
        for pattern in expected:
            while cursor < len(records):
                record = records[cursor]
                if (pattern is None and record[1] in key_tokens) or (
                    pattern is not None and record[2].endswith(pattern)
                ):
                    selected.append(record)
                    cursor += 1
                    break
                cursor += 1
            else:
                break
        if len(selected) != len(expected):
            continue
        key_position = records.index(selected[2])
        if (
            key_position + 2 < len(records)
            and records[key_position + 1] == selected[3]
            and records[key_position + 2] == selected[4]
        ):
            return selected
    return None


def _decrypt_method_tokens(
    image: dnfile.dnPE,
    bodies: dict[int, list[object]],
    key_tokens: set[int],
) -> set[int]:
    """鍵導出からUTF-8復号までが同一methodにある復号器だけを返す。"""

    matched: set[int] = set()
    for method_token, instructions in bodies.items():
        selected = _ordered_decrypt_calls(_call_records(image, instructions), key_tokens)
        if selected is None:
            continue
        after_key = _next_instruction(instructions, selected[2][0])
        after_hash = (
            _next_instruction(instructions, after_key[0])
            if after_key is not None
            else None
        )
        if (
            after_key is None
            or after_hash is None
            or after_key[0] != selected[3][0]
            or after_hash[0] != selected[4][0]
        ):
            continue
        create_index = selected[6][0]
        transform_index = selected[7][0]
        get_string_index = selected[9][0]
        decryptor_store = _next_instruction(instructions, create_index)
        after_transform = _next_instruction(instructions, transform_index)
        before_get_string = _previous_instruction(instructions, get_string_index)
        if (
            decryptor_store is None
            or after_transform is None
            or before_get_string is None
        ):
            continue
        decryptor_slot = _local_slot(decryptor_store[1], "stloc")
        result_slot = _local_slot(after_transform[1], "stloc")
        if (
            decryptor_slot is None
            or result_slot is None
            or _local_slot(before_get_string[1], "ldloc") != result_slot
            or not any(
                _local_slot(item, "ldloc") == decryptor_slot
                for item in instructions[decryptor_store[0] + 1 : transform_index]
            )
            or not _local_unchanged(
                instructions,
                decryptor_slot,
                decryptor_store[0] + 1,
                transform_index,
            )
        ):
            continue
        if not any(
            _loads_argument_zero(item)
            for item in instructions[max(0, transform_index - 12) : transform_index]
        ):
            continue
        matched.add(method_token)
    return matched


def _loads_argument_zero(instruction: object) -> bool:
    if _opcode_name(instruction) == "ldarg.0":
        return True
    if _opcode_name(instruction) not in {"ldarg", "ldarg.s"}:
        return False
    value = _operand(instruction)
    return isinstance(value, int) and not isinstance(value, bool) and value == 0


def _local_unchanged(
    instructions: list[object],
    slot: int,
    start: int,
    stop: int,
) -> bool:
    return all(
        _local_slot(item, "stloc") != slot for item in instructions[start:stop]
    )


def _cloud_reader_method_tokens(
    image: dnfile.dnPE,
    bodies: dict[int, list[object]],
    decrypt_tokens: set[int],
) -> set[int]:
    """Base64(arg0)→AES→HTTP取得のlocal def-useが成立するmethodを返す。"""

    fetch_apis = (
        ".getbytearrayasync",
        ".getstringasync",
        ".downloaddata",
        ".downloadstring",
    )
    matched: set[int] = set()
    for method_token, instructions in bodies.items():
        records = _call_records(image, instructions)
        for call_index, _, name in records:
            if not name.endswith(".frombase64string"):
                continue
            before = _previous_instruction(instructions, call_index)
            after = _next_instruction(instructions, call_index)
            if before is None or after is None or not _loads_argument_zero(before[1]):
                continue
            decoded_slot = _local_slot(after[1], "stloc")
            if decoded_slot is None:
                continue
            for decrypt_index, decrypt_token, _ in records:
                if decrypt_token not in decrypt_tokens or not call_index < decrypt_index:
                    continue
                if decrypt_index - call_index > MAXIMUM_DATA_FLOW_DISTANCE:
                    continue
                source = _previous_instruction(instructions, decrypt_index)
                if source is None or _local_slot(source[1], "ldloc") != decoded_slot:
                    continue
                if not _local_unchanged(
                    instructions, decoded_slot, after[0] + 1, decrypt_index
                ):
                    continue
                plain_store = _next_instruction(instructions, decrypt_index)
                if plain_store is None:
                    continue
                plain_slot = _local_slot(plain_store[1], "stloc")
                if plain_slot is None:
                    continue
                for fetch_index, _, fetch_name in records:
                    if not decrypt_index < fetch_index:
                        continue
                    if fetch_index - decrypt_index > MAXIMUM_DATA_FLOW_DISTANCE:
                        continue
                    argument = _previous_instruction(instructions, fetch_index)
                    if argument is None or _local_slot(argument[1], "ldloc") != plain_slot:
                        continue
                    if fetch_name.endswith(fetch_apis) and _local_unchanged(
                        instructions, plain_slot, plain_store[0] + 1, fetch_index
                    ):
                        matched.add(method_token)
    return matched


def _static_field_source(
    instructions: list[object],
    call_index: int,
) -> int | None:
    """call引数の直近defを遡り、static field tokenだけを受理する。"""

    previous = _previous_instruction(instructions, call_index)
    if previous is None:
        return None
    _, source = previous
    if _opcode_name(source) == "ldsfld":
        try:
            return _strict_token(_operand(source), 0x04)
        except N520ConfigError:
            return None
    slot = _local_slot(source, "ldloc")
    if slot is None:
        return None
    lower = max(-1, previous[0] - MAXIMUM_DATA_FLOW_DISTANCE)
    for index in range(previous[0] - 1, lower, -1):
        if _local_slot(instructions[index], "stloc") != slot:
            continue
        definition = _previous_instruction(instructions, index)
        if definition is None or _opcode_name(definition[1]) != "ldsfld":
            return None
        try:
            return _strict_token(_operand(definition[1]), 0x04)
        except N520ConfigError:
            return None
    return None


def _validated_base64(value: str) -> bool:
    if len(value) % 4 or _BASE64.fullmatch(value) is None:
        return False
    try:
        decoded = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeError, ValueError):
        return False
    return 32 <= len(decoded) <= MAXIMUM_DECODED_CANDIDATE_SIZE


def _base64_values(
    image: dnfile.dnPE,
    data: bytes,
    *,
    method_bodies: dict[int, list[object]] | None = None,
) -> list[str]:
    """cloud設定経路へ一意に結び付く暗号文だけを返す。"""

    bodies = method_bodies if method_bodies is not None else _method_bodies(image, data)
    key_tokens = _key_initializer_method_tokens(image, bodies)
    decrypt_tokens = _decrypt_method_tokens(image, bodies, key_tokens)
    reader_tokens = _cloud_reader_method_tokens(image, bodies, decrypt_tokens)
    if (
        len(key_tokens) != 1
        or len(decrypt_tokens) != 1
        or len(reader_tokens) != 1
    ):
        raise N520ConfigError("N520暗号文へのCIL call graphを検証できません")

    linked_fields: set[int] = set()
    for method_token, instructions in bodies.items():
        for index, instruction in enumerate(instructions):
            if _opcode_name(instruction) not in {"call", "callvirt"}:
                continue
            try:
                target = _strict_token(_operand(instruction), 0x06)
            except N520ConfigError:
                continue
            if target not in reader_tokens:
                continue
            field_token = _static_field_source(instructions, index)
            if field_token is not None:
                linked_fields.add(field_token)
    if len(linked_fields) != 1:
        raise N520ConfigError("cloud readerへ渡るstatic fieldが一意ではありません")
    linked_field = next(iter(linked_fields))

    writes: list[object] = []
    for method_token, instructions in bodies.items():
        for index, instruction in enumerate(instructions):
            if _opcode_name(instruction) != "stsfld":
                continue
            try:
                target = _strict_token(_operand(instruction), 0x04)
            except N520ConfigError:
                continue
            if target != linked_field:
                continue
            source = _previous_instruction(instructions, index)
            is_type_initializer = _token_name(image, method_token).casefold().endswith(
                ".cctor"
            )
            writes.append(source[1] if source is not None and is_type_initializer else None)
    if len(writes) != 1 or _opcode_name(writes[0]) != "ldstr":
        raise N520ConfigError("cloud設定static fieldの書き込みが競合または不明です")
    try:
        value = _user_string(image, _operand(writes[0]))
    except N520ConfigError as exc:
        raise N520ConfigError("cloud設定暗号文を取得できません") from exc
    if not _validated_base64(value):
        raise N520ConfigError("cloud設定暗号文のBase64構造が不正です")
    if MAXIMUM_BASE64_CANDIDATES < 1:
        raise N520ConfigError("Base64設定候補数が上限を超えています")
    return [value]


def _pkcs7_unpad(value: bytes) -> bytes:
    if not value or len(value) % AES.block_size:
        raise N520ConfigError("AES plaintextのblock長が不正です")
    width = value[-1]
    if not 1 <= width <= AES.block_size or value[-width:] != bytes([width]) * width:
        raise N520ConfigError("AES plaintextのPKCS#7 paddingが不正です")
    return value[:-width]


def _decrypt_value(encoded: str, key: bytes) -> str:
    try:
        value = base64.b64decode(encoded.encode("ascii"), validate=True)
    except (UnicodeError, ValueError) as exc:
        raise N520ConfigError("Base64設定候補が不正です") from exc
    if len(value) < 32 or len(value) > MAXIMUM_DECODED_CANDIDATE_SIZE or len(value) % AES.block_size:
        raise N520ConfigError("N520 AES暗号文の長さが不正です")
    derived = hashlib.sha256(key).digest()
    plaintext = _pkcs7_unpad(
        AES.new(derived, AES.MODE_CBC, value[: AES.block_size]).decrypt(
            value[AES.block_size :]
        )
    )
    if not plaintext or len(plaintext) > MAXIMUM_PLAINTEXT_SIZE:
        raise N520ConfigError("N520復号値の長さが上限外です")
    try:
        text = plaintext.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise N520ConfigError("N520復号値がUTF-8ではありません") from exc
    if any(ord(char) < 0x20 and char not in "\t\r\n" for char in text):
        raise N520ConfigError("N520復号値に制御文字があります")
    return text


def _sanitize_path(path: str) -> str:
    segments = []
    for raw in path.split("/"):
        if (
            "%" in raw
            or _SENSITIVE_PATH_SEGMENT.search(raw)
            or _OPAQUE_PATH_SEGMENT.fullmatch(raw)
        ):
            segments.append("[REDACTED]")
        else:
            segments.append(raw[:128])
    return "/".join(segments)[:512]


def _public_url(value: str) -> str | None:
    try:
        parsed = urlsplit(value.rstrip(".,;)'\"]}>"))
        host = normalize_host(parsed.hostname or "")
        port = parsed.port
    except ValueError:
        return None
    if parsed.scheme.casefold() not in {"http", "https", "ftp"} or host is None:
        return None
    if port is not None and not 1 <= port <= 65535:
        return None
    authority = render_authority(host, port)
    if authority is None:
        return None
    return urlunsplit(
        (
            parsed.scheme.casefold(),
            authority,
            _sanitize_path(parsed.path),
            "",
            "",
        )
    )


def _public_network_values(values: list[str]) -> tuple[tuple[str, ...], tuple[str, ...], int]:
    urls: set[str] = set()
    endpoints: set[str] = set()
    opaque = 0
    for value in values:
        value_urls = {
            public
            for candidate in url_candidates([value])
            if (public := _public_url(candidate)) is not None
        }
        value_endpoints = set(endpoint_candidates([value]))
        parsed_endpoint = parse_endpoint(value.strip())
        if parsed_endpoint is not None:
            rendered_endpoint = render_endpoint(*parsed_endpoint)
            if rendered_endpoint is not None:
                value_endpoints.add(rendered_endpoint)
        urls.update(value_urls)
        endpoints.update(value_endpoints)
        if not value_urls and not value_endpoints:
            opaque += 1
    return tuple(sorted(urls)), tuple(sorted(endpoints)), opaque


def recover_config(data: bytes) -> N520ConfigRecovery:
    """managed PEからN520設定を厳密に復元する。"""

    image = _open_managed_image(data)
    evidence = _structural_evidence_from_image(image)
    if evidence["matched"] is not True:
        raise N520ConfigError("N520の独立したmanaged構造が一致しません")
    method_bodies = _method_bodies(image, data)
    key, initializer = _recover_key(image, data, method_bodies=method_bodies)
    candidates = _base64_values(image, data, method_bodies=method_bodies)
    if not candidates:
        raise N520ConfigError("N520 AES設定候補がありません")
    decrypted: dict[str, str] = {}
    for candidate in candidates:
        try:
            plaintext = _decrypt_value(candidate, key)
        except N520ConfigError:
            continue
        decrypted[hashlib.sha256(plaintext.encode("utf-8")).hexdigest()] = plaintext
    if not decrypted:
        raise N520ConfigError("N520 AES設定を1件も検証できません")
    values = [decrypted[digest] for digest in sorted(decrypted)]
    urls, endpoints, opaque = _public_network_values(values)
    return N520ConfigRecovery(
        key_size=len(key),
        key_sha256=hashlib.sha256(key).hexdigest(),
        encrypted_candidate_count=len(candidates),
        decrypted_value_count=len(values),
        urls=urls,
        endpoints=endpoints,
        opaque_value_count=opaque,
        initializer_proof=initializer,
        structural_evidence=evidence,
    )


def probe_config(data: bytes) -> dict[str, object]:
    """完全なN520設定復号に成功した場合だけfamily帰属証拠を返す。

    detectorから利用する軽量契約であり、生鍵、暗号文、復号文字列、endpointは
    返さない。managed構造だけ一致しても復号が完了しなければfail-closedにする。
    """

    unmatched: dict[str, object] = {
        "matched": False,
        "family": None,
        "variant": None,
        "supports_family_attribution": False,
        "static_config_recovered": False,
        "evidence": {},
        "config": {},
        "sample_executed": False,
        "network_contacted": False,
    }
    if not isinstance(data, bytes) or len(data) > MAXIMUM_INPUT_SIZE:
        return unmatched
    try:
        recovery = recover_config(data)
    except N520ConfigError:
        return unmatched
    public_network_value_count = len(recovery.urls) + len(recovery.endpoints)
    if recovery.decrypted_value_count < 1 or public_network_value_count < 1:
        return unmatched
    return {
        "matched": True,
        "family": "valleyrat",
        "variant": "single_pe_n520_managed",
        "supports_family_attribution": True,
        "attribution_scope": "validated_terminal_component_structure",
        "classification_confidence": "high_structural_decoded_config",
        "static_config_recovered": True,
        "evidence": {
            "managed_structure": recovery.structural_evidence,
            "initializer": recovery.initializer_proof,
            "aes_cbc_pkcs7_validated": True,
        },
        "config": {
            "decrypted_value_count": recovery.decrypted_value_count,
            "public_network_value_count": public_network_value_count,
            "opaque_value_count": recovery.opaque_value_count,
            "raw_key_included": False,
            "raw_ciphertexts_included": False,
            "raw_plaintexts_included": False,
            "raw_network_values_included": False,
        },
        "sample_executed": False,
        "network_contacted": False,
    }


__all__ = [
    "MAXIMUM_BASE64_CANDIDATES",
    "MAXIMUM_INPUT_SIZE",
    "N520ConfigError",
    "N520ConfigRecovery",
    "probe_config",
    "public_recovery_summary",
    "recover_config",
    "structural_evidence",
]
