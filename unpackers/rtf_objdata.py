"""RTF ``objdata`` からOLE1 native dataを実行せず復元する。"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

MAX_RTF_BYTES = 32 * 1024 * 1024
MAX_GROUP_DEPTH = 256
MAX_OBJDATA_GROUPS = 32
MAX_OBJDATA_HEX_CHARS = 32 * 1024 * 1024
MAX_NATIVE_BYTES = 16 * 1024 * 1024
MAX_OLE1_STRING_BYTES = 4096
MIN_OBJDATA_BYTES = 32


class RtfObjdataError(ValueError):
    """RTF構造またはOLE1境界を一意に検証できない場合の例外。"""


@dataclass(frozen=True)
class _Control:
    word: bytes | None
    parameter: int | None
    end: int


def _parse_control(data: bytes, offset: int) -> _Control:
    """backslash位置からRTF control word／symbolを有界に読む。"""

    if offset >= len(data) or data[offset] != 0x5C:
        raise RtfObjdataError("control wordの開始位置が不正です")
    cursor = offset + 1
    if cursor >= len(data):
        raise RtfObjdataError("末尾のbackslashは許可しません")
    first = data[cursor]
    if not (65 <= first <= 90 or 97 <= first <= 122):
        if first == 0x27:
            if cursor + 2 >= len(data):
                raise RtfObjdataError("短いhex escapeです")
            try:
                int(data[cursor + 1 : cursor + 3], 16)
            except ValueError as exc:
                raise RtfObjdataError("不正なhex escapeです") from exc
            return _Control(None, None, cursor + 3)
        return _Control(None, None, cursor + 1)

    word_start = cursor
    while cursor < len(data) and (
        65 <= data[cursor] <= 90 or 97 <= data[cursor] <= 122
    ):
        cursor += 1
    word = data[word_start:cursor].lower()
    sign = 1
    if cursor < len(data) and data[cursor] == 0x2D:
        sign = -1
        cursor += 1
    number_start = cursor
    while cursor < len(data) and 48 <= data[cursor] <= 57:
        cursor += 1
    parameter = None
    if cursor > number_start:
        digits = data[number_start:cursor]
        if len(digits) <= 18:
            parameter = sign * int(digits)
    if cursor < len(data) and data[cursor] == 0x20:
        cursor += 1
    if word == b"bin":
        if parameter is None or parameter < 0:
            raise RtfObjdataError("不正なbin長です")
        cursor += parameter
        if cursor > len(data):
            raise RtfObjdataError("bin dataがRTF境界を越えています")
    return _Control(word, parameter, cursor)


def _group_ranges(data: bytes) -> dict[int, int]:
    """escapeとbin dataを除外してRTF groupの対応を検証する。"""

    stack: list[int] = []
    ranges: dict[int, int] = {}
    cursor = 0
    while cursor < len(data):
        value = data[cursor]
        if value == 0x5C:
            cursor = _parse_control(data, cursor).end
            continue
        if value == 0x7B:
            stack.append(cursor)
            if len(stack) > MAX_GROUP_DEPTH:
                raise RtfObjdataError("RTF group depth上限を超えました")
        elif value == 0x7D:
            if not stack:
                trailing = data[cursor:]
                if trailing.count(b"}") <= 4 and not trailing.translate(
                    None, b"} \t\r\n\f"
                ):
                    break
                raise RtfObjdataError("対応しないRTF closing braceです")
            ranges[stack.pop()] = cursor
        cursor += 1
    if stack:
        raise RtfObjdataError("閉じていないRTF groupがあります")
    return ranges


def _objdata_groups(data: bytes, ranges: dict[int, int]) -> list[tuple[int, int, int]]:
    """objdata control wordを含むgroupとpayload開始位置を列挙する。"""

    stack: list[int] = []
    found: list[tuple[int, int, int]] = []
    cursor = 0
    while cursor < len(data):
        value = data[cursor]
        if value == 0x7B:
            stack.append(cursor)
            cursor += 1
            continue
        if value == 0x7D:
            if stack:
                stack.pop()
            cursor += 1
            continue
        if value == 0x5C:
            control = _parse_control(data, cursor)
            if control.word == b"objdata":
                if not stack:
                    raise RtfObjdataError("group外のobjdataです")
                start = stack[-1]
                found.append((start, ranges[start], control.end))
                if len(found) > MAX_OBJDATA_GROUPS:
                    raise RtfObjdataError("objdata件数上限を超えました")
            cursor = control.end
            continue
        cursor += 1
    starts = [item[0] for item in found]
    if len(starts) != len(set(starts)):
        raise RtfObjdataError("同一groupに複数のobjdataがあります")
    return found


def _decode_objdata_hex(data: bytes, start: int, end: int) -> bytes:
    """objdata group直下のhex textだけを復号し、nested junkを除外する。"""

    digits = bytearray()
    depth = 0
    cursor = start
    while cursor < end:
        value = data[cursor]
        if value == 0x5C:
            cursor = _parse_control(data, cursor).end
            continue
        if value == 0x7B:
            depth += 1
            if depth > MAX_GROUP_DEPTH:
                raise RtfObjdataError("objdata nested depth上限を超えました")
            cursor += 1
            continue
        if value == 0x7D:
            if depth <= 0:
                break
            depth -= 1
            cursor += 1
            continue
        if depth == 0:
            if 48 <= value <= 57 or 65 <= value <= 70 or 97 <= value <= 102:
                digits.append(value)
                if len(digits) > MAX_OBJDATA_HEX_CHARS:
                    raise RtfObjdataError("objdata hex上限を超えました")
            elif value not in b" \t\r\n\f":
                raise RtfObjdataError("objdata直下にhex以外のtextがあります")
        cursor += 1
    if len(digits) < MIN_OBJDATA_BYTES * 2 or len(digits) % 2:
        raise RtfObjdataError(f"objdata hex長が不正です: {len(digits)}")
    try:
        decoded = bytes.fromhex(digits.decode("ascii"))
    except ValueError as exc:
        raise RtfObjdataError("objdata hexを復号できません") from exc
    if len(decoded) > MAX_NATIVE_BYTES:
        raise RtfObjdataError("objdata復号size上限を超えました")
    return decoded


def _read_u32(data: bytes, offset: int) -> tuple[int, int]:
    if offset + 4 > len(data):
        raise RtfObjdataError("OLE1 headerが途中で終わっています")
    return struct.unpack_from("<I", data, offset)[0], offset + 4


def _read_ole1_string(data: bytes, offset: int) -> tuple[str, int]:
    length, offset = _read_u32(data, offset)
    if length > MAX_OLE1_STRING_BYTES or offset + length > len(data):
        raise RtfObjdataError("OLE1 string長が不正です")
    raw = data[offset : offset + length]
    if raw and raw[-1] != 0:
        raise RtfObjdataError("OLE1 stringがNUL終端ではありません")
    value = raw[:-1].decode("latin-1") if raw else ""
    if any(ord(character) < 0x20 or ord(character) > 0x7E for character in value):
        raise RtfObjdataError("OLE1 stringに非printable byteがあります")
    return value, offset + length


def _parse_ole1(decoded: bytes) -> tuple[dict[str, object], bytes]:
    """OLE1 embedded object headerを検証しnative dataを返す。"""

    version, cursor = _read_u32(decoded, 0)
    format_id, cursor = _read_u32(decoded, cursor)
    if version != 0x00000501 or format_id != 2:
        raise RtfObjdataError("OLE1 embedded object headerではありません")
    class_name, cursor = _read_ole1_string(decoded, cursor)
    topic_name, cursor = _read_ole1_string(decoded, cursor)
    item_name, cursor = _read_ole1_string(decoded, cursor)
    native_size, cursor = _read_u32(decoded, cursor)
    if not 0 < native_size <= MAX_NATIVE_BYTES or cursor + native_size > len(decoded):
        raise RtfObjdataError("OLE1 native data長が不正です")
    native = decoded[cursor : cursor + native_size]
    return {
        "ole_version": version,
        "format_id": format_id,
        "class_name": class_name,
        "topic_name_present": bool(topic_name),
        "item_name_present": bool(item_name),
        "decoded_size": len(decoded),
        "native_size": len(native),
        "native_sha256": hashlib.sha256(native).hexdigest(),
    }, native


def _read_cstring(data: bytes, offset: int) -> tuple[bytes, int]:
    end = data.find(b"\x00", offset, min(len(data), offset + MAX_OLE1_STRING_BYTES + 1))
    if end < 0:
        raise RtfObjdataError("Ole10Native stringがNUL終端ではありません")
    return data[offset:end], end + 1


def _parse_ole10native(native: bytes) -> tuple[dict[str, object], bytes]:
    """Package classのOle10Native境界を検証して内包dataを返す。"""

    if len(native) < 2 or struct.unpack_from("<H", native, 0)[0] != 2:
        raise RtfObjdataError("Ole10Native headerではありません")
    label, cursor = _read_cstring(native, 2)
    _source_path, cursor = _read_cstring(native, cursor)
    if cursor + 8 > len(native):
        raise RtfObjdataError("Ole10Native metadataが途中で終わっています")
    cursor += 4
    temp_path_length = struct.unpack_from("<I", native, cursor)[0]
    cursor += 4
    if (
        temp_path_length > MAX_OLE1_STRING_BYTES
        or cursor + temp_path_length + 4 > len(native)
    ):
        raise RtfObjdataError("Ole10Native temp path長が不正です")
    temp_path = native[cursor : cursor + temp_path_length]
    if temp_path and temp_path[-1] != 0:
        raise RtfObjdataError("Ole10Native temp pathがNUL終端ではありません")
    cursor += temp_path_length
    payload_size = struct.unpack_from("<I", native, cursor)[0]
    cursor += 4
    if not 0 < payload_size <= MAX_NATIVE_BYTES or cursor + payload_size > len(native):
        raise RtfObjdataError("Ole10Native payload長が不正です")
    payload = native[cursor : cursor + payload_size]
    label_text = label.decode("latin-1", errors="strict")
    declared_extension = ""
    dot = label_text.rfind(".")
    if dot >= 0 and 1 <= len(label_text) - dot - 1 <= 16:
        suffix = label_text[dot:].lower()
        if all(character.isalnum() or character in "._-" for character in suffix):
            declared_extension = suffix
    return {
        "package_payload_size": len(payload),
        "package_payload_sha256": hashlib.sha256(payload).hexdigest(),
        "declared_extension": declared_extension,
        "trailing_metadata_present": cursor + payload_size < len(native),
    }, payload


def recover_rtf_objdata(
    data: bytes,
) -> tuple[dict[str, object], list[tuple[str, bytes]]]:
    """強いRTF／OLE1構造を満たす一意なnative dataだけを復元する。"""

    base: dict[str, object] = {
        "executed": False,
        "network_contacted": False,
    }
    if not data[:256].lstrip().lower().startswith(b"{\\rtf"):
        return {**base, "status": "not_rtf"}, []
    if len(data) > MAX_RTF_BYTES:
        return {**base, "status": "input_size_blocked", "size": len(data)}, []
    try:
        ranges = _group_ranges(data)
        groups = _objdata_groups(data, ranges)
        if not groups:
            return {**base, "status": "no_objdata"}, []
        records: list[dict[str, object]] = []
        artifacts: list[tuple[str, bytes]] = []
        seen: set[str] = set()
        for index, (_group_start, group_end, payload_start) in enumerate(groups):
            try:
                decoded = _decode_objdata_hex(data, payload_start, group_end)
                metadata, native = _parse_ole1(decoded)
                if metadata["class_name"] == "Package":
                    package_metadata, recovered = _parse_ole10native(native)
                    metadata.update(package_metadata)
                    artifact_kind = "rtf-ole1-package-payload"
                else:
                    recovered = native
                    artifact_kind = "rtf-ole1-native-data"
            except RtfObjdataError as exc:
                records.append(
                    {"index": index, "status": "validation_failed", "reason": str(exc)}
                )
                continue
            digest = hashlib.sha256(recovered).hexdigest()
            metadata.update(
                index=index,
                status="validated",
                recovered_sha256=digest,
                duplicate=digest in seen,
            )
            records.append(metadata)
            if digest in seen:
                continue
            seen.add(digest)
            artifacts.append((artifact_kind, recovered))
    except RtfObjdataError as exc:
        return {**base, "status": "validation_failed", "reason": str(exc)}, []
    invalid_count = sum(item.get("status") == "validation_failed" for item in records)
    return {
        **base,
        "status": (
            "partial_artifacts_recovered"
            if artifacts and invalid_count
            else "artifacts_recovered"
            if artifacts
            else "validation_failed"
        ),
        "objdata_group_count": len(groups),
        "unique_native_count": len(artifacts),
        "invalid_objdata_count": invalid_count,
        "objects": records,
    }, artifacts
