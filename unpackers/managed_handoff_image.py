"""HOI1 managed handoff imageを実行せずに境界付きで棚卸しする。

この形式はPowerShellの ``Reflection.Emit`` loaderが型、field、method、CIL、
token fixup、例外領域を再構築するためのserialized imageである。本moduleはCLRを
loadせず、CILやnative codeも実行・emulateしない。全count、length、offsetと入力
終端を検証できた場合だけmetadataを返す。
"""

from __future__ import annotations

import hashlib
import struct
from collections import Counter
from dataclasses import dataclass

MAX_IMAGE_SIZE = 32 * 1024 * 1024
MAX_STRING_SIZE = 16 * 1024
MAX_BLOB_SIZE = 16 * 1024 * 1024
MAX_DATA_BLOBS = 4096
MAX_TYPES = 2048
MAX_FIELDS = 65_536
MAX_METHODS = 65_536
MAX_PARAMETERS = 255
MAX_TOTAL_PARAMETERS = 65_536
MAX_LOCALS = 65_535
MAX_FIXUPS = 262_144
MAX_EXCEPTION_REGIONS = 65_535
MAX_TOTAL_IL = 24 * 1024 * 1024
MAX_TOTAL_BLOBS = 32 * 1024 * 1024
MAX_REPORT_ITEMS = 512


class _ParseError(Exception):
    """検証失敗をreport reasonへ変換する内部例外。"""


@dataclass
class _Cursor:
    data: bytes
    offset: int = 0

    def take(self, size: int, label: str) -> bytes:
        if size < 0:
            raise _ParseError(f"{label}_negative_length")
        end = self.offset + size
        if end < self.offset or end > len(self.data):
            raise _ParseError(f"{label}_truncated")
        value = self.data[self.offset : end]
        self.offset = end
        return value

    def unpack(self, format_string: str, label: str) -> int:
        size = struct.calcsize(format_string)
        try:
            value = struct.unpack(format_string, self.take(size, label))[0]
        except struct.error as exc:  # pragma: no cover - takeで境界検査済み
            raise _ParseError(f"{label}_invalid") from exc
        return int(value)

    def u8(self, label: str) -> int:
        return self.unpack("<B", label)

    def u16(self, label: str) -> int:
        return self.unpack("<H", label)

    def i16(self, label: str) -> int:
        return self.unpack("<h", label)

    def i32(self, label: str) -> int:
        return self.unpack("<i", label)

    def text16(self, label: str, *, required: bool = False) -> str:
        size = self.u16(f"{label}_size")
        if size > MAX_STRING_SIZE:
            raise _ParseError(f"{label}_size_blocked")
        raw = self.take(size, label)
        try:
            value = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise _ParseError(f"{label}_utf8_invalid") from exc
        if "\0" in value or (required and not value):
            raise _ParseError(f"{label}_invalid")
        return value

    def blob16(self, label: str) -> bytes:
        size = self.u16(f"{label}_size")
        if size > MAX_BLOB_SIZE:
            raise _ParseError(f"{label}_size_blocked")
        return self.take(size, label)

    def blob32(self, label: str) -> bytes:
        size = self.i32(f"{label}_size")
        if size > MAX_BLOB_SIZE:
            raise _ParseError(f"{label}_size_blocked")
        return self.take(size, label)


def _base_report(status: str) -> dict[str, object]:
    return {
        "schema_version": 1,
        "status": status,
        "executed": False,
        "emulated": False,
        "clr_loaded": False,
        "network_contacted": False,
    }


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def inspect_managed_handoff_image(data: bytes) -> dict[str, object]:
    """HOI1 imageを完全走査し、安全な構造metadataだけを返す。"""

    if type(data) is not bytes:
        return _base_report("invalid_input")
    if not 1 <= len(data) <= MAX_IMAGE_SIZE:
        return _base_report("size_blocked")
    if not data.startswith(b"HOI1"):
        return _base_report("pattern_not_found")

    cursor = _Cursor(data)
    total_blobs = 0
    data_blob_bytes = 0
    total_fields = 0
    total_methods = 0
    total_parameters = 0
    total_locals = 0
    total_il = 0
    total_fixups = 0
    total_exceptions = 0
    fixup_kinds: Counter[int] = Counter()
    string_literals: list[str] = []
    seen_string_literals: set[str] = set()
    data_summaries: list[dict[str, object]] = []
    type_summaries: list[dict[str, object]] = []
    try:
        if cursor.take(4, "magic") != b"HOI1":  # pragma: no cover - prechecked
            raise _ParseError("magic_mismatch")
        version = cursor.u16("version")
        if version != 1:
            report = _base_report("unsupported_version")
            report["version"] = version
            return report
        namespace = cursor.text16("namespace", required=True)
        main_class = cursor.text16("main_class", required=True)

        data_count = cursor.u16("data_count")
        if data_count > MAX_DATA_BLOBS:
            raise _ParseError("data_count_blocked")
        for index in range(data_count):
            value = cursor.blob32(f"data_{index}")
            total_blobs += len(value)
            data_blob_bytes += len(value)
            if total_blobs > MAX_TOTAL_BLOBS:
                raise _ParseError("blob_budget_blocked")
            if len(data_summaries) < MAX_REPORT_ITEMS:
                data_summaries.append(
                    {
                        "index": index,
                        "size": len(value),
                        "sha256": _sha256(value),
                    }
                )

        type_count = cursor.u16("type_count")
        if not 1 <= type_count <= MAX_TYPES:
            raise _ParseError("type_count_blocked")
        for type_index in range(type_count):
            type_name = cursor.text16(f"type_{type_index}_name", required=True)
            kind = cursor.u8(f"type_{type_index}_kind")
            if kind not in {0, 1, 2}:
                raise _ParseError("type_kind_unsupported")
            attributes = cursor.i32(f"type_{type_index}_attributes")
            packing = cursor.i16(f"type_{type_index}_packing")
            type_size = cursor.i32(f"type_{type_index}_size")
            if type_size < 0:
                raise _ParseError("type_size_negative")
            charset = cursor.u8(f"type_{type_index}_charset")
            if charset > 4:
                raise _ParseError("type_charset_unsupported")

            field_count = cursor.u16(f"type_{type_index}_field_count")
            total_fields += field_count
            if total_fields > MAX_FIELDS:
                raise _ParseError("field_count_blocked")
            field_names: list[str] = []
            for field_index in range(field_count):
                field_name = cursor.text16(
                    f"type_{type_index}_field_{field_index}_name", required=True
                )
                cursor.i32(f"type_{type_index}_field_{field_index}_attributes")
                field_type = cursor.blob16(
                    f"type_{type_index}_field_{field_index}_type"
                )
                total_blobs += len(field_type)
                cursor.i32(f"type_{type_index}_field_{field_index}_offset")
                cursor.u8(f"type_{type_index}_field_{field_index}_marshal_kind")
                marshal_size = cursor.i32(
                    f"type_{type_index}_field_{field_index}_marshal_size"
                )
                if marshal_size < 0:
                    raise _ParseError("field_marshal_size_negative")
                if len(field_names) < MAX_REPORT_ITEMS:
                    field_names.append(field_name)

            method_count = cursor.u16(f"type_{type_index}_method_count")
            total_methods += method_count
            if total_methods > MAX_METHODS:
                raise _ParseError("method_count_blocked")
            method_names: list[str] = []
            type_il = 0
            for method_index in range(method_count):
                prefix = f"type_{type_index}_method_{method_index}"
                method_name = cursor.text16(f"{prefix}_name", required=True)
                cursor.i32(f"{prefix}_attributes")
                cursor.u8(f"{prefix}_implementation")
                cursor.u8(f"{prefix}_generic_attributes")
                cursor.u8(f"{prefix}_generic_count")
                return_type = cursor.blob16(f"{prefix}_return_type")
                total_blobs += len(return_type)

                parameter_count = cursor.u8(f"{prefix}_parameter_count")
                total_parameters += parameter_count
                if parameter_count > MAX_PARAMETERS:
                    raise _ParseError("parameter_count_blocked")
                if total_parameters > MAX_TOTAL_PARAMETERS:
                    raise _ParseError("total_parameter_count_blocked")
                for parameter_index in range(parameter_count):
                    parameter_type = cursor.blob16(
                        f"{prefix}_parameter_{parameter_index}_type"
                    )
                    total_blobs += len(parameter_type)

                init_locals = cursor.u8(f"{prefix}_init_locals")
                if init_locals not in {0, 1}:
                    raise _ParseError("init_locals_invalid")
                cursor.u16(f"{prefix}_max_stack")
                local_count = cursor.u16(f"{prefix}_local_count")
                total_locals += local_count
                if total_locals > MAX_LOCALS:
                    raise _ParseError("local_count_blocked")
                for local_index in range(local_count):
                    pinned = cursor.u8(f"{prefix}_local_{local_index}_pinned")
                    if pinned not in {0, 1}:
                        raise _ParseError("local_pinned_invalid")
                    local_type = cursor.blob16(
                        f"{prefix}_local_{local_index}_type"
                    )
                    total_blobs += len(local_type)

                il = cursor.blob32(f"{prefix}_il")
                total_il += len(il)
                type_il += len(il)
                if total_il > MAX_TOTAL_IL:
                    raise _ParseError("il_budget_blocked")

                fixup_count = cursor.u16(f"{prefix}_fixup_count")
                total_fixups += fixup_count
                if total_fixups > MAX_FIXUPS:
                    raise _ParseError("fixup_count_blocked")
                for fixup_index in range(fixup_count):
                    fixup_offset = cursor.i32(
                        f"{prefix}_fixup_{fixup_index}_offset"
                    )
                    fixup_kind = cursor.u8(f"{prefix}_fixup_{fixup_index}_kind")
                    if fixup_kind not in {0, 1, 2, 3, 5, 6}:
                        raise _ParseError("fixup_kind_unsupported")
                    fixup_kinds[fixup_kind] += 1
                    payload = cursor.blob16(
                        f"{prefix}_fixup_{fixup_index}_payload"
                    )
                    total_blobs += len(payload)
                    if not 0 <= fixup_offset < len(il):
                        raise _ParseError("fixup_offset_out_of_bounds")
                    if fixup_kind == 3:
                        if len(payload) < 2:
                            raise _ParseError("string_fixup_truncated")
                        string_size = struct.unpack_from("<H", payload)[0]
                        if string_size != len(payload) - 2:
                            raise _ParseError("string_fixup_length_mismatch")
                        try:
                            literal = payload[2:].decode("utf-8")
                        except UnicodeDecodeError as exc:
                            raise _ParseError("string_fixup_utf8_invalid") from exc
                        if literal not in seen_string_literals:
                            seen_string_literals.add(literal)
                            if len(string_literals) < MAX_REPORT_ITEMS:
                                string_literals.append(literal)
                    if fixup_kind == 5:
                        if len(payload) != 2:
                            raise _ParseError("data_fixup_size_invalid")
                        data_index = struct.unpack_from("<H", payload)[0]
                        if data_index >= data_count:
                            raise _ParseError("data_fixup_index_out_of_bounds")

                exception_count = cursor.u16(f"{prefix}_exception_count")
                total_exceptions += exception_count
                if total_exceptions > MAX_EXCEPTION_REGIONS:
                    raise _ParseError("exception_count_blocked")
                for exception_index in range(exception_count):
                    exception_prefix = f"{prefix}_exception_{exception_index}"
                    cursor.i32(f"{exception_prefix}_flags")
                    try_offset = cursor.i32(f"{exception_prefix}_try_offset")
                    try_length = cursor.i32(f"{exception_prefix}_try_length")
                    handler_offset = cursor.i32(
                        f"{exception_prefix}_handler_offset"
                    )
                    handler_length = cursor.i32(
                        f"{exception_prefix}_handler_length"
                    )
                    catch_type = cursor.blob16(f"{exception_prefix}_catch_type")
                    total_blobs += len(catch_type)
                    if (
                        min(
                            try_offset,
                            try_length,
                            handler_offset,
                            handler_length,
                        )
                        < 0
                        or try_offset + try_length > len(il)
                        or handler_offset + handler_length > len(il)
                    ):
                        raise _ParseError("exception_region_out_of_bounds")

                if len(method_names) < MAX_REPORT_ITEMS:
                    method_names.append(method_name)

            if total_blobs > MAX_TOTAL_BLOBS:
                raise _ParseError("blob_budget_blocked")
            if len(type_summaries) < MAX_REPORT_ITEMS:
                type_summaries.append(
                    {
                        "index": type_index,
                        "name": type_name,
                        "kind": kind,
                        "attributes": attributes,
                        "packing": packing,
                        "declared_size": type_size,
                        "charset": charset,
                        "field_count": field_count,
                        "field_names": field_names,
                        "field_names_truncated": field_count > len(field_names),
                        "method_count": method_count,
                        "method_names": method_names,
                        "method_names_truncated": method_count > len(method_names),
                        "il_size": type_il,
                    }
                )

        if cursor.offset != len(data):
            raise _ParseError("trailing_data")
    except _ParseError as exc:
        report = _base_report("invalid_structure")
        report.update(
            {
                "reason": str(exc),
                "input_size": len(data),
                "bytes_consumed": cursor.offset,
            }
        )
        return report

    report = _base_report("parsed")
    report.update(
        {
            "format": "HOI1",
            "version": version,
            "input_size": len(data),
            "input_sha256": _sha256(data),
            "namespace": namespace,
            "main_class": main_class,
            "data_blob_count": data_count,
            "data_blob_bytes": data_blob_bytes,
            "data_blobs": data_summaries,
            "data_blobs_truncated": data_count > len(data_summaries),
            "type_count": type_count,
            "types": type_summaries,
            "types_truncated": type_count > len(type_summaries),
            "field_count": total_fields,
            "method_count": total_methods,
            "parameter_count": total_parameters,
            "local_count": total_locals,
            "il_bytes": total_il,
            "fixup_count": total_fixups,
            "fixup_kind_counts": {
                str(kind): count for kind, count in sorted(fixup_kinds.items())
            },
            "string_literals": string_literals,
            "string_literals_truncated": len(seen_string_literals)
            > len(string_literals),
            "exception_region_count": total_exceptions,
            "serialized_type_blob_bytes": total_blobs,
            "complete_input_consumed": True,
        }
    )
    return report


__all__ = ["inspect_managed_handoff_image"]
