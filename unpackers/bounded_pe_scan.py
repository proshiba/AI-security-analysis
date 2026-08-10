"""埋め込みPE候補を、入力・候補数・経過時間の上限付きで走査する。

このモジュールはバイト列を実行せず、外部通信も行わない。候補が上限で
打ち切られた場合は、未走査範囲を完全解析済みと誤認しないよう、理由を
構造化して返す。
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import struct
import time
from typing import Callable


DEFAULT_MAX_SCAN_BYTES = 256 * 1024 * 1024
DEFAULT_MAX_CANDIDATES = 4096
DEFAULT_MAX_RESULTS = 16
DEFAULT_MAX_ELAPSED_SECONDS = 5.0
DEFAULT_MAX_PE_EXTENT = 256 * 1024 * 1024
MAX_PE_HEADER_OFFSET = 16 * 1024 * 1024
MAX_OPTIONAL_HEADER_SIZE = 4096
MAX_PE_SECTIONS = 96


class BoundedExtent(int):
    """検証方法を保持しつつ、従来の ``int`` と互換なPE長。"""

    validation_method: str
    validation_note: str | None

    def __new__(
        cls,
        value: int,
        *,
        validation_method: str,
        validation_note: str | None = None,
    ) -> "BoundedExtent":
        instance = int.__new__(cls, value)
        instance.validation_method = validation_method
        instance.validation_note = validation_note
        return instance


@dataclass(frozen=True)
class StructuralExtent:
    """PEヘッダから得た候補長と、失敗時の保守的な理由。"""

    extent: int | None
    reason: str


class CarvedPeArtifacts(list[tuple[str, bytes]]):
    """従来のlist契約を保ったまま、走査証跡を付帯する。"""

    scan_report: dict[str, object]

    def __init__(
        self,
        values: list[tuple[str, bytes]],
        scan_report: dict[str, object],
    ) -> None:
        super().__init__(values)
        self.scan_report = scan_report


def inspect_structural_pe_extent(
    data: bytes,
    offset: int = 0,
    *,
    max_extent: int = DEFAULT_MAX_PE_EXTENT,
) -> StructuralExtent:
    """コピーやPEライブラリ解析の前に、固定長ヘッダだけで候補を検査する。"""

    if max_extent < 1:
        raise ValueError("max_extentは正の整数で指定してください")
    if offset < 0 or offset + 0x40 > len(data):
        return StructuralExtent(None, "dos_header_out_of_bounds")
    if data[offset : offset + 2] != b"MZ":
        return StructuralExtent(None, "dos_magic_mismatch")

    pe_relative = struct.unpack_from("<I", data, offset + 0x3C)[0]
    if not 0x40 <= pe_relative <= MAX_PE_HEADER_OFFSET:
        return StructuralExtent(None, "pe_header_offset_out_of_bounds")
    pe_offset = offset + pe_relative
    if pe_offset + 24 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\0\0":
        return StructuralExtent(None, "pe_signature_missing")

    section_count = struct.unpack_from("<H", data, pe_offset + 6)[0]
    optional_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
    if not 1 <= section_count <= MAX_PE_SECTIONS:
        return StructuralExtent(None, "section_count_out_of_bounds")
    if not 2 <= optional_size <= MAX_OPTIONAL_HEADER_SIZE:
        return StructuralExtent(None, "optional_header_size_out_of_bounds")

    optional_offset = pe_offset + 24
    section_table = optional_offset + optional_size
    section_table_end = section_table + section_count * 40
    if section_table_end > len(data):
        return StructuralExtent(None, "section_table_out_of_bounds")
    magic = struct.unpack_from("<H", data, optional_offset)[0]
    if magic == 0x10B:
        number_of_directories_offset = 92
        data_directory_offset = 96
    elif magic == 0x20B:
        number_of_directories_offset = 108
        data_directory_offset = 112
    else:
        return StructuralExtent(None, "optional_header_magic_unsupported")
    if optional_size < 64:
        return StructuralExtent(None, "optional_header_truncated")

    size_of_headers = struct.unpack_from("<I", data, optional_offset + 60)[0]
    extent = max(size_of_headers, section_table_end - offset)
    for index in range(section_count):
        section = section_table + index * 40
        raw_size = struct.unpack_from("<I", data, section + 16)[0]
        raw_offset = struct.unpack_from("<I", data, section + 20)[0]
        if raw_size:
            raw_end = raw_offset + raw_size
            if raw_end < raw_offset:
                return StructuralExtent(None, "section_raw_extent_overflow")
            extent = max(extent, raw_end)

    if optional_size >= number_of_directories_offset + 4:
        directory_count = struct.unpack_from(
            "<I", data, optional_offset + number_of_directories_offset
        )[0]
        security_entry = data_directory_offset + 4 * 8
        if directory_count > 4 and optional_size >= security_entry + 8:
            security_offset, security_size = struct.unpack_from(
                "<II", data, optional_offset + security_entry
            )
            if security_offset and security_size:
                security_end = security_offset + security_size
                if security_end < security_offset:
                    return StructuralExtent(None, "security_extent_overflow")
                extent = max(extent, security_end)

    remaining = len(data) - offset
    if not 0 < extent <= max_extent:
        return StructuralExtent(None, "candidate_extent_budget_exceeded")
    if extent > remaining:
        return StructuralExtent(None, "candidate_extent_out_of_bounds")
    return StructuralExtent(extent, "structural_headers_coherent")


def _planned_ranges(input_size: int, start: int, max_scan_bytes: int) -> list[tuple[int, int]]:
    """上限超過時は先頭と末尾を決定論的に走査する。"""

    available = max(0, input_size - start)
    if available <= max_scan_bytes:
        return [(start, input_size)] if available else []
    prefix_size = (max_scan_bytes + 1) // 2
    suffix_size = max_scan_bytes - prefix_size
    prefix_end = start + prefix_size
    suffix_start = input_size - suffix_size
    ranges = [(start, prefix_end)]
    if suffix_start < input_size:
        ranges.append((suffix_start, input_size))
    return ranges


def scan_embedded_pe_candidates(
    data: bytes,
    validator: Callable[[bytes, int], int | None],
    *,
    start_offset: int = 1,
    max_scan_bytes: int = DEFAULT_MAX_SCAN_BYTES,
    max_candidates: int = DEFAULT_MAX_CANDIDATES,
    max_results: int = DEFAULT_MAX_RESULTS,
    max_elapsed_seconds: float = DEFAULT_MAX_ELAPSED_SECONDS,
    clock: Callable[[], float] = time.monotonic,
) -> tuple[list[tuple[int, int]], dict[str, object]]:
    """`MZ`候補を有界走査し、検証済みのoffsetと長さを返す。"""

    if not isinstance(data, bytes):
        raise TypeError("dataはbytesで指定してください")
    if not 0 <= start_offset <= len(data):
        raise ValueError("start_offsetが入力範囲外です")
    if min(max_scan_bytes, max_candidates, max_results) < 1:
        raise ValueError("走査budgetは正の値で指定してください")
    if max_elapsed_seconds <= 0:
        raise ValueError("max_elapsed_secondsは正の値で指定してください")

    planned_ranges = _planned_ranges(len(data), start_offset, max_scan_bytes)
    scope_size = max(0, len(data) - start_offset)
    planned_bytes = sum(end - start for start, end in planned_ranges)
    exhausted: list[str] = []
    if planned_bytes < scope_size:
        exhausted.append("input_scan_budget")

    started = clock()
    found: list[tuple[int, int]] = []
    seen_digests: set[tuple[int, int]] = set()
    methods: Counter[str] = Counter()
    notes: Counter[str] = Counter()
    candidate_count = 0
    rejected_count = 0
    actual_ranges: list[dict[str, int]] = []
    stop = False

    for range_start, range_end in planned_ranges:
        cursor = range_start
        scanned_end = range_start
        while cursor < range_end:
            if clock() - started >= max_elapsed_seconds:
                exhausted.append("elapsed_time_budget")
                stop = True
                break
            offset = data.find(b"MZ", cursor, range_end)
            if offset < 0:
                scanned_end = range_end
                break
            scanned_end = min(range_end, offset + 2)
            if candidate_count >= max_candidates:
                exhausted.append("candidate_count_budget")
                stop = True
                break
            candidate_count += 1
            validated = validator(data, offset)
            method = str(getattr(validated, "validation_method", "validator"))
            note = getattr(validated, "validation_note", None)
            methods[method] += 1
            if note:
                notes[str(note)] += 1
            if validated is None:
                rejected_count += 1
            else:
                extent = int(validated)
                if extent <= 0 or offset + extent > len(data):
                    rejected_count += 1
                    notes["validator_returned_out_of_bounds_extent"] += 1
                elif (offset, extent) not in seen_digests:
                    seen_digests.add((offset, extent))
                    found.append((offset, extent))
                    if len(found) >= max_results:
                        exhausted.append("result_count_budget")
                        stop = True
                        cursor = offset + extent
                        scanned_end = min(range_end, cursor)
                        break
            cursor = offset + max(2, int(validated) if validated else 2)
            scanned_end = min(range_end, cursor)
        if scanned_end > range_start:
            actual_ranges.append({"start": range_start, "end": scanned_end})
        if stop:
            break

    exhausted = list(dict.fromkeys(exhausted))
    scanned_bytes = sum(item["end"] - item["start"] for item in actual_ranges)
    report: dict[str, object] = {
        "schema_version": 1,
        "status": "partial" if exhausted else "complete",
        "input_size": len(data),
        "embedded_scan_start_offset": start_offset,
        "planned_scan_ranges": [
            {"start": start, "end": end} for start, end in planned_ranges
        ],
        "actual_scan_ranges": actual_ranges,
        "scanned_bytes": scanned_bytes,
        "scope_bytes": scope_size,
        "unscanned_scope_bytes": max(0, scope_size - scanned_bytes),
        "candidate_magic_count": candidate_count,
        "rejected_candidate_count": rejected_count,
        "recovered_candidate_count": len(found),
        "validation_methods": dict(sorted(methods.items())),
        "validation_notes": dict(sorted(notes.items())),
        "budgets": {
            "max_scan_bytes": max_scan_bytes,
            "max_candidates": max_candidates,
            "max_results": max_results,
            "max_elapsed_seconds": max_elapsed_seconds,
        },
        "budget_exhausted": bool(exhausted),
        "exhausted_reasons": exhausted,
        "executed": False,
        "network_contacted": False,
    }
    return found, report
