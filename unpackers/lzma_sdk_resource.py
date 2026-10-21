"""LZMA SDK形式のPE resourceを、非実行かつ上限付きで復元する。"""

from __future__ import annotations

import hashlib
import lzma
import struct
from collections import Counter
from dataclasses import dataclass
from itertools import pairwise

from unpackers.bounded_pe_scan import inspect_structural_pe_extent

LZMA_PROPERTIES_SIZE = 5
RESOURCE_HEADER_SIZE = 4 + LZMA_PROPERTIES_SIZE + 4

MAX_CANDIDATES = 32
MAX_RESOURCE_SIZE = 32 * 1024 * 1024
MAX_OUTPUT_SIZE = 32 * 1024 * 1024
MAX_DICTIONARY_SIZE = 64 * 1024 * 1024
MAX_TOTAL_INPUT_SIZE = 64 * 1024 * 1024
MAX_TOTAL_OUTPUT_SIZE = 64 * 1024 * 1024
MAX_TOTAL_WORK_SIZE = 96 * 1024 * 1024
MAX_COMPRESSION_RATIO = 512.0
MAX_PE_HEADER_OFFSET = 1024 * 1024
MAX_PE_SECTIONS = 96

_PER_CANDIDATE_BUDGET_REASONS = frozenset(
    {
        "resource_size_limit",
        "declared_output_size_limit",
        "dictionary_size_limit",
        "compression_ratio_limit",
    }
)


@dataclass(frozen=True)
class _Candidate:
    """境界とLZMA propertiesを検証済みのresource候補。"""

    compressed: bytes
    expected_size: int
    lc: int
    lp: int
    pb: int
    dictionary_size: int


def has_lzma_sdk_resource_prefix(blob: bytes) -> bool:
    """独自headerの固定properties長だけを、復号前の安価な候補条件にする。"""

    return (
        type(blob) is bytes
        and len(blob) > RESOURCE_HEADER_SIZE
        and struct.unpack_from("<I", blob, 0)[0] == LZMA_PROPERTIES_SIZE
    )


def _parse_candidate(blob: bytes) -> tuple[_Candidate | None, str | None]:
    if not has_lzma_sdk_resource_prefix(blob):
        return None, "prefix_mismatch"
    if len(blob) > MAX_RESOURCE_SIZE:
        return None, "resource_size_limit"

    property_byte = blob[4]
    if property_byte >= 9 * 5 * 5:
        return None, "properties_invalid"
    lc = property_byte % 9
    remainder = property_byte // 9
    lp = remainder % 5
    pb = remainder // 5
    if lc + lp > 4 or pb > 4:
        return None, "properties_invalid"

    dictionary_size = struct.unpack_from("<I", blob, 5)[0]
    if dictionary_size < 4096:
        return None, "dictionary_size_invalid"
    if dictionary_size > MAX_DICTIONARY_SIZE:
        return None, "dictionary_size_limit"

    expected_size = struct.unpack_from("<I", blob, 9)[0]
    if expected_size < 1:
        return None, "declared_output_size_invalid"
    if expected_size > MAX_OUTPUT_SIZE:
        return None, "declared_output_size_limit"
    compressed = blob[RESOURCE_HEADER_SIZE:]
    if not compressed:
        return None, "compressed_stream_missing"
    if expected_size / len(compressed) > MAX_COMPRESSION_RATIO:
        return None, "compression_ratio_limit"
    return (
        _Candidate(
            compressed=compressed,
            expected_size=expected_size,
            lc=lc,
            lp=lp,
            pb=pb,
            dictionary_size=dictionary_size,
        ),
        None,
    )


def _validate_pe(data: bytes) -> tuple[dict[str, int] | None, str | None]:
    """復元物のheader・section file境界・実行sectionを厳格に検証する。"""

    structural = inspect_structural_pe_extent(data, max_extent=len(data))
    if structural.extent is None:
        return None, f"pe_{structural.reason}"

    if len(data) < 0x40 or data[:2] != b"MZ":
        return None, "pe_dos_header_missing"
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if not 0x40 <= pe_offset <= MAX_PE_HEADER_OFFSET:
        return None, "pe_header_offset_invalid"
    if pe_offset + 24 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\0\0":
        return None, "pe_signature_missing"

    machine, section_count = struct.unpack_from("<HH", data, pe_offset + 4)
    optional_size, characteristics = struct.unpack_from("<HH", data, pe_offset + 20)
    if machine == 0 or not 1 <= section_count <= MAX_PE_SECTIONS:
        return None, "pe_coff_header_invalid"
    if characteristics & 0x0002 == 0:
        return None, "pe_not_executable_image"

    optional_offset = pe_offset + 24
    optional_end = optional_offset + optional_size
    if optional_size < 64 or optional_end > len(data):
        return None, "pe_optional_header_invalid"
    magic = struct.unpack_from("<H", data, optional_offset)[0]
    if magic not in {0x10B, 0x20B}:
        return None, "pe_optional_magic_invalid"
    size_of_image = struct.unpack_from("<I", data, optional_offset + 56)[0]
    size_of_headers = struct.unpack_from("<I", data, optional_offset + 60)[0]
    section_table_end = optional_end + section_count * 40
    if (
        section_table_end > len(data)
        or size_of_headers < section_table_end
        or size_of_headers > len(data)
        or size_of_image < size_of_headers
    ):
        return None, "pe_header_bounds_invalid"

    executable_section = False
    file_backed_section = False
    raw_ranges: list[tuple[int, int]] = []
    for index in range(section_count):
        section_offset = optional_end + index * 40
        virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from(
            "<IIII", data, section_offset + 8
        )
        section_characteristics = struct.unpack_from("<I", data, section_offset + 36)[0]
        virtual_extent = max(virtual_size, raw_size)
        if (
            virtual_address >= size_of_image
            or virtual_extent > size_of_image - virtual_address
        ):
            return None, "pe_section_virtual_bounds_invalid"
        if raw_size:
            if raw_offset < size_of_headers or raw_offset + raw_size > len(data):
                return None, "pe_section_file_bounds_invalid"
            raw_ranges.append((raw_offset, raw_offset + raw_size))
            file_backed_section = True
        if section_characteristics & 0x20000000 and raw_size > 0:
            executable_section = True
    raw_ranges.sort()
    if any(
        current_start < previous_end
        for (_, previous_end), (current_start, _) in pairwise(raw_ranges)
    ):
        return None, "pe_section_file_ranges_overlap"
    if not file_backed_section:
        return None, "pe_file_backed_section_missing"
    if not executable_section:
        return None, "pe_executable_section_missing"
    return {
        "machine": machine,
        "optional_magic": magic,
        "section_count": section_count,
    }, None


def _decompress(candidate: _Candidate) -> tuple[bytes | None, str | None]:
    filters = [
        {
            "id": lzma.FILTER_LZMA1,
            "dict_size": candidate.dictionary_size,
            "lc": candidate.lc,
            "lp": candidate.lp,
            "pb": candidate.pb,
        }
    ]
    try:
        decoder = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=filters)
        recovered = decoder.decompress(
            candidate.compressed,
            max_length=candidate.expected_size + 1,
        )
    except (lzma.LZMAError, MemoryError, OverflowError, ValueError):
        return None, "lzma_decode_failed"
    if len(recovered) != candidate.expected_size:
        return None, "declared_output_size_mismatch"
    if not decoder.eof:
        return None, "lzma_eof_missing"
    if decoder.unused_data:
        return None, "lzma_trailing_data"
    return recovered, None


class LzmaSdkResourceScanner:
    """複数resourceを総量上限付きで評価し、部分成果をfail-closedにする。"""

    def __init__(
        self,
        *,
        max_candidates: int = MAX_CANDIDATES,
        max_total_input_size: int = MAX_TOTAL_INPUT_SIZE,
        max_total_output_size: int = MAX_TOTAL_OUTPUT_SIZE,
        max_total_work_size: int = MAX_TOTAL_WORK_SIZE,
    ) -> None:
        for value in (
            max_candidates,
            max_total_input_size,
            max_total_output_size,
            max_total_work_size,
        ):
            if type(value) is not int or value <= 0:
                raise ValueError("scanner上限は正の整数で指定してください")
        self.max_candidates = max_candidates
        self.max_total_input_size = max_total_input_size
        self.max_total_output_size = max_total_output_size
        self.max_total_work_size = max_total_work_size
        self.candidate_count = 0
        self.evaluated_count = 0
        self.total_input_size = 0
        self.total_declared_output_size = 0
        self.total_work_size = 0
        self.rejections: Counter[str] = Counter()
        self.limit_reason: str | None = None
        self._resource_inventory_incomplete = False
        self._recovered: dict[str, bytes] = {}

    def _mark_budget_exhausted(self, reason: str) -> None:
        """不完全な試行から部分成果が残らないようfail-closedにする。"""

        self.limit_reason = self.limit_reason or reason
        self._recovered.clear()

    def inspect(self, blob: bytes) -> bool:
        """1 resourceを評価し、prefix候補だった場合だけTrueを返す。"""

        if not has_lzma_sdk_resource_prefix(blob):
            return False
        self.candidate_count += 1
        if self.candidate_count > self.max_candidates:
            self._mark_budget_exhausted("candidate_count_limit")
            return True
        if self.limit_reason is not None:
            return True

        candidate, reason = _parse_candidate(blob)
        if candidate is None:
            safe_reason = reason or "candidate_invalid"
            if safe_reason in _PER_CANDIDATE_BUDGET_REASONS:
                self._mark_budget_exhausted(safe_reason)
            else:
                self.rejections[safe_reason] += 1
            return True

        prospective_input = self.total_input_size + len(candidate.compressed)
        prospective_output = self.total_declared_output_size + candidate.expected_size
        prospective_work = (
            self.total_work_size + len(candidate.compressed) + candidate.expected_size
        )
        if prospective_input > self.max_total_input_size:
            self._mark_budget_exhausted("total_input_size_limit")
            return True
        if prospective_output > self.max_total_output_size:
            self._mark_budget_exhausted("total_output_size_limit")
            return True
        if prospective_work > self.max_total_work_size:
            self._mark_budget_exhausted("total_work_size_limit")
            return True

        self.total_input_size = prospective_input
        self.total_declared_output_size = prospective_output
        self.total_work_size = prospective_work
        self.evaluated_count += 1
        recovered, reason = _decompress(candidate)
        if recovered is None:
            self.rejections[reason or "lzma_decode_failed"] += 1
            return True
        pe_summary, reason = _validate_pe(recovered)
        if pe_summary is None:
            self.rejections[reason or "pe_validation_failed"] += 1
            return True
        digest = hashlib.sha256(recovered).hexdigest()
        self._recovered.setdefault(digest, recovered)
        return True

    def finalize(
        self,
        *,
        resource_inventory_complete: bool,
    ) -> tuple[dict[str, object], list[bytes]]:
        """完全な候補集合だけを返し、resource走査不完了時は成果を破棄する。"""

        limit_reason = self.limit_reason
        if not resource_inventory_complete:
            self._resource_inventory_incomplete = True
            self._recovered.clear()
        if self._resource_inventory_incomplete:
            status = "resource_inventory_incomplete"
            complete = False
            recovered: list[bytes] = []
        elif limit_reason is not None:
            status = "budget_exhausted"
            complete = False
            recovered = []
        else:
            complete = True
            recovered = list(self._recovered.values())
            if recovered:
                status = "recovered_terminal_pe"
            elif self.candidate_count:
                status = "candidate_rejected"
            else:
                status = "no_candidates"
        report: dict[str, object] = {
            "schema_version": 1,
            "status": status,
            "profile": "strict_lzma_sdk_resource_v1",
            "candidate_count": self.candidate_count,
            "evaluated_candidate_count": self.evaluated_count,
            "rejected_candidate_count": sum(self.rejections.values()),
            "rejection_reasons": dict(sorted(self.rejections.items())),
            "recovered_artifact_count": len(recovered),
            "candidate_set_complete": complete,
            "recovery_attempts_complete": complete,
            "recovered_artifact_set_complete": complete,
            "total_compressed_input_bytes": self.total_input_size,
            "total_declared_output_bytes": self.total_declared_output_size,
            "total_work_bytes": self.total_work_size,
            "limit_reason": limit_reason,
            "budgets": {
                "max_candidates": self.max_candidates,
                "max_resource_size": MAX_RESOURCE_SIZE,
                "max_output_size": MAX_OUTPUT_SIZE,
                "max_dictionary_size": MAX_DICTIONARY_SIZE,
                "max_total_input_size": self.max_total_input_size,
                "max_total_output_size": self.max_total_output_size,
                "max_total_work_size": self.max_total_work_size,
                "max_compression_ratio": MAX_COMPRESSION_RATIO,
            },
            "family_attribution_allowed": False,
            "c2_confirmation_allowed": False,
            "safety": {
                "sample_executed": False,
                "network_contacted": False,
                "raw_resource_included": False,
                "raw_payload_included": False,
            },
        }
        return report, recovered
