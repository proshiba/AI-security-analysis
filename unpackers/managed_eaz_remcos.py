#!/usr/bin/env python3
# ruff: noqa: E402, RUF100
"""Eazfuscator系managed loaderから終端PEを静的に復元する。

このmoduleはCLR、CIL、復元payloadを実行しない。元入力へ直接束縛した
``ManifestResource``、レビュー済みCIL shape、完全なResourceSet v2境界を
すべて確認できた場合だけ終端PEを返す。ここで確認するのはloader recipeで
あり、RemcosRATのfamily帰属やC2確認には使用しない。
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import struct
import sys
import time
import warnings
from collections import Counter
from collections.abc import Callable, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from itertools import pairwise
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:  # 単独import/CLI互換
    sys.path.insert(0, str(ROOT))
ANALYSIS_ROOT = ROOT / "analysis-framework"
if str(ANALYSIS_ROOT) not in sys.path:
    sys.path.insert(0, str(ANALYSIS_ROOT))

import dnfile
from dncil.cil.body.reader import read_method_body_from_bytes
from malware.purehvnc.managed_resource_recovery import (
    StaticRecoveryError,
    _array_store,
    _local_index,
    _scalar_assignment,
    trace_flattened_switch,
)

from unpackers.bounded_pe_scan import inspect_structural_pe_extent
from unpackers.managed_bitmap_argb_xor import (
    RecoveryError as ManagedMethodRecoveryError,
)
from unpackers.managed_bitmap_argb_xor import (
    _metadata_names,
    _normalize_methods,
    _row_tokens,
)
from unpackers.managed_constructor_guard import (
    preflight_clr_declarations,
)
from unpackers.managed_eaz_resource import (
    RecoveryError as EazRecoveryError,
)
from unpackers.managed_eaz_resource import (
    _array_allocation,
    _bounded_method_body_data,
    _decode_method,
    _dispatcher_profile,
    _helper_constants,
    _system_byte_tokens,
)
from unpackers.managed_proxy_deobfuscator import (
    MAX_PROFILE_ELAPSED_SECONDS,
    analyze_modsquare_proxy_profile,
)
from unpackers.managed_resource_snapshot import (
    prepare_resource_snapshot,
    revalidated_resource_scan,
)

MAX_INPUT_BYTES = 32 << 20
MAX_METADATA_ROWS = 131_072
MAX_METHOD_ROWS = 4_096
MAX_RESOURCE_COUNT = 128
MAX_RESOURCE_BYTES = 16 << 20
MAX_TOTAL_RESOURCE_BYTES = 32 << 20
MAX_RESOURCE_ENTRIES = 4_096
MAX_RESOURCE_TYPES = 256
MAX_RESOURCE_NAME_CHARS = 512
MAX_RESOURCE_STRING_BYTES = 1 << 20
MAX_STRING_TABLE_ENTRIES = 4_096
MAX_STRING_TABLE_BYTES = 16 << 20
MAX_EXPRESSION_INSTRUCTIONS = 32
MAX_TRACE_STATES = 1_024
MAX_OUTPUT_BYTES = 16 << 20
MAX_ELAPSED_SECONDS = 10.0
TIME_CHECK_INTERVAL = 4_096
RESOURCE_MAGIC = 0xBEEFCACE
_U32_MASK = 0xFFFFFFFF

PROFILE_ID = "eaz-remcos-string-resource-v1"
TRANSFORM_CANONICAL_SHA256 = (
    "fe84efee8382b26794e029eb8de1c535b930d6d8b34a4605b01d23bc2d7e8d82"
)
_TRANSFORM_BUILD_CONSTANT_INDICES = (167, 169, 171, 173)
_TRANSFORM_SIGNATURE = bytes.fromhex("2003011d051d051d05")
_RESOLVER_SIGNATURE = bytes.fromhex("00010e08")
_B0_SIGNATURE = bytes.fromhex("00021d051d050e")
_VOID_SIGNATURE = bytes.fromhex("000001")
_STRING_FIELD_SIGNATURE = bytes.fromhex("060e")
_BYTE_ARRAY_FIELD_SIGNATURE = bytes.fromhex("061d05")
_TRANSFORM_FIXED_CONSTANTS = frozenset(
    {36_951, 40_498, 19_870, 432_322_986, 88_665_022}
)
_RESOLVER_REQUIRED_APIS = frozenset(
    {
        "System.Reflection.Assembly::GetManifestResourceStream",
        "System.BitConverter::ToInt32",
        "System.Array::Copy",
        "System.Text.Encoding::get_Unicode",
        "System.Text.Encoding::GetString",
        "System.BitConverter::GetBytes",
    }
)
_BRANCH_OPCODES = frozenset(
    {
        "br",
        "br.s",
        "brtrue",
        "brtrue.s",
        "brfalse",
        "brfalse.s",
        "beq",
        "beq.s",
        "bge",
        "bge.s",
        "bge.un",
        "bge.un.s",
        "bgt",
        "bgt.s",
        "bgt.un",
        "bgt.un.s",
        "ble",
        "ble.s",
        "ble.un",
        "ble.un.s",
        "blt",
        "blt.s",
        "blt.un",
        "blt.un.s",
        "bne.un",
        "bne.un.s",
        "leave",
        "leave.s",
    }
)
_RESOLVER_CIL_SHA256 = (
    "cdf14ab3752e4547ee8b6ab339f45c6f2048e2ed5eacead23b62d921b68a8635"
)
_TRANSFORM_CIL_SHA256 = (
    "77cab0ddd7c5129e81536b11375f19d3f7aeca744733b22ba844267727a4237d"
)
# 6 distinct childでreviewしたbundle。各digestはtoken/local/branch targetを
# 正規化し、signature、MethodAttributes、EH/extra-section shapeを含む。
_STRICT_ROLE_PROFILES = (
    {
        "profile": "eaz-remcos-a1",
        "crypto": "8f9be65e6288a5129d5042e630bb7538b2e3a7771c974c449a04e052ea1625aa",
        "b0": "cb21b9803ce10b692d4857d80b078e82c4239abfd3f9613dd9081671b72a5bbe",
        "b1": "c5a3aaf486a4df5a71a233c2f726d4b1c79d981086c582ad44aa6bb69922d16e",
        "b2": "649a804ebc0b02cc0d06a3d9182e693d48fe8d3fd6cce4524db93f4beff62b78",
    },
    {
        "profile": "eaz-remcos-a2",
        "crypto": "67735758abf80ddc9749c4fbff93092d56e17da71d99d0f6b4a5362466879518",
        "b0": "23560cfbbcf2a014faa6ea1f9cb52add9bb5e96d91f5d66b1fe80de045d3d6a1",
        "b1": "e5d062c65ba0d0f659feb8719bbb842d5f84dbc4955d8e86a31ef95388eda931",
        "b2": "7d1fd4ce6e25c1a9aabd77fdb384452a0a1544724c55c6eba60a607606f0137f",
    },
    {
        "profile": "eaz-remcos-a3",
        "crypto": "2c4406250cebffaa9baf3ac0f9b2ed7062e08367efac91492074a785bad41745",
        "b0": "b01a79ed83e4292686cc62700d7498220c539fab76ce656bed79e82644ca0c95",
        "b1": "1fcb5a291ece397fe0f2a196a1bc06472fcf545494c98c6910fd90357b9c6f19",
        "b2": "806e2f5526e98a54c8a593e584becb600ccf2d277612660ef42f4ed521aa4b26",
    },
    {
        "profile": "eaz-remcos-b1",
        "crypto": "c837ff48fc2f118aab077e20126e6ddbdb84dad842497f54e00572de47f97127",
        "b0": "d090d45b0d7dc625efac1f7658820e758c455d3338cc415c7ea91fef1da6edd6",
        "b1": "aaa9c359401103312e08263551c65353e421bdc88785cb3aa45a773139dac9b0",
        "b2": "25d94dd96bbfeec1061bee2ccacb671be545e0ddd38b85865a41d931c6b33c3a",
    },
    {
        "profile": "eaz-remcos-b2",
        "crypto": "fa0d0eb29a0664e7c949455ed768ba145d1bb58ac37858635245e446d02bd16d",
        "b0": "e449f1bbbde7f67da1a9ff05d85e520ac56b5a5a8382c112da96e8896c47d7c1",
        "b1": "05baf7117d7bd261901f724ec49c4add37c86fbd2df770d3213256d52d0151d3",
        "b2": "cff56d5f7d69f4726f1a8e2c76c0fd07181326043d99da3be69d74c5f5cd4d14",
    },
    {
        "profile": "eaz-remcos-a4",
        "crypto": "8fedc182f2fbf60be507654854db136d01a17c5fe0a43f8fda279c3a489c04f8",
        "b0": "ea981215e57fb38fafbbedc7c7285116f1dfd19b293e814bd3af17629212bdcb",
        "b1": "1a5bc4c4779f0adc162996107286118dd17ef8d04268091a1b2eec9c711fc47c",
        "b2": "dada8bcbe465207bdd7e419e90b364835d17b89d878d9a48739a8d8b7decc03d",
    },
)


class RemcosEazRecoveryError(ValueError):
    """profile不一致、曖昧性、または入力不整合を表す。"""


class RemcosEazIncompleteError(RemcosEazRecoveryError):
    """deadlineまたはquotaで完全走査できなかったことを表す。"""

    def __init__(
        self,
        reason: str,
        *,
        incomplete_type: str,
        stage: str,
        observed: int | None = None,
        limit: float | None = None,
    ) -> None:
        super().__init__(reason)
        self.incomplete_type = incomplete_type
        self.stage = stage
        self.observed = observed
        self.limit = limit

    def report_details(self) -> dict[str, object]:
        """秘密値を含まない機械判定用の未完了情報を返す。"""

        result: dict[str, object] = {
            "type": self.incomplete_type,
            "stage": self.stage,
        }
        if self.observed is not None:
            result["observed"] = self.observed
        if self.limit is not None:
            result["limit"] = self.limit
        return result


@dataclass(frozen=True)
class _ManifestResource:
    token: int
    name: str
    body_offset: int
    body: bytes


@dataclass(frozen=True)
class _ResourceValue:
    name: str
    value: bytes
    container_token: int
    container_size: int
    container_sha256: str


@dataclass(frozen=True)
class _StringEntry:
    offset: int
    raw: bytes
    value: str


@dataclass(frozen=True)
class _ArrayRecipe:
    key: bytes
    mask: bytes
    traced_states: int
    key_store_count: int
    mask_store_count: int


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _u32(value: int) -> int:
    return value & _U32_MASK


def _check_time(
    deadline: float,
    clock: Callable[[], float],
    *,
    stage: str,
) -> None:
    if clock() > deadline:
        raise RemcosEazIncompleteError(
            "elapsed_time_limit",
            incomplete_type="deadline",
            stage=stage,
            limit=MAX_ELAPSED_SECONDS,
        )


def _bounded_count(observed: int, limit: int, *, stage: str, reason: str) -> None:
    if observed > limit:
        raise RemcosEazIncompleteError(
            reason,
            incomplete_type="quota",
            stage=stage,
            observed=observed,
            limit=limit,
        )


@contextmanager
def _contained_parser_diagnostics():
    previous = logging.root.manager.disable
    logging.disable(logging.CRITICAL)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            yield
    finally:
        logging.disable(previous)


def _text(value: object, *, maximum: int = MAX_RESOURCE_NAME_CHARS) -> str:
    raw = getattr(value, "value", value)
    if not isinstance(raw, str) or not 0 < len(raw) <= maximum:
        raise RemcosEazRecoveryError("metadata_text_invalid")
    if any(ord(character) < 32 or ord(character) == 127 for character in raw):
        raise RemcosEazRecoveryError("metadata_text_invalid")
    return raw


def _integer(value: object) -> int:
    raw = getattr(value, "value", value)
    if isinstance(raw, bool) or not isinstance(raw, int):
        raise RemcosEazRecoveryError("metadata_integer_invalid")
    return raw


def _manifest_resources(
    data: bytes,
    pe: Any,
    *,
    deadline: float,
    clock: Callable[[], float],
) -> tuple[list[_ManifestResource], Any, Any]:
    """完全snapshotと照合し、元入力からembedded bodyだけを切り出す。"""

    try:
        snapshot, resolver, _work = prepare_resource_snapshot(
            data,
            pe,
            max_resources=MAX_RESOURCE_COUNT,
            max_resource_bytes=MAX_TOTAL_RESOURCE_BYTES,
            max_rows=20_000,
            max_total_rows=80_000,
        )
        snapshot = revalidated_resource_scan(data, snapshot)
        coverage = snapshot.coverage()
    except (AttributeError, TypeError, ValueError) as exc:
        raise RemcosEazIncompleteError(
            "manifest_resource_snapshot_unavailable",
            incomplete_type="source_binding",
            stage="manifest_resources",
        ) from exc
    if not (
        coverage.get("status") == "complete"
        and coverage.get("inventory_complete") is True
        and coverage.get("embedded_scan_complete") is True
        and coverage.get("input_binding_verified") is True
        and not coverage.get("reason_counts")
    ):
        raise RemcosEazIncompleteError(
            "manifest_resource_snapshot_incomplete",
            incomplete_type="source_binding",
            stage="manifest_resources",
        )

    table = getattr(
        getattr(getattr(pe, "net", None), "mdtables", None),
        "ManifestResource",
        None,
    )
    rows = list(getattr(table, "rows", ()) or ())
    if not rows:
        # このrecipeは暗号化string tableと終端ResourceSetの双方を
        # ManifestResourceから一意に結ぶ。行がないmanaged PEは適用外であり、
        # 空のdirectoryに対するsize上限をcoverage不足として扱わない。
        raise RemcosEazRecoveryError("manifest_resources_missing")
    _bounded_count(
        len(rows),
        MAX_RESOURCE_COUNT,
        stage="manifest_resources",
        reason="resource_count_limit",
    )
    net_struct = getattr(getattr(pe, "net", None), "struct", None)
    rva = _integer(getattr(net_struct, "ResourcesRva", None))
    size = _integer(getattr(net_struct, "ResourcesSize", None))
    if not 0 < size <= MAX_TOTAL_RESOURCE_BYTES:
        raise RemcosEazIncompleteError(
            "resource_directory_byte_limit",
            incomplete_type="quota",
            stage="manifest_resources",
            observed=size,
            limit=MAX_TOTAL_RESOURCE_BYTES,
        )
    try:
        base = int(pe.get_offset_from_rva(rva))
    except Exception as exc:
        raise RemcosEazRecoveryError("resource_directory_rva_invalid") from exc
    if not 0 <= base < base + size <= len(data):
        raise RemcosEazRecoveryError("resource_directory_bounds")

    result: list[_ManifestResource] = []
    spans: list[tuple[int, int]] = []
    names: set[str] = set()
    total = 0
    for index, row in enumerate(rows, 1):
        _check_time(deadline, clock, stage="manifest_resources")
        implementation = getattr(getattr(row, "Implementation", None), "row", None)
        if implementation is not None:
            raise RemcosEazRecoveryError("linked_resource_not_reviewed")
        name = _text(getattr(row, "Name", None))
        if name in names:
            raise RemcosEazRecoveryError("manifest_resource_name_ambiguous")
        names.add(name)
        relative = _integer(getattr(row, "Offset", None))
        prefix = base + relative
        if relative < 0 or prefix + 4 > base + size:
            raise RemcosEazRecoveryError("manifest_resource_offset_bounds")
        body_size = struct.unpack_from("<I", data, prefix)[0]
        if not 0 < body_size <= MAX_RESOURCE_BYTES:
            raise RemcosEazIncompleteError(
                "resource_byte_limit",
                incomplete_type="quota",
                stage="manifest_resources",
                observed=body_size,
                limit=MAX_RESOURCE_BYTES,
            )
        start = prefix + 4
        end = start + body_size
        if end > base + size:
            raise RemcosEazRecoveryError("manifest_resource_body_bounds")
        total += body_size
        _bounded_count(
            total,
            MAX_TOTAL_RESOURCE_BYTES,
            stage="manifest_resources",
            reason="total_resource_byte_limit",
        )
        spans.append((prefix, end))
        result.append(
            _ManifestResource(
                token=0x28000000 | index,
                name=name,
                body_offset=start,
                body=data[start:end],
            )
        )
    ordered = sorted(spans)
    if any(left[1] > right[0] for left, right in pairwise(ordered)):
        raise RemcosEazRecoveryError("manifest_resource_overlap")
    raw_projection = tuple(
        (
            resource.token & 0xFFFFFF,
            "embedded",
            resource.name,
            resource.body_offset,
            len(resource.body),
            None,
        )
        for resource in result
    )
    snapshot_projection = tuple(
        (
            descriptor.row_index,
            descriptor.kind,
            descriptor.name,
            descriptor.body_offset,
            descriptor.body_size,
            descriptor.linked_scope,
        )
        for descriptor in snapshot._descriptors
    )
    if raw_projection != snapshot_projection:
        raise RemcosEazIncompleteError(
            "manifest_resource_descriptor_mismatch",
            incomplete_type="source_binding",
            stage="manifest_resources",
        )
    return result, snapshot, resolver


def _read_7bit(data: bytes, position: int, end: int) -> tuple[int, int]:
    value = 0
    for index in range(5):
        if position >= end:
            raise RemcosEazRecoveryError("resource_7bit_integer_truncated")
        current = data[position]
        position += 1
        if index == 4 and current > 0x0F:
            raise RemcosEazRecoveryError("resource_7bit_integer_overflow")
        value |= (current & 0x7F) << (index * 7)
        if not current & 0x80:
            return value, position
    raise RemcosEazRecoveryError("resource_7bit_integer_invalid")


def _binary_string(
    data: bytes,
    position: int,
    end: int,
    *,
    encoding: str,
    maximum: int,
) -> tuple[str, int]:
    size, position = _read_7bit(data, position, end)
    if size > maximum or position + size > end:
        raise RemcosEazRecoveryError("resource_string_bounds")
    try:
        value = data[position : position + size].decode(encoding, errors="strict")
    except UnicodeDecodeError as exc:
        raise RemcosEazRecoveryError("resource_string_encoding") from exc
    return value, position + size


def _resource_name(value: str) -> str:
    if (
        not value
        or len(value) > MAX_RESOURCE_NAME_CHARS
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise RemcosEazRecoveryError("resource_name_invalid")
    return value


def _fast_resource_name_hash(value: str) -> int:
    """``FastResourceComparer.HashFunction``をUTF-16 code unit単位で再現する。"""

    try:
        encoded = value.encode("utf-16le", errors="strict")
    except UnicodeEncodeError as exc:
        raise RemcosEazRecoveryError("resource_name_encoding") from exc
    if len(encoded) % 2:
        raise RemcosEazRecoveryError("resource_name_encoding")
    result = 5_381
    for (code_unit,) in struct.iter_unpack("<H", encoded):
        result = (((result << 5) + result) ^ code_unit) & _U32_MASK
    return result - (1 << 32) if result & (1 << 31) else result


def _validate_resource_value(
    raw: bytes,
    start: int,
    end: int,
    type_count: int,
) -> tuple[int, bytes | None]:
    type_code, cursor = _read_7bit(raw, start, end)
    if type_code == 0:
        expected = cursor
    elif type_code == 1:
        _value, expected = _binary_string(
            raw,
            cursor,
            end,
            encoding="utf-8",
            maximum=MAX_RESOURCE_STRING_BYTES,
        )
    elif type_code in {2, 4, 5}:
        expected = cursor + 1
    elif type_code in {3, 6, 7}:
        expected = cursor + 2
    elif type_code in {8, 9, 12}:
        expected = cursor + 4
    elif type_code in {10, 11, 13, 15, 16}:
        expected = cursor + 8
    elif type_code == 14:
        expected = cursor + 16
    elif type_code in {32, 33}:
        if cursor + 4 > end:
            raise RemcosEazRecoveryError("resource_byte_array_length_truncated")
        size = struct.unpack_from("<I", raw, cursor)[0]
        cursor += 4
        if size > MAX_RESOURCE_BYTES:
            raise RemcosEazIncompleteError(
                "resource_byte_array_limit",
                incomplete_type="quota",
                stage="resource_set",
                observed=size,
                limit=MAX_RESOURCE_BYTES,
            )
        expected = cursor + size
        if expected != end:
            raise RemcosEazRecoveryError("resource_byte_array_bounds")
        return type_code, raw[cursor:expected] if type_code == 32 else None
    elif type_code >= 64:
        if type_code - 64 >= type_count or cursor >= end:
            raise RemcosEazRecoveryError("resource_user_type_invalid")
        return type_code, None
    else:
        raise RemcosEazRecoveryError("resource_type_not_reviewed")
    if expected != end:
        raise RemcosEazRecoveryError("resource_value_bounds")
    return type_code, None


def _parse_resource_set(
    resource: _ManifestResource,
    *,
    deadline: float,
    clock: Callable[[], float],
) -> list[_ResourceValue]:
    """ResourceSet v2をdeserializeせず、全entry境界とtype 32だけを読む。"""

    raw = resource.body
    if not 32 <= len(raw) <= MAX_RESOURCE_BYTES:
        raise RemcosEazRecoveryError("resource_set_size_limit")
    if struct.unpack_from("<I", raw)[0] != RESOURCE_MAGIC:
        raise RemcosEazRecoveryError("resource_set_magic")
    header_version, header_size = struct.unpack_from("<ii", raw, 4)
    header_start = 12
    header_end = header_start + header_size
    if header_version != 1 or not header_start <= header_end <= len(raw):
        raise RemcosEazRecoveryError("resource_set_header_invalid")
    cursor = header_start
    for _ in range(2):
        _value, cursor = _binary_string(
            raw, cursor, header_end, encoding="utf-8", maximum=4_096
        )
    if cursor != header_end or header_end + 12 > len(raw):
        raise RemcosEazRecoveryError("resource_set_header_shape")
    version, count, type_count = struct.unpack_from("<iii", raw, header_end)
    if version != 2 or not 0 <= count <= MAX_RESOURCE_ENTRIES:
        raise RemcosEazRecoveryError("resource_set_count_invalid")
    if not 0 <= type_count <= MAX_RESOURCE_TYPES:
        raise RemcosEazRecoveryError("resource_set_type_count_invalid")
    cursor = header_end + 12
    for _ in range(type_count):
        _value, cursor = _binary_string(
            raw, cursor, len(raw), encoding="utf-8", maximum=4_096
        )
    cursor = (cursor + 7) & ~7
    if cursor + count * 8 + 4 > len(raw):
        raise RemcosEazRecoveryError("resource_set_index_truncated")
    name_hashes = list(struct.unpack_from(f"<{count}i", raw, cursor))
    cursor += count * 4
    if any(left > right for left, right in pairwise(name_hashes)):
        raise RemcosEazRecoveryError("resource_name_hashes_not_sorted")
    name_positions = list(struct.unpack_from(f"<{count}i", raw, cursor))
    cursor += count * 4
    data_section = struct.unpack_from("<i", raw, cursor)[0]
    name_section = cursor + 4
    if not name_section <= data_section <= len(raw):
        raise RemcosEazRecoveryError("resource_set_sections_invalid")
    if count == 0:
        if name_section != data_section or data_section != len(raw):
            raise RemcosEazRecoveryError("empty_resource_set_not_exact")
        return []
    if len(set(name_positions)) != count or any(
        position < 0 or name_section + position >= data_section
        for position in name_positions
    ):
        raise RemcosEazRecoveryError("resource_name_offsets_invalid")

    names: list[tuple[str, int, int, int]] = []
    for index, position in enumerate(name_positions):
        if index % 256 == 0:
            _check_time(deadline, clock, stage="resource_set")
        start = name_section + position
        name, after_name = _binary_string(
            raw,
            start,
            data_section,
            encoding="utf-16le",
            maximum=MAX_RESOURCE_NAME_CHARS * 2,
        )
        if after_name + 4 > data_section:
            raise RemcosEazRecoveryError("resource_name_record_truncated")
        data_offset = struct.unpack_from("<i", raw, after_name)[0]
        if _fast_resource_name_hash(name) != name_hashes[index]:
            raise RemcosEazRecoveryError("resource_name_hash_mismatch")
        names.append((_resource_name(name), data_offset, start, after_name + 4))
    if len({name for name, *_rest in names}) != count:
        raise RemcosEazRecoveryError("resource_name_ambiguity")
    name_spans = sorted((start, end) for _name, _offset, start, end in names)
    if (
        name_spans[0][0] != name_section
        or name_spans[-1][1] != data_section
        or any(left[1] != right[0] for left, right in pairwise(name_spans))
    ):
        raise RemcosEazRecoveryError("resource_name_section_not_exact")

    data_offsets = [offset for _name, offset, _start, _end in names]
    if len(set(data_offsets)) != count or any(
        offset < 0 or data_section + offset >= len(raw) for offset in data_offsets
    ):
        raise RemcosEazRecoveryError("resource_data_offsets_invalid")
    ordered = sorted(data_offsets)
    if ordered[0] != 0:
        raise RemcosEazRecoveryError("resource_data_section_not_exact")
    ends = {
        start: (
            data_section + ordered[index + 1] if index + 1 < len(ordered) else len(raw)
        )
        for index, start in enumerate(ordered)
    }
    values: list[_ResourceValue] = []
    digest = _sha256(raw)
    for index, (name, relative, _start, _end) in enumerate(names):
        if index % 256 == 0:
            _check_time(deadline, clock, stage="resource_set")
        start = data_section + relative
        type_code, value = _validate_resource_value(
            raw, start, ends[relative], type_count
        )
        if type_code == 32 and value is not None:
            values.append(
                _ResourceValue(
                    name=name,
                    value=value,
                    container_token=resource.token,
                    container_size=len(raw),
                    container_sha256=digest,
                )
            )
    return values


def _method_signature(method: Any) -> bytes:
    signature = getattr(method, "signature", b"")
    return bytes(signature) if isinstance(signature, (bytes, bytearray)) else b""


def _transform_digest(method: Any) -> str:
    local_map: dict[int, int] = {}
    rows: list[list[object]] = []
    for index, instruction in enumerate(method.instructions):
        raw_local = instruction.local
        local = (
            None
            if raw_local is None
            else local_map.setdefault(raw_local, len(local_map))
        )
        integer: object = instruction.integer
        if index in _TRANSFORM_BUILD_CONSTANT_INDICES:
            integer = "VAR"
        token_kind = instruction.token >> 24 if instruction.token else None
        semantic = (
            instruction.resolved
            if instruction.resolved.startswith("System.")
            else {0x02: "typedef", 0x04: "fielddef", 0x06: "methoddef"}.get(token_kind)
        )
        rows.append(
            [
                instruction.opcode,
                local,
                integer,
                token_kind,
                semantic,
                "str" if instruction.user_string is not None else None,
            ]
        )
    return _sha256(json.dumps(rows, separators=(",", ":")).encode("ascii"))


def _find_transform(
    methods: Sequence[Any],
    *,
    deadline: float,
    clock: Callable[[], float],
) -> tuple[Any, tuple[int, int, int, int]]:
    candidates: list[tuple[Any, tuple[int, int, int, int]]] = []
    for method_index, method in enumerate(methods):
        if method_index % 256 == 0:
            _check_time(deadline, clock, stage="word_transform_scan")
        if (
            _method_signature(method) != _TRANSFORM_SIGNATURE
            or method.body_size != 907
            or len(method.instructions) != 419
        ):
            continue
        integers = {item.integer for item in method.instructions}
        if not _TRANSFORM_FIXED_CONSTANTS.issubset(integers):
            continue
        if _transform_digest(method) != TRANSFORM_CANONICAL_SHA256:
            continue
        constants: list[int] = []
        valid = True
        for index in _TRANSFORM_BUILD_CONSTANT_INDICES:
            item = method.instructions[index]
            if item.opcode != "ldc.i4" or not isinstance(item.integer, int):
                valid = False
                break
            constants.append(_u32(item.integer))
        if valid:
            candidates.append((method, tuple(constants)))
    if len(candidates) != 1:
        raise RemcosEazRecoveryError("word_transform_candidate_ambiguous_or_missing")
    return candidates[0]


def _crypto_signature(signature: bytes) -> bool:
    return (
        len(signature) == 7
        and signature[:4] == b"\x00\x02\x01\x12"
        and signature[-1:] == b"\x08"
    )


def _find_crypto_method(
    methods: Sequence[Any],
    transform_token: int,
    *,
    deadline: float,
    clock: Callable[[], float],
) -> Any:
    candidates = []
    for method_index, method in enumerate(methods):
        if method_index % 256 == 0:
            _check_time(deadline, clock, stage="crypto_method_scan")
        opcodes = Counter(item.opcode for item in method.instructions)
        if (
            not _crypto_signature(_method_signature(method))
            or opcodes["switch"] != 1
            or opcodes["stelem.i1"] < 48
            or not any(
                item.opcode == "call" and item.token == transform_token
                for item in method.instructions
            )
            or sum(
                item.opcode == "newarr"
                and item.resolved == "System.Byte"
                and index > 0
                and method.instructions[index - 1].integer in {16, 32}
                for index, item in enumerate(method.instructions)
            )
            < 2
        ):
            continue
        candidates.append(method)
    if len(candidates) != 1:
        raise RemcosEazRecoveryError("crypto_method_candidate_ambiguous_or_missing")
    candidate = candidates[0]
    opcodes = [item.opcode for item in candidate.instructions]
    sentinel = any(
        opcodes[index : index + 3]
        in (["ldarg.1", "ldc.i4.m1", "bne.un"], ["ldarg.1", "ldc.i4.m1", "bne.un.s"])
        for index in range(len(opcodes) - 2)
    )
    if not sentinel:
        raise RemcosEazRecoveryError("crypto_aes_sentinel_branch_missing")
    return candidate


def _decode_selected_method(
    data: bytes,
    pe: Any,
    token: int,
    *,
    deadline: float,
    clock: Callable[[], float],
) -> Any:
    rid = token & 0xFFFFFF
    rows = list(getattr(pe.net.mdtables.MethodDef, "rows", ()) or ())
    if not 1 <= rid <= len(rows):
        raise RemcosEazRecoveryError("method_token_out_of_bounds")
    try:
        return _decode_method(
            data,
            pe,
            rows[rid - 1],
            token,
            deadline=deadline,
            clock=clock,
        )
    except EazRecoveryError as exc:
        raise RemcosEazRecoveryError(str(exc)) from exc


def _canonical_exception_handlers(
    data: bytes,
    pe: Any,
    method: Any,
    decoded: Any,
    offsets: dict[int, int],
    type_names: dict[int, str],
    token_map: dict[tuple[int, int], int],
) -> tuple[list[list[object]], bool]:
    """source-bound method bodyからEH clause全体をtoken非依存に正規化する。"""

    rid = method.token & 0xFFFFFF
    rows = list(getattr(pe.net.mdtables.MethodDef, "rows", ()) or ())
    if method.token >> 24 != 0x06 or not 1 <= rid <= len(rows):
        raise RemcosEazRecoveryError("cil_eh_method_token_invalid")
    row = rows[rid - 1]
    rva = int(getattr(row, "Rva", 0) or 0)
    try:
        file_offset = int(pe.get_offset_from_rva(rva))
        bounded = _bounded_method_body_data(data, pe, rva, file_offset)
        body = read_method_body_from_bytes(bounded)
    except Exception as exc:
        raise RemcosEazRecoveryError("cil_eh_source_parse_failed") from exc
    if (
        int(getattr(body, "size", 0) or 0) != int(method.body_size)
        or int(getattr(body, "code_size", 0) or 0) != int(decoded.code_size)
        or len(tuple(getattr(body, "instructions", ()) or ()))
        != len(decoded.instructions)
    ):
        raise RemcosEazRecoveryError("cil_eh_source_method_mismatch")
    handlers = tuple(getattr(body, "exception_handlers", ()) or ())
    more_sections = bool(getattr(getattr(body, "flags", None), "MoreSects", False))
    exception_bytes = int(getattr(body, "exception_handlers_size", -1))
    if (
        more_sections is not bool(handlers)
        or exception_bytes < 0
        or len(handlers) != decoded.exception_handler_count
        or more_sections is not decoded.has_extra_sections
    ):
        raise RemcosEazRecoveryError("cil_eh_section_shape_invalid")

    header_size = int(getattr(body, "header_size", 0) or 0)
    code_end = header_size + decoded.code_size
    boundary_indices = dict(offsets)
    boundary_indices[code_end] = len(decoded.instructions)

    def boundary(value: object, *, allow_absent: bool = False) -> object:
        if allow_absent and value == -1:
            return None
        if isinstance(value, bool) or not isinstance(value, int):
            raise RemcosEazRecoveryError("cil_eh_boundary_invalid")
        absolute = header_size + value
        if absolute not in boundary_indices:
            raise RemcosEazRecoveryError("cil_eh_boundary_out_of_bounds")
        return boundary_indices[absolute]

    result: list[list[object]] = []
    for handler in handlers:
        flags = getattr(handler, "exception_type", None)
        if (
            isinstance(flags, bool)
            or not isinstance(flags, int)
            or flags not in {0, 1, 2, 4}
        ):
            raise RemcosEazRecoveryError("cil_eh_flags_invalid")
        catch_token = getattr(getattr(handler, "catch_type", None), "value", None)
        if catch_token == 0:
            catch_token = None
        if catch_token is not None and (
            isinstance(catch_token, bool) or not isinstance(catch_token, int)
        ):
            raise RemcosEazRecoveryError("cil_eh_catch_token_invalid")
        if (flags == 0) is not (catch_token is not None):
            raise RemcosEazRecoveryError("cil_eh_catch_token_shape_invalid")
        canonical_catch: object = None
        if catch_token is not None:
            kind = catch_token >> 24
            if kind not in {0x01, 0x02, 0x1B}:
                raise RemcosEazRecoveryError("cil_eh_catch_token_kind_invalid")
            resolved = type_names.get(catch_token, "")
            canonical_catch = (
                ["framework", resolved]
                if resolved.startswith("System.")
                else [
                    "token",
                    kind,
                    token_map.setdefault((kind, catch_token), len(token_map)),
                ]
            )
        filter_start = getattr(handler, "filter_start", None)
        canonical_filter = boundary(filter_start, allow_absent=flags != 1)
        if flags == 1 and canonical_filter is None:
            raise RemcosEazRecoveryError("cil_eh_filter_boundary_missing")
        result.append(
            [
                flags,
                boundary(getattr(handler, "try_start", None)),
                boundary(getattr(handler, "try_end", None)),
                boundary(getattr(handler, "handler_start", None)),
                boundary(getattr(handler, "handler_end", None)),
                canonical_filter,
                canonical_catch,
            ]
        )
    return result, more_sections


def _canonical_method_digest(
    data: bytes,
    pe: Any,
    method: Any,
    roles: dict[int, str],
    type_names: dict[int, str],
    *,
    opaque_large_constants: bool,
    deadline: float,
    clock: Callable[[], float],
) -> tuple[str, Any]:
    """token/local/targetを正規化し、EHを含む完全CIL digestを返す。"""

    decoded = _decode_selected_method(
        data,
        pe,
        method.token,
        deadline=deadline,
        clock=clock,
    )
    normalized = {item.offset: item for item in method.instructions}
    offsets = {item.offset: index for index, item in enumerate(decoded.instructions)}
    if len(normalized) != len(decoded.instructions):
        raise RemcosEazRecoveryError("cil_model_instruction_mismatch")
    local_map: dict[int, int] = {}
    token_map: dict[tuple[int, int], int] = {}
    rows: list[list[object]] = []
    for index, item in enumerate(decoded.instructions):
        if index % TIME_CHECK_INTERVAL == 0:
            _check_time(deadline, clock, stage="strict_cil_profile")
        known = normalized.get(item.offset)
        if known is None or known.opcode != item.opcode:
            raise RemcosEazRecoveryError("cil_model_instruction_mismatch")
        operand: object
        if item.opcode in _BRANCH_OPCODES:
            if not isinstance(item.operand, int):
                raise RemcosEazRecoveryError("cil_branch_target_invalid")
            if item.operand not in offsets:
                raise RemcosEazRecoveryError("cil_branch_target_out_of_bounds")
            operand = ["target", offsets[item.operand]]
        elif item.opcode == "switch":
            if not isinstance(item.operand, list) or any(
                not isinstance(target, int) for target in item.operand
            ):
                raise RemcosEazRecoveryError("cil_switch_targets_invalid")
            if any(target not in offsets for target in item.operand):
                raise RemcosEazRecoveryError("cil_switch_target_out_of_bounds")
            operand = [
                "targets",
                [offsets[target] for target in item.operand],
            ]
        elif known.local is not None:
            operand = [
                "local",
                local_map.setdefault(known.local, len(local_map)),
            ]
        elif known.user_string is not None:
            operand = [
                "string",
                "empty" if known.user_string == "" else "private",
            ]
        elif known.token is not None:
            if known.token in roles:
                operand = ["role", roles[known.token]]
            elif known.resolved.startswith("System."):
                operand = ["framework", known.resolved]
            else:
                kind = known.token >> 24
                key = (kind, known.token)
                operand = [
                    "token",
                    kind,
                    token_map.setdefault(key, len(token_map)),
                ]
        elif known.integer is not None:
            value: object = known.integer
            if opaque_large_constants and not -1_024 <= known.integer <= 1_024:
                value = "opaque"
            operand = ["int", value]
        elif item.operand is not None:
            operand = ["other", type(item.operand).__name__]
        else:
            operand = None
        rows.append([item.opcode, operand])
    exception_handlers, has_extra_sections = _canonical_exception_handlers(
        data,
        pe,
        method,
        decoded,
        offsets,
        type_names,
        token_map,
    )
    shape = {
        "signature": _method_signature(method).hex(),
        "flags": [
            method.is_static,
            method.is_public,
            method.is_special_name,
            method.is_runtime_special_name,
        ],
        "eh": exception_handlers,
        "extra": has_extra_sections,
        "rows": rows,
    }
    digest = _sha256(json.dumps(shape, separators=(",", ":")).encode("ascii"))
    return digest, decoded


def _strict_role_profile(
    data: bytes,
    pe: Any,
    selected: dict[str, Any],
    *,
    deadline: float,
    clock: Callable[[], float],
) -> tuple[str, dict[str, str]]:
    """6 review済みbundleのいずれかへ全roleを同時に束縛する。"""

    resolver = selected["resolver"]
    crypto = selected["crypto"]
    transform = selected["transform"]
    b0 = selected["b0"]
    b1 = selected["b1"]
    b2 = selected["b2"]
    if not (
        resolver.owner_token == crypto.owner_token == transform.owner_token
        and b0.owner_token == b1.owner_token == b2.owner_token
        and resolver.owner_token != b0.owner_token
    ):
        raise RemcosEazRecoveryError("strict_role_owner_relationship_mismatch")
    roles = {method.token: role for role, method in selected.items()}
    metadata_rows = _row_tokens(pe.net.mdtables, deadline, clock)
    type_names, _method_names, _field_names = _metadata_names(
        pe,
        metadata_rows,
        deadline,
        clock,
    )
    digests: dict[str, str] = {}
    for role, method in selected.items():
        digest, _decoded = _canonical_method_digest(
            data,
            pe,
            method,
            roles,
            type_names,
            opaque_large_constants=role == "transform",
            deadline=deadline,
            clock=clock,
        )
        digests[role] = digest
    if digests["resolver"] != _RESOLVER_CIL_SHA256:
        raise RemcosEazRecoveryError("strict_resolver_cil_profile_mismatch")
    if digests["transform"] != _TRANSFORM_CIL_SHA256:
        raise RemcosEazRecoveryError("strict_transform_cil_profile_mismatch")
    matches = [
        profile
        for profile in _STRICT_ROLE_PROFILES
        if all(digests[role] == profile[role] for role in ("crypto", "b0", "b1", "b2"))
    ]
    if len(matches) != 1:
        raise RemcosEazRecoveryError("strict_role_bundle_mismatch")
    return str(matches[0]["profile"]), digests


def _method_owner_tokens(pe: Any) -> dict[int, int]:
    owners: dict[int, int] = {}
    for type_index, row in enumerate(pe.net.mdtables.TypeDef.rows, 1):
        owner = 0x02000000 | type_index
        for reference in getattr(row, "MethodList", ()) or ():
            token = 0x06000000 | int(reference.row_index)
            if token in owners:
                raise RemcosEazRecoveryError("method_owner_ambiguous")
            owners[token] = owner
    return owners


def _compressed_uint(data: bytes, position: int) -> tuple[int, int]:
    if position >= len(data):
        raise RemcosEazRecoveryError("signature_integer_truncated")
    first = data[position]
    if first < 0x80:
        return first, position + 1
    if first < 0xC0:
        if position + 2 > len(data):
            raise RemcosEazRecoveryError("signature_integer_truncated")
        value = ((first & 0x3F) << 8) | data[position + 1]
        if value < 0x80:
            raise RemcosEazRecoveryError("signature_integer_noncanonical")
        return value, position + 2
    if first < 0xE0:
        if position + 4 > len(data):
            raise RemcosEazRecoveryError("signature_integer_truncated")
        value = (
            ((first & 0x1F) << 24)
            | (data[position + 1] << 16)
            | (data[position + 2] << 8)
            | data[position + 3]
        )
        if value < 0x4000:
            raise RemcosEazRecoveryError("signature_integer_noncanonical")
        return value, position + 4
    raise RemcosEazRecoveryError("signature_integer_invalid")


def _signature_type_end(data: bytes, position: int, *, depth: int = 0) -> int:
    if depth > 8 or position >= len(data):
        raise RemcosEazRecoveryError("signature_type_truncated_or_deep")
    element = data[position]
    position += 1
    if element in {
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x06,
        0x07,
        0x08,
        0x09,
        0x0A,
        0x0B,
        0x0C,
        0x0D,
        0x0E,
        0x16,
        0x18,
        0x19,
        0x1C,
    }:
        return position
    if element in {0x0F, 0x10, 0x1D, 0x45}:
        return _signature_type_end(data, position, depth=depth + 1)
    if element in {0x11, 0x12, 0x13, 0x1E}:
        _value, position = _compressed_uint(data, position)
        return position
    if element == 0x15:
        if position >= len(data) or data[position] not in {0x11, 0x12}:
            raise RemcosEazRecoveryError("signature_genericinst_kind_invalid")
        position += 1
        _value, position = _compressed_uint(data, position)
        count, position = _compressed_uint(data, position)
        if count > 32:
            raise RemcosEazRecoveryError("signature_genericinst_arity_limit")
        for _ in range(count):
            position = _signature_type_end(data, position, depth=depth + 1)
        return position
    raise RemcosEazRecoveryError("signature_type_not_reviewed")


def _method_signature_parts(blob: bytes) -> tuple[bool, bytes, tuple[bytes, ...]]:
    if not isinstance(blob, bytes) or not blob or len(blob) > 512:
        raise RemcosEazRecoveryError("method_signature_invalid")
    flags = blob[0]
    if flags & 0x10 or flags & 0x40 or flags & 0x0F:
        raise RemcosEazRecoveryError("method_signature_convention_not_reviewed")
    count, position = _compressed_uint(blob, 1)
    if count > 32:
        raise RemcosEazRecoveryError("method_signature_parameter_limit")
    start = position
    position = _signature_type_end(blob, position)
    result = blob[start:position]
    parameters = []
    for _ in range(count):
        start = position
        position = _signature_type_end(blob, position)
        parameters.append(blob[start:position])
    if position != len(blob):
        raise RemcosEazRecoveryError("method_signature_trailing_data")
    return bool(flags & 0x20), result, tuple(parameters)


def _field_signature_type(blob: bytes) -> bytes:
    if not isinstance(blob, bytes) or not blob or len(blob) > 512 or blob[0] != 0x06:
        raise RemcosEazRecoveryError("field_signature_invalid")
    end = _signature_type_end(blob, 1)
    if end != len(blob):
        raise RemcosEazRecoveryError("field_signature_trailing_data")
    return blob[1:end]


def _type_signature_token(signature: bytes) -> int | None:
    if not signature or signature[0] not in {0x11, 0x12}:
        return None
    coded, end = _compressed_uint(signature, 1)
    if end != len(signature) or coded & 3 not in {0, 1, 2} or not coded >> 2:
        return None
    return ({0: 0x02, 1: 0x01, 2: 0x1B}[coded & 3] << 24) | (coded >> 2)


def _argument_index(instruction: Any) -> int | None:
    match = re.fullmatch(r"ldarg\.([0-3])", instruction.opcode)
    if match:
        return int(match.group(1))
    if instruction.opcode not in {"ldarg", "ldarg.s"}:
        return None
    operand = instruction.operand
    if isinstance(operand, int) and not isinstance(operand, bool):
        return operand
    match = re.fullmatch(r"(?:argument|arg)\(0x([0-9a-fA-F]+)\)", str(operand))
    return int(match.group(1), 16) if match else None


def _validate_delegate_argument_order(
    instructions: Sequence[Any], stack_argument_count: int
) -> None:
    expected = [stack_argument_count, *range(stack_argument_count)]
    actual = [_argument_index(item) for item in instructions]
    if actual != expected:
        raise RemcosEazRecoveryError("proxy_invoke_argument_permutation_mismatch")


def _callable_signature(pe: Any, token: int) -> bytes:
    table_name = {0x06: "MethodDef", 0x0A: "MemberRef"}.get(token >> 24)
    if table_name is None:
        raise RemcosEazRecoveryError("proxy_target_signature_kind_not_reviewed")
    rows = list(getattr(getattr(pe.net.mdtables, table_name, None), "rows", ()) or ())
    rid = token & 0xFFFFFF
    if not 1 <= rid <= len(rows):
        raise RemcosEazRecoveryError("proxy_target_signature_token_bounds")
    signature = getattr(getattr(rows[rid - 1], "Signature", None), "value", None)
    if not isinstance(signature, bytes):
        raise RemcosEazRecoveryError("proxy_target_signature_missing")
    return signature


def _validate_delegate_wrapper_exception_shape(decoded: Any) -> None:
    if decoded.exception_handler_count != 0 or decoded.has_extra_sections is not False:
        raise RemcosEazRecoveryError("proxy_invoke_wrapper_exception_shape")


def _validate_delegate_wrapper(
    data: bytes,
    methods: Sequence[Any],
    pe: Any,
    field_token: int,
    wrapper_token: int,
    *,
    target_token: int,
    call_kind: str,
    cache: set[tuple[int, int, int, str]],
    deadline: float,
    clock: Callable[[], float],
) -> None:
    pair = (field_token, wrapper_token, target_token, call_kind)
    if pair in cache:
        return
    _check_time(deadline, clock, stage="proxy_wrapper")
    by_token = {method.token: method for method in methods}
    wrapper = by_token.get(wrapper_token)
    if wrapper is None or not wrapper.is_static or not wrapper.is_public:
        raise RemcosEazRecoveryError("proxy_invoke_wrapper_missing")
    decoded = _decode_selected_method(
        data,
        pe,
        wrapper_token,
        deadline=deadline,
        clock=clock,
    )
    _validate_delegate_wrapper_exception_shape(decoded)
    meaningful = [item for item in decoded.instructions if item.opcode != "nop"]
    if (
        len(meaningful) < 3
        or meaningful[-2].opcode != "callvirt"
        or meaningful[-1].opcode != "ret"
    ):
        raise RemcosEazRecoveryError("proxy_invoke_wrapper_shape_mismatch")
    invoke_token = meaningful[-2].operand
    if isinstance(invoke_token, bool) or not isinstance(invoke_token, int):
        raise RemcosEazRecoveryError("proxy_invoke_metadata_token_invalid")
    if invoke_token >> 24 != 0x06 or field_token >> 24 != 0x04:
        raise RemcosEazRecoveryError("proxy_invoke_metadata_token_invalid")
    method_rows = list(pe.net.mdtables.MethodDef.rows)
    field_rows = list(pe.net.mdtables.Field.rows)
    invoke_rid = invoke_token & 0xFFFFFF
    field_rid = field_token & 0xFFFFFF
    if not 1 <= invoke_rid <= len(method_rows) or not 1 <= field_rid <= len(field_rows):
        raise RemcosEazRecoveryError("proxy_invoke_metadata_token_bounds")
    invoke_row = method_rows[invoke_rid - 1]
    field_row = field_rows[field_rid - 1]
    owners = _method_owner_tokens(pe)
    delegate_owner = owners.get(invoke_token)
    if delegate_owner is None or delegate_owner >> 24 != 0x02:
        raise RemcosEazRecoveryError("proxy_invoke_owner_missing")
    field_signature = bytes(getattr(field_row.Signature, "value", b""))
    invoke_signature = bytes(getattr(invoke_row.Signature, "value", b""))
    field_type = _field_signature_type(field_signature)
    if _type_signature_token(field_type) != delegate_owner:
        raise RemcosEazRecoveryError("proxy_invoke_delegate_metadata_mismatch")
    target_signature = _callable_signature(pe, target_token)
    target_has_this, target_return, target_parameters = _method_signature_parts(
        target_signature
    )
    invoke_has_this, invoke_return, invoke_parameters = _method_signature_parts(
        invoke_signature
    )
    wrapper_has_this, wrapper_return, wrapper_parameters = _method_signature_parts(
        _method_signature(wrapper)
    )
    expected_call_kind = "callvirt" if target_has_this else "call"
    stack_parameters = (
        (b"\x1c", *target_parameters) if target_has_this else target_parameters
    )
    if (
        call_kind != expected_call_kind
        or not invoke_has_this
        or wrapper_has_this
        or invoke_return != target_return
        or invoke_parameters != stack_parameters
        or wrapper_return != invoke_return
        or wrapper_parameters != (*invoke_parameters, field_type)
        or len(meaningful) != len(stack_parameters) + 3
        or str(getattr(invoke_row, "Name", "")) != "Invoke"
        or int(getattr(invoke_row.struct, "Flags", -1)) != 0x46
    ):
        raise RemcosEazRecoveryError("proxy_invoke_delegate_metadata_mismatch")
    _validate_delegate_argument_order(meaningful[:-2], len(stack_parameters))
    cache.add(pair)


def _proxy_records(
    data: bytes,
    pe: Any,
    resource_scan: Any,
    metadata_resolver: Any,
    *,
    deadline: float,
    clock: Callable[[], float],
) -> dict[int, tuple[int, str]]:
    _check_time(deadline, clock, stage="proxy_analysis")
    remaining = deadline - clock()
    if remaining <= 0:
        raise RemcosEazIncompleteError(
            "elapsed_time_limit",
            incomplete_type="deadline",
            stage="proxy_analysis",
        )
    try:
        result = analyze_modsquare_proxy_profile(
            data,
            pe,
            resource_scan,
            metadata_resolver,
            include_records=True,
            clock=clock,
            max_elapsed_seconds=min(MAX_PROFILE_ELAPSED_SECONDS, remaining),
        )
        _check_time(deadline, clock, stage="proxy_analysis")
        candidates = result["candidates"]
    except (KeyError, TypeError, ValueError) as exc:
        raise RemcosEazIncompleteError(
            "modsquare_proxy_analysis_unavailable",
            incomplete_type="source_binding",
            stage="proxy_analysis",
        ) from exc
    if result.get("status") == "partial_budget" and any(
        "deadline" in str(reason) or "elapsed_time" in str(reason)
        for reason in result.get("budget_exhausted", ())
    ):
        raise RemcosEazIncompleteError(
            "elapsed_time_limit",
            incomplete_type="deadline",
            stage="proxy_analysis",
        )
    if (
        result.get("status") != "matched"
        or result.get("source_coverage_verified") is not True
        or not isinstance(candidates, list)
        or len(candidates) != 1
    ):
        raise RemcosEazIncompleteError(
            "modsquare_proxy_analysis_incomplete",
            incomplete_type="source_binding",
            stage="proxy_analysis",
        )
    records = candidates[0].get("records")
    if not isinstance(records, list) or not records:
        raise RemcosEazRecoveryError("modsquare_proxy_records_missing")
    resolved: dict[int, tuple[int, str]] = {}
    for index, record in enumerate(records):
        if index % 256 == 0:
            _check_time(deadline, clock, stage="proxy_analysis")
        try:
            if record.get("valid") is not True:
                raise ValueError
            field = int(record["field_token"], 16)
            target = int(record["target_token"], 16)
            call_kind = record["call_kind"]
        except (AttributeError, KeyError, TypeError, ValueError) as exc:
            raise RemcosEazRecoveryError("modsquare_proxy_record_invalid") from exc
        if call_kind not in {"call", "callvirt"} or field in resolved:
            raise RemcosEazRecoveryError("modsquare_proxy_record_ambiguous")
        resolved[field] = (target, call_kind)
    return resolved


def _reachable_instruction_indices(
    decoded: Any, *, allow_reviewed_exception_shape: bool = False
) -> set[int]:
    """EHなしCILのsource-bound CFGからentry到達命令だけを返す。"""

    instructions = tuple(decoded.instructions)
    if not instructions or (
        not allow_reviewed_exception_shape
        and (
            decoded.exception_handler_count != 0
            or decoded.has_extra_sections is not False
        )
    ):
        raise RemcosEazRecoveryError("proxy_graph_exception_shape_not_reviewed")
    offsets = {item.offset: index for index, item in enumerate(instructions)}
    if len(offsets) != len(instructions):
        raise RemcosEazRecoveryError("proxy_graph_instruction_offset_ambiguous")
    terminal = frozenset({"ret", "throw", "rethrow", "endfinally", "endfilter"})
    unconditional = frozenset({"br", "br.s", "leave", "leave.s"})
    successors: dict[int, tuple[int, ...]] = {}
    for index, item in enumerate(instructions):
        fallthrough = index + 1
        if item.opcode in _BRANCH_OPCODES:
            if isinstance(item.operand, bool) or not isinstance(item.operand, int):
                raise RemcosEazRecoveryError("proxy_graph_branch_target_invalid")
            target = offsets.get(item.operand)
            if target is None:
                raise RemcosEazRecoveryError("proxy_graph_branch_target_out_of_bounds")
            if item.opcode in unconditional:
                successors[index] = (target,)
            elif fallthrough < len(instructions):
                successors[index] = (target, fallthrough)
            else:
                raise RemcosEazRecoveryError("proxy_graph_fallthrough_out_of_bounds")
        elif item.opcode == "switch":
            if not isinstance(item.operand, list) or any(
                isinstance(target, bool)
                or not isinstance(target, int)
                or target not in offsets
                for target in item.operand
            ):
                raise RemcosEazRecoveryError("proxy_graph_switch_target_invalid")
            if fallthrough >= len(instructions):
                raise RemcosEazRecoveryError("proxy_graph_fallthrough_out_of_bounds")
            successors[index] = (
                *[offsets[target] for target in item.operand],
                fallthrough,
            )
        elif item.opcode in terminal:
            successors[index] = ()
        elif fallthrough < len(instructions):
            successors[index] = (fallthrough,)
        else:
            raise RemcosEazRecoveryError("proxy_graph_method_falls_through")
    reachable: set[int] = set()
    queue = [0]
    while queue:
        index = queue.pop()
        if index in reachable:
            continue
        reachable.add(index)
        queue.extend(successors[index])
    return reachable


def _proxy_semantic_reachable(
    data: bytes,
    methods: Sequence[Any],
    pe: Any,
    method_names: dict[int, str],
    proxy: dict[int, tuple[int, str]],
    start_token: int,
    expected: str,
    *,
    wrapper_cache: set[tuple[int, int, int, str]],
    deadline: float,
    clock: Callable[[], float],
    reviewed_exception_tokens: frozenset[int] = frozenset(),
) -> int:
    by_token = {method.token: method for method in methods}
    queue = [(start_token, 0)]
    visited: set[int] = set()
    while queue:
        _check_time(deadline, clock, stage="proxy_graph")
        token, depth = queue.pop(0)
        if token in visited or depth > 16:
            continue
        visited.add(token)
        if len(visited) > 256:
            raise RemcosEazIncompleteError(
                "proxy_graph_node_limit",
                incomplete_type="quota",
                stage="proxy_graph",
                observed=len(visited),
                limit=256,
            )
        method = by_token.get(token)
        if method is None:
            continue
        decoded = _decode_selected_method(
            data,
            pe,
            method.token,
            deadline=deadline,
            clock=clock,
        )
        reachable = _reachable_instruction_indices(
            decoded,
            allow_reviewed_exception_shape=token in reviewed_exception_tokens,
        )
        instructions = tuple(decoded.instructions)
        for index in sorted(reachable):
            item = instructions[index]
            if item.opcode in {"call", "callvirt", "newobj"}:
                target_token = item.operand
                if (
                    isinstance(target_token, int)
                    and method_names.get(target_token) == expected
                ):
                    return depth + 1
                if isinstance(target_token, int) and target_token in by_token:
                    queue.append((target_token, depth + 1))
            if (
                item.opcode == "ldsfld"
                and isinstance(item.operand, int)
                and item.operand in proxy
                and index + 1 in reachable
                and instructions[index + 1].opcode == "call"
                and isinstance(instructions[index + 1].operand, int)
            ):
                field_token = item.operand
                wrapper_token = instructions[index + 1].operand
                _validate_delegate_wrapper(
                    data,
                    methods,
                    pe,
                    field_token,
                    wrapper_token,
                    target_token=proxy[field_token][0],
                    call_kind=proxy[field_token][1],
                    cache=wrapper_cache,
                    deadline=deadline,
                    clock=clock,
                )
                target, _call_kind = proxy[field_token]
                if method_names.get(target) == expected:
                    return depth + 1
                if target in by_token:
                    queue.append((target, depth + 1))
    raise RemcosEazRecoveryError("proxy_semantic_sink_unreachable")


def _validate_proxy_bindings(
    data: bytes,
    pe: Any,
    methods: Sequence[Any],
    method_names: dict[int, str],
    resource_scan: Any,
    metadata_resolver: Any,
    *,
    resolver: Any,
    b0: Any,
    b1: Any,
    b2: Any,
    field2a: int,
    field2b: int,
    field2c: int,
    resolver_proxy_field: int,
    resolver_proxy_call: int,
    deadline: float,
    clock: Callable[[], float],
) -> tuple[int, int, int]:
    """resolver/B0/resource getter/Assembly.Loadをproxy表へ結び付ける。"""

    proxy = _proxy_records(
        data,
        pe,
        resource_scan,
        metadata_resolver,
        deadline=deadline,
        clock=clock,
    )
    if proxy.get(resolver_proxy_field) != (resolver.token, "call"):
        raise RemcosEazRecoveryError("resolver_proxy_target_mismatch")
    wrapper_cache: set[tuple[int, int, int, str]] = set()
    _validate_delegate_wrapper(
        data,
        methods,
        pe,
        resolver_proxy_field,
        resolver_proxy_call,
        target_token=resolver.token,
        call_kind="call",
        cache=wrapper_cache,
        deadline=deadline,
        clock=clock,
    )

    compact = [item for item in b1.instructions if item.opcode != "nop"]
    windows = []
    for index in range(len(compact) - 6):
        window = compact[index : index + 7]
        if (
            [item.opcode for item in window]
            == [
                "ldsfld",
                "ldsfld",
                "call",
                "ldsfld",
                "ldsfld",
                "call",
                "stsfld",
            ]
            and window[0].token == field2b
            and window[3].token == field2a
            and window[6].token == field2c
            and all(window[position].token is not None for position in (1, 2, 4, 5))
        ):
            windows.append(window)
    if len(windows) != 1:
        raise RemcosEazRecoveryError("payload_binding_proxy_window_ambiguous")
    window = windows[0]
    resource_field = int(window[1].token)
    resource_call = int(window[2].token)
    transform_field = int(window[4].token)
    transform_call = int(window[5].token)
    resource_target = proxy.get(resource_field)
    if resource_target is None or resource_target[1] != "call":
        raise RemcosEazRecoveryError("resource_accessor_proxy_missing")
    if proxy.get(transform_field) != (b0.token, "call"):
        raise RemcosEazRecoveryError("payload_transform_proxy_target_mismatch")
    _validate_delegate_wrapper(
        data,
        methods,
        pe,
        resource_field,
        resource_call,
        target_token=resource_target[0],
        call_kind=resource_target[1],
        cache=wrapper_cache,
        deadline=deadline,
        clock=clock,
    )
    _validate_delegate_wrapper(
        data,
        methods,
        pe,
        transform_field,
        transform_call,
        target_token=b0.token,
        call_kind="call",
        cache=wrapper_cache,
        deadline=deadline,
        clock=clock,
    )
    by_token = {method.token: method for method in methods}
    resource_accessor = by_token.get(resource_target[0])
    if (
        resource_accessor is None
        or resource_accessor.owner_token != b1.owner_token
        or _method_signature(resource_accessor) != b"\x00\x01\x1d\x05\x0e"
        or not resource_accessor.is_static
        or not resource_accessor.is_public
    ):
        raise RemcosEazRecoveryError("resource_accessor_method_shape_mismatch")
    resource_depth = _proxy_semantic_reachable(
        data,
        methods,
        pe,
        method_names,
        proxy,
        resource_accessor.token,
        "System.Resources.ResourceManager::GetObject",
        wrapper_cache=wrapper_cache,
        deadline=deadline,
        clock=clock,
    )
    load_depth = _proxy_semantic_reachable(
        data,
        methods,
        pe,
        method_names,
        proxy,
        b2.token,
        "System.Reflection.Assembly::Load",
        wrapper_cache=wrapper_cache,
        deadline=deadline,
        clock=clock,
        reviewed_exception_tokens=frozenset({b2.token}),
    )
    return len(wrapper_cache), resource_depth, load_depth


def _array_recipe(
    data: bytes,
    pe: Any,
    method: Any,
    *,
    deadline: float,
    clock: Callable[[], float],
) -> _ArrayRecipe:
    byte_tokens = _system_byte_tokens(pe)
    profile = _dispatcher_profile(method.instructions)
    helpers = _helper_constants(
        data,
        pe,
        method.instructions,
        profile[3],
        deadline=deadline,
        clock=clock,
    )
    states: list[int] = []
    for index in range(2, len(method.instructions)):
        allocation = _array_allocation(method.instructions, index, byte_tokens)
        if allocation is None or allocation[1] != 32:
            continue
        states.extend(
            state
            for state, target in enumerate(profile[1])
            if target == method.instructions[index - 2].offset
        )
    if len(states) != 1:
        raise RemcosEazRecoveryError("key_allocation_state_ambiguous")
    try:
        trace = trace_flattened_switch(
            method.instructions,
            dispatcher_offset=method.instructions[profile[0]].offset,
            initial_state=states[0],
            helper_constants=helpers,
            extra_state_targets=profile[4],
            dispatch_offsets=profile[3],
            max_states=MAX_TRACE_STATES,
            stop_on_other_conditionals=True,
        )
    except StaticRecoveryError as exc:
        raise RemcosEazRecoveryError("constant_array_trace_failed") from exc

    scalars: dict[int, int] = {}
    sizes: dict[int, int] = {}
    values: dict[int, dict[int, int]] = {}
    aliases: dict[int, int] = {}
    processed_offsets: set[int] = set()
    for block in trace.blocks:
        _check_time(deadline, clock, stage="constant_arrays")
        for index, instruction in enumerate(block.instructions):
            # flattened CFGの隣接blockは境界instructionを共有することがある。
            # 同じCIL offsetは一度だけ解釈し、実行回数を推測しない。
            if instruction.offset in processed_offsets:
                continue
            processed_offsets.add(instruction.offset)
            allocation = _array_allocation(block.instructions, index, byte_tokens)
            if allocation:
                if allocation[0] in sizes:
                    raise RemcosEazRecoveryError("constant_array_local_reused")
                sizes[allocation[0]] = allocation[1]
                values[allocation[0]] = {}
            try:
                assignment = _scalar_assignment(block.instructions, index, scalars)
            except StaticRecoveryError as exc:
                raise RemcosEazRecoveryError("constant_scalar_invalid") from exc
            if assignment:
                scalars[assignment[0]] = assignment[1]
            try:
                store = _array_store(block.instructions, index, scalars)
            except StaticRecoveryError as exc:
                raise RemcosEazRecoveryError("constant_array_store_invalid") from exc
            if store and store[0] in sizes:
                # 同一indexの後続storeはCIL上の最終値で上書きする。対象method
                # 自体は後段のexact canonical profileで固定し、未知rewriteは通さない。
                values[store[0]][store[1]] = store[2]
            try:
                local = _local_index(instruction, "ldloc")
            except StaticRecoveryError as exc:
                raise RemcosEazRecoveryError("constant_array_local_invalid") from exc
            if local in sizes and index + 1 < len(block.instructions):
                try:
                    alias = _local_index(block.instructions[index + 1], "stloc")
                except StaticRecoveryError as exc:
                    raise RemcosEazRecoveryError(
                        "constant_array_alias_invalid"
                    ) from exc
                if alias is not None:
                    if local in aliases and aliases[local] != alias:
                        raise RemcosEazRecoveryError("constant_array_alias_ambiguous")
                    aliases[local] = alias

    recovered: dict[int, tuple[bytes, int]] = {}
    for local, size in sizes.items():
        if size not in {16, 32}:
            continue
        if set(values[local]) != set(range(size)) or local not in aliases:
            continue
        if size in recovered:
            raise RemcosEazRecoveryError("constant_array_size_ambiguous")
        recovered[size] = (
            bytes(values[local][index] for index in range(size)),
            len(values[local]),
        )
    if set(recovered) != {16, 32}:
        raise RemcosEazRecoveryError("constant_arrays_incomplete")
    return _ArrayRecipe(
        key=recovered[32][0],
        mask=recovered[16][0],
        traced_states=len(trace.blocks),
        key_store_count=recovered[32][1],
        mask_store_count=recovered[16][1],
    )


def _find_resolver(
    methods: Sequence[Any],
    crypto_token: int,
    resources: Sequence[_ManifestResource],
    *,
    deadline: float,
    clock: Callable[[], float],
) -> tuple[Any, _ManifestResource]:
    by_name = {resource.name: resource for resource in resources}
    candidates: list[tuple[Any, _ManifestResource]] = []
    for method_index, method in enumerate(methods):
        if method_index % 256 == 0:
            _check_time(deadline, clock, stage="string_resolver_scan")
        if _method_signature(method) != _RESOLVER_SIGNATURE or not method.is_static:
            continue
        apis = {
            item.resolved
            for item in method.instructions
            if item.opcode in {"call", "callvirt", "newobj"}
        }
        if not _RESOLVER_REQUIRED_APIS.issubset(apis):
            continue
        if (
            sum(
                item.opcode == "call" and item.token == crypto_token
                for item in method.instructions
            )
            != 1
        ):
            continue
        literals = [
            item.user_string
            for item in method.instructions
            if item.user_string is not None
        ]
        selected = [by_name[value] for value in literals if value in by_name]
        if len(selected) != 1 or "" not in literals:
            continue
        candidates.append((method, selected[0]))
    if len(candidates) != 1:
        raise RemcosEazRecoveryError("string_resolver_candidate_ambiguous_or_missing")
    return candidates[0]


def _next_accumulator(previous: int, constants: Sequence[int]) -> int:
    value0, value1, value2, value3 = constants
    mixed = previous
    modulus = _u32(value2 * 432_322_986)
    if modulus == 0:
        modulus = (1 << 64) - 1
    value3 = _u32(_u32(value3 * value3) % modulus)
    value2 = _u32(36_951 * (value2 & 0xFFFF) + (value2 >> 16))
    value3 = _u32(40_498 * (value3 & 0xFFFF) - (value3 >> 16))
    value1 = _u32(19_870 * value1 - value0 + value3)
    value2 = _u32((value2 << 15) | (value2 >> 17))
    modulus = _u32(value3 * 88_665_022) | 1
    mixed = _u32(_u32(mixed * mixed) % modulus)
    mixed = _u32(mixed ^ (mixed >> 2))
    mixed = _u32(mixed + value1)
    mixed = _u32(mixed ^ (mixed >> 17))
    mixed = _u32(mixed + value2)
    mixed = _u32(mixed ^ _u32(mixed << 15))
    mixed = _u32(mixed + mixed)
    mixed = _u32((((value1 << 5) + value1) ^ value2) + mixed)
    return _u32(previous + mixed)


def _decrypt_string_table(
    encrypted: bytes,
    arrays: _ArrayRecipe,
    constants: Sequence[int],
    *,
    deadline: float,
    clock: Callable[[], float],
) -> bytes:
    if not 0 < len(encrypted) <= MAX_STRING_TABLE_BYTES:
        raise RemcosEazIncompleteError(
            "string_table_byte_limit",
            incomplete_type="quota",
            stage="string_table_transform",
            observed=len(encrypted),
            limit=MAX_STRING_TABLE_BYTES,
        )
    effective = bytearray(arrays.key)
    mask = arrays.mask[::-1]
    if len(effective) != 32 or len(mask) != 16:
        raise RemcosEazRecoveryError("key_mask_length_mismatch")
    for index, value in enumerate(mask):
        effective[index] ^= value
    words = struct.unpack("<8I", effective)
    output = bytearray(len(encrypted))
    accumulator = 0
    for word_index, offset in enumerate(range(0, len(encrypted), 4)):
        if word_index % TIME_CHECK_INTERVAL == 0:
            _check_time(deadline, clock, stage="string_table_transform")
        accumulator = _u32(accumulator + words[word_index % 8])
        accumulator = _next_accumulator(accumulator, constants)
        chunk = encrypted[offset : offset + 4]
        clear = (int.from_bytes(chunk, "little") ^ accumulator).to_bytes(4, "little")
        output[offset : offset + len(chunk)] = clear[: len(chunk)]
    return bytes(output)


def _parse_string_table(
    clear: bytes,
    *,
    deadline: float,
    clock: Callable[[], float],
) -> list[_StringEntry]:
    entries: list[_StringEntry] = []
    cursor = 0
    while cursor < len(clear):
        if len(entries) % 256 == 0:
            _check_time(deadline, clock, stage="string_table_parse")
        _bounded_count(
            len(entries) + 1,
            MAX_STRING_TABLE_ENTRIES,
            stage="string_table_parse",
            reason="string_table_entry_limit",
        )
        if cursor + 4 > len(clear):
            raise RemcosEazRecoveryError("string_table_length_truncated")
        length = struct.unpack_from("<i", clear, cursor)[0]
        end = cursor + 4 + length
        if length < 0 or length % 2 or end > len(clear):
            raise RemcosEazRecoveryError("string_table_entry_bounds")
        raw = clear[cursor + 4 : end]
        try:
            value = raw.decode("utf-16le", errors="strict")
        except UnicodeDecodeError as exc:
            raise RemcosEazRecoveryError("string_table_utf16_invalid") from exc
        entries.append(_StringEntry(cursor, raw, value))
        cursor = end
    if not entries or cursor != len(clear):
        raise RemcosEazRecoveryError("string_table_not_exact")
    return entries


def _field_metadata(
    pe: Any,
    *,
    deadline: float,
    clock: Callable[[], float],
) -> tuple[dict[int, bytes], dict[int, int]]:
    rows = list(getattr(pe.net.mdtables.Field, "rows", ()) or ())
    _bounded_count(
        len(rows),
        MAX_METADATA_ROWS,
        stage="field_metadata",
        reason="field_row_limit",
    )
    signatures: dict[int, bytes] = {}
    owners: dict[int, int] = {}
    for index, row in enumerate(rows, 1):
        if index % 256 == 0:
            _check_time(deadline, clock, stage="field_metadata")
        raw = getattr(getattr(row, "Signature", None), "value", None)
        if not isinstance(raw, (bytes, bytearray)):
            raise RemcosEazRecoveryError("field_signature_unavailable")
        signatures[0x04000000 | index] = bytes(raw)
    for type_index, row in enumerate(pe.net.mdtables.TypeDef.rows, 1):
        if type_index % 256 == 0:
            _check_time(deadline, clock, stage="field_metadata")
        owner = 0x02000000 | type_index
        for reference in getattr(row, "FieldList", ()) or ():
            field_index = int(reference.row_index)
            token = 0x04000000 | field_index
            if token in owners:
                raise RemcosEazRecoveryError("field_owner_ambiguous")
            owners[token] = owner
    return signatures, owners


def _find_loader_methods(
    methods: Sequence[Any],
    pe: Any,
    *,
    deadline: float,
    clock: Callable[[], float],
) -> tuple[Any, Any, Any, int, int, int]:
    signatures, owners = _field_metadata(pe, deadline=deadline, clock=clock)
    bindings: list[tuple[Any, int, int, int]] = []
    for method_index, method in enumerate(methods):
        if method_index % 256 == 0:
            _check_time(deadline, clock, stage="loader_binding_scan")
        compact = [item for item in method.instructions if item.opcode != "nop"]
        for index in range(len(compact) - 6):
            window = compact[index : index + 7]
            if [item.opcode for item in window] != [
                "ldsfld",
                "ldsfld",
                "call",
                "ldsfld",
                "ldsfld",
                "call",
                "stsfld",
            ]:
                continue
            first, second, output = window[0].token, window[3].token, window[6].token
            if not all(
                isinstance(token, int) and token >> 24 == 0x04
                for token in (first, second, output)
            ):
                continue
            if (
                signatures.get(first) != _STRING_FIELD_SIGNATURE
                or signatures.get(second) != _STRING_FIELD_SIGNATURE
                or signatures.get(output) != _BYTE_ARRAY_FIELD_SIGNATURE
                or len({owners.get(first), owners.get(second), owners.get(output)}) != 1
                or owners.get(first) != method.owner_token
                or _method_signature(method) != _VOID_SIGNATURE
                or not method.is_static
            ):
                continue
            bindings.append((method, first, second, output))
    if len(bindings) != 1:
        raise RemcosEazRecoveryError("loader_binding_candidate_ambiguous_or_missing")
    b1, field2b, field2a, field2c = bindings[0]

    b0_candidates = []
    for method_index, method in enumerate(methods):
        if method_index % 256 == 0:
            _check_time(deadline, clock, stage="payload_transform_scan")
        if (
            method.owner_token != b1.owner_token
            or _method_signature(method) != _B0_SIGNATURE
        ):
            continue
        counts = Counter(item.opcode for item in method.instructions)
        apis = {item.resolved for item in method.instructions}
        if (
            {"ldelem.u1", "stelem.i1", "rem", "xor", "sub"}.issubset(counts)
            and counts["rem"] == 4
            and counts["ldlen"] == 5
            and counts["stelem.i1"] == 1
            and "System.Array::Resize" in apis
        ):
            b0_candidates.append(method)
    if len(b0_candidates) != 1:
        raise RemcosEazRecoveryError("b0_candidate_ambiguous_or_missing")
    b0 = b0_candidates[0]

    b2_candidates = [
        method
        for method in methods
        if method.owner_token == b1.owner_token
        and method.token != b1.token
        and _method_signature(method) == _VOID_SIGNATURE
        and method.is_static
        and any(
            item.opcode == "ldsfld" and item.token == field2c
            for item in method.instructions
        )
        and not any(
            item.opcode == "stsfld" and item.token == field2c
            for item in method.instructions
        )
    ]
    if len(b2_candidates) != 1:
        raise RemcosEazRecoveryError("b2_candidate_ambiguous_or_missing")
    return b0, b1, b2_candidates[0], field2a, field2b, field2c


_EXPRESSION_BOUNDARIES = frozenset(
    {
        "br",
        "br.s",
        "leave",
        "leave.s",
        "ret",
        "throw",
        "stfld",
        "stsfld",
    }
)


def _binary_expression(opcode: str, left: int, right: int) -> int:
    if opcode == "xor":
        return _u32(left ^ right)
    if opcode == "or":
        return _u32(left | right)
    if opcode == "and":
        return _u32(left & right)
    if opcode == "add":
        return _u32(left + right)
    if opcode == "sub":
        return _u32(left - right)
    if opcode == "mul":
        return _u32(left * right)
    shift = right & 31
    if opcode == "shl":
        return _u32(left << shift)
    if opcode == "shr.un":
        return _u32(left) >> shift
    if opcode == "shr":
        signed = left if left < 0x80000000 else left - (1 << 32)
        return _u32(signed >> shift)
    raise RemcosEazRecoveryError("offset_expression_opcode_not_reviewed")


def _evaluate_expression(
    instructions: Sequence[Any], holder_values: dict[int, int]
) -> int:
    if not instructions or len(instructions) > MAX_EXPRESSION_INSTRUCTIONS:
        raise RemcosEazRecoveryError("offset_expression_instruction_limit")
    stack: list[int] = []
    index = 0
    while index < len(instructions):
        item = instructions[index]
        if isinstance(item.integer, int) and item.opcode.startswith("ldc.i4"):
            stack.append(_u32(item.integer))
        elif (
            item.opcode == "ldsfld"
            and index + 1 < len(instructions)
            and instructions[index + 1].opcode == "ldfld"
        ):
            holder = instructions[index + 1].token
            if holder not in holder_values:
                raise RemcosEazRecoveryError("offset_holder_value_missing")
            stack.append(holder_values[holder])
            index += 1
        elif item.opcode in {"not", "neg"}:
            if not stack:
                raise RemcosEazRecoveryError("offset_expression_stack_underflow")
            value = stack.pop()
            stack.append(_u32(~value if item.opcode == "not" else -value))
        elif item.opcode in {"conv.i4", "conv.u4"}:
            if not stack:
                raise RemcosEazRecoveryError("offset_expression_stack_underflow")
        elif item.opcode in {
            "xor",
            "or",
            "and",
            "add",
            "sub",
            "mul",
            "shl",
            "shr",
            "shr.un",
        }:
            if len(stack) < 2:
                raise RemcosEazRecoveryError("offset_expression_stack_underflow")
            right = stack.pop()
            left = stack.pop()
            stack.append(_binary_expression(item.opcode, left, right))
        else:
            raise RemcosEazRecoveryError("offset_expression_opcode_not_reviewed")
        index += 1
    if len(stack) != 1:
        raise RemcosEazRecoveryError("offset_expression_stack_shape")
    return stack[0]


def _segment_start(compact: Sequence[Any], end: int) -> int:
    start = end
    while start > 0 and end - start < MAX_EXPRESSION_INSTRUCTIONS:
        if compact[start - 1].opcode in _EXPRESSION_BOUNDARIES:
            break
        start -= 1
    return start


def _holder_value(methods: Sequence[Any], holder: int) -> int:
    candidates: list[int] = []
    for method in methods:
        compact = [item for item in method.instructions if item.opcode != "nop"]
        for index, item in enumerate(compact):
            if item.opcode != "stfld" or item.token != holder:
                continue
            start = _segment_start(compact, index)
            segment = compact[start:index]
            if not segment or segment[0].opcode != "ldsfld":
                raise RemcosEazRecoveryError("offset_holder_assignment_shape")
            candidates.append(_evaluate_expression(segment[1:], {}))
    if len(candidates) != 1:
        raise RemcosEazRecoveryError("offset_holder_assignment_ambiguous")
    return candidates[0]


def _field_offset(
    methods: Sequence[Any], owner: int, field: int
) -> tuple[int, int, int]:
    cctors = [
        method
        for method in methods
        if method.owner_token == owner
        and method.name == ".cctor"
        and method.is_static
        and method.is_special_name
        and method.is_runtime_special_name
    ]
    if len(cctors) != 1:
        raise RemcosEazRecoveryError("loader_cctor_ambiguous_or_missing")
    compact = [item for item in cctors[0].instructions if item.opcode != "nop"]
    matches = [
        index
        for index, item in enumerate(compact)
        if item.opcode == "stsfld" and item.token == field
    ]
    if len(matches) != 1:
        raise RemcosEazRecoveryError("string_field_assignment_ambiguous")
    index = matches[0]
    if (
        index < 3
        or compact[index - 1].opcode != "call"
        or compact[index - 2].opcode != "ldsfld"
    ):
        raise RemcosEazRecoveryError("string_field_assignment_shape")
    start = _segment_start(compact, index - 2)
    expression = compact[start : index - 2]
    holders = [
        expression[position + 1].token
        for position, item in enumerate(expression[:-1])
        if item.opcode == "ldsfld" and expression[position + 1].opcode == "ldfld"
    ]
    if not holders or any(not isinstance(holder, int) for holder in holders):
        raise RemcosEazRecoveryError("offset_holder_reference_missing")
    values = {holder: _holder_value(methods, holder) for holder in set(holders)}
    return (
        _evaluate_expression(expression, values),
        int(compact[index - 2].token),
        int(compact[index - 1].token),
    )


def _recover_offsets(
    methods: Sequence[Any], b1: Any, field2a: int, field2b: int
) -> tuple[int, int, int, int]:
    offset2a, proxy_field2a, proxy_call2a = _field_offset(
        methods, b1.owner_token, field2a
    )
    offset2b, proxy_field2b, proxy_call2b = _field_offset(
        methods, b1.owner_token, field2b
    )
    if (proxy_field2a, proxy_call2a) != (proxy_field2b, proxy_call2b):
        raise RemcosEazRecoveryError("string_resolver_proxy_mismatch")
    return offset2a, offset2b, proxy_field2a, proxy_call2a


def _apply_b0(
    data: bytes,
    key: bytes,
    *,
    deadline: float,
    clock: Callable[[], float],
) -> bytes:
    """CIL通りN+1回更新し、完了後にだけ末尾1 byteを縮小する。"""

    if not 1 < len(data) <= MAX_OUTPUT_BYTES or not 0 < len(key) <= 512:
        raise RemcosEazRecoveryError("b0_input_bounds")
    output = bytearray(data)
    length = len(output)
    for index in range(length + 1):
        if index % TIME_CHECK_INTERVAL == 0:
            _check_time(deadline, clock, stage="b0_transform")
        position = index % length
        following = (index + 1) % length
        mixed = output[position] ^ key[index % len(key)]
        output[position] = (mixed - output[following] + 256) % 256
    del output[-1:]
    return bytes(output)


def _base_report(data: bytes) -> dict[str, object]:
    return {
        "schema_version": 1,
        "status": "not_candidate",
        "profile_id": PROFILE_ID,
        "input": {"size": len(data), "sha256": _sha256(data)},
        "sample_executed": False,
        "clr_loaded": False,
        "instruction_emulation_performed": False,
        "network_contacted": False,
        "raw_resource_names_published": False,
        "raw_resource_bytes_published": False,
        "raw_key_published": False,
        "raw_string_table_published": False,
        "raw_config_published": False,
        "family_attribution_allowed": False,
        "c2_confirmation_allowed": False,
        "terminal_promotion_eligible": False,
    }


def recover_managed_eaz_remcos(
    data: bytes,
    *,
    clock: Callable[[], float] = time.monotonic,
    max_elapsed_seconds: float = MAX_ELAPSED_SECONDS,
) -> tuple[dict[str, object], list[tuple[str, bytes]]]:
    """review済みmanaged loaderから終端PEを静的に復元する。"""

    if type(data) is not bytes:
        return {"status": "rejected", "reason": "input_not_exact_bytes"}, []
    report = _base_report(data)
    if not data or len(data) > MAX_INPUT_BYTES:
        report.update(status="rejected", reason="input_byte_limit")
        return report, []
    if (
        isinstance(max_elapsed_seconds, bool)
        or not isinstance(max_elapsed_seconds, (int, float))
        or not 0 < max_elapsed_seconds <= MAX_ELAPSED_SECONDS
    ):
        report.update(status="rejected", reason="elapsed_limit_invalid")
        return report, []
    start = clock()
    deadline = start + float(max_elapsed_seconds)
    try:
        preflight = preflight_clr_declarations(
            data,
            max_input_bytes=MAX_INPUT_BYTES,
            max_table_rows=20_000,
            max_total_rows=80_000,
        )
        if preflight.get("accepted") is not True:
            reasons = sorted((preflight.get("reason_counts") or {}).keys())
            if reasons == ["preflight_pe_header_invalid"]:
                report.update(status="not_applicable", reason="not_managed_pe")
                return report, []
            raise RemcosEazIncompleteError(
                reasons[0] if reasons else "clr_preflight_incomplete",
                incomplete_type="source_binding",
                stage="clr_preflight",
            )
        _check_time(deadline, clock, stage="clr_parse")
        with _contained_parser_diagnostics():
            pe = dnfile.dnPE(data=data, clr_lazy_load=True)
        if getattr(pe, "net", None) is None:
            raise RemcosEazRecoveryError("clr_metadata_missing")
        method_rows = list(getattr(pe.net.mdtables.MethodDef, "rows", ()) or ())
        _bounded_count(
            len(method_rows),
            MAX_METHOD_ROWS,
            stage="method_inventory",
            reason="method_row_limit",
        )
        methods = _normalize_methods(pe, data, deadline, clock)
        resources, resource_scan, metadata_resolver = _manifest_resources(
            data,
            pe,
            deadline=deadline,
            clock=clock,
        )
        transform, constants = _find_transform(
            methods,
            deadline=deadline,
            clock=clock,
        )
        crypto = _find_crypto_method(
            methods,
            transform.token,
            deadline=deadline,
            clock=clock,
        )
        decoded_crypto = _decode_selected_method(
            data,
            pe,
            crypto.token,
            deadline=deadline,
            clock=clock,
        )
        arrays = _array_recipe(
            data,
            pe,
            decoded_crypto,
            deadline=deadline,
            clock=clock,
        )
        resolver, encrypted_resource = _find_resolver(
            methods,
            crypto.token,
            resources,
            deadline=deadline,
            clock=clock,
        )
        clear_table = _decrypt_string_table(
            encrypted_resource.body,
            arrays,
            constants,
            deadline=deadline,
            clock=clock,
        )
        entries = _parse_string_table(
            clear_table,
            deadline=deadline,
            clock=clock,
        )
        by_offset = {entry.offset: entry for entry in entries}

        b0, b1, b2, field2a, field2b, field2c = _find_loader_methods(
            methods,
            pe,
            deadline=deadline,
            clock=clock,
        )
        offset2a, offset2b, proxy_field, proxy_call = _recover_offsets(
            methods, b1, field2a, field2b
        )
        strict_profile, strict_digests = _strict_role_profile(
            data,
            pe,
            {
                "resolver": resolver,
                "crypto": crypto,
                "transform": transform,
                "b0": b0,
                "b1": b1,
                "b2": b2,
            },
            deadline=deadline,
            clock=clock,
        )
        metadata_rows = _row_tokens(pe.net.mdtables, deadline, clock)
        _type_names, method_names, _field_names = _metadata_names(
            pe,
            metadata_rows,
            deadline,
            clock,
        )
        _check_time(deadline, clock, stage="proxy_analysis")
        wrapper_count, resource_sink_depth, load_sink_depth = _validate_proxy_bindings(
            data,
            pe,
            methods,
            method_names,
            resource_scan,
            metadata_resolver,
            resolver=resolver,
            b0=b0,
            b1=b1,
            b2=b2,
            field2a=field2a,
            field2b=field2b,
            field2c=field2c,
            resolver_proxy_field=proxy_field,
            resolver_proxy_call=proxy_call,
            deadline=deadline,
            clock=clock,
        )
        _check_time(deadline, clock, stage="proxy_analysis")
        key_entry = by_offset.get(offset2a)
        name_entry = by_offset.get(offset2b)
        if key_entry is None or name_entry is None:
            raise RemcosEazRecoveryError("string_field_offset_not_entry_boundary")
        try:
            payload_key = key_entry.value.encode("ascii", errors="strict")
        except UnicodeEncodeError as exc:
            raise RemcosEazRecoveryError("payload_key_not_ascii") from exc
        if not 0 < len(payload_key) <= 512:
            raise RemcosEazRecoveryError("payload_key_length_invalid")

        values: list[_ResourceValue] = []
        resource_sets_parsed = 0
        for resource in resources:
            if (
                len(resource.body) < 4
                or struct.unpack_from("<I", resource.body)[0] != RESOURCE_MAGIC
            ):
                continue
            parsed = _parse_resource_set(resource, deadline=deadline, clock=clock)
            resource_sets_parsed += 1
            values.extend(parsed)
        matches = [value for value in values if value.name == name_entry.value]
        if len(matches) != 1:
            raise RemcosEazRecoveryError("payload_resource_entry_ambiguous_or_missing")
        selected = matches[0]
        terminal = _apply_b0(
            selected.value,
            payload_key,
            deadline=deadline,
            clock=clock,
        )
        extent = inspect_structural_pe_extent(terminal, max_extent=MAX_OUTPUT_BYTES)
        if extent.extent is None:
            raise RemcosEazRecoveryError("terminal_structural_pe_invalid")
        if extent.extent != len(terminal):
            raise RemcosEazRecoveryError("terminal_overlay_not_reviewed")
        _check_time(deadline, clock, stage="finalize")

        effective_key = bytearray(arrays.key)
        for index, value in enumerate(arrays.mask[::-1]):
            effective_key[index] ^= value
        report.update(
            status="recovered_terminal_pe",
            reason=None,
            methods={
                role: {
                    "token": f"0x{method.token:08x}",
                    "body_sha256": method.body_sha256,
                    "body_size": method.body_size,
                    "signature_sha256": _sha256(_method_signature(method)),
                }
                for role, method in (
                    ("string_resolver", resolver),
                    ("crypto_initializer", crypto),
                    ("word_transform", transform),
                    ("payload_transform", b0),
                    ("payload_binding", b1),
                    ("assembly_consumer", b2),
                )
            },
            string_resource={
                "manifest_token": f"0x{encrypted_resource.token:08x}",
                "name_length": len(encrypted_resource.name),
                "name_sha256": _sha256(encrypted_resource.name.encode("utf-8")),
                "size": len(encrypted_resource.body),
                "sha256": _sha256(encrypted_resource.body),
                "source_offset": encrypted_resource.body_offset,
            },
            string_table={
                "size": len(clear_table),
                "sha256": _sha256(clear_table),
                "entry_count": len(entries),
                "exact_extent": True,
            },
            string_fields={
                "key_field_token": f"0x{field2a:08x}",
                "key_offset": offset2a,
                "key_byte_length": len(key_entry.raw),
                "key_value_sha256": _sha256(key_entry.raw),
                "resource_name_field_token": f"0x{field2b:08x}",
                "resource_name_offset": offset2b,
                "resource_name_byte_length": len(name_entry.raw),
                "resource_name_value_sha256": _sha256(name_entry.raw),
                "payload_field_token": f"0x{field2c:08x}",
                "resolver_proxy_field_token": f"0x{proxy_field:08x}",
                "resolver_proxy_call_token": f"0x{proxy_call:08x}",
            },
            resource_set={
                "sets_parsed": resource_sets_parsed,
                "container_manifest_token": f"0x{selected.container_token:08x}",
                "container_size": selected.container_size,
                "container_sha256": selected.container_sha256,
                "entry_name_length": len(selected.name),
                "entry_name_sha256": _sha256(selected.name.encode("utf-8")),
                "value_size": len(selected.value),
                "value_sha256": _sha256(selected.value),
                "type_code": 32,
            },
            static_recipe={
                "strict_role_profile": strict_profile,
                "strict_cil_cfg_eh_validated": True,
                "strict_role_canonical_sha256": strict_digests,
                "word_transform_canonical_sha256": TRANSFORM_CANONICAL_SHA256,
                "build_constants_sha256": _sha256(struct.pack("<4I", *constants)),
                "constant_array_traced_states": arrays.traced_states,
                "key_length": len(arrays.key),
                "key_sha256": _sha256(arrays.key),
                "mask_length": len(arrays.mask),
                "mask_sha256": _sha256(arrays.mask),
                "effective_key_sha256": _sha256(bytes(effective_key)),
                "aes_special_branch_only_for_minus_one": True,
                "normal_string_offset_uses_custom_transform": True,
                "b0_iterations": len(selected.value) + 1,
                "b0_resize_after_loop": True,
                "proxy_records_validated": True,
                "delegate_invoke_wrapper_count": wrapper_count,
                "resource_manager_sink_depth": resource_sink_depth,
                "assembly_load_sink_depth": load_sink_depth,
            },
            output={
                "size": len(terminal),
                "sha256": _sha256(terminal),
                "format": "structural_pe",
                "structural_extent": extent.extent,
                "overlay_size": 0,
            },
            source_binding={
                "mode": "revalidated_snapshot_and_raw_clr_resource_directory",
                "manifest_resources_complete": True,
                "resource_set_entries_complete": True,
                "input_identity_sha256": _sha256(data),
            },
            recursive_validation={
                "strict_settings_validated": False,
                "strict_settings_required_for_family_attribution": True,
                "strict_settings_required_for_terminal_promotion": True,
            },
            elapsed_seconds=round(max(0.0, clock() - start), 6),
        )
        return report, [("managed-eaz-remcos-terminal-pe", terminal)]
    except RemcosEazIncompleteError as exc:
        report.update(
            status="analysis_incomplete",
            reason=str(exc),
            incomplete=exc.report_details(),
        )
        return report, []
    except ManagedMethodRecoveryError as exc:
        report.update(
            status="analysis_incomplete",
            reason="managed_method_normalization_incomplete",
            incomplete={
                "type": "parser_or_quota",
                "stage": "method_inventory",
                "detail": str(exc),
            },
        )
        return report, []
    except (EazRecoveryError, RemcosEazRecoveryError) as exc:
        report.update(status="rejected", reason=str(exc))
        return report, []
    except Exception as exc:  # noqa: BLE001 - hostile parser failureを外部へ漏らさない
        report.update(
            status="rejected",
            reason="static_analysis_failed",
            error_type=type(exc).__name__,
        )
        return report, []


__all__ = [
    "PROFILE_ID",
    "RemcosEazIncompleteError",
    "RemcosEazRecoveryError",
    "recover_managed_eaz_remcos",
]
