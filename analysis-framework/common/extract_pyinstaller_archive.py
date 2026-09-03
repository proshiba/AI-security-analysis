#!/usr/bin/env python3
"""PyInstaller CArchiveを実行せず、安全な範囲で一覧化・静的展開する。"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import struct
import time
import unicodedata
import zlib
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

SHA256_RE = re.compile(r"[0-9a-f]{64}")
DEFAULT_MAX_FILES = 128
DEFAULT_MAX_TOTAL_SIZE = 256 * 1024 * 1024
DEFAULT_MAX_COMPRESSED_TOTAL_SIZE = 256 * 1024 * 1024

DEFAULT_MAX_ENTRY_SIZE = 64 * 1024 * 1024
DEFAULT_MAX_TOC_SIZE = 16 * 1024 * 1024
DEFAULT_MAX_TOC_ENTRIES = 16_384
HARD_MAX_TOC_ENTRIES = 65_536
DEFAULT_MAX_RETAINED_ENTRIES = 128
HARD_MAX_RETAINED_ENTRIES = 128
DEFAULT_SELECTIVE_MAX_TOTAL_SIZE = 128 * 1024 * 1024
DEFAULT_SELECTIVE_MAX_COMPRESSED_TOTAL_SIZE = 128 * 1024 * 1024
DEFAULT_FULL_VALIDATION_MAX_TOTAL_SIZE = 256 * 1024 * 1024
DEFAULT_FULL_VALIDATION_MAX_COMPRESSED_TOTAL_SIZE = 256 * 1024 * 1024
DEFAULT_FULL_VALIDATION_MAX_SECONDS = 120.0
HARD_MAX_FULL_VALIDATION_SECONDS = 300.0
MAX_ENTRY_NAME_BYTES = 4_096
PE_SUFFIXES = frozenset({".cpl", ".dll", ".exe", ".ocx", ".pyd", ".scr", ".sys"})
ARCHIVE_SUFFIXES = frozenset(
    {".7z", ".bz2", ".cab", ".egg", ".gz", ".pyz", ".rar", ".tar", ".whl", ".xz", ".zip", ".zst"}
)
WINDOWS_RESERVED_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", "CLOCK$"}
    | {f"COM{index}" for index in range(1, 10)}
    | {f"LPT{index}" for index in range(1, 10)}
    | {f"COM{index}" for index in "¹²³"}
    | {f"LPT{index}" for index in "¹²³"}
)
FILE_ATTRIBUTE_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


class MemoryCArchiveError(ValueError):
    """メモリ上のPyInstaller CArchiveが不正または上限超過であることを示す。"""


@dataclass(frozen=True)
class MemoryCArchiveEntry:
    """全TOC検証後に保持する、展開前entryの不変metadata。"""

    index: int
    name: str
    normalized_path: str | None
    offset: int
    compressed_size: int
    uncompressed_size: int
    compressed: bool
    typecode: str
    is_option: bool


@dataclass(frozen=True)
class RecoveredCArchiveEntry:
    """優先選択してメモリ内だけで復元したentry。``payload``は公開reportへ含めない。"""

    name: str
    normalized_path: str
    typecode: str
    category: str
    payload_format: str
    priority: int
    compressed: bool
    compressed_size: int
    uncompressed_size: int
    sha256: str
    payload: bytes

    def public_metadata(self) -> dict[str, object]:
        """payloadを除いた、公開可能な小さいmetadataを返す。"""

        return {
            "name": self.name,
            "normalized_path": self.normalized_path,
            "typecode": self.typecode,
            "category": self.category,
            "payload_format": self.payload_format,
            "priority": self.priority,
            "compressed": self.compressed,
            "compressed_size": self.compressed_size,
            "uncompressed_size": self.uncompressed_size,
            "sha256": self.sha256,
        }


@dataclass(frozen=True)
class SelectiveCArchiveAnalysis:
    """公開用集約reportと、非公開の復元bytesを分離した解析結果。"""

    report: dict[str, object]
    recovered_entries: tuple[RecoveredCArchiveEntry, ...]


class MemoryCArchiveReader:
    """境界を検証しながらbytes上のPyInstaller CArchiveを読む。"""

    COOKIE_MAGIC = b"MEI\014\013\012\013\016"
    COOKIE_FORMAT = "!8sIIII64s"
    COOKIE_LENGTH = struct.calcsize(COOKIE_FORMAT)
    TOC_ENTRY_FORMAT = "!IIIIBc"
    TOC_ENTRY_LENGTH = struct.calcsize(TOC_ENTRY_FORMAT)

    def __init__(
        self,
        data: bytes,
        *,
        max_toc_size: int = DEFAULT_MAX_TOC_SIZE,
        max_entries: int = DEFAULT_MAX_TOC_ENTRIES,
    ) -> None:
        if not isinstance(data, bytes):
            raise TypeError("CArchive入力はbytesで指定してください")
        if isinstance(max_toc_size, bool) or not isinstance(max_toc_size, int) or max_toc_size <= 0:
            raise ValueError("max_toc_sizeは正の整数で指定してください")
        if isinstance(max_entries, bool) or not isinstance(max_entries, int) or max_entries <= 0:
            raise ValueError("max_entriesは正の整数で指定してください")
        if max_entries > HARD_MAX_TOC_ENTRIES:
            raise ValueError(f"max_entriesは{HARD_MAX_TOC_ENTRIES}以下で指定してください")
        cookie_offset = data.rfind(self.COOKIE_MAGIC)
        if cookie_offset < 0:
            raise MemoryCArchiveError("PyInstaller CArchive cookieがありません")
        cookie_end = cookie_offset + self.COOKIE_LENGTH
        if cookie_end > len(data):
            raise MemoryCArchiveError("PyInstaller CArchive cookieが途中で切れています")
        magic, archive_length, toc_offset, toc_length, python_version, python_library = struct.unpack(
            self.COOKIE_FORMAT, data[cookie_offset:cookie_end]
        )
        if magic != self.COOKIE_MAGIC:
            raise MemoryCArchiveError("PyInstaller CArchive cookieが一致しません")
        if archive_length < self.COOKIE_LENGTH or archive_length > cookie_end:
            raise MemoryCArchiveError("PyInstaller CArchive長が不正です")
        if toc_length <= 0 or toc_length > max_toc_size:
            raise MemoryCArchiveError("PyInstaller CArchive TOC長が不正または上限超過です")
        expected_archive_length = toc_offset + toc_length + self.COOKIE_LENGTH
        if archive_length != expected_archive_length:
            raise MemoryCArchiveError("PyInstaller CArchive cookieとTOCの長さ関係が一致しません")
        if not python_library.rstrip(b"\0"):
            raise MemoryCArchiveError("PyInstaller CArchiveのPython共有ライブラリ名が空です")
        library_raw = python_library.rstrip(b"\0")
        if b"\0" in library_raw:
            raise MemoryCArchiveError("PyInstaller CArchiveのPython共有ライブラリ名が不正です")
        try:
            library_name = library_raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise MemoryCArchiveError("PyInstaller CArchiveのPython共有ライブラリ名がUTF-8ではありません") from exc
        if any(ord(character) < 32 or ord(character) == 127 for character in library_name):
            raise MemoryCArchiveError("PyInstaller CArchiveのPython共有ライブラリ名に制御文字があります")

        self._data = memoryview(data)
        self._start_offset = cookie_end - archive_length
        self.cookie_offset = cookie_offset
        self.cookie_end = cookie_end
        self.archive_length = archive_length
        self.archive_start_offset = self._start_offset
        self.trailing_size = len(data) - cookie_end
        self.python_version = python_version
        self.python_library = library_name
        toc_start = self._start_offset + toc_offset
        toc_end = toc_start + toc_length
        if toc_start < self._start_offset or toc_end < toc_start or toc_end != cookie_offset:
            raise MemoryCArchiveError("PyInstaller CArchive TOCの境界が不正です")
        self.toc_offset = toc_offset
        self.toc_length = toc_length
        self._data_region_length = toc_offset
        self.toc, self.options, self.entries = self._parse_toc(
            bytes(self._data[toc_start:toc_end]),
            max_entries=max_entries,
        )

    def _parse_toc(
        self,
        data: bytes,
        *,
        max_entries: int,
    ) -> tuple[
        dict[str, tuple[int, int, int, int, str]],
        list[str],
        tuple[MemoryCArchiveEntry, ...],
    ]:
        toc: dict[str, tuple[int, int, int, int, str]] = {}
        options: list[str] = []
        entries: list[MemoryCArchiveEntry] = []
        collision_names: dict[str, str] = {}
        cursor = 0
        entry_count = 0
        while cursor < len(data):
            if len(data) - cursor < self.TOC_ENTRY_LENGTH:
                raise MemoryCArchiveError("PyInstaller CArchive TOC headerが途中で切れています")
            entry_length, offset, length, unpacked_length, compressed, typecode_raw = struct.unpack(
                self.TOC_ENTRY_FORMAT,
                data[cursor : cursor + self.TOC_ENTRY_LENGTH],
            )
            if entry_length <= self.TOC_ENTRY_LENGTH or entry_length > len(data) - cursor:
                raise MemoryCArchiveError("PyInstaller CArchive TOC entry長が不正です")
            name_field = data[cursor + self.TOC_ENTRY_LENGTH : cursor + entry_length]
            if len(name_field) > MAX_ENTRY_NAME_BYTES + 16:
                raise MemoryCArchiveError("PyInstaller CArchive TOC entry名領域が上限を超えました")
            terminator = name_field.find(b"\0")
            if terminator < 0:
                name_raw = name_field
            else:
                name_raw = name_field[:terminator]
                if name_field[terminator:].strip(b"\0"):
                    raise MemoryCArchiveError("PyInstaller CArchive TOC entry名のpaddingが不正です")
            if not name_raw:
                raise MemoryCArchiveError("PyInstaller CArchive TOC entry名が空です")
            if len(name_raw) > MAX_ENTRY_NAME_BYTES:
                raise MemoryCArchiveError("PyInstaller CArchive TOC entry名が上限を超えました")
            try:
                name = name_raw.decode("utf-8")
                typecode = typecode_raw.decode("ascii")
            except UnicodeDecodeError as exc:
                raise MemoryCArchiveError("PyInstaller CArchive TOCの文字コードが不正です") from exc
            if not 0x21 <= ord(typecode) <= 0x7E:
                raise MemoryCArchiveError("PyInstaller CArchiveのtypecodeが不正です")
            if compressed not in {0, 1}:
                raise MemoryCArchiveError("PyInstaller CArchiveの圧縮flagが不正です")
            if offset > self._data_region_length or length > self._data_region_length - offset:
                raise MemoryCArchiveError("PyInstaller CArchive entryの境界が不正です")
            if compressed and length == 0:
                raise MemoryCArchiveError("圧縮CArchive entryの入力長が0です")
            if not compressed and length != unpacked_length:
                raise MemoryCArchiveError("非圧縮CArchive entryの宣言サイズが一致しません")
            if typecode == "o" and (length != 0 or unpacked_length != 0 or compressed != 0):
                raise MemoryCArchiveError("PyInstaller CArchive option recordがpayloadを宣言しています")
            entry = (offset, length, unpacked_length, compressed, typecode)
            if typecode == "o":
                options.append(name)
            else:
                try:
                    relative = safe_relative_path(name)
                except ValueError as exc:
                    raise MemoryCArchiveError(str(exc)) from exc
                normalized_path = relative.as_posix()
                collision_key = _path_collision_key(relative)
                previous = collision_names.get(collision_key)
                if previous is not None:
                    raise MemoryCArchiveError(
                        f"PyInstaller CArchive entryが大文字小文字正規化後に衝突します: {previous!r}, {name!r}"
                    )
                collision_names[collision_key] = name
                toc[name] = entry
            if typecode == "o":
                normalized_path = None
            entries.append(
                MemoryCArchiveEntry(
                    index=entry_count,
                    name=name,
                    normalized_path=normalized_path,
                    offset=offset,
                    compressed_size=length,
                    uncompressed_size=unpacked_length,
                    compressed=bool(compressed),
                    typecode=typecode,
                    is_option=typecode == "o",
                )
            )
            cursor += entry_length
            entry_count += 1
            if entry_count > max_entries:
                raise MemoryCArchiveError("PyInstaller CArchive TOC entry数が上限を超えました")
        if cursor != len(data):
            raise MemoryCArchiveError("PyInstaller CArchive TOC末尾が不正です")

        ranges = sorted(
            (
                entry.offset,
                entry.offset + entry.compressed_size,
                entry.name,
            )
            for entry in entries
            if entry.compressed_size
        )
        previous: tuple[int, int, str] | None = None
        for current in ranges:
            if previous is not None and current[0] < previous[1]:
                raise MemoryCArchiveError(
                    f"PyInstaller CArchive entryの圧縮rangeが重複または重畳しています: {previous[2]!r}, {current[2]!r}"
                )
            previous = current
        return toc, options, tuple(entries)

    def extract(
        self,
        name: str,
        *,
        max_size: int = DEFAULT_MAX_ENTRY_SIZE,
        max_compressed_size: int | None = None,
    ) -> bytes:
        """指定entryだけを上限付きでメモリへ展開する。"""

        if isinstance(max_size, bool) or not isinstance(max_size, int) or max_size <= 0:
            raise ValueError("max_sizeは正の整数で指定してください")
        compressed_limit = max_size if max_compressed_size is None else max_compressed_size
        if isinstance(compressed_limit, bool) or not isinstance(compressed_limit, int) or compressed_limit <= 0:
            raise ValueError("max_compressed_sizeは正の整数で指定してください")
        try:
            offset, length, unpacked_length, compressed, _typecode = self.toc[name]
        except KeyError as exc:
            raise KeyError(f"CArchive entryがありません: {name!r}") from exc
        if unpacked_length > max_size or length > compressed_limit:
            raise MemoryCArchiveError("PyInstaller CArchive entryが展開上限を超えました")
        start = self._start_offset + offset
        payload = bytes(self._data[start : start + length])
        if compressed:
            decoder = zlib.decompressobj()
            try:
                output_limit = min(max_size, unpacked_length) + 1
                unpacked = decoder.decompress(payload, output_limit)
            except zlib.error as exc:
                raise MemoryCArchiveError("PyInstaller CArchive entryのzlib展開に失敗しました") from exc
            if len(unpacked) > max_size or not decoder.eof or decoder.unconsumed_tail or decoder.unused_data:
                raise MemoryCArchiveError("PyInstaller CArchive entryのzlib streamが不正または上限超過です")
        else:
            unpacked = payload
        if len(unpacked) != unpacked_length:
            raise MemoryCArchiveError("PyInstaller CArchive entryの展開サイズが宣言値と一致しません")
        return unpacked


def _path_collision_key(relative: Path) -> str:
    return unicodedata.normalize("NFC", relative.as_posix()).casefold()


def _select_reader_entries(
    reader: MemoryCArchiveReader,
    *,
    exact_names: set[str] | None,
    prefixes: tuple[str, ...],
) -> list[tuple[str, Path]]:
    exact = {unicodedata.normalize("NFC", value.replace("\\", "/")).casefold() for value in (exact_names or set())}
    normalized_prefixes = tuple(unicodedata.normalize("NFC", value.replace("\\", "/")).casefold() for value in prefixes)
    selected: list[tuple[str, Path]] = []
    collision_names: dict[str, str] = {}
    for name in reader.toc:
        relative = safe_relative_path(name)
        folded = _path_collision_key(relative)
        if folded not in exact and not any(folded.startswith(prefix) for prefix in normalized_prefixes):
            continue
        previous = collision_names.get(folded)
        if previous is not None and previous != name:
            raise MemoryCArchiveError(
                f"選択したCArchive entryが大文字小文字正規化後に衝突します: {previous!r}, {name!r}"
            )
        collision_names[folded] = name
        selected.append((name, relative))
    return selected


def _validate_selected_entry_limits(
    reader: MemoryCArchiveReader,
    selected: list[tuple[str, Path]],
    *,
    max_files: int,
    max_total_size: int,
    max_compressed_total_size: int,
    max_entry_size: int,
) -> tuple[int, int]:
    _positive_limit(max_files, "max_files")
    _positive_limit(max_total_size, "max_total_size")
    _positive_limit(max_compressed_total_size, "max_compressed_total_size")
    _positive_limit(max_entry_size, "max_entry_size")
    if max_files > HARD_MAX_RETAINED_ENTRIES:
        raise ValueError(f"max_filesは{HARD_MAX_RETAINED_ENTRIES}以下で指定してください")
    if len(selected) > max_files:
        raise MemoryCArchiveError("選択したCArchive entry数が上限を超えました")

    total_unpacked = 0
    total_compressed = 0
    ranges: list[tuple[int, int, str]] = []
    for name, _relative in selected:
        offset, compressed_size, unpacked_size, _compressed, _typecode = reader.toc[name]
        if compressed_size > max_entry_size or unpacked_size > max_entry_size:
            raise MemoryCArchiveError("選択したCArchive entryが個別サイズ上限を超えました")
        total_unpacked += int(unpacked_size)
        total_compressed += int(compressed_size)
        if total_unpacked > max_total_size:
            raise MemoryCArchiveError("選択したCArchive entryの総展開サイズが上限を超えました")
        if total_compressed > max_compressed_total_size:
            raise MemoryCArchiveError("選択したCArchive entryの圧縮入力総量が上限を超えました")
        if compressed_size:
            ranges.append((int(offset), int(offset + compressed_size), name))

    ranges.sort()
    previous: tuple[int, int, str] | None = None
    for current in ranges:
        if previous is not None and current[0] < previous[1]:
            raise MemoryCArchiveError(
                f"選択したCArchive entryの圧縮rangeが重複または重畳しています: {previous[2]!r}, {current[2]!r}"
            )
        previous = current
    return total_unpacked, total_compressed


def _extract_selected_from_reader(
    reader: MemoryCArchiveReader,
    selected: list[tuple[str, Path]],
    *,
    max_files: int,
    max_total_size: int,
    max_compressed_total_size: int,
    max_entry_size: int,
) -> dict[str, bytes]:
    _validate_selected_entry_limits(
        reader,
        selected,
        max_files=max_files,
        max_total_size=max_total_size,
        max_compressed_total_size=max_compressed_total_size,
        max_entry_size=max_entry_size,
    )
    extracted: dict[str, bytes] = {}
    total_actual = 0
    for name, relative in selected:
        payload = reader.extract(name, max_size=max_entry_size)
        total_actual += len(payload)
        if total_actual > max_total_size:
            raise MemoryCArchiveError("選択したCArchive entryの実展開サイズが上限を超えました")
        key = relative.as_posix()
        if key in extracted:
            raise MemoryCArchiveError("選択したCArchive entryの出力先が重複しています")
        extracted[key] = payload
    return extracted


def extract_selected_entries_from_bytes(
    data: bytes,
    *,
    exact_names: set[str] | None = None,
    prefixes: tuple[str, ...] = (),
    max_files: int = DEFAULT_MAX_FILES,
    max_total_size: int = DEFAULT_MAX_TOTAL_SIZE,
    max_compressed_total_size: int = DEFAULT_MAX_COMPRESSED_TOTAL_SIZE,
    max_entry_size: int = DEFAULT_MAX_ENTRY_SIZE,
    max_toc_size: int = DEFAULT_MAX_TOC_SIZE,
    max_toc_entries: int = DEFAULT_MAX_TOC_ENTRIES,
) -> tuple[MemoryCArchiveReader, dict[str, bytes]]:
    """選択したCArchive entryだけを保存せずメモリへ展開する。"""

    reader = MemoryCArchiveReader(data, max_toc_size=max_toc_size, max_entries=max_toc_entries)
    selected = _select_reader_entries(reader, exact_names=exact_names, prefixes=prefixes)
    extracted = _extract_selected_from_reader(
        reader,
        selected,
        max_files=max_files,
        max_total_size=max_total_size,
        max_compressed_total_size=max_compressed_total_size,
        max_entry_size=max_entry_size,
    )
    return reader, extracted


def _inventory_commitment(reader: MemoryCArchiveReader) -> dict[str, object]:
    """全TOC recordを公開せず、その順序とmetadataへSHA-256でcommitする。"""

    digest = hashlib.sha256()
    for entry in reader.entries:
        record = {
            "compressed": entry.compressed,
            "compressed_size": entry.compressed_size,
            "index": entry.index,
            "is_option": entry.is_option,
            "name": entry.name,
            "normalized_path": entry.normalized_path,
            "offset": entry.offset,
            "typecode": entry.typecode,
            "uncompressed_size": entry.uncompressed_size,
        }
        canonical = json.dumps(
            record,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        digest.update(struct.pack("!I", len(canonical)))
        digest.update(canonical)
    return {
        "algorithm": "sha256",
        "canonicalization": "length_prefixed_canonical_json_utf8_v1",
        "record_count": len(reader.entries),
        "sha256": digest.hexdigest(),
    }


def carchive_inventory_summary(reader: MemoryCArchiveReader) -> dict[str, object]:
    """巨大なentry配列を出力せず、全inventoryの集約値とcommitmentを返す。"""

    payload_entries = [entry for entry in reader.entries if not entry.is_option]
    type_counts = Counter(entry.typecode for entry in reader.entries)
    return {
        "format": "PyInstaller CArchive",
        "reader": "bounded_memory_carchive",
        "archive_start_offset": reader.archive_start_offset,
        "archive_length": reader.archive_length,
        "toc_offset": reader.toc_offset,
        "toc_size": reader.toc_length,
        "cookie_offset": reader.cookie_offset,
        "cookie_size": reader.COOKIE_LENGTH,
        "trailing_size": reader.trailing_size,
        "python_version": reader.python_version,
        "python_library": reader.python_library,
        "entry_count": len(payload_entries),
        "option_count": len(reader.options),
        "toc_record_count": len(reader.entries),
        "type_counts": dict(sorted(type_counts.items())),
        "total_compressed_size": sum(entry.compressed_size for entry in payload_entries),
        "total_uncompressed_size": sum(entry.uncompressed_size for entry in payload_entries),
        "full_inventory_published": False,
        "inventory_commitment": _inventory_commitment(reader),
    }


def _positive_limit(value: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{name}は正の整数で指定してください")
    return value


def _selection_category(entry: MemoryCArchiveEntry, preferred_keys: set[str]) -> tuple[int, str] | None:
    if entry.normalized_path is None:
        return None
    key = unicodedata.normalize("NFC", entry.normalized_path).casefold()
    if key in preferred_keys:
        return 0, "caller_preferred"
    if entry.typecode == "s":
        return 10, "python_script"
    if entry.typecode in {"m", "M"}:
        return 20, "python_module"
    if entry.typecode == "z":
        return 30, "pyz_archive"
    suffix = PurePosixPath(entry.normalized_path).suffix.casefold()
    if suffix in PE_SUFFIXES:
        return 40, "pe_name_candidate"
    if entry.typecode == "Z" or suffix in ARCHIVE_SUFFIXES:
        return 50, "nested_archive"
    return None


def _is_structurally_valid_pe(payload: bytes) -> bool:
    """header範囲内だけを読み、PE section tableまでの構造を検証する。"""

    if len(payload) < 0x40 or payload[:2] != b"MZ":
        return False
    pe_offset = struct.unpack_from("<I", payload, 0x3C)[0]
    if pe_offset < 0x40 or pe_offset > len(payload) - 24:
        return False
    if payload[pe_offset : pe_offset + 4] != b"PE\0\0":
        return False
    section_count = struct.unpack_from("<H", payload, pe_offset + 6)[0]
    optional_header_size = struct.unpack_from("<H", payload, pe_offset + 20)[0]
    if section_count == 0 or section_count > 96:
        return False
    section_table = pe_offset + 24 + optional_header_size
    return section_table <= len(payload) and section_count * 40 <= len(payload) - section_table


def _payload_format(payload: bytes, entry: MemoryCArchiveEntry) -> str:
    """実行せず、typecodeと先頭magic/PE境界だけでpayload形式を分類する。"""

    if entry.typecode == "s":
        return "pyinstaller_python_script_entry"
    if entry.typecode in {"m", "M"}:
        return "pyinstaller_python_module_entry"
    if entry.typecode == "z":
        return "pyinstaller_pyz" if payload.startswith(b"PYZ\0") else "pyz_declared_unrecognized_magic"
    if not payload:
        return "empty"
    if _is_structurally_valid_pe(payload):
        return "portable_executable"
    if payload.startswith(b"MZ"):
        return "dos_mz_non_pe_or_truncated"
    if payload.startswith(b"\x7fELF"):
        return "elf"
    if payload.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return "zip"
    if payload.startswith(b"MSCF"):
        return "cab"
    if payload.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7z"
    if payload.startswith((b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01\x00")):
        return "rar"
    if payload.startswith(b"\x1f\x8b"):
        return "gzip"
    if payload.startswith(b"BZh"):
        return "bzip2"
    if payload.startswith(b"\xfd7zXZ\x00"):
        return "xz"
    if payload.startswith(b"\x28\xb5\x2f\xfd"):
        return "zstd"
    if payload.startswith(b"%PDF-"):
        return "pdf"
    if payload.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if payload.startswith((b"GIF87a", b"GIF89a")):
        return "gif"
    if payload.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if payload.startswith(b"SQLite format 3\0"):
        return "sqlite3"
    return "unknown_binary_or_data"


def analyze_carchive_bytes(
    data: bytes,
    *,
    preferred_names: Iterable[str] = (),
    max_retained_entries: int = DEFAULT_MAX_RETAINED_ENTRIES,
    max_entry_compressed_size: int = DEFAULT_MAX_ENTRY_SIZE,
    max_entry_uncompressed_size: int = DEFAULT_MAX_ENTRY_SIZE,
    max_total_compressed_size: int = DEFAULT_SELECTIVE_MAX_COMPRESSED_TOTAL_SIZE,
    max_total_uncompressed_size: int = DEFAULT_SELECTIVE_MAX_TOTAL_SIZE,
    max_validation_entry_compressed_size: int = DEFAULT_MAX_ENTRY_SIZE,
    max_validation_entry_uncompressed_size: int = DEFAULT_MAX_ENTRY_SIZE,
    max_validation_total_compressed_size: int = DEFAULT_FULL_VALIDATION_MAX_COMPRESSED_TOTAL_SIZE,
    max_validation_total_uncompressed_size: int = DEFAULT_FULL_VALIDATION_MAX_TOTAL_SIZE,
    max_validation_seconds: float = DEFAULT_FULL_VALIDATION_MAX_SECONDS,
    max_toc_size: int = DEFAULT_MAX_TOC_SIZE,
    max_toc_entries: int = DEFAULT_MAX_TOC_ENTRIES,
) -> SelectiveCArchiveAnalysis:
    """
    PyInstaller CArchiveを実行・保存せず、優先entryだけをbytesへ復元する。

    TOC全体の境界、path衝突、payload range重畳は選択前に検証する。全entryが
    内容検証budget内なら1件ずつ展開してEOF・実サイズ・hashを検証し、非候補bytes
    は即時破棄する。script、module、PYZ、PE名候補、入れ子archiveだけを優先順で
    128件以下保持する。budget超過時は選択entryだけを検証し、部分状態を明示する。
    PyInstallerという包装形式だけからmalware familyや悪性意図は推定しない。
    """

    if not isinstance(data, bytes):
        raise TypeError("CArchive入力はbytesで指定してください")
    retained_limit = _positive_limit(max_retained_entries, "max_retained_entries")
    if retained_limit > HARD_MAX_RETAINED_ENTRIES:
        raise ValueError(f"max_retained_entriesは{HARD_MAX_RETAINED_ENTRIES}以下で指定してください")
    entry_compressed_limit = _positive_limit(max_entry_compressed_size, "max_entry_compressed_size")
    entry_uncompressed_limit = _positive_limit(max_entry_uncompressed_size, "max_entry_uncompressed_size")
    total_compressed_limit = _positive_limit(max_total_compressed_size, "max_total_compressed_size")
    total_uncompressed_limit = _positive_limit(max_total_uncompressed_size, "max_total_uncompressed_size")
    validation_entry_compressed_limit = _positive_limit(
        max_validation_entry_compressed_size,
        "max_validation_entry_compressed_size",
    )
    validation_entry_uncompressed_limit = _positive_limit(
        max_validation_entry_uncompressed_size,
        "max_validation_entry_uncompressed_size",
    )
    validation_total_compressed_limit = _positive_limit(
        max_validation_total_compressed_size,
        "max_validation_total_compressed_size",
    )
    validation_total_uncompressed_limit = _positive_limit(
        max_validation_total_uncompressed_size,
        "max_validation_total_uncompressed_size",
    )
    if isinstance(max_validation_seconds, bool) or not isinstance(max_validation_seconds, (int, float)):
        raise ValueError("max_validation_secondsは正の有限数で指定してください")
    validation_seconds = float(max_validation_seconds)
    if not 0 < validation_seconds <= HARD_MAX_FULL_VALIDATION_SECONDS:
        raise ValueError(f"max_validation_secondsは0より大きく{HARD_MAX_FULL_VALIDATION_SECONDS}以下で指定してください")

    preferred_keys: set[str] = set()
    preferred_original: dict[str, str] = {}
    for name in preferred_names:
        if not isinstance(name, str):
            raise TypeError("preferred_namesの各要素はstrで指定してください")
        try:
            relative = safe_relative_path(name)
        except ValueError as exc:
            raise MemoryCArchiveError(str(exc)) from exc
        key = _path_collision_key(relative)
        if key not in preferred_keys:
            preferred_keys.add(key)
            preferred_original[key] = relative.as_posix()

    reader = MemoryCArchiveReader(data, max_toc_size=max_toc_size, max_entries=max_toc_entries)
    present_keys = {
        unicodedata.normalize("NFC", entry.normalized_path).casefold()
        for entry in reader.entries
        if entry.normalized_path is not None
    }
    missing_preferred = sorted(original for key, original in preferred_original.items() if key not in present_keys)

    candidates: list[tuple[int, str, str, MemoryCArchiveEntry]] = []
    category_counts: Counter[str] = Counter()
    for entry in reader.entries:
        profile = _selection_category(entry, preferred_keys)
        if profile is None or entry.normalized_path is None:
            continue
        priority, category = profile
        category_counts[category] += 1
        normalized_sort_key = unicodedata.normalize("NFC", entry.normalized_path).casefold()
        candidates.append((priority, normalized_sort_key, category, entry))
    candidates.sort(
        key=lambda item: (
            item[0],
            item[3].normalized_path.count("/"),
            item[1],
            item[3].name,
            item[3].offset,
            item[3].index,
        )
    )

    recovered: list[RecoveredCArchiveEntry] = []
    excluded: Counter[str] = Counter()
    total_compressed = 0
    total_uncompressed = 0
    for priority, _sort_key, category, entry in candidates:
        if len(recovered) >= retained_limit:
            excluded["retained_entry_limit"] += 1
            continue
        if entry.compressed_size > entry_compressed_limit:
            excluded["entry_compressed_size_limit"] += 1
            continue
        if entry.uncompressed_size > entry_uncompressed_limit:
            excluded["entry_uncompressed_size_limit"] += 1
            continue
        if total_compressed + entry.compressed_size > total_compressed_limit:
            excluded["total_compressed_size_limit"] += 1
            continue
        if total_uncompressed + entry.uncompressed_size > total_uncompressed_limit:
            excluded["total_uncompressed_size_limit"] += 1
            continue
        payload = reader.extract(
            entry.name,
            max_size=entry_uncompressed_limit,
            max_compressed_size=entry_compressed_limit,
        )
        if len(payload) != entry.uncompressed_size:
            raise MemoryCArchiveError("選択CArchive entryの実展開サイズが宣言値と一致しません")
        total_compressed += entry.compressed_size
        total_uncompressed += len(payload)
        recovered.append(
            RecoveredCArchiveEntry(
                name=entry.name,
                normalized_path=entry.normalized_path,
                typecode=entry.typecode,
                category=category,
                payload_format=_payload_format(payload, entry),
                priority=priority,
                compressed=entry.compressed,
                compressed_size=entry.compressed_size,
                uncompressed_size=entry.uncompressed_size,
                sha256=sha256_bytes(payload),
                payload=payload,
            )
        )

    payload_entries = tuple(entry for entry in reader.entries if not entry.is_option)
    payload_entry_count = len(payload_entries)
    retained_count = len(recovered)
    non_candidate_count = payload_entry_count - len(candidates)
    retained_by_name = {entry.name: entry for entry in recovered}

    validation_exclusions: Counter[str] = Counter()
    declared_compressed_total = sum(entry.compressed_size for entry in payload_entries)
    declared_uncompressed_total = sum(entry.uncompressed_size for entry in payload_entries)
    if declared_compressed_total > validation_total_compressed_limit:
        validation_exclusions["declared_total_compressed_size_limit"] += 1
    if declared_uncompressed_total > validation_total_uncompressed_limit:
        validation_exclusions["declared_total_uncompressed_size_limit"] += 1
    oversized_compressed_entries = sum(
        entry.compressed_size > validation_entry_compressed_limit for entry in payload_entries
    )
    oversized_uncompressed_entries = sum(
        entry.uncompressed_size > validation_entry_uncompressed_limit for entry in payload_entries
    )
    if oversized_compressed_entries:
        validation_exclusions["entry_compressed_size_limit"] = oversized_compressed_entries
    if oversized_uncompressed_entries:
        validation_exclusions["entry_uncompressed_size_limit"] = oversized_uncompressed_entries

    validated_names = set(retained_by_name)
    validated_compressed_total = sum(entry.compressed_size for entry in recovered)
    validated_uncompressed_total = sum(entry.uncompressed_size for entry in recovered)
    validated_format_counts = Counter(entry.payload_format for entry in recovered)
    discarded_after_validation = 0
    reused_retained_count = 0
    validation_timed_out = False
    content_digest = hashlib.sha256()
    can_attempt_full_validation = not validation_exclusions or retained_count == payload_entry_count
    if can_attempt_full_validation:
        deadline = time.monotonic() + validation_seconds
        for entry in payload_entries:
            if time.monotonic() > deadline:
                validation_timed_out = True
                break
            retained = retained_by_name.get(entry.name)
            if retained is None:
                payload = reader.extract(
                    entry.name,
                    max_size=validation_entry_uncompressed_limit,
                    max_compressed_size=validation_entry_compressed_limit,
                )
                payload_sha256 = sha256_bytes(payload)
                payload_format = _payload_format(payload, entry)
                if entry.name not in validated_names:
                    validated_names.add(entry.name)
                    validated_compressed_total += entry.compressed_size
                    validated_uncompressed_total += len(payload)
                    validated_format_counts[payload_format] += 1
                    discarded_after_validation += 1
                del payload
            else:
                payload_sha256 = retained.sha256
                payload_format = retained.payload_format
                reused_retained_count += 1
            content_record = {
                "index": entry.index,
                "name": entry.name,
                "payload_format": payload_format,
                "sha256": payload_sha256,
                "size": entry.uncompressed_size,
            }
            canonical = json.dumps(
                content_record,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            content_digest.update(struct.pack("!I", len(canonical)))
            content_digest.update(canonical)
            if time.monotonic() > deadline and len(validated_names) < payload_entry_count:
                validation_timed_out = True
                break

    full_content_validation = len(validated_names) == payload_entry_count and not validation_timed_out
    if full_content_validation:
        content_validation_status = "complete"
        content_commitment: dict[str, object] | None = {
            "algorithm": "sha256",
            "canonicalization": "length_prefixed_entry_content_sha256_json_utf8_v1",
            "record_count": payload_entry_count,
            "sha256": content_digest.hexdigest(),
        }
    elif validation_timed_out:
        content_validation_status = "partial_time_limit"
        content_commitment = None
    else:
        content_validation_status = "partial_budget_limit"
        content_commitment = None

    blockers: list[str] = []
    if excluded:
        blockers.append("priority_entries_excluded_by_retention_budget")
    if missing_preferred:
        blockers.append("caller_preferred_entries_not_found")
    if not full_content_validation:
        if validation_exclusions:
            blockers.append("full_content_validation_exceeds_budget")
        if validation_timed_out:
            blockers.append("full_content_validation_time_limit_reached")
        if non_candidate_count:
            blockers.append("bulk_non_priority_entries_not_decompressed_by_design")
        if retained_count < payload_entry_count:
            blockers.append("unselected_streams_not_fully_eof_and_size_validated")
    if retained_count == payload_entry_count:
        status = "all_entries_recovered"
    elif retained_count:
        status = "selective_recovery"
    else:
        status = "inventory_only"

    retained_type_counts = Counter(entry.typecode for entry in recovered)
    retained_category_counts = Counter(entry.category for entry in recovered)
    report: dict[str, object] = {
        "schema_version": 1,
        "complete": full_content_validation and not blockers,
        "analysis_status": (
            "complete_content_validation_selective_retention"
            if full_content_validation
            else "partial_content_validation"
        ),
        "blockers": list(blockers),
        "sample": {"sha256": sha256_bytes(data), "size": len(data)},
        "classification": {
            "packaging": "PyInstaller CArchive",
            "malware_family": "not_inferred_from_packaging",
            "malicious_intent": "not_inferred_from_packaging",
        },
        "archive": carchive_inventory_summary(reader),
        "selection": {
            "status": status,
            "strategy": "bounded_priority_v1",
            "deterministic_tie_breakers": ["path_depth", "normalized_path", "original_name", "offset", "toc_index"],
            "priority_order": [
                "caller_preferred",
                "python_script",
                "python_module",
                "pyz_archive",
                "pe_name_candidate",
                "nested_archive",
            ],
            "candidate_count": len(candidates),
            "candidate_category_counts": dict(sorted(category_counts.items())),
            "retained_count": retained_count,
            "retained_type_counts": dict(sorted(retained_type_counts.items())),
            "retained_category_counts": dict(sorted(retained_category_counts.items())),
            "omitted_entry_count": payload_entry_count - retained_count,
            "non_candidate_count": non_candidate_count,
            "excluded_candidate_counts": dict(sorted(excluded.items())),
            "missing_preferred_names": missing_preferred,
            "total_compressed_size": total_compressed,
            "total_uncompressed_size": total_uncompressed,
            "limits": {
                "max_retained_entries": retained_limit,
                "max_entry_compressed_size": entry_compressed_limit,
                "max_entry_uncompressed_size": entry_uncompressed_limit,
                "max_total_compressed_size": total_compressed_limit,
                "max_total_uncompressed_size": total_uncompressed_limit,
            },
            "selected_entries": [entry.public_metadata() for entry in recovered],
            "blockers": blockers,
        },
        "content_validation": {
            "status": content_validation_status,
            "full_content_validation": full_content_validation,
            "validated_entry_count": len(validated_names),
            "total_entry_count": payload_entry_count,
            "retained_entries_reused": reused_retained_count,
            "discarded_after_validation_count": discarded_after_validation,
            "validated_compressed_size": validated_compressed_total,
            "validated_uncompressed_size": validated_uncompressed_total,
            "format_counts": dict(sorted(validated_format_counts.items())),
            "format_classification_complete": full_content_validation,
            "content_commitment": content_commitment,
            "exclusion_counts": dict(sorted(validation_exclusions.items())),
            "time_limit_reached": validation_timed_out,
            "limits": {
                "max_entry_compressed_size": validation_entry_compressed_limit,
                "max_entry_uncompressed_size": validation_entry_uncompressed_limit,
                "max_total_compressed_size": validation_total_compressed_limit,
                "max_total_uncompressed_size": validation_total_uncompressed_limit,
                "max_seconds": validation_seconds,
            },
        },
        "safety": {
            "sample_executed": False,
            "external_process_started": False,
            "network_contacted": False,
            "file_written": False,
            "bytes_only": True,
            "all_toc_records_bounds_validated": True,
            "all_payload_ranges_overlap_validated": True,
            "all_paths_collision_validated": True,
            "retained_declared_and_actual_sizes_validated": True,
            "retained_zlib_eof_validated": True,
            "full_content_validation": full_content_validation,
            "all_payload_declared_and_actual_sizes_validated": full_content_validation,
            "all_compressed_streams_eof_validated": full_content_validation,
            "all_payload_formats_classified": full_content_validation,
            "unselected_payloads_decompressed_then_discarded": discarded_after_validation > 0,
        },
    }
    return SelectiveCArchiveAnalysis(report=report, recovered_entries=tuple(recovered))


# 統合側で目的を明示しやすい別名。実装とcontractはanalyze_carchive_bytesと同一である。
recover_prioritized_entries_from_bytes = analyze_carchive_bytes


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe_relative_path(name: str) -> Path:
    """Windowsでも安全なCArchive内の相対パスだけを許可する。"""

    normalized = name.replace("\\", "/")
    if not normalized or normalized.startswith("/") or "\x00" in normalized:
        raise ValueError(f"安全でないCArchiveエントリ名です: {name!r}")
    if re.match(r"^[A-Za-z]:", normalized):
        raise ValueError(f"ドライブ指定を含むCArchiveエントリ名です: {name!r}")
    if any(part in {"", ".", ".."} for part in normalized.split("/")):
        raise ValueError(f"相対移動を含むCArchiveエントリ名です: {name!r}")
    pure = PurePosixPath(normalized)
    if any(part in {"", ".", ".."} for part in pure.parts):
        raise ValueError(f"相対移動を含むCArchiveエントリ名です: {name!r}")
    for part in pure.parts:
        if any(ord(character) < 32 or ord(character) == 127 for character in part):
            raise ValueError(f"制御文字を含むCArchiveエントリ名です: {name!r}")
        if ":" in part:
            raise ValueError(f"代替データストリーム指定を含むCArchiveエントリ名です: {name!r}")
        if part.endswith((" ", ".")):
            raise ValueError(f"末尾のdotまたはspaceを含むCArchiveエントリ名です: {name!r}")
        reserved_stem = part.split(".", 1)[0].rstrip(" .").upper()
        if reserved_stem in WINDOWS_RESERVED_NAMES:
            raise ValueError(f"Windows予約名を含むCArchiveエントリ名です: {name!r}")
    return Path(*pure.parts)


def _is_reparse_point(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    return path.is_symlink() or bool(getattr(metadata, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT)


def reject_existing_reparse_components(path: Path) -> None:
    """既存の出力先componentにsymlink/junction等があれば拒否する。"""

    absolute = path.absolute()
    parts = absolute.parts
    if not parts:
        raise ValueError("出力先パスが空です")
    current = Path(parts[0])
    if _is_reparse_point(current):
        raise ValueError(f"出力先にreparse pointが含まれます: {current}")
    for part in parts[1:]:
        current /= part
        try:
            current.lstat()
        except FileNotFoundError:
            break
        if _is_reparse_point(current):
            raise ValueError(f"出力先にreparse pointが含まれます: {current}")


def _existing_path(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    return True


def _normalize_windows_final_path(value: str) -> str:
    if value.startswith("\\\\?\\UNC\\"):
        value = "\\\\" + value[8:]
    elif value.startswith("\\\\?\\"):
        value = value[4:]
    return os.path.normcase(os.path.normpath(value))


def _windows_final_path_from_fd(file_descriptor: int) -> str | None:
    if os.name != "nt":
        return None
    import ctypes
    import msvcrt
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_final_path = kernel32.GetFinalPathNameByHandleW
    get_final_path.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]
    get_final_path.restype = wintypes.DWORD
    capacity = 32_768
    buffer = ctypes.create_unicode_buffer(capacity)
    handle = wintypes.HANDLE(msvcrt.get_osfhandle(file_descriptor))
    length = get_final_path(handle, buffer, capacity, 0)
    if length == 0 or length >= capacity:
        error = ctypes.get_last_error()
        raise ValueError(f"予約出力のfinal pathを確認できません: Windows error={error}")
    return buffer.value


def _verify_reserved_output_identity(handle, destination: Path) -> None:
    """予約済みhandleと現在の非reparse出力pathが同じ通常fileか確認する。"""

    reject_existing_reparse_components(destination)
    if _is_reparse_point(destination):
        raise ValueError(f"予約出力がreparse pointへ変更されました: {destination}")
    try:
        path_metadata = destination.stat(follow_symlinks=False)
    except FileNotFoundError as exc:
        raise ValueError(f"予約出力pathが書込み中に消失しました: {destination}") from exc
    handle_metadata = os.fstat(handle.fileno())
    if not stat.S_ISREG(handle_metadata.st_mode) or not stat.S_ISREG(path_metadata.st_mode):
        raise ValueError(f"予約出力が通常fileではありません: {destination}")
    if not os.path.samestat(handle_metadata, path_metadata):
        raise ValueError(f"予約出力handleとpathのidentityが一致しません: {destination}")
    final_path = _windows_final_path_from_fd(handle.fileno())
    if final_path is not None:
        expected = _normalize_windows_final_path(str(destination.absolute()))
        observed = _normalize_windows_final_path(final_path)
        if observed != expected:
            raise ValueError(f"予約出力のfinal pathが意図したpathと一致しません: {destination}")


def _write_reserved_file(destination: Path, payload: bytes) -> None:
    """既存fileを上書きせず予約し、identity確認後にpayloadを書き込む。"""

    try:
        with destination.open("xb") as handle:
            _verify_reserved_output_identity(handle, destination)
            written = handle.write(payload)
            if written != len(payload):
                raise OSError(f"予約出力へ全byteを書き込めませんでした: {destination}")
            handle.flush()
            os.fsync(handle.fileno())
            _verify_reserved_output_identity(handle, destination)
    except FileExistsError as exc:
        raise FileExistsError(f"既存のCArchive出力は上書きしません: {destination}") from exc


def selected_names(
    names: Iterable[str],
    exact_names: set[str],
    prefixes: tuple[str, ...],
) -> list[str]:
    """明示名または接頭辞に一致するエントリだけを返す。"""
    normalized_prefixes = tuple(value.replace("\\", "/") for value in prefixes)
    selected = []
    for name in names:
        normalized = name.replace("\\", "/")
        if normalized in exact_names or any(normalized.startswith(prefix) for prefix in normalized_prefixes):
            selected.append(name)
    return selected


def inventory(reader: MemoryCArchiveReader) -> list[dict[str, object]]:
    """内部診断向け全一覧。公開reportにはcarchive_inventory_summaryを使う。"""

    entries = []
    for name, item in reader.toc.items():
        offset, compressed_size, uncompressed_size, compression_flag, typecode = item
        entries.append(
            {
                "name": name,
                "offset": offset,
                "compressed_size": compressed_size,
                "uncompressed_size": uncompressed_size,
                "compressed": bool(compression_flag),
                "typecode": typecode,
            }
        )
    return entries


def analyze(
    sample: Path,
    expected_sha256: str,
    output_dir: Path | None = None,
    exact_names: set[str] | None = None,
    prefixes: tuple[str, ...] = (),
    max_files: int = DEFAULT_MAX_FILES,
    max_total_size: int = DEFAULT_MAX_TOTAL_SIZE,
    max_compressed_total_size: int = DEFAULT_MAX_COMPRESSED_TOTAL_SIZE,
    max_entry_size: int = DEFAULT_MAX_ENTRY_SIZE,
    max_toc_size: int = DEFAULT_MAX_TOC_SIZE,
    max_toc_entries: int = DEFAULT_MAX_TOC_ENTRIES,
) -> dict[str, object]:
    expected = expected_sha256.lower()
    if not SHA256_RE.fullmatch(expected):
        raise ValueError("expected_sha256は64桁の小文字16進数で指定してください")
    data = sample.read_bytes()
    actual = sha256_bytes(data)
    if actual != expected:
        raise ValueError(f"SHA-256が一致しません: expected={expected} actual={actual}")

    reader = MemoryCArchiveReader(data, max_toc_size=max_toc_size, max_entries=max_toc_entries)
    result: dict[str, object] = {
        "schema_version": 1,
        "sample": {"sha256": actual, "size": len(data), "source_name": sample.name},
        "classification": {
            "packaging": "PyInstaller CArchive",
            "malware_family": "not_inferred_from_packaging",
            "malicious_intent": "not_inferred_from_packaging",
        },
        "archive": carchive_inventory_summary(reader),
        "extraction": {
            "performed": False,
            "selected_count": 0,
            "written_count": 0,
            "total_compressed_size": 0,
            "total_uncompressed_size": 0,
            "files": [],
        },
        "safety": {
            "sample_executed": False,
            "network_contacted": False,
            "path_normalization": True,
            "casefold_collision_rejected": True,
            "reparse_component_rejected": True,
            "exclusive_output_create": True,
            "post_write_identity_verified": True,
            "hash_verified_before_parse": True,
            "bounded_memory_reader": True,
            "all_toc_records_bounds_validated": True,
            "all_payload_ranges_overlap_validated": True,
            "all_paths_collision_validated": True,
        },
    }
    if output_dir is None:
        return result

    if not (exact_names or set()) and not prefixes:
        raise ValueError("展開時は--nameまたは--prefixによる明示フィルタが必要です")
    selected = _select_reader_entries(reader, exact_names=exact_names, prefixes=prefixes)
    total_declared, total_compressed = _validate_selected_entry_limits(
        reader,
        selected,
        max_files=max_files,
        max_total_size=max_total_size,
        max_compressed_total_size=max_compressed_total_size,
        max_entry_size=max_entry_size,
    )
    extracted = _extract_selected_from_reader(
        reader,
        selected,
        max_files=max_files,
        max_total_size=max_total_size,
        max_compressed_total_size=max_compressed_total_size,
        max_entry_size=max_entry_size,
    )

    reject_existing_reparse_components(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    reject_existing_reparse_components(output_dir)
    files = []
    total_actual = 0
    planned: list[tuple[str, Path, bytes]] = []
    for name, relative in selected:
        payload = extracted[relative.as_posix()]
        declared = int(reader.toc[name][2])
        if len(payload) != declared:
            raise ValueError(f"展開サイズが宣言値と一致しません: {name!r}")
        total_actual += len(payload)
        if total_actual > max_total_size:
            raise ValueError("実展開サイズが上限を超えました")
        destination = output_dir / relative
        reject_existing_reparse_components(destination.parent)
        destination.parent.mkdir(parents=True, exist_ok=True)
        reject_existing_reparse_components(destination.parent)
        reject_existing_reparse_components(destination)
        if _existing_path(destination):
            raise FileExistsError(f"既存のCArchive出力は上書きしません: {destination}")
        planned.append((name, destination, payload))

    for name, destination, payload in planned:
        _write_reserved_file(destination, payload)
        relative = destination.relative_to(output_dir)
        files.append(
            {
                "name": name,
                "relative_path": relative.as_posix(),
                "size": len(payload),
                "sha256": sha256_bytes(payload),
                "typecode": reader.toc[name][4],
            }
        )
    if total_actual != total_declared:
        raise ValueError("実展開総サイズが宣言値と一致しません")
    result["extraction"] = {
        "performed": True,
        "selected_count": len(selected),
        "written_count": len(files),
        "total_compressed_size": total_compressed,
        "total_uncompressed_size": total_actual,
        "files": files,
    }
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sample", type=Path)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--name", action="append", default=[])
    parser.add_argument("--prefix", action="append", default=[])
    parser.add_argument("--max-files", type=int, default=DEFAULT_MAX_FILES)
    parser.add_argument("--max-total-size", type=int, default=DEFAULT_MAX_TOTAL_SIZE)
    parser.add_argument("--max-compressed-total-size", type=int, default=DEFAULT_MAX_COMPRESSED_TOTAL_SIZE)
    parser.add_argument("--max-entry-size", type=int, default=DEFAULT_MAX_ENTRY_SIZE)
    args = parser.parse_args()
    result = analyze(
        args.sample,
        args.expected_sha256,
        args.output_dir,
        set(args.name),
        prefixes=tuple(args.prefix),
        max_files=args.max_files,
        max_total_size=args.max_total_size,
        max_compressed_total_size=args.max_compressed_total_size,
        max_entry_size=args.max_entry_size,
    )
    rendered = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.manifest:
        args.manifest.parent.mkdir(parents=True, exist_ok=True)
        args.manifest.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
