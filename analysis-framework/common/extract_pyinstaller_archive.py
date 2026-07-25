#!/usr/bin/env python3
"""PyInstaller CArchiveを実行せず、安全な範囲で一覧化・静的展開する。"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import struct
from typing import Iterable
import unicodedata
import zlib


SHA256_RE = re.compile(r"[0-9a-f]{64}")
DEFAULT_MAX_FILES = 512
DEFAULT_MAX_TOTAL_SIZE = 256 * 1024 * 1024
DEFAULT_MAX_COMPRESSED_TOTAL_SIZE = 256 * 1024 * 1024

DEFAULT_MAX_ENTRY_SIZE = 64 * 1024 * 1024
DEFAULT_MAX_TOC_SIZE = 16 * 1024 * 1024
DEFAULT_MAX_TOC_ENTRIES = 4_096
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
        if not python_library.rstrip(b"\0"):
            raise MemoryCArchiveError("PyInstaller CArchiveのPython共有ライブラリ名が空です")

        self._data = memoryview(data)
        self._start_offset = cookie_end - archive_length
        self.python_version = python_version
        self.python_library = python_library.rstrip(b"\0").decode("utf-8", errors="replace")
        toc_start = self._start_offset + toc_offset
        toc_end = toc_start + toc_length
        if toc_start < self._start_offset or toc_end < toc_start or toc_end > cookie_offset:
            raise MemoryCArchiveError("PyInstaller CArchive TOCの境界が不正です")
        self._data_region_length = toc_offset
        self.toc, self.options = self._parse_toc(
            bytes(self._data[toc_start:toc_end]),
            max_entries=max_entries,
        )

    def _parse_toc(
        self,
        data: bytes,
        *,
        max_entries: int,
    ) -> tuple[dict[str, tuple[int, int, int, int, str]], list[str]]:
        toc: dict[str, tuple[int, int, int, int, str]] = {}
        options: list[str] = []
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
            name_raw = data[cursor + self.TOC_ENTRY_LENGTH : cursor + entry_length].rstrip(b"\0")
            if not name_raw:
                raise MemoryCArchiveError("PyInstaller CArchive TOC entry名が空です")
            try:
                name = name_raw.decode("utf-8")
                typecode = typecode_raw.decode("ascii")
            except UnicodeDecodeError as exc:
                raise MemoryCArchiveError("PyInstaller CArchive TOCの文字コードが不正です") from exc
            if compressed not in {0, 1}:
                raise MemoryCArchiveError("PyInstaller CArchiveの圧縮flagが不正です")
            if offset > self._data_region_length or length > self._data_region_length - offset:
                raise MemoryCArchiveError("PyInstaller CArchive entryの境界が不正です")
            entry = (offset, length, unpacked_length, compressed, typecode)
            if typecode == "o":
                options.append(name)
            elif name in toc:
                raise MemoryCArchiveError("PyInstaller CArchive TOC entry名が重複しています")
            else:
                toc[name] = entry
            cursor += entry_length
            entry_count += 1
            if entry_count > max_entries:
                raise MemoryCArchiveError("PyInstaller CArchive TOC entry数が上限を超えました")
        if cursor != len(data):
            raise MemoryCArchiveError("PyInstaller CArchive TOC末尾が不正です")
        return toc, options

    def extract(self, name: str, *, max_size: int = DEFAULT_MAX_ENTRY_SIZE) -> bytes:
        """指定entryだけを上限付きでメモリへ展開する。"""

        try:
            offset, length, unpacked_length, compressed, _typecode = self.toc[name]
        except KeyError as exc:
            raise KeyError(f"CArchive entryがありません: {name!r}") from exc
        if unpacked_length > max_size or length > max_size:
            raise MemoryCArchiveError("PyInstaller CArchive entryが展開上限を超えました")
        start = self._start_offset + offset
        payload = bytes(self._data[start : start + length])
        if compressed:
            decoder = zlib.decompressobj()
            try:
                unpacked = decoder.decompress(payload, max_size + 1)
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
    from ctypes import wintypes
    import msvcrt

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
    """bounded memory readerが検証済みのTOCだけを一覧化する。"""

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
    entries = inventory(reader)
    result: dict[str, object] = {
        "schema_version": 1,
        "sample": {"sha256": actual, "size": len(data), "source_name": sample.name},
        "archive": {
            "format": "PyInstaller CArchive",
            "entry_count": len(entries),
            "options": list(reader.options),
            "entries": entries,
            "reader": "bounded_memory_carchive",
        },
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
