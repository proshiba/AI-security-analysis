#!/usr/bin/env python3
"""PyInstaller CArchiveを実行せず、安全な範囲で一覧化・静的展開する。"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
from typing import Iterable

from PyInstaller.archive.readers import CArchiveReader


SHA256_RE = re.compile(r"[0-9a-f]{64}")
DEFAULT_MAX_FILES = 512
DEFAULT_MAX_TOTAL_SIZE = 256 * 1024 * 1024


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe_relative_path(name: str) -> Path:
    """CArchive内の名前を安全な相対パスへ変換する。"""
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
    if any(any(ord(character) < 32 for character in part) for part in pure.parts):
        raise ValueError(f"制御文字を含むCArchiveエントリ名です: {name!r}")
    return Path(*pure.parts)


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


def inventory(reader: CArchiveReader) -> list[dict[str, object]]:
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
) -> dict[str, object]:
    expected = expected_sha256.lower()
    if not SHA256_RE.fullmatch(expected):
        raise ValueError("expected_sha256は64桁の小文字16進数で指定してください")
    data = sample.read_bytes()
    actual = sha256_bytes(data)
    if actual != expected:
        raise ValueError(f"SHA-256が一致しません: expected={expected} actual={actual}")

    reader = CArchiveReader(str(sample))
    entries = inventory(reader)
    result: dict[str, object] = {
        "schema_version": 1,
        "sample": {"sha256": actual, "size": len(data), "source_name": sample.name},
        "archive": {
            "format": "PyInstaller CArchive",
            "entry_count": len(entries),
            "options": list(reader.options),
            "entries": entries,
        },
        "extraction": {
            "performed": False,
            "selected_count": 0,
            "written_count": 0,
            "total_uncompressed_size": 0,
            "files": [],
        },
        "safety": {
            "sample_executed": False,
            "network_contacted": False,
            "path_normalization": True,
            "hash_verified_before_parse": True,
        },
    }
    if output_dir is None:
        return result

    exact = {value.replace("\\", "/") for value in (exact_names or set())}
    if not exact and not prefixes:
        raise ValueError("展開時は--nameまたは--prefixによる明示フィルタが必要です")
    names = selected_names(reader.toc, exact, prefixes)
    if len(names) > max_files:
        raise ValueError(f"選択件数が上限を超えました: {len(names)} > {max_files}")
    total_declared = sum(int(reader.toc[name][2]) for name in names)
    if total_declared > max_total_size:
        raise ValueError(f"宣言展開サイズが上限を超えました: {total_declared} > {max_total_size}")

    output_dir.mkdir(parents=True, exist_ok=True)
    files = []
    total_actual = 0
    for name in names:
        relative = safe_relative_path(name)
        payload = reader.extract(name)
        declared = int(reader.toc[name][2])
        if len(payload) != declared:
            raise ValueError(f"展開サイズが宣言値と一致しません: {name!r}")
        total_actual += len(payload)
        if total_actual > max_total_size:
            raise ValueError("実展開サイズが上限を超えました")
        destination = output_dir / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload)
        files.append(
            {
                "name": name,
                "relative_path": relative.as_posix(),
                "size": len(payload),
                "sha256": sha256_bytes(payload),
                "typecode": reader.toc[name][4],
            }
        )
    result["extraction"] = {
        "performed": True,
        "selected_count": len(names),
        "written_count": len(files),
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
    args = parser.parse_args()
    result = analyze(
        args.sample,
        args.expected_sha256,
        args.output_dir,
        set(args.name),
        tuple(args.prefix),
        args.max_files,
        args.max_total_size,
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
