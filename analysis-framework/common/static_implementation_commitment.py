#!/usr/bin/env python3
"""静的解析実装treeを有界列挙し、再開判断用commitmentへ固定する。"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

SCHEMA_VERSION = 1
MAX_DISCOVERY_ENTRIES = 4_096
MAX_IMPLEMENTATION_FILES = 2_048
MAX_IMPLEMENTATION_TOTAL_BYTES = 32 * 1024 * 1024
MAX_IMPLEMENTATION_FILE_BYTES = 8 * 1024 * 1024
MAX_IMPLEMENTATION_DEPTH = 16
FILE_ATTRIBUTE_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
SOURCE_ROOTS: tuple[tuple[str, frozenset[str]], ...] = (
    ("analysis-framework/common", frozenset({".py"})),
    ("analysis-framework/classifiers", frozenset({".json", ".py", ".yaml", ".yml"})),
    ("analysis-framework/registry", frozenset({".json", ".yaml", ".yml"})),
    (
        "analysis-framework/malware",
        frozenset({".json", ".py", ".rules", ".yar", ".yaml", ".yml"}),
    ),
    ("extractors", frozenset({".json", ".py", ".yaml", ".yml"})),
    ("unpackers", frozenset({".json", ".py", ".yaml", ".yml"})),
)
SOURCE_FILES = ("analysis-framework/requirements.txt",)
EXCLUDED_DIRECTORIES = frozenset({".git", ".mypy_cache", ".pytest_cache", ".venv", "__pycache__", "tests"})


class StaticImplementationError(RuntimeError):
    """静的解析実装treeの安全な固定に失敗したことを表す。"""


@dataclass(frozen=True)
class ImplementationSource:
    """commitment対象となる通常単一link file。"""

    relative_path: str
    path: Path
    size: int
    device: int
    inode: int
    modified_ns: int
    changed_ns: int


def _implementation_source(relative_path: str, path: Path, information: os.stat_result) -> ImplementationSource:
    """列挙時metadataを後続の単一handle読取りへ束縛する。"""

    return ImplementationSource(
        relative_path=relative_path,
        path=path,
        size=information.st_size,
        device=information.st_dev,
        inode=information.st_ino,
        modified_ns=information.st_mtime_ns,
        changed_ns=information.st_ctime_ns,
    )


def _matches_source(information: os.stat_result, source: ImplementationSource) -> bool:
    return (
        stat.S_ISREG(information.st_mode)
        and information.st_nlink == 1
        and not _is_reparse(information)
        and information.st_size == source.size
        and information.st_dev == source.device
        and information.st_ino == source.inode
        and information.st_mtime_ns == source.modified_ns
        and information.st_ctime_ns == source.changed_ns
    )


def _matches_open_source(information: os.stat_result, source: ImplementationSource) -> bool:
    """Windowsで表現が異なるctimeを除き、open handleのidentityを比較する。"""

    return (
        stat.S_ISREG(information.st_mode)
        and information.st_nlink == 1
        and not _is_reparse(information)
        and information.st_size == source.size
        and information.st_dev == source.device
        and information.st_ino == source.inode
        and information.st_mtime_ns == source.modified_ns
    )


def _verify_source_path(repository: Path, source: ImplementationSource) -> None:
    """sourceまでの各directoryを非reparseとして再確認する。"""

    expected = repository.joinpath(*source.relative_path.split("/"))
    if expected != source.path:
        raise StaticImplementationError("静的解析実装fileのpath identityが一致しません")
    current = repository
    for part in source.relative_path.split("/")[:-1]:
        current /= part
        try:
            information = current.lstat()
        except OSError as exc:
            raise StaticImplementationError("静的解析実装fileの親directoryを確認できません") from exc
        if not stat.S_ISDIR(information.st_mode) or current.is_symlink() or _is_reparse(information):
            raise StaticImplementationError("静的解析実装fileの親にreparse pointは使えません")


def read_implementation_source(repository: Path, source: ImplementationSource) -> bytes:
    """列挙時identityと同じ通常単一link fileを1つのhandleから有界に読む。"""

    root = _repository_root(repository)
    _verify_source_path(root, source)
    try:
        before_path = source.path.lstat()
    except OSError as exc:
        raise StaticImplementationError("静的解析実装fileを読取り前に確認できません") from exc
    if source.path.is_symlink() or not _matches_source(before_path, source):
        raise StaticImplementationError("静的解析実装fileが列挙後に変更されました")
    flags = os.O_RDONLY | int(getattr(os, "O_BINARY", 0))
    flags |= int(getattr(os, "O_CLOEXEC", 0))
    flags |= int(getattr(os, "O_NOINHERIT", 0))
    flags |= int(getattr(os, "O_NOFOLLOW", 0))
    try:
        descriptor = os.open(source.path, flags)
    except OSError as exc:
        raise StaticImplementationError("静的解析実装fileを安全に開けません") from exc
    try:
        opened = os.fstat(descriptor)
        if not _matches_open_source(opened, source):
            raise StaticImplementationError("静的解析実装fileのhandle identityが一致しません")
        remaining = source.size + 1
        chunks: list[bytes] = []
        while remaining > 0:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after_handle = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    _verify_source_path(root, source)
    try:
        after_path = source.path.lstat()
    except OSError as exc:
        raise StaticImplementationError("静的解析実装fileを読取り後に確認できません") from exc
    if (
        len(payload) != source.size
        or not _matches_open_source(after_handle, source)
        or source.path.is_symlink()
        or not _matches_source(after_path, source)
    ):
        raise StaticImplementationError("静的解析実装fileが読取り中に変更されました")
    return payload


def verify_implementation_snapshot(
    repository: Path,
    sources: tuple[ImplementationSource, ...],
    expected_sha256: dict[str, str],
) -> None:
    """tree membership、identity、size、内容hashがsnapshotから不変か確認する。"""

    current = discover_implementation_sources(repository)
    if current != sources:
        raise StaticImplementationError("静的解析実装treeのmembershipまたはidentityが変更されました")
    if set(expected_sha256) != {source.relative_path for source in sources}:
        raise StaticImplementationError("静的解析実装snapshotのfile集合が不正です")
    for source in sources:
        digest = hashlib.sha256(read_implementation_source(repository, source)).hexdigest()
        if digest != expected_sha256[source.relative_path]:
            raise StaticImplementationError("静的解析実装fileの内容が変更されました")


def _is_reparse(information: os.stat_result) -> bool:
    return bool(getattr(information, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT)


def _repository_root(value: Path) -> Path:
    path = Path(os.path.abspath(os.fspath(value)))
    current = Path(path.parts[0])
    for part in path.parts[1:]:
        current /= part
        try:
            component = current.lstat()
        except OSError as exc:
            raise StaticImplementationError("静的解析実装rootを確認できません") from exc
        if current.is_symlink() or _is_reparse(component):
            raise StaticImplementationError("静的解析実装rootにreparse pointは使えません")
    try:
        information = path.lstat()
    except OSError as exc:
        raise StaticImplementationError("静的解析実装rootを確認できません") from exc
    if not stat.S_ISDIR(information.st_mode) or path.is_symlink() or _is_reparse(information):
        raise StaticImplementationError("静的解析実装rootは通常directoryに限定します")
    return path


def discover_implementation_sources(repository: Path) -> tuple[ImplementationSource, ...]:
    """対象suffixだけをreparse非追跡・件数／深さ上限付きで列挙する。"""

    root = _repository_root(repository)
    sources: list[ImplementationSource] = []
    observed = 0
    total_bytes = 0
    seen_casefolded: set[str] = set()
    for relative_file in SOURCE_FILES:
        folded = relative_file.casefold()
        if folded in seen_casefolded:
            raise StaticImplementationError("静的解析実装source fileのpathが正規化後に重複します")
        path = root.joinpath(*relative_file.split("/"))
        try:
            information = path.lstat()
        except OSError as exc:
            raise StaticImplementationError("静的解析実装source fileがありません") from exc
        if (
            not stat.S_ISREG(information.st_mode)
            or information.st_nlink != 1
            or path.is_symlink()
            or _is_reparse(information)
            or not 0 <= information.st_size <= MAX_IMPLEMENTATION_FILE_BYTES
        ):
            raise StaticImplementationError("静的解析実装source fileは有界な通常単一link fileに限定します")
        seen_casefolded.add(folded)
        total_bytes += information.st_size
        sources.append(_implementation_source(relative_file, path, information))
        if len(sources) > MAX_IMPLEMENTATION_FILES:
            raise StaticImplementationError("静的解析実装file件数が上限を超えました")
        if total_bytes > MAX_IMPLEMENTATION_TOTAL_BYTES:
            raise StaticImplementationError("静的解析実装fileの合計sizeが上限を超えました")
    for relative_root, suffixes in SOURCE_ROOTS:
        source_root = root.joinpath(*relative_root.split("/"))
        try:
            root_information = source_root.lstat()
        except OSError as exc:
            raise StaticImplementationError("静的解析実装source rootがありません") from exc
        if (
            not stat.S_ISDIR(root_information.st_mode)
            or source_root.is_symlink()
            or _is_reparse(root_information)
        ):
            raise StaticImplementationError("静的解析実装source rootにreparse pointは使えません")
        pending: list[tuple[Path, int]] = [(source_root, 0)]
        while pending:
            current, depth = pending.pop()
            try:
                with os.scandir(current) as iterator:
                    entries = sorted(iterator, key=lambda item: (item.name.casefold(), item.name))
            except OSError as exc:
                raise StaticImplementationError("静的解析実装treeを列挙できません") from exc
            for entry in entries:
                observed += 1
                if observed > MAX_DISCOVERY_ENTRIES:
                    raise StaticImplementationError("静的解析実装treeのentry件数が上限を超えました")
                try:
                    information = entry.stat(follow_symlinks=False)
                except OSError as exc:
                    raise StaticImplementationError("静的解析実装entryを確認できません") from exc
                if entry.is_symlink() or _is_reparse(information):
                    raise StaticImplementationError("静的解析実装treeにreparse pointは使えません")
                path = Path(entry.path)
                if stat.S_ISDIR(information.st_mode):
                    if entry.name.casefold() in EXCLUDED_DIRECTORIES:
                        continue
                    if depth >= MAX_IMPLEMENTATION_DEPTH:
                        raise StaticImplementationError("静的解析実装treeの深さが上限を超えました")
                    pending.append((path, depth + 1))
                    continue
                if (
                    not stat.S_ISREG(information.st_mode)
                    or path.suffix.casefold() not in suffixes
                    or path.name.casefold().startswith("test_")
                ):
                    continue
                try:
                    file_information = path.lstat()
                except OSError as exc:
                    raise StaticImplementationError("静的解析実装fileを確認できません") from exc
                if (
                    not stat.S_ISREG(file_information.st_mode)
                    or path.is_symlink()
                    or _is_reparse(file_information)
                    or file_information.st_nlink != 1
                    or not 0 <= file_information.st_size <= MAX_IMPLEMENTATION_FILE_BYTES
                ):
                    raise StaticImplementationError("静的解析実装fileは有界な通常単一link fileに限定します")
                try:
                    relative = path.relative_to(root).as_posix()
                except ValueError as exc:
                    raise StaticImplementationError("静的解析実装fileがrepository外です") from exc
                folded = relative.casefold()
                if folded in seen_casefolded:
                    raise StaticImplementationError("静的解析実装fileのpathが正規化後に重複します")
                seen_casefolded.add(folded)
                total_bytes += file_information.st_size
                if len(sources) >= MAX_IMPLEMENTATION_FILES:
                    raise StaticImplementationError("静的解析実装file件数が上限を超えました")
                if total_bytes > MAX_IMPLEMENTATION_TOTAL_BYTES:
                    raise StaticImplementationError("静的解析実装fileの合計sizeが上限を超えました")
                sources.append(_implementation_source(relative, path, file_information))
    return tuple(sorted(sources, key=lambda item: (item.relative_path.casefold(), item.relative_path)))


def build_implementation_commitment(
    repository: Path,
    *,
    hash_file: Callable[[ImplementationSource], str],
) -> tuple[dict[str, object], tuple[ImplementationSource, ...]]:
    """callerが安全に読んだhashからpath込みのcanonical commitmentを返す。"""

    sources = discover_implementation_sources(repository)
    files: list[dict[str, object]] = []
    for source in sources:
        digest = hash_file(source)
        if not isinstance(digest, str) or len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
            raise StaticImplementationError("静的解析実装fileのSHA-256が不正です")
        files.append({"path": source.relative_path, "size": source.size, "sha256": digest})
    canonical = {
        "schema_version": SCHEMA_VERSION,
        "roots": [relative for relative, _suffixes in SOURCE_ROOTS],
        "source_files": list(SOURCE_FILES),
        "files": files,
    }
    encoded = json.dumps(
        canonical,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    ).encode("utf-8")
    return (
        {
            "schema_version": SCHEMA_VERSION,
            "file_count": len(files),
            "total_bytes": sum(source.size for source in sources),
            "manifest_sha256": hashlib.sha256(encoded).hexdigest(),
        },
        sources,
    )
