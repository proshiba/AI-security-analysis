"""解析入力を単一handleから不変snapshotとして読むための共通境界。"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from safe_artifact_io import unlink_created_file_if_unchanged
from safe_private_output import reject_existing_reparse_components

FILE_ATTRIBUTE_REPARSE_POINT = 0x400
READ_CHUNK = 1024 * 1024


def decode_strict_json(data: bytes) -> object:
    """UTF-8 JSONを重複keyと非有限数値を拒否して復号する。"""

    def reject_constant(value: str) -> None:
        raise ValueError(f"JSONの非有限数値は許可しません: {value}")

    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        document: dict[str, object] = {}
        for key, value in pairs:
            if key in document:
                raise ValueError(f"JSON objectに重複keyがあります: {key}")
            document[key] = value
        return document

    return json.loads(
        data.decode("utf-8"),
        object_pairs_hook=unique_object,
        parse_constant=reject_constant,
    )


@dataclass(frozen=True)
class SnapshotIdentity:
    """公開可能な入力snapshot識別情報。"""

    size: int
    sha256: str
    device: int
    inode: int
    modified_ns: int
    link_count: int

    def public_dict(self) -> dict[str, int | str]:
        """host内部identityを除いた決定的な公開JSON表現を返す。"""
        return {
            "size": self.size,
            "sha256": self.sha256,
            "link_count": self.link_count,
        }


@dataclass(frozen=True)
class ByteSnapshot:
    """上限内で読み取ったbytesとhandle identity。"""

    data: bytes
    identity: SnapshotIdentity


@dataclass(frozen=True)
class FileSnapshot:
    """private temporary fileへ固定した入力snapshot。"""

    path: Path
    identity: SnapshotIdentity


def _absolute(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _identity_tuple(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        int(value.st_dev),
        int(value.st_ino),
        int(value.st_size),
        int(value.st_mtime_ns),
        int(value.st_mode),
        int(value.st_nlink),
    )


def _filesystem_object(value: os.stat_result) -> tuple[int, int]:
    return int(value.st_dev), int(value.st_ino)


def _checked_directory(path: Path) -> os.stat_result:
    reject_existing_reparse_components(path)
    metadata = path.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or path.is_symlink()
        or int(getattr(metadata, "st_file_attributes", 0)) & FILE_ATTRIBUTE_REPARSE_POINT
    ):
        raise ValueError("出力先parentは通常directoryではありません")
    return metadata


def _verify_created_output(
    path: Path,
    parent_before: os.stat_result,
    handle: BinaryIO,
    created: os.stat_result,
) -> None:
    opened = os.fstat(handle.fileno())
    at_path = path.lstat()
    parent_after = path.parent.lstat()
    if (
        not stat.S_ISREG(opened.st_mode)
        or not stat.S_ISREG(at_path.st_mode)
        or path.is_symlink()
        or int(getattr(at_path, "st_file_attributes", 0)) & FILE_ATTRIBUTE_REPARSE_POINT
        or int(opened.st_nlink) != 1
        or int(at_path.st_nlink) != 1
        or _filesystem_object(opened) != _filesystem_object(created)
        or _filesystem_object(at_path) != _filesystem_object(created)
    ):
        raise ValueError("作成した出力fileのidentityが変化しました")
    if (
        not stat.S_ISDIR(parent_after.st_mode)
        or path.parent.is_symlink()
        or int(getattr(parent_after, "st_file_attributes", 0)) & FILE_ATTRIBUTE_REPARSE_POINT
        or _filesystem_object(parent_after) != _filesystem_object(parent_before)
    ):
        raise ValueError("出力先parent directoryのidentityが変化しました")


def _checked_lstat(path: Path) -> os.stat_result:
    reject_existing_reparse_components(path)
    value = path.lstat()
    if path.is_symlink() or (int(getattr(value, "st_file_attributes", 0)) & FILE_ATTRIBUTE_REPARSE_POINT):
        raise ValueError("reparse point／symlink入力は許可しません")
    if not stat.S_ISREG(value.st_mode):
        raise ValueError("入力は通常fileではありません")
    if int(value.st_nlink) != 1:
        raise ValueError("hardlink入力は許可しません")
    return value


def _verify_handle_identity(
    path: Path,
    before: os.stat_result,
    handle: BinaryIO,
) -> os.stat_result:
    opened = os.fstat(handle.fileno())
    if _identity_tuple(opened) != _identity_tuple(before):
        raise ValueError("open前後で入力identityが変化しました")
    if _identity_tuple(path.lstat()) != _identity_tuple(before):
        raise ValueError("入力pathがopen後に置換されました")
    return opened


def _finalize_identity(
    path: Path,
    before: os.stat_result,
    handle: BinaryIO,
    digest: str,
    size: int,
) -> SnapshotIdentity:
    after_handle = os.fstat(handle.fileno())
    after_path = path.lstat()
    if _identity_tuple(after_handle) != _identity_tuple(before):
        raise ValueError("read中に入力handle identityが変化しました")
    if _identity_tuple(after_path) != _identity_tuple(before):
        raise ValueError("read中に入力path identityが変化しました")
    if size != int(before.st_size):
        raise ValueError("stat sizeとsnapshot sizeが一致しません")
    return SnapshotIdentity(
        size=size,
        sha256=digest,
        device=int(before.st_dev),
        inode=int(before.st_ino),
        modified_ns=int(before.st_mtime_ns),
        link_count=int(before.st_nlink),
    )


def read_bounded_snapshot(path: Path, maximum: int) -> ByteSnapshot:
    """maximum+1方式で単一handleからbounded bytesを読む。"""
    source = _absolute(path)
    before = _checked_lstat(source)
    if before.st_size > maximum:
        raise ValueError("入力が許可上限を超えています")
    with source.open("rb", buffering=0) as handle:
        _verify_handle_identity(source, before, handle)
        data = handle.read(maximum + 1)
        if len(data) > maximum or handle.read(1):
            raise ValueError("入力が許可上限を超えています")
        digest = hashlib.sha256(data).hexdigest()
        identity = _finalize_identity(source, before, handle, digest, len(data))
    return ByteSnapshot(data=data, identity=identity)


def copy_bounded_snapshot(
    source_path: Path,
    destination_path: Path,
    maximum: int,
    *,
    expected_sha256: str,
) -> FileSnapshot:
    """単一handleからprivate temporary fileへcopyしhashを照合する。"""
    source = _absolute(source_path)
    destination = _absolute(destination_path)
    if os.path.normcase(str(source)) == os.path.normcase(str(destination)):
        raise ValueError("snapshot destinationと入力が同一です")
    if destination.exists() or destination.is_symlink():
        raise FileExistsError("snapshot destinationが既に存在します")
    before = _checked_lstat(source)
    parent_before = _checked_directory(destination.parent)
    if before.st_size > maximum:
        raise ValueError("入力が許可上限を超えています")
    digest = hashlib.sha256()
    total = 0
    created_metadata: os.stat_result | None = None
    try:
        with source.open("rb", buffering=0) as input_handle, destination.open("xb", buffering=0) as output_handle:
            created_metadata = os.fstat(output_handle.fileno())
            _verify_created_output(destination, parent_before, output_handle, created_metadata)
            _verify_handle_identity(source, before, input_handle)
            while True:
                chunk = input_handle.read(min(READ_CHUNK, maximum + 1 - total))
                if not chunk:
                    break
                total += len(chunk)
                if total > maximum:
                    raise ValueError("入力が許可上限を超えています")
                output_handle.write(chunk)
                digest.update(chunk)
            output_handle.flush()
            os.fsync(output_handle.fileno())
            _verify_created_output(destination, parent_before, output_handle, created_metadata)
            identity = _finalize_identity(source, before, input_handle, digest.hexdigest(), total)
    except Exception:
        if created_metadata is not None:
            unlink_created_file_if_unchanged(destination, created_metadata)
        raise
    if identity.sha256 != expected_sha256:
        if created_metadata is not None:
            unlink_created_file_if_unchanged(destination, created_metadata)
        raise ValueError("PCAP SHA-256が期待値と一致しません")
    return FileSnapshot(path=destination, identity=identity)


def ensure_new_output(output: Path, inputs: Iterable[Path]) -> Path:
    """入力との同一pathと既存出力を拒否する。"""
    target = _absolute(output)
    input_names = {os.path.normcase(str(_absolute(path))) for path in inputs}
    if os.path.normcase(str(target)) in input_names:
        raise ValueError("入力と出力を同じpathにできません")
    if target.exists() or target.is_symlink():
        raise FileExistsError("既存出力の上書きは許可しません")
    _checked_directory(target.parent)
    parent_stat = target.parent.lstat()
    if not stat.S_ISDIR(parent_stat.st_mode):
        raise ValueError("出力先parentはdirectoryではありません")
    if target.parent.is_symlink() or (
        int(getattr(parent_stat, "st_file_attributes", 0)) & FILE_ATTRIBUTE_REPARSE_POINT
    ):
        raise ValueError("reparse point配下へは出力しません")
    return target


def write_new_json(path: Path, document: object) -> None:
    """既存fileを上書きせずUTF-8 JSONを作成する。"""
    serialized = json.dumps(document, ensure_ascii=False, indent=2) + "\n"
    parent_before = _checked_directory(path.parent)
    created_metadata: os.stat_result | None = None
    try:
        with path.open("x", encoding="utf-8", newline="\n") as handle:
            created_metadata = os.fstat(handle.fileno())
            _verify_created_output(path, parent_before, handle, created_metadata)
            handle.write(serialized)
            handle.flush()
            os.fsync(handle.fileno())
            _verify_created_output(path, parent_before, handle, created_metadata)
    except Exception:
        if created_metadata is not None:
            unlink_created_file_if_unchanged(path, created_metadata)
        raise


__all__ = [
    "ByteSnapshot",
    "FileSnapshot",
    "SnapshotIdentity",
    "copy_bounded_snapshot",
    "decode_strict_json",
    "ensure_new_output",
    "read_bounded_snapshot",
    "write_new_json",
]
