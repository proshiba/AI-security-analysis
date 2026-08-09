"""解析成果物の失敗時cleanupに使う、path identity保護付きhelper。"""

from __future__ import annotations

import os
import secrets
import stat
from pathlib import Path


def _is_reparse(metadata: os.stat_result) -> bool:
    flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(flag and getattr(metadata, "st_file_attributes", 0) & flag)


def stable_file_identity(metadata: os.stat_result) -> tuple[int, int]:
    """同一filesystem objectを比較するためdevice/inode identityを返す。"""

    return int(metadata.st_dev), int(metadata.st_ino)


def _is_single_regular_file(path: Path, metadata: os.stat_result) -> bool:
    return (
        stat.S_ISREG(metadata.st_mode)
        and not stat.S_ISLNK(metadata.st_mode)
        and not _is_reparse(metadata)
        and int(getattr(metadata, "st_nlink", 1)) == 1
        and not path.is_symlink()
    )


def _restore_quarantined_path(quarantine: Path, target: Path) -> bool:
    """差替えられたpathを上書きせず元の名前へ戻す。

    Python標準APIには、すべてのOSで利用できるfile-ID条件付きrename/unlinkがない。
    通常fileではhardlinkを使って宛先非存在を原子的に要求し、利用できない
    filesystemではrename前後に宛先を再確認する。復元できない場合はquarantineを
    残し、別objectを削除しないことを優先する。
    """

    if os.path.lexists(target):
        return False
    try:
        os.link(quarantine, target, follow_symlinks=False)
    except (NotImplementedError, OSError):
        try:
            if os.path.lexists(target):
                return False
            os.rename(quarantine, target)
        except OSError:
            return False
        return True

    try:
        quarantine_metadata = quarantine.lstat()
        target_metadata = target.lstat()
        if stable_file_identity(quarantine_metadata) != stable_file_identity(target_metadata):
            return False
        os.unlink(quarantine)
    except OSError:
        return False
    return True


def unlink_created_file_if_unchanged(
    path: Path,
    created_metadata: os.stat_result,
) -> bool:
    """作成した同一通常fileがpath上に残る場合だけcleanupする。

    pathがsymlink/reparse/hardlinkになった場合、または別identityへ置換された
    場合は削除しない。失敗cleanup自体の失敗は元例外を隠さないようFalseで返す。

    標準APIにはportableなfile-ID条件付きunlinkがないため、対象を推測困難な
    sibling名へ移してidentityを再検証してから削除する。同一directoryを変更可能な
    adversaryがquarantine名まで競合させる場合の完全な原子性は保証できない。
    """

    target = Path(path)
    try:
        parent = target.parent
        parent_metadata = parent.lstat()
        if (
            not stat.S_ISDIR(parent_metadata.st_mode)
            or stat.S_ISLNK(parent_metadata.st_mode)
            or _is_reparse(parent_metadata)
        ):
            return False
        current = target.lstat()
    except OSError:
        return False
    if (
        not _is_single_regular_file(target, current)
        or stable_file_identity(current) != stable_file_identity(created_metadata)
    ):
        return False

    quarantine: Path | None = None
    for _ in range(16):
        candidate = parent / f".{target.name}.cleanup-{secrets.token_hex(16)}"
        if not os.path.lexists(candidate):
            quarantine = candidate
            break
    if quarantine is None:
        return False
    try:
        os.rename(target, quarantine)
    except OSError:
        return False

    try:
        moved = quarantine.lstat()
        parent_after = parent.lstat()
    except OSError:
        return False
    if (
        stable_file_identity(parent_metadata) != stable_file_identity(parent_after)
        or not _is_single_regular_file(quarantine, moved)
        or stable_file_identity(moved) != stable_file_identity(created_metadata)
    ):
        _restore_quarantined_path(quarantine, target)
        return False

    try:
        final = quarantine.lstat()
        if (
            not _is_single_regular_file(quarantine, final)
            or stable_file_identity(final) != stable_file_identity(created_metadata)
        ):
            _restore_quarantined_path(quarantine, target)
            return False
        os.unlink(quarantine)
    except OSError:
        _restore_quarantined_path(quarantine, target)
        return False
    return True
