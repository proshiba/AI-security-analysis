#!/usr/bin/env python3
"""復号済みバイナリを許可された非公開ディレクトリへ安全に保存する。"""

from __future__ import annotations

from collections.abc import Iterable
import hashlib
import os
from pathlib import Path
import re
import stat


FILE_ATTRIBUTE_REPARSE_POINT = getattr(
    stat,
    "FILE_ATTRIBUTE_REPARSE_POINT",
    0x400,
)
SHA256_RE = re.compile(r"[0-9a-f]{64}")
WINDOWS_RESERVED_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", "CLOCK$"}
    | {f"COM{index}" for index in range(1, 10)}
    | {f"LPT{index}" for index in range(1, 10)}
    | {"COM¹", "COM²", "COM³", "LPT¹", "LPT²", "LPT³"}
)


def _lexical_absolute(path: Path) -> Path:
    """symlinkを解決せず、`.`と`..`だけを正規化した絶対pathを返す。"""

    return Path(os.path.abspath(os.fspath(path)))


def _is_reparse_point(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    return path.is_symlink() or bool(getattr(metadata, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT)


def reject_existing_reparse_components(path: Path) -> None:
    """既存path componentにsymlink、junction、reparse pointがあれば拒否する。"""

    absolute = _lexical_absolute(path)
    parts = absolute.parts
    if not parts:
        raise ValueError("出力pathが空です")
    current = Path(parts[0])
    if _is_reparse_point(current):
        raise ValueError(f"出力pathにreparse pointが含まれます: {current}")
    for part in parts[1:]:
        current /= part
        try:
            current.lstat()
        except FileNotFoundError:
            break
        if _is_reparse_point(current):
            raise ValueError(f"出力pathにreparse pointが含まれます: {current}")


def _existing_path(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    return True


def _normalized_path_key(path: Path) -> str:
    return os.path.normcase(os.path.normpath(os.fspath(_lexical_absolute(path))))


def _is_within_root(path: Path, root: Path) -> bool:
    try:
        common = os.path.commonpath([_normalized_path_key(path), _normalized_path_key(root)])
    except ValueError:
        return False
    return common == _normalized_path_key(root)


def _validate_relative_output_name(destination: Path, root: Path) -> None:
    try:
        relative = destination.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"出力先が許可rootの外側です: destination={destination} root={root}") from exc
    if not relative.parts:
        raise ValueError("許可root自体を出力fileとして使用できません")
    for part in relative.parts:
        if part in {"", ".", ".."}:
            raise ValueError(f"安全でない出力名です: {relative}")
        if ":" in part or any(ord(character) < 32 for character in part):
            raise ValueError(f"安全でない出力名です: {relative}")
        if part.endswith((" ", ".")):
            raise ValueError(f"安全でない出力名です: {relative}")
        reserved_stem = part.split(".", 1)[0].rstrip(" .").upper()
        if reserved_stem in WINDOWS_RESERVED_NAMES:
            raise ValueError(f"Windows予約名を出力に使用できません: {relative}")


def _prepare_root(root: Path, *, create: bool) -> Path:
    absolute = _lexical_absolute(root)
    reject_existing_reparse_components(absolute)
    if create:
        absolute.mkdir(parents=True, exist_ok=True)
    reject_existing_reparse_components(absolute)
    if not absolute.is_dir():
        raise NotADirectoryError(f"許可rootが通常directoryではありません: {absolute}")
    return absolute


def _prepare_destination(destination: Path, root: Path) -> Path:
    absolute = _lexical_absolute(destination)
    if not _is_within_root(absolute, root):
        raise ValueError(f"出力先が許可rootの外側です: destination={absolute} root={root}")
    _validate_relative_output_name(absolute, root)

    reject_existing_reparse_components(absolute)
    if not absolute.parent.is_dir():
        raise NotADirectoryError(f"出力先の親directoryがありません: {absolute.parent}")
    if _existing_path(absolute):
        raise FileExistsError(f"既存の非公開出力は上書きしません: {absolute}")
    return absolute


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
    get_final_path.argtypes = [
        wintypes.HANDLE,
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
    ]
    get_final_path.restype = wintypes.DWORD
    capacity = 32_768
    buffer = ctypes.create_unicode_buffer(capacity)
    handle = wintypes.HANDLE(msvcrt.get_osfhandle(file_descriptor))
    length = get_final_path(handle, buffer, capacity, 0)
    if length == 0 or length >= capacity:
        error = ctypes.get_last_error()
        raise ValueError(f"非公開出力のfinal pathを確認できません: Windows error={error}")
    return buffer.value


def _verify_reserved_output_identity(handle, destination: Path, root: Path) -> None:
    """予約済みhandle、path、許可rootの同一性と通常file属性を確認する。"""

    if not _is_within_root(destination, root):
        raise ValueError(f"予約済み出力が許可rootの外側です: {destination}")
    reject_existing_reparse_components(root)
    reject_existing_reparse_components(destination)
    if _is_reparse_point(destination):
        raise ValueError(f"予約済み出力がreparse pointへ変更されました: {destination}")
    try:
        path_metadata = destination.stat(follow_symlinks=False)
    except FileNotFoundError as exc:
        raise ValueError(f"予約済み出力pathが書込み中に消失しました: {destination}") from exc
    handle_metadata = os.fstat(handle.fileno())
    if not stat.S_ISREG(handle_metadata.st_mode) or not stat.S_ISREG(path_metadata.st_mode):
        raise ValueError(f"予約済み出力が通常fileではありません: {destination}")
    if not os.path.samestat(handle_metadata, path_metadata):
        raise ValueError(f"予約済み出力handleとpathのidentityが一致しません: {destination}")
    final_path = _windows_final_path_from_fd(handle.fileno())
    if final_path is not None:
        expected = _normalize_windows_final_path(os.fspath(destination))
        observed = _normalize_windows_final_path(final_path)
        if observed != expected:
            raise ValueError(f"予約済み出力のfinal pathが意図したpathと一致しません: {destination}")


def _sha256_from_handle(handle) -> str:
    handle.seek(0)
    digest = hashlib.sha256()
    while chunk := handle.read(1024 * 1024):
        digest.update(chunk)
    return digest.hexdigest()


def _remove_if_same_file(destination: Path, metadata: os.stat_result) -> bool:
    """作成したfileが同一identityのままの場合だけ失敗時に削除する。"""

    try:
        reject_existing_reparse_components(destination)
        if _is_reparse_point(destination):
            return False
        current = destination.stat(follow_symlinks=False)
        if not stat.S_ISREG(current.st_mode):
            return False
        if not os.path.samestat(metadata, current):
            return False
        destination.unlink()
    except (OSError, ValueError):
        return False
    return True


def _write_reserved_file(
    destination: Path,
    payload: bytes,
    expected_sha256: str,
    root: Path,
) -> os.stat_result:
    created_metadata: os.stat_result | None = None
    try:
        with destination.open("xb+") as handle:
            created_metadata = os.fstat(handle.fileno())
            _verify_reserved_output_identity(handle, destination, root)
            remaining = memoryview(payload)
            while remaining:
                written = handle.write(remaining)
                if not written:
                    raise OSError(f"非公開出力へ全byteを書き込めませんでした: {destination}")
                remaining = remaining[written:]
            handle.flush()
            os.fsync(handle.fileno())
            _verify_reserved_output_identity(handle, destination, root)
            observed_sha256 = _sha256_from_handle(handle)
            if observed_sha256 != expected_sha256:
                raise ValueError(
                    "書込み後SHA-256が復号済みデータと一致しません: "
                    f"expected={expected_sha256} actual={observed_sha256}"
                )
            _verify_reserved_output_identity(handle, destination, root)
            return created_metadata
    except FileExistsError as exc:
        raise FileExistsError(f"既存の非公開出力は上書きしません: {destination}") from exc
    except BaseException:
        if created_metadata is not None:
            _remove_if_same_file(destination, created_metadata)
        raise


def write_private_outputs(
    outputs: Iterable[tuple[Path, bytes, str]],
    *,
    allowed_root: Path,
    create_root: bool = False,
) -> dict[Path, str]:
    """検証済みbytesを排他作成し、失敗時はこの呼出しで作成したfileだけ戻す。

    `outputs`の各要素は`(出力path, payload, 期待SHA-256)`である。SHA-256は
    fileを作成する前にpayloadと照合し、fsync後にも同じhandleから再計算する。
    """

    planned = list(outputs)
    validated: list[tuple[Path, bytes, str]] = []
    path_keys: set[str] = set()
    for destination, payload, expected_sha256 in planned:
        expected = expected_sha256.lower()
        if not SHA256_RE.fullmatch(expected):
            raise ValueError(f"期待SHA-256の形式が不正です: {expected_sha256!r}")
        actual = hashlib.sha256(payload).hexdigest()
        if actual != expected:
            raise ValueError(f"復号済みデータのSHA-256が期待値と一致しません: expected={expected} actual={actual}")
        key = _normalized_path_key(destination)
        if key in path_keys:
            raise ValueError(f"非公開出力pathが重複しています: {destination}")
        path_keys.add(key)
        validated.append((destination, payload, expected))

    root = _prepare_root(allowed_root, create=create_root)
    prepared = [
        (_prepare_destination(destination, root), payload, expected) for destination, payload, expected in validated
    ]

    created: list[tuple[Path, os.stat_result]] = []
    digests: dict[Path, str] = {}
    try:
        for destination, payload, expected in prepared:
            metadata = _write_reserved_file(
                destination,
                payload,
                expected,
                root,
            )
            created.append((destination, metadata))
            digests[destination] = expected
    except BaseException as exc:
        cleanup_failures = [
            os.fspath(destination)
            for destination, metadata in reversed(created)
            if not _remove_if_same_file(destination, metadata)
        ]
        if cleanup_failures and hasattr(exc, "add_note"):
            exc.add_note("作成済み出力を安全に削除できませんでした: " + ", ".join(cleanup_failures))
        raise
    return digests


def write_private_output(
    destination: Path,
    payload: bytes,
    expected_sha256: str,
    *,
    allowed_root: Path | None = None,
) -> str:
    """単一の明示pathへ安全に保存し、検証済みSHA-256を返す。"""

    root = allowed_root if allowed_root is not None else destination.parent
    written = write_private_outputs(
        [(destination, payload, expected_sha256)],
        allowed_root=root,
    )
    return next(iter(written.values()))
