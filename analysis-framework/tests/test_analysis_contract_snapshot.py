"""case成果物の単一handle snapshot境界を敵対条件で回帰検証する。"""

from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path

import pytest

FRAMEWORK_ROOT = Path(__file__).resolve().parents[1]
COMMON_ROOT = FRAMEWORK_ROOT / "common"
if str(COMMON_ROOT) not in sys.path:
    sys.path.insert(0, str(COMMON_ROOT))

import analysis_contract as contract  # noqa: E402


def test_valid_json_and_artifact_hash_use_verified_snapshot(tmp_path: Path) -> None:
    """正常fileは厳密JSON解釈とSHA-256検証の両方で受理する。"""

    case_dir = tmp_path / "case"
    case_dir.mkdir()
    path = case_dir / "artifact.json"
    payload = b'{"schema_version":1,"nested":{"enabled":true}}'
    path.write_bytes(payload)

    assert contract.load_json_object_strict(path) == {
        "schema_version": 1,
        "nested": {"enabled": True},
    }
    expected = contract.artifact_hashes(case_dir, ["artifact.json"])
    assert expected == {"artifact.json": hashlib.sha256(payload).hexdigest()}
    assert contract.verify_artifact_hashes(case_dir, expected) == []


@pytest.mark.parametrize(
    "payload",
    [
        b'{"value":NaN}',
        b'{"value":Infinity}',
        b'{"value":-Infinity}',
        b'{"value":1e9999}',
        b'{"value":1,"value":2}',
        b'\xef\xbb\xbf{"value":1}',
        b'{"value":"\xff"}',
    ],
)
def test_strict_json_rejects_nonfinite_duplicate_bom_and_invalid_utf8(
    tmp_path: Path,
    payload: bytes,
) -> None:
    """非有限数、重複key、BOM、UTF-8不正byteをfail-closedで拒否する。"""

    path = tmp_path / "artifact.json"
    path.write_bytes(payload)

    with pytest.raises(ValueError):
        contract.load_json_object_strict(path)


@pytest.mark.parametrize(
    "payload",
    [
        b'{"value":' + (b'9' * 500) + b'}',
        b'{"value":' + (b'[' * 2_000) + b'0' + (b']' * 2_000) + b'}',
    ],
)
def test_strict_json_rejects_excessive_integer_and_nesting(
    tmp_path: Path,
    payload: bytes,
) -> None:
    """過大整数と過深containerを成果物検証前に拒否する。"""

    path = tmp_path / "artifact.json"
    path.write_bytes(payload)
    with pytest.raises(ValueError):
        contract.load_json_object_strict(path)


def test_json_rejects_file_over_configured_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """lstat時点で上限を超えるfileを読まずに拒否する。"""

    path = tmp_path / "artifact.json"
    path.write_bytes(b'{"a":123}')
    monkeypatch.setattr(contract, "MAX_JSON_OBJECT_SIZE", 8)

    with pytest.raises(ValueError, match="上限"):
        contract.load_json_object_strict(path)


def test_bounded_descriptor_reads_at_most_limit_plus_one(tmp_path: Path) -> None:
    """読取上限を超える入力でもdescriptorからは上限+1 byteだけ取得する。"""

    path = tmp_path / "large.bin"
    path.write_bytes(b"A" * 64)
    descriptor = os.open(path, os.O_RDONLY | int(getattr(os, "O_BINARY", 0)))
    try:
        data = contract._read_bounded_descriptor(descriptor, max_bytes=8)
    finally:
        os.close(descriptor)

    assert data == b"A" * 9


def test_lstat_open_replacement_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """lstat後かつopen前の同サイズfile差替えをidentity差分で拒否する。"""

    path = tmp_path / "artifact.json"
    replacement = tmp_path / "replacement.json"
    path.write_bytes(b'{"v":1}')
    replacement.write_bytes(b'{"v":2}')
    original_open = contract.os.open
    swapped = False

    def replacing_open(candidate: object, flags: int, *args: object, **kwargs: object) -> int:
        nonlocal swapped
        if Path(candidate) == path and not swapped:
            swapped = True
            os.replace(replacement, path)
        return original_open(candidate, flags, *args, **kwargs)

    monkeypatch.setattr(contract.os, "open", replacing_open)
    with pytest.raises(ValueError, match="差し替え"):
        contract.load_json_object_strict(path)
    assert swapped is True


def test_hardlink_added_during_read_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """open後に追加されたhardlinkを読取後fstatのlink数で拒否する。"""

    path = tmp_path / "artifact.json"
    alias = tmp_path / "alias.json"
    path.write_bytes(b'{"v":1}')
    original_reader = contract._read_bounded_descriptor

    def add_hardlink_then_read(descriptor: int, *, max_bytes: int) -> bytes:
        try:
            os.link(path, alias)
        except OSError as exc:
            pytest.skip(f"hardlinkを作成できない環境です: {exc}")
        return original_reader(descriptor, max_bytes=max_bytes)

    monkeypatch.setattr(contract, "_read_bounded_descriptor", add_hardlink_then_read)
    with pytest.raises(ValueError, match="hardlink"):
        contract.load_json_object_strict(path)


def test_same_size_content_change_during_read_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """読取中の同サイズ上書きをmtime／ctime安定性検証で拒否する。"""

    path = tmp_path / "artifact.json"
    path.write_bytes(b'{"v":1}')
    before = path.stat()
    original_reader = contract._read_bounded_descriptor

    def mutate_then_return(descriptor: int, *, max_bytes: int) -> bytes:
        data = original_reader(descriptor, max_bytes=max_bytes)
        try:
            with path.open("r+b") as stream:
                stream.write(b'{"v":2}')
                stream.flush()
                os.fsync(stream.fileno())
            os.utime(
                path,
                ns=(before.st_atime_ns, before.st_mtime_ns + 1_000_000_000),
            )
        except OSError as exc:
            pytest.skip(f"open中fileを更新できない環境です: {exc}")
        return data

    monkeypatch.setattr(contract, "_read_bounded_descriptor", mutate_then_return)
    with pytest.raises(ValueError, match="変更"):
        contract.load_json_object_strict(path)


def test_directory_reparse_replacement_after_read_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """読取後に親directoryがreparse先へ差し替わった場合も拒否する。"""

    case_dir = tmp_path / "case"
    parent = case_dir / "nested"
    parent.mkdir(parents=True)
    path = parent / "artifact.json"
    path.write_bytes(b'{"v":1}')
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / path.name).write_bytes(b'{"v":2}')
    saved_parent = case_dir / "nested-original"
    original_check = contract.ensure_no_reparse_components
    target_checks = 0

    def replace_parent_on_final_check(candidate: Path) -> None:
        nonlocal target_checks
        if Path(candidate) == path:
            target_checks += 1
            if target_checks == 2:
                parent.rename(saved_parent)
                try:
                    parent.symlink_to(outside, target_is_directory=True)
                except OSError as exc:
                    if parent.is_symlink():
                        parent.unlink()
                    saved_parent.rename(parent)
                    pytest.skip(f"directory symlinkを作成できない環境です: {exc}")
        original_check(candidate)

    monkeypatch.setattr(
        contract,
        "ensure_no_reparse_components",
        replace_parent_on_final_check,
    )
    with pytest.raises(ValueError, match="reparse point"):
        contract.load_json_object_strict(path)
    assert target_checks == 2


def test_artifact_hash_verification_rejects_existing_hardlink(tmp_path: Path) -> None:
    """hashが一致しても複数linkのcase成果物は検証済みにしない。"""

    case_dir = tmp_path / "case"
    case_dir.mkdir()
    path = case_dir / "artifact.bin"
    alias = tmp_path / "artifact-alias.bin"
    payload = b"bounded artifact"
    path.write_bytes(payload)
    try:
        os.link(path, alias)
    except OSError as exc:
        pytest.skip(f"hardlinkを作成できない環境です: {exc}")

    digest = hashlib.sha256(payload).hexdigest()
    assert contract.verify_artifact_hashes(
        case_dir,
        {"artifact.bin": digest},
    ) == ["artifact_hardlink_forbidden:artifact.bin"]
    with pytest.raises(ValueError, match="hardlink"):
        contract.artifact_hashes(case_dir, ["artifact.bin"])


def test_captured_semantic_bytes_are_the_verified_hash_snapshot(tmp_path: Path) -> None:
    """意味検証用bytesがSHA-256を計算した同一snapshotであることを確認する。"""

    case_dir = tmp_path / "case"
    case_dir.mkdir()
    path = case_dir / "classification.json"
    payload = b'{"selected_families":["fixture"]}'
    path.write_bytes(payload)
    digest = hashlib.sha256(payload).hexdigest()

    errors, snapshots = contract._verify_artifact_hashes_with_snapshots(
        case_dir,
        {"classification.json": digest},
        capture_paths=frozenset({"classification.json"}),
    )
    assert errors == []
    assert hashlib.sha256(snapshots["classification.json"]).hexdigest() == digest
    path.write_bytes(b'{"selected_families":[]}')
    assert contract._decode_json_object_strict(
        snapshots["classification.json"],
        path=path,
    ) == {"selected_families": ["fixture"]}
