"""解析入力snapshot共通境界の検証。"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

import immutable_snapshot as snapshot_io
import pytest
from immutable_snapshot import (
    copy_bounded_snapshot,
    decode_strict_json,
    ensure_new_output,
    read_bounded_snapshot,
    write_new_json,
)


def test_reads_maximum_bytes_and_rejects_maximum_plus_one(tmp_path: Path) -> None:
    exact = tmp_path / "exact.bin"
    exact.write_bytes(b"abcd")
    assert read_bounded_snapshot(exact, 4).data == b"abcd"
    oversized = tmp_path / "oversized.bin"
    oversized.write_bytes(b"abcde")
    with pytest.raises(ValueError, match="上限"):
        read_bounded_snapshot(oversized, 4)


def test_copy_snapshot_hash_binds_and_cleans_mismatch(tmp_path: Path) -> None:
    source = tmp_path / "source.pcapng"
    source.write_bytes(b"pcap")
    destination = tmp_path / "snapshot.pcapng"
    result = copy_bounded_snapshot(
        source,
        destination,
        16,
        expected_sha256=hashlib.sha256(b"pcap").hexdigest(),
    )
    assert result.path.read_bytes() == b"pcap"
    bad_destination = tmp_path / "bad.pcapng"
    with pytest.raises(ValueError, match="期待値"):
        copy_bounded_snapshot(
            source,
            bad_destination,
            16,
            expected_sha256="0" * 64,
        )
    assert not bad_destination.exists()


def test_rejects_hardlink_and_symlink_inputs(tmp_path: Path) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"data")
    hardlink = tmp_path / "hardlink.bin"
    os.link(source, hardlink)
    with pytest.raises(ValueError, match="hardlink"):
        read_bounded_snapshot(source, 16)
    hardlink.unlink()
    symlink = tmp_path / "symlink.bin"
    try:
        symlink.symlink_to(source)
    except OSError:
        pytest.skip("この環境ではsymlinkを作成できません")
    with pytest.raises(ValueError, match="reparse point|symlink"):
        read_bounded_snapshot(symlink, 16)


def test_rejects_symlink_ancestor_for_input_and_output(tmp_path: Path) -> None:
    real_directory = tmp_path / "real"
    real_directory.mkdir()
    source = real_directory / "source.bin"
    source.write_bytes(b"data")
    alias = tmp_path / "alias"
    try:
        alias.symlink_to(real_directory, target_is_directory=True)
    except OSError:
        pytest.skip("この環境ではsymbolic linkを作成できません")

    with pytest.raises(ValueError, match="reparse point"):
        read_bounded_snapshot(alias / "source.bin", 16)
    with pytest.raises(ValueError, match="reparse point"):
        ensure_new_output(alias / "output.json", ())


def test_output_must_be_new_and_distinct_from_inputs(tmp_path: Path) -> None:
    source = tmp_path / "input.json"
    source.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="同じpath"):
        ensure_new_output(source, (source,))
    existing = tmp_path / "existing.json"
    existing.write_text("old", encoding="utf-8")
    with pytest.raises(FileExistsError, match="上書き"):
        ensure_new_output(existing, (source,))
    output = ensure_new_output(tmp_path / "new.json", (source,))
    write_new_json(output, {"ok": True})
    with pytest.raises(FileExistsError, match="上書き"):
        ensure_new_output(output, (source,))


def test_strict_json_rejects_duplicate_keys_and_nonfinite_numbers() -> None:
    for payload in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}'):
        with pytest.raises(ValueError):
            decode_strict_json(payload)


def test_created_output_path_must_still_reference_open_handle(tmp_path: Path) -> None:
    output = tmp_path / "output.json"
    replacement = tmp_path / "replacement.json"
    replacement.write_text("replacement", encoding="utf-8")
    parent = output.parent.lstat()
    with output.open("xb", buffering=0) as handle:
        created = os.fstat(handle.fileno())
        with pytest.raises(ValueError, match="identity"):
            snapshot_io._verify_created_output(replacement, parent, handle, created)


def test_write_failure_never_raw_unlinks_unverified_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    output = tmp_path / "output.json"
    cleanup_calls: list[tuple[Path, os.stat_result]] = []

    def refuse_cleanup(path: Path, metadata: os.stat_result) -> bool:
        cleanup_calls.append((path, metadata))
        return False

    def fail_fsync(_descriptor: int) -> None:
        raise OSError("fixture fsync failure")

    monkeypatch.setattr(snapshot_io, "unlink_created_file_if_unchanged", refuse_cleanup)
    monkeypatch.setattr(snapshot_io.os, "fsync", fail_fsync)
    with pytest.raises(OSError, match="fixture"):
        write_new_json(output, {"ok": True})
    assert output.exists()
    assert cleanup_calls and cleanup_calls[0][0] == output


def test_public_snapshot_identity_omits_host_internal_metadata(tmp_path: Path) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"data")
    identity = read_bounded_snapshot(source, 16).identity.public_dict()
    assert identity == {
        "size": 4,
        "sha256": hashlib.sha256(b"data").hexdigest(),
        "link_count": 1,
    }
    assert not {"device", "inode", "modified_ns"} & identity.keys()
