"""リポジトリ外解析データの暗号化保管処理を検証する。"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys

import pyzipper
import pytest


COMMON = Path(__file__).parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import archive_analysis_datastore as datastore  # noqa: E402


def test_aes256_archive_round_trip_has_no_absolute_paths(short_tmp: Path) -> None:
    source = short_tmp / "sample-target"
    source.mkdir()
    (source / "payload.bin").write_bytes(b"MZ\x00test")
    (source / "notes.json").write_text('{"kind":"memory"}\n', encoding="utf-8")
    files = datastore.collect_source_files([source])
    created_at = datetime(2026, 8, 8, 0, 0, tzinfo=timezone.utc)
    manifest = datastore.build_manifest(target="sample-0123", created_at=created_at, files=files)
    archive = short_tmp / "sample.zip"

    datastore.create_encrypted_archive(archive, files, manifest)
    datastore.verify_encrypted_archive(archive, files, manifest)

    with pyzipper.AESZipFile(archive) as handle:
        handle.setpassword(b"infected")
        names = handle.namelist()
        stored_manifest = json.loads(handle.read(datastore.MANIFEST_NAME))
    assert names == [
        datastore.MANIFEST_NAME,
        "data/sample-target/notes.json",
        "data/sample-target/payload.bin",
    ]
    assert all(":" not in item and not item.startswith("/") for item in names)
    assert all("source" not in item for item in stored_manifest["files"])
    assert stored_manifest["files"][1]["sha256"] == hashlib.sha256(b"MZ\x00test").hexdigest()


def test_archive_requires_correct_password(short_tmp: Path) -> None:
    source = short_tmp / "payload.bin"
    source.write_bytes(b"secret")
    files = datastore.collect_source_files([source])
    manifest = datastore.build_manifest(
        target="sample",
        created_at=datetime(2026, 8, 8, tzinfo=timezone.utc),
        files=files,
    )
    archive = short_tmp / "sample.zip"
    datastore.create_encrypted_archive(archive, files, manifest)
    with pyzipper.AESZipFile(archive) as handle:
        handle.setpassword(b"wrong")
        with pytest.raises(RuntimeError):
            handle.read(datastore.MANIFEST_NAME)


@pytest.mark.parametrize("target", ["../escape", "UPPER", "with/slash", "", "-leading"])
def test_target_rejects_unsafe_values(target: str) -> None:
    with pytest.raises(datastore.DatastoreError):
        datastore.validate_target(target)


@pytest.mark.parametrize("prefix", ["../escape", "safe/../escape", "/", "safe//nested", "safe/white space"])
def test_prefix_rejects_unsafe_values(prefix: str) -> None:
    with pytest.raises(datastore.DatastoreError):
        datastore.validate_prefix(prefix)


def test_duplicate_top_level_source_names_are_rejected(short_tmp: Path) -> None:
    left = short_tmp / "left" / "same.bin"
    right = short_tmp / "right" / "same.bin"
    left.parent.mkdir()
    right.parent.mkdir()
    left.write_bytes(b"left")
    right.write_bytes(b"right")
    with pytest.raises(datastore.DatastoreError, match="重複"):
        datastore.collect_source_files([left, right])


def test_host_credential_names_are_rejected(short_tmp: Path) -> None:
    source = short_tmp / "target"
    source.mkdir()
    (source / "creds.txt").write_text("do-not-store", encoding="utf-8")
    with pytest.raises(datastore.DatastoreError, match="資格情報"):
        datastore.collect_source_files([source])


def test_s3_key_is_target_and_month_scoped() -> None:
    key = datastore.build_s3_key(
        "analysis-targets",
        "guloader-0123",
        datetime(2026, 8, 8, tzinfo=timezone.utc),
        "archive.zip",
    )
    assert key == "analysis-targets/guloader-0123/2026/08/archive.zip"


def test_upload_command_requires_sse_checksum_and_metadata(short_tmp: Path) -> None:
    command = datastore.build_upload_command(
        aws_cli=Path("aws.exe"),
        archive_path=short_tmp / "archive.zip",
        bucket="bucket",
        key="analysis-targets/sample/2026/08/archive.zip",
        region="us-east-1",
        archive_sha256="a" * 64,
        manifest_sha256="b" * 64,
        target="sample",
    )
    assert command[1:3] == ["s3", "cp"]
    assert command[command.index("--sse") + 1] == "AES256"
    assert command[command.index("--checksum-algorithm") + 1] == "SHA256"
    metadata = command[command.index("--metadata") + 1]
    assert "archive-sha256=" + "a" * 64 in metadata
    assert "manifest-sha256=" + "b" * 64 in metadata


def test_head_object_verification_is_fail_closed() -> None:
    valid = {
        "ContentLength": 123,
        "ServerSideEncryption": "AES256",
        "Metadata": {
            "archive-sha256": "a" * 64,
            "manifest-sha256": "b" * 64,
            "analysis-target": "sample",
        },
    }
    datastore.verify_head_object(
        valid,
        expected_size=123,
        archive_sha256="a" * 64,
        manifest_sha256="b" * 64,
        target="sample",
    )
    invalid = dict(valid, ServerSideEncryption=None)
    with pytest.raises(datastore.DatastoreError, match="ServerSideEncryption"):
        datastore.verify_head_object(
            invalid,
            expected_size=123,
            archive_sha256="a" * 64,
            manifest_sha256="b" * 64,
            target="sample",
        )
