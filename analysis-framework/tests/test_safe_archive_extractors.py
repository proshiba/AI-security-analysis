"""安全なZIP展開CLIと内包ZIPラッパーの統合動作を検証する。"""

from __future__ import annotations

import io
from pathlib import Path
import sys
import zipfile

import pytest


COMMON = Path(__file__).parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import analyze_submission  # noqa: E402
import extract_packages  # noqa: E402
from malware_io import ArchiveValidationError  # noqa: E402
import safe_extract_zip  # noqa: E402


def _zip_bytes(members: list[tuple[str, bytes]]) -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in members:
            archive.writestr(name, data)
    return stream.getvalue()


def test_safe_extract_zip_cli_extracts_nested_members(short_tmp: Path) -> None:
    archive = short_tmp / "input.zip"
    output = short_tmp / "output"
    archive.write_bytes(_zip_bytes([("folder/a.bin", b"A"), ("b.bin", b"B")]))
    assert safe_extract_zip.main(["--archive", str(archive), "--output", str(output)]) == 0
    assert (output / "folder" / "a.bin").read_bytes() == b"A"
    assert (output / "b.bin").read_bytes() == b"B"


@pytest.mark.parametrize(
    "members",
    [
        [("../outside.bin", b"A"), ("safe.bin", b"B")],
        [("A.bin", b"A"), ("a.BIN", b"B")],
        [("payload", b"A"), ("payload/a.bin", b"B")],
    ],
)
def test_safe_extract_zip_validates_every_member_before_writing(
    short_tmp: Path,
    members: list[tuple[str, bytes]],
) -> None:
    archive = short_tmp / "invalid.zip"
    output = short_tmp / "output"
    archive.write_bytes(_zip_bytes(members))
    with pytest.raises(ArchiveValidationError):
        safe_extract_zip.main(["--archive", str(archive), "--output", str(output)])
    assert not output.exists()


def test_safe_extract_zip_cli_enforces_compression_ratio(short_tmp: Path) -> None:
    archive = short_tmp / "dense.zip"
    output = short_tmp / "output"
    archive.write_bytes(_zip_bytes([("dense.bin", b"A" * 4096)]))
    with pytest.raises(ArchiveValidationError, match="compression ratio"):
        safe_extract_zip.main(
            [
                "--archive",
                str(archive),
                "--output",
                str(output),
                "--max-compression-ratio",
                "2",
            ]
        )
    assert not output.exists()


def test_extract_packages_uses_same_no_overwrite_contract(short_tmp: Path) -> None:
    output = short_tmp / "output"
    data = _zip_bytes([("folder/a.bin", b"A")])
    assert extract_packages.extract_zip_bytes(data, output) == 1
    with pytest.raises(ArchiveValidationError, match="overwrite"):
        extract_packages.extract_zip_bytes(data, output)
    assert (output / "folder" / "a.bin").read_bytes() == b"A"


def test_recursive_submission_zip_uses_shared_validation() -> None:
    """再帰解析でもパストラバーサルを解析開始前に拒否する。"""
    with pytest.raises(ArchiveValidationError, match="unsafe archive member path"):
        analyze_submission.analyze_zip(
            _zip_bytes([("safe.bin", b"A"), ("../outside.bin", b"B")]),
            1,
        )


def test_recursive_submission_zip_enforces_compression_ratio(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """再帰解析でも高圧縮メンバーを展開しない。"""
    monkeypatch.setattr(analyze_submission, "MAX_NESTED_COMPRESSION_RATIO", 2.0)
    with pytest.raises(ArchiveValidationError, match="compression ratio"):
        analyze_submission.analyze_zip(
            _zip_bytes([("dense.bin", b"A" * 4096)]),
            1,
        )
