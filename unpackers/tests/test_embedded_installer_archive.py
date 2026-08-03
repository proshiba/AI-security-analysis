from __future__ import annotations

import hashlib
import io
import struct
import zipfile

from unpackers import embedded_installer_archive as target


def _plain_archive(members: list[tuple[str, bytes]]) -> bytes:
    header = bytearray(struct.pack("<I", len(members)))
    record_positions: list[int] = []
    for name, blob in members:
        header.extend(name.encode("utf-8") + b"\0")
        while len(header) % 4:
            header.append(0)
        record_positions.append(len(header))
        header.extend(struct.pack("<II", 0, len(blob)))
    output = bytearray(header)
    for record_position, (_name, blob) in zip(record_positions, members):
        struct.pack_into("<I", output, record_position, len(output))
        output.extend(blob)
    return bytes(output)


def _candidate_zip(payload: bytes) -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("package.dat", payload)
    return stream.getvalue()


def test_recover_embedded_installer_archive() -> None:
    """親PEの直前seed materialと暗号化resourceを相関して2後段を復元する。"""

    seed_mask = bytes(range(16))
    parent = b"MZ" + b"A" * 64 + seed_mask + target.MASK_ANCHOR
    members = [
        ("sample.exe", b"MZ" + b"P" * 126),
        ("priority.bin", b"configuration"),
    ]
    plain = _plain_archive(members)
    key = 0x1122334455667788
    encrypted = target._stream_xor(plain, key, seed_mask)
    package = (
        target.ARCHIVE_MARKER
        + struct.pack("<I", len(encrypted))
        + struct.pack("<Q", key)
        + encrypted
    )
    candidate = _candidate_zip(package)

    report, artifacts, consumed = target.recover_embedded_installer_archive(
        parent,
        [("pe-resource-zip", candidate)],
        max_member_size=1024 * 1024,
        max_total_size=2 * 1024 * 1024,
    )

    assert report["status"] == "artifacts_recovered"
    assert report["record_count"] == 2
    assert report["seed_value_published"] is False
    assert report["key_value_published"] is False
    assert [kind for kind, _blob in artifacts] == [
        "embedded-installer-pe",
        "embedded-installer-autoit-a3x",
    ]
    assert [blob for _kind, blob in artifacts] == [blob for _name, blob in members]
    assert consumed == {hashlib.sha256(candidate).hexdigest()}


def test_recovery_fails_closed_without_parent_anchor() -> None:
    """親側のreview済みanchorがなければ暗号化memberへ推測復号を行わない。"""

    report, artifacts, consumed = target.recover_embedded_installer_archive(
        b"MZ-no-anchor",
        [("pe-resource-zip", _candidate_zip(b"opaque"))],
        max_member_size=1024,
        max_total_size=4096,
    )
    assert report == {"status": "no_reviewed_anchor"}
    assert artifacts == []
    assert consumed == set()
