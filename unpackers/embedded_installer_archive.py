"""埋め込み暗号化installer archiveを実行せず境界付きで復元する。"""

from __future__ import annotations

import hashlib
import io
import struct
import zipfile

from unpackers.path_safety import safe_member_name

ARCHIVE_MARKER = b"\x1a\xc8\x47\x13"
MASK_ANCHOR = '"autoit3'.encode("utf-16le")
MAX_RECORDS = 32
MAX_NAME_BYTES = 260
MASK64 = (1 << 64) - 1


def _add64(*values: int) -> int:
    return sum(values) & MASK64


def _stream_block(counter: int, state1: int, state2: int, state3: int) -> bytes:
    """Ghidraで確認した4x64-bit stateの32-byte keystream blockを返す。"""

    value6 = (_add64(state1, counter) >> 21) ^ _add64(state1, counter)
    value10 = _add64(state3, state2)
    value10 = ((value10 << 5) & MASK64) ^ value10
    value5 = _add64((value10 >> 29) ^ state1, value6)
    value7 = _add64((value6 >> 11) ^ state3, value10)
    value9 = _add64(((value7 << 25) & MASK64) ^ value10, value7)
    value9 = ((value9 << 5) & MASK64) ^ value9
    value10 = _add64(value5 >> 27, value5, value6)
    value10 = (value10 >> 21) ^ value10
    value11 = _add64((value9 >> 29) ^ value5, value10)
    value5 = _add64((value10 >> 11) ^ value7, value9)
    value6 = _add64(((value5 << 25) & MASK64) ^ value9, value5)
    value6 = ((value6 << 5) & MASK64) ^ value6
    value7 = _add64(value11 >> 27, value11, value10)
    value7 = (value7 >> 21) ^ value7
    value11 = _add64((value6 >> 29) ^ value11, value7)
    value9 = _add64((value7 >> 11) ^ value5, value6)
    value10 = _add64(((value9 << 25) & MASK64) ^ value6, value9)
    value10 = ((value10 << 5) & MASK64) ^ value10
    value6 = _add64(value11 >> 27, value11, value7)
    value6 = (value6 >> 21) ^ value6
    value5 = _add64((value10 >> 29) ^ value11, value6)
    value12 = _add64((value6 >> 11) ^ value9, value10)
    return struct.pack(
        "<QQQQ",
        _add64(value6, counter, value5 >> 27),
        _add64(value5, state1),
        _add64(((value12 << 25) & MASK64) ^ value10, state2),
        _add64(value12, state3),
    )


def _stream_xor(data: bytes, key: int, seed_mask: bytes) -> bytes:
    if len(seed_mask) != 16:
        raise ValueError("seed mask must be 16 bytes")
    repeated_key = struct.pack("<Q", key) * 2
    state_material = bytes(a ^ b for a, b in zip(repeated_key, seed_mask))
    state1, state2 = struct.unpack("<QQ", state_material)
    output = bytearray(len(data))
    for block_offset in range(0, len(data), 32):
        keystream = _stream_block(block_offset // 32, state1, state2, key)
        chunk = data[block_offset : block_offset + 32]
        for index, value in enumerate(chunk):
            output[block_offset + index] = value ^ keystream[index]
    return bytes(output)


def _stored_member_data(archive_data: bytes) -> tuple[dict[str, object], bytes] | None:
    try:
        with zipfile.ZipFile(io.BytesIO(archive_data)) as archive:
            infos = archive.infolist()
    except (OSError, ValueError, zipfile.BadZipFile):
        return None
    if len(infos) != 1:
        return None
    info = infos[0]
    if info.compress_type != zipfile.ZIP_STORED:
        return None
    offset = int(info.header_offset)
    if offset < 0 or offset + 30 > len(archive_data):
        return None
    if archive_data[offset : offset + 4] != b"PK\x03\x04":
        return None
    name_size, extra_size = struct.unpack_from("<HH", archive_data, offset + 26)
    data_offset = offset + 30 + name_size + extra_size
    data_end = data_offset + int(info.compress_size)
    if data_offset < 30 or data_end > len(archive_data):
        return None
    return (
        {
            "name": info.filename,
            "encrypted_flag": bool(info.flag_bits & 1),
            "compressed_size": int(info.compress_size),
            "uncompressed_size": int(info.file_size),
        },
        archive_data[data_offset:data_end],
    )


def _align4(value: int) -> int:
    return (value + 3) & ~3


def _classify(blob: bytes, name: str) -> str:
    lowered = name.casefold()
    if blob.startswith(b"MZ"):
        return "pe"
    if blob.startswith(b"PK\x03\x04"):
        return "zip"
    if lowered.endswith((".ps1", ".js", ".jse", ".vbs", ".vbe", ".bat", ".cmd")):
        return "script"
    return "data"


def _parse_plain_archive(
    plain: bytes,
    *,
    max_member_size: int,
    max_total_size: int,
) -> tuple[list[dict[str, object]], list[tuple[str, bytes]]] | None:
    if len(plain) < 4:
        return None
    record_count = struct.unpack_from("<I", plain, 0)[0]
    if not 1 <= record_count <= MAX_RECORDS:
        return None
    cursor = 4
    records: list[dict[str, object]] = []
    for _ in range(record_count):
        name_end = plain.find(b"\0", cursor, min(len(plain), cursor + MAX_NAME_BYTES))
        if name_end < 0:
            return None
        try:
            name = safe_member_name(plain[cursor:name_end].decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return None
        cursor = _align4(name_end + 1)
        if cursor + 8 > len(plain):
            return None
        member_offset, member_size = struct.unpack_from("<II", plain, cursor)
        cursor += 8
        records.append({"name": name, "offset": member_offset, "size": member_size})
    header_end = cursor
    total = 0
    recovered_members: list[tuple[str, bytes]] = []
    prior_end = header_end
    for record in records:
        offset = int(record["offset"])
        size = int(record["size"])
        if size <= 0 or size > max_member_size:
            return None
        if offset < header_end or offset < prior_end or offset + size > len(plain):
            return None
        total += size
        if total > max_total_size:
            return None
        blob = plain[offset : offset + size]
        recovered_members.append((str(record["name"]), blob))
        prior_end = offset + size

    autoit_host_present = any(
        blob.startswith(b"MZ") for _name, blob in recovered_members
    )
    artifacts: list[tuple[str, bytes]] = []
    inventory: list[dict[str, object]] = []
    for name, blob in recovered_members:
        kind = _classify(blob, name)
        if autoit_host_present and kind == "data" and name.casefold().endswith(".bin"):
            kind = "autoit-a3x"
        digest = hashlib.sha256(blob).hexdigest()
        inventory.append(
            {
                "name": name,
                "size": len(blob),
                "sha256": digest,
                "format": kind,
                "status": "recovered",
            }
        )
        artifacts.append((f"embedded-installer-{kind}", blob))
    return inventory, artifacts


def recover_embedded_installer_archive(
    parent_data: bytes,
    candidate_archives: list[tuple[str, bytes]],
    *,
    max_member_size: int,
    max_total_size: int,
) -> tuple[dict[str, object], list[tuple[str, bytes]], set[str]]:
    """親PEのseed materialと暗号化ZIP resourceを相関して後段を復元する。"""

    anchor_offset = parent_data.find(MASK_ANCHOR)
    if anchor_offset < 16:
        return {"status": "no_reviewed_anchor"}, [], set()
    seed_mask = parent_data[anchor_offset - 16 : anchor_offset]
    for candidate_kind, archive_data in candidate_archives:
        stored = _stored_member_data(archive_data)
        if stored is None:
            continue
        member, encrypted = stored
        marker_offset = encrypted.find(ARCHIVE_MARKER)
        if marker_offset < 0 or marker_offset + 16 > len(encrypted):
            continue
        encrypted_size = struct.unpack_from("<I", encrypted, marker_offset + 4)[0]
        key = struct.unpack_from("<Q", encrypted, marker_offset + 8)[0]
        encrypted_start = marker_offset + 16
        encrypted_end = encrypted_start + encrypted_size
        if encrypted_size <= 0 or encrypted_size > max_total_size:
            continue
        if encrypted_end > len(encrypted):
            continue
        plain = _stream_xor(encrypted[encrypted_start:encrypted_end], key, seed_mask)
        parsed = _parse_plain_archive(
            plain,
            max_member_size=max_member_size,
            max_total_size=max_total_size,
        )
        if parsed is None:
            continue
        inventory, artifacts = parsed
        archive_sha256 = hashlib.sha256(archive_data).hexdigest()
        return (
            {
                "status": "artifacts_recovered",
                "algorithm": "reviewed_4x64_stream_cipher",
                "source_kind": candidate_kind,
                "source_archive_sha256": archive_sha256,
                "source_member": member,
                "marker_offset": marker_offset,
                "encrypted_size": encrypted_size,
                "record_count": len(inventory),
                "inventory": inventory,
                "seed_value_published": False,
                "key_value_published": False,
                "executed": False,
                "network_contacted": False,
            },
            artifacts,
            {archive_sha256},
        )
    return {"status": "no_valid_encrypted_archive"}, [], set()
