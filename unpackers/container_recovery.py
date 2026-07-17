"""Bounded recovery helpers for XZ, Mach-O FAT, and inflated PE files."""

from __future__ import annotations

import hashlib
import lzma
import struct

import pefile

MAX_ARTIFACT = 256 * 1024 * 1024
MAX_SECURITY_GAP = 64 * 1024 * 1024
MAX_XZ_METADATA = 1024 * 1024
MACHO_FAT_MAGICS = {b"\xca\xfe\xba\xbe": ">", b"\xbe\xba\xfe\xca": "<"}


def _allowed_xz_trailer(data: bytes) -> bool:
    """Return true for bounded XML property-list metadata after XZ streams."""
    probe = data.lstrip()
    return (
        0 < len(data) <= MAX_XZ_METADATA
        and probe.startswith(b"<?xml")
        and b"<plist" in probe[:4096]
        and b"</plist>" in probe
    )


def recover_xz(data: bytes) -> tuple[dict, bytes | None]:
    """Decompress concatenated XZ streams with absolute output and memory bounds."""
    remaining = data
    output = bytearray()
    stream_count = 0
    trailing_metadata: bytes | None = None
    try:
        while remaining:
            decompressor = lzma.LZMADecompressor(
                format=lzma.FORMAT_XZ, memlimit=512 * 1024 * 1024
            )
            before = len(output)
            limit = MAX_ARTIFACT - len(output) + 1
            if limit <= 0:
                return {
                    "status": "output_limit_blocked",
                    "size_at_limit": len(output),
                }, None
            output.extend(decompressor.decompress(remaining, max_length=limit))
            while (
                not decompressor.eof
                and not decompressor.needs_input
                and len(output) <= MAX_ARTIFACT
            ):
                limit = MAX_ARTIFACT - len(output) + 1
                output.extend(decompressor.decompress(b"", max_length=limit))
            if len(output) > MAX_ARTIFACT:
                return {
                    "status": "output_limit_blocked",
                    "size_at_limit": len(output),
                }, None
            if not decompressor.eof:
                return {
                    "status": "invalid_xz",
                    "error": "incomplete_stream",
                    "recovered_size": len(output),
                }, None
            stream_count += 1
            remaining = decompressor.unused_data
            if not remaining:
                break
            if remaining.startswith(b"\xfd7zXZ\x00"):
                continue
            if _allowed_xz_trailer(remaining):
                trailing_metadata = remaining
                break
            return {
                "status": "trailing_data_blocked",
                "streams": stream_count,
                "trailing_size": len(remaining),
            }, None
    except lzma.LZMAError as exc:
        return {"status": "invalid_xz", "error": type(exc).__name__}, None
    recovered = bytes(output)
    if not recovered:
        return {"status": "empty_output"}, None
    report = {
        "status": (
            "recovered_with_trailing_metadata"
            if trailing_metadata is not None
            else "recovered"
        ),
        "streams": stream_count,
        "size": len(recovered),
        "sha256": hashlib.sha256(recovered).hexdigest(),
    }
    if trailing_metadata is not None:
        report["trailing_metadata_size"] = len(trailing_metadata)
        report["trailing_metadata_sha256"] = hashlib.sha256(
            trailing_metadata
        ).hexdigest()
        report["trailing_metadata_format"] = "xml-plist"
    return report, recovered


def recover_macho_slices(data: bytes) -> tuple[dict, list[tuple[str, bytes]]]:
    """Recover bounded thin Mach-O slices from a universal Mach-O binary."""
    endian = MACHO_FAT_MAGICS.get(data[:4])
    if not endian or len(data) < 8:
        return {"status": "not_universal", "architectures": []}, []
    count = struct.unpack_from(endian + "I", data, 4)[0]
    if not 1 <= count <= 32 or 8 + count * 20 > len(data):
        return {"status": "invalid_architecture_table", "count": count}, []
    inventory: list[dict] = []
    artifacts: list[tuple[str, bytes]] = []
    for index in range(count):
        cpu, subtype, offset, size, alignment = struct.unpack_from(
            endian + "IIIII", data, 8 + index * 20
        )
        item = {
            "index": index,
            "cpu_type": hex(cpu),
            "cpu_subtype": hex(subtype),
            "offset": offset,
            "size": size,
            "alignment": alignment,
        }
        if not 0 < size <= MAX_ARTIFACT or offset + size > len(data):
            item["status"] = "bounds_blocked"
        else:
            blob = data[offset : offset + size]
            item.update(
                status="recovered", sha256=hashlib.sha256(blob).hexdigest()
            )
            artifacts.append((f"macho-slice-{index}", blob))
        inventory.append(item)
    return {
        "status": "recovered" if artifacts else "no_slice_recovered",
        "architectures": inventory,
    }, artifacts


def recover_inflated_pe(data: bytes) -> tuple[dict, bytes | None]:
    """Remove an oversized security-directory gap while preserving PE sections.

    Recovery is attempted only when the certificate table begins more than
    64 MiB after the final section. The security directory is cleared in the
    derived artifact; the original certificate hash remains in the report.
    """
    try:
        image = pefile.PE(data=data, fast_load=True)
        section_end = max(
            int(section.PointerToRawData + section.SizeOfRawData)
            for section in image.sections
        )
        security = image.OPTIONAL_HEADER.DATA_DIRECTORY[4]
        security_offset, security_size = int(security.VirtualAddress), int(security.Size)
    except (ValueError, AttributeError, IndexError, pefile.PEFormatError):
        return {"status": "parse_failed"}, None
    gap = security_offset - section_end
    if (
        security_offset <= 0
        or security_size <= 0
        or gap <= MAX_SECURITY_GAP
        or security_offset + security_size > len(data)
    ):
        return {
            "status": "not_inflated",
            "section_end": section_end,
            "security_offset": security_offset,
            "security_size": security_size,
            "gap_size": max(gap, 0),
        }, None
    compact = bytearray(data[:section_end])
    directory_offset = int(security.get_file_offset())
    if directory_offset + 8 > len(compact):
        return {"status": "directory_outside_compact_image"}, None
    compact[directory_offset : directory_offset + 8] = b"\0" * 8
    recovered = bytes(compact)
    try:
        pefile.PE(data=recovered, fast_load=True)
    except pefile.PEFormatError:
        return {"status": "recovered_image_invalid"}, None
    certificate = data[security_offset : security_offset + security_size]
    return {
        "status": "recovered",
        "original_size": len(data),
        "recovered_size": len(recovered),
        "removed_gap_size": gap,
        "security_size": security_size,
        "security_sha256": hashlib.sha256(certificate).hexdigest(),
        "sha256": hashlib.sha256(recovered).hexdigest(),
    }, recovered
