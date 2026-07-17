"""Recover a validated 32-byte-XOR wrapper around Donut shellcode."""

from __future__ import annotations

import hashlib

import pefile

from unpackers.donut_unpacker import is_donut_shellcode

KEY_SIZE = 32
BLOB_OFFSET = 0x51
EXPECTED_STRINGS = {
    0x21: b"%s\\%s",
    0x27: b"SystemRoot",
    0x32: b"System32\\conhost.exe",
    0x47: b'"%s" "%s"',
}


def sha256_bytes(data: bytes) -> str:
    """Return a lowercase SHA-256 digest."""
    return hashlib.sha256(data).hexdigest()


def repeated_xor(data: bytes, key: bytes, stream_offset: int = 0) -> bytes:
    """Apply a repeated XOR key starting at an explicit stream offset."""
    if not key:
        raise ValueError("key must not be empty")
    return bytes(
        value ^ key[(stream_offset + index) % len(key)]
        for index, value in enumerate(data)
    )


def recover_xor32_donut_wrapper(
    data: bytes,
) -> tuple[dict, list[tuple[str, bytes]]]:
    """Recover Donut bytes only from the tightly validated observed PE wrapper.

    The wrapper is accepted only when a PE has a sufficiently large ``.rdata``
    section, the first 32 bytes decode four exact process-launch strings at
    fixed offsets, and the decoded payload has a valid Donut call-over-instance
    structure. These checks prevent a generic XOR brute-force path.
    """
    if not data.startswith(b"MZ"):
        return {"status": "not_pe"}, []
    try:
        image = pefile.PE(data=data, fast_load=True)
        section = next(
            item for item in image.sections if item.Name.rstrip(b"\0") == b".rdata"
        )
    except (StopIteration, AttributeError, ValueError, pefile.PEFormatError):
        return {"status": "wrapper_not_detected"}, []
    start = int(section.PointerToRawData)
    size = int(section.SizeOfRawData)
    if size <= BLOB_OFFSET + 10 or start < 0 or start + size > len(data):
        return {"status": "wrapper_not_detected"}, []
    rdata = data[start : start + size]
    key = rdata[:KEY_SIZE]
    if len(key) != KEY_SIZE:
        return {"status": "wrapper_not_detected"}, []
    decoded_strings = {}
    for offset, expected in EXPECTED_STRINGS.items():
        end = offset + len(expected)
        if end > len(rdata):
            return {"status": "wrapper_not_detected"}, []
        decoded = repeated_xor(rdata[offset:end], key)
        if decoded != expected:
            return {"status": "wrapper_not_detected"}, []
        decoded_strings[hex(offset)] = decoded.decode("ascii")
    recovered = repeated_xor(rdata[BLOB_OFFSET:], key)
    if not is_donut_shellcode(recovered):
        return {
            "status": "decoded_payload_failed_donut_validation",
            "key_sha256": sha256_bytes(key),
            "decoded_strings": decoded_strings,
        }, []
    return {
        "status": "donut_shellcode_recovered",
        "profile": "xor32_rdata_conhost_wrapper",
        "key_size": len(key),
        "key_sha256": sha256_bytes(key),
        "decoded_strings": decoded_strings,
        "encrypted_offset": start + BLOB_OFFSET,
        "encrypted_size": len(rdata) - BLOB_OFFSET,
        "encrypted_sha256": sha256_bytes(rdata[BLOB_OFFSET:]),
        "recovered_size": len(recovered),
        "recovered_sha256": sha256_bytes(recovered),
    }, [("xor32-donut-shellcode", recovered)]
