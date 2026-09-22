"""逆順4 fragmentとaffine XORを使うPE wrapperからDonutを静的回収する。"""

from __future__ import annotations

from collections.abc import Iterator
import hashlib
import struct

import pefile

from unpackers.donut_unpacker import decrypt_instance, is_donut_shellcode

MAXIMUM_INPUT_BYTES = 32 * 1024 * 1024
MAXIMUM_SHELLCODE_BYTES = 16 * 1024 * 1024
DATA_PREFIX_SIZE = 0x20
CHUNK_COUNT = 4
SUPPORTED_CHUNK_COUNTS = (4, 8)
CHUNK_ALIGNMENT = 16
MAXIMUM_CANDIDATE_WORK_BYTES = 64 * 1024 * 1024
KEY_DELTA = -99


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _align(value: int) -> int:
    return (value + CHUNK_ALIGNMENT - 1) & ~(CHUNK_ALIGNMENT - 1)


def affine_xor(base_key: int, data: bytes) -> bytes:
    """base keyを各byteで99減算するreview済みXOR streamを適用する。"""

    if not 1 <= base_key <= 0xFF:
        raise ValueError("base key must be a non-zero byte")
    return bytes(
        value ^ ((base_key + KEY_DELTA * offset) & 0xFF)
        for offset, value in enumerate(data)
    )


def _section_bytes(data: bytes, section: object) -> bytes | None:
    try:
        start = int(section.PointerToRawData)
        size = int(section.SizeOfRawData)
    except (AttributeError, TypeError, ValueError):
        return None
    if start < 0 or size < 0 or start + size > len(data):
        return None
    return data[start : start + size]


def _metadata_candidates(
    data: bytes, sections: list[object]
) -> list[tuple[str, int, int]]:
    candidates = []
    for section in sections:
        name = section.Name.rstrip(b"\0")
        if name == b".data":
            continue
        blob = _section_bytes(data, section)
        if blob is None:
            continue
        for offset in range(0, len(blob) - 7, 4):
            if blob[offset] == 0 or blob[offset + 1 : offset + 4] != bytes(3):
                continue
            size = struct.unpack_from("<I", blob, offset + 4)[0]
            if 0x1000 <= size <= MAXIMUM_SHELLCODE_BYTES:
                candidates.append(
                    (name.decode("ascii", errors="replace"), blob[offset], size)
                )
    return candidates


def _metadata_from_data_tail(section_data: bytes) -> tuple[int, int] | None:
    """`.data`末尾の1-byte key・3-byte zero・sizeだけを受理する。"""

    if len(section_data) < 8:
        return None
    metadata = section_data[-8:]
    if metadata[0] == 0 or metadata[1:4] != bytes(3):
        return None
    size = struct.unpack_from("<I", metadata, 4)[0]
    if not 0x1000 <= size <= MAXIMUM_SHELLCODE_BYTES:
        return None
    return metadata[0], size


def _metadata_from_data_tail_window(
    section_data: bytes,
) -> list[tuple[int, int, int]]:
    """`.data`末尾1,024 bytesからmetadata候補を上限付きで列挙する。"""

    candidates = []
    start = max(0, len(section_data) - 0x400)
    start += (-start) % 4
    for offset in range(start, len(section_data) - 7, 4):
        metadata = section_data[offset : offset + 8]
        if metadata[0] == 0 or metadata[1:4] != bytes(3):
            continue
        size = struct.unpack_from("<I", metadata, 4)[0]
        if 0x1000 <= size <= MAXIMUM_SHELLCODE_BYTES:
            candidates.append((metadata[0], size, len(section_data) - offset))
    return candidates


def _reassemble(
    section_data: bytes,
    shellcode_size: int,
    extra_alignment_mask: int = 0,
) -> bytes | None:
    common = shellcode_size // CHUNK_COUNT
    if common <= 0:
        return None
    logical_sizes = [common] * (CHUNK_COUNT - 1)
    logical_sizes.append(shellcode_size - sum(logical_sizes))
    stored_sizes = list(reversed(logical_sizes))
    cursor = DATA_PREFIX_SIZE
    stored_chunks = []
    for index, chunk_size in enumerate(stored_sizes):
        end = cursor + chunk_size
        if end > len(section_data):
            return None
        stored_chunks.append(section_data[cursor:end])
        if index + 1 < CHUNK_COUNT:
            aligned = _align(end)
            if extra_alignment_mask & (1 << index):
                aligned += CHUNK_ALIGNMENT
            if aligned > len(section_data) or section_data[end:aligned] != bytes(
                aligned - end
            ):
                return None
            cursor = aligned
    return b"".join(reversed(stored_chunks))


def _candidate_reassemblies(
    section_data: bytes,
    metadata_candidates: list[tuple[int, int, int]],
) -> Iterator[tuple[int, int, int, bytes, int]]:
    """padding 0/16 bytesの8組合せを順次試し、同時保持量を制限する。"""

    if len(metadata_candidates) > 8:
        return
    for base_key, shellcode_size, metadata_offset_from_end in metadata_candidates:
        if shellcode_size > len(section_data) - DATA_PREFIX_SIZE:
            continue
        for extra_alignment_mask in range(1 << (CHUNK_COUNT - 1)):
            encrypted = _reassemble(section_data, shellcode_size, extra_alignment_mask)
            if encrypted is not None:
                yield (
                    base_key,
                    shellcode_size,
                    metadata_offset_from_end,
                    encrypted,
                    extra_alignment_mask,
                )


def _reassemble_chunks(
    section_data: bytes,
    shellcode_size: int,
    extra_alignment_mask: int,
    chunk_count: int,
) -> bytes | None:
    common = shellcode_size // chunk_count
    if common <= 0:
        return None
    logical_sizes = [common] * (chunk_count - 1)
    logical_sizes.append(shellcode_size - sum(logical_sizes))
    stored_sizes = list(reversed(logical_sizes))
    cursor = DATA_PREFIX_SIZE
    stored_chunks = []
    for index, chunk_size in enumerate(stored_sizes):
        end = cursor + chunk_size
        if end > len(section_data):
            return None
        stored_chunks.append(section_data[cursor:end])
        if index + 1 < chunk_count:
            aligned = _align(end)
            if extra_alignment_mask & (1 << index):
                aligned += CHUNK_ALIGNMENT
            if aligned > len(section_data) or section_data[end:aligned] != bytes(
                aligned - end
            ):
                return None
            cursor = aligned
    return b"".join(reversed(stored_chunks))


def _candidate_reassemblies_multi(
    section_data: bytes,
    metadata_candidates: list[tuple[int, int, int]],
) -> Iterator[tuple[int, int, int, bytes, int, int]]:
    """4/8分割と追加paddingのbounded候補を順次返す。"""

    if len(metadata_candidates) > 8:
        return
    for base_key, shellcode_size, metadata_offset_from_end in metadata_candidates:
        if shellcode_size > len(section_data) - DATA_PREFIX_SIZE:
            continue
        for chunk_count in SUPPORTED_CHUNK_COUNTS:
            combination_count = 1 << (chunk_count - 1)
            if shellcode_size * combination_count > MAXIMUM_CANDIDATE_WORK_BYTES:
                continue
            for extra_alignment_mask in range(combination_count):
                encrypted = _reassemble_chunks(
                    section_data,
                    shellcode_size,
                    extra_alignment_mask,
                    chunk_count,
                )
                if encrypted is not None:
                    yield (
                        base_key,
                        shellcode_size,
                        metadata_offset_from_end,
                        encrypted,
                        extra_alignment_mask,
                        chunk_count,
                    )


def recover_reverse_chunk_affine_xor_donut_pe(
    data: bytes,
) -> tuple[dict, list[tuple[str, bytes]]]:
    """metadata、fragment境界、XOR式、Donut instanceが一致する場合だけ回収する。"""

    if not data.startswith(b"MZ"):
        return {"status": "not_pe"}, []
    if len(data) > MAXIMUM_INPUT_BYTES:
        return {"status": "input_limit_exceeded"}, []
    try:
        image = pefile.PE(data=data, fast_load=True)
        sections = list(image.sections)
        data_sections = [
            section for section in sections if section.Name.rstrip(b"\0") == b".data"
        ]
        if len(data_sections) != 1:
            raise ValueError("unique .data section required")
    except (AttributeError, ValueError, pefile.PEFormatError):
        return {"status": "wrapper_not_detected"}, []
    section_data = _section_bytes(data, data_sections[0])
    if (
        section_data is None
        or len(section_data) < DATA_PREFIX_SIZE + 0x1000
        or section_data[:DATA_PREFIX_SIZE] != bytes(DATA_PREFIX_SIZE)
    ):
        return {"status": "wrapper_not_detected"}, []
    metadata_candidates = _metadata_from_data_tail_window(section_data)
    if not metadata_candidates:
        return {"status": "wrapper_not_detected"}, []
    successes: dict[str, tuple[dict, bytes]] = {}
    for (
        base_key,
        shellcode_size,
        metadata_offset_from_end,
        encrypted,
        extra_alignment_mask,
        chunk_count,
    ) in _candidate_reassemblies_multi(section_data, metadata_candidates):
        recovered = affine_xor(base_key, encrypted)
        if not is_donut_shellcode(recovered):
            continue
        try:
            _instance, layout = decrypt_instance(recovered)
        except ValueError:
            continue
        digest = _sha256(recovered)
        successes[digest] = (
            {
                "status": "donut_shellcode_recovered",
                "profile": "pe_data_reverse_four_chunks_affine_xor",
                "metadata_section": ".data_tail_window",
                "metadata_offset_from_end": metadata_offset_from_end,
                "encrypted_size": len(encrypted),
                "encrypted_sha256": _sha256(encrypted),
                "chunk_count": chunk_count,
                "chunk_order": "stored_reverse_logical",
                "chunk_alignment": CHUNK_ALIGNMENT,
                "extra_alignment_blocks": [
                    (extra_alignment_mask >> index) & 1
                    for index in range(chunk_count - 1)
                ],
                "xor_key_size": 1,
                "xor_key_sha256": _sha256(bytes([base_key])),
                "xor_delta": KEY_DELTA,
                "raw_key_published": False,
                "donut_layout": layout.name,
                "recovered_size": len(recovered),
                "recovered_sha256": digest,
                "executed": False,
                "network_contacted": False,
            },
            recovered,
        )
    if len(successes) != 1:
        return {
            "status": "wrapper_not_detected" if not successes else "ambiguous_recovery",
            "candidate_count": len(successes),
        }, []
    report, recovered = next(iter(successes.values()))
    return report, [("reverse-chunk-affine-xor-donut-shellcode", recovered)]
