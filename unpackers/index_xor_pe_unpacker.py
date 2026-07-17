"""Recover generic first-byte/index-XOR PE envelopes without executing them.

The transform is a delivery-layer primitive and is not, by itself, evidence of
PureHVNC, Donut, or any other terminal malware family.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class XorCandidate:
    """One structurally validated embedded PE candidate."""

    offset: int
    stride: int
    key: int
    data: bytes


def first_byte_index_xor(envelope: bytes) -> bytes:
    """Decrypt bytes where byte zero is the key and later bytes use key+index."""
    if len(envelope) < 2:
        raise ValueError("envelope must contain a key and ciphertext")
    key = envelope[0]
    return bytes((((key + index) & 0xFF) ^ value) for index, value in enumerate(envelope[1:]))


def pe_extent(data: bytes) -> int | None:
    """Return a bounded PE file extent, or none when headers are invalid."""
    if len(data) < 0x100 or data[:2] != b"MZ":
        return None
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset + 24 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\0\0":
        return None
    sections = struct.unpack_from("<H", data, pe_offset + 6)[0]
    optional = struct.unpack_from("<H", data, pe_offset + 20)[0]
    table = pe_offset + 24 + optional
    if not 1 <= sections <= 96 or table + sections * 40 > len(data):
        return None
    extent = table + sections * 40
    for index in range(sections):
        raw_size, raw_offset = struct.unpack_from("<II", data, table + index * 40 + 16)
        if raw_offset + raw_size > len(data):
            return None
        extent = max(extent, raw_offset + raw_size)
    return extent


def find_first_byte_xor_pes(data: bytes, strides: tuple[int, ...] = (1, 4)) -> list[XorCandidate]:
    """Find stride-one or sparse-stride XOR envelopes that decrypt to valid PEs."""
    candidates: list[XorCandidate] = []
    for stride in strides:
        if stride < 1:
            raise ValueError("stride must be positive")
        for offset in range(0, len(data) - 3 * stride):
            key = data[offset]
            if (data[offset + stride] ^ key) != 0x4D:
                continue
            if (data[offset + 2 * stride] ^ ((key + 1) & 0xFF)) != 0x5A:
                continue
            envelope = data[offset::stride]
            clear = first_byte_index_xor(envelope)
            extent = pe_extent(clear)
            if extent:
                candidates.append(XorCandidate(offset, stride, key, clear[:extent]))
    unique: dict[tuple[bytes, int], XorCandidate] = {}
    for item in candidates:
        unique[(hashlib.sha256(item.data).digest(), item.stride)] = item
    return sorted(unique.values(), key=lambda item: (item.offset, item.stride))


def candidate_report(candidates: list[XorCandidate]) -> list[dict[str, int | str]]:
    """Convert recovered candidates to publish-safe metadata."""
    return [
        {
            "offset": item.offset,
            "stride": item.stride,
            "key": item.key,
            "size": len(item.data),
            "sha256": hashlib.sha256(item.data).hexdigest(),
        }
        for item in candidates
    ]


def build_parser() -> argparse.ArgumentParser:
    """Build the generic static envelope-recovery parser."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--json", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Recover validated embedded PEs and emit hashes and offsets."""
    args = build_parser().parse_args(argv)
    candidates = find_first_byte_xor_pes(args.input.read_bytes())
    report = candidate_report(candidates)
    if args.output_dir:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        for index, item in enumerate(candidates):
            digest = hashlib.sha256(item.data).hexdigest()
            (args.output_dir / f"recovered-{index}-{digest}.bin").write_bytes(item.data)
    output = {"candidates": report, "executed": False, "network_contacted": False}
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
