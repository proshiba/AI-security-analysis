"""Recover APT-C-60 downloader, loader, and SpyGlace repository envelopes.

The module only applies deterministic repeating-XOR transforms and validates
the resulting Portable Executable.  Recovered files are never loaded or run.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path

import pefile

REPOSITORY_XOR_KEY = b"sgznqhtgnghvmzxponum"
DOWNLOADER2_XOR_KEY = b"AadDDRTaSPtyAG57er#$ad!lDKTOPLTEL78pE"


@dataclass(frozen=True)
class RecoveredPayload:
    """One validated PE and the transform used to recover it."""

    data: bytes
    method: str
    input_sha256: str
    payload_sha256: str
    role: str


def sha256_bytes(data: bytes) -> str:
    """Return a lowercase SHA-256 digest."""
    return hashlib.sha256(data).hexdigest()


def repeating_xor(data: bytes, key: bytes) -> bytes:
    """Apply a symmetric repeating-key XOR transform."""
    if not key:
        raise ValueError("XOR key must not be empty")
    return bytes(value ^ key[index % len(key)] for index, value in enumerate(data))


def valid_pe(data: bytes) -> bool:
    """Return whether bytes form a bounded, structurally valid PE image."""
    if len(data) < 0x100 or not data.startswith(b"MZ"):
        return False
    try:
        image = pefile.PE(data=data, fast_load=True)
    except (pefile.PEFormatError, ValueError):
        return False
    return 1 <= image.FILE_HEADER.NumberOfSections <= 96


def classify_payload(data: bytes) -> str:
    """Classify a recovered APT-C-60 PE by high-specificity static markers."""
    if b"rpsgwra{l" in data and b"[ilJvvrSrel" in data:
        return "spyglace"
    if DOWNLOADER2_XOR_KEY in data:
        return "downloader2"
    if REPOSITORY_XOR_KEY in data:
        return "downloader1"
    lowered = data.lower()
    clsid_marker = "7849596a-48ea-486e-8937-a2a3009f31a9"
    clsid = (
        clsid_marker.encode() in lowered or clsid_marker.encode("utf-16le") in lowered
    )
    inproc = (
        b"inprocserver32" in lowered or "inprocserver32".encode("utf-16le") in lowered
    )
    cached = (
        b"cachedimage_2355_1481_pos4.dat" in lowered
        or "cachedimage_2355_1481_pos4.dat".encode("utf-16le") in lowered
    )
    if clsid and (inproc or cached):
        return "spyglace_loader"
    return "unknown_pe"


def recover_payload(data: bytes) -> RecoveredPayload | None:
    """Recover a literal or known repeating-XOR-wrapped PE, if present."""
    candidates = [("literal", data)]
    candidates.extend(
        (
            ("xor:sgznqhtgnghvmzxponum", repeating_xor(data, REPOSITORY_XOR_KEY)),
            (
                "xor:AadDDRTaSPtyAG57er#$ad!lDKTOPLTEL78pE",
                repeating_xor(data, DOWNLOADER2_XOR_KEY),
            ),
        )
    )
    for method, candidate in candidates:
        if valid_pe(candidate):
            return RecoveredPayload(
                data=candidate,
                method=method,
                input_sha256=sha256_bytes(data),
                payload_sha256=sha256_bytes(candidate),
                role=classify_payload(candidate),
            )
    return None


def build_parser() -> argparse.ArgumentParser:
    """Build the non-executing recovery command-line parser."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument(
        "--output", type=Path, help="Optional path for recovered PE bytes"
    )
    parser.add_argument("--report", type=Path, help="Optional JSON metadata path")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Recover one artifact and optionally write bytes and metadata."""
    args = build_parser().parse_args(argv)
    result = recover_payload(args.input.read_bytes())
    if result is None:
        raise SystemExit("no supported APT-C-60 PE envelope found")
    metadata = {
        "schema_version": 1,
        "input_sha256": result.input_sha256,
        "payload_sha256": result.payload_sha256,
        "method": result.method,
        "role": result.role,
        "payload_size": len(result.data),
        "executed": False,
        "network_contacted": False,
    }
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(result.data)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(metadata, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
