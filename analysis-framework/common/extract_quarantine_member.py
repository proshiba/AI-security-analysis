#!/usr/bin/env python3
"""Persist one authenticated MalwareBazaar member with a non-executable name."""

from __future__ import annotations

import argparse
from pathlib import Path

from malware_io import read_aes_zip_members, write_json


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--password", default="infected")
    args = parser.parse_args()

    members = read_aes_zip_members(args.archive, password=args.password)
    if len(members) != 1:
        raise ValueError(f"expected one file member, found {len(members)}")
    member = members[0]
    expected = args.expected_sha256.lower()
    if member.sha256.lower() != expected:
        raise ValueError(f"hash mismatch: expected {expected}, got {member.sha256}")

    args.output_dir.mkdir(parents=True, exist_ok=True)
    destination = args.output_dir / f"{member.sha256}.quarantine.bin"
    destination.write_bytes(member.data)
    metadata = {
        "schema_version": 1,
        "source_archive": str(args.archive),
        "original_member_name": member.name,
        "output": str(destination),
        "sha256": member.sha256,
        "size": len(member.data),
        "executed": False,
        "network_contacted": False,
    }
    write_json(args.output_dir / "quarantine-extraction.json", metadata)
    print({"output": str(destination), "sha256": member.sha256, "executed": False})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
