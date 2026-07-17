"""Compatibility facade for the generic index-XOR PE recovery helper.

The delivery transform formerly lived under a PureHVNC-specific name. It is
kept import-compatible, but callers should use
``unpackers.index_xor_pe_unpacker`` and classify recovered payloads separately.
"""

from __future__ import annotations

from unpackers.index_xor_pe_unpacker import (
    XorCandidate,
    build_parser,
    candidate_report,
    find_first_byte_xor_pes,
    first_byte_index_xor,
    main,
    pe_extent,
)

__all__ = [
    "XorCandidate",
    "build_parser",
    "candidate_report",
    "find_first_byte_xor_pes",
    "first_byte_index_xor",
    "main",
    "pe_extent",
]


if __name__ == "__main__":
    raise SystemExit(main())
