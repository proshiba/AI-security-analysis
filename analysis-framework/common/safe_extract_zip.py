"""通常ZIPを安全上限内で展開し、メンバーは実行しない。"""

from __future__ import annotations

import argparse
from pathlib import Path

from malware_io import (
    DEFAULT_MAX_ARCHIVE_MEMBERS,
    DEFAULT_MAX_COMPRESSION_RATIO,
    DEFAULT_MAX_EXTRACTED_TOTAL,
    DEFAULT_MAX_MEMBER_SIZE,
    persist_archive_members,
    read_zip_members,
)


def build_parser() -> argparse.ArgumentParser:
    """安全な通常ZIP展開用の引数を構築する。"""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--max-member-size", type=int, default=DEFAULT_MAX_MEMBER_SIZE)
    parser.add_argument("--max-members", type=int, default=DEFAULT_MAX_ARCHIVE_MEMBERS)
    parser.add_argument("--max-total-size", type=int, default=DEFAULT_MAX_EXTRACTED_TOTAL)
    parser.add_argument("--max-compression-ratio", type=float, default=DEFAULT_MAX_COMPRESSION_RATIO)
    return parser


def main(argv: list[str] | None = None) -> int:
    """ZIP全体を検証してから、上書きせずにメンバーを保存する。"""

    args = build_parser().parse_args(argv)
    members = read_zip_members(
        args.archive,
        max_member_size=args.max_member_size,
        max_members=args.max_members,
        max_total_size=args.max_total_size,
        max_compression_ratio=args.max_compression_ratio,
    )
    written = persist_archive_members(members, args.output)
    print(f"安全に{len(written)}件を展開しました: {args.output}; executed=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
