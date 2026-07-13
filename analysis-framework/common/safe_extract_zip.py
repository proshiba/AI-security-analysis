from __future__ import annotations

import argparse
import zipfile
from pathlib import Path


def main() -> int:
    """Implement the main operation for the analysis framework."""
    parser = argparse.ArgumentParser(description="Extract a ZIP after path traversal checks; never execute members.")
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    with zipfile.ZipFile(args.archive) as archive:
        for item in archive.infolist():
            member = Path(item.filename)
            if member.is_absolute() or ".." in member.parts:
                raise ValueError(f"unsafe archive member: {item.filename}")
        args.output.mkdir(parents=True, exist_ok=True)
        archive.extractall(args.output)
    print(f"Extracted safely to {args.output}; no member was executed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
