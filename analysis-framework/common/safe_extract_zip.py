from __future__ import annotations
import argparse
import zipfile
from pathlib import Path
from malware_io import validate_member_name

def main() -> int:
    parser = argparse.ArgumentParser(description="Extract an ordinary ZIP after member-path checks; never execute members.")
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(args.archive) as archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            name = validate_member_name(info.filename)
            target = args.output.joinpath(*Path(name).parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(archive.read(info))
    print(f"Extracted safely to {args.output}; no member was executed.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
