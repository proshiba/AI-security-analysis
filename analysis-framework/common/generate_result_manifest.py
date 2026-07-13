from __future__ import annotations
import argparse
from pathlib import Path
from malware_io import sha256_file

def main() -> int:
    parser = argparse.ArgumentParser(description="Create a deterministic SHA-256 manifest for publishable result files.")
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--output", default="manifest.sha256")
    args = parser.parse_args()
    target = args.root / args.output
    rows = [f"{sha256_file(path)}  {path.relative_to(args.root).as_posix()}" for path in sorted(item for item in args.root.rglob("*") if item.is_file() and item != target)]
    target.write_text("\n".join(rows) + "\n", encoding="utf-8")
    print(f"wrote {len(rows)} entries to {target}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
