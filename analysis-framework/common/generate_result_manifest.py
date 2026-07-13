from __future__ import annotations

import argparse
import hashlib
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser(description="Create a deterministic SHA-256 manifest for publishable result files.")
    ap.add_argument("--root", required=True, type=Path)
    ap.add_argument("--output", default="manifest.sha256")
    args = ap.parse_args()
    target = args.root / args.output
    rows = []
    for path in sorted(p for p in args.root.rglob("*") if p.is_file() and p != target):
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        rows.append(f"{digest}  {path.relative_to(args.root).as_posix()}")
    target.write_text("\n".join(rows) + "\n", encoding="utf-8")
    print(f"wrote {len(rows)} entries to {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
