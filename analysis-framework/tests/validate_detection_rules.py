from __future__ import annotations

import argparse
from pathlib import Path

import yaml
import yara


def main() -> int:
    ap = argparse.ArgumentParser(description="Parse Sigma YAML and compile YARA rules.")
    ap.add_argument("--results-root", required=True, type=Path)
    args = ap.parse_args()
    yaml_count = 0
    yara_count = 0
    for path in args.results_root.rglob("*.yml"):
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(doc, dict) or "detection" not in doc or "logsource" not in doc:
            raise ValueError(f"not a Sigma-like rule: {path}")
        yaml_count += 1
    for path in args.results_root.rglob("*.yar"):
        yara.compile(filepath=str(path))
        yara_count += 1
    print(f"PASS: parsed {yaml_count} Sigma YAML files and compiled {yara_count} YARA files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
