#!/usr/bin/env python3
"""Compare ValleyRAT vvaS emulator and c2-live JSON results."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def load_records(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    records = data.get("results") if isinstance(data, dict) and isinstance(data.get("results"), list) else [data]
    normalized = []
    for record in records:
        banner = record.get("banner") or {}
        normalized.append({
            "source": str(path),
            "host": record.get("host"),
            "port": record.get("port"),
            "protocol": record.get("protocol"),
            "declared_stage2_size": record.get("declared_stage2_size"),
            "expected_stage2_size": record.get("expected_stage2_size"),
            "header_matches": record.get("header_matches"),
            "status": record.get("status"),
            "banner_sha256": banner.get("sha256"),
            "banner_shodan_mmh3": banner.get("shodan_mmh3"),
            "banner_prefix_base64": banner.get("prefix_base64"),
        })
    return normalized


def classify_group(records: list[dict[str, Any]]) -> str:
    if any(record.get("status") in {"protocol_mismatch", "connected_no_response"} for record in records):
        return "protocol_mismatch"
    if any(record.get("status") in {"closed", "timeout", "error"} for record in records):
        return "unavailable"
    sizes = {record.get("declared_stage2_size") for record in records}
    banners = {record.get("banner_sha256") for record in records}
    if len(sizes) > 1:
        return "stage_size_changed"
    if len(banners) > 1:
        return "banner_changed"
    return "unchanged"


def compare(paths: list[Path]) -> dict[str, Any]:
    records = [record for path in paths for record in load_records(path)]
    groups: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        key = f"{record.get('host')}:{record.get('port')}/{record.get('protocol')}"
        groups.setdefault(key, []).append(record)
    return {
        "schema_version": 1,
        "targets": [
            {
                "target": key,
                "comparison_status": classify_group(group),
                "records": group,
            }
            for key, group in sorted(groups.items())
        ],
    }


def print_table(summary: dict[str, Any]) -> None:
    print("target\tstatus\trecords")
    for target in summary["targets"]:
        print(f"{target['target']}\t{target['comparison_status']}\t{len(target['records'])}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Compare ValleyRAT vvaS emulator JSON results.")
    parser.add_argument("json_files", nargs="+", type=Path)
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON instead of a table.")
    args = parser.parse_args()
    summary = compare(args.json_files)
    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print_table(summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
