#!/usr/bin/env python3
"""MalwareBazaarの日次Windows選定へ終端payload回収優先候補を統合する。"""

from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path
from typing import Any


def _read_manifest(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"manifest must be an object: {path}")
    return value


def _digest(value: object) -> str:
    digest = str(value or "").lower()
    if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        raise ValueError(f"invalid SHA-256: {value!r}")
    return digest


def _timestamp(row: dict[str, Any]) -> datetime:
    raw = str(row.get("first_seen") or "")
    try:
        return datetime.strptime(raw, "%Y-%m-%d %H:%M:%S")
    except ValueError as exc:
        raise ValueError(f"invalid first_seen: {raw!r}") from exc


def build_priority_plan(
    base: dict[str, Any], priority_manifests: list[tuple[str, dict[str, Any]]]
) -> tuple[dict[str, Any], dict[str, Any]]:
    if base.get("selection_mode") != "windows_pe_newest":
        raise ValueError("base manifest is not a frozen Windows selection")
    requested = int(base.get("requested") or 0)
    hashes = [_digest(value) for value in base.get("selected_hashes") or []]
    metadata = [dict(row) for row in base.get("selected_metadata") or [] if isinstance(row, dict)]
    if requested < 1 or len(hashes) != requested or len(metadata) != requested:
        raise ValueError("base manifest does not contain the requested frozen selection")
    metadata_by_hash = {_digest(row.get("sha256_hash")): row for row in metadata}
    if set(metadata_by_hash) != set(hashes):
        raise ValueError("base selected_hashes and selected_metadata do not match")

    additions: list[dict[str, Any]] = []
    already_selected: list[dict[str, str]] = []
    seen_priority: set[str] = set()
    for family, manifest in priority_manifests:
        selected = manifest.get("selected_hashes") or []
        rows = manifest.get("selected_metadata") or []
        if manifest.get("selection_mode") != "signature_newest" or len(selected) != 1 or len(rows) != 1:
            raise ValueError(f"priority manifest must contain one frozen signature candidate: {family}")
        digest = _digest(selected[0])
        row = dict(rows[0])
        if _digest(row.get("sha256_hash")) != digest:
            raise ValueError(f"priority metadata mismatch: {family}")
        if digest in seen_priority:
            raise ValueError(f"duplicate priority SHA-256: {digest}")
        seen_priority.add(digest)
        if digest in metadata_by_hash:
            already_selected.append({"family": family, "sha256": digest})
            continue
        row["terminal_payload_priority_family"] = family.lower()
        additions.append(row)

    removable = sorted(
        (row for row in metadata if _digest(row.get("sha256_hash")) not in seen_priority),
        key=_timestamp,
    )
    if len(removable) < len(additions):
        raise ValueError("base selection does not contain enough non-priority candidates")
    removed = removable[: len(additions)]
    removed_hashes = {_digest(row.get("sha256_hash")) for row in removed}
    retained = [row for row in metadata if _digest(row.get("sha256_hash")) not in removed_hashes]
    combined = sorted([*retained, *additions], key=_timestamp, reverse=True)
    if len(combined) != requested or len({_digest(row.get("sha256_hash")) for row in combined}) != requested:
        raise ValueError("priority merge did not preserve a unique fixed-size selection")

    updated = dict(base)
    updated["selected_hashes"] = [_digest(row.get("sha256_hash")) for row in combined]
    updated["selected_metadata"] = combined
    provenance = dict(updated.get("selection_provenance") or {})
    provenance["terminal_payload_priority"] = {
        "policy": "P0 family latest unanalysed candidate replaces oldest general candidate",
        "already_selected": already_selected,
        "added": [
            {
                "family": str(row["terminal_payload_priority_family"]),
                "sha256": _digest(row.get("sha256_hash")),
                "first_seen": row.get("first_seen"),
            }
            for row in additions
        ],
        "replaced": [
            {"sha256": _digest(row.get("sha256_hash")), "first_seen": row.get("first_seen")}
            for row in removed
        ],
    }
    updated["selection_provenance"] = provenance
    updated["selection_only"] = True
    updated["downloaded"] = 0
    updated["pending"] = 0
    updated["complete"] = False
    updated["retry_queue"] = []
    updated["items"] = []
    plan = {
        "requested": requested,
        "priority_candidate_count": len(priority_manifests),
        "already_selected_count": len(already_selected),
        "added_count": len(additions),
        "replaced_count": len(removed),
        "selected_count": len(combined),
        "unique_count": len(updated["selected_hashes"]),
        "terminal_payload_priority": provenance["terminal_payload_priority"],
    }
    return updated, plan


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-manifest", required=True, type=Path)
    parser.add_argument("--priority-root", required=True, type=Path)
    parser.add_argument("--family", action="append", default=[])
    parser.add_argument("--write", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    families = args.family or sorted(path.name for path in args.priority_root.iterdir() if path.is_dir())
    priorities = [
        (family, _read_manifest(args.priority_root / family / "manifest.json")) for family in families
    ]
    updated, plan = build_priority_plan(_read_manifest(args.base_manifest), priorities)
    if args.write:
        args.base_manifest.write_text(
            json.dumps(updated, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
    print(json.dumps({**plan, "write_performed": args.write}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
