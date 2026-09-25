#!/usr/bin/env python3
"""MalwareBazaarの日次Windows選定へ終端payload回収優先候補を統合する。"""

from __future__ import annotations

import argparse
import importlib.util
import json
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Any


def _read_manifest(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise TypeError(f"manifest must be an object: {path}")
    return value


def _digest(value: object) -> str:
    digest = str(value or "").lower()
    if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        raise ValueError(f"invalid SHA-256: {value!r}")
    return digest


@lru_cache(maxsize=1)
def _batch_contract() -> Any:
    """取得器の選定commitmentとatomic保存契約をそのまま再利用する。"""

    path = Path(__file__).with_name("malwarebazaar_batch.py")
    spec = importlib.util.spec_from_file_location("malwarebazaar_batch_priority_contract", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("MalwareBazaar取得器の契約を読めません")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _timestamp(row: dict[str, Any]) -> datetime:
    raw = str(row.get("first_seen") or "")
    try:
        return datetime.strptime(raw, "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC)
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
    if base.get("selection_only") is False or base.get("downloaded") not in (None, 0) or base.get("items"):
        raise ValueError("base selection has already started downloading")
    if (base.get("selection_provenance") or {}).get("terminal_payload_priority"):
        raise ValueError("base selection has already been priority merged")
    stored_commitment = base.get("selection_commitment_sha256")
    if stored_commitment is not None and stored_commitment != _batch_contract()._windows_selection_commitment(base):
        raise ValueError("base selection commitment is invalid")
    metadata_by_hash = {_digest(row.get("sha256_hash")): row for row in metadata}
    if set(metadata_by_hash) != set(hashes):
        raise ValueError("base selected_hashes and selected_metadata do not match")

    additions: list[dict[str, Any]] = []
    already_selected: list[dict[str, str]] = []
    skipped_non_windows_pe: list[dict[str, str]] = []
    seen_priority: set[str] = set()
    for family, manifest in priority_manifests:
        selected = manifest.get("selected_hashes") or []
        rows = manifest.get("selected_metadata") or []
        if (
            manifest.get("selection_mode") != "signature_newest"
            or not selected
            or len(selected) != len(rows)
            or len(selected) > requested
        ):
            raise ValueError(f"priority manifest must contain bounded frozen signature candidates: {family}")
        for selected_hash, source_row in zip(selected, rows):
            if not isinstance(source_row, dict):
                raise TypeError(f"priority metadata is not an object: {family}")
            digest = _digest(selected_hash)
            row = dict(source_row)
            if _digest(row.get("sha256_hash")) != digest:
                raise ValueError(f"priority metadata mismatch: {family}")
            if row.get("file_type") not in {"exe", "dll"} or row.get("file_format") not in (None, "PE"):
                skipped_non_windows_pe.append({"family": family, "sha256": digest})
                continue
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
        "policy": "指定ファミリーの最新未解析Windows PE候補で一般選定の最古候補を置換",
        "already_selected": already_selected,
        "skipped_non_windows_pe": skipped_non_windows_pe,
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
    updated["selection_commitment_sha256"] = _batch_contract()._windows_selection_commitment(updated)
    plan = {
        "requested": requested,
        "priority_family_count": len(priority_manifests),
        "priority_candidate_count": len(seen_priority),
        "skipped_non_windows_pe_count": len(skipped_non_windows_pe),
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
    priorities = []
    for family in families:
        family_root = args.priority_root / family
        manifest_path = family_root / "manifest.json"
        if not manifest_path.is_file():
            nested = sorted(family_root.glob("*/manifest.json"))
            if len(nested) != 1:
                raise ValueError(f"priority manifest must be unique: {family}")
            manifest_path = nested[0]
        priorities.append((family, _read_manifest(manifest_path)))
    updated, plan = build_priority_plan(_read_manifest(args.base_manifest), priorities)
    if args.write:
        batch = _batch_contract()
        batch._write_json_atomic(args.base_manifest, updated)
        batch.write_verification_family_hints(args.base_manifest)
    print(json.dumps({**plan, "write_performed": args.write}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
