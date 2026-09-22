#!/usr/bin/env python3
"""終端未復元caseの元archive証拠を照合し、静的再解析の入口を分類する。"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

from collection_followup_planner import (
    FollowupPlanError,
    _index_source_archives,
    _snapshot_sha256,
)

SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
IDENTIFIER_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z")
MAX_CASES = 5_000
MAX_DOCUMENT_BYTES = 16 * 1024 * 1024
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024


class TerminalGapQueueError(ValueError):
    """証拠が不正で安全な元archive照合を継続できない場合の例外。"""


def _digest(value: object, *, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise TerminalGapQueueError(f"{label}のSHA-256が不正です")
    return value


def _identifier(value: object, *, label: str) -> str:
    if not isinstance(value, str) or IDENTIFIER_RE.fullmatch(value) is None:
        raise TerminalGapQueueError(f"{label}が不正です")
    return value


def _json(path: Path) -> dict[str, Any]:
    try:
        if not path.is_file() or path.stat().st_size > MAX_DOCUMENT_BYTES:
            raise TerminalGapQueueError(f"証拠文書が見つからないか容量上限を超えています: {path.name}")
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise TerminalGapQueueError(f"証拠文書を読めません: {path.name}") from exc
    if not isinstance(value, dict):
        raise TerminalGapQueueError(f"証拠文書はobjectではありません: {path.name}")
    return value


def _case_directory(repository: Path, case: dict[str, Any]) -> Path:
    digest = _digest(case.get("sha256"), label="case")
    family = _identifier(case.get("family"), label="family")
    version = _identifier(case.get("version_key"), label="version_key")
    expected = f"analysis-results/malware/{family}/versions/{version}/cases/{digest}"
    if case.get("canonical_path") != expected:
        raise TerminalGapQueueError(f"case pathがcatalog形式と一致しません: {digest}")
    case_dir = repository.joinpath(*expected.split("/"))
    if not case_dir.is_dir() or not case_dir.resolve().is_relative_to(repository.resolve()):
        raise TerminalGapQueueError(f"case directoryがrepository外または不在です: {digest}")
    return case_dir


def _binding(sha256: object, size: object, *, label: str) -> tuple[str, int]:
    digest = _digest(sha256, label=label)
    if type(size) is not int or not 1 <= size <= MAX_ARCHIVE_BYTES:
        raise TerminalGapQueueError(f"{label}のarchive sizeが不正です")
    return digest, size


def _source_bindings(
    repository: Path,
    case: dict[str, Any],
    case_dir: Path,
    collection_cache: dict[Path, dict[str, Any]],
) -> list[dict[str, Any]]:
    digest = case["sha256"]
    bindings: list[dict[str, Any]] = []
    report_path = case_dir / "report.json"
    if report_path.is_file():
        report = _json(report_path)
        sample = report.get("sample")
        if (
            isinstance(sample, dict)
            and sample.get("input_kind") == "authenticated_single_member_zip"
            and sample.get("outer_sha256") is not None
        ):
            if sample.get("sha256") != digest:
                raise TerminalGapQueueError(f"report.sample.sha256がcaseと不一致です: {digest}")
            outer_hash, outer_size = _binding(
                sample.get("outer_sha256"), sample.get("outer_size"), label="report.sample"
            )
            bindings.append(
                {"archive_sha256": outer_hash, "archive_size": outer_size, "source": "case_report"}
            )

    metadata_path = case_dir / "metadata.json"
    metadata = _json(metadata_path) if metadata_path.is_file() else {}
    if metadata and metadata.get("sha256") != digest:
        raise TerminalGapQueueError(f"metadata.sha256がcaseと不一致です: {digest}")
    collections = metadata.get("collections", [])
    if not isinstance(collections, list) or len(collections) > 64:
        raise TerminalGapQueueError(f"metadata.collectionsが不正です: {digest}")
    for collection in collections:
        collection_id = _identifier(collection, label="collection_id")
        path = (
            repository
            / "analysis-results"
            / "collections"
            / collection_id
            / "sources"
            / case["family"]
            / "malwarebazaar-manifest.json"
        )
        if not path.is_file():
            continue
        if path not in collection_cache:
            collection_cache[path] = _json(path)
        manifest = collection_cache[path]
        items = manifest.get("items")
        if not isinstance(items, list) or len(items) > 5_000:
            raise TerminalGapQueueError(f"収集manifest.itemsが不正です: {collection_id}")
        matches = [item for item in items if isinstance(item, dict) and item.get("sha256") == digest]
        if len(matches) > 1:
            raise TerminalGapQueueError(f"収集manifestのcaseが重複しています: {digest}")
        if not matches:
            continue
        item = matches[0]
        source_meta = item.get("metadata")
        if isinstance(source_meta, dict) and source_meta.get("sha256_hash") != digest:
            raise TerminalGapQueueError(f"収集manifestの内部hashが不一致です: {digest}")
        archive_hash, archive_size = _binding(
            item.get("zip_sha256"), item.get("zip_size"), label="collection manifest"
        )
        bindings.append(
            {
                "archive_sha256": archive_hash,
                "archive_size": archive_size,
                "source": f"collection:{collection_id}",
            }
        )
    return sorted(bindings, key=lambda item: (item["archive_sha256"], item["source"]))


def _source_decision(
    case: dict[str, Any], bindings: list[dict[str, Any]], archive_index: dict[str, tuple[str, Path | None]] | None
) -> dict[str, Any]:
    if case.get("state") == "source_material_absent":
        return {"status": "required_terminal_bytes_absent", "action": "seek_exact_sandbox_artifact_or_full_chain"}
    unique = {(item["archive_sha256"], item["archive_size"]) for item in bindings}
    if len(unique) > 1:
        return {"status": "conflicting_source_bindings", "action": "review_source_integrity_conflict"}
    if not unique:
        return {"status": "source_integrity_unbound", "action": "recover_original_archive_integrity_metadata"}
    archive_sha256, archive_size = next(iter(unique))
    result: dict[str, Any] = {
        "archive_sha256": archive_sha256,
        "archive_size": archive_size,
        "binding_sources": sorted(item["source"] for item in bindings),
    }
    if archive_index is None:
        result.update(status="not_checked", action="verify_original_archive_before_static_followup")
        return result
    state, candidate = archive_index.get(case["sha256"], ("absent", None))
    if state == "duplicate":
        result.update(status="duplicate_archive_name", action="resolve_duplicate_private_sources")
    elif state != "candidate" or candidate is None:
        result.update(status="archive_absent", action="reacquire_exact_original_archive")
    else:
        try:
            observed_sha256, observed_size = _snapshot_sha256(candidate, maximum_bytes=MAX_ARCHIVE_BYTES)
        except (OSError, FollowupPlanError, ValueError):
            result.update(status="unsafe_or_invalid_archive", action="review_private_archive_integrity")
        else:
            if observed_sha256 != archive_sha256 or observed_size != archive_size:
                result.update(status="archive_mismatch", action="review_private_archive_integrity")
            else:
                result.update(status="verified", action="start_new_static_workflow_after_evidence_change")
    return result


def build_queue(
    repository: Path,
    inventory: dict[str, Any],
    *,
    families: set[str] | None = None,
    input_root: Path | None = None,
) -> dict[str, Any]:
    """公開証拠と任意の私有入力rootを照合し、実行を伴わないcase別計画を返す。"""

    root = repository.resolve(strict=True)
    raw_cases = inventory.get("cases")
    if not isinstance(raw_cases, list) or len(raw_cases) > MAX_CASES:
        raise TerminalGapQueueError("終端ギャップ台帳のcasesが不正です")
    selected: list[tuple[dict[str, Any], Path]] = []
    seen: set[str] = set()
    for raw in raw_cases:
        if not isinstance(raw, dict):
            raise TerminalGapQueueError("終端ギャップ台帳のcaseがobjectではありません")
        digest = _digest(raw.get("sha256"), label="case")
        if digest in seen:
            raise TerminalGapQueueError("終端ギャップ台帳のSHA-256が重複しています")
        seen.add(digest)
        family = _identifier(raw.get("family"), label="family")
        if families is not None and family not in families:
            continue
        selected.append((raw, _case_directory(root, raw)))

    try:
        archive_index = (
            _index_source_archives(input_root.resolve(strict=True), (case["sha256"] for case, _ in selected))
            if input_root is not None
            else None
        )
    except (OSError, FollowupPlanError, ValueError) as exc:
        raise TerminalGapQueueError("私有入力rootを安全に列挙できません") from exc

    collection_cache: dict[Path, dict[str, Any]] = {}
    rows: list[dict[str, Any]] = []
    for case, case_dir in selected:
        bindings = _source_bindings(root, case, case_dir, collection_cache)
        decision = _source_decision(case, bindings, archive_index)
        rows.append(
            {
                "sha256": case["sha256"],
                "family": case["family"],
                "priority": case.get("priority"),
                "state": case.get("state"),
                "gap_types": case.get("gap_types", []),
                "source": decision,
                "automatic_dispatch_allowed": False,
            }
        )
    rows.sort(key=lambda item: (item["priority"] or "P9", item["family"], item["sha256"]))
    counts = Counter(row["source"]["status"] for row in rows)
    return {
        "schema_version": 1,
        "scope": {"case_count": len(rows), "source_status_counts": dict(sorted(counts.items()))},
        "safety": {"sample_executed": False, "network_contacted": False, "automatic_dispatch_allowed": False},
        "cases": rows,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=Path("."))
    parser.add_argument("--inventory", type=Path, default=Path("intelligence/terminal-payload-recovery/inventory.json"))
    parser.add_argument("--family", action="append", default=[])
    parser.add_argument("--input-root", type=Path, help="任意のリポジトリ外・私有archive root。読取のみ")
    parser.add_argument("--output", type=Path, help="analysis-results/research配下の公開JSON出力先")
    parser.add_argument("--write", action="store_true", help="指定先へ決定的なJSONを保存する")
    parser.add_argument("--check", action="store_true", help="指定先が現在の証拠と一致するか検証する")
    args = parser.parse_args(argv)
    root = args.repository.resolve(strict=True)
    if args.write and args.check:
        parser.error("--writeと--checkは同時指定できません")
    if (args.write or args.check) and args.output is None:
        parser.error("--writeまたは--checkには--outputが必要です")
    if args.input_root is not None and (
        args.input_root.resolve(strict=True).is_relative_to(root)
        or root.is_relative_to(args.input_root.resolve(strict=True))
    ):
        parser.error("input-rootはrepositoryと包含関係にできません")
    inventory_path = args.inventory if args.inventory.is_absolute() else root / args.inventory
    inventory = _json(inventory_path)
    families = {_identifier(value, label="family") for value in args.family} or None
    queue = build_queue(root, inventory, families=families, input_root=args.input_root)
    queue["inventory_sha256"] = hashlib.sha256(inventory_path.read_bytes()).hexdigest()
    rendered = json.dumps(queue, ensure_ascii=False, indent=2) + "\n"
    if args.output is not None:
        output = args.output if args.output.is_absolute() else root / args.output
        resolved = output.resolve(strict=False)
        relative = resolved.relative_to(root) if resolved.is_relative_to(root) else None
        if (
            relative is None
            or relative.parts[:2] != ("analysis-results", "research")
            or output.suffix != ".json"
        ):
            parser.error("公開出力先はrepository内のanalysis-results/research配下のJSONに限定します")
        if args.write:
            output.parent.mkdir(parents=True, exist_ok=True)
            temporary = output.with_name(output.name + ".tmp")
            temporary.write_text(rendered, encoding="utf-8", newline="\n")
            temporary.replace(output)
            print(json.dumps({"status": "written", "case_count": len(queue["cases"])}, ensure_ascii=False))
            return 0
        if args.check:
            try:
                current = output.read_text(encoding="utf-8")
            except OSError:
                current = None
            matched = current == rendered
            print(json.dumps({"status": "current" if matched else "stale", "case_count": len(queue["cases"])}, ensure_ascii=False))
            return 0 if matched else 1
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
