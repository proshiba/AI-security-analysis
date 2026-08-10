#!/usr/bin/env python3
"""既知マルウェアのscript-only解析カバレッジを機械監査する。"""

from __future__ import annotations

import argparse
from collections import defaultdict
import json
import os
from pathlib import Path
import tempfile
from typing import Any, Sequence

from analysis_contract import load_json_object_strict
from handler_catalog import HandlerSpec, discover_handlers


SCHEMA_VERSION = 1
FRAMEWORK_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REGISTRY = FRAMEWORK_ROOT / "registry" / "malware_types.json"


def _registered_families(path: Path) -> set[str]:
    document = load_json_object_strict(path)
    values = document.get("malware_types")
    if not isinstance(values, dict):
        raise ValueError("registry.malware_typesはobjectで指定してください")
    if any(not isinstance(key, str) or not key for key in values):
        raise ValueError("registryのfamily名が不正です")
    return set(values)


def build_coverage(
    *,
    registered_families: set[str],
    specs: Sequence[HandlerSpec],
) -> dict[str, Any]:
    """detectorとhandlerの組合せから自動化能力を決定的に集計する。"""

    by_family: dict[str, list[HandlerSpec]] = defaultdict(list)
    for spec in specs:
        by_family[spec.family].append(spec)
    rows = []
    for family in sorted(registered_families | set(by_family)):
        family_specs = sorted(by_family.get(family, []), key=lambda item: item.id)
        automatic = [item for item in family_specs if item.automatic and item.supported_interface]
        manual = [item for item in family_specs if item not in automatic]
        detector = family in registered_families
        if detector and automatic:
            status = "fully_routable"
            blocker = None
            next_action = None
        elif automatic:
            status = "candidate_verification_only"
            blocker = "detector_missing"
            next_action = "family固有detectorを追加し、候補検証から自動選択へ昇格させる。"
        elif detector and family_specs:
            status = "manual_handler_only"
            blocker = "automatic_handler_missing"
            next_action = "既存handlerを副作用のない共通契約へ適合させる。"
        elif detector:
            status = "classification_only"
            blocker = "handler_missing"
            next_action = "config・通信先・特徴ロジックを返す静的handlerを追加する。"
        elif family_specs:
            status = "manual_only_without_detector"
            blocker = "detector_and_automatic_handler_missing"
            next_action = "detectorを追加し、既存handlerを共通契約へ適合させる。"
        else:
            status = "unsupported"
            blocker = "detector_and_handler_missing"
            next_action = "detectorと静的handlerを追加する。"
        rows.append(
            {
                "family": family,
                "status": status,
                "detector_registered": detector,
                "automatic_selection_possible": bool(detector and automatic),
                "candidate_verification_possible": bool(automatic),
                "script_only_handler_available": bool(automatic),
                "automatic_handlers": [item.id for item in automatic],
                "manual_or_unsupported_handlers": [item.id for item in manual],
                "accepted_formats": sorted(
                    {value for item in automatic for value in item.input_formats}
                ),
                "blocker": blocker,
                "next_action_ja": next_action,
            }
        )
    status_counts = {
        status: sum(item["status"] == status for item in rows)
        for status in (
            "fully_routable",
            "candidate_verification_only",
            "manual_handler_only",
            "classification_only",
            "manual_only_without_detector",
            "unsupported",
        )
    }
    total = len(rows)
    fully = status_counts["fully_routable"]
    script_only = sum(item["script_only_handler_available"] for item in rows)
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "complete",
        "counts": {
            "families": total,
            "detector_registered": sum(item["detector_registered"] for item in rows),
            "script_only_handler_available": script_only,
            "fully_routable": fully,
            "candidate_verification_only": status_counts["candidate_verification_only"],
            "fully_routable_percent": round(100.0 * fully / total, 2) if total else 0.0,
            "script_only_handler_percent": round(100.0 * script_only / total, 2) if total else 0.0,
            "by_status": status_counts,
        },
        "families": rows,
        "executed_sample": False,
        "network_contacted": False,
        "ai_used": False,
    }


def render_markdown(report: dict[str, Any]) -> str:
    """人向けの日本語カバレッジ表を生成する。"""

    counts = report["counts"]
    lines = [
        "# 既知マルウェア自動解析カバレッジ",
        "",
        "本表はdetectorと静的handlerの実装状況から自動生成しています。検体実行、外部通信、生成AIは使用しません。",
        "",
        f"- 対象family: {counts['families']}件",
        f"- detector＋handlerで自動選択可能: {counts['fully_routable']}件（{counts['fully_routable_percent']}%）",
        f"- script-only handler利用可能: {counts['script_only_handler_available']}件（{counts['script_only_handler_percent']}%）",
        f"- handlerによる候補検証のみ: {counts['candidate_verification_only']}件",
        "",
        "| family | 状態 | detector | 自動handler | blocker |",
        "|---|---|---:|---:|---|",
    ]
    for item in report["families"]:
        lines.append(
            "| {family} | {status} | {detector} | {handlers} | {blocker} |".format(
                family=item["family"],
                status=item["status"],
                detector="あり" if item["detector_registered"] else "なし",
                handlers=len(item["automatic_handlers"]),
                blocker=item["blocker"] or "なし",
            )
        )
    lines.extend(
        [
            "",
            "## 判定の意味",
            "",
            "- `fully_routable`: detectorで候補を選び、静的handlerまで自動実行できます。",
            "- `candidate_verification_only`: 外部metadataなどから候補化できますが、family確定には強いhandler証拠が必要です。",
            "- `classification_only`: family判定後のconfig・C2・ロジック抽出が未自動化です。",
            "- `manual_handler_only`: handlerは存在しますが共通の安全契約へ未適合です。",
            "",
        ]
    )
    return "\n".join(lines)


def _atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            Path(temporary).unlink(missing_ok=True)
        finally:
            raise


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    parser.add_argument("--json-output", type=Path)
    parser.add_argument("--markdown-output", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.json_output is None and args.markdown_output is None:
        raise SystemExit("--json-outputまたは--markdown-outputを指定してください")
    report = build_coverage(
        registered_families=_registered_families(args.registry),
        specs=discover_handlers(),
    )
    if args.json_output is not None:
        _atomic_write_text(
            args.json_output,
            json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        )
    if args.markdown_output is not None:
        _atomic_write_text(args.markdown_output, render_markdown(report))
    print(json.dumps(report["counts"], ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
