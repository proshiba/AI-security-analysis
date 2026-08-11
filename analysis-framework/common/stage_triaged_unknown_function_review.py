#!/usr/bin/env python3
"""未分類binaryのtriaged_unknownを代表関数レビュー待ちpartialへ正規化する。"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from analysis_contract import seal_report


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
FUNCTION_BLOCKER = "representative_function_analysis_required"


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON objectが必要です: {path}")
    return value


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def stage_cases(root: Path, *, write: bool = False) -> dict[str, Any]:
    cases_root = root / "cases"
    if not cases_root.is_dir():
        raise ValueError("one-shot cases directoryがありません")
    candidates: list[str] = []
    promoted_triaged: list[str] = []
    augmented_partial: list[str] = []
    untouched_triaged: list[dict[str, str]] = []
    reports: dict[str, dict[str, Any]] = {}
    for case_dir in sorted(path for path in cases_root.iterdir() if path.is_dir()):
        digest = case_dir.name.lower()
        if not SHA256_RE.fullmatch(digest):
            continue
        report = _read_json(case_dir / "report.json")
        state = report.get("case_state")
        if not isinstance(state, dict) or state.get("status") not in {"triaged_unknown", "partial"}:
            continue
        logic = _read_json(case_dir / "static-logic.json")
        blockers = state.get("blockers")
        if (
            report.get("assessment_only") is not False
            or state.get("complete") is not False
            or state.get("resumable") is not False
            or not isinstance(blockers, list)
            or any(not isinstance(blocker, str) for blocker in blockers)
            or logic.get("status") != "function_analysis_required"
        ):
            untouched_triaged.append({"sha256": digest, "reason": "not_safe_to_stage"})
            continue
        if FUNCTION_BLOCKER in blockers:
            continue
        if state.get("status") == "triaged_unknown" and blockers:
            untouched_triaged.append({"sha256": digest, "reason": "triaged_unknown_has_blockers"})
            continue
        updated = dict(report)
        updated_state = dict(state)
        updated_state["status"] = "partial"
        updated_state["blockers"] = sorted({*blockers, FUNCTION_BLOCKER})
        updated["case_state"] = updated_state
        seal_report(updated)
        reports[digest] = updated
        candidates.append(digest)
        if state.get("status") == "triaged_unknown":
            promoted_triaged.append(digest)
        else:
            augmented_partial.append(digest)

    summary_path = root / "summary.json"
    summary = _read_json(summary_path)
    summary_cases = summary.get("cases")
    counts = summary.get("counts")
    if not isinstance(summary_cases, list) or not isinstance(counts, dict):
        raise ValueError("summary.jsonのcases/countsが不正です")
    summary_by_hash = {
        str(item.get("sha256") or "").lower(): item
        for item in summary_cases
        if isinstance(item, dict)
    }
    if any(digest not in summary_by_hash for digest in candidates):
        raise ValueError("summary.jsonにstaging候補がありません")
    if int(counts.get("triaged_unknown") or 0) < len(promoted_triaged):
        raise ValueError("summary countsがstaging候補数と一致しません")

    if write:
        for digest, report in reports.items():
            _write_json(cases_root / digest / "report.json", report)
            summary_by_hash[digest]["case_state"] = "partial"
        counts["triaged_unknown"] = int(counts.get("triaged_unknown") or 0) - len(promoted_triaged)
        counts["partial"] = int(counts.get("partial") or 0) + len(promoted_triaged)
        _write_json(summary_path, summary)

    return {
        "candidate_count": len(candidates),
        "candidate_sha256": candidates,
        "promoted_triaged_unknown_count": len(promoted_triaged),
        "augmented_partial_count": len(augmented_partial),
        "untouched_triaged_unknown": untouched_triaged,
        "write_performed": write,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--one-shot", required=True, type=Path)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args(argv)
    print(json.dumps(stage_cases(args.one_shot, write=args.write), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
