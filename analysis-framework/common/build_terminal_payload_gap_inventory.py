#!/usr/bin/env python3
"""終端ペイロード未取得ケースと最新版取得優先表を決定的に生成する。"""

from __future__ import annotations

import argparse
import csv
import io
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

import yaml

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_PRIORITY_RANK = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
_SAFE_EVIDENCE_FILES = (
    "README.md",
    "FEATURES.md",
    "OVERALL-LOGIC.md",
    "STATIC-LOGIC.md",
    "report.json",
    "metadata.json",
    "config.json",
    "submission-analysis.json",
)
_NEGATIVE_RE = re.compile(
    r"(?:未取得|未復元|未回収|未解決|取得できな|復元できな|取得不可|復元不可|"
    r"not[ _-]?recovered|not[ _-]?retrieved|unresolved|missing|unavailable)",
    re.IGNORECASE,
)
_PAYLOAD_OBJECT_RE = re.compile(
    r"(?:payload|ペイロード|child[ _-]?PE|子PE|子実行ファイル|子バイナリ|"
    r"terminal[ _-]?(?:layer|family|assembly)|終端(?:層|本体|RAT|ファミリー|family|"
    r"PE|assembly|アセンブリ|resource|リソース|設定|config)|"
    r"最終(?:層|本体|RAT|ファミリー|family|PE|assembly|アセンブリ|resource|"
    r"リソース|設定|config)|後段(?:層|本体|RAT|PE|payload|ペイロード)|"
    r"第[二2]段(?:階|目)?(?:層|本体|PE|payload|ペイロード)|second[ _-]?stage)",
    re.IGNORECASE,
)
_POSITIVE_COMPLETION_RE = re.compile(
    r"(?:未復元ではな|未取得ではな|完全に復元|復元済み|取得済み|"
    r"terminal_family_confirmed\s*[\":=]+\s*true)",
    re.IGNORECASE,
)
_REPORT_BLOCKER_RE = re.compile(
    r"(?:terminal|payload|body_not_recovered|family_unresolved|resource_unresolved)",
    re.IGNORECASE,
)
_DATE_KEYS = {
    "added_at",
    "analysis_date",
    "collection_date",
    "date",
    "first_seen",
    "last_seen",
    "observed_at",
    "observed_date",
}
_DATE_RE = re.compile(r"(?<!\d)(20\d{2}-\d{2}-\d{2})(?!\d)")
_SIGNATURE_CANDIDATES = {
    "acrstealer": ["ACRStealer"],
    "agenttesla": ["AgentTesla"],
    "amadey": ["Amadey"],
    "darkcomet": ["DarkComet"],
    "efimer": ["Efimer"],
    "formbook": ["Formbook"],
    "hijackloader": ["HijackLoader"],
    "latrodectus": ["Latrodectus"],
    "lummastealer": ["LummaStealer", "LummaC2"],
    "mirai": ["Mirai"],
    "njrat": ["njRAT"],
    "prometei": ["Prometei"],
    "purehvnc": ["PureHVNC", "PureRAT"],
    "purelogs": ["PureLogs"],
    "quasarrat": ["QuasarRAT"],
    "redlinestealer": ["RedLineStealer"],
    "remcosrat": ["RemcosRAT"],
    "remusstealer": ["RemusStealer"],
    "shadowpad": ["ShadowPad"],
    "snakekeylogger": ["SnakeKeylogger"],
    "stealc": ["Stealc"],
    "valleyrat": ["ValleyRAT"],
    "venomrat": ["VenomRAT"],
    "vidar": ["Vidar"],
}


def _atomic_text_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(content, encoding="utf-8", newline="\n")
    temporary.replace(path)


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _normalize_sha256(value: Any, *, locator: str) -> str:
    sha256 = str(value or "").strip().lower()
    if not _SHA256_RE.fullmatch(sha256):
        raise ValueError(f"SHA-256が不正です: {locator}: {value!r}")
    return sha256


def _identity(
    catalog: dict[str, Any], sha256: str, *, fallback_family: str | None = None
) -> dict[str, str]:
    entry = catalog.get(sha256, {})
    family = str(entry.get("family") or fallback_family or "unclassified")
    if fallback_family and entry.get("family") and family != fallback_family:
        raise ValueError(
            f"familyがcatalogとinventoryで不一致です: {sha256}: "
            f"{family} != {fallback_family}"
        )
    return {
        "family": family,
        "version_key": str(entry.get("version_key") or "unknown"),
        "canonical_path": str(entry.get("canonical_path") or ""),
    }


def _new_case(sha256: str, identity: dict[str, str]) -> dict[str, Any]:
    return {
        "sha256": sha256,
        **identity,
        "priorities": set(),
        "states": set(),
        "gap_types": set(),
        "blockers": set(),
        "evidence": {},
        "observation_date": None,
    }


def _case_for(
    cases: dict[str, dict[str, Any]],
    catalog: dict[str, Any],
    sha256: str,
    *,
    fallback_family: str | None = None,
) -> dict[str, Any]:
    identity = _identity(catalog, sha256, fallback_family=fallback_family)
    current = cases.setdefault(sha256, _new_case(sha256, identity))
    if current["family"] != identity["family"]:
        raise ValueError(f"case内でfamilyが競合しました: {sha256}")
    return current


def _add_evidence(
    case: dict[str, Any],
    *,
    source: str,
    path: str,
    locator: str,
    summary: str,
) -> None:
    key = (source, path, locator, summary)
    case["evidence"][key] = {
        "source": source,
        "path": path,
        "locator": locator,
        "summary": summary[:320],
    }


def _gap_types(blockers: list[str], *, source_absent: bool = False) -> set[str]:
    joined = " ".join(blockers).casefold()
    result: set[str] = set()
    if source_absent:
        result.add("required_bytes_absent")
    if any(word in joined for word in ("payload", "terminal_layer", "terminal_family")):
        result.add("terminal_payload_unrecovered")
    if any(word in joined for word in ("config", "設定", "c2_not_recovered")):
        result.add("terminal_config_unrecovered")
    if any(word in joined for word in ("decoder", "constant_propagation", "state_machine")):
        result.add("decoder_or_constant_recovery_incomplete")
    if any(
        word in joined
        for word in (
            "virtual",
            "themida",
            "koi",
            "protector",
            "enigma",
            "nspack",
            "control_flow",
            "opaque",
        )
    ):
        result.add("protector_or_virtualization_boundary")
    if any(word in joined for word in ("size_gate", "container", "overlay", "resource")):
        result.add("container_or_resource_boundary")
    if not result:
        result.add("static_recovery_incomplete")
    return result


def _iter_dates(value: Any, key: str | None = None):
    if isinstance(value, dict):
        for child_key, child in value.items():
            yield from _iter_dates(child, str(child_key).casefold())
    elif isinstance(value, list):
        for child in value:
            yield from _iter_dates(child, key)
    elif key in _DATE_KEYS and isinstance(value, str):
        match = _DATE_RE.search(value)
        if match:
            yield match.group(1)


def _observation_date(case_dir: Path) -> str | None:
    metadata = case_dir / "metadata.json"
    if metadata.is_file():
        try:
            dates = sorted(set(_iter_dates(_load_json(metadata))))
        except (OSError, ValueError, json.JSONDecodeError):
            dates = []
        if dates:
            return dates[-1]
    readme = case_dir / "README.md"
    if readme.is_file():
        first_lines = "\n".join(
            readme.read_text(encoding="utf-8-sig", errors="replace").splitlines()[:8]
        )
        match = _DATE_RE.search(first_lines)
        if match:
            return match.group(1)
    return None


def _merge_curated_inventory(
    repository: Path,
    catalog: dict[str, Any],
    cases: dict[str, dict[str, Any]],
) -> dict[str, int]:
    path = repository / "analysis-framework" / "inventories" / "static-hard-cases.yaml"
    data = yaml.safe_load(path.read_text(encoding="utf-8-sig")) or {}
    counts = {"active": 0, "source_absent": 0}

    for index, item in enumerate(data.get("cases", [])):
        sha256 = _normalize_sha256(item.get("sha256"), locator=f"cases[{index}]")
        family = str(item.get("family") or "")
        blockers = [str(value) for value in item.get("blockers", [])]
        case = _case_for(cases, catalog, sha256, fallback_family=family)
        case["priorities"].add(str(item.get("priority") or "P2"))
        case["states"].add("curated_recovery_backlog")
        case["blockers"].update(blockers)
        case["gap_types"].update(_gap_types(blockers))
        _add_evidence(
            case,
            source="curated_static_hard_inventory",
            path=path.relative_to(repository).as_posix(),
            locator=f"cases[{index}]",
            summary=", ".join(blockers),
        )
        counts["active"] += 1

    for group_index, group in enumerate(data.get("groups", [])):
        family = str(group.get("family") or "")
        blockers = [str(value) for value in group.get("blockers", [])]
        group_id = str(group.get("id") or f"groups[{group_index}]")
        for hash_index, value in enumerate(group.get("hashes", [])):
            sha256 = _normalize_sha256(
                value, locator=f"groups[{group_index}].hashes[{hash_index}]"
            )
            case = _case_for(cases, catalog, sha256, fallback_family=family)
            case["priorities"].add(str(group.get("priority") or "P2"))
            case["states"].add("curated_recovery_backlog")
            case["blockers"].update(blockers)
            case["gap_types"].update(_gap_types(blockers))
            _add_evidence(
                case,
                source="curated_static_hard_inventory",
                path=path.relative_to(repository).as_posix(),
                locator=group_id,
                summary=", ".join(blockers),
            )
            counts["active"] += 1

    excluded = data.get("excluded_cases", {}) or {}
    reason = str(excluded.get("reason") or "required terminal bytes are absent")
    for index, value in enumerate(excluded.get("hashes", [])):
        sha256 = _normalize_sha256(value, locator=f"excluded_cases.hashes[{index}]")
        case = _case_for(cases, catalog, sha256)
        case["priorities"].add("P0")
        case["states"].add("source_material_absent")
        case["blockers"].add("required_terminal_bytes_absent")
        case["gap_types"].update(
            _gap_types(["required_terminal_bytes_absent"], source_absent=True)
        )
        _add_evidence(
            case,
            source="curated_static_hard_inventory",
            path=path.relative_to(repository).as_posix(),
            locator=f"excluded_cases.hashes[{index}]",
            summary=reason,
        )
        counts["source_absent"] += 1
    return counts


def _merge_report_evidence(
    repository: Path,
    catalog: dict[str, Any],
    cases: dict[str, dict[str, Any]],
) -> int:
    found = 0
    for sha256, entry in sorted(catalog.items()):
        canonical = str(entry.get("canonical_path") or "")
        if not canonical:
            continue
        report_path = repository / canonical / "report.json"
        if not report_path.is_file():
            continue
        try:
            report = _load_json(report_path)
        except (OSError, ValueError, json.JSONDecodeError):
            continue
        blockers = [str(value) for value in report.get("case_state", {}).get("blockers", [])]
        terminal = report.get("classification", {}).get("terminal_family_confirmed")
        relevant = [value for value in blockers if _REPORT_BLOCKER_RE.search(value)]
        if terminal is not False and not relevant:
            continue
        normalized = _normalize_sha256(sha256, locator=canonical)
        case = _case_for(cases, catalog, normalized)
        case["priorities"].add("P0" if terminal is False else "P1")
        case["states"].add("explicit_unrecovered")
        case["blockers"].update(relevant or ["terminal_family_not_confirmed"])
        case["gap_types"].update(
            _gap_types(relevant or ["terminal_family_not_confirmed"])
        )
        _add_evidence(
            case,
            source="structured_case_report",
            path=report_path.relative_to(repository).as_posix(),
            locator="classification.terminal_family_confirmed / case_state.blockers",
            summary=", ".join(relevant or ["terminal_family_confirmed=false"]),
        )
        found += 1
    return found


def _line_is_explicit_gap(line: str) -> bool:
    for segment in re.split(r"[。！？\r\n]+", line):
        if _POSITIVE_COMPLETION_RE.search(segment):
            continue
        if _NEGATIVE_RE.search(segment) and _PAYLOAD_OBJECT_RE.search(segment):
            return True
    return False


def _structured_terminal_completions(
    repository: Path, catalog: dict[str, Any]
) -> set[str]:
    resolved: set[str] = set()
    for sha256, entry in sorted(catalog.items()):
        canonical = str(entry.get("canonical_path") or "")
        report_path = repository / canonical / "report.json"
        if not canonical or not report_path.is_file():
            continue
        try:
            report = _load_json(report_path)
        except (OSError, ValueError, json.JSONDecodeError):
            continue
        terminal = report.get("classification", {}).get("terminal_family_confirmed")
        case_state = report.get("case_state", {})
        case_complete = (
            case_state.get("complete") is True
            or case_state.get("status") == "complete"
        )
        manual = report.get("manual_deep_analysis")
        manual_terminal_closed = (
            isinstance(manual, dict)
            and manual.get("terminal_payload_gap") == "closed"
        )
        c2_terminal_recovered = False
        c2_path = report_path.parent / "c2-analysis.json"
        if c2_path.is_file():
            try:
                c2_document = _load_json(c2_path)
            except (OSError, ValueError, json.JSONDecodeError):
                c2_document = None
            c2_terminal = (
                c2_document.get("terminal_payload")
                if isinstance(c2_document, dict)
                else None
            )
            c2_terminal_recovered = (
                isinstance(c2_terminal, dict)
                and c2_terminal.get("reached") is True
                and c2_terminal.get("status")
                in {"recovered", "no_additional_payload_verified"}
            )
        if terminal is True and (
            case_complete or manual_terminal_closed or c2_terminal_recovered
        ):
            resolved.add(_normalize_sha256(sha256, locator=canonical))
    return resolved


def _merge_document_evidence(
    repository: Path,
    catalog: dict[str, Any],
    cases: dict[str, dict[str, Any]],
) -> int:
    found_cases: set[str] = set()
    for sha256, entry in sorted(catalog.items()):
        canonical = str(entry.get("canonical_path") or "")
        if not canonical or "/malware/" not in f"/{canonical.replace(chr(92), '/')}/":
            continue
        case_dir = repository / canonical
        if not case_dir.is_dir():
            continue
        for name in _SAFE_EVIDENCE_FILES:
            path = case_dir / name
            if not path.is_file() or name == "report.json":
                continue
            try:
                lines = path.read_text(
                    encoding="utf-8-sig", errors="replace"
                ).splitlines()
            except OSError:
                continue
            for line_number, line in enumerate(lines, start=1):
                compact = " ".join(line.split())
                if not _line_is_explicit_gap(compact):
                    continue
                normalized = _normalize_sha256(sha256, locator=canonical)
                case = _case_for(cases, catalog, normalized)
                case["priorities"].add("P1")
                case["states"].add("explicit_unrecovered")
                case["blockers"].add("human_documented_terminal_gap")
                case["gap_types"].update(_gap_types([compact]))
                _add_evidence(
                    case,
                    source="human_readable_case_document",
                    path=path.relative_to(repository).as_posix(),
                    locator=f"line:{line_number}",
                    summary=compact,
                )
                found_cases.add(normalized)
                break
    return len(found_cases)


def _finalize_case(repository: Path, case: dict[str, Any]) -> dict[str, Any]:
    canonical = case["canonical_path"]
    case_dir = repository / canonical if canonical else None
    observation = _observation_date(case_dir) if case_dir and case_dir.is_dir() else None
    priorities = [value for value in case["priorities"] if value in _PRIORITY_RANK]
    priority = min(priorities, key=_PRIORITY_RANK.get) if priorities else "P2"
    states = set(case["states"])
    if "source_material_absent" in states:
        state = "source_material_absent"
    elif "explicit_unrecovered" in states:
        state = "explicit_unrecovered"
    else:
        state = "curated_recovery_backlog"
    evidence = sorted(
        case["evidence"].values(),
        key=lambda item: (item["path"], item["locator"], item["summary"]),
    )
    return {
        "sha256": case["sha256"],
        "family": case["family"],
        "version_key": case["version_key"],
        "canonical_path": canonical,
        "priority": priority,
        "state": state,
        "gap_types": sorted(case["gap_types"]),
        "blockers": sorted(case["blockers"]),
        "observation_date": observation,
        "requires_latest_sample": True,
        "evidence": evidence,
    }


def _family_rows(cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for case in cases:
        grouped.setdefault(case["family"], []).append(case)
    rows = []
    for family, members in grouped.items():
        priority = min((item["priority"] for item in members), key=_PRIORITY_RANK.get)
        dated = [item for item in members if item["observation_date"]]
        latest = max(dated, key=lambda item: (item["observation_date"], item["sha256"])) if dated else None
        blocker_counts = Counter(
            blocker for item in members for blocker in item["blockers"]
        )
        rows.append(
            {
                "family": family,
                "priority": priority,
                "case_count": len(members),
                "explicit_unrecovered_count": sum(
                    item["state"] == "explicit_unrecovered" for item in members
                ),
                "source_material_absent_count": sum(
                    item["state"] == "source_material_absent" for item in members
                ),
                "latest_local_observation": latest["observation_date"] if latest else None,
                "latest_local_sha256": latest["sha256"] if latest else None,
                "top_blockers": [
                    value for value, _ in blocker_counts.most_common(5)
                ],
                "malwarebazaar_signature_candidates": _SIGNATURE_CANDIDATES.get(
                    family, []
                ),
                "selection_policy": {
                    "order": "first_seen_desc",
                    "exclude_existing_sha256": True,
                    "prefer_full_delivery_chain": True,
                    "prefer_sandbox_with_memory_or_dumped_artifacts": True,
                    "leaf_only_sample_is_fallback": True,
                },
            }
        )
    return sorted(
        rows,
        key=lambda item: (
            _PRIORITY_RANK[item["priority"]],
            -item["source_material_absent_count"],
            0 if item["malwarebazaar_signature_candidates"] else 1,
            -item["explicit_unrecovered_count"],
            -item["case_count"],
            item["family"],
        ),
    )


def build_inventory(repository: Path) -> dict[str, Any]:
    """過去成果物から終端ペイロード未取得ケースとfamily優先表を構築する。"""

    root = repository.resolve()
    catalog_path = root / "analysis-results" / "catalog" / "cases.json"
    catalog_document = _load_json(catalog_path)
    if not isinstance(catalog_document, dict):
        raise TypeError("analysis-results/catalog/cases.jsonはobjectである必要があります")
    catalog = catalog_document.get("cases", catalog_document)
    if not isinstance(catalog, dict):
        raise TypeError("analysis-results/catalog/cases.jsonのcasesはobjectである必要があります")
    cases: dict[str, dict[str, Any]] = {}
    curated = _merge_curated_inventory(root, catalog, cases)
    report_count = _merge_report_evidence(root, catalog, cases)
    document_count = _merge_document_evidence(root, catalog, cases)
    resolved = _structured_terminal_completions(root, catalog)
    for sha256 in resolved:
        cases.pop(sha256, None)
    finalized = [_finalize_case(root, case) for case in cases.values()]
    finalized.sort(key=lambda item: item["observation_date"] or "", reverse=True)
    finalized.sort(
        key=lambda item: (
            _PRIORITY_RANK[item["priority"]], item["family"], item["sha256"]
        )
    )
    state_counts = Counter(item["state"] for item in finalized)
    return {
        "schema_version": 1,
        "scope": {
            "catalog_case_count": len(catalog),
            "gap_case_count": len(finalized),
            "family_count": len({item["family"] for item in finalized}),
            "curated_active_count": curated["active"],
            "curated_source_absent_count": curated["source_absent"],
            "structured_report_match_count": report_count,
            "human_document_match_count": document_count,
            "structured_terminal_completion_count": len(resolved),
            "state_counts": dict(sorted(state_counts.items())),
        },
        "source_paths": [
            "analysis-framework/inventories/static-hard-cases.yaml",
            "analysis-results/catalog/cases.json",
            "analysis-results/malware/*/versions/*/cases/*/report.json",
            "analysis-results/malware/*/versions/*/cases/*/{README,FEATURES,OVERALL-LOGIC,STATIC-LOGIC,metadata,config,submission-analysis}",
        ],
        "safety": {
            "sample_executed": False,
            "network_contacted": False,
            "sample_downloaded": False,
            "raw_artifacts_written": False,
        },
        "families": _family_rows(finalized),
        "cases": finalized,
    }


def _code(value: Any) -> str:
    tick = chr(96)
    return f"{tick}{value}{tick}"


def _render_readme(inventory: dict[str, Any]) -> str:
    scope = inventory["scope"]
    states = scope["state_counts"]
    lines = [
        "# 終端ペイロード未取得ケースと最新版取得優先表",
        "",
        "## 結論",
        "",
        f"過去の{scope['catalog_case_count']:,}ケースを対象に、精査済み難解析台帳、構造化レポート、人が読めるケース文書を統合し、終端ペイロードまたは終端ファミリーの確認まで到達していない{scope['gap_case_count']:,}ケース／{scope['family_count']:,}ファミリーを抽出しました。",
        "",
        "単なる解析状態の" + _code("partial") + "は対象にしていません。精査済み難解析台帳に登録済みであるか、終端payload・本体・family・assemblyなどの未取得が現在の成果物に明記されている場合だけを収録します。最終C2だけが未回収で、終端本体を確認済みのケースはこの台帳へ自動追加しません。",
        "",
        "| 状態 | 件数 | 意味 |",
        "|---|---:|---|",
        f"| 明示的未取得 | {states.get('explicit_unrecovered', 0):,} | 現在のreportまたはケース文書が終端未取得を明記 |",
        f"| 継続復元backlog | {states.get('curated_recovery_backlog', 0):,} | 精査済み難解析台帳に残る復元課題。最新成果物で再確認が必要 |",
        f"| 必要byte不在 | {states.get('source_material_absent', 0):,} | 提出物に終端byteがなく、同じ検体の静的処理だけでは復元不能 |",
        "",
        "全ケースは[ケース一覧](CASES.md)、表計算向けには[inventory.csv](inventory.csv)、根拠を含む機械可読正本は[inventory.json](inventory.json)を参照してください。",
        "",
        "## ファミリー別優先順位",
        "",
        "P0から順に、MalwareBazaar等でfirst seenが新しい検体を実行時に照会します。ここに書かれた『最新版』を固定hashとして保持せず、取得時点で既存SHA-256を除外して選び直します。DLL単体より、親archive、sidecar、decoy、設定blobを含む完全な配布chainを優先します。",
        "",
        "| 優先度 | ファミリー | 未取得ケース | 明示的未取得 | byte不在 | ローカル最新観測 | MalwareBazaar署名候補 |",
        "|---|---|---:|---:|---:|---|---|",
    ]
    for family in inventory["families"]:
        signatures = ", ".join(
            _code(value) for value in family["malwarebazaar_signature_candidates"]
        ) or "要OSINT確認"
        lines.append(
            f"| {family['priority']} | {_code(family['family'])} | {family['case_count']} | "
            f"{family['explicit_unrecovered_count']} | {family['source_material_absent_count']} | "
            f"{family['latest_local_observation'] or '不明'} | {signatures} |"
        )
    lines.extend(
        [
            "",
            "## 次回以降の取得・解析フロー",
            "",
            "```mermaid",
            "flowchart TD",
            '    A["本台帳を再生成"] --> B["P0からfamilyを選択"]',
            '    B --> C["取得時点の最新版を照会<br/>既存SHA-256を除外"]',
            '    C --> D{"完全な配布chainがあるか"}',
            '    D -->|"ある"| E["親archive・sidecar・子artifactを認証"]',
            '    D -->|"ない"| F["Triage等のexact sample<br/>dump・memory・relationを探索"]',
            '    E --> G["上限付き静的layer解析"]',
            '    F --> G',
            '    G --> H{"終端artifactをhash化できたか"}',
            '    H -->|"いいえ"| I["blockerと次の最小手順を更新"]',
            '    H -->|"はい"| J["終端family・version・config・C2を解析"]',
            '    J --> K["親子関係と全SHA-256を記録"]',
            '    K --> L["台帳を再生成しgapを閉じる"]',
            "```",
            "",
            "1. " + _code("build_terminal_payload_gap_inventory.py --check") + "で台帳同期を確認します。",
            "2. P0の先頭familyから、取得時点で最も新しいWindows検体を照会します。signatureは外部サービスの表記変更があるため候補として扱い、tag・完全一致hash・relationでも確認します。",
            "3. leaf DLL／loaderだけでなく、親archive、sidecar、resource、download script、公開sandboxのdump・memory artifactを探します。必要byte不在ケースでは、同じrootの解析を繰り返さず、新しい完全配布物を優先します。",
            "4. ローカルでは検体を実行しません。静的復元で足りない場合は、公開sandboxの既存実行からexact sampleのdump・memoryを取得するか、別途承認された隔離環境の結果を入力にします。",
            "5. 復元した各layerにSHA-256、親SHA-256、復元方法、取得日時、実行有無を付け、通常の静的解析pipelineへ再帰投入します。復元binary自体は公開成果物へ保存しません。",
            "6. 終端artifact、family、version、config、C2を確認するか、追加stageが存在しないことを静的に説明できた時だけgapを閉じます。外層の解析完了や" + _code("partial") + "解除だけでは閉じません。",
            "",
            "## MalwareBazaar選定例",
            "",
            "最初はdownloadせず" + _code("--selection-only") + "で候補と既存hashの重複を確認します。保存先はリポジトリ外のアクセス制限領域とします。",
            "",
            "```powershell",
            "py -3.13 .\\analysis-framework\\common\\malwarebazaar_batch.py --signature <署名候補> --selection-only --limit 10 --exclude-manifest <既存manifest> --root <非公開隔離領域>",
            "```",
            "",
            "## 安全性と解釈",
            "",
            "この生成処理は成果物の読み取りだけを行い、検体取得、検体実行、C2接続、外部通信を行いません。P0は脅威度ではなく、終端解析を進めるための取得優先度です。ファミリー名は既存catalogの帰属であり、未復元の終端familyを新たに断定するものではありません。",
            "",
            "## 更新",
            "",
            "```powershell",
            "py -3.13 .\\analysis-framework\\common\\build_terminal_payload_gap_inventory.py --repository . --write",
            "py -3.13 .\\analysis-framework\\common\\build_terminal_payload_gap_inventory.py --repository . --check",
            "```",
            "",
        ]
    )
    return "\n".join(lines)


def _render_cases(inventory: dict[str, Any]) -> str:
    lines = [
        "# 終端ペイロード未取得ケース一覧",
        "",
        "状態は自動生成時点の証拠を示します。継続復元backlogは古い記録を含むため、解決済みなら終端artifactのSHA-256と親子関係をケース成果物へ追加してから台帳を再生成します。",
        "",
        "| 優先度 | ファミリー | SHA-256 | 状態 | 観測日 | 主な未解決種別 | 根拠 |",
        "|---|---|---|---|---|---|---|",
    ]
    labels = {
        "explicit_unrecovered": "明示的未取得",
        "curated_recovery_backlog": "継続復元backlog",
        "source_material_absent": "必要byte不在",
    }
    for case in inventory["cases"]:
        evidence = case["evidence"][0] if case["evidence"] else None
        if case["canonical_path"]:
            case_target = Path("..", "..", case["canonical_path"]).as_posix() + "/"
            case_link = f"[{case['sha256']}]({case_target})"
        else:
            case_link = _code(case["sha256"])
        if evidence:
            link = f"[{evidence['path']}]({Path('..', '..', evidence['path']).as_posix()})"
        else:
            link = "なし"
        gaps = ", ".join(_code(value) for value in case["gap_types"])
        lines.append(
            f"| {case['priority']} | {_code(case['family'])} | {case_link} | "
            f"{labels[case['state']]} | {case['observation_date'] or '不明'} | {gaps} | {link} |"
        )
    lines.append("")
    return "\n".join(lines)


def _render_csv(cases: list[dict[str, Any]]) -> str:
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(
        [
            "優先度",
            "ファミリー",
            "SHA-256",
            "版",
            "状態",
            "観測日",
            "未解決種別",
            "blocker",
            "ケースパス",
            "根拠ファイル",
        ]
    )
    for case in cases:
        writer.writerow(
            [
                case["priority"],
                case["family"],
                case["sha256"],
                case["version_key"],
                case["state"],
                case["observation_date"] or "",
                ";".join(case["gap_types"]),
                ";".join(case["blockers"]),
                case["canonical_path"],
                ";".join(item["path"] for item in case["evidence"]),
            ]
        )
    return buffer.getvalue()


def render_outputs(inventory: dict[str, Any]) -> dict[str, str]:
    """台帳JSONから日本語README、全ケース表、CSV、JSONを描画する。"""

    return {
        "README.md": _render_readme(inventory),
        "CASES.md": _render_cases(inventory),
        "inventory.csv": _render_csv(inventory["cases"]),
        "inventory.json": json.dumps(
            inventory, ensure_ascii=False, indent=2, sort_keys=True
        )
        + "\n",
    }


def sync_outputs(
    repository: Path, output_dir: Path, *, write: bool = False
) -> dict[str, Any]:
    """期待される生成物との差分を返し、指定時だけ原子的に更新する。"""

    root = repository.resolve()
    target = output_dir if output_dir.is_absolute() else root / output_dir
    inventory = build_inventory(root)
    outputs = render_outputs(inventory)
    mismatches = []
    for name, content in outputs.items():
        path = target / name
        current = path.read_text(encoding="utf-8-sig") if path.is_file() else None
        if current == content:
            continue
        mismatches.append(path.relative_to(root).as_posix())
        if write:
            _atomic_text_write(path, content)
    return {
        "output_dir": target.relative_to(root).as_posix(),
        "mismatches": mismatches,
        "write_performed": bool(write and mismatches),
        "scope": inventory["scope"],
    }


def main(argv: list[str] | None = None) -> int:
    """CLI引数を処理し、生成・同期確認の終了コードを返す。"""

    parser = argparse.ArgumentParser(
        description="過去成果物から終端ペイロード未取得台帳を生成する。"
    )
    parser.add_argument("--repository", type=Path, default=Path("."))
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("intelligence/terminal-payload-recovery"),
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--write", action="store_true", help="生成物を更新する")
    mode.add_argument("--check", action="store_true", help="不一致時に終了コード1を返す")
    args = parser.parse_args(argv)
    result = sync_outputs(args.repository, args.output_dir, write=args.write)
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 1 if args.check and result["mismatches"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
