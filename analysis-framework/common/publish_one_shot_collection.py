#!/usr/bin/env python3
"""MalwareBazaarワンショット静的解析を正規caseとcollectionへ公開する。"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import re
import sys
from typing import Any

COMMON = Path(__file__).resolve().parent
REPOSITORY = COMMON.parents[1]
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

from case_features import build_case_profile, render_features_markdown  # noqa: E402
from result_layout import canonical_malware_case_path  # noqa: E402
from result_publication import (  # noqa: E402
    detect_publication_context,
    register_publication_cases,
)
from static_logic import render_static_logic_markdown  # noqa: E402

SHA256_RE = re.compile(r"[0-9a-f]{64}")
COLLECTION_RE = re.compile(r"[a-z0-9][a-z0-9-]{2,79}")

# MalwareBazaarの報告名を、既にリポジトリで管理しているIDだけへ対応させる。
REPORTED_FAMILY_ALIASES = {
    "acrstealer": "acrstealer",
    "agenttesla": "agenttesla",
    "efimer": "efimer",
    "formbook": "formbook",
    "guloader": "guloader",
    "hijackloader": "hijackloader",
    "maskgramstealer": "maskgram-stealer",
    "prometei": "prometei",
    "remcosrat": "remcosrat",
    "remusstealer": "remusstealer",
    "snakekeylogger": "snakekeylogger",
    "vidar": "vidar",
    "wannacry": "wannacry",
}
PUBLIC_METADATA_KEYS = (
    "sha256_hash",
    "sha1_hash",
    "md5_hash",
    "first_seen",
    "last_seen",
    "file_name",
    "file_size",
    "file_type",
    "file_format",
    "file_arch",
    "imphash",
    "tlsh",
    "ssdeep",
    "signature",
    "tags",
)


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON objectが必要です: {path}")
    return value


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def normalize_reported_name(value: object) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value or "").casefold())


def choose_family(
    metadata: dict[str, Any], report: dict[str, Any], existing_families: set[str]
) -> tuple[str, str]:
    """内部高確度判定、提供元signature、直接tagの順で保守的に分類する。"""

    classification = report.get("classification") or {}
    selected = str(classification.get("selected_family") or "").casefold()
    selection_basis = str(classification.get("selection_basis") or "")
    if selected in existing_families and selection_basis != "explicit_operator_selection":
        return selected, "one_shot_static_detector"

    signature = normalize_reported_name(metadata.get("signature"))
    mapped = REPORTED_FAMILY_ALIASES.get(signature)
    if mapped in existing_families:
        return mapped, "malwarebazaar_reported_signature"
    if signature:
        return "unclassified", "unsupported_reported_signature"

    tags = {
        normalize_reported_name(value)
        for value in (metadata.get("tags") or [])
        if not str(value).casefold().startswith("dropped-by-")
    }
    mapped_tags = {
        REPORTED_FAMILY_ALIASES[tag]
        for tag in tags
        if tag in REPORTED_FAMILY_ALIASES
        and REPORTED_FAMILY_ALIASES[tag] in existing_families
    }
    if len(mapped_tags) == 1:
        return mapped_tags.pop(), "malwarebazaar_direct_tag"
    return "unclassified", "no_supported_family_evidence"


def safe_metadata(item: dict[str, Any]) -> dict[str, Any]:
    metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
    return {key: metadata.get(key) for key in PUBLIC_METADATA_KEYS}


def pe_summary(generic: dict[str, Any]) -> dict[str, Any]:
    pe = generic.get("pe") if isinstance(generic.get("pe"), dict) else {}
    sections = pe.get("sections") if isinstance(pe.get("sections"), list) else []
    imports = pe.get("imports") if isinstance(pe.get("imports"), dict) else {}
    imported_names = sorted(
        {
            str(name)
            for values in imports.values()
            if isinstance(values, list)
            for name in values
        }
    )
    return {
        "type": generic.get("type"),
        "size": generic.get("size"),
        "entropy": generic.get("entropy"),
        "machine": pe.get("machine"),
        "timestamp": pe.get("timestamp"),
        "entry_point_rva": pe.get("entry_point_rva"),
        "imphash": pe.get("imphash"),
        "is_dotnet": pe.get("is_dotnet"),
        "section_count": len(sections),
        "sections": sections,
        "import_library_count": len(imports),
        "import_count": len(imported_names),
        "imports": imports,
    }


def capability_notes(pe: dict[str, Any]) -> list[dict[str, str]]:
    names = {
        str(name).casefold()
        for values in (pe.get("imports") or {}).values()
        if isinstance(values, list)
        for name in values
    }
    checks = (
        ("process_creation", {"createprocessa", "createprocessw", "shellexecutea", "shellexecutew"}, "プロセス起動APIのimportを確認"),
        ("process_injection", {"virtualallocex", "writeprocessmemory", "createremotethread"}, "別プロセス操作に使われ得るAPIのimportを確認"),
        ("network_access", {"internetopena", "internetopenw", "internetconnecta", "internetconnectw", "wsaconnect", "connect", "urldownloadtofilea", "urldownloadtofilew"}, "ネットワーク接続・取得APIのimportを確認"),
        ("registry_access", {"regsetvalueexa", "regsetvalueexw", "regcreatekeyexa", "regcreatekeyexw"}, "Registry更新APIのimportを確認"),
        ("anti_debug", {"isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess"}, "デバッガ確認に使われ得るAPIのimportを確認"),
        ("cryptography", {"cryptdecrypt", "cryptencrypt", "bcryptdecrypt", "bcryptencrypt"}, "暗号処理APIのimportを確認"),
    )
    notes = []
    for capability, markers, description in checks:
        hits = sorted(names & markers)
        if hits:
            notes.append({"capability": capability, "basis": description, "imports": ", ".join(hits)})
    return notes


def render_iocs(digest: str) -> str:
    return "\n".join(
        [
            "# IOC 一覧",
            "",
            "| 種別 (Type) | 値 (Value) | 役割 (Role) | 確度 (Confidence) | 根拠 (Source) |",
            "|---|---|---|---|---|",
            f"| SHA-256 | {digest} | 提出検体 | 確認済み | MalwareBazaar取得検体 |",
            "",
            "汎用文字列走査だけで得たURL、domain、IPは誤検知を含み得るため、C2へ昇格していません。",
            "設定構造またはファミリー固有処理で裏付けられたC2は、本ケースの追加レビュー対象です。",
            "",
        ]
    )


def render_readme(
    digest: str,
    family: str,
    attribution_basis: str,
    metadata: dict[str, Any],
    pe: dict[str, Any],
    capabilities: list[dict[str, str]],
    logic: dict[str, Any],
    handler_count: int,
) -> str:
    signature = metadata.get("signature") or "未報告"
    tags = ", ".join(str(value) for value in (metadata.get("tags") or [])) or "なし"
    lines = [
        f"# Windows検体ケース {digest}",
        "",
        "## 概要",
        "",
        f"- 正規分類: `{family}`",
        f"- 分類根拠: `{attribution_basis}`",
        f"- MalwareBazaar報告signature: `{signature}`",
        f"- MalwareBazaarタグ: `{tags}`",
        f"- 初回観測: `{metadata.get('first_seen') or '不明'}`",
        f"- 元ファイル名: `{metadata.get('file_name') or '不明'}`",
        f"- SHA-256: `{digest}`",
        f"- 形式: `{pe.get('type') or metadata.get('file_type') or '不明'}`",
        f"- サイズ: `{pe.get('size') or metadata.get('file_size') or '不明'}` bytes",
        f"- entropy: `{pe.get('entropy') if pe.get('entropy') is not None else '不明'}`",
        f"- .NET: `{pe.get('is_dotnet') if pe.get('is_dotnet') is not None else '不明'}`",
        f"- section数: `{pe.get('section_count')}`",
        f"- import DLL数／関数数: `{pe.get('import_library_count')}`／`{pe.get('import_count')}`",
        f"- ファミリー固有handler成功数: `{handler_count}`",
        f"- 静的ロジック状態: `{logic.get('status')}`",
        "- 検体実行: `false`",
        "- 外部接続: `false`",
        "",
        "## 静的な処理能力の手掛かり",
        "",
    ]
    if capabilities:
        for item in capabilities:
            lines.append(
                f"- `{item['capability']}`: {item['basis']}（`{item['imports']}`）。importだけでは実行経路を確定しません。"
            )
    else:
        lines.append("- import相関だけでは特徴的な処理能力を確定できませんでした。")
    lines.extend(
        [
            "",
            "## 静的ロジック",
            "",
            "関数境界・call graph・逆コンパイルが未記録のbinaryは`function_analysis_required`のままです。詳細は[STATIC-LOGIC.md](STATIC-LOGIC.md)を参照してください。",
            "",
            "## C2評価",
            "",
            "汎用文字列走査の候補をC2として採用していません。ファミリー固有設定で裏付けられない限り、現在のC2、所有者、到達性は未確認です。",
            "",
            "## 関連成果物",
            "",
            "- [正規化解析データ](analysis.json)",
            "- [検体特徴](FEATURES.md)",
            "- [静的ロジック](STATIC-LOGIC.md)",
            "- [IOC一覧](IOC-LIST.md)",
            "- [適用可否判定](applicability.json)",
            "- [静的レイヤー](static-layers.json)",
            "",
            "## 制約",
            "",
            "- 検体、復元層、埋め込みpayloadを実行していません。",
            "- C2、配布先、dead-drop resolverへ接続していません。",
            "- MalwareBazaarのsignature／tagは提供元報告として保持し、内部の静的根拠と区別しています。",
            "",
        ]
    )
    return "\n".join(lines)


def publish_case(
    repository: Path,
    results: Path,
    collection_id: str,
    source: Path,
    item: dict[str, Any],
    existing_families: set[str],
) -> tuple[str, Path, dict[str, Any]]:
    digest = str(item.get("sha256") or "").casefold()
    if not SHA256_RE.fullmatch(digest):
        raise ValueError(f"不正なSHA-256: {digest}")
    report = load_json(source / "report.json")
    if (report.get("sample") or {}).get("sha256") != digest:
        raise ValueError(f"reportのSHA-256不一致: {digest}")
    if report.get("executed_sample") is not False or report.get("network_contacted") is not False:
        raise ValueError(f"安全フラグ不一致: {digest}")
    metadata = safe_metadata(item)
    family, attribution_basis = choose_family(metadata, report, existing_families)
    destination = canonical_malware_case_path(results, family, digest, "unknown")
    destination.mkdir(parents=True, exist_ok=True)

    documents = {}
    for name in (
        "report.json",
        "classification.json",
        "applicability.json",
        "generic-triage.json",
        "static-layers.json",
        "campaign-labels.json",
    ):
        documents[name] = load_json(source / name)
        write_json(destination / name, documents[name])
    handler_results = []
    for execution in report.get("handler_executions") or []:
        relative = execution.get("result") if isinstance(execution, dict) else None
        if execution.get("status") == "succeeded" and isinstance(relative, str):
            handler_results.append(load_json(source / relative))
    write_json(destination / "handler-results.json", {"schema_version": 1, "results": handler_results})

    logic = load_json(source / "static-logic.json")
    logic["family"] = family
    write_json(destination / "static-logic.json", logic)
    (destination / "STATIC-LOGIC.md").write_text(
        render_static_logic_markdown(logic), encoding="utf-8"
    )
    generic = documents["generic-triage.json"]
    pe = pe_summary(generic)
    capabilities = capability_notes(pe)
    version = {
        "status": "unknown",
        "reported": None,
        "normalized_key": "unknown",
        "confidence": "none",
        "reason": "no_approved_sample_specific_version_evidence",
        "evidence": [],
    }
    canonical_path = destination.relative_to(repository).as_posix()
    metadata_document = {
        "schema_version": 1,
        "sha256": digest,
        "case_id": f"sha256:{digest}",
        "case_kind": "malware",
        "family": family,
        "canonical_path": canonical_path,
        "collections": [collection_id],
        "malware_version": version,
        "source": {
            "provider": "MalwareBazaar Community API",
            "sample_url": f"https://bazaar.abuse.ch/sample/{digest}/",
            "reported_metadata": metadata,
        },
        "attribution": {
            "basis": attribution_basis,
            "reported_signature": metadata.get("signature"),
            "reported_tags": metadata.get("tags") or [],
        },
        "safety": {"sample_executed": False, "network_contacted": False},
    }
    write_json(destination / "metadata.json", metadata_document)
    analysis = {
        "schema_version": 1,
        "case": {
            "sha256": digest,
            "family": family,
            "version": "unknown",
            "format": pe.get("type") or metadata.get("file_type") or "unknown",
            "packing_suspected": bool((pe.get("entropy") or 0) >= 7.2),
            "unpack_status": "bounded_static_layers_recorded",
            "recovered_artifacts": max(
                0,
                int((documents["static-layers.json"].get("counts") or {}).get("recovered_layers") or 0),
            ),
            "static_config_recovered": any(
                bool((value.get("result") or {}).get("config", {}).get("static_config_recovered"))
                for value in handler_results
                if isinstance(value, dict)
            ),
            "declarative_status": "function_review_required" if logic.get("status") == "function_analysis_required" else "ready",
            "sample_executed": False,
            "network_contacted": False,
        },
        "source_attribution": metadata_document["attribution"],
        "pe_static_summary": pe,
        "capability_hints": capabilities,
        "artifacts": {
            "report": "report.json",
            "classification": "classification.json",
            "applicability": "applicability.json",
            "generic_triage": "generic-triage.json",
            "static_layers": "static-layers.json",
            "handler_results": "handler-results.json",
            "static_logic": "static-logic.json",
        },
        "limitations": [
            "検体と復元層は実行していない。",
            "汎用文字列候補をC2として採用していない。",
            "関数本体未レビューのbinaryは完了扱いにしていない。",
        ],
    }
    write_json(destination / "analysis.json", analysis)
    write_json(
        destination / "iocs.json",
        {
            "schema_version": 1,
            "sha256": [digest],
            "network": [],
            "assessment": "汎用文字列候補はC2へ昇格していない",
            "sample_executed": False,
            "network_contacted": False,
        },
    )
    (destination / "IOC-LIST.md").write_text(render_iocs(digest), encoding="utf-8")
    (destination / "README.md").write_text(
        render_readme(
            digest,
            family,
            attribution_basis,
            metadata,
            pe,
            capabilities,
            logic,
            len(handler_results),
        ),
        encoding="utf-8",
    )
    profile = build_case_profile(destination)
    profile["family"] = family
    write_json(destination / "features.json", profile)
    (destination / "FEATURES.md").write_text(
        render_features_markdown(profile), encoding="utf-8"
    )
    summary = {
        "sha256": digest,
        "family": family,
        "attribution_basis": attribution_basis,
        "reported_signature": metadata.get("signature"),
        "first_seen": metadata.get("first_seen"),
        "file_type": metadata.get("file_type"),
        "static_logic_status": logic.get("status"),
        "handler_successes": len(handler_results),
        "handler_failures": sum(
            isinstance(value, dict)
            and value.get("status") in {"failed", "preflight_failed"}
            for value in (report.get("handler_executions") or [])
        ),
        "static_config_recovered": analysis["case"]["static_config_recovered"],
        "case_path": canonical_path,
    }
    return family, destination, summary


def initialize_collection(
    results: Path, collection_id: str, manifest: dict[str, Any]
) -> Path:
    root = results / "collections" / collection_id
    public_items = []
    for item in manifest.get("items") or []:
        public_items.append(
            {
                "sha256": item.get("sha256"),
                "zip_sha256": item.get("zip_sha256"),
                "zip_size": item.get("zip_size"),
                "metadata": safe_metadata(item),
            }
        )
    document = {
        "schema_version": 1,
        "collection_id": collection_id,
        "source": "MalwareBazaar Community API",
        "selection_mode": manifest.get("selection_mode"),
        "file_types": manifest.get("file_types"),
        "query_limit": manifest.get("query_limit"),
        "selected_at": manifest.get("selected_at"),
        "requested": manifest.get("requested"),
        "downloaded": manifest.get("downloaded"),
        "pending": manifest.get("pending"),
        "complete": manifest.get("complete"),
        "first_seen_newest": (manifest.get("selected_metadata") or [{}])[0].get("first_seen"),
        "first_seen_oldest": (manifest.get("selected_metadata") or [{}])[-1].get("first_seen"),
        "cases": [],
        "family_sources": [],
        "acquisition_items": public_items,
        "samples_executed": False,
        "network_contacted": False,
        "archives_stored_in_repository": False,
    }
    write_json(root / "manifest.json", document)
    return root


def find_case_source(one_shots: list[Path], digest: str) -> Path:
    """分割run群から完了caseを返し、明示familyの追加解析を優先する。"""
    matches = [
        root / "cases" / digest
        for root in one_shots
        if (root / "cases" / digest / "report.json").is_file()
    ]
    if len(matches) == 1:
        return matches[0]
    explicit = []
    for match in matches:
        report = load_json(match / "report.json")
        if (report.get("classification") or {}).get("selection_basis") == "explicit_operator_selection":
            explicit.append(match)
    if len(explicit) == 1:
        return explicit[0]
    raise ValueError(
        f"完了case sourceまたは明示family追加解析は1件必要です: {digest} "
        f"(全{len(matches)}件、明示{len(explicit)}件)"
    )


def publish(
    repository: Path,
    manifest_path: Path,
    one_shots: list[Path],
    collection_id: str,
) -> dict[str, Any]:
    if not COLLECTION_RE.fullmatch(collection_id):
        raise ValueError("collection IDは小文字英数とhyphenだけで指定してください")
    results = repository / "analysis-results"
    manifest = load_json(manifest_path)
    if manifest.get("complete") is not True or manifest.get("downloaded") != 100:
        raise ValueError("取得manifestが100件完了していません")
    collection = initialize_collection(results, collection_id, manifest)
    existing_families = {
        path.name for path in (results / "malware").iterdir() if path.is_dir()
    }
    existing_families.add("unclassified")
    by_family: dict[str, list[Path]] = defaultdict(list)
    summaries = []
    for item in manifest.get("items") or []:
        digest = str(item.get("sha256") or "").casefold()
        source = find_case_source(one_shots, digest)
        family, destination, summary = publish_case(
            repository, results, collection_id, source, item, existing_families
        )
        by_family[family].append(destination)
        summaries.append(summary)

    for family, case_paths in sorted(by_family.items()):
        aggregate = collection / "sources" / family
        aggregate.mkdir(parents=True, exist_ok=True)
        family_summaries = [item for item in summaries if item["family"] == family]
        write_json(
            aggregate / "summary.json",
            {
                "schema_version": 1,
                "family": family,
                "count": len(family_summaries),
                "cases": family_summaries,
                "sample_executed": False,
                "network_contacted": False,
            },
        )
        (aggregate / "README.md").write_text(
            "\n".join(
                [
                    f"# {family} 収録ケース",
                    "",
                    f"このcollectionでは{len(family_summaries)}件を収録しました。分類根拠と制約は各ケースを参照してください。",
                    "",
                    "- 検体実行: なし",
                    "- 外部接続: なし",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        context = detect_publication_context(aggregate, family)
        if context is None:
            raise ValueError(f"collection公開contextを解決できません: {family}")
        register_publication_cases(context, case_paths)

    counts = Counter(item["family"] for item in summaries)
    status_counts = Counter(item["static_logic_status"] for item in summaries)
    handler_successes = sum(item["handler_successes"] for item in summaries)
    handler_failures = sum(item["handler_failures"] for item in summaries)
    static_config_count = sum(bool(item["static_config_recovered"]) for item in summaries)
    lines = [
        "# MalwareBazaar 最新Windows検体100件（2026-07-23）",
        "",
        "MalwareBazaarのEXE／DLL照会を統合し、既解析SHA-256を除外して取得日時の新しい順に100件を固定しました。今回の固定集合はすべてEXEでした。暗号化ZIPはリポジトリ外に保持し、検体を実行せず静的解析しました。",
        "",
        f"- 対象期間: `{manifest['selected_metadata'][0].get('first_seen')}`〜`{manifest['selected_metadata'][-1].get('first_seen')}`",
        f"- 取得: `{manifest.get('downloaded')}/100`、pending `{manifest.get('pending')}`",
        "- 検体実行: なし",
        "- C2／配布先への接続: なし",
        "- 汎用文字列候補はC2へ昇格していない",
        f"- ファミリー固有handler成功結果: `{handler_successes}`",
        f"- handler失敗／事前確認失敗: `{handler_failures}`",
        f"- 静的設定回収: `{static_config_count}`",
        "",
        "## 分類内訳",
        "",
        "| 正規分類 | 件数 |",
        "|---|---:|",
    ]
    for family, count in sorted(counts.items(), key=lambda value: (-value[1], value[0])):
        lines.append(f"| [{family}](sources/{family}/README.md) | {count} |")
    lines.extend(
        [
            "",
            "## 静的ロジック状態",
            "",
            "| 状態 | 件数 |",
            "|---|---:|",
        ]
    )
    for status, count in sorted(status_counts.items()):
        lines.append(f"| `{status}` | {count} |")
    lines.extend(
        [
            "",
            "個別のPE構造、import由来能力、適用可否、復元層、静的ロジック、IOC評価は各正規ケースに記録しています。全件一覧は[manifest.json](manifest.json)を参照してください。",
            "",
        ]
    )
    (collection / "README.md").write_text("\n".join(lines), encoding="utf-8")
    write_json(collection / "publication-summary.json", {"schema_version": 1, "counts": dict(counts), "static_logic_status": dict(status_counts), "handler_successes": handler_successes, "handler_failures": handler_failures, "static_config_recovered": static_config_count, "cases": summaries, "samples_executed": False, "network_contacted": False})
    return {"published": len(summaries), "families": dict(counts), "collection": str(collection)}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=REPOSITORY)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--one-shot", required=True, action="append", type=Path)
    parser.add_argument("--collection-id", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result = publish(
        args.repository.resolve(),
        args.manifest.resolve(),
        [path.resolve() for path in args.one_shot],
        args.collection_id,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())