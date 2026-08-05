#!/usr/bin/env python3
"""日次IOCから取得した検体の静的解析結果を公開可能な形へ要約する。"""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

CAPABILITY_APIS = {
    "network_client": {"connect", "socket", "wsastartup", "wsaeventselect", "winhttpopen", "internetopen", "curl_easy_init"},
    "host_discovery": {"getusernamea", "getusernamew", "getcomputernamea", "getcomputernamew", "getcomputernameexw", "getadaptersaddresses", "gettimezoneinformation"},
    "file_enumeration": {"findfirstfilea", "findfirstfilew", "findfirstfileexw", "findnextfilea", "findnextfilew", "createfilea", "createfilew", "readfile"},
    "process_execution": {"createprocessa", "createprocessw", "createprocessasuserw", "createprocesswithtokenw", "shellexecutea", "shellexecutew", "winexec"},
    "process_inspection": {"createtoolhelp32snapshot", "process32first", "process32next", "openprocess", "getprocessmemoryinfo"},
    "screen_capture": {"bitblt", "stretchblt", "getdibits", "createcompatiblebitmap", "createcompatibledc"},
    "registry_change": {"regcreatekeyexa", "regcreatekeyexw", "regsetvalueexa", "regsetvalueexw", "regdeletevaluea", "regdeletevaluew"},
    "anti_analysis_surface": {"isdebuggerpresent", "outputdebugstringa", "outputdebugstringw", "addvectoredexceptionhandler", "setunhandledexceptionfilter", "getthreadcontext", "setthreadcontext"},
    "certificate_store_access": {"certopenstore", "certenumcertificatesinstore", "certfreecertificatecontext"},
}

CAPABILITY_JA = {
    "network_client": "socket/HTTPクライアント相当の通信機能",
    "host_discovery": "利用者・端末・NIC・時間帯の収集",
    "file_enumeration": "ファイル列挙と読み取り",
    "process_execution": "子プロセスまたは別トークンでのプロセス起動",
    "process_inspection": "プロセス列挙・参照",
    "screen_capture": "GDIによる画面取得",
    "registry_change": "レジストリ作成・更新・削除",
    "anti_analysis_surface": "デバッガ・例外・スレッドコンテキストに関係する処理",
    "certificate_store_access": "Windows証明書ストアの列挙",
}

HASH_IOC_TYPES = {"file_hash_sha1", "file_hash_sha256"}


def _imports(triage: dict[str, Any]) -> set[str]:
    output: set[str] = set()
    for functions in (triage.get("pe") or {}).get("imports", {}).values():
        output.update(str(function).lower() for function in functions)
    return output


def infer_capabilities(triage: dict[str, Any]) -> list[dict[str, Any]]:
    imports = _imports(triage)
    results = []
    for name, candidates in CAPABILITY_APIS.items():
        evidence = sorted(imports & candidates)
        if evidence:
            results.append({
                "id": name,
                "summary_ja": CAPABILITY_JA[name],
                "evidence_imports": evidence,
                "confidence": "import_surface_only",
            })
    return results


def _read_labels(ioc_csv: Path) -> dict[str, dict[str, str]]:
    with ioc_csv.open("r", encoding="utf-8-sig", newline="") as stream:
        rows = list(csv.DictReader(stream))
    return {
        str(row.get("ioc_value") or "").lower(): row
        for row in rows
        if row.get("ioc_type") in HASH_IOC_TYPES and row.get("ioc_value")
    }


def _provider_aliases(path: Path | None, labels: dict[str, dict[str, str]]) -> dict[str, dict[str, str]]:
    aliases: dict[str, dict[str, str]] = {}
    if path is None or not path.is_file():
        return aliases
    payload = json.loads(path.read_text(encoding="utf-8"))
    for item in payload.get("items", []):
        metadata = item.get("metadata") or {}
        query = str(item.get("digest") or item.get("sha256") or item.get("sha1") or "").lower()
        source = labels.get(query, {})
        if not source and item.get("reported_malware"):
            source = {
                "malware": str(item["reported_malware"]),
                "malware_type": "provider_lookup",
                "ioc_value": query,
            }
        for value in (
            item.get("sha256"), item.get("sha1"),
            metadata.get("sha256_hash"), metadata.get("sha1_hash"),
        ):
            if value and source:
                aliases[str(value).lower()] = source
    return aliases


def _architecture(triage: dict[str, Any]) -> dict[str, Any]:
    if triage.get("type") == "pe":
        pe = triage.get("pe") or {}
        return {"machine": pe.get("machine"), "entry_point": pe.get("entry_point_rva")}
    if triage.get("type") == "elf":
        elf = triage.get("elf") or {}
        return {
            "machine": elf.get("machine"),
            "bits": elf.get("bits"),
            "byte_order": elf.get("byte_order"),
            "entry_point": elf.get("entry_point"),
        }
    macho = triage.get("macho") or {}
    return {"machine": macho.get("cpu_type"), "entry_point": macho.get("entry_point")}


def _function_reviews(path: Path | None) -> dict[str, dict[str, Any]]:
    if path is None or not path.is_file():
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    return {
        str(item.get("sha256") or "").lower(): item
        for item in payload.get("samples", [])
        if item.get("sha256")
    }

def build_summary(
    case_root: Path,
    ioc_csv: Path,
    source_date: str,
    provider_lookups: Path | None = None,
    function_reviews: Path | None = None,
) -> dict[str, Any]:
    labels = _read_labels(ioc_csv)
    aliases = _provider_aliases(provider_lookups, labels)
    reviews = _function_reviews(function_reviews)
    samples: list[dict[str, Any]] = []
    clusters: dict[str, list[str]] = defaultdict(list)

    for case in sorted(path for path in case_root.iterdir() if path.is_dir()):
        triage_path = case / "generic-triage.json"
        logic_path = case / "static-logic.json"
        if not triage_path.is_file() or not logic_path.is_file():
            continue
        triage = json.loads(triage_path.read_text(encoding="utf-8"))
        static_logic = json.loads(logic_path.read_text(encoding="utf-8"))
        digest = str(triage.get("sha256") or case.name).lower()
        source = labels.get(digest) or aliases.get(digest, {})
        review = reviews.get(digest, {})
        reviewed_functions = review.get("functions") or []
        pe = triage.get("pe") or {}
        elf = triage.get("elf") or {}
        sample_type = str(triage.get("type") or "unknown")
        architecture = _architecture(triage)
        imphash = pe.get("imphash")
        telfhash = elf.get("telfhash")
        if imphash:
            cluster_key = f"imphash:{imphash}"
        elif telfhash:
            cluster_key = f"telfhash:{telfhash}"
        else:
            cluster_key = f"format:{sample_type}:{architecture.get('machine')}:{architecture.get('byte_order', '-') }"
        clusters[cluster_key].append(digest)

        sample: dict[str, Any] = {
            "sha256": digest,
            "reported_malware": source.get("malware") or "unknown",
            "reported_malware_type": source.get("malware_type") or "unknown",
            "source_hash": source.get("ioc_value"),
            "attribution_basis": "tech-memoのIOCラベルとプロバイダのハッシュ対応情報",
            "file_type": sample_type,
            "size": triage.get("size"),
            "entropy": triage.get("entropy"),
            "magic": triage.get("magic"),
            "architecture": architecture,
            "imphash": imphash,
            "telfhash": telfhash,
            "is_dotnet": pe.get("is_dotnet"),
            "capabilities": infer_capabilities(triage),
            "analysis_coverage": triage.get("analysis_coverage"),
            "static_logic_status": static_logic.get("status"),
            "function_count": max(static_logic.get("coverage", {}).get("function_count", 0), len(reviewed_functions)),
            "call_edge_count": static_logic.get("coverage", {}).get("call_edge_count", 0),
            "function_bodies_reviewed": bool(reviewed_functions) or static_logic.get("coverage", {}).get("function_bodies_reviewed", False),
            "reviewed_functions": reviewed_functions,
            "function_review_source": review.get("source"),
            "limitations": static_logic.get("limitations", []),
            "sample_executed": False,
            "network_contacted_by_sample": False,
        }
        if sample_type == "script":
            script = triage.get("script") or {}
            sample["script_indicators"] = script.get("indicators", {})
            sample["script_iocs"] = script.get("iocs", {})
            sample["functions"] = static_logic.get("functions", [])
            sample["call_edges"] = static_logic.get("call_edges", [])
        samples.append(sample)

    format_counts = Counter(item["file_type"] for item in samples)
    cluster_rows = []
    for key, members in sorted(clusters.items()):
        member_set = set(members)
        family_counts = Counter(
            item["reported_malware"] for item in samples if item["sha256"] in member_set
        )
        cluster_rows.append({
            "cluster_key": key,
            "member_count": len(members),
            "members": sorted(members),
            "reported_malware": dict(sorted(family_counts.items())),
            "assessment": (
                "同一の構造指標は類似性の手掛かりだが、同一ファミリまたは同一キャンペーンを単独では確定しない。"
                if not key.startswith("format:")
                else "形式・アーキテクチャだけの集合であり、コード類似性の根拠には使用しない。"
            ),
        })

    return {
        "schema_version": 2,
        "source_date": source_date,
        "sample_count": len(samples),
        "counts": {
            "formats": dict(sorted(format_counts.items())),
            "pe": format_counts["pe"],
            "elf": format_counts["elf"],
            "macho": format_counts["macho"],
            "script": format_counts["script"],
            "function_analysis_complete": sum(bool(item["function_bodies_reviewed"]) for item in samples),
            "script_structure_recorded": sum(item["static_logic_status"] == "automated_script_structure" for item in samples),
            "function_analysis_required": sum(item["static_logic_status"] == "function_analysis_required" and not item["function_bodies_reviewed"] for item in samples),
        },
        "samples": samples,
        "clusters": cluster_rows,
        "safety": {
            "sample_executed": False,
            "network_contacted_by_sample": False,
            "raw_sample_published": False,
            "raw_decompilation_published": False,
        },
    }


def render_markdown(summary: dict[str, Any]) -> str:
    counts = summary["counts"]
    format_text = "、".join(f"{name}: {count}件" for name, count in counts["formats"].items()) or "なし"
    lines = [
        f"# 取得検体の静的解析 — {summary['source_date']}", "",
        "## 解析範囲", "",
        f"- 取得・一次解析: {summary['sample_count']}件",
        f"- 形式別: {format_text}",
        f"- 関数本体レビュー済み: {counts['function_analysis_complete']}件",
        f"- 関数解析が必要: {counts['function_analysis_required']}件", "",
        (
            "検体は実行せず、汎用トリアージ、既存ファミリ抽出器、Ghidra等の静的解析結果を要約した。"
            "関数本体レビューが未完了の検体では、importや文字列だけから挙動成立を断定しない。"
        ), "",
        "## 検体一覧", "",
        "| SHA-256 | OSINTラベル | 形式 | アーキテクチャ | サイズ | entropy | 静的ロジック状態 |",
        "|---|---|---|---|---:|---:|---|",
    ]
    for item in summary["samples"]:
        arch = item["architecture"]
        arch_text = "/".join(str(value) for value in (arch.get("machine"), arch.get("bits"), arch.get("byte_order")) if value is not None) or "-"
        lines.append(
            f"| `{item['sha256']}` | {item['reported_malware']} | `{item['file_type']}` | "
            f"`{arch_text}` | {item['size']} | {item['entropy']} | `{item['static_logic_status']}` |"
        )
    lines.extend(["", "## 構造クラスタ", "", "| キー | 件数 | OSINTラベル内訳 | 評価 |", "|---|---:|---|---|"])
    for cluster in summary["clusters"]:
        labels = "、".join(f"{name}: {count}" for name, count in cluster["reported_malware"].items())
        lines.append(f"| `{cluster['cluster_key']}` | {cluster['member_count']} | {labels} | {cluster['assessment']} |")
    reviewed_samples = [item for item in summary["samples"] if item.get("reviewed_functions")]
    if reviewed_samples:
        lines.extend(["", "## 特徴関数レビュー", ""])
        for item in reviewed_samples:
            source = str(item.get("function_review_source") or "不明").replace("|", "\\|")
            lines.extend([
                f"### `{item['sha256']}`",
                "",
                f"- 解析元: `{source}`",
                f"- レビュー関数: {len(item['reviewed_functions'])}件",
                "",
                "| アドレス | 関数 | 役割 | 静的根拠 |",
                "|---|---|---|---|",
            ])
            for function in item["reviewed_functions"]:
                address = str(function.get("address") or "-").replace("|", "\\|")
                name = str(function.get("name") or "-").replace("|", "\\|")
                role = str(function.get("role") or "-").replace("|", "\\|")
                evidence = str(function.get("evidence") or "-").replace("|", "\\|")
                lines.append(f"| `{address}` | `{name}` | {role} | {evidence} |")
    lines.extend([
        "", "## 制約", "",
        "- 関数本体レビュー未完了のバイナリは、追加の逆コンパイルとコールグラフ整理が必要。",
        "- プロバイダのファミリ名は帰属の補助情報であり、独自に復元した設定・通信・コード類似性と分けて扱う。",
        "- 検体の通信は発生させていない。公開結果には検体本体と逆コンパイル全文を含めない。", "",
    ])
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="日次取得検体の静的解析を公開用に要約する")
    parser.add_argument("--cases", type=Path, required=True)
    parser.add_argument("--ioc-csv", type=Path, required=True)
    parser.add_argument("--source-date", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--provider-lookups", type=Path)
    parser.add_argument("--function-reviews", type=Path)
    arguments = parser.parse_args()
    summary = build_summary(
        arguments.cases.resolve(),
        arguments.ioc_csv.resolve(),
        arguments.source_date,
        arguments.provider_lookups.resolve() if arguments.provider_lookups else None,
        arguments.function_reviews.resolve() if arguments.function_reviews else None,
    )
    output = arguments.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    (output / "sample-static-summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (output / "STATIC-ANALYSIS.md").write_text(render_markdown(summary), encoding="utf-8")
    print(json.dumps(summary["counts"], ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
