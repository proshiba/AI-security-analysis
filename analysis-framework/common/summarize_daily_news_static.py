#!/usr/bin/env python3
"""日次IOCから取得した検体の静的解析を公開可能な形へ要約する。"""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


CAPABILITY_APIS = {
    "network_client": {
        "connect",
        "socket",
        "wsastartup",
        "wsaeventselect",
        "winhttpopen",
        "internetopen",
        "curl_easy_init",
    },
    "host_discovery": {
        "getusernamea",
        "getusernamew",
        "getcomputernamea",
        "getcomputernamew",
        "getcomputernameexw",
        "getadaptersaddresses",
        "gettimezoneinformation",
    },
    "file_enumeration": {
        "findfirstfilea",
        "findfirstfilew",
        "findfirstfileexw",
        "findnextfilea",
        "findnextfilew",
        "createfilea",
        "createfilew",
        "readfile",
    },
    "process_execution": {
        "createprocessa",
        "createprocessw",
        "createprocessasuserw",
        "createprocesswithtokenw",
        "shellexecutea",
        "shellexecutew",
        "winexec",
    },
    "process_inspection": {
        "createtoolhelp32snapshot",
        "process32first",
        "process32next",
        "openprocess",
        "getprocessmemoryinfo",
    },
    "screen_capture": {
        "bitblt",
        "stretchblt",
        "getdibits",
        "createcompatiblebitmap",
        "createcompatibledc",
    },
    "registry_change": {
        "regcreatekeyexa",
        "regcreatekeyexw",
        "regsetvalueexa",
        "regsetvalueexw",
        "regdeletevaluea",
        "regdeletevaluew",
    },
    "anti_analysis_surface": {
        "isdebuggerpresent",
        "outputdebugstringa",
        "outputdebugstringw",
        "addvectoredexceptionhandler",
        "setunhandledexceptionfilter",
        "getthreadcontext",
        "setthreadcontext",
    },
    "certificate_store_access": {
        "certopenstore",
        "certenumcertificatesinstore",
        "certfreecertificatecontext",
    },
}

CAPABILITY_JA = {
    "network_client": "socket/HTTPクライアント相当の通信機能",
    "host_discovery": "利用者・端末・NIC・時刻帯の収集",
    "file_enumeration": "ファイル列挙と読取り",
    "process_execution": "子プロセスまたは別tokenでのプロセス起動",
    "process_inspection": "プロセス列挙・参照",
    "screen_capture": "GDIによる画面取得",
    "registry_change": "レジストリ作成・更新・削除",
    "anti_analysis_surface": "debugger/例外/thread contextに関係する処理",
    "certificate_store_access": "Windows証明書ストアの列挙",
}


def _imports(triage: dict[str, Any]) -> set[str]:
    output = set()
    for functions in (triage.get("pe") or {}).get("imports", {}).values():
        output.update(str(function).lower() for function in functions)
    return output


def infer_capabilities(triage: dict[str, Any]) -> list[dict[str, Any]]:
    imports = _imports(triage)
    results = []
    for name, candidates in CAPABILITY_APIS.items():
        evidence = sorted(imports & candidates)
        if evidence:
            results.append(
                {
                    "id": name,
                    "summary_ja": CAPABILITY_JA[name],
                    "evidence_imports": evidence,
                    "confidence": "import_surface_only",
                }
            )
    return results


def _read_labels(ioc_csv: Path) -> dict[str, dict[str, str]]:
    with ioc_csv.open("r", encoding="utf-8-sig", newline="") as stream:
        rows = list(csv.DictReader(stream))
    return {
        row["ioc_value"].lower(): row
        for row in rows
        if row.get("ioc_type") == "file_hash_sha256"
    }


def build_summary(
    case_root: Path,
    ioc_csv: Path,
    source_date: str,
) -> dict[str, Any]:
    labels = _read_labels(ioc_csv)
    samples: list[dict[str, Any]] = []
    clusters: dict[str, list[str]] = defaultdict(list)
    for case in sorted(path for path in case_root.iterdir() if path.is_dir()):
        triage = json.loads((case / "generic-triage.json").read_text(encoding="utf-8"))
        static_logic = json.loads((case / "static-logic.json").read_text(encoding="utf-8"))
        digest = case.name
        source = labels.get(digest, {})
        pe = triage.get("pe") or {}
        sample_type = str(triage.get("type") or "unknown")
        imphash = pe.get("imphash")
        cluster_key = f"imphash:{imphash}" if imphash else f"format:{sample_type}"
        clusters[cluster_key].append(digest)
        sample = {
            "sha256": digest,
            "reported_malware": source.get("malware") or "unknown",
            "reported_malware_type": source.get("malware_type") or "unknown",
            "attribution_basis": "tech-memo IOC label and provider metadata",
            "file_type": sample_type,
            "size": triage.get("size"),
            "entropy": triage.get("entropy"),
            "magic": triage.get("magic"),
            "architecture": pe.get("machine"),
            "entry_point_rva": pe.get("entry_point_rva"),
            "imphash": imphash,
            "is_dotnet": pe.get("is_dotnet"),
            "sections": [
                {
                    "name": section.get("name"),
                    "raw_size": section.get("raw_size"),
                    "virtual_size": section.get("virtual_size"),
                    "entropy": section.get("entropy"),
                }
                for section in pe.get("sections", [])
            ],
            "capabilities": infer_capabilities(triage),
            "analysis_coverage": triage.get("analysis_coverage"),
            "static_logic_status": static_logic.get("status"),
            "function_count": static_logic.get("coverage", {}).get("function_count", 0),
            "call_edge_count": static_logic.get("coverage", {}).get("call_edge_count", 0),
            "function_bodies_reviewed": static_logic.get("coverage", {}).get(
                "function_bodies_reviewed",
                False,
            ),
            "limitations": static_logic.get("limitations", []),
            "sample_executed": False,
            "network_contacted_by_sample": False,
        }
        if sample_type == "script":
            script = triage.get("script") or {}
            sample["script_indicators"] = script.get("indicators", {})
            sample["script_iocs"] = {
                "urls": script.get("iocs", {}).get("urls", []),
                "domains": [
                    domain
                    for domain in script.get("iocs", {}).get("domains", [])
                    if domain in {"callsdk.online", "web.telegram.org", "webk.telegram.org", "webz.telegram.org"}
                ],
            }
            sample["functions"] = [
                {
                    "name": function.get("name"),
                    "api_calls": function.get("api_calls", []),
                    "control_flow": function.get("control_flow", {}),
                    "fingerprints": function.get("fingerprints", {}),
                }
                for function in static_logic.get("functions", [])
            ]
            sample["call_edges"] = static_logic.get("call_edges", [])
        samples.append(sample)

    cluster_rows = []
    for key, members in sorted(clusters.items()):
        family_counts = Counter(
            next(item["reported_malware"] for item in samples if item["sha256"] == digest)
            for digest in members
        )
        cluster_rows.append(
            {
                "cluster_key": key,
                "member_count": len(members),
                "members": sorted(members),
                "reported_malware": dict(sorted(family_counts.items())),
                "assessment": (
                    "同一imphashはimport構成の一致を示すが、同一family、同一payload、"
                    "同一campaignの確定根拠にはならない。"
                    if key.startswith("imphash:")
                    else "形式だけの集合であり、コード類似性を示さない。"
                ),
            }
        )
    return {
        "schema_version": 1,
        "source_date": source_date,
        "sample_count": len(samples),
        "counts": {
            "pe": sum(item["file_type"] == "pe" for item in samples),
            "macho": sum(item["file_type"] == "macho" for item in samples),
            "script": sum(item["file_type"] == "script" for item in samples),
            "function_analysis_complete": sum(
                bool(item["function_bodies_reviewed"]) for item in samples
            ),
            "script_structure_recorded": sum(
                item["static_logic_status"] == "automated_script_structure"
                for item in samples
            ),
            "function_analysis_required": sum(
                item["static_logic_status"] == "function_analysis_required"
                for item in samples
            ),
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
    lines = [
        f"# 取得検体の静的解析: {summary['source_date']}",
        "",
        "## 解析範囲",
        "",
        f"- 取得・一次解析: {summary['sample_count']}検体",
        f"- PE: {counts['pe']}件、Mach-O: {counts['macho']}件、VBS: {counts['script']}件",
        f"- script処理構造を記録: {counts['script_structure_recorded']}件",
        f"- binary関数解析が未完: {counts['function_analysis_required']}件",
        "",
        "検体は実行していない。PE/Mach-Oのimport、section、entry point、entropy、文字列、"
        "VBSの構文とcall edgeを解析した。Ghidra MCPはインスタンスを検出したものの、"
        "project selectorを取得できず、binaryの関数本体レビューは完了していない。"
        "そのため17 binaryを完了扱いにせず、明示的に追加解析対象として残す。",
        "",
        "## 重要な静的所見",
        "",
        "### NukeSpedラベルのVBS",
        "",
        "`8889f1b6...a87775`は16処理単位と7本の内部call edgeを持つ。WMIで利用者名、"
        "OS、CPU、時刻帯、NIC、稼働プロセスを収集し、Chromium/Firefox profileと"
        "Telegram Web利用痕跡を列挙する。`post`はWinHTTP要求、JSON文字列の抽出、"
        "server指示のURL encode、`Shell.Run`による後続処理を含む。"
        "`callsdk.online`へのURL literalを静的に確認した。これは構文・call edgeに基づく"
        "確認であり、通信は実行していない。",
        "",
        "### TAG-195関連ラベルのWindows群",
        "",
        "TinyEgg、ChonkyChicken、Modular ChonkyChicken、ChromEggscalatorのラベル間で、"
        "同一imphashのクラスタが複数確認された。特に"
        "`e5e1c7bf79d9e27780f9dccbb11ab144`にはTinyEgg 1件とChonkyChicken 4件が混在する。"
        "これは共通loader、builder、静的library、または同一toolset内の役割違いを示唆するが、"
        "imphashだけではfamilyを統合できない。",
        "",
        "ChonkyChicken側のimport surfaceには端末/NIC情報、process列挙、GDI画面取得、"
        "レジストリ操作、別tokenでのprocess起動が現れる。TinyEgg側には端末情報、"
        "ファイル列挙、socket処理が現れる。ChromEggscalator群は高entropyの`.text`と"
        "named pipe、process起動、ファイル操作を含む。これらはAPI能力面の根拠であり、"
        "各挙動が実行経路上で成立することまでは未確認である。",
        "",
        "### Remus Stealer（IOCラベル）",
        "",
        "`b81291ca...a7bebf`はPE64で、高entropyの全体像とdebugger/例外/thread contextに"
        "関係するimportを持つ。`CreateMutexA`、ファイル/ディレクトリ操作、process参照、"
        "`SHGetFolderPathW`も確認した。providerのRemus Stealerラベルとは整合するが、"
        "config復号、C2 literal、特徴的関数本体は未復元である。",
        "",
        "### macOS NukeSpedラベル",
        "",
        "Mach-O 2件を確認した。片方には`api.telegram.org`を含むURL literalがあるが、"
        "token部分は公開結果で秘匿した。もう1件は高entropyで文字列scanが上限に達し、"
        "browser profile関連の文字列が見える。Mach-O固有解析と関数本体レビューが必要である。",
        "",
        "## 検体一覧",
        "",
        "| SHA-256 | OSINTラベル | 形式 | サイズ | entropy | imphash | 関数状態 |",
        "|---|---|---|---:|---:|---|---|",
    ]
    for item in summary["samples"]:
        lines.append(
            f"| `{item['sha256']}` | {item['reported_malware']} | `{item['file_type']}` | "
            f"{item['size']} | {item['entropy']} | `{item['imphash'] or '-'}` | "
            f"`{item['static_logic_status']}` |"
        )
    lines.extend(
        [
            "",
            "## 構造クラスタ",
            "",
            "| キー | 件数 | OSINTラベル内訳 | 評価 |",
            "|---|---:|---|---|",
        ]
    )
    for cluster in summary["clusters"]:
        labels = ", ".join(
            f"{name}: {count}" for name, count in cluster["reported_malware"].items()
        )
        lines.append(
            f"| `{cluster['cluster_key']}` | {cluster['member_count']} | {labels} | "
            f"{cluster['assessment']} |"
        )
    lines.extend(
        [
            "",
            "## 未完了事項",
            "",
            "- PE/Mach-O 17件の代表関数逆コンパイル、call graph、config復号。",
            "- Mach-O 2件のload command、Objective-C/Swift symbol、署名、永続化ロジックの精査。",
            "- Remus Stealerのconfig/C2復元と、既存Remus extractorへの適用可否確認。",
            "- TAG-195関連クラスタの関数fingerprint比較。imphashだけの相関をcampaign確定に使わない。",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="日次取得検体の静的解析を公開用に要約する。")
    parser.add_argument("--cases", type=Path, required=True)
    parser.add_argument("--ioc-csv", type=Path, required=True)
    parser.add_argument("--source-date", required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    summary = build_summary(
        arguments.cases.resolve(),
        arguments.ioc_csv.resolve(),
        arguments.source_date,
    )
    output = arguments.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    (output / "sample-static-summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (output / "STATIC-ANALYSIS.md").write_text(
        render_markdown(summary),
        encoding="utf-8",
    )
    print(json.dumps(summary["counts"], ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
