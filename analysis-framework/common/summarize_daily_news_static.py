#!/usr/bin/env python3
"""日次IOCから取得した検体の静的解析結果を公開可能な形へ要約する。"""

from __future__ import annotations

import argparse
import csv
import importlib
import io
import json
import os
import re
import stat
import sys
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

COMMON_ROOT = Path(__file__).resolve().parent
if str(COMMON_ROOT) not in sys.path:
    sys.path.insert(0, str(COMMON_ROOT))
analysis_contract = importlib.import_module("analysis_contract")

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
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_SUMMARY_CASES = 1_000
MAX_PUBLIC_SAMPLE_BYTES = 256 * 1024
MAX_PUBLIC_SAMPLES_TOTAL_BYTES = 32 * 1024 * 1024


def _imports(triage: dict[str, Any]) -> set[str]:
    output: set[str] = set()
    imports = (triage.get("pe") or {}).get("imports", {})
    if not isinstance(imports, Mapping) or len(imports) > 2_048:
        raise ValueError("import tableが上限内のobjectではありません")
    function_count = 0
    for functions in imports.values():
        if not isinstance(functions, list):
            raise TypeError("import function listが不正です")
        function_count += len(functions)
        if function_count > 10_000:
            raise ValueError("import function件数が上限を超えています")
        output.update(str(function).lower() for function in functions)
    return output


def _bounded_public_copy(value: Any, *, maximum_bytes: int) -> tuple[Any, int]:
    """選択済み公開fieldだけを容量内のdetached JSONへ変換する。"""

    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    if not 0 < len(encoded) <= maximum_bytes:
        raise ValueError("日次公開sample fieldが容量上限を超えています")
    return json.loads(encoded), len(encoded)


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


def _labels_from_rows(rows: Iterable[Mapping[str, Any]]) -> dict[str, dict[str, str]]:
    return {
        str(row.get("ioc_value") or "").lower(): dict(row)
        for row in rows
        if row.get("ioc_type") in HASH_IOC_TYPES and row.get("ioc_value")
    }


def _read_labels(ioc_csv: Path) -> dict[str, dict[str, str]]:
    payload = analysis_contract._read_regular_file_snapshot(
        ioc_csv,
        max_bytes=8 * 1024 * 1024,
    )
    stream = io.StringIO(payload.decode("utf-8-sig", errors="strict"), newline="")
    return _labels_from_rows(csv.DictReader(stream))


def _provider_aliases_document(
    payload: Mapping[str, Any] | None,
    labels: dict[str, dict[str, str]],
) -> dict[str, dict[str, str]]:
    """親で検証済みのprovider文書からだけhash aliasを構築する。"""

    aliases: dict[str, dict[str, str]] = {}
    if payload is None:
        return aliases
    items = payload.get("items")
    if not isinstance(items, list) or len(items) > MAX_SUMMARY_CASES * 4:
        raise ValueError("provider文書のitemsが上限内のlistではありません")
    for item in items:
        if not isinstance(item, Mapping):
            raise TypeError("provider文書のitemがobjectではありません")
        metadata = item.get("metadata") or {}
        if not isinstance(metadata, Mapping):
            raise TypeError("provider metadataがobjectではありません")
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


def _provider_aliases(path: Path | None, labels: dict[str, dict[str, str]]) -> dict[str, dict[str, str]]:
    if path is None or not os.path.lexists(path):
        return {}
    payload = analysis_contract.load_json_object_strict(path)
    return _provider_aliases_document(payload, labels)


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
    if path is None or not os.path.lexists(path):
        return {}
    payload = analysis_contract.load_json_object_strict(path)
    return {
        str(item.get("sha256") or "").lower(): item
        for item in payload.get("samples", [])
        if item.get("sha256")
    }

def _build_summary_materialized(
    case_documents: Iterable[Mapping[str, Any]],
    *,
    labels: dict[str, dict[str, str]],
    aliases: dict[str, dict[str, str]],
    reviews: dict[str, dict[str, Any]],
    source_date: str,
    input_commitment: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    samples: list[dict[str, Any]] = []
    clusters: dict[str, list[str]] = defaultdict(list)
    retained_sample_bytes = 0

    observed: set[str] = set()
    previous_digest: str | None = None
    for document in case_documents:
        if len(observed) >= MAX_SUMMARY_CASES:
            raise ValueError("日次要約case件数が上限を超えています")
        if not isinstance(document, Mapping):
            raise TypeError("日次要約case documentがobjectではありません")
        digest = document.get("sha256")
        if (
            not isinstance(digest, str)
            or SHA256_RE.fullmatch(digest) is None
            or digest in observed
            or (previous_digest is not None and digest <= previous_digest)
        ):
            raise ValueError("日次要約case SHA-256が不正または重複しています")
        observed.add(digest)
        previous_digest = digest
        triage = document.get("generic_triage")
        static_logic = document.get("static_logic")
        if not isinstance(triage, Mapping) or not isinstance(static_logic, Mapping):
            raise TypeError("日次要約caseの静的JSONがobjectではありません")
        if str(triage.get("sha256") or digest).lower() != digest:
            raise ValueError("日次要約caseとgeneric triageのSHA-256が一致しません")
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
        detached, encoded_size = _bounded_public_copy(
            sample,
            maximum_bytes=MAX_PUBLIC_SAMPLE_BYTES,
        )
        retained_sample_bytes += encoded_size
        if retained_sample_bytes > MAX_PUBLIC_SAMPLES_TOTAL_BYTES:
            raise ValueError("日次公開sample合計sizeが上限を超えています")
        samples.append(detached)

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

    summary = {
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
    if input_commitment is not None:
        summary["input_commitment"] = dict(input_commitment)
    return summary


def build_summary_from_documents(
    case_documents: Iterable[Mapping[str, Any]],
    ioc_rows: Iterable[Mapping[str, Any]],
    source_date: str,
    *,
    provider_document: Mapping[str, Any] | None,
    input_commitment: Mapping[str, Any],
    function_review_document: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """検証済みin-memory文書だけから決定的な公開要約を作る。"""

    if provider_document is not None and provider_document.get("source_date") != source_date:
        raise ValueError("provider文書と日次要約のsource dateが一致しません")
    if input_commitment.get("source_date") != source_date:
        raise ValueError("日次要約input commitmentのsource dateが一致しません")
    labels = _labels_from_rows(ioc_rows)
    reviews: dict[str, dict[str, Any]] = {}
    if function_review_document is not None:
        raw_reviews = function_review_document.get("samples")
        if not isinstance(raw_reviews, list) or len(raw_reviews) > MAX_SUMMARY_CASES:
            raise ValueError("function review文書が不正です")
        reviews = {
            str(item.get("sha256") or "").lower(): dict(item)
            for item in raw_reviews
            if isinstance(item, Mapping) and item.get("sha256")
        }
    return _build_summary_materialized(
        case_documents,
        labels=labels,
        aliases=_provider_aliases_document(provider_document, labels),
        reviews=reviews,
        source_date=source_date,
        input_commitment=input_commitment,
    )


def _bounded_case_entries(case_root: Path) -> list[os.DirEntry[str]]:
    """case rootを先に固定し、上限+1件目で列挙を打ち切る。"""

    absolute = Path(os.path.abspath(os.fspath(case_root)))
    try:
        analysis_contract.ensure_no_reparse_components(absolute)
        before = absolute.lstat()
        if (
            not stat.S_ISDIR(before.st_mode)
            or analysis_contract._stat_has_reparse_attribute(before)
        ):
            raise ValueError("case root type invalid")
        entries: list[os.DirEntry[str]] = []
        with os.scandir(absolute) as iterator:
            for entry in iterator:
                if len(entries) >= MAX_SUMMARY_CASES:
                    raise OverflowError
                entries.append(entry)
        after = absolute.lstat()
    except OverflowError as error:
        raise ValueError("日次要約case件数が上限を超えています") from error
    except (OSError, ValueError) as error:
        raise ValueError("日次要約case rootを安全に列挙できません") from error
    if (
        not stat.S_ISDIR(after.st_mode)
        or analysis_contract._stat_has_reparse_attribute(after)
        or not analysis_contract._same_file_identity(before, after)
        or before.st_mtime_ns != after.st_mtime_ns
        or before.st_ctime_ns != after.st_ctime_ns
    ):
        raise ValueError("日次要約case rootを安全に列挙できません")
    return sorted(entries, key=lambda entry: entry.name.casefold())


def build_summary(
    case_root: Path,
    ioc_csv: Path,
    source_date: str,
    provider_lookups: Path | None = None,
    function_reviews: Path | None = None,
) -> dict[str, Any]:
    """既存CLI互換のpath入力をmaterializeし、pure builderへ渡す。"""

    documents: list[dict[str, Any]] = []
    entries = _bounded_case_entries(case_root)
    for entry in entries:
        if not entry.is_dir(follow_symlinks=False):
            continue
        case = Path(entry.path)
        triage_path = case / "generic-triage.json"
        logic_path = case / "static-logic.json"
        if not os.path.lexists(triage_path) or not os.path.lexists(logic_path):
            continue
        documents.append(
            {
                "sha256": case.name.lower(),
                "generic_triage": analysis_contract.load_json_object_strict(triage_path),
                "static_logic": analysis_contract.load_json_object_strict(logic_path),
            }
        )
    labels = _read_labels(ioc_csv)
    return _build_summary_materialized(
        documents,
        labels=labels,
        aliases=_provider_aliases(provider_lookups, labels),
        reviews=_function_reviews(function_reviews),
        source_date=source_date,
    )


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
