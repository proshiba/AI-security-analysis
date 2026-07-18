#!/usr/bin/env python3
"""Generate publish-safe per-case reports for a reviewed multi-family batch."""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
import os
from pathlib import Path
import re
import sys

REPO = Path(__file__).parents[2]
COMMON = Path(__file__).parent
for location in (REPO, COMMON):
    if str(location) not in sys.path:
        sys.path.insert(0, str(location))

from c2_candidate_detector import assess  # noqa: E402
from extractors.profiled_family import extract_family, load_profiles, normalize_family, sanitize_network_url, url_role  # noqa: E402
from generate_ioc_lists import Indicator, indicators_from_reviewed_findings, render_ioc_list  # noqa: E402
from malware_io import read_single_aes_zip_member  # noqa: E402
from result_layout import (  # noqa: E402
    canonical_collection_manifest_path,
    canonical_collection_root,
    canonical_collection_source_path,
    canonical_malware_case_path,
    resolve_catalog_case_path,
)

RUN_ID = "malwarebazaar-20260717"


def public_source(item: dict) -> dict:
    """Return source metadata without reporter identity or local archive paths."""
    metadata = item.get("metadata") or {}
    return {
        "sha256": item["sha256"],
        "requested_signature": item["requested_signature"],
        "first_seen": metadata.get("first_seen"),
        "file_name": metadata.get("file_name"),
        "file_size": metadata.get("file_size"),
        "file_type": metadata.get("file_type"),
        "file_format": metadata.get("file_format"),
        "file_arch": metadata.get("file_arch"),
        "tags": metadata.get("tags") or [],
        "imphash": metadata.get("imphash"),
        "tlsh": metadata.get("tlsh"),
        "ssdeep": metadata.get("ssdeep"),
    }


def normalize_finding(item: dict) -> dict | None:
    """Retain only publish-safe network finding fields with calibrated confidence."""
    value = str(item.get("value") or "")
    if not value or len(value) > 1024:
        return None
    kind = str(item.get("kind") or "network.candidate")
    if kind == "network.url" or value.lower().startswith(("http://", "https://", "ftp://")):
        value = sanitize_network_url(value) or ""
        if not value:
            return None
    return {
        "kind": kind,
        "value": value,
        "role": str(item.get("role") or "candidate_infrastructure"),
        "confidence": str(item.get("confidence") or "candidate"),
        "source": str(item.get("source") or "static_analysis"),
    }


def merge_findings(extractor_result: dict, static_case: dict) -> list[dict]:
    """Merge extractor and recursive-layer literals without upgrading confidence."""
    output: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for raw in extractor_result.get("findings") or []:
        item = normalize_finding(raw)
        if item and (item["kind"], item["value"]) not in seen:
            seen.add((item["kind"], item["value"]))
            output.append(item)
    for raw_value in (static_case.get("iocs") or {}).get("urls") or []:
        value = sanitize_network_url(raw_value)
        if not value:
            continue
        key = ("network.url", value)
        if key not in seen:
            seen.add(key)
            output.append({"kind": "network.url", "value": value, "role": url_role("recursive_layer_literal", value), "confidence": "candidate", "source": "bounded_recursive_static_analysis"})
    for value in (static_case.get("iocs") or {}).get("ips") or []:
        if ":" not in value:
            continue
        key = ("network.endpoint", value)
        if key not in seen:
            seen.add(key)
            output.append({"kind": "network.endpoint", "value": value, "role": "recursive_layer_literal", "confidence": "candidate", "source": "bounded_recursive_static_analysis"})
    return output[:256]


def build_case(item: dict, static_case: dict, extractor_result: dict, c2_plan: dict, profile: dict) -> dict:
    """Build one public case document with explicit evidence and limitations."""
    findings = merge_findings(extractor_result, static_case)
    return {
        "schema_version": 1,
        "family": profile["family"],
        "display_name": profile["display_name"],
        "source": public_source(item),
        "attribution": {
            "family": profile["family"],
            "confidence": "high",
            "basis": ["exact MalwareBazaar signature query", "downloaded member SHA-256 verified", "reviewed batch campaign registry"],
            "campaign_or_operator": "not attributed",
        },
        "static_analysis": {
            "root_unpack": static_case.get("root_unpack") or {},
            "layers": static_case.get("layers") or [],
            "repository_yara_matches": static_case.get("repository_yara_matches") or [],
            "profile_config": extractor_result.get("config") or {},
            "findings": findings,
        },
        "c2_assessment": c2_plan,
        "detection_inputs": {
            "sha256": item["sha256"],
            "imphash": (item.get("metadata") or {}).get("imphash"),
            "tags": (item.get("metadata") or {}).get("tags") or [],
            "profile_markers": (extractor_result.get("config") or {}).get("marker_hits") or [],
            "observed_config_keys": (extractor_result.get("config") or {}).get("observed_config_keys") or [],
            "packer_markers": (static_case.get("root_unpack") or {}).get("packer_markers") or [],
            "network_candidates": [entry["value"] for entry in findings],
        },
        "sample_executed": False,
        "network_contacted": False,
        "limitations": [
            "Static-only analysis; encrypted runtime-only values can remain unresolved.",
            "A literal endpoint, open port, or passive-search hit does not independently confirm a C2 service.",
            "Family source signature does not identify an operator or campaign.",
        ],
    }


def markdown_table(rows: list[list[str]]) -> str:
    """Render a small escaped Markdown table."""
    if not rows:
        return ""
    escaped = [[str(value).replace("|", "\\|").replace("\n", " ") for value in row] for row in rows]
    header = "| " + " | ".join(escaped[0]) + " |"
    separator = "| " + " | ".join("---" for _ in escaped[0]) + " |"
    body = ["| " + " | ".join(row) + " |" for row in escaped[1:]]
    return "\n".join([header, separator, *body])


def case_markdown(case: dict) -> str:
    """検体単位の詳細な日本語 README を描画する。"""
    source = case["source"]
    static = case["static_analysis"]
    config = static["profile_config"]
    findings = static["findings"]
    finding_rows = [["値 (Value)", "役割 (Role)", "信頼度 (Confidence)", "根拠 (Source)"]] + [
        [f"`{item['value']}`", item["role"], item["confidence"], item["source"]] for item in findings
    ]
    layer_rows = [["深さ", "種別", "形式", "サイズ", "SHA-256"]] + [
        [str(item.get("depth", "")), str(item.get("kind", "")), str(item.get("format", "")), str(item.get("size", "")), f"`{item.get('sha256', '')}`"]
        for item in static["layers"][:32]
    ]
    return f'''# {case["display_name"]} 検体 {source["sha256"]}

## 概要

- ファミリー: `{case["family"]}`（MalwareBazaar の exact signature 選択と SHA-256 検証に基づく高信頼）
- 初回観測: `{source.get("first_seen")}`
- 提出名／種別／サイズ: `{source.get("file_name")}` / `{source.get("file_type")}` / `{source.get("file_size")}` bytes
- SHA-256: `{source["sha256"]}`
- オペレーター／キャンペーン: 未帰属
- 実行／通信: 検体は未実行、インフラには未接続

## 静的挙動と設定

- 分類／通信方式: `{config.get("category")}` / `{config.get("transport")}`
- unpack 状態: `{static["root_unpack"].get("unpack_status")}`
- packing 分類: `{static["root_unpack"].get("packing_classification")}`
- 一致 marker: `{", ".join(config.get("marker_hits") or []) or "なし"}`
- 観測した config key: `{", ".join(config.get("observed_config_keys") or []) or "なし"}`
- 静的 config 候補の回収: `{config.get("static_config_recovered", False)}`

### インフラ候補

{markdown_table(finding_rows) if findings else "公開可能な通信候補は静的解析で回収できませんでした。"}

候補を稼働中または確認済み C2 とは扱いません。受動的な Shodan pivot とファミリー固有の確認条件は `c2-observation-plan.json` を参照してください。

### 回収した layer

{markdown_table(layer_rows) if static["layers"] else "制限内で内部 layer は回収できませんでした。"}

## 検知入力

- exact hash: 高精度で誤検知リスクは低い一方、亜種は検出できません。
- profile marker 群と endpoint の組合せ: 中信頼。fork、流出 builder、正規ソフトウェアの文字列と重なる場合があります。
- 単独の URL/IP literal: 低信頼で誤検知リスクが高く、共有 hosting、update service、埋込み文書が原因になり得ます。
- YARA 入力: profile marker、file size 上限、レビュー済みファミリー文脈です。
- Sigma 入力: 観測した script 配布挙動だけを使用し、直接 PE 検体に動的 process 挙動を補っていません。

## 制約

これは範囲を制限した静的解析です。pack された設定や実行時復号される設定は未解決の可能性があり、source 上のファミリー帰属だけでは共通オペレーターやキャンペーンを特定できません。
'''


def ioc_indicators(hashes: list[str], findings: list[dict]) -> list[Indicator]:
    """Normalize reviewed hashes and findings into the shared IOC contract."""
    return indicators_from_reviewed_findings(hashes, findings)


def ioc_markdown(hashes: list[str], findings: list[dict]) -> str:
    """Render the shared five-column IOC-only table."""
    return render_ioc_list(ioc_indicators(hashes, findings))


def yara_rule(family: str, profile: dict) -> str:
    """Render a conservative profile-marker YARA rule with false-positive notes."""
    strings = []
    for index, marker in enumerate(profile["markers"]):
        escaped = marker.replace("\\", "\\\\").replace('"', '\\"')
        strings.append(f'        $m{index} = "{escaped}" ascii wide nocase')
    threshold = min(int(profile["minimum_markers"]), len(strings))
    name = re.sub(r"[^A-Za-z0-9_]", "_", f"ASA_{family}_Profile_20260717")
    return f'''rule {name}
{{
    meta:
        description = "Profile markers for {profile["display_name"]}; corroboration required"
        author = "AI-security-analysis"
        date = "2026-07-17"
        confidence = "medium"
        false_positive = "Forks, leaked builders, test tools, and unrelated software containing generic markers"
    strings:
{chr(10).join(strings)}
    condition:
        filesize < 100MB and {threshold} of ($m*)
}}
'''


def family_markdown(
    family: str,
    profile: dict,
    cases: list[dict],
    case_links: dict[str, str] | None = None,
) -> str:
    """family 集約結果を誤検知評価付きの日本語 Markdown で描画する。"""
    types = Counter(str(case["source"].get("file_type") or "unknown") for case in cases)
    statuses = Counter(str(case["static_analysis"]["root_unpack"].get("unpack_status") or "unknown") for case in cases)
    recovered = sum(bool(case["static_analysis"]["profile_config"].get("static_config_recovered")) for case in cases)
    findings = [item for case in cases for item in case["static_analysis"]["findings"]]
    case_links = case_links or {}
    case_rows = [["SHA-256", "種別", "unpack", "config", "通信候補数"]]
    for case in cases:
        digest = case["source"]["sha256"]
        link = case_links.get(digest, f"cases/{digest}/README.md")
        case_rows.append([
            f"[{digest}]({link})",
            str(case["source"].get("file_type")),
            str(case["static_analysis"]["root_unpack"].get("unpack_status")),
            str(case["static_analysis"]["profile_config"].get("static_config_recovered", False)),
            str(len(case["static_analysis"]["findings"])),
        ])
    return f'''# {profile["display_name"]} — MalwareBazaar 静的レビュー 2026-07-17

## 対象と結果

MalwareBazaar の exact signature で選んだ最新検体を静的解析しました。内部 hash を検証し、検体と回収 payload は実行せず、候補インフラにも接続していません。

- 分類: `{profile["category"]}`
- 想定通信方式／役割: `{profile["transport"]}` / `{profile["endpoint_role"]}`
- file type 分布: `{dict(types)}`
- unpack 状態分布: `{dict(statuses)}`
- profile config 候補: `{recovered}/{len(cases)}`
- 公開可能な通信候補: `{len(findings)}`

ここでのファミリー帰属は、単一のオペレーターやキャンペーンを意味しません。builder 流出、fork、repack、異なる配布 chain は別々に評価する必要があります。

## 検体

{markdown_table(case_rows)}

## C2／config の解釈

確認条件: {profile["confirmation"]}。条件を満たすまでは配布／C2／流出先の候補としてのみ報告します。受動的な Shodan query は case ごとに保存し、live 観測がない banner、JARM、証明書、HTTP title は補完していません。

## 検知と誤検知評価

| 信頼度 | 推奨入力 | 誤検知上の注意 |
| --- | --- | --- |
| 高 | レビュー済み exact SHA-256 | 誤検知は極めて少ない一方、rebuild／repack を検出できません。 |
| 中 | 複数 family marker と復号・裏付け済み endpoint 構造 | fork、流出 builder、research tool、共有 library が一致する場合があります。 |
| 低 | 単一 marker、URL/IP、packer label、一般的な script interpreter 挙動 | 共有 hosting、正規 automation、installer、文書文字列を過検知し得ます。 |

生成 YARA rule は中信頼であり、benign corpus による検証が必要です。Sigma は実際の endpoint telemetry に基づく必要があり、この静的 batch では process／registry event を補っていません。
'''


def write_text(path: Path, value: str) -> None:
    """Write normalized UTF-8 text after creating parent directories."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(value.replace("\r\n", "\n"))


def _merged_catalog_document(
    output_root: Path, entries: dict[str, dict]
) -> dict:
    path = output_root / "catalog" / "cases.json"
    if path.is_file():
        current = json.loads(path.read_text(encoding="utf-8-sig"))
        if current.get("schema_version") != 1 or not isinstance(current.get("cases"), dict):
            raise ValueError(f"invalid case catalog: {path}")
    else:
        current = {"schema_version": 1, "cases": {}}
    merged = dict(current["cases"])
    for digest, entry in sorted(entries.items()):
        existing = merged.get(digest)
        if isinstance(existing, dict):
            for key in ("case_id", "family", "case_kind", "canonical_path"):
                if existing.get(key) != entry.get(key):
                    raise ValueError(f"conflicting case catalog entry: {digest}")
        merged[digest] = {**(existing or {}), **entry}
    return {"schema_version": 1, "cases": dict(sorted(merged.items()))}


def _merged_collection_document(
    path: Path,
    run_id: str,
    cases: list[dict[str, str]],
    family_sources: list[dict[str, str]],
) -> dict:
    if path.is_file():
        current = json.loads(path.read_text(encoding="utf-8-sig"))
        if current.get("collection_id") != run_id:
            raise ValueError(f"collection ID mismatch: {path}")
    else:
        current = {"schema_version": 1, "collection_id": run_id}
    existing_cases = current.get("cases") or []
    if any(not isinstance(item, dict) or set(item) != {"case_id"} for item in existing_cases):
        raise ValueError(f"collection cases must contain case_id only: {path}")
    case_ids = {str(item["case_id"]) for item in existing_cases}
    case_ids.update(str(item["case_id"]) for item in cases)
    source_map: dict[str, str] = {}
    for item in [*(current.get("family_sources") or []), *family_sources]:
        if not isinstance(item, dict) or set(item) != {"family", "path"}:
            raise ValueError(f"invalid collection family source: {path}")
        family = str(item["family"])
        source_path = str(item["path"])
        if family in source_map and source_map[family] != source_path:
            raise ValueError(f"conflicting collection family source: {family}")
        source_map[family] = source_path
    return {
        "schema_version": 1,
        "collection_id": run_id,
        "family_sources": [
            {"family": family, "path": source_map[family]}
            for family in sorted(source_map)
        ],
        "cases": [{"case_id": case_id} for case_id in sorted(case_ids)],
    }


def collection_markdown(document: dict) -> str:
    """collection manifestから、検体を複製しない日本語READMEを生成する。"""

    collection_id = str(document.get("collection_id") or "")
    cases = document.get("cases") or []
    family_sources = document.get("family_sources") or []
    if document.get("schema_version") != 1 or not collection_id:
        raise ValueError("invalid collection manifest")
    if any(not isinstance(item, dict) or set(item) != {"case_id"} for item in cases):
        raise ValueError("collection cases must contain case_id only")
    if any(
        not isinstance(item, dict) or set(item) != {"family", "path"}
        for item in family_sources
    ):
        raise ValueError("invalid collection family source")
    lines = [
        f"# コレクション：{collection_id}",
        "",
        "このディレクトリは収集・選定単位の索引です。検体別成果物は重複して保存せず、"
        "SHA-256安定IDから `../../catalog/cases.json` の正規パスを参照します。",
        "",
        f"- 登録ケース数：{len(cases)}件",
        f"- ファミリー別集約資料：{len(family_sources)}件",
        "- 検体実行・抽出インフラへの接続：実施していません",
        "",
        "## ファミリー別資料",
        "",
    ]
    if family_sources:
        for item in sorted(family_sources, key=lambda value: str(value["family"])):
            family = str(item["family"])
            source_path = str(item["path"])
            lines.append(f"- [{family}]({source_path}/README.md)")
    else:
        lines.append("- ファミリー別集約資料はありません。")
    lines.extend(
        [
            "",
            "## ケース参照",
            "",
            "ケース一覧の正本は `manifest.json` の `case_id` です。版または帰属が後日更新されても、"
            "SHA-256をキーにcatalogから現在の配置を解決してください。",
            "",
        ]
    )
    return "\n".join(lines)


def _write_json_documents_atomic(documents: dict[Path, dict]) -> None:
    """catalog と collection manifest を一組として更新し、失敗時に戻す。"""

    temporary: dict[Path, Path] = {}
    originals: dict[Path, bytes | None] = {}
    try:
        for path, document in documents.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            temp = path.with_name(path.name + ".tmp")
            if temp.exists():
                raise ValueError(f"temporary index already exists: {temp}")
            temp.write_text(
                json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
                newline="\n",
            )
            temporary[path] = temp
            originals[path] = path.read_bytes() if path.is_file() else None
        replaced: list[Path] = []
        try:
            for path, temp in temporary.items():
                temp.replace(path)
                replaced.append(path)
        except Exception:
            for path in reversed(replaced):
                original = originals[path]
                if original is None:
                    path.unlink(missing_ok=True)
                else:
                    rollback = path.with_name(path.name + ".rollback-tmp")
                    rollback.write_bytes(original)
                    rollback.replace(path)
            raise
    finally:
        for temp in temporary.values():
            temp.unlink(missing_ok=True)


def _case_layout_metadata(
    output_root: Path, case_directory: Path, case: dict, run_id: str
) -> dict:
    digest = case["source"]["sha256"]
    return {
        "schema_version": 1,
        "case_id": f"sha256:{digest}",
        "sha256": digest,
        "case_kind": "malware",
        "family": case["family"],
        "malware_version": {
            "status": "unknown",
            "reported": None,
            "normalized_key": "unknown",
            "confidence": "none",
            "reason": "no_approved_sample_specific_version_evidence",
            "evidence": [],
        },
        "collections": [run_id],
        "canonical_path": case_directory.relative_to(output_root.parent).as_posix(),
    }


def regenerate_run_ioc_lists(output_root: Path, run_id: str = RUN_ID) -> dict:
    """Rebuild aggregate IOC tables from already-published case documents."""
    output_root = output_root.resolve()
    family_count = case_count = indicator_count = 0
    collection_root = canonical_collection_root(output_root, run_id)
    sources_root = collection_root / "sources"
    if not sources_root.is_dir():
        return {
            "families": 0,
            "cases": 0,
            "indicators": 0,
            "run_id": run_id,
        }
    for family_dir in sorted(
        (path for path in sources_root.iterdir() if path.is_dir()),
        key=lambda path: path.name.lower(),
    ):
        manifest_path = family_dir / "manifest.json"
        if not manifest_path.is_file():
            continue
        manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
        if manifest.get("source") != "MalwareBazaar exact signature query":
            continue
        family = str(manifest.get("family") or family_dir.name)
        hashes: list[str] = []
        findings: list[dict] = []
        for item in manifest.get("items") or []:
            digest = str(item.get("sha256") or "").lower()
            case_dir = resolve_catalog_case_path(
                output_root, digest, family=family, fallback_version_key="unknown"
            )
            indicator_path = case_dir / "indicators.json"
            if not indicator_path.is_file():
                raise ValueError(f"missing public case indicators: {indicator_path}")
            case = json.loads(indicator_path.read_text(encoding="utf-8-sig"))
            source_digest = str((case.get("source") or {}).get("sha256") or "").lower()
            if digest != source_digest or digest != case_dir.name.lower():
                raise ValueError(f"public case hash mismatch: {indicator_path}")
            hashes.append(digest)
            findings.extend((case.get("static_analysis") or {}).get("findings") or [])
        indicators = ioc_indicators(hashes, findings)
        write_text(family_dir / "IOC-LIST.md", render_ioc_list(indicators))
        family_count += 1
        case_count += len(hashes)
        indicator_count += len(indicators)
    collection_manifest = canonical_collection_manifest_path(output_root, run_id)
    if collection_manifest.is_file():
        write_text(
            collection_root / "README.md",
            collection_markdown(
                json.loads(collection_manifest.read_text(encoding="utf-8-sig"))
            ),
        )
    return {
        "families": family_count,
        "cases": case_count,
        "indicators": indicator_count,
        "run_id": run_id,
    }


def generate(
    manifest_path: Path,
    cache: Path,
    output_root: Path,
    run_id: str = RUN_ID,
) -> dict:
    """Generate all public reports directly from encrypted archives and static cache."""
    output_root = output_root.resolve()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    profiles = load_profiles()
    grouped: dict[str, list[dict]] = defaultdict(list)
    for item in manifest.get("items") or []:
        grouped[normalize_family(item["requested_signature"], profiles)].append(item)
    total_cases = total_findings = 0
    family_counts = {}
    collection_cases: set[str] = set()
    family_sources: list[dict[str, str]] = []
    catalog_entries: dict[str, dict] = {}
    collection_root = canonical_collection_root(output_root, run_id)
    for family, items in sorted(grouped.items()):
        profile = {"family": family, **profiles[family]}
        family_dir = canonical_collection_source_path(output_root, run_id, family)
        cases = []
        case_links: dict[str, str] = {}
        for item in sorted(items, key=lambda value: value["sha256"]):
            member = read_single_aes_zip_member(Path(item["zip_path"]))
            digest = hashlib.sha256(member.data).hexdigest()
            if digest != item["sha256"]:
                raise ValueError(f"inner SHA-256 mismatch: {item['sha256']}")
            static_path = cache / "cases" / digest / "case.json"
            static_case = json.loads(static_path.read_text(encoding="utf-8"))
            extractor_result = extract_family(family, member.data, member.name)
            c2_plan = assess(extractor_result)
            case = build_case(item, static_case, extractor_result, c2_plan, profile)
            cases.append(case)
            case_dir = canonical_malware_case_path(
                output_root, family, digest, "unknown"
            )
            case_links[digest] = Path(
                os.path.relpath(case_dir / "README.md", family_dir)
            ).as_posix()
            write_text(case_dir / "README.md", case_markdown(case))
            write_text(case_dir / "indicators.json", json.dumps(case, ensure_ascii=False, indent=2) + "\n")
            write_text(case_dir / "config.json", json.dumps(extractor_result, ensure_ascii=False, indent=2) + "\n")
            write_text(case_dir / "c2-observation-plan.json", json.dumps(c2_plan, ensure_ascii=False, indent=2) + "\n")
            write_text(case_dir / "IOC-LIST.md", ioc_markdown([digest], case["static_analysis"]["findings"]))
            metadata = _case_layout_metadata(output_root, case_dir, case, run_id)
            write_text(
                case_dir / "metadata.json",
                json.dumps(metadata, ensure_ascii=False, indent=2) + "\n",
            )
            catalog_entries[digest] = {
                "case_id": metadata["case_id"],
                "family": metadata["family"],
                "case_kind": metadata["case_kind"],
                "version_key": metadata["malware_version"]["normalized_key"],
                "canonical_path": metadata["canonical_path"],
            }
            collection_cases.add(digest)
        findings = [item for case in cases for item in case["static_analysis"]["findings"]]
        hashes = [case["source"]["sha256"] for case in cases]
        public_manifest = {"schema_version": 1, "source": "MalwareBazaar exact signature query", "run_id": run_id, "family": family, "items": [case["source"] for case in cases], "sample_executed": False, "network_contacted": False}
        write_text(
            family_dir / "README.md",
            family_markdown(family, profile, cases, case_links),
        )
        write_text(family_dir / "IOC-LIST.md", ioc_markdown(hashes, findings))
        write_text(family_dir / "manifest.json", json.dumps(public_manifest, ensure_ascii=False, indent=2) + "\n")
        write_text(family_dir / "rules" / "yara" / f"{family}_profile.yar", yara_rule(family, profile))
        family_sources.append(
            {
                "family": family,
                "path": family_dir.relative_to(collection_root).as_posix(),
            }
        )
        total_cases += len(cases)
        total_findings += len(findings)
        family_counts[family] = len(cases)
    collection_path = canonical_collection_manifest_path(output_root, run_id)
    collection_manifest = _merged_collection_document(
        collection_path,
        run_id,
        [{"case_id": f"sha256:{digest}"} for digest in sorted(collection_cases)],
        family_sources,
    )
    catalog_document = _merged_catalog_document(output_root, catalog_entries)
    _write_json_documents_atomic(
        {
            output_root / "catalog" / "cases.json": catalog_document,
            collection_path: collection_manifest,
        }
    )
    write_text(
        collection_root / "README.md",
        collection_markdown(collection_manifest),
    )
    return {"families": len(grouped), "cases": total_cases, "findings": total_findings, "family_counts": family_counts, "collection_id": run_id, "sample_executed": False, "network_contacted": False}


def build_parser() -> argparse.ArgumentParser:
    """Build the publish-safe report generation parser."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--cache", type=Path)
    parser.add_argument("--output-root", type=Path, default=REPO / "analysis-results")
    parser.add_argument("--regenerate-run-iocs", action="store_true")
    parser.add_argument("--run-id", default=RUN_ID)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Generate reports and print aggregate counts."""
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.regenerate_run_iocs:
        result = regenerate_run_ioc_lists(args.output_root, args.run_id)
    else:
        if args.manifest is None or args.cache is None:
            parser.error("--manifest and --cache are required unless --regenerate-run-iocs is used")
        result = generate(args.manifest, args.cache, args.output_root, args.run_id)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
