#!/usr/bin/env python3
"""ValleyRAT検体を公開campaignとローカル候補clusterへ静的に関連付ける。"""

from __future__ import annotations

import argparse
from collections import defaultdict
from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Iterable, Mapping


FRAMEWORK_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REGISTRY = FRAMEWORK_ROOT / "registry" / "valleyrat_osint_campaigns.json"
DEFAULT_OUTPUT = (
    FRAMEWORK_ROOT.parent
    / "analysis-results"
    / "research"
    / "campaigns"
    / "valleyrat-20260725"
)
SHA256_RE = re.compile(r"(?<![0-9a-fA-F])([0-9a-fA-F]{64})(?![0-9a-fA-F])")
ENDPOINT_RE = re.compile(
    r"(?<![0-9])((?:[0-9]{1,3}\.){3}[0-9]{1,3})(?::([0-9]{1,5}))?"
)
CAMPAIGN_TYPE_RE = re.compile(r'"campaign_type"\s*:\s*"([^"]+)"')
CASE_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
TEXT_SUFFIXES = {".json", ".md", ".txt", ".yaml", ".yml"}


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON objectではありません: {path}")
    return value


def load_registry(path: Path = DEFAULT_REGISTRY) -> dict[str, Any]:
    """OSINT campaign registryを読み、hash形式とID重複を検証する。"""

    registry = _read_json(path)
    if registry.get("family") != "valleyrat":
        raise ValueError("ValleyRAT registryではありません")
    seen: set[str] = set()
    for campaign in registry.get("public_campaigns", []):
        campaign_id = str(campaign.get("campaign_id", ""))
        if not campaign_id or campaign_id in seen:
            raise ValueError(f"campaign_idが空または重複しています: {campaign_id!r}")
        seen.add(campaign_id)
        for digest in campaign.get("sha256", []):
            if not CASE_SHA_RE.fullmatch(str(digest).lower()):
                raise ValueError(f"不正なSHA-256です: {digest!r}")
        for digest in campaign.get("md5", []):
            if not re.fullmatch(r"[0-9a-f]{32}", str(digest).lower()):
                raise ValueError(f"不正なMD5です: {digest!r}")
    return registry


def discover_cases(repository: Path) -> list[Path]:
    """canonicalなValleyRAT case directoryをSHA-256順で列挙する。"""

    root = (
        repository
        / "analysis-results"
        / "malware"
        / "valleyrat"
        / "versions"
    )
    return sorted(
        path
        for path in root.glob("*/cases/*")
        if path.is_dir() and CASE_SHA_RE.fullmatch(path.name.lower())
    )


def load_malwarebazaar_metadata(repository: Path) -> dict[str, dict[str, Any]]:
    """全collection manifestからValleyRAT metadataをSHA-256別に集約する。"""

    result: dict[str, dict[str, Any]] = {}
    collections = repository / "analysis-results" / "collections"
    for path in sorted(collections.glob("*/sources/valleyrat/malwarebazaar-manifest.json")):
        manifest = _read_json(path)
        collection = path.parents[2].name
        for item in manifest.get("items", []):
            if not isinstance(item, dict):
                continue
            digest = str(item.get("sha256", "")).lower()
            metadata = item.get("metadata")
            if not CASE_SHA_RE.fullmatch(digest) or not isinstance(metadata, dict):
                continue
            merged = dict(metadata)
            merged["_collection"] = collection
            result[digest] = merged
    return result


def _text_artifacts(case_dir: Path) -> Iterable[Path]:
    for path in sorted(case_dir.rglob("*")):
        if (
            path.is_file()
            and path.suffix.lower() in TEXT_SUFFIXES
            and path.stat().st_size <= 16 * 1024 * 1024
        ):
            yield path


def extract_case_evidence(
    case_dir: Path,
    metadata: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """caseの公開済みテキスト成果物だけからhash・endpoint・配布型を抽出する。"""

    digest = case_dir.name.lower()
    hashes = {digest}
    endpoints: set[str] = set()
    campaign_type = "unknown"
    for path in _text_artifacts(case_dir):
        text = path.read_text(encoding="utf-8-sig", errors="replace")
        hashes.update(value.lower() for value in SHA256_RE.findall(text))
        for host, port in ENDPOINT_RE.findall(text):
            octets = [int(item) for item in host.split(".")]
            if any(item > 255 for item in octets):
                continue
            endpoints.add(f"{host}:{port}" if port else host)
        if campaign_type == "unknown" and path.name in {"features.json", "analysis.json"}:
            match = CAMPAIGN_TYPE_RE.search(text)
            if match:
                campaign_type = match.group(1)
    record = dict(metadata or {})
    return {
        "sha256": digest,
        "case_path": case_dir.as_posix(),
        "artifact_sha256": sorted(hashes),
        "md5": str(record.get("md5_hash", "")).lower(),
        "first_seen": record.get("first_seen"),
        "file_name": record.get("file_name"),
        "file_type": record.get("file_type"),
        "imphash": str(record.get("imphash", "")).lower(),
        "tlsh": record.get("tlsh"),
        "tags": sorted(str(item) for item in (record.get("tags") or [])),
        "collection": record.get("_collection"),
        "delivery_pattern": campaign_type,
        "endpoints": sorted(endpoints),
    }


def match_public_campaigns(
    evidence: Mapping[str, Any],
    registry: Mapping[str, Any],
) -> list[dict[str, Any]]:
    """完全hash一致を確定、network indicator一致だけを参考候補として返す。"""

    artifact_hashes = set(evidence.get("artifact_sha256", []))
    root_md5 = str(evidence.get("md5", "")).lower()
    endpoint_hosts = {str(item).split(":", 1)[0] for item in evidence.get("endpoints", [])}
    matches: list[dict[str, Any]] = []
    for campaign in registry.get("public_campaigns", []):
        sha_matches = sorted(artifact_hashes & set(campaign.get("sha256", [])))
        md5_matches = (
            [root_md5]
            if root_md5 and root_md5 in set(campaign.get("md5", []))
            else []
        )
        network_matches = sorted(
            endpoint_hosts & set(campaign.get("network_indicators", []))
        )
        if not sha_matches and not md5_matches and not network_matches:
            continue
        exact = bool(sha_matches or md5_matches)
        matches.append(
            {
                "campaign_id": campaign["campaign_id"],
                "name_ja": campaign["name_ja"],
                "status": (
                    "confirmed_exact_hash"
                    if exact
                    else "supporting_network_match_only"
                ),
                "confidence": "高" if exact else "低",
                "matched_sha256": sha_matches,
                "matched_md5": md5_matches,
                "matched_network_indicators": network_matches,
                "reported_actor": campaign.get("reported_actor"),
                "actor_confidence": campaign.get("actor_confidence"),
                "source_ids": campaign.get("source_ids", []),
            }
        )
    return matches


def build_imphash_clusters(cases: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """同一imphashを持つ複数caseをコード近縁clusterとして生成する。"""

    groups: dict[str, list[str]] = defaultdict(list)
    for case in cases:
        imphash = str(case.get("imphash", "")).lower()
        digest = str(case.get("sha256", "")).lower()
        if imphash and re.fullmatch(r"[0-9a-f]{32}", imphash):
            groups[imphash].append(digest)
    return [
        {
            "campaign_id": f"local-valleyrat-imphash-{imphash[:12]}",
            "name_ja": f"imphash完全一致コードcluster {imphash[:12]}",
            "classification": "local_code_cluster_candidate",
            "confidence": "低",
            "imphash": imphash,
            "members": sorted(set(members)),
            "evidence_ja": [
                f"ルートPEのimphash完全一致: {imphash}",
                "同一コード系統の補助証拠であり、同一配布campaignまたはactorの確定ではない"
            ],
            "actor_status": "未帰属",
        }
        for imphash, members in sorted(groups.items())
        if len(set(members)) >= 2
    ]


def build_attribution(
    cases: list[dict[str, Any]],
    registry: Mapping[str, Any],
) -> dict[str, Any]:
    """case証拠、公開campaign、curated cluster、imphash clusterを統合する。"""

    curated = list(registry.get("curated_local_clusters", []))
    code_clusters = build_imphash_clusters(cases)
    local_by_member: dict[str, list[dict[str, Any]]] = defaultdict(list)
    code_by_member: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for cluster in curated:
        for digest in cluster.get("members", []):
            local_by_member[str(digest).lower()].append(cluster)
    for cluster in code_clusters:
        for digest in cluster["members"]:
            code_by_member[digest].append(cluster)

    records: list[dict[str, Any]] = []
    for case in sorted(cases, key=lambda item: str(item["sha256"])):
        digest = str(case["sha256"])
        public_matches = match_public_campaigns(case, registry)
        confirmed_public = [
            item for item in public_matches if item["status"] == "confirmed_exact_hash"
        ]
        local_clusters = [
            {
                "campaign_id": item["campaign_id"],
                "name_ja": item["name_ja"],
                "classification": item["classification"],
                "confidence": item["confidence"],
                "evidence_ja": item["evidence_ja"],
                "actor_status": item["actor_status"],
            }
            for item in local_by_member.get(digest, [])
        ]
        code_relations = [
            {
                "campaign_id": item["campaign_id"],
                "name_ja": item["name_ja"],
                "confidence": item["confidence"],
                "imphash": item["imphash"],
                "members": item["members"],
            }
            for item in code_by_member.get(digest, [])
        ]
        if confirmed_public:
            status = "confirmed_public_campaign"
        elif local_clusters:
            status = "local_campaign_candidate"
        elif code_relations:
            status = "local_code_cluster_candidate"
        else:
            status = "unresolved"
        community_actor_tags = [
            tag for tag in case.get("tags", []) if tag.casefold() == "silverfox"
        ]
        records.append(
            {
                **case,
                "status": status,
                "public_campaign_matches": public_matches,
                "local_campaign_candidates": local_clusters,
                "code_cluster_relations": code_relations,
                "actor_assessment": {
                    "status": (
                        "source_reported_for_exact_campaign"
                        if confirmed_public
                        and any(item.get("reported_actor") for item in confirmed_public)
                        else "unresolved"
                    ),
                    "community_tags_not_used_for_attribution": community_actor_tags,
                },
            }
        )

    status_counts: dict[str, int] = defaultdict(int)
    for item in records:
        status_counts[item["status"]] += 1
    public_counts = {
        campaign["campaign_id"]: sum(
            1
            for case in records
            for match in case["public_campaign_matches"]
            if match["campaign_id"] == campaign["campaign_id"]
            and match["status"] == "confirmed_exact_hash"
        )
        for campaign in registry.get("public_campaigns", [])
    }
    return {
        "schema_version": 1,
        "generated_at": datetime.now(UTC).isoformat(),
        "family": "valleyrat",
        "method": {
            "public_confirmation": "公開IOCとのSHA-256またはMD5完全一致",
            "local_campaign": "curated親子関係または固有構成",
            "code_relation": "ルートPEのimphash完全一致。campaign確定には不使用",
            "actor_policy": "community tag単独では帰属しない",
        },
        "counts": {
            "cases": len(records),
            "by_status": dict(sorted(status_counts.items())),
            "public_campaign_exact_matches": sum(public_counts.values()),
            "curated_local_clusters": len(curated),
            "imphash_code_clusters": len(code_clusters),
        },
        "public_campaign_match_counts": public_counts,
        "curated_local_clusters": curated,
        "imphash_code_clusters": code_clusters,
        "cases": records,
        "safety": {
            "samples_opened": False,
            "samples_executed": False,
            "network_contacted": False,
            "source_scope": "repository_text_artifacts_and_public_osint_only",
        },
    }


def _case_link(output_root: Path, case_path: str) -> str:
    repository = output_root.parents[3]
    absolute = repository / Path(case_path)
    return Path(
        *(
            [".."] * len(output_root.relative_to(repository).parts)
            + list(absolute.relative_to(repository).parts)
        )
    ).as_posix()


def _render_readme(
    report: Mapping[str, Any],
    registry: Mapping[str, Any],
) -> str:
    counts = report["counts"]
    status = counts["by_status"]
    lines = [
        "# ValleyRAT campaign帰属試行",
        "",
        "## 結論",
        "",
        f"canonical case `{counts['cases']}`件を公開OSINTと照合しました。"
        f" 公開campaignのhash完全一致は`{counts['public_campaign_exact_matches']}`件です。",
        "完全一致しない検体を既知actorへ押し込まず、ローカルで親子関係または固有構成が確認済みのものだけをcampaign候補へ分けました。",
        "",
        "## 分類結果",
        "",
        "| 状態 | 件数 | 意味 |",
        "|---|---:|---|",
        f"| 公開campaign完全一致 | {status.get('confirmed_public_campaign', 0)} | 公開SHA-256またはMD5との完全一致 |",
        f"| ローカルcampaign候補 | {status.get('local_campaign_candidate', 0)} | 親子hashまたは固有の配布chainをレビュー済み |",
        f"| コードcluster候補のみ | {status.get('local_code_cluster_candidate', 0)} | imphash完全一致。campaign確定ではない |",
        f"| 未解決 | {status.get('unresolved', 0)} | 帰属に足る強い共有証拠なし |",
        "",
        "詳細は[全case一覧](CASES.md)、[公開OSINT campaign照合](OSINT-CAMPAIGNS.md)、"
        "[判定規則](rules/README.md)を参照してください。",
        "",
        "## 重要な解釈",
        "",
        "- 既存の`campaign_type`は解析handlerを選ぶ配布・構造分類であり、攻撃campaign名ではありません。",
        "- MalwareBazaarの`SilverFox`はcommunity tagとして保持しますが、actor帰属には使用しません。",
        "- ValleyRAT builderが広く利用可能であるため、ValleyRAT検出だけでSilver Fox、TA4922、その他のactorを決めません。",
        "- imphash一致はコード近縁性の手掛かりです。同一operator、同一配布、同一期間を意味しません。",
        "",
        "## ローカルcandidate cluster",
        "",
    ]
    for cluster in report["curated_local_clusters"]:
        lines.append(
            f"- [{cluster['name_ja']}](local-candidates/{cluster['campaign_id']}/README.md): "
            f"{len(cluster['members'])}件、確度`{cluster['confidence']}`"
        )
    lines.extend(
        [
            "",
            "## 安全性",
            "",
            "この処理は既存の公開済み解析成果物とOSINT registryだけを読みます。"
            "検体実行、C2接続、外部サービスへの検体送信は行いません。",
            "",
        ]
    )
    return "\n".join(lines)


def _render_osint(report: Mapping[str, Any], registry: Mapping[str, Any]) -> str:
    lines = [
        "# 公開OSINT campaign照合",
        "",
        "hash完全一致を最優先しました。network、lure、配布方式だけの類似は確定扱いにしません。",
        "",
        "| campaign | 期間 | 報告actor | 完全一致case |",
        "|---|---|---|---:|",
    ]
    counts = report["public_campaign_match_counts"]
    for campaign in registry["public_campaigns"]:
        lines.append(
            f"| `{campaign['campaign_id']}` / {campaign['name_ja']} | "
            f"{campaign['period']} | {campaign.get('reported_actor') or '未帰属'} | "
            f"{counts[campaign['campaign_id']]} |"
        )
    lines.extend(["", "## 参照資料", ""])
    for source in registry["sources"]:
        lines.append(f"- [原題: {source['title']}]({source['url']})")
    lines.extend(
        [
            "",
            "## 帰属上の注意",
            "",
            "Proofpointは2023年のValleyRAT活動を複数の異なる活動集合として扱っています。"
            "ITOCHU C&Iも日本語malspamの攻撃者属性を確定していません。"
            "Check PointとLevelBlueの調査が示すbuilder流通も考慮し、family一致をactor一致へ昇格させません。",
            "",
        ]
    )
    return "\n".join(lines)


def _render_cases(report: Mapping[str, Any], output_root: Path) -> str:
    lines = [
        "# ValleyRAT全caseのcampaign判定",
        "",
        "| SHA-256 | 観測名 | 配布・解析pattern | 判定 | campaign候補 |",
        "|---|---|---|---|---|",
    ]
    for case in report["cases"]:
        campaigns = [
            item["campaign_id"] for item in case["public_campaign_matches"]
            if item["status"] == "confirmed_exact_hash"
        ]
        campaigns.extend(
            item["campaign_id"] for item in case["local_campaign_candidates"]
        )
        if not campaigns:
            campaigns.extend(
                item["campaign_id"] for item in case["code_cluster_relations"]
            )
        link = _case_link(output_root, case["case_path"])
        name = str(case.get("file_name") or "metadataなし").replace("|", "\\|")
        lines.append(
            f"| [`{case['sha256'][:12]}…`]({link}/README.md) | {name} | "
            f"`{case['delivery_pattern']}` | `{case['status']}` | "
            f"{', '.join(f'`{item}`' for item in campaigns) or 'なし'} |"
        )
    lines.extend(
        [
            "",
            "community tag、ファイル名、取得日時だけではcampaignを確定していません。",
            "",
        ]
    )
    return "\n".join(lines)


def _render_cluster(
    cluster: Mapping[str, Any],
    by_sha: Mapping[str, Mapping[str, Any]],
    output_root: Path,
) -> str:
    lines = [
        f"# {cluster['name_ja']}",
        "",
        f"- ID: `{cluster['campaign_id']}`",
        f"- 分類: `{cluster['classification']}`",
        f"- 確度: `{cluster['confidence']}`",
        f"- actor: `{cluster['actor_status']}`",
        "",
        "## 根拠",
        "",
    ]
    lines.extend(f"- {item}" for item in cluster["evidence_ja"])
    lines.extend(["", "## 検体", ""])
    for digest in cluster["members"]:
        case = by_sha.get(digest)
        if not case:
            lines.append(f"- `{digest}`: canonical caseなし")
            continue
        link = _case_link(output_root, str(case["case_path"]))
        lines.append(
            f"- [`{digest}`]({link}/README.md) — "
            f"観測名: {case.get('file_name') or '観測ファイル名なし'}"
        )
    lines.extend(
        [
            "",
            "このcluster名はローカル解析用です。公開actorまたは既知campaignへの帰属を意味しません。",
            "",
        ]
    )
    return "\n".join(lines)


def _render_rules(registry: Mapping[str, Any]) -> str:
    return "\n".join(
        [
            "# ValleyRAT campaign自動判定規則",
            "",
            "## 優先順位",
            "",
            "1. 公開資料のSHA-256またはMD5完全一致",
            "2. レビュー済みの親子hash・固有配布chain",
            "3. imphash完全一致のコード近縁cluster",
            "4. 上記がなければ未解決",
            "",
            "network IOCだけの一致、ファイル名、取得時期、community tag、"
            "genericなDLL side-loadingだけでは公開campaignを確定しません。",
            "",
            "## actorの扱い",
            "",
            registry["policy"]["actor_attribution"],
            "",
            "公開campaignに完全一致し、その資料がactorを報告している場合も、"
            "`source_reported_for_exact_campaign`として情報源依存であることを残します。",
            "",
            "## 実行方法",
            "",
            "```powershell",
            "python .\\analysis-framework\\common\\attribute_valleyrat_campaigns.py --repository . --write",
            "python .\\analysis-framework\\common\\attribute_valleyrat_campaigns.py --repository . --check",
            "```",
            "",
        ]
    )


def build_documents(
    report: Mapping[str, Any],
    registry: Mapping[str, Any],
    output_root: Path,
) -> dict[Path, str]:
    """帰属reportから日本語Markdownとmachine-readable JSONを構築する。"""

    stable_report = dict(report)
    stable_report["generated_at"] = "generated-deterministically"
    documents = {
        output_root / "README.md": _render_readme(report, registry),
        output_root / "OSINT-CAMPAIGNS.md": _render_osint(report, registry),
        output_root / "CASES.md": _render_cases(report, output_root),
        output_root / "rules" / "README.md": _render_rules(registry),
        output_root / "case-attributions.json": (
            json.dumps(stable_report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        ),
    }
    by_sha = {item["sha256"]: item for item in report["cases"]}
    for cluster in report["curated_local_clusters"]:
        documents[
            output_root
            / "local-candidates"
            / cluster["campaign_id"]
            / "README.md"
        ] = _render_cluster(cluster, by_sha, output_root)
    return {path: text.rstrip() + "\n" for path, text in documents.items()}


def apply_documents(documents: Mapping[Path, str], *, check: bool) -> list[str]:
    """生成文書を書き込むか、既存内容との差分を検査する。"""

    differences: list[str] = []
    for path, text in sorted(documents.items(), key=lambda item: str(item[0])):
        current = path.read_text(encoding="utf-8") if path.is_file() else None
        if current == text:
            continue
        differences.append(str(path))
        if not check:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8", newline="\n")
    return differences


def run(
    repository: Path,
    registry_path: Path,
    output_root: Path,
) -> tuple[dict[str, Any], dict[Path, str]]:
    """repositoryを走査し、帰属reportと生成予定文書を返す。"""

    repository = repository.resolve()
    registry = load_registry(registry_path.resolve())
    metadata = load_malwarebazaar_metadata(repository)
    cases = [
        extract_case_evidence(path, metadata.get(path.name.lower()))
        for path in discover_cases(repository)
    ]
    for case in cases:
        case["case_path"] = (
            Path(case["case_path"]).resolve().relative_to(repository).as_posix()
        )
    report = build_attribution(cases, registry)
    documents = build_documents(report, registry, output_root.resolve())
    return report, documents


def main(argv: list[str] | None = None) -> int:
    """CLI entry point。write、check、dry-runを安全に切り替える。"""

    parser = argparse.ArgumentParser(
        description="ValleyRAT caseを公開OSINT campaignとローカル候補へ分類する"
    )
    parser.add_argument("--repository", type=Path, default=FRAMEWORK_ROOT.parent)
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--write", action="store_true", help="生成結果を書き込む")
    mode.add_argument("--check", action="store_true", help="既存生成結果との差分を検査する")
    args = parser.parse_args(argv)

    report, documents = run(args.repository, args.registry, args.output_root)
    if args.write or args.check:
        differences = apply_documents(documents, check=args.check)
        if args.check and differences:
            for path in differences:
                print(f"差分: {path}")
            return 1
    print(
        json.dumps(
            {
                "cases": report["counts"]["cases"],
                "by_status": report["counts"]["by_status"],
                "public_campaign_exact_matches": report["counts"][
                    "public_campaign_exact_matches"
                ],
                "document_sha256": {
                    str(path): hashlib.sha256(text.encode("utf-8")).hexdigest()
                    for path, text in documents.items()
                },
                "write_performed": bool(args.write),
                "check_performed": bool(args.check),
            },
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
