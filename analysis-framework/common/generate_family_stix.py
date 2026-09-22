#!/usr/bin/env python3
"""公開済み解析と出典付きOSINTからファミリー別STIX 2.1を生成する。"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import date
import json
from itertools import combinations
from pathlib import Path
import re
import uuid
from typing import Any, Iterator

from render_malware_family_docs import _load_knowledge, _validate_family_knowledge


BASE_URL = "https://github.com/proshiba/AI-security-analysis/blob/main/"
NAMESPACE = uuid.UUID("2f00bbf9-e8bd-43e4-976a-790b9a479761")
EXCLUDED_FAMILIES = {
    "unclassified", "screenconnect-rmm", "xmrig",
    "credential-phishing-html", "manageengine-endpoint-central-abuse",
    "infrastructure-decoy-hta",
    "linux-downloader", "linux-reverse-shell", "mig-logcleaner",
}
DISCOVERY_ONLY = re.compile(r"MalwareBazaar|VirusTotal|Triage|投稿検体|収集元|提出ファイル名")
NON_ATTACK_HISTORY = re.compile(r"逮捕|押収|国際捜査|Operation Magnus|Operation Endgame")
SENSITIVE_OVERVIEW = re.compile(r"https?://|[0-9a-fA-F]{64}|[A-Za-z]:\\|@[A-Za-z0-9.-]+|(?:\d{1,3}\.){3}\d{1,3}")
INLINE_SOURCE = re.compile(r"\[\[[a-z0-9-]+\]\]")
GENERIC_ACTOR = re.compile(
    r"不特定|未特定|未帰属|複数|多数|購入者|アフィリエイト|配布者|運用者|犯罪者|正規の|顧客|販売者|支持派"
)
GENERIC_ROLES = {
    "compiler_or_library_code", "entry_point", "entrypoint", "export_entry",
    "general_internal_logic", "runtime_initialization", "unknown",
}
TECHNICAL_CLUSTERS = {
    # 複数検体を技法で束ねた暫定分類。STIX malware instance/familyのどちらでもない。
    "dotnet-resource-loader", "nsis-obfuscated-loader", "png-registry-loader",
    "protected-pe-loader", "windows-script-stager",
}
STRONG_CLASSIFICATION_BASIS = re.compile(
    r"^(?:known_|reviewed_|exact_|reconstructed_|terminal_|decoded_|recovered_|manual_)"
)
GENERIC_FUNCTION_NAME = re.compile(
    r"^(?:FUN_|sub_|fcn\.|DelayLoad_|runtime[./]|internal/|type:\.|reflect[./]|"
    r"sync[./]|crypto/|math[./]|net[./]|encoding/|os[./]|fmt[./]|"
    r"strings[./]|bytes[./]|syscall[./]|time[./]|unicode/|strconv[./]|"
    r"slices[./]|maps[./]|iter[./]|cmp[./]|errors[./]|path[./]|"
    r"io[./]|bufio[./]|hash[./]|log[./]|text[./]|database/|archive/|"
    r"compress/|container/|debug/|embed[./]|flag[./]|html[./]|image[./]|"
    r"index/|mime[./]|plugin[./]|regexp[./]|sort[./]|testing[./]|"
    r"unsafe[./]|vendor/|go[./]|System\.|Microsoft\.|AgGateway\.|"
    r"MessagePackLib\.|SecurityDriven\.|Virtuaxel\.|<>c__|<Module>|"
    r"<PrivateImplementationDetails>)|\.InitializeComponent$|^get_ResourceManager$",
    re.IGNORECASE,
)
DIMENSIONS = ("execution_stages", "layer_chain", "module_stack", "capabilities", "function_roles")
MODEL_LABELS = {
    "maas": "business-model:maas",
    "commercial_service": "business-model:commercial-service",
    "commodity": "business-model:commodity",
    "open_source_dual_use": "business-model:open-source",
    "freeware_dual_use": "business-model:freeware",
    "restricted_criminal_tool": "business-model:restricted",
}
CONFIDENCE = {"high": 80, "medium": 50, "low": 20}


def _identifier(kind: str, key: str) -> str:
    return f"{kind}--{uuid.uuid5(NAMESPACE, kind + ':' + key)}"


def _object(kind: str, key: str, timestamp: str, **fields: Any) -> dict[str, Any]:
    return {
        "type": kind,
        "spec_version": "2.1",
        "id": _identifier(kind, key),
        "created": timestamp,
        "modified": timestamp,
        **fields,
    }


def _clean(text: str) -> str:
    return " ".join(INLINE_SOURCE.sub("", text).split())


def _references(family: dict[str, Any], ids: list[str] | None = None) -> list[dict[str, str]]:
    available = {source["id"]: source for source in family["sources"]}
    selected = sorted(set(ids or available))
    result = []
    for source_id in selected:
        source = available[source_id]
        result.append({
            "source_name": source["publisher"],
            "description": f"{source.get('title_ja', source.get('title', source.get('title_original', '公開資料')))} ({source_id})",
            "url": source["url"],
        })
    return result


def _local_reference(family_id: str, filename: str) -> dict[str, str]:
    return {
        "source_name": "AI-security-analysis",
        "description": f"{family_id} 公開静的解析",
        "url": BASE_URL + f"analysis-results/malware/{family_id}/{filename}",
    }


def _named_actor(name: str) -> bool:
    # 斜線併記は別名か別主体か自動確定できず、包括的な集団名もSDOへ昇格しない。
    return not GENERIC_ACTOR.search(name) and "/" not in name and "・" not in name and bool(name.strip())


def _assert_attack_history(summary: str) -> bool:
    """検体を発見しただけの経路を攻撃履歴へ転記しない。"""
    return not DISCOVERY_ONLY.search(summary) and not NON_ATTACK_HISTORY.search(summary)


def _load_catalog(path: Path) -> dict[str, list[str]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data.get("cases"), dict):
        raise ValueError("case catalogの構造が不正")
    cases: dict[str, list[str]] = defaultdict(list)
    for sha, item in data["cases"].items():
        family = item.get("family")
        if family in EXCLUDED_FAMILIES or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", str(family)):
            continue
        if not re.fullmatch(r"[0-9a-f]{64}", sha) or item.get("case_kind") != "malware":
            continue
        if not str(item.get("canonical_path", "")).startswith(f"analysis-results/malware/{family}/"):
            raise ValueError(f"case catalogのfamily/pathが不一致: {sha}")
        cases[family].append(sha)
    return {key: sorted(value) for key, value in cases.items()}


def _strong_case_hashes(repository: Path, cases: dict[str, list[str]]) -> set[str]:
    """配置先ラベルとは独立に、case報告が強いファミリー根拠を持つものだけ返す。"""
    approved: set[str] = set()
    for family, hashes in cases.items():
        for sha in hashes:
            report_path = repository / "analysis-results/malware" / family
            # case catalogは既にfamily/path整合性を検証済み。版は可変なのでhash名で探索する。
            for candidate in report_path.glob(f"versions/*/cases/{sha}/report.json"):
                try:
                    classification = json.loads(candidate.read_text(encoding="utf-8")).get("classification", {})
                except (OSError, UnicodeError, json.JSONDecodeError):
                    continue
                if (classification.get("family") == family
                        and classification.get("confidence") == "high"
                        and STRONG_CLASSIFICATION_BASIS.match(str(classification.get("selection_basis") or ""))):
                    approved.add(sha)
                    break
    return approved


def _local_overview(path: Path) -> str | None:
    """公開済みfamily READMEから最初の安全な説明段落を採用する。"""
    lines = path.read_text(encoding="utf-8").splitlines()[:120]
    heading_seen = False
    paragraph: list[str] = []

    def safe_paragraph() -> str | None:
        value = _clean(" ".join(paragraph)).replace("`", "")
        if (not value or len(value) > 600 or DISCOVERY_ONLY.search(value)
                or SENSITIVE_OVERVIEW.search(value) or "知識が未登録" in value
                or value.startswith(("詳細は[", "カタログ登録は", "このディレクトリには"))):
            return None
        return "公開済みローカル概要: " + value

    for line in lines:
        stripped = line.strip()
        if not heading_seen:
            heading_seen = stripped.startswith("# ")
            continue
        if not stripped or stripped.startswith(("#", "-", "|", "[", "<!--")):
            if paragraph:
                candidate = safe_paragraph()
                if candidate:
                    return candidate
                paragraph = []
            continue
        paragraph.append(stripped)
    return safe_paragraph()


def _static_features(path: Path, families: set[str], approved_hashes: set[str]) -> dict[str, dict[str, Counter[str]]]:
    if not path.is_file():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    profiles = data.get("profiles", {})
    if not isinstance(profiles, dict):
        raise ValueError("logic-similarity profilesが不正")
    result: dict[str, dict[str, Counter[str]]] = defaultdict(lambda: defaultdict(Counter))
    for profile in profiles.values():
        family = profile.get("family")
        if family not in families or profile.get("sha256") not in approved_hashes:
            continue
        dimensions = profile.get("dimensions", {})
        for dimension in DIMENSIONS:
            values = dimensions.get(dimension, [])
            if not isinstance(values, list):
                continue
            for value in sorted({value for value in values if isinstance(value, str)}):
                if (len(value) <= 100
                        and not value.startswith(("analysis:", "packing:", "unpack:", "config:"))
                        and value not in {"root:unknown", "builder:version"}):
                    result[family][dimension][value] += 1
    return result


def _iter_array_objects(path: Path, key: str) -> Iterator[dict[str, Any]]:
    """整形済み大容量索引から、指定top-level配列だけを有界メモリで読む。"""
    marker = f'  "{key}": ['
    inside = False
    buffer: list[str] = []
    with path.open("r", encoding="utf-8") as source:
        for line in source:
            if not inside:
                if line.rstrip() == marker:
                    inside = True
                continue
            if line.startswith("  ]"):
                return
            if line.startswith("    {"):
                if buffer:
                    raise ValueError(f"{key}: object境界が不正")
                buffer = [line]
            elif buffer:
                buffer.append(line)
                if line.startswith("    }"):
                    yield json.loads("".join(buffer).rstrip().removesuffix(","))
                    buffer = []
    if not inside or buffer:
        raise ValueError(f"{key}: 配列が欠落または途中で終了")


def _code_groups(
    path: Path, families: set[str], repository: Path, approved_hashes: set[str],
) -> tuple[dict[str, list[dict[str, Any]]], dict[tuple[str, str], list[dict[str, Any]]]]:
    if not path.is_file():
        return {}, {}
    groups = [group for group in _iter_array_objects(path, "exact_groups") if 2 <= len(group.get("members", [])) <= 12]
    required = {member for group in groups for member in group["members"]}
    records: dict[str, dict[str, Any]] = {}
    for record in _iter_array_objects(path, "function_records"):
        source = str(record.get("source") or "")
        # function_records.sha256は復元された内部layer hashのことがある。
        # case分類は公開caseのディレクトリ名で照合する。
        case_sha = Path(source).parent.name
        if (record.get("record_id") in required and record.get("family") in families
                and re.fullmatch(r"[0-9a-f]{64}", case_sha)
                and case_sha in approved_hashes):
            record["case_sha256"] = case_sha
            records[record["record_id"]] = record
    source_cache: dict[str, dict[str, dict[str, Any]]] = {}
    repository = repository.resolve()

    def verified_function(record: dict[str, Any]) -> str | None:
        """元の静的関数に遡り、ランタイム/共通SDKや推定関数を除外する。"""
        source = str(record.get("source") or "")
        if not source.startswith("analysis-results/malware/") or ".." in Path(source).parts:
            return None
        if source not in source_cache:
            source_path = (repository / source).resolve()
            if not source_path.is_relative_to(repository) or not source_path.is_file():
                source_cache[source] = {}
            else:
                try:
                    report = json.loads(source_path.read_text(encoding="utf-8"))
                    source_cache[source] = {
                        str(function.get("function_id")): function
                        for function in report.get("functions", []) if isinstance(function, dict)
                    }
                except (OSError, UnicodeError, json.JSONDecodeError):
                    source_cache[source] = {}
        function = source_cache[source].get(str(record.get("function_id")))
        if not function:
            return None
        name = str(function.get("name") or "")
        evidence = function.get("evidence") or {}
        fingerprints = function.get("fingerprints") or {}
        normalized = str(fingerprints.get("normalized_logic_sha256") or "")
        if (not name or GENERIC_FUNCTION_NAME.search(name)
                or evidence.get("source") not in {"ghidra-mcp", "dnfile/dncil"}
                or not str(evidence.get("confidence") or "").startswith("confirmed_static_")
                or not re.fullmatch(r"[0-9a-f]{64}", normalized)):
            return None
        return normalized

    for record_id, record in list(records.items()):
        normalized = verified_function(record)
        if normalized is None:
            del records[record_id]
        else:
            record["normalized_logic_sha256"] = normalized
    within: dict[str, list[dict[str, Any]]] = defaultdict(list)
    across: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for group in groups:
        members = [records[member] for member in group["members"] if member in records]
        members = [item for item in members if item.get("semantic_token_count", 0) >= 16 and item.get("role") not in GENERIC_ROLES]
        digest = group.get("semantic_sequence_sha256", "")
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            continue
        by_normalized: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for member in members:
            by_normalized[member["normalized_logic_sha256"]].append(member)
        for normalized, exact_members in by_normalized.items():
            by_family: dict[str, list[dict[str, Any]]] = defaultdict(list)
            for member in exact_members:
                by_family[member["family"]].append(member)
            for family, entries in by_family.items():
                if len({entry["case_sha256"] for entry in entries}) >= 2:
                    within[family].append({"fingerprint": digest, "normalized_logic_sha256": normalized, "role": entries[0]["role"], "case_count": len({entry["case_sha256"] for entry in entries})})
            for left, right in combinations(sorted(by_family), 2):
                left_roles = {entry["role"] for entry in by_family[left]}
                right_roles = {entry["role"] for entry in by_family[right]}
                if not left_roles & right_roles:
                    continue
                across[left, right].append({
                    "fingerprint": digest,
                    "normalized_logic_sha256": normalized,
                    "role": sorted(left_roles & right_roles)[0],
                    "left_sha256": by_family[left][0]["case_sha256"],
                    "right_sha256": by_family[right][0]["case_sha256"],
                })
    return dict(within), dict(across)


def _validate_bundle(bundle: dict[str, Any]) -> None:
    """生成Bundle内の必須値、ID、参照を外部通信なしで検証する。"""
    if bundle.get("type") != "bundle" or not isinstance(bundle.get("objects"), list):
        raise ValueError("STIX Bundleの基本構造が不正")
    objects = bundle["objects"]
    by_id = {item["id"]: item for item in objects}
    if len(by_id) != len(objects) or not any(item.get("type") == "malware" for item in objects):
        raise ValueError("STIX object ID重複またはmalware欠落")
    required = {
        "malware": {"name", "is_family"},
        "note": {"content", "object_refs"},
        "threat-actor": {"name"},
        "campaign": {"name"},
        "relationship": {"relationship_type", "source_ref", "target_ref"},
        "report": {"name", "published", "object_refs", "report_types"},
    }
    for item in objects:
        kind = item.get("type")
        if kind not in required or not required[kind] <= item.keys():
            raise ValueError(f"STIX objectの必須値が不正: {kind}")
        if item.get("spec_version") != "2.1" or not re.fullmatch(rf"{re.escape(kind)}--[0-9a-f]{{8}}-[0-9a-f]{{4}}-[1-5][0-9a-f]{{3}}-[89ab][0-9a-f]{{3}}-[0-9a-f]{{12}}", item["id"]):
            raise ValueError(f"STIX IDまたは版が不正: {item.get('id')}")
        if item.get("created", "") > item.get("modified", ""):
            raise ValueError(f"STIX created/modifiedが不正: {item['id']}")
        confidence = item.get("confidence")
        if confidence is not None and (type(confidence) is not int or not 0 <= confidence <= 100):
            raise ValueError(f"STIX confidenceが不正: {item['id']}")
        for ref in item.get("object_refs", []):
            if ref not in by_id:
                raise ValueError(f"Bundle内に参照先がない: {ref}")
        if kind == "relationship" and (item["source_ref"] not in by_id or item["target_ref"] not in by_id):
            raise ValueError(f"STIX Relationshipの参照先がない: {item['id']}")
        for source in item.get("external_references", []):
            if not source.get("source_name") or not str(source.get("url", "")).startswith("https://"):
                raise ValueError(f"STIX出典が不正: {item['id']}")


def _reconcile_versions(bundle: dict[str, Any], previous_path: Path, timestamp: str) -> None:
    """既存Bundleと同じobject IDでは初出時刻を保持し、未変更objectの版を増やさない。"""
    if not previous_path.is_file():
        return
    previous = json.loads(previous_path.read_text(encoding="utf-8"))
    if previous.get("type") != "bundle" or not isinstance(previous.get("objects"), list):
        raise ValueError(f"既存STIX Bundleが不正: {previous_path.name}")
    old_by_id = {item["id"]: item for item in previous["objects"]}
    if len(old_by_id) != len(previous["objects"]):
        raise ValueError(f"既存STIX object IDが重複: {previous_path.name}")
    for item in bundle["objects"]:
        old = old_by_id.get(item["id"])
        if old is None:
            continue
        if old.get("type") != item["type"] or not old.get("created") or not old.get("modified"):
            raise ValueError(f"既存STIX objectの版が不正: {item['id']}")
        item["created"] = old["created"]
        new_content = {key: value for key, value in item.items() if key not in {"created", "modified"}}
        old_content = {key: value for key, value in old.items() if key not in {"created", "modified"}}
        if new_content == old_content:
            item["modified"] = old["modified"]
        elif timestamp < old["modified"]:
            raise ValueError(f"既存STIX版より過去の日付への変更は不可: {item['id']}")


def _family_objects(
    family_id: str,
    knowledge: dict[str, Any] | None,
    case_hashes: list[str],
    features: dict[str, Counter[str]],
    code_within: list[dict[str, Any]],
    code_across: list[tuple[str, list[dict[str, Any]]]],
    campaigns: list[dict[str, Any]],
    developers: list[dict[str, Any]],
    timestamp: str,
    local_overview: str | None = None,
) -> list[dict[str, Any]]:
    objects: list[dict[str, Any]] = []
    name = knowledge["display_name"] if knowledge else family_id
    overview = _clean(knowledge["overview_ja"]) if knowledge else (local_overview or "出典付きのファミリー別OSINT知識は未登録。静的解析結果のみを参照する。")
    if DISCOVERY_ONLY.search(overview):
        overview = "攻撃時の機能・経路は関連する静的解析を参照する。発見経路は除外した。"
    refs = [_local_reference(family_id, "README.md")]
    if knowledge:
        refs += _references(knowledge)
    malware = _object(
        "malware", family_id, timestamp, name=name, description=overview, is_family=True,
        aliases=knowledge.get("aliases", []) if knowledge else [],
        external_references=refs,
        lang="ja",
    )
    if knowledge:
        label = MODEL_LABELS.get(knowledge["commodity"]["classification"])
        if label:
            malware["labels"] = [label]
    objects.append(malware)
    malware_id = malware["id"]

    def add_note(key: str, content: str, refs_for_note: list[dict[str, str]], targets: list[str] | None = None, confidence: int | None = None) -> None:
        fields: dict[str, Any] = {
            "content": content,
            "object_refs": targets or [malware_id],
            "external_references": refs_for_note,
            "lang": "ja",
        }
        if confidence is not None:
            fields["confidence"] = confidence
        objects.append(_object("note", f"{family_id}:{key}", timestamp, **fields))

    if knowledge is None:
        add_note(
            "osint-unregistered",
            "本STIXでは、出典付きの開発者・利用者・OSS／商用／MaaS提供形態・特定アクター専用性・攻撃利用史は未登録。情報が存在しないことを意味しない。",
            [_local_reference(family_id, "README.md")],
        )

    if knowledge:
        developer = knowledge["developer"]
        add_note("developer", "開発主体: " + _clean(developer["assessment_ja"]), _references(knowledge, developer["source_ids"]), confidence=CONFIDENCE[developer["confidence"]])
        for author in developers:
            author_id = _identifier("threat-actor", author["name"])
            objects.append(_object("threat-actor", author["name"], timestamp, name=author["name"], lang="ja"))
            objects.append(_object(
                "relationship", f"{family_id}:authored-by:{author['name']}", timestamp,
                relationship_type="authored-by", source_ref=malware_id, target_ref=author_id,
                description=author["description_ja"], confidence=CONFIDENCE[author["confidence"]],
                external_references=_references(knowledge, author["source_ids"]), lang="ja",
            ))
        commodity = knowledge["commodity"]
        add_note("business-model", "提供形態: " + commodity["classification"] + "。" + _clean(commodity["assessment_ja"]), _references(knowledge, commodity["source_ids"]))
        dedicated = "単一アクター専用ではないと報告されている。" if re.search(r"単一.{0,10}専用ではない|単一.{0,10}限定.{0,6}ない|複数.{0,20}利用", commodity["assessment_ja"]) else "公開根拠からは未確認。利用アクターの存在だけで専用性を推定しない。"
        add_note("dedication", "特定アクター専用性: " + dedicated, _references(knowledge, commodity["source_ids"]))
        for index, actor in enumerate(knowledge["actors"]):
            actor_name = actor["name"]
            actor_refs = _references(knowledge, actor["source_ids"])
            targets = [malware_id]
            if _named_actor(actor_name):
                actor_obj = _object("threat-actor", actor_name, timestamp, name=actor_name, lang="ja")
                if actor_obj["id"] not in {obj["id"] for obj in objects}:
                    objects.append(actor_obj)
                targets.append(actor_obj["id"])
                # 不確実なOSINTを機械的に「uses」の確定関係へ昇格しない。
                statement = actor["relationship_ja"]
                if re.search(r"利用|使用|配布|展開", statement) and not re.search(r"可能性|疑い|未確認|不明", statement):
                    objects.append(_object(
                        "relationship", f"{family_id}:uses:{actor_name}", timestamp,
                        relationship_type="uses", source_ref=actor_obj["id"], target_ref=malware_id,
                        description=_clean(statement), external_references=actor_refs,
                        confidence=CONFIDENCE[actor["confidence"]], lang="ja",
                    ))
            add_note(f"actor:{index}", "利用主体に関する公開報告: " + actor_name + "。" + _clean(actor["relationship_ja"]), actor_refs, targets, CONFIDENCE[actor["confidence"]])
        for index, event in enumerate(knowledge["historical_use"]):
            summary = _clean(event["summary_ja"])
            if not _assert_attack_history(summary):
                continue
            text = f"攻撃利用履歴（{event['period']}）: {summary}"
            if event["actors"]:
                text += " 報告された主体: " + "、".join(event["actors"]) + "。"
            add_note(f"history:{index}", text, _references(knowledge, event["source_ids"]))

        for campaign in campaigns:
            campaign_refs = _references(knowledge, campaign["source_ids"])
            campaign_obj = _object(
                "campaign", f"{family_id}:{campaign['name']}", timestamp,
                name=campaign["name"], description=campaign["description_ja"],
                external_references=campaign_refs,
                confidence=CONFIDENCE[campaign["confidence"]], lang="ja",
            )
            objects.append(campaign_obj)
            objects.append(_object(
                "relationship", f"{family_id}:campaign-uses:{campaign['name']}", timestamp,
                relationship_type="uses", source_ref=campaign_obj["id"], target_ref=malware_id,
                external_references=campaign_refs,
                confidence=CONFIDENCE[campaign["confidence"]],
            ))
            for actor_name in campaign.get("attributed_actor_names", []):
                objects.append(_object(
                    "relationship", f"{family_id}:campaign-attributed-to:{campaign['name']}:{actor_name}", timestamp,
                    relationship_type="attributed-to", source_ref=campaign_obj["id"],
                    target_ref=_identifier("threat-actor", actor_name),
                    description=campaign["attribution_ja"],
                    external_references=campaign_refs,
                    confidence=CONFIDENCE[campaign["attribution_confidence"]], lang="ja",
                ))

    if features:
        lines = [f"公開済み{len(case_hashes)}件のcaseに対応する静的比較プロファイルから集計した特徴。件数は観測case数であり、全版共通の断定ではない。"]
        for dimension in DIMENSIONS:
            selected = sorted(features.get(dimension, Counter()).items(), key=lambda item: (-item[1], item[0]))[:12]
            if selected:
                lines.append(dimension + ": " + "、".join(f"{value} ({count}件)" for value, count in selected))
        add_note("static-features", "\n".join(lines), [_local_reference(family_id, "README.md"), {
            "source_name": "AI-security-analysis", "description": "静的ロジック比較プロファイル", "url": BASE_URL + "analysis-results/catalog/logic-similarity.json",
        }])
    if code_within:
        selected = sorted(code_within, key=lambda item: (-item["case_count"], item["fingerprint"]))[:10]
        content = f"同一ファミリー内で複数caseに現れた正規化関数fingerprint: {len(code_within)} group。代表例: "
        content += "、".join(f"{item['role']} / {item['fingerprint']} ({item['case_count']}件)" for item in selected)
        content += "。共有ライブラリや生成コードの可能性があるため、これだけで版・運用者を確定しない。"
        add_note("code-within", content, [{"source_name": "AI-security-analysis", "description": "関数コード類似性索引", "url": BASE_URL + "analysis-results/catalog/code-similarity.json"}])
    for other, groups in code_across:
        selected = sorted(groups, key=lambda item: item["fingerprint"])[:5]
        content = f"{other}とのファミリー横断コード類似候補: 正規化関数の完全一致{len(groups)} group。"
        content += " 例: " + "、".join(f"{item['role']} / {item['fingerprint']} (SHA-256 {item['left_sha256']} / {item['right_sha256']})" for item in selected)
        content += "。同じ開発者・攻撃者・campaign・派生関係を意味しない。"
        add_note(f"code-across:{other}", content, [{"source_name": "AI-security-analysis", "description": "関数コード類似性索引", "url": BASE_URL + "analysis-results/catalog/code-similarity.json"}], [malware_id], 20)

    report_members = [item["id"] for item in objects]
    report = _object("report", family_id, timestamp, name=f"{name}：静的解析・攻撃利用史・OSINT", description="攻撃経路に関連する静的解析と審査済みの公開情報を収録した。", report_types=["malware"], published=timestamp, object_refs=report_members, external_references=[_local_reference(family_id, "README.md")], lang="ja")
    objects.append(report)
    return objects


def generate(repository: Path, as_of: date) -> tuple[dict[str, str], dict[str, Any]]:
    """公開case索引とOSINTから再現可能なファミリー別Bundle群を組み立てる。"""
    timestamp = as_of.isoformat() + "T00:00:00Z"
    knowledge, _ = _load_knowledge(repository / "analysis-framework/knowledge/malware_families")
    curated = json.loads((repository / "analysis-framework/knowledge/stix_curated.json").read_text(encoding="utf-8"))
    if curated.get("schema_version") != 1 or not all(isinstance(curated.get(key), list) for key in ("families", "campaigns", "developers")):
        raise ValueError("STIX精選知識のschemaが不正")
    for family in curated["families"]:
        family = _validate_family_knowledge(family)
        if family["id"] in knowledge:
            raise ValueError(f"重複したSTIX知識: {family['id']}")
        knowledge[family["id"]] = family
    campaigns: dict[str, list[dict[str, Any]]] = defaultdict(list)
    developers: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for kind, target in (("campaigns", campaigns), ("developers", developers)):
        for item in curated[kind]:
            family = item.get("family")
            if family not in knowledge or item.get("confidence") not in CONFIDENCE or not isinstance(item.get("name"), str) or not item["name"].strip() or not isinstance(item.get("description_ja"), str) or not item["description_ja"].strip():
                raise ValueError(f"STIX {kind}知識が不正")
            source_ids = item.get("source_ids")
            if not isinstance(source_ids, list) or not source_ids or not set(source_ids) <= {source["id"] for source in knowledge[family]["sources"]}:
                raise ValueError(f"STIX {kind}の出典が不正: {family}")
            if kind == "campaigns" and "attributed_actor_names" in item:
                names = item["attributed_actor_names"]
                known = {actor["name"] for actor in knowledge[family]["actors"]} | {
                    developer["name"] for developer in curated["developers"] if developer.get("family") == family
                }
                if (not isinstance(names, list) or not names
                        or not all(isinstance(name, str) for name in names)
                        or len(names) != len(set(names))
                        or not all(_named_actor(name) and name in known for name in names)
                        or item.get("attribution_confidence") not in CONFIDENCE
                        or not isinstance(item.get("attribution_ja"), str) or not item["attribution_ja"].strip()):
                    raise ValueError(f"STIX campaignのactor帰属が不正: {family}")
            target[family].append(item)
    cases = _load_catalog(repository / "analysis-results/catalog/cases.json")
    families = {family for family in cases if family not in TECHNICAL_CLUSTERS and (repository / "analysis-results/malware" / family / "README.md").is_file()}
    # case catalogに未移行でも、公開済み解析と出典付き知識があるfamilyを含める。
    for family in knowledge:
        if family not in EXCLUDED_FAMILIES | TECHNICAL_CLUSTERS and (repository / "analysis-results/malware" / family / "README.md").is_file():
            families.add(family)
    approved_hashes = _strong_case_hashes(repository, cases)
    features = _static_features(repository / "analysis-results/catalog/logic-similarity.json", families, approved_hashes)
    within, across = _code_groups(repository / "analysis-results/catalog/code-similarity.json", families, repository, approved_hashes)
    by_family_across: dict[str, list[tuple[str, list[dict[str, Any]]]]] = defaultdict(list)
    for (left, right), groups in across.items():
        if len(groups) < 2:
            continue
        by_family_across[left].append((right, groups))
        by_family_across[right].append((left, groups))
    output: dict[str, str] = {}
    stats = {"families": 0, "families_with_osint": 0, "actor_relationships": 0, "developer_relationships": 0, "campaigns": 0, "campaign_attributions": 0, "history_notes": 0, "code_similarity_notes": 0, "excluded_non_attack_events": 0,
             "catalog_cases_in_exported_families": sum(len(cases.get(family, [])) for family in families),
             "strongly_attributed_cases": sum(len(set(cases.get(family, [])) & approved_hashes) for family in families)}
    for family in sorted(families):
        item = knowledge.get(family)
        local_overview = _local_overview(repository / "analysis-results/malware" / family / "README.md") if item is None else None
        objects = _family_objects(family, item, sorted(set(cases.get(family, [])) & approved_hashes), features.get(family, {}), within.get(family, []), sorted(by_family_across.get(family, [])), campaigns.get(family, []), developers.get(family, []), timestamp, local_overview)
        bundle = {"type": "bundle", "id": _identifier("bundle", f"{family}:{as_of.isoformat()}"), "objects": objects}
        _reconcile_versions(bundle, repository / "analysis-results/stix/families" / f"{family}.json", timestamp)
        _validate_bundle(bundle)
        output[f"families/{family}.json"] = json.dumps(bundle, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        stats["families"] += 1
        stats["families_with_osint"] += int(item is not None)
        stats["actor_relationships"] += sum(obj["type"] == "relationship" and obj["source_ref"].startswith("threat-actor--") for obj in objects)
        stats["developer_relationships"] += sum(obj["type"] == "relationship" and obj["relationship_type"] == "authored-by" for obj in objects)
        stats["campaigns"] += sum(obj["type"] == "campaign" for obj in objects)
        stats["campaign_attributions"] += sum(obj["type"] == "relationship" and obj["relationship_type"] == "attributed-to" for obj in objects)
        stats["history_notes"] += sum(obj["type"] == "note" and "攻撃利用履歴" in obj["content"] for obj in objects)
        stats["code_similarity_notes"] += sum(obj["type"] == "note" and "コード類似候補" in obj["content"] for obj in objects)
        if item:
            stats["excluded_non_attack_events"] += sum(not _assert_attack_history(_clean(event["summary_ja"])) for event in item["historical_use"])
    index = {"schema_version": 1, "stix_version": "2.1", "as_of": as_of.isoformat(), "counts": stats, "families": sorted(families),
             "excluded_technical_clusters": sorted(family for family in TECHNICAL_CLUSTERS if family in cases),
             "safety": {"sample_executed": False, "live_c2_contacted": False, "discovery_route_excluded": True, "unreviewed_campaign_promoted": False,
                        "low_confidence_case_used_for_static_features": False,
                        "generic_runtime_used_for_code_similarity": False}}
    output["index.json"] = json.dumps(index, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    lines = ["# ファミリー別STIX 2.1", "", "静的解析と出典付きOSINTをファミリー別Bundleへまとめた公開成果物です。検体の発見経路や未審査のcampaign候補は攻撃経路として収録しません。", "", "コード類似は共有関数の比較候補であり、同一開発者・利用アクター・campaignを示すものではありません。OSINT未登録ファミリーは公開済みローカル概要と静的比較情報に限定し、未知の開発者や商品化形態を補完しません。", "", "[攻撃インフラ横断STIX Bundle](infrastructure/bundle.json)／[調査・判定基準](../../analysis-framework/docs/INFRASTRUCTURE-STIX.md)", "", "[ファミリー別の生成手順と判定境界](../../analysis-framework/docs/FAMILY-STIX.md)", "", f"生成日: {as_of.isoformat()}。ファミリー: {stats['families']}件、OSINT登録: {stats['families_with_osint']}件、利用関係: {stats['actor_relationships']}件。", "", "| ファミリー | STIX Bundle | 出典付きOSINT |", "|---|---|---|",]
    link_index = next(i for i, line in enumerate(lines) if line.startswith("[攻撃インフラ横断STIX Bundle]"))
    lines[link_index] = lines[link_index].replace(
        "／[調査・判定基準]",
        "／[一次資料照合済みcampaign STIX Bundle](reviewed-campaigns/bundle.json)／[調査・判定基準]",
    )
    for family in sorted(families):
        lines.append(f"| {family} | [JSON](families/{family}.json) | {'あり' if family in knowledge else '未登録'} |")
    output["README.md"] = "\n".join(lines) + "\n"
    return output, index


def main() -> int:
    """ファミリー別STIX成果物を生成するか、既存成果物と照合する。"""
    parser = argparse.ArgumentParser(description="ファミリー別STIX 2.1を公開済み解析とOSINTから生成・照合します。")
    parser.add_argument("--repository", type=Path, default=Path("."), help="解析リポジトリのルート")
    parser.add_argument("--as-of", type=date.fromisoformat, required=True, help="作成日（YYYY-MM-DD、再現性のため必須）")
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--write", action="store_true", help="成果物を更新")
    action.add_argument("--check", action="store_true", help="既存成果物との一致を確認")
    args = parser.parse_args()
    repository = args.repository.resolve()
    result, index = generate(repository, args.as_of)
    root = repository / "analysis-results/stix"
    for relative, text in result.items():
        target = root / relative
        if args.check:
            if not target.is_file() or target.read_text(encoding="utf-8") != text:
                raise SystemExit(f"STIX成果物が不一致: {relative}")
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8", newline="\n")
    # 別generatorが管理するinfrastructure/等は、ファミリー成果物の集合照合から除外する。
    managed_files = list(root.glob("*.json")) + list((root / "families").glob("*.json"))
    actual = {path.relative_to(root).as_posix() for path in managed_files if path.is_file()}
    expected = {relative for relative in result if relative.endswith(".json")}
    if args.check and actual != expected:
        raise SystemExit(f"STIX成果物の集合が不一致: 余分={sorted(actual - expected)} 不足={sorted(expected - actual)}")
    print(json.dumps(index["counts"], ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
