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

from analysis_contract import (  # noqa: E402
    artifact_hashes,
    case_integrity_errors,
    ensure_no_reparse_components,
    load_json_object_strict,
    normalize_artifact_path,
    normalize_sha256_digest,
    resolve_case_artifact,
    seal_report,
)
from case_features import build_case_profile, render_features_markdown  # noqa: E402
from ioc_markdown import normalize_confirmed_network_iocs, render_submitted_iocs  # noqa: E402
from result_layout import canonical_malware_case_path  # noqa: E402
from result_publication import (  # noqa: E402
    detect_publication_context,
    register_publication_cases,
)
from static_logic import render_static_logic_markdown  # noqa: E402

SHA256_RE = re.compile(r"[0-9a-f]{64}")
COLLECTION_RE = re.compile(r"[a-z0-9][a-z0-9-]{2,79}")
FUNCTION_ANALYSIS_BLOCKER = "representative_function_analysis_required"
PARTIAL_STAGING_ALLOWED_BLOCKERS = {
    FUNCTION_ANALYSIS_BLOCKER,
    "generic_triage_partial",
    "handler_ambiguous_evidence",
    "handler_failed",
    "handler_incompatible_input_format",
    "handler_no_evidence",
    "handler_preflight_failed",
    "detector_error_present",
    "static_layer_limit_reached",
    "selected_family_layer_incomplete",
    "static_layer_incomplete",
}
PARTIAL_STAGING_FAMILY_BLOCKER = re.compile(
    r"selected_family_has_no_(?:automatic_handler|valid_handler_evidence):[a-z0-9_-]+"
)

# MalwareBazaarの報告名を、既にリポジトリで管理しているIDだけへ対応させる。
REPORTED_FAMILY_ALIASES = {
    "acrstealer": "acrstealer",
    "agenttesla": "agenttesla",
    "amadey": "amadey",
    "asyncrat": "asyncrat",
    "efimer": "efimer",
    "formbook": "formbook",
    "guloader": "guloader",
    "hijackloader": "hijackloader",
    "maskgramstealer": "maskgram-stealer",
    "mirai": "mirai",
    "nanocore": "nanocore",
    "prometei": "prometei",
    "purerat": "purehvnc",
    "purelogsstealer": "purelogs",
    "remcosrat": "remcosrat",
    "remusstealer": "remusstealer",
    "snakekeylogger": "snakekeylogger",
    "stealc": "stealc",
    "valleyrat": "valleyrat",
    "vidar": "vidar",
    "wannacry": "wannacry",
}
INTERNAL_FAMILY_TO_PUBLIC = {
    "dotnet_resource_loader": "dotnet-resource-loader",
    "formbook_loader": "formbook",
    "linux_downloader": "linux-downloader",
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
    return load_json_object_strict(path)


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def normalize_reported_name(value: object) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value or "").casefold())


def public_family_id(internal_family: str) -> str:
    """内部handler IDを公開先の正規family IDへ変換する。"""

    normalized = internal_family.casefold()
    return INTERNAL_FAMILY_TO_PUBLIC.get(normalized, normalized)


def selected_family_has_handler_support(report: dict[str, Any], internal_family: str) -> bool:
    """選択familyを、handlerの十分な静的証拠がある場合だけ公開候補にする。"""

    case_state = report.get("case_state")
    if isinstance(case_state, dict):
        blockers = {str(value) for value in case_state.get("blockers") or []}
        unsupported = {
            f"selected_family_has_no_valid_handler_evidence:{internal_family}",
            f"selected_family_has_no_automatic_handler:{internal_family}",
        }
        if blockers & unsupported:
            return False

    executions = report.get("handler_executions")
    if not isinstance(executions, list):
        return False
    relevant = [
        item
        for item in executions
        if isinstance(item, dict)
        and str(item.get("handler_id") or "").partition(":")[0].casefold() == internal_family
    ]
    if not relevant:
        return False
    for item in relevant:
        if item.get("status") != "succeeded":
            continue
        evidence = item.get("selected_evidence")
        if isinstance(evidence, dict) and evidence.get("sufficient") is True:
            return True
    return False


def choose_family(metadata: dict[str, Any], report: dict[str, Any], existing_families: set[str]) -> tuple[str, str]:
    """内部高確度判定、提供元signature、直接tagの順で保守的に分類する。"""

    classification = report.get("classification") or {}
    selected_internal = str(classification.get("selected_family") or "").casefold()
    selection_basis = str(classification.get("selection_basis") or "")
    contract = report.get("analysis_contract")
    settings = contract.get("settings") if isinstance(contract, dict) else None
    forced_family = settings.get("forced_family") if isinstance(settings, dict) else None
    if selection_basis != "explicit_operator_selection" and not forced_family:
        selected_public = public_family_id(selected_internal)
        if selected_public in existing_families and selected_family_has_handler_support(
            report, selected_internal
        ):
            return selected_public, "one_shot_static_detector"
        selected_families = classification.get("selected_families")
        if (
            isinstance(selected_families, list)
            and selected_families
            and all(isinstance(value, str) for value in selected_families)
        ):
            implicit = {str(value).casefold() for value in selected_families if str(value)}
            if len(implicit) == 1:
                candidate_internal = implicit.pop()
                candidate_public = public_family_id(candidate_internal)
                if candidate_public in existing_families and selected_family_has_handler_support(
                    report, candidate_internal
                ):
                    return candidate_public, "one_shot_recovered_layer_detector"

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
        if tag in REPORTED_FAMILY_ALIASES and REPORTED_FAMILY_ALIASES[tag] in existing_families
    }
    if len(mapped_tags) == 1:
        return mapped_tags.pop(), "malwarebazaar_direct_tag"
    return "unclassified", "no_supported_family_evidence"


def safe_metadata(item: dict[str, Any]) -> dict[str, Any]:
    metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
    return {key: metadata.get(key) for key in PUBLIC_METADATA_KEYS}


def collection_display_metadata(
    manifest: dict[str, Any],
    items: list[dict[str, Any]],
) -> dict[str, Any]:
    """collection README用の日付・期間・実形式をmanifestから導出する。"""

    metadata = [item.get("metadata") or {} for item in items]
    first_seen = [str(item.get("first_seen")) for item in metadata if item.get("first_seen")]
    selected_date = str(manifest.get("selected_at") or "").split("T", 1)[0]
    if not selected_date and first_seen:
        selected_date = first_seen[0].split(" ", 1)[0]
    type_counts = Counter(str(item.get("file_type") or item.get("file_format") or "不明").upper() for item in metadata)
    type_summary = "、".join(f"{file_type} {count}件" for file_type, count in sorted(type_counts.items())) or "形式不明"
    return {
        "selected_date": selected_date or "日付不明",
        "first_seen_newest": first_seen[0] if first_seen else "不明",
        "first_seen_oldest": first_seen[-1] if first_seen else "不明",
        "type_summary": type_summary,
    }


def is_partial_staging_case(report: dict[str, Any]) -> bool:
    """代表関数解析待ちを含む既知blockerだけのpartialをstaging対象にする。"""

    state = report.get("case_state")
    blockers = state.get("blockers") if isinstance(state, dict) else None
    if (
        report.get("assessment_only") is not False
        or not isinstance(state, dict)
        or state.get("status") != "partial"
        or state.get("complete") is not False
        or state.get("resumable") is not False
        or not isinstance(blockers, list)
        or FUNCTION_ANALYSIS_BLOCKER not in blockers
    ):
        return False
    return all(
        isinstance(blocker, str)
        and (
            blocker in PARTIAL_STAGING_ALLOWED_BLOCKERS or PARTIAL_STAGING_FAMILY_BLOCKER.fullmatch(blocker) is not None
        )
        for blocker in blockers
    )


def validate_case_state(
    report: dict[str, Any],
    digest: str,
    *,
    allow_function_staging: bool = False,
) -> str:
    """新形式の解析結果が公開可能な完了状態であることを検証する。"""

    if allow_function_staging and is_partial_staging_case(report):
        return "analysis_followup_pending"
    state = report.get("case_state")
    status = state.get("status") if isinstance(state, dict) else "invalid"
    blockers = state.get("blockers") if isinstance(state, dict) else None
    if (
        not isinstance(state, dict)
        or status not in {"complete", "triaged_unknown"}
        or state.get("complete") is not True
        or state.get("resumable") is not True
        or blockers != []
        or report.get("assessment_only") is not False
    ):
        raise ValueError(f"one-shot解析が公開可能な完了状態ではありません: {digest} (case_state={status})")
    return "complete"


def validate_source_case(
    source: Path,
    report: dict[str, Any],
    digest: str,
    *,
    allow_function_staging: bool = False,
    expected_contract: dict[str, Any] | None = None,
) -> str:
    """公開前にreport seal、状態不変条件、全成果物をfail-closedで検証する。"""

    stage = validate_case_state(
        report,
        digest,
        allow_function_staging=allow_function_staging,
    )
    errors = case_integrity_errors(
        source,
        report,
        expected_digest=digest,
        expected_contract=expected_contract,
        require_resumable=stage == "complete",
    )
    if errors:
        raise ValueError(f"one-shot解析caseの整合性検証に失敗しました: {digest} ({errors})")
    return stage


def load_validated_source_report(
    source: Path,
    digest: str,
    *,
    allow_function_staging: bool = False,
    expected_contract: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], str]:
    """source reportを安全に読み、公開可能性を副作用なしで検証する。"""

    normalize_sha256_digest(digest)
    ensure_no_reparse_components(source)
    report = load_json(resolve_case_artifact(source, "report.json"))
    if (report.get("sample") or {}).get("sha256") != digest:
        raise ValueError(f"reportのSHA-256不一致: {digest}")
    if report.get("executed_sample") is not False or report.get("network_contacted") is not False:
        raise ValueError(f"安全フラグ不一致: {digest}")
    stage = validate_source_case(
        source,
        report,
        digest,
        allow_function_staging=allow_function_staging,
        expected_contract=expected_contract,
    )
    return report, stage


def reseal_canonical_report(case_dir: Path, report: dict[str, Any]) -> None:
    """生成後の正規成果物に合わせてhash manifestとreport sealを更新する。"""

    manifest = report.get("artifact_sha256")
    if not isinstance(manifest, dict) or not manifest:
        raise ValueError("reportに成果物hash manifestがありません")
    report["artifact_sha256"] = artifact_hashes(case_dir, manifest)
    seal_report(report)
    write_json(case_dir / "report.json", report)
    errors = case_integrity_errors(
        case_dir,
        report,
        expected_digest=case_dir.name,
        require_resumable=not is_partial_staging_case(report),
    )
    if errors:
        raise ValueError(f"正規caseの再封印後検証に失敗しました: {case_dir.name} ({errors})")


def pe_summary(generic: dict[str, Any]) -> dict[str, Any]:
    pe = generic.get("pe") if isinstance(generic.get("pe"), dict) else {}
    sections = pe.get("sections") if isinstance(pe.get("sections"), list) else []
    imports = pe.get("imports") if isinstance(pe.get("imports"), dict) else {}
    imported_names = sorted({str(name) for values in imports.values() if isinstance(values, list) for name in values})
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
        (
            "process_creation",
            {"createprocessa", "createprocessw", "shellexecutea", "shellexecutew"},
            "プロセス起動APIのimportを確認",
        ),
        (
            "process_injection",
            {"virtualallocex", "writeprocessmemory", "createremotethread"},
            "別プロセス操作に使われ得るAPIのimportを確認",
        ),
        (
            "network_access",
            {
                "internetopena",
                "internetopenw",
                "internetconnecta",
                "internetconnectw",
                "wsaconnect",
                "connect",
                "urldownloadtofilea",
                "urldownloadtofilew",
            },
            "ネットワーク接続・取得APIのimportを確認",
        ),
        (
            "registry_access",
            {"regsetvalueexa", "regsetvalueexw", "regcreatekeyexa", "regcreatekeyexw"},
            "Registry更新APIのimportを確認",
        ),
        (
            "anti_debug",
            {"isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess"},
            "デバッガ確認に使われ得るAPIのimportを確認",
        ),
        (
            "cryptography",
            {"cryptdecrypt", "cryptencrypt", "bcryptdecrypt", "bcryptencrypt"},
            "暗号処理APIのimportを確認",
        ),
    )
    notes = []
    for capability, markers, description in checks:
        hits = sorted(names & markers)
        if hits:
            notes.append({"capability": capability, "basis": description, "imports": ", ".join(hits)})
    return notes


def _trusted_handler_result(
    execution: dict[str, Any],
    artifact: dict[str, Any],
) -> bool:
    """reportと一致する成功handlerの正規化済み静的証拠だけを受理する。"""

    if (
        execution.get("status") != "succeeded"
        or artifact.get("executed_sample") is not False
        or artifact.get("network_contacted") is not False
    ):
        return False
    execution_evidence = execution.get("selected_evidence")
    artifact_evidence = artifact.get("selected_evidence")
    if (
        not isinstance(execution_evidence, dict)
        or execution_evidence.get("sufficient") is not True
        or not isinstance(artifact_evidence, dict)
        or artifact_evidence.get("sufficient") is not True
    ):
        return False
    execution_id = str(execution.get("handler_id") or "")
    handler = artifact.get("handler")
    artifact_id = str(handler.get("id") or "") if isinstance(handler, dict) else ""
    return bool(execution_id and artifact_id and execution_id == artifact_id)


def confirmed_static_handler_iocs(
    handler_results: list[tuple[dict[str, Any], dict[str, Any]]],
) -> list[dict[str, Any]]:
    """確認済み静的設定のC2だけを公開用network IOCへ正規化する。"""

    candidates_for_normalization: list[dict[str, Any]] = []
    for execution, artifact in handler_results:
        if not _trusted_handler_result(execution, artifact):
            continue
        result = artifact.get("result")
        candidates = result.get("c2") if isinstance(result, dict) else None
        if not isinstance(candidates, list):
            continue
        handler = artifact.get("handler") or {}
        source = f"handler:{handler.get('id')}"
        for candidate in candidates:
            if not isinstance(candidate, dict):
                continue
            record = dict(candidate)
            record["source"] = source
            candidates_for_normalization.append(record)
    return normalize_confirmed_network_iocs(candidates_for_normalization)


def static_config_recovered(
    handler_results: list[tuple[dict[str, Any], dict[str, Any]]],
    network_iocs: list[dict[str, Any]],
) -> bool:
    """信頼済みconfig flagまたは確認済みC2があれば静的設定回収済みとする。"""

    if network_iocs:
        return True
    for execution, artifact in handler_results:
        if not _trusted_handler_result(execution, artifact):
            continue
        result = artifact.get("result")
        if not isinstance(result, dict):
            continue
        if (
            result.get("static_config_recovered") is True
            or result.get("decoded_config_recovered") is True
        ):
            return True
        config = result.get("config")
        if isinstance(config, dict) and config.get("static_config_recovered") is True:
            return True
    return False


def render_iocs(
    digest: str,
    network_iocs: list[dict[str, Any]] | None = None,
) -> str:
    """提出hashと確認済み静的C2だけをIOC Markdownへ描画する。"""

    return render_submitted_iocs(digest, network_iocs or [])


def render_readme(
    digest: str,
    family: str,
    attribution_basis: str,
    metadata: dict[str, Any],
    pe: dict[str, Any],
    capabilities: list[dict[str, str]],
    logic: dict[str, Any],
    handler_count: int,
    confirmed_c2_count: int,
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
    capability_materials = (
        "、".join(
            f"`{item['capability']}`（`{item['imports']}`）"
            for item in capabilities
        )
        if capabilities
        else "特徴的なimport相関なし"
    )
    lines.extend(
        [
            "",
            "## 実行・感染チェーン",
            "",
            "MalwareBazaarの暗号化ZIPから認証済みルート検体を静的に取り出し、復元可能な埋め込み層を追跡してから関数解析へ渡しました。"
            "検体を実行していないため、実行時の親子プロセス、永続化、後段取得は未確認です。"
            "静的な層関係と処理段階は[OVERALL-LOGIC.md](OVERALL-LOGIC.md)を参照してください。",
            "",
            "## 静的ロジック",
            "",
            "関数境界・call graph・逆コンパイルが未記録のbinaryは`function_analysis_required`のままです。詳細は[STATIC-LOGIC.md](STATIC-LOGIC.md)を参照してください。",
            "",
            "## ファイルIOC",
            "",
            f"- 提出検体SHA-256: `{digest}`",
            "- 復元層のhashと役割は[IOC-LIST.md](IOC-LIST.md)および[静的レイヤー](static-layers.json)を参照してください。",
            "",
            "## C2／通信IOC",
            "",
            (
                f"ファミリー固有handlerの静的設定構造から、確認済みC2観測を`{confirmed_c2_count}`件記録しました。"
                "重複するendpointでもroleまたはevidenceが異なる観測は保持しています。"
                "到達性、所有者、稼働状況は未確認です。"
                if confirmed_c2_count
                else "汎用文字列走査の候補をC2として採用していません。ファミリー固有設定で裏付けられない限り、現在のC2、所有者、到達性は未確認です。"
            ),
            "公開可能な通信IOCは[IOC-LIST.md](IOC-LIST.md)を参照してください。",
            "",
            "## Sigma／YARA材料",
            "",
            f"- exact-match材料: SHA-256 `{digest}`",
            f"- PE構造材料: 形式 `{pe.get('type') or metadata.get('file_type') or '不明'}`、"
            f"サイズ `{pe.get('size') or metadata.get('file_size') or '不明'}` bytes、"
            f"entropy `{pe.get('entropy') if pe.get('entropy') is not None else '不明'}`、"
            f"section数 `{pe.get('section_count')}`",
            f"- 能力相関材料: {capability_materials}",
            "- providerのfamily名、ファイル名、単一importだけでは判定せず、hash、PE構造、複数import、復元層、親子関係、通信帰属を組み合わせます。",
            "- 本節はルール実装前の材料であり、環境別の正常系検証と誤検知評価を経ずに本番判定へ使用しません。",
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
    *,
    allow_function_staging: bool = False,
) -> tuple[str, Path, dict[str, Any]]:
    digest = item.get("sha256")
    digest = normalize_sha256_digest(digest)
    report, publication_stage = load_validated_source_report(
        source,
        digest,
        allow_function_staging=allow_function_staging,
    )
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
        documents[name] = load_json(resolve_case_artifact(source, name))
        write_json(destination / name, documents[name])
    handler_results = []
    trusted_handler_results: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for execution in report.get("handler_executions") or []:
        relative = execution.get("result") if isinstance(execution, dict) else None
        if not isinstance(relative, str):
            continue
        relative = normalize_artifact_path(relative)
        result = load_json(resolve_case_artifact(source, relative))
        write_json(destination.joinpath(*relative.split("/")), result)
        if execution.get("status") == "succeeded":
            handler_results.append(result)
            trusted_handler_results.append((execution, result))
    write_json(destination / "handler-results.json", {"schema_version": 1, "results": handler_results})
    network_iocs = confirmed_static_handler_iocs(trusted_handler_results)
    config_recovered = static_config_recovered(trusted_handler_results, network_iocs)

    logic = load_json(resolve_case_artifact(source, "static-logic.json"))
    logic["family"] = family
    write_json(destination / "static-logic.json", logic)
    (destination / "STATIC-LOGIC.md").write_text(render_static_logic_markdown(logic), encoding="utf-8")
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
        "case_kind": "unclassified" if family == "unclassified" else "malware",
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
            "static_config_recovered": config_recovered,
            "confirmed_static_c2_observations": len(network_iocs),
            "declarative_status": "function_review_required"
            if logic.get("status") == "function_analysis_required"
            else "ready",
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
            "iocs": "iocs.json",
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
            "network": network_iocs,
            "assessment": (
                "ファミリー固有handlerの静的設定証拠から確認済みC2を収録した。到達性は検証していない"
                if network_iocs
                else "汎用文字列候補はC2へ昇格していない"
            ),
            "sample_executed": False,
            "network_contacted": False,
        },
    )
    (destination / "IOC-LIST.md").write_text(render_iocs(digest, network_iocs), encoding="utf-8")
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
            len(network_iocs),
        ),
        encoding="utf-8",
    )
    profile = build_case_profile(destination)
    profile["family"] = family
    write_json(destination / "features.json", profile)
    (destination / "FEATURES.md").write_text(render_features_markdown(profile), encoding="utf-8")
    reseal_canonical_report(destination, report)
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
            isinstance(value, dict) and value.get("status") in {"failed", "preflight_failed"}
            for value in (report.get("handler_executions") or [])
        ),
        "static_config_recovered": analysis["case"]["static_config_recovered"],
        "confirmed_static_c2_observations": len(network_iocs),
        "case_path": canonical_path,
        "publication_stage": publication_stage,
    }
    return family, destination, summary


def initialize_collection(
    results: Path,
    collection_id: str,
    manifest: dict[str, Any],
    *,
    publication_stage: str,
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
    display = collection_display_metadata(
        manifest,
        [item for item in manifest.get("items") or [] if isinstance(item, dict)],
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
        "acquisition_complete": manifest.get("complete"),
        "analysis_complete": publication_stage == "complete",
        "complete": publication_stage == "complete",
        "publication_stage": publication_stage,
        "first_seen_newest": display["first_seen_newest"],
        "first_seen_oldest": display["first_seen_oldest"],
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
    matches = [root / "cases" / digest for root in one_shots if (root / "cases" / digest / "report.json").is_file()]
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
        f"完了case sourceまたは明示family追加解析は1件必要です: {digest} (全{len(matches)}件、明示{len(explicit)}件)"
    )

def _validate_acquisition_manifest_count(manifest: dict[str, Any]) -> tuple[int, list[Any]]:
    """取得manifestの要求件数と完了件数を検証する。

    ``requested`` を持たない旧manifestは、従来仕様の100件として扱う。
    """

    requested = manifest.get("requested", 100)
    if isinstance(requested, bool) or not isinstance(requested, int) or requested <= 0:
        raise ValueError("取得manifestのrequestedは正の整数である必要があります")
    if manifest.get("complete") is not True or manifest.get("downloaded") != requested:
        raise ValueError(f"取得manifestが要求件数{requested}件を完了していません")
    items = manifest.get("items")
    if not isinstance(items, list) or len(items) != requested:
        raise ValueError(f"取得manifestのitemsが要求件数{requested}件ではありません")
    return requested, items


def publish(
    repository: Path,
    manifest_path: Path,
    one_shots: list[Path],
    collection_id: str,
    *,
    allow_function_staging: bool = False,
    expected_contract_sha256: str | None = None,
) -> dict[str, Any]:
    if not COLLECTION_RE.fullmatch(collection_id):
        raise ValueError("collection IDは小文字英数とhyphenだけで指定してください")
    if expected_contract_sha256 is not None:
        expected_contract_sha256 = normalize_sha256_digest(expected_contract_sha256)
    results = repository / "analysis-results"
    manifest = load_json(manifest_path)
    requested_count, items = _validate_acquisition_manifest_count(manifest)
    validated_sources = {}
    source_stages: dict[str, str] = {}
    baseline_contract: dict[str, Any] | None = None
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            raise ValueError(f"取得manifest itemがobjectではありません: {index}")
        digest = normalize_sha256_digest(item.get("sha256"))
        if digest in validated_sources:
            raise ValueError(f"取得manifestに重複SHA-256があります: {digest}")
        source = find_case_source(one_shots, digest)
        report, stage = load_validated_source_report(
            source,
            digest,
            allow_function_staging=allow_function_staging,
            expected_contract=baseline_contract,
        )
        contract = report.get("analysis_contract")
        if not isinstance(contract, dict):
            raise ValueError(f"analysis contractがありません: {digest}")
        fingerprint = normalize_sha256_digest(contract.get("sha256"))
        if expected_contract_sha256 is not None and fingerprint != expected_contract_sha256:
            raise ValueError(
                f"期待するanalysis contract SHA-256と一致しません: {digest} "
                f"({fingerprint} != {expected_contract_sha256})"
            )
        if baseline_contract is None:
            baseline_contract = dict(contract)
        validated_sources[digest] = source
        source_stages[digest] = stage

    if baseline_contract is None:
        raise ValueError("検証済みanalysis contractがありません")
    analysis_contract_sha256 = normalize_sha256_digest(baseline_contract.get("sha256"))

    # 全要求件数のsourceを検証し終えるまでcollection/caseへ一切書き込まない。
    publication_stage = (
        "analysis_followup_pending" if "analysis_followup_pending" in source_stages.values() else "complete"
    )
    collection = initialize_collection(
        results,
        collection_id,
        manifest,
        publication_stage=publication_stage,
    )
    existing_families = {path.name for path in (results / "malware").iterdir() if path.is_dir()}
    existing_families.add("unclassified")
    by_family: dict[str, list[Path]] = defaultdict(list)
    summaries = []
    for item in items:
        digest = normalize_sha256_digest(item.get("sha256"))
        source = validated_sources[digest]
        family, destination, summary = publish_case(
            repository,
            results,
            collection_id,
            source,
            item,
            existing_families,
            allow_function_staging=allow_function_staging,
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
    confirmed_c2_count = sum(item["confirmed_static_c2_observations"] for item in summaries)
    display = collection_display_metadata(manifest, items)
    lines = [
        f"# MalwareBazaar Windows検体{requested_count}件（{display['selected_date']}）",
        "",
        f"MalwareBazaarのWindows対象照会を統合し、既解析SHA-256を除外して取得日時の新しい順に{requested_count}件を固定しました。形式内訳は{display['type_summary']}です。取得時の暗号化ZIPはリポジトリ外で照合し、検証済み隔離入力だけを保持して、検体を実行せず静的解析しました。",
        "",
        f"- 対象期間: `{display['first_seen_newest']}`〜`{display['first_seen_oldest']}`",
        f"- 取得: `{manifest.get('downloaded')}/{requested_count}`、pending `{manifest.get('pending')}`",
        f"- 公開段階: `{publication_stage}`",
        f"- 解析契約SHA-256: `{analysis_contract_sha256}`",
        "- 検体実行: なし",
        "- C2／配布先への接続: なし",
        "- 汎用文字列候補はC2へ昇格していない",
        f"- ファミリー固有handler成功結果: `{handler_successes}`",
        f"- handler失敗／事前確認失敗: `{handler_failures}`",
        f"- 静的設定回収: `{static_config_count}`",
        f"- 確認済み静的C2観測: `{confirmed_c2_count}`",
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
    collection_manifest = load_json(collection / "manifest.json")
    collection_manifest["analysis_contract_sha256"] = analysis_contract_sha256
    collection_manifest["cases"] = [
        {"case_id": f"sha256:{item['sha256']}"} for item in sorted(summaries, key=lambda value: value["sha256"])
    ]
    collection_manifest["family_sources"] = [
        {"family": family, "path": f"sources/{family}"} for family in sorted(by_family)
    ]
    write_json(collection / "manifest.json", collection_manifest)
    write_json(
        collection / "publication-summary.json",
        {
            "schema_version": 1,
            "publication_stage": publication_stage,
            "analysis_complete": publication_stage == "complete",
            "analysis_contract_sha256": analysis_contract_sha256,
            "counts": dict(counts),
            "static_logic_status": dict(status_counts),
            "handler_successes": handler_successes,
            "handler_failures": handler_failures,
            "static_config_recovered": static_config_count,
            "confirmed_static_c2_observations": confirmed_c2_count,
            "cases": summaries,
            "samples_executed": False,
            "network_contacted": False,
        },
    )
    return {
        "published": len(summaries),
        "publication_stage": publication_stage,
        "analysis_contract_sha256": analysis_contract_sha256,
        "families": dict(counts),
        "collection": str(collection),
    }


class JapaneseArgumentParser(argparse.ArgumentParser):
    """argparseの固定見出しを日本語へ置換する。"""

    def format_help(self) -> str:
        """usage・options・標準help文を日本語化する。"""

        return (
            super()
            .format_help()
            .replace("usage:", "使用法:")
            .replace("options:", "オプション:")
            .replace("show this help message and exit", "このhelpを表示して終了します")
        )


def build_parser() -> argparse.ArgumentParser:
    """公開CLIの引数parserを構築する。"""

    parser = JapaneseArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=REPOSITORY)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--one-shot", required=True, action="append", type=Path)
    parser.add_argument("--collection-id", required=True)
    parser.add_argument(
        "--expected-contract-sha256",
        help="全caseで要求するone-shot analysis contractのSHA-256",
    )
    parser.add_argument(
        "--allow-partial-staging",
        "--allow-function-staging",
        dest="allow_function_staging",
        action="store_true",
        help="整合性検証済みのpartial caseを追加静的解析用stagingとして配置します",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result = publish(
        args.repository.resolve(),
        args.manifest.resolve(),
        [path.resolve() for path in args.one_shot],
        args.collection_id,
        allow_function_staging=args.allow_function_staging,
        expected_contract_sha256=args.expected_contract_sha256,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
