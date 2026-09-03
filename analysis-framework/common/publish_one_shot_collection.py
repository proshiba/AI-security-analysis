#!/usr/bin/env python3
"""MalwareBazaarワンショット静的解析を正規caseとcollectionへ公開する。"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import sys
import tempfile
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

COMMON = Path(__file__).resolve().parent
REPOSITORY = COMMON.parents[1]
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import analysis_job_runner  # noqa: E402
import orchestration_outcome  # noqa: E402
from automated_case_analysis import build_case_automation_artifacts  # noqa: E402
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
from c2_analysis_contract import (  # noqa: E402
    REQUIRED_PHASES,
    build_unresolved_contract,
)
from c2_analysis_contract import (  # noqa: E402
    validate_contract as validate_c2_contract,
)
from case_features import build_case_profile, render_features_markdown  # noqa: E402
from handler_evidence import (  # noqa: E402
    confirmed_static_handler_iocs,
    is_dual_use_management_endpoint,
    static_config_recovered,
    trusted_handler_result,
)
from ioc_markdown import render_submitted_iocs  # noqa: E402
from malwarebazaar_family_labels import (  # noqa: E402
    REPORTED_FAMILY_ALIASES,
    normalize_reported_name,
)
from overall_logic_diagrams import render_overall_logic_markdown  # noqa: E402
from result_layout import (  # noqa: E402
    resolve_catalog_case_path,
)
from result_publication import (  # noqa: E402
    detect_publication_context,
    register_publication_cases,
)
from screenconnect_evidence import (  # noqa: E402
    legacy_screenconnect_config,
    validated_screenconnect_config,
)
from static_logic import render_static_logic_markdown  # noqa: E402

SHA256_RE = re.compile(r"[0-9a-f]{64}")
CASE_PUBLICATION_TRANSACTION_SCHEMA = 1
STATIC_FAMILY_ATTRIBUTION_BASES = frozenset(
    {
        "one_shot_static_detector",
        "one_shot_recovered_layer_detector",
    }
)
PROVIDER_FAMILY_ATTRIBUTION_BASES = frozenset(
    {
        "malwarebazaar_reported_signature",
        "malwarebazaar_direct_tag",
    }
)
COLLECTION_RE = re.compile(r"[a-z0-9][a-z0-9-]{2,79}")
FORBIDDEN_PUBLICATION_BASENAMES = frozenset({"datastore-upload.json"})
FUNCTION_ANALYSIS_BLOCKER = "representative_function_analysis_required"
ROOT_TO_TERMINAL_LINEAGE_BLOCKER = "root_to_terminal_byte_derivation_incomplete"
ANALYSIS_FOLLOWUP_BLOCKERS = {
    FUNCTION_ANALYSIS_BLOCKER,
    ROOT_TO_TERMINAL_LINEAGE_BLOCKER,
}
POST_ANALYSIS_HARDENING_STATUS = "renderer_and_resource_coverage_fail_closed_hardening"
PARTIAL_STAGING_ALLOWED_BLOCKERS = {
    *ANALYSIS_FOLLOWUP_BLOCKERS,
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
    "orchestration:config",
    "orchestration:function_analysis",
    "orchestration:generic_triage",
    "orchestration:network",
    "orchestration:static_layers",
    "orchestration:terminal_payload",
}
PARTIAL_STAGING_FAMILY_BLOCKER = re.compile(
    r"selected_family_has_no_(?:automatic_handler|valid_handler_evidence):[a-z0-9_-]+"
)

INTERNAL_FAMILY_TO_PUBLIC = {
    "dotnet_resource_loader": "dotnet-resource-loader",
    "formbook_loader": "formbook",
    "linux_downloader": "linux-downloader",
    "maskgram_stealer": "maskgram-stealer",
    "screenconnect_rmm": "screenconnect-rmm",
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


def build_post_analysis_publication_record(
    *,
    sample_count: int,
    resource_scan_observations: int,
    relevant_resource_failures: int,
) -> dict[str, Any]:
    """解析後hardeningと実行時contract snapshotの関係を定型記録する。"""

    values = {
        "sample_count": sample_count,
        "resource_scan_observations": resource_scan_observations,
        "relevant_resource_failures": relevant_resource_failures,
    }
    for label, value in values.items():
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"{label}は0以上の整数で指定してください")
    if sample_count <= 0:
        raise ValueError("sample_countは正の整数で指定してください")
    if resource_scan_observations <= 0:
        raise ValueError("resource_scan_observationsは正の整数で指定してください")
    if relevant_resource_failures > resource_scan_observations:
        raise ValueError("relevant_resource_failuresが観測数を超えています")

    result_changed = relevant_resource_failures > 0
    impact = "該当失敗があるため、影響検体の再解析が必要。" if result_changed else "該当失敗は0件で、抽出結果は不変。"
    return {
        "status": POST_ANALYSIS_HARDENING_STATUS,
        "sample_count": sample_count,
        "resource_scan_observations": resource_scan_observations,
        "relevant_resource_failures": relevant_resource_failures,
        "analysis_result_changed": result_changed,
        "analysis_contract_semantics": "execution_time_snapshot",
        "note_ja": (
            "公開用OVERALL-LOGIC.mdレンダラーとPE resource coverageの"
            "fail-closed hardeningを解析完了後に修正した。"
            f"今回{sample_count}件で確認したresource scan "
            f"{resource_scan_observations}観測について、{impact}"
            "analysis_contract SHA-256は解析実行時のsnapshotとして保持する。"
        ),
    }


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
        if isinstance(item, dict) and str(item.get("handler_id") or "").partition(":")[0].casefold() == internal_family
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
        if selected_public in existing_families and selected_family_has_handler_support(report, selected_internal):
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

    case_state = report.get("case_state")
    if isinstance(case_state, dict) and case_state.get("status") == "triaged_unknown":
        return "unclassified", "internal_static_evidence_unresolved"

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


def build_family_attribution(
    family: str,
    attribution_basis: str,
    metadata: dict[str, Any],
) -> dict[str, Any]:
    """整理先ラベル、provider報告、内部静的確認を混同しない帰属契約を作る。"""

    reported_label = str(metadata.get("signature") or "").strip() or None
    reported_family = None
    if reported_label:
        reported_family = REPORTED_FAMILY_ALIASES.get(normalize_reported_name(reported_label))
    if reported_family is None:
        mapped_tags = [
            (str(value), REPORTED_FAMILY_ALIASES.get(normalize_reported_name(value)))
            for value in (metadata.get("tags") or [])
            if not str(value).casefold().startswith("dropped-by-")
        ]
        matching_tags = [(label, mapped) for label, mapped in mapped_tags if mapped is not None and mapped == family]
        if len(matching_tags) == 1:
            reported_label, reported_family = matching_tags[0]

    statically_confirmed = attribution_basis in STATIC_FAMILY_ATTRIBUTION_BASES
    provider_only = attribution_basis in PROVIDER_FAMILY_ATTRIBUTION_BASES
    if statically_confirmed:
        status = "statically_confirmed"
        catalog_role = "statically_confirmed_family"
        note_ja = "内部の静的handler証拠でファミリーを確認しました。"
    elif provider_only:
        status = "provider_reported_not_statically_confirmed"
        catalog_role = "provider_reported_grouping"
        note_ja = (
            "整理先は提供元報告ラベルに基づきます。内部の静的証拠では"
            "ファミリーを確認しておらず、帰属確定として扱いません。"
        )
    else:
        status = "unresolved"
        catalog_role = "unclassified_grouping"
        note_ja = "内部の静的証拠ではファミリーを解決できていません。"
    return {
        "status": status,
        "basis": attribution_basis,
        "catalog_family": family,
        "catalog_family_role": catalog_role,
        "provider_reported_label": reported_label,
        "provider_reported_family": reported_family,
        "statically_confirmed_family": family if statically_confirmed else None,
        "supports_attribution": statically_confirmed,
        "note_ja": note_ja,
    }


def _family_attribution_readme_lines(
    attribution: dict[str, Any],
) -> list[str]:
    family = attribution["catalog_family"]
    status = attribution["status"]
    if status == "statically_confirmed":
        return [
            f"- 整理先ラベル: `{family}`",
            f"- 内部静的確認済みファミリー: `{family}`",
            "- ファミリー帰属状態: `statically_confirmed`",
        ]
    if status == "provider_reported_not_statically_confirmed":
        label = attribution.get("provider_reported_label") or family
        return [
            f"- 整理先ラベル: `{family}`（提供元報告に基づく）",
            f"- 提供元報告ラベル: `{label}`",
            "- 内部静的確認済みファミリー: `なし`",
            "- ファミリー帰属状態: `provider_reported_not_statically_confirmed`",
            f"- 注意: {attribution['note_ja']}",
        ]
    return [
        f"- 整理先ラベル: `{family}`",
        "- 内部静的確認済みファミリー: `なし`",
        "- ファミリー帰属状態: `unresolved`",
        f"- 注意: {attribution['note_ja']}",
    ]


def _screenconnect_remote_command_capability(logic: dict[str, Any]) -> bool:
    """レビュー済み関数名／callからScreenConnectのremote command能力を判定する。"""

    markers = {
        "runcommandlineprogram",
        "runcommandlinecommands",
        "createremoteprocess",
    }
    for function in logic.get("functions") or []:
        if not isinstance(function, dict):
            continue
        values = [
            function.get("name"),
            *(function.get("api_calls") or []),
            *(function.get("callees") or []),
        ]
        if any(any(marker in str(value).casefold() for marker in markers) for value in values):
            return True
    return False


def render_published_features_markdown(profile: dict[str, Any]) -> str:
    """FEATURESの整理先familyへ帰属状態を併記する。"""

    rendered = render_features_markdown(profile)
    attribution = profile.get("family_attribution")
    if not isinstance(attribution, dict):
        return rendered
    original = f"- ファミリー: `{profile['family']}`"
    replacement = "\n".join(_family_attribution_readme_lines(attribution))
    if rendered.count(original) != 1:
        raise ValueError("FEATURES.mdのfamily表示位置を一意に特定できません")
    rendered = rendered.replace(original, replacement)
    management = profile.get("screenconnect_management_assessment")
    if not isinstance(management, dict):
        return rendered
    marker = "\n## 範囲と制約\n"
    if rendered.count(marker) != 1:
        raise ValueError("FEATURES.mdの制約節を一意に特定できません")
    management_lines = [
        "",
        "## 双用途管理能力の評価",
        "",
        "- 双用途管理client: `確認済み`",
        (
            "- remote command能力: `静的関数証拠で確認済み`"
            if management["remote_command_capability_statically_confirmed"]
            else "- remote command能力: `静的確認未完了`"
        ),
        (f"- 確認済み管理endpoint: `{management['management_endpoint_observations']}`件"),
        (
            "- 別個のmalware C2: "
            + (
                f"`{management['separate_malware_c2_observations']}`件を確認"
                if management["separate_malware_c2_observations"]
                else "`未確認`"
            )
        ),
        "- 管理endpointの悪性利用: `未確認`",
        "",
    ]
    return rendered.replace(marker, "\n".join(management_lines) + marker)


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
    """代表関数解析待ちまたはroot-to-terminal lineage待ちを含む既知blockerだけをstaging対象にする。"""

    state = report.get("case_state")
    blockers = state.get("blockers") if isinstance(state, dict) else None
    if (
        report.get("assessment_only") is not False
        or not isinstance(state, dict)
        or state.get("status") != "partial"
        or state.get("complete") is not False
        or state.get("resumable") is not False
        or not isinstance(blockers, list)
        or not any(blocker in ANALYSIS_FOLLOWUP_BLOCKERS for blocker in blockers)
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
    expected_flags = {
        "complete": (True, True),
        "triaged_unknown": (False, False),
    }
    expected_complete, expected_resumable = expected_flags.get(
        status,
        (None, None),
    )
    if (
        not isinstance(state, dict)
        or status not in expected_flags
        or state.get("complete") is not expected_complete
        or state.get("resumable") is not expected_resumable
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
        require_resumable=(report.get("case_state") or {}).get("status") == "complete",
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


def reseal_canonical_report(
    case_dir: Path,
    report: dict[str, Any],
    *,
    expected_digest: str | None = None,
) -> None:
    """生成後の正規成果物に合わせてhash manifestとreport sealを更新する。"""

    source_manifest = report.get("artifact_sha256")
    if not isinstance(source_manifest, dict) or not source_manifest:
        raise ValueError("reportに成果物hash manifestがありません")
    report["artifact_sha256"] = artifact_hashes(case_dir, source_manifest)
    seal_report(report)
    write_json(case_dir / "report.json", report)
    bound_digest = case_dir.name if expected_digest is None else normalize_sha256_digest(expected_digest)
    errors = case_integrity_errors(
        case_dir,
        report,
        expected_digest=bound_digest,
        require_resumable=(report.get("case_state") or {}).get("status") == "complete",
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


def render_iocs(
    digest: str,
    network_iocs: list[dict[str, Any]] | None = None,
) -> str:
    """提出hashと確認済み静的C2だけをIOC Markdownへ描画する。"""

    return render_submitted_iocs(digest, network_iocs or [])


def _human_readable_provider_filename(value: Any) -> str:
    """Provider側で文字化けした名前を人間向け文書へそのまま出さない。"""

    name = str(value or "").strip()
    if not name:
        return "不明"
    if re.search(r"\?{3,}", name):
        suffix = Path(name).suffix
        return f"providerで判読不能な名前（拡張子 {suffix}）" if suffix else "providerで判読不能な名前"
    return name


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
    confirmed_network_count: int | None = None,
    confirmed_management_count: int = 0,
    family_attribution: dict[str, Any] | None = None,
) -> str:
    if confirmed_network_count is None:
        confirmed_network_count = confirmed_c2_count
    attribution = family_attribution or build_family_attribution(
        family,
        attribution_basis,
        metadata,
    )
    remote_command_confirmed = family == "screenconnect-rmm" and _screenconnect_remote_command_capability(logic)
    if family == "screenconnect-rmm" and confirmed_management_count:
        c2_assessment = (
            f"双用途のScreenConnect管理clientと管理endpointを"
            f"`{confirmed_management_count}`件、静的設定から確認しました。"
            + (
                "レビュー済み関数の`RunCommandLineProgram`等からremote command能力も静的に確認しました。"
                if remote_command_confirmed
                else "remote command実行経路はこの成果物では静的確認未完了です。"
            )
            + (
                f"別個のmalware C2観測を`{confirmed_c2_count}`件記録しました。"
                if confirmed_c2_count
                else "別個のmalware C2は未確認です。"
            )
            + "管理endpointの悪性利用、所有者、到達性は確認していません。"
        )
    elif confirmed_network_count:
        c2_assessment = (
            f"ファミリー固有handlerの静的設定構造から、確認済み通信先を"
            f"`{confirmed_network_count}`件、そのうちC2観測を"
            f"`{confirmed_c2_count}`件記録しました。"
            "重複するendpointでもroleまたはevidenceが異なる観測は保持しています。"
            "到達性、所有者、稼働状況は未確認です。"
        )
    else:
        c2_assessment = (
            "汎用文字列走査の候補をC2として採用していません。"
            "ファミリー固有設定で裏付けられない限り、現在のC2、所有者、到達性は未確認です。"
        )
    signature = metadata.get("signature") or "未報告"
    tags = ", ".join(str(value) for value in (metadata.get("tags") or [])) or "なし"
    lines = [
        f"# Windows検体ケース {digest}",
        "",
        "## 概要",
        "",
        *_family_attribution_readme_lines(attribution),
        f"- 分類根拠: `{attribution_basis}`",
        f"- MalwareBazaar報告signature: `{signature}`",
        f"- MalwareBazaarタグ: `{tags}`",
        f"- 初回観測: `{metadata.get('first_seen') or '不明'}`",
        f"- 元ファイル名: `{_human_readable_provider_filename(metadata.get('file_name'))}`",
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
        "、".join(f"`{item['capability']}`（`{item['imports']}`）" for item in capabilities)
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
            c2_assessment,
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


def _refresh_legacy_screenconnect_orchestration(
    report: dict[str, Any],
    outcome: dict[str, Any],
    handler_results: list[tuple[dict[str, Any], dict[str, Any]]],
) -> bool:
    """封印済み旧ScreenConnect成果物からconfig・通信gateだけを再評価する。"""

    resolution = outcome.get("family_resolution")
    gates = outcome.get("quality_gates")
    state = report.get("case_state")
    if (
        outcome.get("schema_version") != 2
        or not isinstance(resolution, dict)
        or resolution.get("status") != "resolved"
        or resolution.get("family") != "screenconnect_rmm"
        or not isinstance(gates, dict)
        or not isinstance(state, dict)
        or (report.get("candidate_handler_assessment") or {}).get("planned_attempt_count") != 0
    ):
        return False
    old_blockers = outcome.get("blockers")
    old_actions = outcome.get("next_actions_ja")
    report_blockers = state.get("blockers")
    if (
        not isinstance(old_blockers, list)
        or old_blockers != sorted(set(old_blockers))
        or not isinstance(old_actions, list)
        or len(old_actions) != len(old_blockers)
        or not isinstance(report_blockers, list)
        or {
            value.removeprefix("orchestration:")
            for value in report_blockers
            if isinstance(value, str) and value.startswith("orchestration:")
        }
        != set(old_blockers)
    ):
        raise ValueError("ScreenConnect旧成果物のblocker整合性を確認できません")
    action_by_blocker = dict(zip(old_blockers, old_actions, strict=True))
    expected_actions = {
        "config": "family固有config extractorを追加または更新してください。",
        "network": "復号configから通信先を抽出する処理を追加してください。",
    }
    records: list[dict[str, Any]] = []
    for execution, artifact in handler_results:
        payload = artifact.get("result")
        if legacy_screenconnect_config(payload) is None:
            continue
        if not trusted_handler_result(execution, artifact):
            raise ValueError("ScreenConnect旧成果物のhandler信頼境界を確認できません")
        handler = artifact.get("handler")
        if (
            not isinstance(handler, dict)
            or handler.get("family") != "screenconnect_rmm"
            or handler.get("id") != execution.get("handler_id")
        ):
            raise ValueError("ScreenConnect旧成果物のhandler identityが一致しません")
        record = {
            "source": "selected_family_analysis",
            "family": "screenconnect_rmm",
            "handler_id": execution["handler_id"],
            "status": execution.get("status"),
            "selected_evidence": execution.get("selected_evidence"),
            "selected_layer_sha256": execution.get("selected_layer_sha256"),
            "result": artifact,
        }
        verified = artifact.get("verified_binary_outputs")
        if isinstance(verified, list) and verified:
            record["verified_binary_outputs"] = verified
        audit = artifact.get("verified_binary_output_audit")
        if isinstance(audit, dict):
            record["verified_binary_output_audit"] = audit
        records.append(record)
    if not records:
        return False
    if len(records) != 1:
        raise ValueError("ScreenConnect旧成果物の適格handlerが一意ではありません")

    outputs = orchestration_outcome.summarize_handler_outputs(
        records,
        family_filter="screenconnect_rmm",
    )
    endpoints = outputs.get("qualified_network_endpoints")
    if (
        outputs.get("config_recovered") is not True
        or not isinstance(endpoints, list)
        or not endpoints
        or any(
            not isinstance(endpoint, dict)
            or endpoint.get("role") not in {"remote_management_relay", "screenconnect_clickonce_bootstrap"}
            for endpoint in endpoints
        )
    ):
        raise ValueError("ScreenConnect旧成果物から双用途管理先を厳格に再評価できません")
    for name, observed in (("config", None), ("network", True)):
        gate = gates.get(name)
        if (
            not isinstance(gate, dict)
            or gate.get("required") is not True
            or gate.get("status") not in {"required_missing", "satisfied"}
            or name in action_by_blocker
            and action_by_blocker[name] != expected_actions[name]
        ):
            raise ValueError(f"ScreenConnect旧成果物の{name} gateが不正です")
        gate["satisfied"] = True
        gate["observed"] = observed
        gate["status"] = "satisfied"

    outcome["outputs"] = outputs
    outcome["candidate_outputs"] = orchestration_outcome.summarize_handler_outputs(
        records,
        verified_only=False,
    )
    refreshed_blockers = sorted(
        name for name, gate in gates.items() if isinstance(gate, dict) and gate.get("status") == "required_missing"
    )
    if any(name not in action_by_blocker for name in refreshed_blockers):
        raise ValueError("ScreenConnect旧成果物の残余next actionを確認できません")
    outcome["blockers"] = refreshed_blockers
    outcome["next_actions_ja"] = [action_by_blocker[name] for name in refreshed_blockers]
    outcome["status"] = "partial" if refreshed_blockers else "complete"
    state["blockers"] = sorted(
        {value for value in report_blockers if isinstance(value, str) and not value.startswith("orchestration:")}
        | {f"orchestration:{name}" for name in refreshed_blockers}
    )
    state["status"] = "partial" if state["blockers"] else "complete"
    state["complete"] = not state["blockers"]
    state["resumable"] = not state["blockers"]
    return True


def _build_screenconnect_management_contract(
    *,
    digest: str,
    public_family: str,
    layer_report: dict[str, Any],
    handler_results: list[tuple[dict[str, Any], dict[str, Any]]],
    report: dict[str, Any],
    orchestration: dict[str, Any] | None,
) -> tuple[dict[str, Any], dict[str, Any]] | None:
    """検証済みScreenConnect終端clientだけC2非該当契約へ再構築する。"""

    if public_family != "screenconnect-rmm":
        return None
    state = report.get("case_state")
    resolution = orchestration.get("family_resolution") if isinstance(orchestration, dict) else None
    gates = orchestration.get("quality_gates") if isinstance(orchestration, dict) else None
    counts = layer_report.get("counts")
    limit_events = layer_report.get("limit_events")
    state_pending = (
        isinstance(state, dict)
        and state.get("status") == "partial"
        and state.get("complete") is False
        and state.get("resumable") is False
        and isinstance(state.get("blockers"), list)
        and bool(state["blockers"])
        and all(isinstance(value, str) and bool(value) for value in state["blockers"])
        and len(state["blockers"]) == len(set(state["blockers"]))
    )
    orchestration_pending = (
        isinstance(orchestration, dict)
        and orchestration.get("status") == "partial"
        and isinstance(orchestration.get("blockers"), list)
        and bool(orchestration["blockers"])
        and all(isinstance(value, str) and bool(value) for value in orchestration["blockers"])
        and len(orchestration["blockers"]) == len(set(orchestration["blockers"]))
    )
    if state_pending or orchestration_pending:
        if (
            not (state_pending and orchestration_pending)
            or not isinstance(orchestration, dict)
            or type(orchestration.get("schema_version")) is not int
            or orchestration.get("schema_version") != 2
            or orchestration.get("sample_sha256") != digest
            or not isinstance(resolution, dict)
            or resolution.get("status") != "resolved"
            or resolution.get("family") != "screenconnect_rmm"
            or not isinstance(gates, dict)
        ):
            raise ValueError("ScreenConnect pending C2契約の対象identityが不正です")
        return None
    if (
        not isinstance(state, dict)
        or state.get("status") != "complete"
        or state.get("complete") is not True
        or state.get("resumable") is not True
        or state.get("blockers") != []
        or not isinstance(orchestration, dict)
        or type(orchestration.get("schema_version")) is not int
        or orchestration.get("schema_version") != 2
        or orchestration.get("sample_sha256") != digest
        or orchestration.get("status") != "complete"
        or orchestration.get("blockers") != []
        or orchestration.get("next_actions_ja") != []
        or not isinstance(resolution, dict)
        or resolution.get("status") != "resolved"
        or resolution.get("family") != "screenconnect_rmm"
        or not isinstance(gates, dict)
        or any(
            not isinstance(gate, dict)
            or not (
                (gate.get("required") is True and gate.get("satisfied") is True and gate.get("status") == "satisfied")
                or (
                    gate.get("required") is False
                    and gate.get("satisfied") is False
                    and gate.get("status") == "not_applicable"
                )
            )
            for gate in gates.values()
        )
        or any(
            not isinstance(gates.get(name), dict)
            or gates[name].get("required") is not True
            or gates[name].get("satisfied") is not True
            or gates[name].get("status") != "satisfied"
            for name in (
                "generic_triage",
                "static_layers",
                "family_resolution",
                "handler_evidence",
                "config",
                "network",
                "function_analysis",
                "requirements_policy",
            )
        )
        or not isinstance(gates.get("terminal_payload"), dict)
        or gates["terminal_payload"].get("required") is not False
        or gates["terminal_payload"].get("satisfied") is not False
        or gates["terminal_payload"].get("status") != "not_applicable"
        or not isinstance(counts, dict)
        or type(counts.get("limit_events")) is not int
        or counts.get("limit_events") != 0
        or limit_events != []
    ):
        raise ValueError("ScreenConnect C2非該当判定の外側静的品質gateが未完了です")
    eligible = [
        (execution, artifact)
        for execution, artifact in handler_results
        if validated_screenconnect_config(artifact.get("result")) is not None
    ]
    if not eligible:
        raise ValueError("完了ScreenConnect caseのconfig証拠を再検証できません")
    if len(eligible) != 1 or len(handler_results) != 1:
        raise ValueError("ScreenConnect C2契約を一意なhandler証拠へ結合できません")
    execution, artifact = eligible[0]
    if not trusted_handler_result(execution, artifact):
        raise ValueError("ScreenConnect C2契約のhandler信頼境界を確認できません")
    handler = artifact.get("handler")
    if (
        not isinstance(handler, dict)
        or handler.get("family") != "screenconnect_rmm"
        or handler.get("id") != execution.get("handler_id")
        or execution.get("selected_layer_sha256") != digest
    ):
        raise ValueError("ScreenConnect C2契約を対象root handlerへ結合できません")
    validated_config = validated_screenconnect_config(artifact.get("result"))
    if validated_config is None:
        raise ValueError("ScreenConnect C2契約のconfigを再検証できません")
    patterns, contract = build_case_automation_artifacts(
        sha256=digest,
        family="screenconnect_rmm",
        layer_report=layer_report,
        handler_results=eligible,
        screenconnect_no_c2_completion_verified=True,
    )
    config = patterns.get("config")
    communication = patterns.get("communication")
    phases = {item.get("phase"): item for item in contract.get("phase_evidence", []) if isinstance(item, dict)}
    if (
        not isinstance(config, dict)
        or config.get("static_config_recovered") is not True
        or config.get("terminal_managed_client") is not True
        or not isinstance(communication, dict)
        or not 1 <= len(communication.get("confirmed_static_management_endpoints", [])) <= 2
        or len(communication["confirmed_static_management_endpoints"]) != len(validated_config["config_endpoints"])
        or communication.get("confirmed_static_endpoints") != communication["confirmed_static_management_endpoints"]
        or communication.get("confirmed_static_c2_endpoints") != []
        or communication.get("candidate_patterns") != []
        or communication.get("protocol_confirmed") is not False
        or communication.get("protocol_evidence") != []
        or contract.get("c2", {}).get("outcome") != "no_c2_capability_verified"
        or contract.get("c2", {}).get("endpoints") != []
        or contract.get("c2", {}).get("protocol", {}).get("status") != "not_applicable"
        or any(
            not isinstance(phases.get(name), dict) or phases[name].get("status") == "blocked"
            for name in REQUIRED_PHASES
        )
        or contract.get("terminal_payload", {}).get("blockers") != []
        or contract.get("deep_analysis", {}).get("blockers") != []
    ):
        raise ValueError("ScreenConnect終端clientのC2非該当契約を厳格に再構築できません")
    validation = validate_c2_contract(contract, digest)
    if validation.get("complete") is not True:
        raise ValueError("ScreenConnect C2非該当契約が完了条件を満たしません")
    return patterns, contract


def _is_legacy_vidar_structural_endpoint(
    value: Any,
    *,
    handler_id: str,
) -> bool:
    """旧集計器がkind=network.urlをhost化したexact recordだけを識別する。"""

    if not isinstance(value, dict) or set(value) != {
        "host",
        "port",
        "scheme",
        "path",
        "contacted",
        "provenance",
    }:
        return False
    provenance = value.get("provenance")
    return bool(
        value.get("host") == "network.url"
        and value.get("port") is None
        and value.get("scheme") is None
        and value.get("path") is None
        and value.get("contacted") is False
        and isinstance(provenance, list)
        and provenance
        and all(
            isinstance(item, dict)
            and set(item) == {"family", "handler_id", "source", "evidence_path"}
            and item.get("family") == "vidar"
            and item.get("handler_id") == handler_id
            and item.get("source") == "selected_family_analysis"
            and isinstance(item.get("evidence_path"), str)
            and re.fullmatch(r"findings\.[0-9]+\.kind", item["evidence_path"]) is not None
            for item in provenance
        )
    )


def _refresh_legacy_vidar_structural_network_labels(
    report: dict[str, Any],
    outcome: dict[str, Any],
    handler_results: list[tuple[dict[str, Any], dict[str, Any]]],
) -> bool:
    """旧Vidar成果物からschema labelの偽endpointだけをfail-closedで除去する。"""

    resolution = outcome.get("family_resolution")
    if (
        outcome.get("schema_version") != 2
        or not isinstance(resolution, dict)
        or resolution.get("status") != "resolved"
        or resolution.get("family") != "vidar"
        or (report.get("candidate_handler_assessment") or {}).get("planned_attempt_count") != 0
    ):
        return False

    records: list[dict[str, Any]] = []
    handler_ids: list[str] = []
    for execution, artifact in handler_results:
        handler = artifact.get("handler")
        if not isinstance(handler, dict) or handler.get("family") != "vidar":
            continue
        if not trusted_handler_result(execution, artifact):
            raise ValueError("Vidar旧成果物のhandler信頼境界を確認できません")
        handler_id = execution.get("handler_id")
        if not isinstance(handler_id, str) or handler.get("id") != handler_id:
            raise ValueError("Vidar旧成果物のhandler identityが一致しません")
        record = {
            "source": "selected_family_analysis",
            "family": "vidar",
            "handler_id": handler_id,
            "status": execution.get("status"),
            "selected_evidence": execution.get("selected_evidence"),
            "selected_layer_sha256": execution.get("selected_layer_sha256"),
            "result": artifact,
        }
        verified = artifact.get("verified_binary_outputs")
        if isinstance(verified, list) and verified:
            record["verified_binary_outputs"] = verified
        audit = artifact.get("verified_binary_output_audit")
        if isinstance(audit, dict):
            record["verified_binary_output_audit"] = audit
        records.append(record)
        handler_ids.append(handler_id)
    if not records:
        return False
    if len(records) != 1:
        raise ValueError("Vidar旧成果物の適格handlerが一意ではありません")

    refreshed = orchestration_outcome.summarize_handler_outputs(
        records,
        family_filter="vidar",
    )
    refreshed_candidates = orchestration_outcome.summarize_handler_outputs(
        records,
        verified_only=False,
    )

    def without_legacy_label(value: Any, label: str) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise ValueError(f"Vidar旧成果物の{label}がobjectではありません")
        endpoints = value.get("network_endpoints")
        if not isinstance(endpoints, list):
            raise ValueError(f"Vidar旧成果物の{label}.network_endpointsが不正です")
        kept = [
            endpoint
            for endpoint in endpoints
            if not _is_legacy_vidar_structural_endpoint(
                endpoint,
                handler_id=handler_ids[0],
            )
        ]
        if len(kept) == len(endpoints):
            raise ValueError(f"Vidar旧成果物の{label}にexact structural labelがありません")
        return {**value, "network_endpoints": kept}

    old_outputs = without_legacy_label(outcome.get("outputs"), "outputs")
    old_candidates = without_legacy_label(
        outcome.get("candidate_outputs"),
        "candidate_outputs",
    )
    if old_outputs != refreshed or old_candidates != refreshed_candidates:
        raise ValueError("Vidar旧成果物はstructural label以外にも差分があります")
    outcome["outputs"] = refreshed
    outcome["candidate_outputs"] = refreshed_candidates
    return True


def _publication_case_path_sha256(path: Path) -> str:
    normalized = os.path.normcase(os.fspath(Path(os.path.abspath(path))))
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _publication_io_path(path: Path) -> Path:
    """Windowsのdeep canonical layoutではextended-length pathでI/Oする。"""

    absolute = Path(os.path.abspath(path))
    if os.name != "nt":
        return absolute
    value = os.fspath(absolute)
    if value.startswith("\\\\?\\"):
        return absolute
    if value.startswith("\\\\"):
        return Path(f"\\\\?\\UNC\\{value.lstrip(chr(92))}")
    return Path(f"\\\\?\\{value}")


def _same_publication_path(first: Path, second: Path) -> bool:
    def normalized(path: Path) -> str:
        value = os.fspath(path)
        if value.startswith("\\\\?\\UNC\\"):
            value = "\\\\" + value[8:]
        elif value.startswith("\\\\?\\"):
            value = value[4:]
        return os.path.normcase(os.path.abspath(value))

    return normalized(first) == normalized(second)


def _case_tree_sha256(path: Path) -> str:
    manifest = analysis_job_runner.analysis_output_content_manifest(path)
    return analysis_job_runner.analysis_output_content_sha256(manifest)


def _publication_case_name_key(destination: Path) -> str:
    if SHA256_RE.fullmatch(destination.name) is not None:
        return destination.name
    return _publication_case_path_sha256(destination)


def _publication_journal_path(destination: Path) -> Path:
    return _publication_io_path(
        destination.parent / f".casepub-{_publication_case_name_key(destination)}.transaction.json"
    )


class _CasePublicationLock:
    """同一canonical caseのpublisherをprocess間で排他する。"""

    def __init__(self, destination: Path) -> None:
        commitment = _publication_case_path_sha256(destination)
        self.path = Path(tempfile.gettempdir()) / "ai-security-analysis-case-publication-locks" / f"{commitment}.lock"
        self.descriptor: int | None = None

    def __enter__(self) -> _CasePublicationLock:
        ensure_no_reparse_components(self.path.parent)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        ensure_no_reparse_components(self.path.parent)
        descriptor = os.open(
            self.path,
            os.O_RDWR | os.O_CREAT | getattr(os, "O_BINARY", 0),
            0o600,
        )
        try:
            if os.fstat(descriptor).st_size == 0:
                os.write(descriptor, b"\0")
                os.fsync(descriptor)
            os.lseek(descriptor, 0, os.SEEK_SET)
            if os.name == "nt":
                import msvcrt  # noqa: PLC0415

                msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl  # noqa: PLC0415

                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (OSError, BlockingIOError) as exc:
            os.close(descriptor)
            raise ValueError("同一caseのpublisherが既に実行中です") from exc
        self.descriptor = descriptor
        return self

    def __exit__(self, *_args: object) -> None:
        if self.descriptor is None:
            return
        try:
            os.lseek(self.descriptor, 0, os.SEEK_SET)
            if os.name == "nt":
                import msvcrt  # noqa: PLC0415

                msvcrt.locking(self.descriptor, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl  # noqa: PLC0415

                fcntl.flock(self.descriptor, fcntl.LOCK_UN)
        finally:
            os.close(self.descriptor)
            self.descriptor = None


def _atomic_publication_journal(
    path: Path,
    document: dict[str, Any],
    *,
    expected_sha256: str | None = None,
    require_absent: bool = False,
) -> str:
    """case昇格journalをfsync済み同一親fileからatomicに置換する。"""

    ensure_no_reparse_components(path.parent)
    path.parent.mkdir(parents=True, exist_ok=True)
    ensure_no_reparse_components(path.parent)
    current_sha256: str | None = None
    if path.is_file():
        raw, _current = analysis_job_runner.load_json_object_snapshot(
            path,
            max_bytes=1024 * 1024,
        )
        current_sha256 = hashlib.sha256(raw).hexdigest()
    elif os.path.lexists(path):
        raise ValueError("case公開journalが通常fileではありません")
    if require_absent and current_sha256 is not None:
        raise ValueError("case公開journalが既に存在します")
    if expected_sha256 is not None and current_sha256 != expected_sha256:
        raise ValueError("case公開journalが競合変更されました")
    payload = (json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    temporary = path.with_name(f".{path.name}.{os.getpid():x}.{time.time_ns():x}.tmp")
    try:
        with temporary.open("xb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        if expected_sha256 is not None:
            raw, _current = analysis_job_runner.load_json_object_snapshot(
                path,
                max_bytes=1024 * 1024,
            )
            if hashlib.sha256(raw).hexdigest() != expected_sha256:
                raise ValueError("case公開journalがcommit直前に変更されました")
        elif require_absent and os.path.lexists(path):
            raise ValueError("case公開journalがcommit直前に作成されました")
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()
    return hashlib.sha256(payload).hexdigest()


def _unlink_publication_journal(path: Path, *, expected_sha256: str) -> None:
    """読込時commitmentと一致するjournalだけを削除する。"""

    raw, _document = analysis_job_runner.load_json_object_snapshot(
        path,
        max_bytes=1024 * 1024,
    )
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError("case公開journalが回復中に変更されました")
    path.unlink()


def _remove_committed_case_tree(path: Path, *, expected_sha256: str) -> None:
    """transaction journalへhash結合されたcase treeだけを削除する。"""

    if _case_tree_sha256(path) != expected_sha256:
        raise ValueError("case公開transaction treeがcommitmentから変更されました")
    ensure_no_reparse_components(path)
    shutil.rmtree(path)


def _remove_owned_partial_staging(container: Path, *, destination: Path) -> None:
    """pre-build journalへ束縛した同一親のpartial stagingだけを除去する。"""

    prefix = f".casepub-{_publication_case_name_key(destination)}."
    if (
        not _same_publication_path(container.parent, destination.parent)
        or not container.name.startswith(prefix)
        or not container.name.endswith(".staging")
    ):
        raise ValueError("partial case stagingのowned境界が不正です")
    ensure_no_reparse_components(container)
    information = container.lstat()
    if not stat.S_ISDIR(information.st_mode):
        raise ValueError("partial case stagingがdirectoryではありません")
    for path in container.rglob("*"):
        metadata = path.lstat()
        if getattr(metadata, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400):
            raise ValueError("partial case stagingにreparse pointがあります")
        if stat.S_ISREG(metadata.st_mode) and metadata.st_nlink != 1:
            raise ValueError("partial case stagingにhardlinkがあります")
        if not (stat.S_ISREG(metadata.st_mode) or stat.S_ISDIR(metadata.st_mode)):
            raise ValueError("partial case stagingに未許可entryがあります")
    shutil.rmtree(container)


def _recover_case_publication(destination: Path) -> str | None:
    """中断したcase directory昇格を内容hashによりrollback／roll-forwardする。"""

    journal_path = _publication_journal_path(destination)
    if not os.path.lexists(journal_path):
        return None
    raw, journal = analysis_job_runner.load_json_object_snapshot(
        journal_path,
        max_bytes=1024 * 1024,
    )
    journal_sha256 = hashlib.sha256(raw).hexdigest()
    existing = journal.get("existing_destination")
    old_sha256 = journal.get("old_tree_sha256")
    new_sha256 = journal.get("new_tree_sha256")
    staging_name = journal.get("staging_name")
    backup_name = journal.get("backup_name")
    if (
        journal.get("schema_version") != CASE_PUBLICATION_TRANSACTION_SCHEMA
        or journal.get("case_sha256") != destination.name
        or journal.get("destination_path_sha256") != _publication_case_path_sha256(destination)
        or journal.get("phase") not in {"building", "prepared", "applying", "verified"}
        or type(existing) is not bool
        or (existing and (not isinstance(old_sha256, str) or SHA256_RE.fullmatch(old_sha256) is None))
        or (not existing and old_sha256 is not None)
        or (journal.get("phase") == "building" and new_sha256 is not None)
        or (
            journal.get("phase") != "building"
            and (not isinstance(new_sha256, str) or SHA256_RE.fullmatch(new_sha256) is None)
        )
        or not isinstance(staging_name, str)
        or not isinstance(backup_name, str)
        or Path(staging_name).name != staging_name
        or Path(backup_name).name != backup_name
        or not staging_name.startswith(f".casepub-{_publication_case_name_key(destination)}.")
        or not staging_name.endswith(".staging")
        or not backup_name.startswith(f".casepub-{_publication_case_name_key(destination)}.")
        or not backup_name.endswith(".backup")
    ):
        raise ValueError("case公開transaction journalの契約が不正です")
    staging_container = _publication_io_path(destination.parent / staging_name)
    staging = staging_container / destination.name
    backup = _publication_io_path(destination.parent / backup_name)

    def observed(path: Path) -> str | None:
        if not os.path.lexists(path):
            return None
        if not path.is_dir():
            raise ValueError("case公開transaction pathがdirectoryではありません")
        return _case_tree_sha256(path)

    destination_sha = observed(destination)
    if os.path.lexists(staging_container):
        if not staging_container.is_dir():
            raise ValueError("case公開staging containerがdirectoryではありません")
        children = list(staging_container.iterdir())
        if any(path.name != destination.name for path in children):
            raise ValueError("case公開staging containerに未束縛entryがあります")
    staging_sha = None if journal["phase"] == "building" else observed(staging)
    backup_sha = observed(backup)
    allowed_destination = {None, old_sha256}
    if isinstance(new_sha256, str):
        allowed_destination.add(new_sha256)
    if destination_sha not in allowed_destination:
        raise ValueError("case公開先に第三者変更を検出しました")
    if staging_sha not in ({None, new_sha256} if isinstance(new_sha256, str) else {None}):
        raise ValueError("case公開stagingに第三者変更を検出しました")
    if backup_sha not in ({None, old_sha256} if existing else {None}):
        raise ValueError("case公開backupに第三者変更を検出しました")

    if journal["phase"] == "building":
        if backup_sha is not None or destination_sha != old_sha256:
            raise ValueError("building中のcase公開transactionが公開先を変更しています")
        if os.path.lexists(staging_container):
            _remove_owned_partial_staging(
                staging_container,
                destination=destination,
            )
        _unlink_publication_journal(
            journal_path,
            expected_sha256=journal_sha256,
        )
        return "discarded_partial_build"

    if journal["phase"] == "verified":
        if destination_sha != new_sha256 or staging_sha is not None:
            raise ValueError("verified case公開transactionが部分適用状態です")
        if os.path.lexists(staging_container):
            staging_container.rmdir()
        if backup_sha is not None:
            _remove_committed_case_tree(backup, expected_sha256=old_sha256)
        _unlink_publication_journal(
            journal_path,
            expected_sha256=journal_sha256,
        )
        return "rolled_forward"

    if destination_sha == new_sha256:
        _remove_committed_case_tree(destination, expected_sha256=new_sha256)
        destination_sha = None
    if existing:
        if destination_sha == old_sha256 and backup_sha == old_sha256:
            _remove_committed_case_tree(backup, expected_sha256=old_sha256)
            backup_sha = None
        elif destination_sha is None and backup_sha == old_sha256:
            os.replace(backup, _publication_io_path(destination))
            destination_sha = _case_tree_sha256(destination)
            backup_sha = None
        if destination_sha != old_sha256 or backup_sha is not None:
            raise ValueError("case公開transactionを元caseへrollbackできません")
    elif destination_sha is not None or backup_sha is not None:
        raise ValueError("新規case公開transactionを未公開状態へrollbackできません")
    if staging_sha == new_sha256:
        _remove_committed_case_tree(staging, expected_sha256=new_sha256)
    if os.path.lexists(staging_container):
        staging_container.rmdir()
    _unlink_publication_journal(
        journal_path,
        expected_sha256=journal_sha256,
    )
    return "rolled_back"


def _promote_case_publication(
    destination: Path,
    staging: Path,
    *,
    new_tree_sha256: str,
    journal: dict[str, Any],
    journal_sha256: str,
) -> None:
    """検証済みstagingをdurable journal付きでcanonical caseへ昇格する。"""

    existing = journal["existing_destination"]
    old_tree_sha256 = journal["old_tree_sha256"]
    destination_io = _publication_io_path(destination)
    backup = _publication_io_path(destination.parent / journal["backup_name"])
    journal_path = _publication_journal_path(destination)
    try:
        if _case_tree_sha256(staging) != new_tree_sha256:
            raise ValueError("case公開stagingが昇格直前に変更されました")
        if existing and _case_tree_sha256(destination) != old_tree_sha256:
            raise ValueError("canonical caseが昇格直前に変更されました")
        journal["phase"] = "applying"
        journal_sha256 = _atomic_publication_journal(
            journal_path,
            journal,
            expected_sha256=journal_sha256,
        )
        if existing:
            os.replace(destination_io, backup)
        os.replace(staging, destination_io)
        staging.parent.rmdir()
        if _case_tree_sha256(destination) != new_tree_sha256:
            raise ValueError("昇格後canonical caseのtree hashが一致しません")
        journal["phase"] = "verified"
        _atomic_publication_journal(
            journal_path,
            journal,
            expected_sha256=journal_sha256,
        )
        _recover_case_publication(destination)
    except BaseException:
        try:
            _recover_case_publication(destination)
        except BaseException as recovery_error:
            raise RuntimeError("case公開transactionを自動回復できませんでした") from recovery_error
        raise


def publish_case(
    repository: Path,
    results: Path,
    collection_id: str,
    source: Path,
    item: dict[str, Any],
    existing_families: set[str],
    *,
    allow_function_staging: bool = False,
    _staging_destination: Path | None = None,
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
    family_attribution = build_family_attribution(
        family,
        attribution_basis,
        metadata,
    )
    statically_confirmed_family = family_attribution["statically_confirmed_family"]
    canonical_destination = resolve_catalog_case_path(results, digest, family=family)
    existing_metadata_path = canonical_destination / "metadata.json"
    existing_version = None
    if existing_metadata_path.is_file():
        existing_metadata = load_json(existing_metadata_path)
        if existing_metadata.get("sha256") != digest:
            raise ValueError(f"既存metadataのSHA-256が一致しません: {digest}")
        if existing_metadata.get("family") != family:
            raise ValueError(f"既存metadataのfamilyが一致しません: {digest}")
        candidate_version = existing_metadata.get("malware_version")
        if not isinstance(candidate_version, dict):
            raise ValueError(f"既存metadataのmalware_versionが不正です: {digest}")
        existing_version = dict(candidate_version)
    if _staging_destination is None:
        canonical_destination.parent.mkdir(parents=True, exist_ok=True)
        with _CasePublicationLock(canonical_destination):
            _recover_case_publication(canonical_destination)
            existing = canonical_destination.is_dir()
            if not existing and os.path.lexists(canonical_destination):
                raise ValueError("canonical case pathがdirectoryではありません")
            old_tree_sha256 = _case_tree_sha256(canonical_destination) if existing else None
            token = f".casepub-{_publication_case_name_key(canonical_destination)}.{os.getpid():x}-{time.time_ns():x}"
            staging_container = canonical_destination.parent / f"{token}.staging"
            staging_container_io = _publication_io_path(staging_container)
            staging = staging_container_io / digest
            backup = canonical_destination.parent / f"{token}.backup"
            journal = {
                "schema_version": CASE_PUBLICATION_TRANSACTION_SCHEMA,
                "case_sha256": digest,
                "destination_path_sha256": _publication_case_path_sha256(canonical_destination),
                "existing_destination": existing,
                "old_tree_sha256": old_tree_sha256,
                "new_tree_sha256": None,
                "staging_name": staging_container.name,
                "backup_name": backup.name,
                "phase": "building",
            }
            journal_path = _publication_journal_path(canonical_destination)
            journal_sha256 = _atomic_publication_journal(
                journal_path,
                journal,
                require_absent=True,
            )
            try:
                staging_container_io.mkdir()
                family_value, _destination, summary = publish_case(
                    repository,
                    results,
                    collection_id,
                    source,
                    item,
                    existing_families,
                    allow_function_staging=allow_function_staging,
                    _staging_destination=staging,
                )
                new_tree_sha256 = _case_tree_sha256(staging)
                journal["new_tree_sha256"] = new_tree_sha256
                journal["phase"] = "prepared"
                journal_sha256 = _atomic_publication_journal(
                    journal_path,
                    journal,
                    expected_sha256=journal_sha256,
                )
                _promote_case_publication(
                    canonical_destination,
                    staging,
                    new_tree_sha256=new_tree_sha256,
                    journal=journal,
                    journal_sha256=journal_sha256,
                )
                return family_value, canonical_destination, summary
            except BaseException:
                try:
                    _recover_case_publication(canonical_destination)
                except BaseException as recovery_error:
                    raise RuntimeError("case公開build transactionを自動回復できませんでした") from recovery_error
                raise
    destination = _staging_destination
    if (
        destination.name != digest
        or not _same_publication_path(
            destination.parent.parent,
            canonical_destination.parent,
        )
        or not destination.parent.name.startswith(f".casepub-{_publication_case_name_key(canonical_destination)}.")
        or not destination.parent.name.endswith(".staging")
    ):
        raise ValueError("case公開stagingはcanonical caseと同じparentに限定します")
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
        if name == "classification.json":
            documents[name]["publication_attribution"] = family_attribution
        write_json(destination / name, documents[name])
    for relative_value in (report.get("knowledge_artifacts") or {}).values():
        relative = normalize_artifact_path(relative_value)
        source_path = resolve_case_artifact(source, relative)
        target = destination.joinpath(*relative.split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source_path.read_bytes())
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
    evidence_family = "screenconnect_rmm" if family == "screenconnect-rmm" else family
    management_iocs = [
        record
        for record in network_iocs
        if is_dual_use_management_endpoint(
            record,
            family=evidence_family,
            handler_results=trusted_handler_results,
        )
    ]
    management_identities = {
        json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")) for record in management_iocs
    }
    confirmed_c2_iocs = [
        record
        for record in network_iocs
        if json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")) not in management_identities
    ]
    config_recovered = static_config_recovered(trusted_handler_results, network_iocs)
    orchestration_path = destination / "orchestration.json"
    orchestration_document: dict[str, Any] | None = None
    if orchestration_path.is_file():
        orchestration_document = load_json(orchestration_path)
        orchestration_refreshed = _refresh_legacy_screenconnect_orchestration(
            report,
            orchestration_document,
            trusted_handler_results,
        )
        orchestration_refreshed = (
            _refresh_legacy_vidar_structural_network_labels(
                report,
                orchestration_document,
                trusted_handler_results,
            )
            or orchestration_refreshed
        )
        if orchestration_refreshed:
            write_json(orchestration_path, orchestration_document)

    logic = load_json(resolve_case_artifact(source, "static-logic.json"))
    logic["family"] = statically_confirmed_family or "unclassified"
    logic["publication_attribution"] = family_attribution
    write_json(destination / "static-logic.json", logic)
    (destination / "STATIC-LOGIC.md").write_text(render_static_logic_markdown(logic), encoding="utf-8")
    (destination / "OVERALL-LOGIC.md").write_text(
        render_overall_logic_markdown(logic, documents["static-layers.json"]),
        encoding="utf-8",
    )
    generic = documents["generic-triage.json"]
    pe = pe_summary(generic)
    capabilities = capability_notes(pe)
    version = existing_version or {
        "status": "unknown",
        "reported": None,
        "normalized_key": "unknown",
        "confidence": "none",
        "reason": "no_approved_sample_specific_version_evidence",
        "evidence": [],
    }
    canonical_path = canonical_destination.relative_to(repository).as_posix()
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
            **family_attribution,
            "reported_signature": metadata.get("signature"),
            "reported_tags": metadata.get("tags") or [],
        },
        "safety": {"sample_executed": False, "network_contacted": False},
    }
    write_json(destination / "metadata.json", metadata_document)
    handler_ids = [
        str(execution.get("handler_id"))
        for execution in (report.get("handler_executions") or [])
        if isinstance(execution, dict) and isinstance(execution.get("handler_id"), str)
    ]
    source_c2_path = source / "c2-analysis.json"
    source_c2 = load_json(source_c2_path) if source_c2_path.is_file() else {}
    screenconnect_contract = _build_screenconnect_management_contract(
        digest=digest,
        public_family=family,
        layer_report=documents["static-layers.json"],
        handler_results=trusted_handler_results,
        report=report,
        orchestration=orchestration_document,
    )
    if screenconnect_contract is not None:
        communication_patterns, c2_analysis = screenconnect_contract
        write_json(destination / "communication-patterns.json", communication_patterns)
    elif source_c2.get("sha256") == digest and not (
        family == "screenconnect-rmm" and source_c2.get("c2", {}).get("outcome") == "no_c2_capability_verified"
    ):
        c2_analysis = source_c2
    else:
        c2_analysis = build_unresolved_contract(digest, family, handlers=handler_ids)
    c2_validation = validate_c2_contract(c2_analysis, digest, repository=repository)
    write_json(destination / "c2-analysis.json", c2_analysis)
    screenconnect_management_assessment = None
    if family == "screenconnect-rmm":
        screenconnect_management_assessment = {
            "dual_use_management_client": True,
            "remote_command_capability_statically_confirmed": (_screenconnect_remote_command_capability(logic)),
            "management_endpoint_observations": len(management_iocs),
            "separate_malware_c2_observations": len(confirmed_c2_iocs),
            "malicious_use_confirmed": False,
        }
    analysis = {
        "schema_version": 1,
        "case": {
            "sha256": digest,
            "family": family,
            "family_role": family_attribution["catalog_family_role"],
            "family_attribution_status": family_attribution["status"],
            "statically_confirmed_family": statically_confirmed_family,
            "provider_reported_family": family_attribution["provider_reported_family"],
            "version": "unknown",
            "format": pe.get("type") or metadata.get("file_type") or "unknown",
            "packing_suspected": bool((pe.get("entropy") or 0) >= 7.2),
            "unpack_status": "bounded_static_layers_recorded",
            "recovered_artifacts": max(
                0,
                int((documents["static-layers.json"].get("counts") or {}).get("recovered_layers") or 0),
            ),
            "static_config_recovered": config_recovered,
            "confirmed_static_network_observations": len(network_iocs),
            "confirmed_static_c2_observations": len(confirmed_c2_iocs),
            "confirmed_static_management_observations": len(management_iocs),
            "declarative_status": "function_review_required"
            if logic.get("status") == "function_analysis_required"
            else "ready",
            "sample_executed": False,
            "network_contacted": False,
        },
        "family_attribution": family_attribution,
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
            "overall_logic": "OVERALL-LOGIC.md",
            "c2_analysis": "c2-analysis.json",
            "iocs": "iocs.json",
        },
        "limitations": [
            "検体と復元層は実行していない。",
            "汎用文字列候補をC2として採用していない。",
            "関数本体未レビューのbinaryは完了扱いにしていない。",
        ],
    }
    if screenconnect_management_assessment is not None:
        analysis["screenconnect_management_assessment"] = screenconnect_management_assessment
    write_json(destination / "analysis.json", analysis)
    write_json(
        destination / "iocs.json",
        {
            "schema_version": 1,
            "sha256": [digest],
            "network": network_iocs,
            "assessment": (
                "ファミリー固有handlerの静的設定証拠から双用途管理先を収録した。悪性利用とC2帰属は確定していない"
                if management_iocs and not confirmed_c2_iocs
                else "ファミリー固有handlerの静的設定証拠から確認済み通信先を収録した。到達性は検証していない"
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
            len(confirmed_c2_iocs),
            confirmed_network_count=len(network_iocs),
            confirmed_management_count=len(management_iocs),
            family_attribution=family_attribution,
        ),
        encoding="utf-8",
    )
    profile = build_case_profile(destination)
    profile["family"] = family
    profile["family_attribution"] = family_attribution
    if screenconnect_management_assessment is not None:
        profile["screenconnect_management_assessment"] = screenconnect_management_assessment
    write_json(destination / "features.json", profile)
    (destination / "FEATURES.md").write_text(
        render_published_features_markdown(profile),
        encoding="utf-8",
    )
    reseal_canonical_report(destination, report, expected_digest=digest)
    summary = {
        "sha256": digest,
        "family": family,
        "family_role": family_attribution["catalog_family_role"],
        "family_attribution_status": family_attribution["status"],
        "provider_reported_label": family_attribution["provider_reported_label"],
        "provider_reported_family": family_attribution["provider_reported_family"],
        "statically_confirmed_family": statically_confirmed_family,
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
        "confirmed_static_network_observations": len(network_iocs),
        "confirmed_static_c2_observations": len(confirmed_c2_iocs),
        "confirmed_static_management_observations": len(management_iocs),
        "c2_analysis_outcome": str(c2_validation.get("outcome") or "unresolved"),
        "c2_analysis_complete": bool(c2_validation.get("complete")),
        "c2_analysis_finding_count": int(c2_validation.get("finding_count") or 0),
        "case_path": canonical_path,
        "publication_stage": publication_stage,
    }
    return family, canonical_destination, summary


def initialize_collection(
    results: Path,
    collection_id: str,
    manifest: dict[str, Any],
    *,
    publication_stage: str,
    _destination: Path | None = None,
) -> Path:
    root = _destination or results / "collections" / collection_id
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


def _reject_forbidden_publication_names(roots: list[Path]) -> None:
    """private snapshot全体でrepo非公開名を大小文字非依存に拒否する。"""

    for root in roots:
        for path in (root, *root.rglob("*")):
            if path.name.casefold() in FORBIDDEN_PUBLICATION_BASENAMES:
                raise ValueError(f"repositoryへ公開できないprivate artifact名です: {path.name}")


def _verify_snapshot_expectations(
    expectations: dict[Path, dict[str, Any]] | None,
) -> None:
    """publisher snapshotが固定時のexact content manifestから不変か確認する。"""

    if expectations is None:
        return
    for snapshot, expected in expectations.items():
        if analysis_job_runner.analysis_output_content_manifest(snapshot) != expected:
            raise ValueError("公開用private snapshotが公開処理中に変更されました")


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


def _publish_from_snapshots(
    repository: Path,
    manifest_path: Path,
    one_shots: list[Path],
    collection_id: str,
    *,
    allow_function_staging: bool = False,
    expected_contract_sha256: str | None = None,
    post_analysis_resource_scan_observations: int | None = None,
    post_analysis_resource_failures: int = 0,
    _expected_snapshot_manifests: dict[Path, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    if not COLLECTION_RE.fullmatch(collection_id):
        raise ValueError("collection IDは小文字英数とhyphenだけで指定してください")
    if expected_contract_sha256 is not None:
        expected_contract_sha256 = normalize_sha256_digest(expected_contract_sha256)
    _reject_forbidden_publication_names(one_shots)
    _verify_snapshot_expectations(_expected_snapshot_manifests)
    results = repository / "analysis-results"
    manifest = load_json(manifest_path)
    requested_count, items = _validate_acquisition_manifest_count(manifest)
    post_analysis_publication = None
    if post_analysis_resource_scan_observations is not None:
        post_analysis_publication = build_post_analysis_publication_record(
            sample_count=requested_count,
            resource_scan_observations=post_analysis_resource_scan_observations,
            relevant_resource_failures=post_analysis_resource_failures,
        )
    elif post_analysis_resource_failures != 0:
        raise ValueError("post_analysis_resource_failuresにはresource scan観測数も必要です")
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
    canonical_collection = results / "collections" / collection_id
    canonical_collection.parent.mkdir(parents=True, exist_ok=True)
    with _CasePublicationLock(canonical_collection):
        _recover_case_publication(canonical_collection)
    collection_token = f".casepub-{_publication_case_name_key(canonical_collection)}.{os.getpid():x}-{time.time_ns():x}"
    collection_staging_container = canonical_collection.parent / f"{collection_token}.staging"
    collection_staging_container_io = _publication_io_path(collection_staging_container)
    collection_staging_container_io.mkdir()
    collection = initialize_collection(
        results,
        collection_id,
        manifest,
        publication_stage=publication_stage,
        _destination=collection_staging_container_io / collection_id,
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
        family_attribution_counts = Counter(item["family_attribution_status"] for item in family_summaries)
        write_json(
            aggregate / "summary.json",
            {
                "schema_version": 1,
                "family": family,
                "family_role": "collection_grouping_label",
                "count": len(family_summaries),
                "family_attribution_status": dict(family_attribution_counts),
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
                    (
                        f"`{family}`はこのcollectionの整理先ラベルです。"
                        "各ケースの内部静的確認済みファミリーとは同義ではありません。"
                    ),
                    "",
                    f"- 収録件数: `{len(family_summaries)}`",
                    (f"- 内部静的確認済み: `{family_attribution_counts.get('statically_confirmed', 0)}`"),
                    (
                        "- 提供元報告のみ（内部静的未確認）: "
                        f"`{family_attribution_counts.get('provider_reported_not_statically_confirmed', 0)}`"
                    ),
                    (f"- 未解決: `{family_attribution_counts.get('unresolved', 0)}`"),
                    "- 分類根拠と制約は各ケースを参照してください。",
                    "",
                    "- 検体実行: なし",
                    "- 外部接続: なし",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        canonical_aggregate = canonical_collection / "sources" / family
        context = detect_publication_context(canonical_aggregate, family)
        if context is None:
            raise ValueError(f"collection公開contextを解決できません: {family}")
        register_publication_cases(context, case_paths)

    counts = Counter(item["family"] for item in summaries)
    status_counts = Counter(item["static_logic_status"] for item in summaries)
    attribution_status_counts = Counter(item["family_attribution_status"] for item in summaries)
    handler_successes = sum(item["handler_successes"] for item in summaries)
    handler_failures = sum(item["handler_failures"] for item in summaries)
    static_config_count = sum(bool(item["static_config_recovered"]) for item in summaries)
    confirmed_c2_count = sum(item["confirmed_static_c2_observations"] for item in summaries)
    confirmed_network_count = sum(item["confirmed_static_network_observations"] for item in summaries)
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
        f"- 確認済み静的通信先観測: `{confirmed_network_count}`",
        f"- 確認済み静的C2観測: `{confirmed_c2_count}`",
        (
            "- 提供元報告のみで内部静的ファミリー未確認: "
            f"`{attribution_status_counts.get('provider_reported_not_statically_confirmed', 0)}`"
        ),
        "",
        "## 整理先ラベル内訳",
        "",
        "| 整理先ラベル | 件数 | 内部静的確認済み | 提供元報告のみ・内部静的未確認 | 未解決 |",
        "|---|---:|---:|---:|---:|",
    ]
    for family, count in sorted(counts.items(), key=lambda value: (-value[1], value[0])):
        family_summaries = [item for item in summaries if item["family"] == family]
        family_attribution_counts = Counter(item["family_attribution_status"] for item in family_summaries)
        lines.append(
            f"| [{family}](sources/{family}/README.md) | {count} | "
            f"{family_attribution_counts.get('statically_confirmed', 0)} | "
            f"{family_attribution_counts.get('provider_reported_not_statically_confirmed', 0)} | "
            f"{family_attribution_counts.get('unresolved', 0)} |"
        )
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
            "個別のPE構造、import由来能力、適用可否、復元層、静的ロジック、IOC評価、帰属状態は各ケースに記録しています。全件一覧は[manifest.json](manifest.json)を参照してください。",
            "",
        ]
    )
    if post_analysis_publication is not None:
        lines.extend(
            [
                "## 解析後の公開・hardening変更",
                "",
                post_analysis_publication["note_ja"],
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
    publication_summary = {
        "schema_version": 1,
        "publication_stage": publication_stage,
        "analysis_complete": publication_stage == "complete",
        "analysis_contract_sha256": analysis_contract_sha256,
        "counts": dict(counts),
        "family_attribution_status": dict(attribution_status_counts),
        "static_logic_status": dict(status_counts),
        "handler_successes": handler_successes,
        "handler_failures": handler_failures,
        "static_config_recovered": static_config_count,
        "confirmed_static_c2_observations": confirmed_c2_count,
        "confirmed_static_network_observations": confirmed_network_count,
        "cases": summaries,
        "samples_executed": False,
        "network_contacted": False,
    }
    if post_analysis_publication is not None:
        publication_summary["post_analysis_publication"] = post_analysis_publication
    write_json(collection / "publication-summary.json", publication_summary)
    _verify_snapshot_expectations(_expected_snapshot_manifests)
    new_collection_sha256 = _case_tree_sha256(collection)
    with _CasePublicationLock(canonical_collection):
        _recover_case_publication(canonical_collection)
        existing_collection = canonical_collection.is_dir()
        if not existing_collection and os.path.lexists(canonical_collection):
            raise ValueError("canonical collection pathがdirectoryではありません")
        old_collection_sha256 = _case_tree_sha256(canonical_collection) if existing_collection else None
        collection_backup = canonical_collection.parent / f"{collection_token}.backup"
        collection_journal = {
            "schema_version": CASE_PUBLICATION_TRANSACTION_SCHEMA,
            "case_sha256": collection_id,
            "destination_path_sha256": _publication_case_path_sha256(canonical_collection),
            "existing_destination": existing_collection,
            "old_tree_sha256": old_collection_sha256,
            "new_tree_sha256": new_collection_sha256,
            "staging_name": collection_staging_container.name,
            "backup_name": collection_backup.name,
            "phase": "prepared",
        }
        collection_journal_path = _publication_journal_path(canonical_collection)
        collection_journal_sha256 = _atomic_publication_journal(
            collection_journal_path,
            collection_journal,
            require_absent=True,
        )
        _promote_case_publication(
            canonical_collection,
            collection,
            new_tree_sha256=new_collection_sha256,
            journal=collection_journal,
            journal_sha256=collection_journal_sha256,
        )
    return {
        "published": len(summaries),
        "publication_stage": publication_stage,
        "analysis_contract_sha256": analysis_contract_sha256,
        "families": dict(counts),
        "collection": str(canonical_collection),
    }


def _set_snapshot_tree_read_only(root: Path, *, read_only: bool) -> None:
    """publisher専用snapshotを読取専用化し、cleanup時だけ書込権限を戻す。"""

    entries = sorted(root.rglob("*"), key=lambda path: len(path.parts), reverse=not read_only)
    entries.append(root)
    for path in entries:
        information = path.lstat()
        if stat.S_ISDIR(information.st_mode):
            mode = stat.S_IRUSR | stat.S_IXUSR
            if not read_only:
                mode |= stat.S_IWUSR
        elif stat.S_ISREG(information.st_mode):
            mode = stat.S_IRUSR
            if not read_only:
                mode |= stat.S_IWUSR
        else:
            raise ValueError("公開用snapshotに通常file／directory以外があります")
        os.chmod(path, mode)


def _snapshot_publication_sources(
    one_shots: list[Path],
    temporary_root: Path,
) -> list[tuple[Path, dict[str, Any]]]:
    """全one-shot treeをexact manifestへ固定したpublisher専用copyへ変換する。"""

    if not one_shots:
        raise ValueError("one-shot sourceがありません")
    snapshots: list[tuple[Path, dict[str, Any]]] = []
    observed_sources: set[str] = set()
    for index, source in enumerate(one_shots):
        source_key = str(source.resolve(strict=True)).casefold()
        if source_key in observed_sources:
            raise ValueError("one-shot sourceが重複しています")
        observed_sources.add(source_key)
        before = analysis_job_runner.analysis_output_content_manifest(source)
        snapshot = temporary_root / f"{index:06d}"
        shutil.copytree(source, snapshot, symlinks=True)
        copied = analysis_job_runner.analysis_output_content_manifest(snapshot)
        after = analysis_job_runner.analysis_output_content_manifest(source)
        if before != after or copied != before:
            raise ValueError("one-shot sourceが公開用snapshot作成中に変更されました")
        snapshots.append((snapshot, copied))
    return snapshots


def publish(
    repository: Path,
    manifest_path: Path,
    one_shots: list[Path],
    collection_id: str,
    *,
    allow_function_staging: bool = False,
    expected_contract_sha256: str | None = None,
    post_analysis_resource_scan_observations: int | None = None,
    post_analysis_resource_failures: int = 0,
) -> dict[str, Any]:
    """検証と消費を同じ読取専用private snapshotへ固定して公開する。"""

    with tempfile.TemporaryDirectory(prefix="one-shot-publication-") as temporary:
        temporary_root = Path(temporary)
        snapshot_records = _snapshot_publication_sources(one_shots, temporary_root)
        snapshots = [snapshot for snapshot, _manifest in snapshot_records]
        try:
            for snapshot, expected_manifest in snapshot_records:
                _set_snapshot_tree_read_only(snapshot, read_only=True)
                if analysis_job_runner.analysis_output_content_manifest(snapshot) != expected_manifest:
                    raise ValueError("公開用private snapshotが読取専用固定前に変更されました")
            return _publish_from_snapshots(
                repository,
                manifest_path,
                snapshots,
                collection_id,
                allow_function_staging=allow_function_staging,
                expected_contract_sha256=expected_contract_sha256,
                post_analysis_resource_scan_observations=post_analysis_resource_scan_observations,
                post_analysis_resource_failures=post_analysis_resource_failures,
                _expected_snapshot_manifests={
                    snapshot: expected_manifest for snapshot, expected_manifest in snapshot_records
                },
            )
        finally:
            for snapshot in snapshots:
                if snapshot.exists():
                    _set_snapshot_tree_read_only(snapshot, read_only=False)


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
    parser.add_argument(
        "--post-analysis-resource-scan-observations",
        type=int,
        help="解析後のPE resource coverage hardeningを記録する場合の確認済み観測数",
    )
    parser.add_argument(
        "--post-analysis-resource-failures",
        type=int,
        default=0,
        help="上記観測のうちhardening該当失敗だった件数",
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
        post_analysis_resource_scan_observations=args.post_analysis_resource_scan_observations,
        post_analysis_resource_failures=args.post_analysis_resource_failures,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
