"""MalwareBazaarワンショットcollection公開処理の試験。"""

from __future__ import annotations

import copy
import hashlib
import os
import shutil
import sys
from pathlib import Path

import pytest

COMMON = Path(__file__).parents[1] / "common"
sys.path.insert(0, str(COMMON))

import analysis_contract  # noqa: E402
import publish_one_shot_collection as publisher  # noqa: E402
import static_logic  # noqa: E402


def report(selected_family: str | None = None) -> dict:
    """handler証拠を含む最小のワンショット分類結果を返す。"""

    value = {
        "classification": {"selected_family": selected_family},
        "handler_executions": [],
    }
    if selected_family:
        value["handler_executions"].append(
            {
                "handler_id": f"{selected_family}:handler.py:extract_config",
                "status": "succeeded",
                "selected_evidence": {"sufficient": True},
            }
        )
    return value


def confirmed_handler_artifact(
    handler_id: str,
    c2: list[dict] | None = None,
    *,
    config_recovered: bool = False,
) -> dict:
    """正規化済みhandler成果物を模した公開可能fixtureを返す。"""

    return {
        "handler": {"id": handler_id},
        "result": {
            "c2": c2 or [],
            "config": {"static_config_recovered": config_recovered},
        },
        "selected_evidence": {"sufficient": True, "tier": 4},
        "executed_sample": False,
        "network_contacted": False,
    }


def valid_source_case(tmp_path: Path, digest: str = "a" * 64) -> tuple[Path, dict]:
    """公開前整合性を満たす最小の通常解析caseを作る。"""

    source = tmp_path / digest
    source.mkdir()
    json_artifacts = {
        "static-layers.json": {"schema_version": 1, "layers": []},
        "classification.json": {
            "schema_version": 1,
            "selected_families": [],
            "root": {"one_shot_selection": {"family": None, "basis": None}},
        },
        "applicability.json": {
            "schema_version": 1,
            "selected_family": None,
            "selected_families": [],
            "selection_basis": None,
            "handlers": [],
            "executed_sample": False,
            "network_contacted": False,
        },
        "features.json": {"schema_version": 1},
        "campaign-labels.json": {"schema_version": 1, "labels": []},
        "static-logic.json": {"schema_version": 1, "status": "automated_script_structure"},
        "generic-triage.json": {"schema_version": 1, "type": "data"},
    }
    for name, value in json_artifacts.items():
        publisher.write_json(source / name, value)
    (source / "FEATURES.md").write_text("# 検体特徴\n", encoding="utf-8")
    (source / "STATIC-LOGIC.md").write_text("# 静的ロジック\n", encoding="utf-8")
    report_value = {
        "schema_version": 1,
        "sample": {"sha256": digest, "source_name": "sample.bin"},
        "classification": {
            "family": None,
            "selected_family": None,
            "selected_families": [],
            "selection_basis": None,
        },
        "static_layers": "static-layers.json",
        "generic_triage": "complete",
        "analysis_contract": {
            "schema_version": 1,
            "pipeline_contract_version": analysis_contract.PIPELINE_CONTRACT_VERSION,
            "sha256": "b" * 64,
            "component_count": 0,
            "settings": {"assessment_only": False},
        },
        "handler_executions": [],
        "assessment_only": False,
        "executed_sample": False,
        "network_contacted": False,
        "knowledge_artifacts": dict(analysis_contract.REQUIRED_KNOWLEDGE_ARTIFACTS),
        "case_state": {
            "status": "triaged_unknown",
            "complete": False,
            "resumable": False,
            "blockers": [],
            "detector_error_families": [],
            "static_layer_issues": [],
            "incomplete_selected_layer_attempts": [],
        },
    }
    report_value["artifact_sha256"] = analysis_contract.artifact_hashes(
        source, analysis_contract.BASE_REQUIRED_ARTIFACTS | {"generic-triage.json"}
    )
    analysis_contract.seal_report(report_value)
    publisher.write_json(source / "report.json", report_value)
    return source, report_value


def test_choose_family_uses_internal_result_before_provider() -> None:
    """内部高確度判定を提供元ラベルより優先する。"""
    family, basis = publisher.choose_family(
        {"signature": "WannaCry", "tags": ["WannaCry"]},
        report("efimer"),
        {"efimer", "wannacry", "unclassified"},
    )
    assert (family, basis) == ("efimer", "one_shot_static_detector")


def test_choose_family_rejects_legacy_result_without_positive_handler_evidence() -> None:
    """旧形式でも明示的なhandler成功証拠がなければ内部familyを採用しない。"""

    value = {"classification": {"selected_family": "formbook_loader"}}
    assert publisher.choose_family(
        {"signature": "NanoCore", "tags": ["NanoCore"]},
        value,
        {"formbook", "nanocore", "unclassified"},
    ) == ("nanocore", "malwarebazaar_reported_signature")


def test_choose_family_rejects_internal_result_without_handler_evidence() -> None:
    """実行済みhandlerが証拠なしなら、静的detectorのfamilyを公開ラベルへ昇格しない。"""

    value = report("formbook_loader")
    value["handler_executions"] = [
        {
            "handler_id": "formbook_loader:extract_config.py:extract_config",
            "status": "no_evidence",
            "selected_evidence": {"sufficient": False},
        }
    ]
    assert publisher.choose_family(
        {"signature": "NanoCore", "tags": ["NanoCore"]},
        value,
        {"formbook", "nanocore", "unclassified"},
    ) == ("nanocore", "malwarebazaar_reported_signature")


def test_choose_family_keeps_internal_result_with_handler_evidence() -> None:
    """handlerが十分な証拠を返した内部判定は、提供元ラベルより優先する。"""

    value = report("formbook_loader")
    value["handler_executions"] = [
        {
            "handler_id": "formbook_loader:extract_config.py:extract_config",
            "status": "succeeded",
            "selected_evidence": {"sufficient": True},
        }
    ]
    assert publisher.choose_family(
        {"signature": "NanoCore", "tags": ["NanoCore"]},
        value,
        {"formbook", "nanocore", "unclassified"},
    ) == ("formbook", "one_shot_static_detector")


def test_choose_family_rejects_modern_result_without_handler_execution() -> None:
    """現行reportでhandler実行がない内部判定は、提供元ラベルより優先しない。"""

    value = report("formbook_loader")
    value["handler_executions"] = []
    value["case_state"] = {"blockers": ["selected_family_has_no_automatic_handler:formbook_loader"]}
    assert publisher.choose_family(
        {"signature": "NanoCore", "tags": ["NanoCore"]},
        value,
        {"formbook", "nanocore", "unclassified"},
    ) == ("nanocore", "malwarebazaar_reported_signature")


@pytest.mark.parametrize(
    ("internal_family", "public_family"),
    [
        ("dotnet_resource_loader", "dotnet-resource-loader"),
        ("formbook_loader", "formbook"),
        ("maskgram_stealer", "maskgram-stealer"),
        ("linux_downloader", "linux-downloader"),
    ],
)
def test_choose_family_maps_internal_handler_id_to_public_family(
    internal_family: str,
    public_family: str,
) -> None:
    """内部handler証拠を照合した後、公開用の正規family IDを返す。"""

    assert publisher.choose_family(
        {"signature": "NanoCore", "tags": ["NanoCore"]},
        report(internal_family),
        {public_family, "nanocore", "unclassified"},
    ) == (public_family, "one_shot_static_detector")


def test_choose_family_mapped_internal_result_requires_positive_evidence() -> None:
    """正規IDへ変換できてもno_evidenceなら提供元ラベルへフォールバックする。"""

    value = report("dotnet_resource_loader")
    value["handler_executions"][0].update(
        {
            "status": "no_evidence",
            "selected_evidence": {"sufficient": False},
        }
    )
    assert publisher.choose_family(
        {"signature": "NanoCore", "tags": ["NanoCore"]},
        value,
        {"dotnet-resource-loader", "nanocore", "unclassified"},
    ) == ("nanocore", "malwarebazaar_reported_signature")


def test_choose_family_maps_unique_recovered_internal_family() -> None:
    """復旧レイヤーの一意な内部IDも正規の公開family IDへ変換する。"""

    value = report()
    value["classification"]["selected_families"] = ["linux_downloader"]
    value["handler_executions"] = [
        {
            "handler_id": "linux_downloader:handler.py:extract_config",
            "status": "succeeded",
            "selected_evidence": {"sufficient": True},
        }
    ]
    assert publisher.choose_family(
        {"signature": None, "tags": []},
        value,
        {"linux-downloader", "unclassified"},
    ) == ("linux-downloader", "one_shot_recovered_layer_detector")


def test_choose_family_ambiguous_mapped_results_use_provider_fallback() -> None:
    """復旧レイヤーの複数familyは暗黙選択せず提供元ラベルへ戻す。"""

    value = report()
    value["classification"]["selected_families"] = [
        "dotnet_resource_loader",
        "linux_downloader",
    ]
    value["handler_executions"] = [
        {
            "handler_id": f"{family}:handler.py:extract_config",
            "status": "succeeded",
            "selected_evidence": {"sufficient": True},
        }
        for family in value["classification"]["selected_families"]
    ]
    assert publisher.choose_family(
        {"signature": "NanoCore", "tags": ["NanoCore"]},
        value,
        {
            "dotnet-resource-loader",
            "linux-downloader",
            "nanocore",
            "unclassified",
        },
    ) == ("nanocore", "malwarebazaar_reported_signature")


def test_choose_family_is_conservative_for_provider_labels() -> None:
    """対応済み直接ラベルだけを採用し、dropped-byを本体分類へ流用しない。"""
    known = {"efimer", "vidar", "unclassified"}
    assert publisher.choose_family({"signature": "Efimer", "tags": []}, report(), known) == (
        "efimer",
        "malwarebazaar_reported_signature",
    )
    assert publisher.choose_family(
        {"signature": None, "tags": ["ClickFix", "Efimer", "exe"]},
        report(),
        known,
    ) == ("efimer", "malwarebazaar_direct_tag")
    assert publisher.choose_family(
        {"signature": None, "tags": ["dropped-by-Remus", "exe"]},
        report(),
        known,
    ) == ("unclassified", "no_supported_family_evidence")
    assert publisher.choose_family({"signature": "NewFamily", "tags": ["Efimer"]}, report(), known) == (
        "unclassified",
        "unsupported_reported_signature",
    )


@pytest.mark.parametrize(
    ("reported_label", "family"),
    [("Vidar", "vidar"), ("RemusStealer", "remusstealer")],
)
def test_provider_only_attribution_is_not_static_confirmation(
    reported_label: str,
    family: str,
) -> None:
    """提供元報告だけのVidar/RemusStealerを静的確認済みと扱わない。"""

    attribution = publisher.build_family_attribution(
        family,
        "malwarebazaar_reported_signature",
        {"signature": reported_label, "tags": ["exe"]},
    )

    assert attribution["status"] == "provider_reported_not_statically_confirmed"
    assert attribution["catalog_family_role"] == "provider_reported_grouping"
    assert attribution["provider_reported_label"] == reported_label
    assert attribution["provider_reported_family"] == family
    assert attribution["statically_confirmed_family"] is None
    assert attribution["supports_attribution"] is False


def test_choose_family_keeps_triaged_unknown_unclassified() -> None:
    """内部静的解析がunknownで閉じたcaseをprovider署名だけで再分類しない。"""
    source_report = report()
    source_report["case_state"] = {
        "status": "triaged_unknown",
        "complete": False,
        "resumable": False,
        "blockers": [],
    }
    assert publisher.choose_family(
        {"signature": "Vidar", "tags": []},
        source_report,
        {"vidar", "unclassified"},
    ) == ("unclassified", "internal_static_evidence_unresolved")


def test_capability_notes_require_exact_imports() -> None:
    """能力手掛かりは完全一致importだけから作り、実行を断定しない。"""
    notes = publisher.capability_notes({"imports": {"KERNEL32.dll": ["CreateProcessW", "WriteProcessMemory"]}})
    assert {item["capability"] for item in notes} == {
        "process_creation",
        "process_injection",
    }
    assert publisher.capability_notes({"imports": {"KERNEL32.dll": ["NotCreateProcessWMarker"]}}) == []


def test_render_iocs_contains_only_submitted_hash() -> None:
    """汎用候補domainをIOCへ昇格せず、提出SHA-256だけを描画する。"""
    digest = "a" * 64
    rendered = publisher.render_iocs(digest)
    assert digest in rendered
    assert "汎用文字列走査" in rendered
    assert "http://" not in rendered


def test_render_readme_separates_chain_iocs_and_detection_materials() -> None:
    """ケースREADMEはチェーン、IOC、Sigma／YARA材料を独立した節にする。"""

    digest = "a" * 64
    rendered = publisher.render_readme(
        digest,
        "unclassified",
        "no_supported_family_evidence",
        {
            "signature": None,
            "tags": ["exe"],
            "first_seen": "2026-07-30 00:00:00",
            "file_name": "sample.exe",
            "file_type": "exe",
            "file_size": 4096,
        },
        {
            "type": "pe",
            "size": 4096,
            "entropy": 7.1,
            "is_dotnet": False,
            "section_count": 5,
            "import_library_count": 1,
            "import_count": 1,
        },
        [
            {
                "capability": "process_creation",
                "basis": "プロセス起動APIのimportを確認",
                "imports": "createprocessw",
            }
        ],
        {"status": "function_analysis_required"},
        0,
        0,
    )

    for heading in (
        "## 実行・感染チェーン",
        "## ファイルIOC",
        "## C2／通信IOC",
        "## Sigma／YARA材料",
        "## 制約",
    ):
        assert heading in rendered
    assert digest in rendered
    assert "createprocessw" in rendered
    assert "単一importだけでは判定せず" in rendered


def test_render_readme_replaces_unreadable_provider_filename() -> None:
    """連続疑問符のprovider名は文字化け監査へ影響しない日本語説明へ置換する。"""

    rendered = publisher.render_readme(
        "a" * 64,
        "unclassified",
        "no_supported_family_evidence",
        {
            "file_name": "?????.exe",
            "file_type": "exe",
            "file_size": 4096,
        },
        {
            "type": "pe",
            "size": 4096,
            "entropy": 7.1,
            "is_dotnet": False,
            "section_count": 5,
            "import_library_count": 1,
            "import_count": 1,
        },
        [],
        {"status": "function_analysis_required"},
        0,
        0,
    )

    assert "providerで判読不能な名前（拡張子 .exe）" in rendered
    assert "???" not in rendered


def test_screenconnect_internal_family_maps_to_existing_public_family() -> None:
    assert publisher.public_family_id("screenconnect_rmm") == "screenconnect-rmm"


def test_legacy_screenconnect_orchestration_refresh_separates_management_endpoint() -> None:
    digest = "a" * 64
    handler_id = "screenconnect_rmm:fixture:extract_config"
    payload = {
        "schema_version": 1,
        "family": "ScreenConnect RMM",
        "classification": "commercial_rmm_dual_use",
        "malware_by_itself": False,
        "abuse_attribution": "not_established",
        "artifact_role": "access_agent_installer",
        "logic": ["埋め込み管理先を静的に回収"],
        "network_contacted": False,
        "sample_executed": False,
        "malicious_use_context": {
            "assessment": "requires_incident_context",
            "malicious_use_confirmed": False,
            "unauthorized_installation_observed": False,
            "embedded_management_endpoint_observed": True,
            "requires_authorization_and_delivery_context": True,
        },
        "relay": {
            "host": "192.0.2.12",
            "port": 8041,
            "transport": "tcp_tls",
            "role": "remote_management_relay",
            "c2_classification": "dual_use_not_c2_by_itself",
            "tenant_key_sha256": "b" * 64,
            "tenant_key_length": 407,
            "redacted_query": "?h=192.0.2.12&p=8041&k=<redacted>",
        },
    }
    quality = analysis_contract.handler_result_quality(payload)
    assert quality["sufficient"] is True
    execution = {
        "handler_id": handler_id,
        "status": "succeeded",
        "selected_evidence": quality,
        "selected_layer_sha256": digest,
    }
    artifact = {
        "handler": {"id": handler_id, "family": "screenconnect_rmm"},
        "result": payload,
        "selected_evidence": quality,
        "executed_sample": False,
        "network_contacted": False,
    }
    satisfied_gate = {
        "required": True,
        "satisfied": True,
        "observed": None,
        "status": "satisfied",
    }
    missing_gate = {
        "required": True,
        "satisfied": False,
        "observed": None,
        "status": "required_missing",
    }
    outcome = {
        "schema_version": 2,
        "sample_sha256": digest,
        "status": "partial",
        "family_resolution": {
            "status": "resolved",
            "family": "screenconnect_rmm",
        },
        "quality_gates": {
            "config": dict(missing_gate),
            "family_resolution": dict(satisfied_gate),
            "function_analysis": dict(missing_gate),
            "generic_triage": dict(missing_gate),
            "handler_evidence": dict(satisfied_gate),
            "network": {**missing_gate, "observed": False},
            "requirements_policy": dict(satisfied_gate),
            "static_layers": dict(satisfied_gate),
            "terminal_payload": {
                "required": False,
                "satisfied": False,
                "observed": None,
                "status": "not_applicable",
            },
        },
        "blockers": ["config", "function_analysis", "generic_triage", "network"],
        "next_actions_ja": [
            "family固有config extractorを追加または更新してください。",
            "特徴関数と全体ロジックの静的解析を追加してください。",
            "汎用静的triageの失敗または部分結果を再処理してください。",
            "復号configから通信先を抽出する処理を追加してください。",
        ],
    }
    report = {
        "candidate_handler_assessment": {"planned_attempt_count": 0},
        "case_state": {
            "status": "partial",
            "complete": False,
            "resumable": False,
            "blockers": [
                "generic_triage_partial",
                "orchestration:config",
                "orchestration:function_analysis",
                "orchestration:generic_triage",
                "orchestration:network",
                "representative_function_analysis_required",
            ],
        },
    }

    assert (
        publisher._refresh_legacy_screenconnect_orchestration(
            report,
            outcome,
            [(execution, artifact)],
        )
        is True
    )
    assert outcome["blockers"] == ["function_analysis", "generic_triage"]
    assert outcome["quality_gates"]["config"]["status"] == "satisfied"
    assert outcome["quality_gates"]["network"]["status"] == "satisfied"
    endpoints = outcome["outputs"]["qualified_network_endpoints"]
    assert len(endpoints) == 1
    assert endpoints[0]["role"] == "remote_management_relay"
    assert endpoints[0]["role"] != "c2"
    assert "orchestration:config" not in report["case_state"]["blockers"]
    assert "orchestration:network" not in report["case_state"]["blockers"]
    layer_report = {
        "counts": {"recovered_layers": 128, "limit_events": 0},
        "limit_events": [],
    }
    assert (
        publisher._build_screenconnect_management_contract(
            digest=digest,
            public_family="screenconnect-rmm",
            layer_report=layer_report,
            handler_results=[(execution, artifact)],
            report=report,
            orchestration=outcome,
        )
        is None
    )
    mismatched_pending = {**outcome, "sample_sha256": "b" * 64}
    with pytest.raises(ValueError, match="pending C2契約の対象identity"):
        publisher._build_screenconnect_management_contract(
            digest=digest,
            public_family="screenconnect-rmm",
            layer_report=layer_report,
            handler_results=[(execution, artifact)],
            report=report,
            orchestration=mismatched_pending,
        )
    mismatched_pending_status = copy.deepcopy(outcome)
    mismatched_pending_status.update({"status": "complete", "blockers": [], "next_actions_ja": []})
    with pytest.raises(ValueError, match="pending C2契約の対象identity"):
        publisher._build_screenconnect_management_contract(
            digest=digest,
            public_family="screenconnect-rmm",
            layer_report=layer_report,
            handler_results=[(execution, artifact)],
            report=report,
            orchestration=mismatched_pending_status,
        )

    for name in ("function_analysis", "generic_triage"):
        outcome["quality_gates"][name] = dict(satisfied_gate)
    outcome["status"] = "complete"
    outcome["blockers"] = []
    outcome["next_actions_ja"] = []
    report["case_state"].update(
        {
            "status": "complete",
            "complete": True,
            "resumable": True,
            "blockers": [],
        }
    )
    report["case_state"]["resumable"] = False
    with pytest.raises(ValueError, match="外側静的品質gate"):
        publisher._build_screenconnect_management_contract(
            digest=digest,
            public_family="screenconnect-rmm",
            layer_report=layer_report,
            handler_results=[(execution, artifact)],
            report=report,
            orchestration=outcome,
        )
    report["case_state"]["resumable"] = True
    outcome["quality_gates"]["terminal_payload"]["status"] = "satisfied"
    with pytest.raises(ValueError, match="外側静的品質gate"):
        publisher._build_screenconnect_management_contract(
            digest=digest,
            public_family="screenconnect-rmm",
            layer_report=layer_report,
            handler_results=[(execution, artifact)],
            report=report,
            orchestration=outcome,
        )
    outcome["quality_gates"]["terminal_payload"]["status"] = "not_applicable"
    layer_report["counts"]["limit_events"] = False
    with pytest.raises(ValueError, match="外側静的品質gate"):
        publisher._build_screenconnect_management_contract(
            digest=digest,
            public_family="screenconnect-rmm",
            layer_report=layer_report,
            handler_results=[(execution, artifact)],
            report=report,
            orchestration=outcome,
        )
    layer_report["counts"]["limit_events"] = 0
    rebuilt = publisher._build_screenconnect_management_contract(
        digest=digest,
        public_family="screenconnect-rmm",
        layer_report=layer_report,
        handler_results=[(execution, artifact)],
        report=report,
        orchestration=outcome,
    )
    assert rebuilt is not None
    patterns, contract = rebuilt
    assert len(patterns["communication"]["confirmed_static_management_endpoints"]) == 1
    assert contract["c2"]["outcome"] == "no_c2_capability_verified"
    assert contract["c2"]["protocol"]["status"] == "not_applicable"
    assert contract["deep_analysis"]["blockers"] == []

    mismatched_execution = {**execution, "selected_layer_sha256": "b" * 64}
    with pytest.raises(ValueError, match="対象root handler"):
        publisher._build_screenconnect_management_contract(
            digest=digest,
            public_family="screenconnect-rmm",
            layer_report=layer_report,
            handler_results=[(mismatched_execution, artifact)],
            report=report,
            orchestration=outcome,
        )

    mismatched_family_artifact = {
        **artifact,
        "handler": {"id": handler_id, "family": "vidar"},
    }
    with pytest.raises(ValueError, match="対象root handler"):
        publisher._build_screenconnect_management_contract(
            digest=digest,
            public_family="screenconnect-rmm",
            layer_report=layer_report,
            handler_results=[(execution, mismatched_family_artifact)],
            report=report,
            orchestration=outcome,
        )

    application = {
        "url": "https://192.0.2.12:8041/Bin/ScreenConnect.Client.application",
        "scheme": "https",
        "host": "192.0.2.12",
        "port": 8041,
        "path": "/Bin/ScreenConnect.Client.application",
        "transport": "tcp_tls",
        "role": "screenconnect_clickonce_bootstrap",
        "contacted": False,
        "c2_classification": "dual_use_management_endpoint_not_c2_by_itself",
    }
    two_endpoint_payload = {**payload, "application": application}
    two_endpoint_artifact = {**artifact, "result": two_endpoint_payload}
    rebuilt_legacy_two = publisher._build_screenconnect_management_contract(
        digest=digest,
        public_family="screenconnect-rmm",
        layer_report=layer_report,
        handler_results=[(execution, two_endpoint_artifact)],
        report=report,
        orchestration=outcome,
    )
    assert rebuilt_legacy_two is not None
    assert len(rebuilt_legacy_two[0]["communication"]["confirmed_static_management_endpoints"]) == 2

    modern_payload = copy.deepcopy(two_endpoint_payload)
    modern_payload["config"] = {
        "static_config_recovered": True,
        "config_endpoints": [
            {
                "host": "192.0.2.12",
                "port": 8041,
                "transport": "tcp_tls",
                "role": "remote_management_relay",
                "confidence": "confirmed_static_configuration",
                "evidence": {
                    "kind": "screenconnect_embedded_management_endpoint",
                    "c2_classification": "dual_use_not_c2_by_itself",
                    "malicious_use_confirmed": False,
                },
            },
            {
                "url": application["url"],
                "host": application["host"],
                "port": application["port"],
                "transport": application["transport"],
                "path": application["path"],
                "role": application["role"],
                "confidence": "confirmed_static_configuration",
                "evidence": {
                    "kind": "screenconnect_embedded_management_endpoint",
                    "c2_classification": ("dual_use_management_endpoint_not_c2_by_itself"),
                    "malicious_use_confirmed": False,
                },
            },
        ],
        "static_evidence": {
            "all_expected_fields_validated": True,
            "source": "screenconnect_embedded_management_configuration",
            "dual_use_endpoint": True,
        },
    }
    modern_artifact = {**artifact, "result": modern_payload}
    rebuilt_modern = publisher._build_screenconnect_management_contract(
        digest=digest,
        public_family="screenconnect-rmm",
        layer_report=layer_report,
        handler_results=[(execution, modern_artifact)],
        report=report,
        orchestration=outcome,
    )
    assert rebuilt_modern is not None
    assert len(rebuilt_modern[0]["communication"]["confirmed_static_management_endpoints"]) == 2


def test_legacy_vidar_refresh_removes_only_exact_structural_network_label() -> None:
    digest = "a" * 64
    handler_id = "vidar:fixture:extract"
    payload = {
        "version": "3.2",
        "findings": [
            {"kind": "network.url", "value": "https://example.test/bootstrap"},
            {"kind": "network.url", "value": "https://t.me/example"},
        ],
    }
    quality = analysis_contract.handler_result_quality(payload)
    assert quality["sufficient"] is True
    execution = {
        "handler_id": handler_id,
        "status": "succeeded",
        "selected_evidence": quality,
        "selected_layer_sha256": digest,
    }
    artifact = {
        "handler": {"id": handler_id, "family": "vidar"},
        "result": payload,
        "selected_evidence": quality,
        "executed_sample": False,
        "network_contacted": False,
    }
    record = {
        "source": "selected_family_analysis",
        "family": "vidar",
        "handler_id": handler_id,
        "status": "succeeded",
        "selected_evidence": quality,
        "selected_layer_sha256": digest,
        "result": artifact,
    }
    refreshed = publisher.orchestration_outcome.summarize_handler_outputs(
        [record],
        family_filter="vidar",
    )
    fake = {
        "host": "network.url",
        "port": None,
        "scheme": None,
        "path": None,
        "contacted": False,
        "provenance": [
            {
                "family": "vidar",
                "handler_id": handler_id,
                "source": "selected_family_analysis",
                "evidence_path": "findings.0.kind",
            }
        ],
    }
    legacy = copy.deepcopy(refreshed)
    legacy["network_endpoints"].append(fake)
    outcome = {
        "schema_version": 2,
        "family_resolution": {"status": "resolved", "family": "vidar"},
        "outputs": legacy,
        "candidate_outputs": copy.deepcopy(legacy),
    }
    report_document = {
        "candidate_handler_assessment": {"planned_attempt_count": 0},
    }

    assert (
        publisher._refresh_legacy_vidar_structural_network_labels(
            report_document,
            outcome,
            [(execution, artifact)],
        )
        is True
    )
    assert [item["host"] for item in outcome["outputs"]["network_endpoints"]] == [
        "example.test",
        "t.me",
    ]
    assert (
        publisher._refresh_legacy_vidar_structural_network_labels(
            report_document,
            outcome,
            [(execution, artifact)],
        )
        is False
    )


def test_confirmed_static_handler_iocs_are_sanitized_deduplicated_and_traceable() -> None:
    """確認済み設定だけを採用し、秘密値を除去してrole・evidenceを保持する。"""

    handler_id = "efimer:extract_config.py:extract_config"
    execution = {
        "handler_id": handler_id,
        "status": "succeeded",
        "selected_evidence": {"sufficient": True},
    }
    confirmed = {
        "url": "https://user:pass@example.test/route.php?token=secret#fragment",
        "role": "beacon_or_tasking",
        "confidence": "confirmed_static_configuration",
        "transport": "https",
        "evidence": {
            "kind": "deobfuscated_static_assignment",
            "source_file": "config.js",
            "token": "must-not-be-published",
        },
    }
    candidate = {
        **confirmed,
        "url": "https://candidate.example/path",
        "confidence": "candidate_static_literal",
    }
    artifact = confirmed_handler_artifact(
        handler_id,
        [confirmed, dict(confirmed), candidate],
    )

    records = publisher.confirmed_static_handler_iocs([(execution, artifact)])

    assert len(records) == 1
    assert records[0]["url"] == "https://example.test/route.php"
    assert records[0]["role"] == "beacon_or_tasking"
    assert records[0]["evidence"]["source_file"] == "config.js"
    assert records[0]["evidence"]["token"] == "[REDACTED]"
    assert records[0]["source"] == f"handler:{handler_id}"
    assert publisher.static_config_recovered([(execution, artifact)], records) is True

    rendered = publisher.render_iocs("a" * 64, records)
    assert "https://example.test/route.php" in rendered
    assert "beacon_or_tasking" in rendered
    assert "config.js" in rendered
    assert "user:pass" not in rendered
    assert "token=secret" not in rendered
    assert "candidate.example" not in rendered


def test_confirmed_static_handler_iocs_accept_validated_config_endpoints() -> None:
    """検証済みconfig_endpointsを確認済みIOC境界へ正規化する。"""

    handler_id = "maskgram_stealer:extract_config.py:extract_config"
    execution = {
        "handler_id": handler_id,
        "status": "succeeded",
        "selected_evidence": {"sufficient": True},
    }
    artifact = confirmed_handler_artifact(handler_id, [])
    artifact["result"] = {
        "config_endpoints": [
            {
                "host": "c2.example",
                "port": 443,
                "transport": "https",
                "role": "c2",
                "resolved_from": "telegram",
                "confidence": "confirmed_static_configuration",
            }
        ],
        "static_evidence": {"all_expected_fields_validated": True},
    }

    records = publisher.confirmed_static_handler_iocs([(execution, artifact)])

    assert len(records) == 1
    assert records[0]["host"] == "c2.example"
    assert records[0]["evidence"]["all_expected_fields_validated"] is True


def test_config_endpoints_fail_closed_without_full_static_validation() -> None:
    """全項目の静的検証がないconfig_endpointsは公開しない。"""

    handler_id = "maskgram_stealer:extract_config.py:extract_config"
    execution = {
        "handler_id": handler_id,
        "status": "succeeded",
        "selected_evidence": {"sufficient": True},
    }
    artifact = confirmed_handler_artifact(handler_id, [])
    artifact["result"] = {
        "config_endpoints": [
            {
                "host": "unvalidated.example",
                "port": 443,
                "confidence": "confirmed_static_configuration",
            }
        ],
        "static_evidence": {"all_expected_fields_validated": False},
    }

    assert publisher.confirmed_static_handler_iocs([(execution, artifact)]) == []


@pytest.mark.parametrize(
    ("execution_update", "artifact_update"),
    [
        ({"status": "no_evidence"}, {}),
        ({"selected_evidence": {"sufficient": False}}, {}),
        ({"handler_id": "other:handler"}, {}),
        ({}, {"selected_evidence": {"sufficient": False}}),
        ({}, {"network_contacted": True}),
        ({}, {"executed_sample": True}),
    ],
)
def test_confirmed_static_handler_iocs_fail_closed_for_untrusted_artifacts(
    execution_update: dict,
    artifact_update: dict,
) -> None:
    """不一致、証拠不足、実行・通信済みhandler成果物はIOCにもconfigにも使わない。"""

    handler_id = "family:handler.py:extract_config"
    execution = {
        "handler_id": handler_id,
        "status": "succeeded",
        "selected_evidence": {"sufficient": True},
        **execution_update,
    }
    artifact = {
        **confirmed_handler_artifact(
            handler_id,
            [
                {
                    "host": "c2.example",
                    "port": 443,
                    "role": "tasking",
                    "confidence": "confirmed_static_configuration",
                    "evidence": {"kind": "decoded_config"},
                }
            ],
            config_recovered=True,
        ),
        **artifact_update,
    }

    assert publisher.confirmed_static_handler_iocs([(execution, artifact)]) == []
    assert publisher.static_config_recovered([(execution, artifact)], []) is False


def test_static_config_flag_requires_trusted_handler_evidence() -> None:
    """C2がないconfig flagも十分なhandler証拠がある場合だけ採用する。"""

    handler_id = "family:handler.py:extract_config"
    execution = {
        "handler_id": handler_id,
        "status": "succeeded",
        "selected_evidence": {"sufficient": True},
    }
    artifact = confirmed_handler_artifact(handler_id, config_recovered=True)
    assert publisher.static_config_recovered([(execution, artifact)], []) is True


@pytest.mark.parametrize(
    "flag_name",
    ["static_config_recovered", "decoded_config_recovered"],
)
def test_root_static_config_flags_require_boolean_true(flag_name: str) -> None:
    """result直下の復元フラグは、信頼済みhandlerの真偽値trueだけを採用する。"""

    handler_id = "family:handler.py:extract_config"
    execution = {
        "handler_id": handler_id,
        "status": "succeeded",
        "selected_evidence": {"sufficient": True},
    }
    artifact = confirmed_handler_artifact(handler_id)
    artifact["result"][flag_name] = True
    assert publisher.static_config_recovered([(execution, artifact)], []) is True

    artifact["result"][flag_name] = 1
    assert publisher.static_config_recovered([(execution, artifact)], []) is False


def test_find_case_source_requires_exactly_one_completed_report(tmp_path: Path) -> None:
    """分割runの未完了directoryを無視し、重複完了caseを拒否する。"""
    digest = "b" * 64
    first = tmp_path / "first" / "cases" / digest
    second = tmp_path / "second" / "cases" / digest
    first.mkdir(parents=True)
    second.mkdir(parents=True)
    (first / "report.json").write_text("{}", encoding="utf-8")
    assert publisher.find_case_source([tmp_path / "first", tmp_path / "second"], digest) == first
    (second / "report.json").write_text("{}", encoding="utf-8")
    try:
        publisher.find_case_source([tmp_path / "first", tmp_path / "second"], digest)
    except ValueError as exc:
        assert "2件" in str(exc)
    else:
        raise AssertionError("重複完了caseを拒否しませんでした")


def test_find_case_source_prefers_explicit_family_followup(tmp_path: Path) -> None:
    """汎用runと明示family runが重なる場合は追加解析を優先する。"""
    digest = "c" * 64
    generic = tmp_path / "generic" / "cases" / digest
    forced = tmp_path / "forced" / "cases" / digest
    generic.mkdir(parents=True)
    forced.mkdir(parents=True)
    (generic / "report.json").write_text('{"classification":{"selection_basis":"detector"}}', encoding="utf-8")
    (forced / "report.json").write_text(
        '{"classification":{"selection_basis":"explicit_operator_selection"}}',
        encoding="utf-8",
    )
    assert publisher.find_case_source([tmp_path / "generic", tmp_path / "forced"], digest) == forced


def test_choose_family_does_not_mislabel_explicit_selection_as_detector() -> None:
    """明示family選択は提供元報告として記録する。"""
    value = report("wannacry")
    value["classification"]["selection_basis"] = "explicit_operator_selection"
    assert publisher.choose_family(
        {"signature": "WannaCry", "tags": []},
        value,
        {"wannacry", "unclassified"},
    ) == ("wannacry", "malwarebazaar_reported_signature")


def test_choose_family_uses_unique_recovered_layer_result() -> None:
    """rootが未判定でも復旧レイヤーの一意な内部判定を採用する。"""

    value = report()
    value["classification"]["selected_families"] = ["Efimer"]
    value["handler_executions"] = [
        {
            "handler_id": "efimer:handler.py:extract_config",
            "status": "succeeded",
            "selected_evidence": {"sufficient": True},
        }
    ]
    assert publisher.choose_family(
        {"signature": None, "tags": []},
        value,
        {"efimer", "unclassified"},
    ) == ("efimer", "one_shot_recovered_layer_detector")


def test_choose_family_rejects_explicit_recovered_layer_result() -> None:
    """一意でも明示指定由来の復旧レイヤー判定は内部検出として採用しない。"""

    value = report()
    value["classification"].update(
        {
            "selected_families": ["efimer"],
            "selection_basis": "explicit_operator_selection",
        }
    )
    assert publisher.choose_family(
        {"signature": None, "tags": []},
        value,
        {"efimer", "unclassified"},
    ) == ("unclassified", "no_supported_family_evidence")


def test_choose_family_rejects_ambiguous_recovered_layer_results() -> None:
    """復旧レイヤー間でfamilyが分かれた場合は暗黙選択しない。"""

    value = report()
    value["classification"]["selected_families"] = ["efimer", "vidar"]
    assert publisher.choose_family(
        {"signature": None, "tags": []},
        value,
        {"efimer", "vidar", "unclassified"},
    ) == ("unclassified", "no_supported_family_evidence")


def test_validate_case_state_requires_status_specific_boolean_shape() -> None:
    """legacy状態を拒否し、statusに対応するboolean状態だけを受理する。"""

    with pytest.raises(ValueError, match="公開可能な完了状態ではありません"):
        publisher.validate_case_state({}, "a" * 64)
    publisher.validate_case_state(
        {
            "assessment_only": False,
            "case_state": {
                "status": "triaged_unknown",
                "complete": False,
                "resumable": False,
                "blockers": [],
            },
        },
        "a" * 64,
    )


def test_analysis_contract_accepts_nonresumable_partial_with_followup_blocker() -> None:
    """追加解析queueを持つpartial caseを未完了かつ再開不可として検証する。"""

    value = {
        "assessment_only": False,
        "case_state": {
            "status": "partial",
            "complete": False,
            "resumable": False,
            "blockers": ["c2_protocol_confirmation_pending"],
            "detector_error_families": [],
            "static_layer_issues": [],
            "incomplete_selected_layer_attempts": [],
        },
        "classification": {
            "selected_family": "fixture",
            "selected_families": ["fixture"],
        },
        "handler_executions": [],
        "generic_triage": "complete",
    }

    assert analysis_contract._case_state_errors(value, require_resumable=False) == []
    assert analysis_contract._case_state_errors(value, require_resumable=True) == ["case_state_not_resumable"]


def test_validate_case_state_rejects_assessment_only_completion() -> None:
    """公開処理が必要成果物を持たないassessment-only完了caseを拒否する。"""

    with pytest.raises(ValueError, match="公開可能な完了状態ではありません"):
        publisher.validate_case_state(
            {
                "assessment_only": True,
                "case_state": {
                    "status": "assessment_only_complete",
                    "complete": True,
                    "resumable": True,
                    "blockers": [],
                },
            },
            "a" * 64,
        )


@pytest.mark.parametrize(
    "case_state",
    [
        {"status": "partial", "complete": False},
        {"status": "failed", "complete": False},
        {"status": "partial"},
        "partial",
    ],
)
def test_validate_case_state_rejects_incomplete_new_reports(
    case_state: object,
) -> None:
    """新形式の部分解析、失敗、壊れた状態表現は公開を拒否する。"""

    with pytest.raises(ValueError, match="公開可能な完了状態ではありません"):
        publisher.validate_case_state({"case_state": case_state}, "b" * 64)


def test_publish_case_rejects_incomplete_new_report(tmp_path: Path) -> None:
    """publish_caseは成果物生成前に部分解析の新reportを拒否する。"""

    digest = "d" * 64
    source = tmp_path / "source"
    source.mkdir()
    publisher.write_json(
        source / "report.json",
        {
            "sample": {"sha256": digest},
            "executed_sample": False,
            "network_contacted": False,
            "case_state": {"status": "partial", "complete": False},
        },
    )
    with pytest.raises(ValueError, match="case_state=partial"):
        publisher.publish_case(
            tmp_path,
            tmp_path / "results",
            "collection",
            source,
            {"sha256": digest},
            {"unclassified"},
        )


def test_choose_family_does_not_publish_forced_recovered_layer_as_detector() -> None:
    """forced runのchild判定を内部detector由来の自動帰属として公開しない。"""

    value = report()
    value["classification"].update(
        {
            "selected_families": ["efimer"],
            "selection_basis": "explicit_family_detector_unmatched",
        }
    )
    value["analysis_contract"] = {"settings": {"forced_family": "efimer"}}
    assert publisher.choose_family(
        {"signature": None, "tags": []},
        value,
        {"efimer", "unclassified"},
    ) == ("unclassified", "no_supported_family_evidence")


def test_source_case_rejects_report_semantic_tamper(tmp_path: Path) -> None:
    """成果物hashが無傷でもreportの分類改変をseal不一致として拒否する。"""

    digest = "a" * 64
    source, report_value = valid_source_case(tmp_path, digest)
    report_value["classification"]["family"] = "tampered-family"
    publisher.write_json(source / "report.json", report_value)
    with pytest.raises(ValueError, match="report_semantic_sha256_mismatch"):
        publisher.validate_source_case(source, report_value, digest)


def test_source_case_rejects_resealed_state_invariant_tamper(tmp_path: Path) -> None:
    """sealを再計算されてもstatus・blocker不変条件の破壊を拒否する。"""

    digest = "b" * 64
    source, report_value = valid_source_case(tmp_path, digest)
    report_value["case_state"]["blockers"] = ["forged_blocker"]
    analysis_contract.seal_report(report_value)
    publisher.write_json(source / "report.json", report_value)
    with pytest.raises(ValueError, match="公開可能な完了状態ではありません"):
        publisher.validate_source_case(source, report_value, digest)


def test_source_case_rejects_incomplete_artifact_manifest(tmp_path: Path) -> None:
    """必須成果物が存在していてもmanifestに含まれなければ公開しない。"""

    digest = "c" * 64
    source, report_value = valid_source_case(tmp_path, digest)
    del report_value["artifact_sha256"]["static-logic.json"]
    analysis_contract.seal_report(report_value)
    publisher.write_json(source / "report.json", report_value)
    with pytest.raises(ValueError, match="artifact_manifest_missing:static-logic.json"):
        publisher.validate_source_case(source, report_value, digest)


@pytest.mark.parametrize(
    "relative",
    ["../outside.json", "handlers\\outside.json", "C:/outside.json", "/outside.json"],
)
def test_source_case_rejects_unsafe_handler_result_path(tmp_path: Path, relative: str) -> None:
    """handler resultのtraversal・区切り曖昧性・絶対pathを拒否する。"""

    digest = "d" * 64
    source, report_value = valid_source_case(tmp_path, digest)
    report_value["handler_executions"] = [{"handler_id": "family:handler", "status": "succeeded", "result": relative}]
    analysis_contract.seal_report(report_value)
    publisher.write_json(source / "report.json", report_value)
    with pytest.raises(ValueError, match="unsafe_handler_result_path"):
        publisher.validate_source_case(source, report_value, digest)


def test_source_case_rejects_handler_result_missing_from_manifest(tmp_path: Path) -> None:
    """安全な相対pathでもmanifestにないhandler resultを拒否する。"""

    digest = "e" * 64
    source, report_value = valid_source_case(tmp_path, digest)
    handler = source / "handlers" / "result.json"
    publisher.write_json(handler, {"schema_version": 1})
    report_value["handler_executions"] = [
        {
            "handler_id": "family:handler",
            "status": "succeeded",
            "result": "handlers/result.json",
        }
    ]
    analysis_contract.seal_report(report_value)
    publisher.write_json(source / "report.json", report_value)
    with pytest.raises(ValueError, match="artifact_manifest_missing:handlers/result.json"):
        publisher.validate_source_case(source, report_value, digest)


def test_source_case_rejects_symlinked_artifact(tmp_path: Path) -> None:
    """case内成果物がcase外へのsymbolic linkなら公開を拒否する。"""

    digest = "f" * 64
    source, report_value = valid_source_case(tmp_path, digest)
    external = tmp_path / "external.json"
    external.write_text("{}", encoding="utf-8")
    target = source / "classification.json"
    target.unlink()
    try:
        os.symlink(external, target)
    except OSError as exc:
        pytest.skip(f"symbolic linkを作成できない環境です: {exc}")
    with pytest.raises(ValueError, match="case_path_contains_reparse_point"):
        publisher.validate_source_case(source, report_value, digest)


@pytest.mark.parametrize("digest", ["A" * 64, "a" * 63, "a" * 65, "../" + "a" * 64])
def test_publish_case_rejects_noncanonical_digest_boundary(tmp_path: Path, digest: str) -> None:
    """case identityに使うdigestは小文字16進64文字へ限定する。"""

    with pytest.raises(ValueError, match="不正なSHA-256形式"):
        publisher.publish_case(
            tmp_path,
            tmp_path / "results",
            "collection",
            tmp_path / "source",
            {"sha256": digest},
            {"unclassified"},
        )


def test_source_case_cross_checks_classification_artifact(tmp_path: Path) -> None:
    """artifactとmanifestを再hashされてもreport分類とのsemantic不一致を拒否する。"""

    digest = "1" * 64
    source, report_value = valid_source_case(tmp_path, digest)
    classification = publisher.load_json(source / "classification.json")
    classification["selected_families"] = ["forged-family"]
    publisher.write_json(source / "classification.json", classification)
    report_value["artifact_sha256"] = analysis_contract.artifact_hashes(source, report_value["artifact_sha256"])
    analysis_contract.seal_report(report_value)
    publisher.write_json(source / "report.json", report_value)
    with pytest.raises(ValueError, match="classification_artifact_mismatch:selected_families"):
        publisher.validate_source_case(source, report_value, digest)


def test_source_case_rejects_unknown_handler_status(tmp_path: Path) -> None:
    """未知のhandler statusを完了caseへ混入できない。"""

    digest = "2" * 64
    source, report_value = valid_source_case(tmp_path, digest)
    report_value["handler_executions"] = [{"handler_id": "family:handler", "status": "forged_success"}]
    analysis_contract.seal_report(report_value)
    publisher.write_json(source / "report.json", report_value)
    with pytest.raises(ValueError, match="handler_status_invalid:0"):
        publisher.validate_source_case(source, report_value, digest)


def test_source_case_requires_success_for_each_selected_family(tmp_path: Path) -> None:
    """completeへ昇格した各familyに十分なhandler成功があることを要求する。"""

    digest = "3" * 64
    source, report_value = valid_source_case(tmp_path, digest)
    report_value["classification"].update(
        {
            "selected_family": "family-a",
            "selected_families": ["family-a"],
            "selection_basis": "detector",
        }
    )
    report_value["case_state"]["status"] = "complete"
    report_value["case_state"]["complete"] = True
    report_value["case_state"]["resumable"] = True
    classification = publisher.load_json(source / "classification.json")
    classification["selected_families"] = ["family-a"]
    classification["root"]["one_shot_selection"] = {
        "family": "family-a",
        "basis": "detector",
    }
    publisher.write_json(source / "classification.json", classification)
    applicability = publisher.load_json(source / "applicability.json")
    applicability.update(
        {
            "selected_family": "family-a",
            "selected_families": ["family-a"],
            "selection_basis": "detector",
        }
    )
    publisher.write_json(source / "applicability.json", applicability)
    report_value["artifact_sha256"] = analysis_contract.artifact_hashes(source, report_value["artifact_sha256"])
    analysis_contract.seal_report(report_value)
    publisher.write_json(source / "report.json", report_value)
    with pytest.raises(ValueError, match="selected_family_without_successful_handler:family-a"):
        publisher.validate_source_case(source, report_value, digest)


def test_source_case_accepts_strictly_documented_handler_no_evidence(tmp_path: Path) -> None:
    """全経路を正常試行したno-evidenceは、帰属限界付きで完了を許可する。"""

    digest = "4" * 64
    layer_sha = "5" * 64
    family = "stealc"
    handler_id = f"{family}:handler.py:extract_config"
    source, report_value = valid_source_case(tmp_path, digest)
    result_path = "handlers/stealc.json"
    publisher.write_json(source / result_path, {"schema_version": 1, "evidence": "insufficient"})
    report_value["classification"].update(
        {
            "family": family,
            "selected_family": family,
            "selected_families": [family],
            "selection_basis": "provider_label",
        }
    )
    report_value["handler_executions"] = [
        {
            "handler_id": handler_id,
            "status": "no_evidence",
            "result": result_path,
            "selected_evidence": {"sufficient": False},
            "attempts": [
                {
                    "status": "succeeded",
                    "routing_role": "selected_family_layer",
                    "evidence_status": "insufficient",
                    "evidence": {"sufficient": False},
                    "layer": {"sha256": layer_sha},
                }
            ],
        }
    ]
    report_value["documented_handler_no_evidence"] = {
        "family": family,
        "basis": "all_routed_handler_attempts_completed_without_family_specific_evidence",
        "handler_ids": [handler_id],
        "attempted_layer_sha256": [layer_sha],
        "resolved_blockers": [
            "handler_no_evidence",
            "selected_family_has_no_valid_handler_evidence:stealc",
            "selected_family_layer_incomplete",
        ],
        "attribution_effect": "provider_label_retained_but_not_upgraded_to_static_confirmation",
    }
    report_value["case_state"]["status"] = "complete"
    report_value["case_state"]["complete"] = True
    report_value["case_state"]["resumable"] = True
    classification = publisher.load_json(source / "classification.json")
    classification["selected_families"] = [family]
    classification["malware_type"] = family
    classification["root"]["malware_type"] = family
    classification["root"]["one_shot_selection"] = {
        "family": family,
        "basis": "provider_label",
    }
    publisher.write_json(source / "classification.json", classification)
    applicability = publisher.load_json(source / "applicability.json")
    applicability.update(
        {
            "selected_family": family,
            "selected_families": [family],
            "selection_basis": "provider_label",
            "handlers": [
                {
                    "id": handler_id,
                    "family": family,
                    "status": "applicable",
                }
            ],
        }
    )
    publisher.write_json(source / "applicability.json", applicability)
    report_value["artifact_sha256"] = analysis_contract.artifact_hashes(
        source, {*report_value["artifact_sha256"], result_path}
    )
    analysis_contract.seal_report(report_value)
    publisher.write_json(source / "report.json", report_value)

    publisher.validate_source_case(source, report_value, digest)
    report_value["documented_handler_no_evidence"]["attempted_layer_sha256"] = ["6" * 64]
    analysis_contract.seal_report(report_value)
    publisher.write_json(source / "report.json", report_value)
    with pytest.raises(ValueError, match="documented_handler_no_evidence_layer_set_mismatch"):
        publisher.validate_source_case(source, report_value, digest)


def test_source_case_rejects_noncanonical_manifest_digest(tmp_path: Path) -> None:
    """artifact manifestのdigestも小文字16進64文字だけを受理する。"""

    digest = "4" * 64
    source, report_value = valid_source_case(tmp_path, digest)
    report_value["artifact_sha256"]["classification.json"] = "A" * 64
    analysis_contract.seal_report(report_value)
    publisher.write_json(source / "report.json", report_value)
    with pytest.raises(ValueError, match="invalid_sha256:classification.json"):
        publisher.validate_source_case(source, report_value, digest)


def test_source_case_rejects_reparse_intermediate_component(tmp_path: Path) -> None:
    """最終fileだけでなく途中directoryのjunction・symlinkもresolve前に拒否する。"""

    digest = "5" * 64
    source, report_value = valid_source_case(tmp_path, digest)
    external = tmp_path / "external-handlers"
    external.mkdir()
    publisher.write_json(external / "result.json", {"schema_version": 1})
    link = source / "handlers"
    try:
        os.symlink(external, link, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory symbolic linkを作成できない環境です: {exc}")
    report_value["handler_executions"] = [
        {
            "handler_id": "family:handler",
            "status": "succeeded",
            "result": "handlers/result.json",
            "selected_evidence": {"sufficient": True},
        }
    ]
    report_value["artifact_sha256"]["handlers/result.json"] = hashlib.sha256(
        (external / "result.json").read_bytes()
    ).hexdigest()
    analysis_contract.seal_report(report_value)
    publisher.write_json(source / "report.json", report_value)
    with pytest.raises(ValueError, match="case_path_contains_reparse_point"):
        publisher.validate_source_case(source, report_value, digest)


def test_publish_preflights_all_sources_before_any_repository_write(tmp_path: Path) -> None:
    """後続caseが不正でも先行caseやcollectionを部分公開しない。"""

    repository = tmp_path / "repository"
    one_shot = tmp_path / "one-shot"
    cases = one_shot / "cases"
    cases.mkdir(parents=True)
    digests = [f"{index:064x}" for index in range(100)]
    valid_source_case(cases, digests[0])
    invalid_source, invalid_report = valid_source_case(cases, digests[1])
    invalid_report["classification"]["family"] = "tampered-family"
    publisher.write_json(invalid_source / "report.json", invalid_report)
    manifest = tmp_path / "manifest.json"
    publisher.write_json(
        manifest,
        {
            "complete": True,
            "downloaded": 100,
            "items": [{"sha256": digest, "metadata": {}} for digest in digests],
        },
    )

    with pytest.raises(ValueError, match="report_semantic_sha256_mismatch"):
        publisher.publish(
            repository,
            manifest,
            [one_shot],
            "preflight-test",
        )
    assert not (repository / "analysis-results").exists()


def test_acquisition_manifest_count_accepts_requested_50() -> None:
    """要求件数50件の完了manifestを100件固定で拒否しない。"""

    items = [{"sha256": f"{index:064x}"} for index in range(50)]
    requested, validated = publisher._validate_acquisition_manifest_count(
        {
            "requested": 50,
            "complete": True,
            "downloaded": 50,
            "items": items,
        }
    )
    assert requested == 50
    assert validated == items


def test_post_analysis_publication_record_is_structured_and_explicit() -> None:
    """解析後hardening、非影響件数、contract snapshotを定型記録する。"""

    record = publisher.build_post_analysis_publication_record(
        sample_count=50,
        resource_scan_observations=93,
        relevant_resource_failures=0,
    )

    assert record == {
        "status": "renderer_and_resource_coverage_fail_closed_hardening",
        "sample_count": 50,
        "resource_scan_observations": 93,
        "relevant_resource_failures": 0,
        "analysis_result_changed": False,
        "analysis_contract_semantics": "execution_time_snapshot",
        "note_ja": (
            "公開用OVERALL-LOGIC.mdレンダラーとPE resource coverageの"
            "fail-closed hardeningを解析完了後に修正した。"
            "今回50件で確認したresource scan 93観測について、"
            "該当失敗は0件で、抽出結果は不変。"
            "analysis_contract SHA-256は解析実行時のsnapshotとして保持する。"
        ),
    }


@pytest.mark.parametrize(
    ("sample_count", "observations", "failures"),
    [
        (0, 1, 0),
        (1, 0, 0),
        (1, 1, 2),
        (True, 1, 0),
        (1, 1, -1),
    ],
)
def test_post_analysis_publication_record_rejects_invalid_counts(
    sample_count: int,
    observations: int,
    failures: int,
) -> None:
    """件数矛盾とboolをfail closedで拒否する。"""

    with pytest.raises(ValueError):
        publisher.build_post_analysis_publication_record(
            sample_count=sample_count,
            resource_scan_observations=observations,
            relevant_resource_failures=failures,
        )


def test_parser_accepts_post_analysis_resource_hardening_counts() -> None:
    """定型注記を再生成できるCLI引数を保持する。"""

    args = publisher.build_parser().parse_args(
        [
            "--manifest",
            "manifest.json",
            "--one-shot",
            "one-shot",
            "--collection-id",
            "daily-test",
            "--post-analysis-resource-scan-observations",
            "93",
            "--post-analysis-resource-failures",
            "0",
        ]
    )
    assert args.post_analysis_resource_scan_observations == 93
    assert args.post_analysis_resource_failures == 0


def test_acquisition_manifest_count_keeps_legacy_100_default() -> None:
    """requestedを持たない旧manifestは従来どおり100件として検証する。"""

    items = [{"sha256": f"{index:064x}"} for index in range(100)]
    requested, validated = publisher._validate_acquisition_manifest_count(
        {
            "complete": True,
            "downloaded": 100,
            "items": items,
        }
    )
    assert requested == 100
    assert validated == items


def test_acquisition_manifest_count_rejects_incomplete_requested_batch() -> None:
    """要求件数と取得件数が異なるmanifestを拒否する。"""

    with pytest.raises(ValueError, match="要求件数50件"):
        publisher._validate_acquisition_manifest_count(
            {
                "requested": 50,
                "complete": True,
                "downloaded": 49,
                "items": [{"sha256": f"{index:064x}"} for index in range(49)],
            }
        )


def test_publish_rejects_mixed_analysis_contracts_before_writing(tmp_path: Path) -> None:
    """分割runのanalysis contractが1件でも異なれば書込み前に拒否する。"""

    repository = tmp_path / "repository"
    one_shot = tmp_path / "one-shot"
    cases = one_shot / "cases"
    cases.mkdir(parents=True)
    digests = [f"{index:064x}" for index in range(100)]
    valid_source_case(cases, digests[0])
    second_source, second_report = valid_source_case(cases, digests[1])
    second_report["analysis_contract"]["sha256"] = "c" * 64
    analysis_contract.seal_report(second_report)
    publisher.write_json(second_source / "report.json", second_report)
    manifest = tmp_path / "manifest.json"
    publisher.write_json(
        manifest,
        {
            "complete": True,
            "downloaded": 100,
            "items": [{"sha256": digest, "metadata": {}} for digest in digests],
        },
    )

    with pytest.raises(ValueError, match="analysis_contract_mismatch"):
        publisher.publish(repository, manifest, [one_shot], "mixed-contract-test")
    assert not (repository / "analysis-results").exists()


def test_publish_rejects_unexpected_analysis_contract_sha256_before_writing(tmp_path: Path) -> None:
    """明示したanalysis contract SHA-256と異なるrunを最初のcaseで拒否する。"""

    repository = tmp_path / "repository"
    one_shot = tmp_path / "one-shot"
    cases = one_shot / "cases"
    cases.mkdir(parents=True)
    digests = [f"{index:064x}" for index in range(100)]
    valid_source_case(cases, digests[0])
    manifest = tmp_path / "manifest.json"
    publisher.write_json(
        manifest,
        {
            "complete": True,
            "downloaded": 100,
            "items": [{"sha256": digest, "metadata": {}} for digest in digests],
        },
    )

    with pytest.raises(ValueError, match="期待するanalysis contract SHA-256"):
        publisher.publish(
            repository,
            manifest,
            [one_shot],
            "expected-contract-test",
            expected_contract_sha256="d" * 64,
        )
    assert not (repository / "analysis-results").exists()


def test_collection_build_failure_preserves_existing_collection_byte_identical(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """2件目の生成失敗でも既存collectionを部分更新しない。"""

    repository = tmp_path / "repository"
    results = repository / "analysis-results"
    (results / "malware" / "unclassified").mkdir(parents=True)
    canonical = results / "collections" / "atomic-collection"
    canonical.mkdir(parents=True)
    (canonical / "sentinel.txt").write_text("old-complete\n", encoding="utf-8")
    before = publisher.analysis_job_runner.analysis_output_content_manifest(canonical)
    cases = tmp_path / "one-shot" / "cases"
    cases.mkdir(parents=True)
    digests = ["a" * 64, "b" * 64]
    for digest in digests:
        valid_source_case(cases, digest)
    manifest = tmp_path / "manifest.json"
    publisher.write_json(
        manifest,
        {
            "requested": 2,
            "downloaded": 2,
            "pending": 0,
            "complete": True,
            "items": [{"sha256": digest, "metadata": {}} for digest in digests],
        },
    )
    calls = 0

    def fail_second_case(*_args: object, **_kwargs: object) -> tuple:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("injected second-case failure")
        return "unclassified", cases / digests[0], {}

    monkeypatch.setattr(publisher, "publish_case", fail_second_case)

    with pytest.raises(OSError, match="second-case failure"):
        publisher._publish_from_snapshots(
            repository,
            manifest,
            [tmp_path / "one-shot"],
            "atomic-collection",
        )

    assert calls == 2
    assert publisher.analysis_job_runner.analysis_output_content_manifest(canonical) == before


def test_collection_rejects_datastore_upload_name_case_insensitively(
    tmp_path: Path,
) -> None:
    """private tree内のdatastore receipt候補を公開処理の最初に拒否する。"""

    one_shot = tmp_path / "one-shot"
    nested = one_shot / "cases" / ("a" * 64) / "private"
    nested.mkdir(parents=True)
    (nested / "Datastore-Upload.JSON").write_text("{}\n", encoding="utf-8")
    repository = tmp_path / "repository"

    with pytest.raises(ValueError, match="公開できないprivate artifact名"):
        publisher._publish_from_snapshots(
            repository,
            tmp_path / "missing-manifest.json",
            [one_shot],
            "forbidden-receipt",
        )

    assert not (repository / "analysis-results").exists()


def test_publish_rejects_source_change_during_private_snapshot_before_repository_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """copy直後に原本treeが変わればprivate publisherとrepository書込へ進まない。"""

    repository = tmp_path / "repository"
    repository.mkdir()
    one_shot = tmp_path / "one-shot"
    one_shot.mkdir()
    evidence = one_shot / "evidence.json"
    evidence.write_text('{"verified":true}\n', encoding="utf-8")
    manifest = tmp_path / "manifest.json"
    manifest.write_text("{}\n", encoding="utf-8")
    real_copytree = publisher.shutil.copytree
    private_publish_calls = 0

    def copytree_then_mutate_source(
        source: Path,
        destination: Path,
        **kwargs: object,
    ) -> Path:
        copied = real_copytree(source, destination, **kwargs)
        evidence.write_text('{"verified":false}\n', encoding="utf-8")
        return copied

    def publish_from_snapshots(*_args: object, **_kwargs: object) -> dict[str, object]:
        nonlocal private_publish_calls
        private_publish_calls += 1
        pytest.fail("private publisher must not run after the source tree changes")

    monkeypatch.setattr(publisher.shutil, "copytree", copytree_then_mutate_source)
    monkeypatch.setattr(publisher, "_publish_from_snapshots", publish_from_snapshots)

    with pytest.raises(ValueError, match="snapshot作成中に変更"):
        publisher.publish(repository, manifest, [one_shot], "source-race-test")

    assert private_publish_calls == 0
    assert not (repository / "analysis-results").exists()


def test_publish_uses_private_snapshot_and_removes_it_after_return(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """内部publisherは原本と分離したprivate copyだけを読み、return後にcopyを消す。"""

    repository = tmp_path / "repository"
    repository.mkdir()
    one_shot = tmp_path / "one-shot"
    one_shot.mkdir()
    evidence = one_shot / "evidence.json"
    evidence.write_text('{"verified":true}\n', encoding="utf-8")
    manifest = tmp_path / "manifest.json"
    manifest.write_text("{}\n", encoding="utf-8")
    observed: dict[str, object] = {}

    def publish_from_snapshots(
        current_repository: Path,
        current_manifest: Path,
        sources: list[Path],
        collection_id: str,
        **_kwargs: object,
    ) -> dict[str, object]:
        assert current_repository == repository
        assert current_manifest == manifest
        assert collection_id == "private-snapshot-test"
        assert len(sources) == 1
        snapshot = sources[0]
        observed["snapshot"] = snapshot
        observed["before"] = (snapshot / "evidence.json").read_text(encoding="utf-8")
        assert snapshot != one_shot
        evidence.write_text('{"verified":false}\n', encoding="utf-8")
        observed["after"] = (snapshot / "evidence.json").read_text(encoding="utf-8")
        return {"published": 1}

    monkeypatch.setattr(publisher, "_publish_from_snapshots", publish_from_snapshots)

    result = publisher.publish(repository, manifest, [one_shot], "private-snapshot-test")

    assert result == {"published": 1}
    assert observed["before"] == '{"verified":true}\n'
    assert observed["after"] == '{"verified":true}\n'
    snapshot = observed["snapshot"]
    assert isinstance(snapshot, Path)
    assert not snapshot.exists()


def test_partial_staging_preserves_all_original_blockers(
    tmp_path: Path,
) -> None:
    """整合済みpartialを受理し、追加解析前に原blockerを変更しない。"""

    digest = "6" * 64
    source, report_value = valid_source_case(tmp_path, digest)
    report_value["case_state"].update(
        {
            "status": "partial",
            "complete": False,
            "resumable": False,
            "blockers": [publisher.FUNCTION_ANALYSIS_BLOCKER],
        }
    )
    analysis_contract.seal_report(report_value)
    publisher.write_json(source / "report.json", report_value)

    with pytest.raises(ValueError, match="公開可能な完了状態ではありません"):
        publisher.validate_source_case(source, report_value, digest)
    assert (
        publisher.validate_source_case(
            source,
            report_value,
            digest,
            allow_function_staging=True,
        )
        == "analysis_followup_pending"
    )

    report_value["case_state"]["blockers"] = [publisher.ROOT_TO_TERMINAL_LINEAGE_BLOCKER]
    analysis_contract.seal_report(report_value)
    publisher.write_json(source / "report.json", report_value)
    assert (
        publisher.validate_source_case(
            source,
            report_value,
            digest,
            allow_function_staging=True,
        )
        == "analysis_followup_pending"
    )

    report_value["case_state"]["blockers"] = [
        "handler_failed",
        publisher.FUNCTION_ANALYSIS_BLOCKER,
    ]
    analysis_contract.seal_report(report_value)
    publisher.write_json(source / "report.json", report_value)
    assert (
        publisher.validate_source_case(
            source,
            report_value,
            digest,
            allow_function_staging=True,
        )
        == "analysis_followup_pending"
    )
    assert report_value["case_state"]["blockers"] == [
        "handler_failed",
        publisher.FUNCTION_ANALYSIS_BLOCKER,
    ]

    report_value["case_state"]["blockers"] = [
        "generic_triage_partial",
        "orchestration:config",
        "orchestration:function_analysis",
        "orchestration:generic_triage",
        "orchestration:network",
        "orchestration:static_layers",
        "orchestration:terminal_payload",
        publisher.FUNCTION_ANALYSIS_BLOCKER,
        "selected_family_layer_incomplete",
    ]
    analysis_contract.seal_report(report_value)
    publisher.write_json(source / "report.json", report_value)
    assert (
        publisher.validate_source_case(
            source,
            report_value,
            digest,
            allow_function_staging=True,
        )
        == "analysis_followup_pending"
    )

    report_value["case_state"].update({"status": "failed", "blockers": ["generic_triage_failed"]})
    analysis_contract.seal_report(report_value)
    publisher.write_json(source / "report.json", report_value)
    with pytest.raises(ValueError, match="公開可能な完了状態ではありません"):
        publisher.validate_source_case(
            source,
            report_value,
            digest,
            allow_function_staging=True,
        )


def test_partial_staging_rejects_missing_function_blocker_and_unknown_blocker(tmp_path: Path) -> None:
    """代表関数解析待ちがないpartialと未知blockerをstagingへ入れない。"""

    digest = "8" * 64
    source, report_value = valid_source_case(tmp_path, digest)
    report_value["case_state"].update(
        {
            "status": "partial",
            "complete": False,
            "resumable": False,
            "blockers": ["handler_failed"],
        }
    )
    with pytest.raises(ValueError, match="公開可能な完了状態ではありません"):
        publisher.validate_source_case(
            source,
            report_value,
            digest,
            allow_function_staging=True,
        )

    report_value["case_state"]["blockers"] = [
        publisher.FUNCTION_ANALYSIS_BLOCKER,
        "unknown_partial_reason",
    ]
    with pytest.raises(ValueError, match="公開可能な完了状態ではありません"):
        publisher.validate_source_case(
            source,
            report_value,
            digest,
            allow_function_staging=True,
        )


def test_reseal_canonical_report_refreshes_generated_artifact_hash(
    tmp_path: Path,
) -> None:
    """canonical生成で変更した成果物へhash manifestとsealを同期する。"""

    digest = "7" * 64
    source, report_value = valid_source_case(tmp_path, digest)
    publisher.write_json(
        source / "static-logic.json",
        {"schema_version": 1, "status": "automated_script_structure", "family": "updated"},
    )

    publisher.reseal_canonical_report(source, report_value)

    refreshed = publisher.load_json(source / "report.json")
    assert (
        analysis_contract.case_integrity_errors(
            source,
            refreshed,
            expected_digest=digest,
            require_resumable=False,
        )
        == []
    )


def test_publish_case_uses_unclassified_case_kind(tmp_path: Path) -> None:
    digest = "8" * 64
    source, report_value = valid_source_case(tmp_path, digest)
    publisher.write_json(
        source / "static-logic.json",
        static_logic.build_static_logic_report(
            sha256=digest,
            family="unclassified",
            source_name="sample.bin",
        ),
    )
    publisher.reseal_canonical_report(source, report_value)
    repository = tmp_path / "r"
    repository.mkdir()

    family, destination, _ = publisher.publish_case(
        repository,
        repository / "analysis-results",
        "unclassified-test",
        source,
        {"sha256": digest, "metadata": {}},
        {"unclassified"},
    )

    assert family == "unclassified"
    metadata = publisher.load_json(destination / "metadata.json")
    assert metadata["case_kind"] == "unclassified"
    overall = (destination / "OVERALL-LOGIC.md").read_text(encoding="utf-8")
    assert overall.count("```mermaid") == 3
    analysis = publisher.load_json(destination / "analysis.json")
    assert analysis["artifacts"]["overall_logic"] == "OVERALL-LOGIC.md"
    assert "[OVERALL-LOGIC.md](OVERALL-LOGIC.md)" in (destination / "README.md").read_text(encoding="utf-8")


def test_publish_case_helper_failure_preserves_existing_case_byte_identical(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """staging内の後段helper失敗では既存canonical caseを一切変更しない。"""

    digest = "7" * 64
    source, source_report = valid_source_case(tmp_path, digest)
    publisher.write_json(
        source / "static-logic.json",
        static_logic.build_static_logic_report(
            sha256=digest,
            family="unclassified",
            source_name="sample.bin",
        ),
    )
    publisher.reseal_canonical_report(source, source_report)
    repository = tmp_path / "r"
    repository.mkdir()
    _family, destination, _summary = publisher.publish_case(
        repository,
        repository / "analysis-results",
        "atomic-fixture",
        source,
        {"sha256": digest, "metadata": {}},
        {"unclassified"},
    )
    before = publisher.analysis_job_runner.analysis_output_content_manifest(destination)

    def fail_after_staging_writes(**_kwargs: object) -> None:
        raise OSError("injected helper failure")

    monkeypatch.setattr(
        publisher,
        "_build_screenconnect_management_contract",
        fail_after_staging_writes,
    )
    with pytest.raises(OSError, match="injected helper failure"):
        publisher.publish_case(
            repository,
            repository / "analysis-results",
            "atomic-fixture",
            source,
            {"sha256": digest, "metadata": {}},
            {"unclassified"},
        )

    assert publisher.analysis_job_runner.analysis_output_content_manifest(destination) == before
    assert not publisher._publication_journal_path(destination).exists()
    prefix = f".casepub-{publisher._publication_case_name_key(destination)}."
    assert not any(path.name.startswith(prefix) for path in destination.parent.iterdir())


def test_collection_publication_cleanup_removes_only_current_process_staging(
    tmp_path: Path,
) -> None:
    """未journal化のcollection stagingは現在process所有分だけ回収する。"""

    repository = tmp_path / "r"
    parent = repository / "analysis-results" / "collections"
    parent.mkdir(parents=True)
    collection_id = "cleanup-fixture"
    destination = parent / collection_id
    key = publisher._publication_case_name_key(destination)
    owned = parent / f".casepub-{key}.{os.getpid():x}-fixture.staging"
    foreign = parent / f".casepub-{key}.different-process.staging"
    for container in (owned, foreign):
        staged = publisher._publication_io_path(container) / collection_id
        staged.mkdir(parents=True)
        (staged / "manifest.json").write_text("{}", encoding="utf-8")

    publisher._cleanup_current_process_collection_staging(repository, collection_id)

    assert not owned.exists()
    assert foreign.is_dir()


def test_publish_case_recovers_build_kill_and_removes_partial_staging(
    tmp_path: Path,
) -> None:
    """staging生成中のprocess killを模擬し、次回publishでorphanを回収する。"""

    digest = "6" * 64
    source, source_report = valid_source_case(tmp_path, digest)
    publisher.write_json(
        source / "static-logic.json",
        static_logic.build_static_logic_report(
            sha256=digest,
            family="unclassified",
            source_name="sample.bin",
        ),
    )
    publisher.reseal_canonical_report(source, source_report)
    repository = tmp_path / "r"
    repository.mkdir()
    results = repository / "analysis-results"
    _family, destination, _summary = publisher.publish_case(
        repository,
        results,
        "kill-fixture",
        source,
        {"sha256": digest, "metadata": {}},
        {"unclassified"},
    )
    old_sha256 = publisher._case_tree_sha256(destination)
    key = publisher._publication_case_name_key(destination)
    container = destination.parent / f".casepub-{key}.killed.staging"
    backup = destination.parent / f".casepub-{key}.killed.backup"
    journal = {
        "schema_version": publisher.CASE_PUBLICATION_TRANSACTION_SCHEMA,
        "case_sha256": digest,
        "destination_path_sha256": publisher._publication_case_path_sha256(destination),
        "existing_destination": True,
        "old_tree_sha256": old_sha256,
        "new_tree_sha256": None,
        "staging_name": container.name,
        "backup_name": backup.name,
        "phase": "building",
    }
    publisher._atomic_publication_journal(
        publisher._publication_journal_path(destination),
        journal,
        require_absent=True,
    )
    partial = publisher._publication_io_path(container) / digest
    partial.mkdir(parents=True)
    (partial / "part.tmp").write_bytes(b"partial")

    publisher.publish_case(
        repository,
        results,
        "kill-fixture",
        source,
        {"sha256": digest, "metadata": {}},
        {"unclassified"},
    )

    assert destination.is_dir()
    assert not publisher._publication_journal_path(destination).exists()
    assert not os.path.lexists(container)


def test_case_publication_rejects_parallel_publisher(
    tmp_path: Path,
) -> None:
    """同じcanonical caseを同時に更新する2つ目のpublisherを拒否する。"""

    digest = "5" * 64
    source, source_report = valid_source_case(tmp_path, digest)
    publisher.write_json(
        source / "static-logic.json",
        static_logic.build_static_logic_report(
            sha256=digest,
            family="unclassified",
            source_name="sample.bin",
        ),
    )
    publisher.reseal_canonical_report(source, source_report)
    repository = tmp_path / "r"
    repository.mkdir()
    results = repository / "analysis-results"
    destination = publisher.resolve_catalog_case_path(
        results,
        digest,
        family="unclassified",
    )
    destination.parent.mkdir(parents=True)

    with publisher._CasePublicationLock(destination):
        with pytest.raises(ValueError, match="既に実行中"):
            publisher.publish_case(
                repository,
                results,
                "parallel-fixture",
                source,
                {"sha256": digest, "metadata": {}},
                {"unclassified"},
            )
    assert not destination.exists()


def test_case_publication_recovers_kill_between_directory_renames(
    tmp_path: Path,
) -> None:
    """backup退避後のkill状態は次回回復で旧caseへbyte-identicalに戻す。"""

    digest = "4" * 64
    source, source_report = valid_source_case(tmp_path, digest)
    publisher.write_json(
        source / "static-logic.json",
        static_logic.build_static_logic_report(
            sha256=digest,
            family="unclassified",
            source_name="sample.bin",
        ),
    )
    publisher.reseal_canonical_report(source, source_report)
    repository = tmp_path / "r"
    repository.mkdir()
    results = repository / "analysis-results"
    _family, destination, _summary = publisher.publish_case(
        repository,
        results,
        "rename-kill-fixture",
        source,
        {"sha256": digest, "metadata": {}},
        {"unclassified"},
    )
    old_manifest = publisher.analysis_job_runner.analysis_output_content_manifest(destination)
    old_sha256 = publisher._case_tree_sha256(destination)
    key = publisher._publication_case_name_key(destination)
    container = destination.parent / f".casepub-{key}.renamekill.staging"
    staged_case = publisher._publication_io_path(container) / digest
    backup = destination.parent / f".casepub-{key}.renamekill.backup"
    shutil.copytree(publisher._publication_io_path(destination), staged_case)
    (staged_case / "README.md").write_text("# 新しい未確定case\n", encoding="utf-8")
    new_sha256 = publisher._case_tree_sha256(staged_case)
    journal = {
        "schema_version": publisher.CASE_PUBLICATION_TRANSACTION_SCHEMA,
        "case_sha256": digest,
        "destination_path_sha256": publisher._publication_case_path_sha256(destination),
        "existing_destination": True,
        "old_tree_sha256": old_sha256,
        "new_tree_sha256": new_sha256,
        "staging_name": container.name,
        "backup_name": backup.name,
        "phase": "applying",
    }
    publisher._atomic_publication_journal(
        publisher._publication_journal_path(destination),
        journal,
        require_absent=True,
    )
    os.replace(
        publisher._publication_io_path(destination),
        publisher._publication_io_path(backup),
    )
    os.replace(staged_case, publisher._publication_io_path(destination))
    publisher._publication_io_path(container).rmdir()

    assert publisher._recover_case_publication(destination) == "rolled_back"
    assert publisher.analysis_job_runner.analysis_output_content_manifest(destination) == old_manifest
    assert not backup.exists()
    assert not publisher._publication_journal_path(destination).exists()


def test_publish_case_separates_provider_label_from_static_attribution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """provider-onlyのVidar整理先を内部静的確認済みfamilyとして表示しない。"""

    digest = "3" * 64
    source, source_report = valid_source_case(tmp_path, digest)
    publisher.write_json(
        source / "static-logic.json",
        static_logic.build_static_logic_report(
            sha256=digest,
            family="unclassified",
            source_name="sample.bin",
        ),
    )
    publisher.reseal_canonical_report(source, source_report)
    repository = tmp_path / "r"
    (repository / "analysis-results" / "malware" / "vidar").mkdir(
        parents=True,
    )
    monkeypatch.setattr(
        publisher,
        "choose_family",
        lambda *_args: ("vidar", "malwarebazaar_reported_signature"),
    )

    family, destination, summary = publisher.publish_case(
        repository,
        repository / "analysis-results",
        "provider-only-fixture",
        source,
        {
            "sha256": digest,
            "metadata": {
                "signature": "Vidar",
                "tags": ["exe"],
                "file_type": "exe",
            },
        },
        {"vidar", "unclassified"},
    )

    assert family == "vidar"
    assert summary["family"] == "vidar"
    assert summary["family_attribution_status"] == "provider_reported_not_statically_confirmed"
    assert summary["statically_confirmed_family"] is None
    attribution = publisher.load_json(destination / "classification.json")["publication_attribution"]
    assert attribution["catalog_family"] == "vidar"
    assert attribution["provider_reported_label"] == "Vidar"
    assert attribution["statically_confirmed_family"] is None
    assert attribution["supports_attribution"] is False
    analysis = publisher.load_json(destination / "analysis.json")
    assert analysis["case"]["family"] == "vidar"
    assert analysis["case"]["family_role"] == "provider_reported_grouping"
    assert analysis["case"]["statically_confirmed_family"] is None
    features = publisher.load_json(destination / "features.json")
    assert features["family_attribution"]["status"] == "provider_reported_not_statically_confirmed"
    assert publisher.load_json(destination / "static-logic.json")["family"] == "unclassified"
    for markdown_name in ("README.md", "FEATURES.md"):
        markdown = (destination / markdown_name).read_text(encoding="utf-8")
        assert "提供元報告" in markdown
        assert "内部静的確認済みファミリー: `なし`" in markdown
        assert "正規分類" not in markdown
    refreshed = publisher.load_json(destination / "report.json")
    assert (
        analysis_contract.case_integrity_errors(
            destination,
            refreshed,
            expected_digest=digest,
            require_resumable=False,
        )
        == []
    )


def test_collection_summary_counts_provider_only_separately(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """collection集計でも整理先labelと内部静的確認件数を分離する。"""

    digest = "2" * 64
    cases = tmp_path / "one-shot" / "cases"
    cases.mkdir(parents=True)
    source, source_report = valid_source_case(cases, digest)
    publisher.write_json(
        source / "static-logic.json",
        static_logic.build_static_logic_report(
            sha256=digest,
            family="unclassified",
            source_name="sample.bin",
        ),
    )
    publisher.reseal_canonical_report(source, source_report)
    repository = tmp_path / "r"
    (repository / "analysis-results" / "malware" / "vidar").mkdir(
        parents=True,
    )
    manifest = tmp_path / "manifest.json"
    publisher.write_json(
        manifest,
        {
            "requested": 1,
            "downloaded": 1,
            "pending": 0,
            "complete": True,
            "selected_at": "2026-09-02T00:00:00Z",
            "items": [
                {
                    "sha256": digest,
                    "metadata": {
                        "signature": "Vidar",
                        "tags": ["exe"],
                        "file_type": "exe",
                    },
                }
            ],
        },
    )
    monkeypatch.setattr(
        publisher,
        "choose_family",
        lambda *_args: ("vidar", "malwarebazaar_reported_signature"),
    )
    publisher._publish_from_snapshots(
        repository,
        manifest,
        [tmp_path / "one-shot"],
        "provider-only-collection",
    )

    collection = repository / "analysis-results" / "collections" / "provider-only-collection"
    readme = (collection / "README.md").read_text(encoding="utf-8")
    assert "| 整理先ラベル |" in readme
    assert "正規分類" not in readme
    assert "提供元報告のみで内部静的ファミリー未確認: `1`" in readme
    family_readme = (collection / "sources" / "vidar" / "README.md").read_text(encoding="utf-8")
    assert "整理先ラベル" in family_readme
    assert "提供元報告のみ（内部静的未確認）: `1`" in family_readme
    family_summary = publisher.load_json(collection / "sources" / "vidar" / "summary.json")
    assert family_summary["family_role"] == "collection_grouping_label"
    assert family_summary["family_attribution_status"] == {"provider_reported_not_statically_confirmed": 1}
    publication_summary = publisher.load_json(collection / "publication-summary.json")
    assert publication_summary["family_attribution_status"] == {"provider_reported_not_statically_confirmed": 1}
    catalog = publisher.load_json(repository / "analysis-results" / "catalog" / "cases.json")
    assert catalog["cases"][digest]["family"] == "vidar"
    case_path = repository.joinpath(*catalog["cases"][digest]["canonical_path"].split("/"))
    assert publisher.load_json(case_path / "metadata.json")["collections"] == ["provider-only-collection"]


def test_screenconnect_readme_separates_management_and_malware_c2() -> None:
    """人間向け説明で管理能力、管理先、別C2、悪性利用を分離する。"""

    rendered = publisher.render_readme(
        "1" * 64,
        "screenconnect-rmm",
        "one_shot_static_detector",
        {"signature": "ScreenConnect", "tags": ["exe"]},
        {"type": "pe", "size": 4096},
        [],
        {
            "status": "reviewed_function_logic",
            "functions": [
                {
                    "name": "ScreenConnect.WindowsExtensions.RunCommandLineCommands",
                    "api_calls": ["RunCommandLineProgram"],
                    "callees": [],
                }
            ],
        },
        1,
        0,
        confirmed_network_count=1,
        confirmed_management_count=1,
    )

    assert "双用途のScreenConnect管理client" in rendered
    assert "remote command能力も静的に確認" in rendered
    assert "管理endpoint" in rendered
    assert "別個のmalware C2は未確認" in rendered
    assert "悪性利用" in rendered


def test_screenconnect_features_separates_management_and_malware_c2() -> None:
    """FEATURESでも管理能力、管理先、別C2、悪性利用を分離する。"""

    rendered = publisher.render_published_features_markdown(
        {
            "sha256": "1" * 64,
            "family": "screenconnect-rmm",
            "campaign_type": "unknown",
            "sample_characteristics": [],
            "behaviors": [],
            "analysis_assessment": {
                "status": "partial",
                "score": 0,
                "maximum_score": 1,
                "unresolved": ["static_function_logic"],
                "next_actions": [],
            },
            "family_attribution": publisher.build_family_attribution(
                "screenconnect-rmm",
                "one_shot_static_detector",
                {"signature": "ScreenConnect", "tags": ["exe"]},
            ),
            "screenconnect_management_assessment": {
                "dual_use_management_client": True,
                "remote_command_capability_statically_confirmed": True,
                "management_endpoint_observations": 1,
                "separate_malware_c2_observations": 0,
                "malicious_use_confirmed": False,
            },
        }
    )

    assert "## 双用途管理能力の評価" in rendered
    assert "remote command能力: `静的関数証拠で確認済み`" in rendered
    assert "確認済み管理endpoint: `1`件" in rendered
    assert "別個のmalware C2: `未確認`" in rendered
    assert "管理endpointの悪性利用: `未確認`" in rendered


def test_publish_case_reuses_catalog_versioned_path_and_metadata_version(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """追加解析の再公開ではcatalogのversion付き正規pathと既存version根拠を維持する。"""

    digest = "d" * 64
    monkeypatch.setattr(publisher, "choose_family", lambda *_args: ("efimer", "fixture"))
    source, report_value = valid_source_case(tmp_path, digest)
    publisher.write_json(
        source / "static-logic.json",
        static_logic.build_static_logic_report(
            sha256=digest,
            family="efimer",
            source_name="sample.bin",
        ),
    )
    publisher.reseal_canonical_report(source, report_value)
    repository = tmp_path / "repository"
    results = repository / "analysis-results"
    destination = results / "malware" / "efimer" / "versions" / "v2" / "cases" / digest
    destination.mkdir(parents=True)
    version = {
        "status": "confirmed",
        "reported": "2.0",
        "normalized_key": "v2",
        "confidence": "high",
        "reason": "sample_specific_static_version",
        "evidence": ["fixture"],
    }
    publisher.write_json(
        destination / "metadata.json",
        {
            "schema_version": 1,
            "sha256": digest,
            "family": "efimer",
            "malware_version": version,
        },
    )
    publisher.write_json(
        results / "catalog" / "cases.json",
        {
            "schema_version": 1,
            "cases": {
                digest: {
                    "family": "efimer",
                    "canonical_path": destination.relative_to(repository).as_posix(),
                }
            },
        },
    )

    family, published, _ = publisher.publish_case(
        repository,
        results,
        "followup-test",
        source,
        {"sha256": digest, "metadata": {"signature": "Efimer"}},
        {"efimer", "unclassified"},
    )

    assert family == "efimer"
    assert published == destination
    assert publisher.load_json(destination / "metadata.json")["malware_version"] == version


def test_publish_case_reflects_confirmed_static_c2_and_keeps_report_integrity(
    tmp_path: Path,
) -> None:
    """確認済みC2とconfig集計を公開し、生成後のartifact hashとsealを維持する。"""

    digest = "9" * 64
    source, report_value = valid_source_case(tmp_path, digest)
    handler_id = "efimer:extract_config.py:extract_config"
    relative = "handlers/efimer-result.json"
    handler_artifact = confirmed_handler_artifact(
        handler_id,
        [
            {
                "url": "http://user:pass@c2.example/route.php?secret=1",
                "role": "beacon_or_tasking",
                "confidence": "confirmed_static_configuration",
                "transport": "http",
                "reachability": "not_tested",
                "evidence": {
                    "kind": "deobfuscated_static_assignment",
                    "source_file": "config.js",
                },
            },
            {
                "url": "https://candidate.example/path",
                "role": "candidate",
                "confidence": "candidate_static_literal",
                "evidence": {"kind": "string_scan"},
            },
        ],
    )
    report_value["classification"].update(
        {
            "selected_family": "efimer",
            "selected_families": ["efimer"],
            "selection_basis": "handler_evidence",
        }
    )
    report_value["case_state"]["status"] = "complete"
    report_value["case_state"]["complete"] = True
    report_value["case_state"]["resumable"] = True

    classification = publisher.load_json(source / "classification.json")
    classification["selected_family"] = "efimer"
    classification["selected_families"] = ["efimer"]
    classification["root"]["one_shot_selection"] = {
        "family": "efimer",
        "basis": "handler_evidence",
    }
    publisher.write_json(source / "classification.json", classification)

    applicability = publisher.load_json(source / "applicability.json")
    applicability.update(
        {
            "selected_family": "efimer",
            "selected_families": ["efimer"],
            "selection_basis": "handler_evidence",
            "handlers": [{"id": handler_id, "family": "efimer", "status": "applicable"}],
        }
    )
    publisher.write_json(source / "applicability.json", applicability)

    publisher.write_json(
        source / "static-logic.json",
        static_logic.build_static_logic_report(
            sha256=digest,
            family="efimer",
            source_name="sample.bin",
        ),
    )

    publisher.write_json(source / relative, handler_artifact)
    report_value["handler_executions"] = [
        {
            "handler_id": handler_id,
            "status": "succeeded",
            "result": relative,
            "selected_evidence": {"sufficient": True, "tier": 4},
        }
    ]
    tracked = set(report_value["artifact_sha256"]) | {relative}
    report_value["artifact_sha256"] = analysis_contract.artifact_hashes(source, tracked)
    analysis_contract.seal_report(report_value)
    publisher.write_json(source / "report.json", report_value)

    repository = tmp_path / "r"
    repository.mkdir()
    family, destination, summary = publisher.publish_case(
        repository,
        repository / "analysis-results",
        "confirmed-c2-test",
        source,
        {
            "sha256": digest,
            "metadata": {
                "signature": "Efimer",
                "tags": ["Efimer", "exe"],
                "file_type": "exe",
                "file_size": 1234,
                "first_seen": "2026-07-24 00:00:00",
            },
        },
        {"efimer", "unclassified"},
    )

    assert family == "efimer"
    iocs = publisher.load_json(destination / "iocs.json")
    assert len(iocs["network"]) == 1
    assert iocs["network"][0]["url"] == "http://c2.example/route.php"
    assert iocs["network"][0]["role"] == "beacon_or_tasking"
    assert iocs["network"][0]["evidence"]["source_file"] == "config.js"
    assert "candidate.example" not in (destination / "IOC-LIST.md").read_text(encoding="utf-8")

    analysis = publisher.load_json(destination / "analysis.json")
    assert analysis["case"]["static_config_recovered"] is True
    assert analysis["case"]["confirmed_static_c2_observations"] == 1
    assert summary["static_config_recovered"] is True
    assert summary["confirmed_static_c2_observations"] == 1
    assert summary["c2_analysis_complete"] is False
    c2_analysis = publisher.load_json(destination / "c2-analysis.json")
    assert c2_analysis["sha256"] == digest
    assert c2_analysis["c2"]["outcome"] == "unresolved"
    assert analysis["artifacts"]["c2_analysis"] == "c2-analysis.json"

    published_report = publisher.load_json(destination / "report.json")
    assert (
        analysis_contract.case_integrity_errors(
            destination,
            published_report,
            expected_digest=digest,
            require_resumable=True,
        )
        == []
    )


@pytest.mark.parametrize(
    ("reported_signature", "family"),
    [
        ("ValleyRAT", "valleyrat"),
        ("AsyncRAT", "asyncrat"),
        ("NanoCore", "nanocore"),
        ("PureRAT", "purehvnc"),
        ("PureLogsStealer", "purelogs"),
        ("Mirai", "mirai"),
        ("Amadey", "amadey"),
        ("Stealc", "stealc"),
    ],
)
def test_choose_family_maps_reviewed_existing_reported_signatures(
    reported_signature: str,
    family: str,
) -> None:
    """レビュー済みsignatureは既存family IDがある場合だけ対応付ける。"""

    assert publisher.choose_family(
        {"signature": reported_signature, "tags": []},
        report(),
        {family, "unclassified"},
    ) == (family, "malwarebazaar_reported_signature")
    assert publisher.choose_family(
        {"signature": reported_signature, "tags": []},
        report(),
        {"unclassified"},
    ) == ("unclassified", "unsupported_reported_signature")


def test_collection_display_metadata_is_not_hardcoded_to_date_or_exe() -> None:
    """README表示値をselected_atと実際のEXE／DLL metadataから導出する。"""

    display = publisher.collection_display_metadata(
        {"selected_at": "2026-07-24T09:30:00+09:00"},
        [
            {"metadata": {"first_seen": "2026-07-24 08:00:00", "file_type": "exe"}},
            {"metadata": {"first_seen": "2026-07-23 23:00:00", "file_type": "dll"}},
        ],
    )

    assert display == {
        "selected_date": "2026-07-24",
        "first_seen_newest": "2026-07-24 08:00:00",
        "first_seen_oldest": "2026-07-23 23:00:00",
        "type_summary": "DLL 1件、EXE 1件",
    }
