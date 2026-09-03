from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import sys

import pytest


COMMON = Path(__file__).resolve().parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

from analysis_contract import artifact_hashes, seal_report  # noqa: E402
import validate_collection_behavior_quality as validator  # noqa: E402


SHA = "a" * 64


@pytest.fixture
def tmp_path(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """WindowsのMAX_PATHを避ける短い専用fixture rootを返す。"""

    return tmp_path_factory.mktemp("vq")

def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _attribution(mode: str, family: str) -> dict[str, object]:
    if mode == "screenconnect":
        return {
            "status": "statically_confirmed",
            "catalog_family": family,
            "catalog_family_role": "statically_confirmed_family",
            "provider_reported_label": "ConnectWise",
            "provider_reported_family": None,
            "statically_confirmed_family": family,
            "supports_attribution": True,
            "note_ja": "内部静的確認済みです。",
        }
    if mode == "provider":
        return {
            "status": "provider_reported_not_statically_confirmed",
            "catalog_family": family,
            "catalog_family_role": "provider_reported_grouping",
            "provider_reported_label": "Vidar",
            "provider_reported_family": family,
            "statically_confirmed_family": None,
            "supports_attribution": False,
            "note_ja": "提供元報告であり内部静的確認済みファミリーではありません。",
        }
    return {
        "status": "unresolved",
        "catalog_family": family,
        "catalog_family_role": "unclassified",
        "provider_reported_label": None,
        "provider_reported_family": None,
        "statically_confirmed_family": None,
        "supports_attribution": False,
        "note_ja": "帰属未解決です。",
    }


def _static_logic(*, process_creation: bool = False) -> dict[str, object]:
    api_calls = ["CreateProcessW"] if process_creation else ["System.Attribute..ctor"]
    return {
        "schema_version": 1,
        "case_id": f"sha256:{SHA}",
        "sha256": SHA,
        "family": "screenconnect-rmm",
        "status": "characteristic_function_static_analysis_complete",
        "coverage": {
            "all_static_analysis_content_retained": True,
            "call_edge_count": 0,
            "call_graph_recorded": False,
            "discovered_function_inventory_count": 1,
            "characteristic_function_selected_count": 1,
            "decompilation_attempted_count": 1,
            "decompilation_succeeded_count": 1,
            "decompilation_limited_or_failed_count": 0,
            "decompilation_excluded_count": 0,
            "unselected_function_count": 0,
            "ghidra_function_inventory_count": 1,
            "managed_method_inventory_count": 0,
            "ghidra_programs_with_valid_mcp_responses": 1,
        },
        "call_edges": [],
        "functions": [
            {
                "function_id": f"{SHA}:cil:1",
                "name": "System.Runtime.CompilerServices.NullableAttribute..ctor",
                "role": "support",
                "api_calls": api_calls,
                "callees": api_calls,
                "constants": ["literal"],
                "evidence": {"confidence": "confirmed_static_cil_disassembly"},
                "function_analysis": {
                    "static_analysis_fields_retained": True,
                    "source_field_counts": {"constants": 1},
                },
            }
        ],
        "overall_logic": {"observed_call_edges": []},
    }


def _screenconnect_communication() -> dict[str, object]:
    endpoint = {
        "host": "198.51.100.20",
        "port": 8041,
        "transport": "tcp_tls",
        "role": "remote_management_relay",
        "source": "handler:screenconnect_rmm:test",
        "confidence": "confirmed_static_configuration",
        "evidence": {
            "kind": "screenconnect_embedded_management_endpoint",
            "c2_classification": "dual_use_not_c2_by_itself",
            "malicious_use_confirmed": False,
        },
    }
    return {
        "schema_version": 1,
        "sha256": SHA,
        "family": "screenconnect_rmm",
        "status": "confirmed_static_configuration_patterns",
        "communication": {
            "confirmed_static_management_endpoints": [endpoint],
            "confirmed_static_c2_endpoints": [],
            "confirmed_static_endpoints": [copy.deepcopy(endpoint)],
            "candidate_patterns": [],
            "protocol_evidence": [],
            "protocol_hints": ["tcp_tls"],
            "protocol_confirmed": False,
            "liveness_confirmed": False,
        },
        "config": {"static_config_recovered": True, "terminal_managed_client": True},
        "evidence_boundary": {
            "candidate_patterns_are_c2_confirmation": False,
            "dual_use_management_endpoint_is_c2_confirmation": False,
            "protocol_confirmation_requires_family_specific_evidence": True,
            "static_endpoint_is_liveness_confirmation": False,
            "static_protocol_is_liveness_confirmation": False,
        },
        "safety": {
            "credentials_published": False,
            "network_contacted": False,
            "raw_payload_published": False,
            "sample_executed": False,
        },
    }


def _screenconnect_c2() -> dict[str, object]:
    return {
        "schema_version": 1,
        "sha256": SHA,
        "family": "screenconnect_rmm",
        "analysis_attempted": True,
        "c2": {
            "endpoints": [],
            "evidence": ["双用途管理endpointをC2から分離した。"],
            "extraction_attempted": True,
            "outcome": "no_c2_capability_verified",
            "protocol": {
                "confidence": "none",
                "live_verified": False,
                "method": None,
                "static_hints": ["tcp_tls"],
                "status": "not_applicable",
                "tcp_open_only": False,
            },
        },
        "deep_analysis": {
            "attempted_methods": ["静的解析"],
            "blockers": [],
            "next_minimum_step": "配布経路とtelemetryを確認する。",
            "priority": "low",
            "queue": "not_required",
            "status": "complete",
        },
        "phase_evidence": [],
        "safety": {
            "credentials_published": False,
            "raw_payload_published": False,
            "sample_executed_locally": False,
        },
        "terminal_payload": {
            "blockers": [],
            "family": "screenconnect_rmm",
            "next_actions": [],
            "reached": True,
            "status": "recovered",
        },
    }


def _orchestration(mode: str) -> dict[str, object]:
    if mode != "screenconnect":
        return {
            "schema_version": 2,
            "sample_sha256": SHA,
            "status": "complete",
            "blockers": [],
            "next_actions_ja": [],
            "family_resolution": {"status": "unresolved", "family": None},
            "quality_gates": {},
        }
    gates = {
        name: {
            "required": True,
            "satisfied": True,
            "observed": True if name in {"network", "requirements_policy"} else None,
            "status": "satisfied",
        }
        for name in validator.SCREENCONNECT_REQUIRED_GATES
    }
    gates["terminal_payload"] = {
        "required": False,
        "satisfied": False,
        "observed": None,
        "status": "not_applicable",
    }
    return {
        "schema_version": 2,
        "sample_sha256": SHA,
        "status": "complete",
        "blockers": [],
        "next_actions_ja": [],
        "family_resolution": {
            "status": "resolved",
            "family": "screenconnect_rmm",
        },
        "quality_gates": gates,
    }


def _reseal(case_dir: Path) -> None:
    report_path = case_dir / "report.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["artifact_sha256"] = artifact_hashes(case_dir, report["artifact_sha256"])
    seal_report(report)
    _write_json(report_path, report)


def _fixture(
    tmp_path: Path,
    *,
    mode: str = "screenconnect",
    process_creation: bool = False,
) -> tuple[Path, Path, Path]:
    repository = tmp_path / "repository"
    collection = repository / "analysis-results" / "collections" / "test-collection"
    family = {
        "screenconnect": "screenconnect-rmm",
        "provider": "vidar",
        "unknown": "unclassified",
    }[mode]
    case_dir = (
        repository
        / "analysis-results"
        / "malware"
        / family
        / "versions"
        / "unknown"
        / "cases"
        / SHA
    )
    case_dir.mkdir(parents=True)
    collection.mkdir(parents=True)
    attribution = _attribution(mode, family)
    selected = ["screenconnect_rmm"] if mode == "screenconnect" else []
    selected_family = "screenconnect_rmm" if mode == "screenconnect" else None
    classification_family = "screenconnect_rmm" if mode == "screenconnect" else "unknown"
    selection_basis = "type_detector_structure" if mode == "screenconnect" else "no_unique_detection_above_threshold"

    classification = {
        "schema_version": 1,
        "selected_families": selected,
        "malware_type": classification_family,
        "malware_type_confidence": "medium" if selected else "low",
        "campaign_type": "unknown",
        "publication_attribution": attribution,
        "root": {
            "malware_type": classification_family,
            "malware_type_confidence": "medium" if selected else "low",
            "campaign_type": "unknown",
            "one_shot_selection": {
                "family": selected_family,
                "basis": selection_basis,
            },
        },
    }
    handler_id = "screenconnect_rmm:test"
    applicability = {
        "schema_version": 1,
        "selected_families": selected,
        "selected_family": selected_family,
        "selection_basis": selection_basis,
        "handlers": (
            [{"id": handler_id, "family": "screenconnect_rmm", "status": "applicable"}]
            if selected
            else []
        ),
        "executed_sample": False,
        "network_contacted": False,
    }
    logic = _static_logic(process_creation=process_creation)
    logic["family"] = "screenconnect-rmm" if selected else "unclassified"
    logic["publication_attribution"] = attribution
    communication = (
        _screenconnect_communication()
        if mode == "screenconnect"
        else {"schema_version": 1, "sha256": SHA, "communication": {}}
    )
    c2 = (
        _screenconnect_c2()
        if mode == "screenconnect"
        else {"schema_version": 1, "sha256": SHA, "c2": {"outcome": "unresolved"}}
    )
    orchestration = _orchestration(mode)
    feature_behaviors = (
        [
            {
                "id": "execution:process_creation",
                "category": "実行",
                "label": "プロセス起動API",
                "confidence": "documented",
                "evidence": "CreateProcessW import",
            }
        ]
        if process_creation
        else []
    )
    features = {
        "schema_version": 1,
        "sha256": SHA,
        "case_id": f"sha256:{SHA}",
        "family": family,
        "family_attribution": attribution,
        "behaviors": feature_behaviors,
        "analysis_assessment": {
            "status": "complete" if mode == "screenconnect" else "partial",
            "missing": [],
            "unresolved": [] if mode == "screenconnect" else ["family_attribution"],
        },
    }
    if mode == "screenconnect":
        features["screenconnect_management_assessment"] = {
            "dual_use_management_client": True,
            "remote_command_capability_statically_confirmed": False,
            "management_endpoint_observations": 1,
            "separate_malware_c2_observations": 0,
            "malicious_use_confirmed": False,
        }
    analysis = {
        "schema_version": 1,
        "case": {
            "sha256": SHA,
            "family": family,
            "family_role": attribution["catalog_family_role"],
            "family_attribution_status": attribution["status"],
            "statically_confirmed_family": attribution["statically_confirmed_family"],
            "provider_reported_family": attribution["provider_reported_family"],
            "declarative_status": logic["status"],
            "confirmed_static_management_observations": 1 if mode == "screenconnect" else 0,
            "confirmed_static_c2_observations": 0,
            "confirmed_static_network_observations": 1 if mode == "screenconnect" else 0,
        },
        "family_attribution": attribution,
        "capability_hints": (
            [
                {
                    "capability": "process_creation",
                    "basis": "プロセス起動APIのimportを確認",
                    "imports": "createprocessw",
                }
            ]
            if process_creation
            else []
        ),
    }
    canonical_path = case_dir.relative_to(repository).as_posix()
    metadata = {
        "schema_version": 1,
        "sha256": SHA,
        "case_id": f"sha256:{SHA}",
        "canonical_path": canonical_path,
        "family": family,
        "attribution": attribution,
    }
    routing = {
        "schema_version": 1,
        "selected_families": selected,
        "candidates": (
            [
                {
                    "family": family,
                    "evidence": [{"supports_attribution": mode == "screenconnect"}],
                }
            ]
            if mode in {"screenconnect", "provider"}
            else []
        ),
    }

    execution_text = (
        "実行経路は静的には未確認です。固定commandの復元は未完了です。"
        if process_creation
        else "実行経路に関する追加の断定はありません。"
    )
    if mode == "provider":
        attribution_text = (
            "- 整理先ラベル: `vidar`（提供元報告に基づく）\n"
            "- 提供元報告ラベル: `Vidar`\n"
            "- 内部静的確認済みファミリー: `なし`\n"
            "- ファミリー帰属状態: `provider_reported_not_statically_confirmed`"
        )
    elif mode == "screenconnect":
        attribution_text = (
            "- 整理先ラベル: `screenconnect-rmm`\n"
            "- 内部静的確認済みファミリー: `screenconnect-rmm`\n"
            "- ファミリー帰属状態: `statically_confirmed`"
        )
    else:
        attribution_text = (
            "- 整理先ラベル: `unclassified`\n"
            "- 内部静的確認済みファミリー: `なし`\n"
            "- ファミリー帰属状態: `unresolved`"
        )
    screen_text = (
        "双用途のScreenConnect管理clientです。remote command実行経路は静的確認未完了です。"
        "管理endpointの悪性利用は未確認で、別個のmalware C2も未確認です。"
        if mode == "screenconnect"
        else ""
    )
    readme = f"# ケース {SHA}\n\n{attribution_text}\n\n{execution_text}\n{screen_text}\n"
    features_markdown = (
        f"# 挙動・検体特徴：{SHA}\n\n{attribution_text}\n\n{execution_text}\n{screen_text}\n"
    )

    documents: dict[str, object] = {
        "classification.json": classification,
        "applicability.json": applicability,
        "generic-triage.json": {"schema_version": 1, "sha256": SHA},
        "static-layers.json": {"schema_version": 1, "sha256": SHA},
        "campaign-labels.json": {"schema_version": 1, "labels": []},
        "static-logic.json": logic,
        "features.json": features,
        "analysis.json": analysis,
        "metadata.json": metadata,
        "family-routing.json": routing,
        "communication-patterns.json": communication,
        "c2-analysis.json": c2,
        "orchestration.json": orchestration,
    }
    for name, document in documents.items():
        _write_json(case_dir / name, document)
    (case_dir / "STATIC-LOGIC.md").write_text("# 静的ロジック\n", encoding="utf-8")
    (case_dir / "README.md").write_text(readme, encoding="utf-8")
    (case_dir / "FEATURES.md").write_text(features_markdown, encoding="utf-8")
    if mode == "screenconnect":
        _write_json(
            case_dir / "handler-result.json",
            {"schema_version": 1, "handler": {"id": handler_id, "family": "screenconnect_rmm"}},
        )

    knowledge = {
        "features": "features.json",
        "features_markdown": "FEATURES.md",
        "campaign_labels": "campaign-labels.json",
        "static_logic": "static-logic.json",
        "static_logic_markdown": "STATIC-LOGIC.md",
        "c2_analysis": "c2-analysis.json",
        "communication_patterns": "communication-patterns.json",
        "orchestration": "orchestration.json",
    }
    report = {
        "schema_version": 1,
        "assessment_only": False,
        "executed_sample": False,
        "network_contacted": False,
        "sample": {"sha256": SHA},
        "analysis_contract": {
            "schema_version": 1,
            "pipeline_contract_version": 2,
            "sha256": hashlib.sha256(b"fixture-contract").hexdigest(),
            "settings": {"assessment_only": False},
        },
        "generic_triage": "complete",
        "static_layers": "static-layers.json",
        "orchestration": "orchestration.json",
        "knowledge_artifacts": knowledge,
        "classification": {
            "automation_status": "resolved" if selected else "unresolved",
            "family": classification_family,
            "confidence": "medium" if selected else "low",
            "campaign": "unknown",
            "selected_families": selected,
            "selected_family": selected_family,
            "selection_basis": selection_basis,
        },
        "case_state": {
            "status": "complete" if selected else "triaged_unknown",
            "complete": bool(selected),
            "resumable": bool(selected),
            "blockers": [],
            "detector_error_families": [],
            "static_layer_issues": [],
            "incomplete_selected_layer_attempts": [],
        },
        "handler_executions": (
            [
                {
                    "handler_id": handler_id,
                    "status": "succeeded",
                    "result": "handler-result.json",
                    "selected_evidence": {"sufficient": True},
                }
            ]
            if selected
            else []
        ),
    }
    artifact_paths = [
        "classification.json",
        "applicability.json",
        "generic-triage.json",
        "static-layers.json",
        "campaign-labels.json",
        "static-logic.json",
        "STATIC-LOGIC.md",
        "features.json",
        "FEATURES.md",
        "c2-analysis.json",
        "communication-patterns.json",
        "orchestration.json",
    ]
    if selected:
        artifact_paths.append("handler-result.json")
    report["artifact_sha256"] = artifact_hashes(case_dir, artifact_paths)
    seal_report(report)
    _write_json(case_dir / "report.json", report)

    attribution_basis = (
        "type_detector_structure"
        if mode == "screenconnect"
        else "malwarebazaar_reported_signature"
        if mode == "provider"
        else "none"
    )
    summary_case = {
        "sha256": SHA,
        "case_path": canonical_path,
        "family": family,
        "family_role": attribution["catalog_family_role"],
        "family_attribution_status": attribution["status"],
        "provider_reported_family": attribution["provider_reported_family"],
        "statically_confirmed_family": attribution["statically_confirmed_family"],
        "attribution_basis": attribution_basis,
    }
    _write_json(
        collection / "manifest.json",
        {"schema_version": 1, "cases": [{"case_id": f"sha256:{SHA}"}]},
    )
    _write_json(
        collection / "publication-summary.json",
        {"schema_version": 1, "cases": [summary_case]},
    )
    if mode == "provider":
        collection_readme = (
            "# test collection\n\n提供元報告による整理先であり、内部の静的確認済みファミリーではありません。\n\n"
            "| 整理先 | 件数 |\n|---|---:|\n| [vidar](sources/vidar/README.md) | 1 |\n"
        )
    else:
        collection_readme = "# test collection\n"
    (collection / "README.md").write_text(collection_readme, encoding="utf-8")
    return repository, collection, case_dir


def _codes(result: dict[str, object]) -> set[str]:
    codes = {item["code"] for item in result["findings"]}
    for case in result["results"]:
        codes.update(item["code"] for item in case["findings"])
    return codes


def test_screenconnect_positive_fixture_is_complete(tmp_path: Path) -> None:
    repository, collection, _case_dir = _fixture(tmp_path)

    result = validator.validate_collection(repository, collection)

    assert result["complete"] is True
    assert result["finding_count"] == 0


def test_provider_only_positive_fixture_keeps_attribution_boundary(tmp_path: Path) -> None:
    repository, collection, _case_dir = _fixture(tmp_path, mode="provider")

    result = validator.validate_collection(repository, collection)

    assert result["complete"] is True
    assert result["provider_only_cases"] == 1


def test_report_artifact_tamper_is_rejected(tmp_path: Path) -> None:
    repository, collection, case_dir = _fixture(tmp_path)
    features = json.loads((case_dir / "features.json").read_text(encoding="utf-8"))
    features["sha256"] = "b" * 64
    _write_json(case_dir / "features.json", features)

    result = validator.validate_collection(repository, collection)

    assert result["complete"] is False
    assert "report_integrity_error" in _codes(result)


def test_report_semantic_seal_tamper_is_rejected(tmp_path: Path) -> None:
    repository, collection, case_dir = _fixture(tmp_path)
    report_path = case_dir / "report.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["report_semantic_sha256"] = "b" * 64
    _write_json(report_path, report)

    result = validator.validate_collection(repository, collection)

    assert "report_integrity_error" in _codes(result)


def test_resealed_artifact_case_identity_tamper_is_rejected(tmp_path: Path) -> None:
    repository, collection, case_dir = _fixture(tmp_path)
    features_path = case_dir / "features.json"
    features = json.loads(features_path.read_text(encoding="utf-8"))
    features["sha256"] = "b" * 64
    _write_json(features_path, features)
    _reseal(case_dir)

    result = validator.validate_collection(repository, collection)

    assert "artifact_case_identity_mismatch" in _codes(result)


def test_manifest_fallback_sha_field_is_rejected(tmp_path: Path) -> None:
    repository, collection, _case_dir = _fixture(tmp_path)
    _write_json(
        collection / "manifest.json",
        {"schema_version": 1, "cases": [{"sha256": SHA}]},
    )

    result = validator.validate_collection(repository, collection)

    assert "collection_contract_invalid" in _codes(result)


def test_resealed_negative_symbol_role_tamper_is_rejected(tmp_path: Path) -> None:
    repository, collection, case_dir = _fixture(tmp_path)
    logic = json.loads((case_dir / "static-logic.json").read_text(encoding="utf-8"))
    logic["functions"][0]["role"] = "persistence"
    _write_json(case_dir / "static-logic.json", logic)
    _reseal(case_dir)

    result = validator.validate_collection(repository, collection)

    assert "negative_symbol_promoted_to_behavior" in _codes(result)


def test_resealed_call_and_constant_count_tamper_is_rejected(tmp_path: Path) -> None:
    repository, collection, case_dir = _fixture(tmp_path)
    logic = json.loads((case_dir / "static-logic.json").read_text(encoding="utf-8"))
    logic["coverage"]["call_edge_count"] = 1
    logic["functions"][0]["function_analysis"]["source_field_counts"]["constants"] = 2
    _write_json(case_dir / "static-logic.json", logic)
    _reseal(case_dir)

    result = validator.validate_collection(repository, collection)
    codes = _codes(result)

    assert "call_edge_count_mismatch" in codes
    assert "constant_coverage_count_mismatch" in codes


def test_resealed_management_endpoint_c2_promotion_is_rejected(tmp_path: Path) -> None:
    repository, collection, case_dir = _fixture(tmp_path)
    path = case_dir / "communication-patterns.json"
    communication = json.loads(path.read_text(encoding="utf-8"))
    endpoint = copy.deepcopy(
        communication["communication"]["confirmed_static_management_endpoints"][0]
    )
    endpoint["role"] = "malware_c2"
    communication["communication"]["confirmed_static_c2_endpoints"] = [endpoint]
    _write_json(path, communication)
    _reseal(case_dir)

    result = validator.validate_collection(repository, collection)

    assert "screenconnect_management_endpoint_promoted_to_c2" in _codes(result)


def test_provider_only_definite_family_tamper_is_rejected(tmp_path: Path) -> None:
    repository, collection, case_dir = _fixture(tmp_path, mode="provider")
    analysis_path = case_dir / "analysis.json"
    analysis = json.loads(analysis_path.read_text(encoding="utf-8"))
    analysis["case"]["family_role"] = "statically_confirmed_family"
    analysis["case"]["statically_confirmed_family"] = "vidar"
    _write_json(analysis_path, analysis)

    result = validator.validate_collection(repository, collection)

    assert "provider_analysis_definite_family" in _codes(result)


def test_process_creation_requires_fixed_command_status_in_both_docs(tmp_path: Path) -> None:
    repository, collection, case_dir = _fixture(
        tmp_path,
        mode="unknown",
        process_creation=True,
    )
    readme_path = case_dir / "README.md"
    readme = readme_path.read_text(encoding="utf-8").replace(
        "固定commandの復元は未完了です。",
        "追加の静的確認が必要です。",
    )
    readme_path.write_text(readme, encoding="utf-8")

    result = validator.validate_collection(repository, collection)

    assert "process_creation_fixed_command_status_missing" in _codes(result)


def test_manifest_case_path_misdirection_is_rejected(tmp_path: Path) -> None:
    repository, collection, _case_dir = _fixture(tmp_path)
    path = collection / "publication-summary.json"
    summary = json.loads(path.read_text(encoding="utf-8"))
    summary["cases"][0]["case_path"] = (
        "analysis-results/malware/screenconnect-rmm/versions/unknown/cases/" + "b" * 64
    )
    _write_json(path, summary)

    result = validator.validate_collection(repository, collection)

    assert "case_resolution_failed" in _codes(result)
