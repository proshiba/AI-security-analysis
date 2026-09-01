"""MalwareBazaarワンショットcollection公開処理の試験。"""

from __future__ import annotations

import hashlib
import os
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
        "orchestration:config",
        "orchestration:function_analysis",
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
