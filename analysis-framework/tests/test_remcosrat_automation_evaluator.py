from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import platform
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest
import pyzipper

ROOT = Path(__file__).resolve().parents[2]
EVALUATOR = ROOT / "analysis-framework" / "malware" / "remcosrat" / "evaluate_automation.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("remcosrat_automation_evaluator_tests", EVALUATOR)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


MODULE = _load_module()


def test_module_loading_does_not_add_family_directory_to_sys_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """評価器のimport後もfamily固有moduleを共通名で解決させない。"""

    family_directory = str(EVALUATOR.parent)
    monkeypatch.setattr(sys, "path", [item for item in sys.path if item != family_directory])

    _load_module()

    assert family_directory not in sys.path


def _aes_zip(
    member: bytes,
    *,
    name: str = "fixture.exe",
    password: bytes = b"infected",
    bits: int = 256,
) -> bytes:
    stream = io.BytesIO()
    with pyzipper.AESZipFile(
        stream,
        mode="w",
        compression=pyzipper.ZIP_DEFLATED,
        encryption=pyzipper.WZ_AES,
    ) as archive:
        archive.setpassword(password)
        archive.setencryption(pyzipper.WZ_AES, nbits=bits)
        archive.writestr(name, member)
    return stream.getvalue()


def _write_fixture(
    tmp_path: Path,
    members: list[tuple[str, bytes]],
) -> tuple[Path, Path, str]:
    archives_root = tmp_path / "archives"
    selected: list[str] = []
    items: list[dict] = []
    for digest, member in members:
        archive_bytes = _aes_zip(member)
        case_dir = archives_root / digest
        case_dir.mkdir(parents=True)
        (case_dir / f"{digest}.zip").write_bytes(archive_bytes)
        selected.append(digest)
        items.append(
            {
                "sha256": digest,
                "zip_path": "provider-path-is-not-trusted",
                "zip_sha256": hashlib.sha256(archive_bytes).hexdigest(),
                "zip_size": len(archive_bytes),
                "metadata": {
                    "sha256_hash": digest,
                    "signature": "RemcosRAT",
                    "file_name": "provider-name-is-selection-only.exe",
                },
            }
        )
    manifest = {
        "schema_version": 1,
        "selection_mode": "signature_newest",
        "signature": "RemcosRAT",
        "selected_hashes": selected,
        "items": items,
        "archives_remain_encrypted": True,
        "samples_executed": False,
    }
    manifest_path = tmp_path / "manifest.json"
    raw = (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    manifest_path.write_bytes(raw)
    return manifest_path, archives_root, hashlib.sha256(raw).hexdigest()


def _root_layer(unit) -> object:
    return MODULE.StaticLayer(
        name=unit.source_name,
        data=unit.data,
        sha256=hashlib.sha256(unit.data).hexdigest(),
        parent_sha256=None,
        depth=0,
        transform="submission",
    )


def _pipeline() -> dict:
    return {"counts": {"limit_events": 0}, "steps": [], "limit_events": []}


def _detector(data: bytes, _path: Path | None) -> dict:
    return {
        "matched": True,
        "confidence": "high",
        "observations": {
            "inner_sha256": hashlib.sha256(data).hexdigest(),
            "valid_rcdata_settings": True,
        },
    }


def _extractor(data: bytes, *, endpoint: str = "private-c2.example:2404") -> dict:
    digest = hashlib.sha256(data).hexdigest()
    configuration_sha256 = hashlib.sha256(b"config:" + data).hexdigest()
    host, raw_port = endpoint.rsplit(":", 1)
    port = int(raw_port)
    return {
        "family": "remcosrat",
        "sample_sha256": digest,
        "classification_confidence": "confirmed_static_configuration",
        "family_attribution_confirmed": True,
        "static_config_recovered": True,
        "decoded_config_recovered": True,
        "operational_c2_recovered": True,
        "executed": False,
        "network_contacted": False,
        "safety": {
            "sample_executed": False,
            "network_contacted": False,
        },
        "config": {
            "static_config_recovered": True,
            "decoded_config_recovered": True,
            "family_attribution_confirmed": True,
            "validated_field_indices": [0, 1, 2, 14, 41],
            "complete_c2_record_set_validated": True,
            "family_specific_mutex_prefix_validated": True,
            "c2_record_count": 1,
            "endpoints": [endpoint],
            "decoded_settings_sha256": configuration_sha256,
            "settings_resource_sha256": hashlib.sha256(b"resource:" + data).hexdigest(),
            "rc4_key_sha256": hashlib.sha256(b"secret-key:" + data).hexdigest(),
        },
        "c2": [
            {
                "endpoint": endpoint,
                "host": host,
                "host_kind": "dns",
                "port": port,
                "tls_enabled": True,
                "third_field_kind": "tls_flag",
                "role": "interactive_c2",
                "confidence": "confirmed_static_configuration",
                "monitor_eligible": True,
                "contacted": False,
                "liveness_confirmed": False,
                "evidence": {
                    "kind": "rc4_decrypted_rcdata_settings",
                    "resource_type": "RT_RCDATA",
                    "resource_name": "SETTINGS",
                    "config_field_index": 0,
                    "all_expected_fields_validated": True,
                    "validated_field_indices": [0, 1, 2, 14, 41],
                    "complete_c2_record_set_validated": True,
                    "family_specific_mutex_prefix_validated": True,
                },
            }
        ],
    }


def _policy() -> object:
    return MODULE.StaticLayerPolicy(
        max_layers=4, max_depth=2, max_layer_size=1024 * 1024, max_total_size=2 * 1024 * 1024
    )


def _trusted_tool_configuration(
    tmp_path: Path,
) -> tuple[object, Path, Path]:
    """実行しない人工7-Zipとoperator manifestを作成する。"""

    operator_root = tmp_path / "operator-tools"
    operator_root.mkdir()
    sevenzip = operator_root / ("sevenzip.exe" if os.name == "nt" else "sevenzip")
    sevenzip.write_bytes(b"MZ synthetic tool bytes; this file must never be executed")
    tool_bytes = sevenzip.read_bytes()
    manifest = operator_root / "trusted-static-tools.json"
    manifest.write_bytes(
        json.dumps(
            {
                "schema_version": 1,
                "profile_id": "remcos-evaluator-test-tools",
                "platform": {
                    "sys_platform": sys.platform.casefold(),
                    "machine": platform.machine().casefold(),
                },
                "tools": {
                    "upx": None,
                    "sevenzip": {
                        "path": str(sevenzip.resolve()),
                        "size": len(tool_bytes),
                        "sha256": hashlib.sha256(tool_bytes).hexdigest(),
                    },
                    "innounp": None,
                },
            },
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
    )
    configuration = MODULE.TrustedToolConfiguration(
        manifest_path=manifest.resolve(),
        manifest_sha256=hashlib.sha256(manifest.read_bytes()).hexdigest(),
    )
    return configuration, manifest, sevenzip


def _isolate_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(MODULE, "_source_identity", lambda: {"fixture.py": "0" * 64})
    monkeypatch.setattr(MODULE, "detect_format", lambda _data, _name: "pe")
    monkeypatch.setattr(
        MODULE,
        "recover_static_layers",
        lambda unit, **_kwargs: ([_root_layer(unit)], _pipeline()),
    )


def test_encrypted_zip_success_counts_one_parent_and_redacts_raw_values(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sample = b"MZ-remcos-evaluator-success"
    digest = hashlib.sha256(sample).hexdigest()
    manifest, archives, manifest_sha256 = _write_fixture(tmp_path, [(digest, sample)])
    _isolate_runtime(monkeypatch)

    result = MODULE.evaluate_cohort(
        manifest_path=manifest,
        archives_root=archives,
        policy=_policy(),
        expected_case_count=1,
        expected_manifest_sha256=manifest_sha256,
        detector=_detector,
        extractor=_extractor,
    )

    assert result["cohort"]["manifest_sha256"] == manifest_sha256
    assert result["current"]["root_case_count"] == 1
    assert result["current"]["family_confirmed_case_count"] == 1
    assert result["current"]["static_config_recovered_case_count"] == 1
    assert result["current"]["qualified_c2_case_count"] == 1
    assert result["current"]["strict_joint_case_count"] == 1
    assert result["current"]["strict_joint_rate"] == 1.0
    assert result["current"]["target_met"] is False
    assert result["current"]["root_pe"]["case_count"] == 1
    assert result["current"]["delivery"]["case_count"] == 0
    assert result["current"]["by_root_format"]["pe"]["strict_joint_case_count"] == 1
    assert result["current"]["partial_case_count"] == 0
    assert result["current"]["evaluation_status"] == "complete"
    assert result["strict_contract"]["all_static_layers_required_for_success"] is True
    assert result["strict_contract"]["all_static_layers_evaluated"] is True
    assert result["strict_contract"]["non_production_test_hook_used"] is True
    assert result["current"]["unique_configuration_count"] == 1
    assert result["current"]["unique_endpoint_count"] == 1
    assert result["current"]["root_vs_derived_provenance"]["strict_joint_root_layer_case_count"] == 1
    assert result["current"]["root_vs_derived_provenance"]["strict_joint_derived_layer_case_count"] == 0
    assert result["cases"][0]["archive_authenticated_in_memory"] is True
    assert result["cases"][0]["inner_sha256_verified"] is True
    assert result["safety"]["archive_authenticated_before_analysis"] is True
    assert result["safety"]["inner_sha256_verified_before_analysis"] is True
    rendered = json.dumps(result, ensure_ascii=False)
    assert "private-c2.example" not in rendered
    assert "secret-key" not in rendered
    assert "provider-name-is-selection-only" not in rendered


def test_implementation_identity_covers_dynamic_handler_and_common_dependencies() -> None:
    relative = {path.relative_to(ROOT).as_posix() for path in MODULE._source_identity_paths()}

    assert {
        "analysis-framework/common/analysis_contract.py",
        "analysis-framework/common/analyze_iso9660.py",
        "analysis-framework/common/bounded_process.py",
        "analysis-framework/common/extract_pyinstaller_archive.py",
        "analysis-framework/common/handler_catalog.py",
        "analysis-framework/common/malware_io.py",
        "analysis-framework/common/rebuild_mapped_pe.py",
        "analysis-framework/malware/remcosrat/extract_config.py",
    }.issubset(relative)


def test_source_mutation_during_evaluation_prevents_target_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sample = b"MZ-remcos-source-mutation"
    digest = hashlib.sha256(sample).hexdigest()
    manifest, archives, _manifest_sha256 = _write_fixture(tmp_path, [(digest, sample)])
    _isolate_runtime(monkeypatch)
    identities = iter(
        [
            {"fixture.py": "0" * 64},
            {"fixture.py": "1" * 64},
        ]
    )
    monkeypatch.setattr(MODULE, "_source_identity", lambda: next(identities))

    result = MODULE.evaluate_cohort(
        manifest_path=manifest,
        archives_root=archives,
        policy=_policy(),
        expected_case_count=1,
        detector=_detector,
        extractor=_extractor,
    )

    assert result["current"]["strict_joint_case_count"] == 1
    assert result["current"]["implementation_stable_during_evaluation"] is False
    assert result["current"]["target_met"] is False


def test_case_deadline_is_partial_and_prevents_target_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sample = b"MZ-remcos-case-deadline"
    digest = hashlib.sha256(sample).hexdigest()
    manifest, archives, _manifest_sha256 = _write_fixture(tmp_path, [(digest, sample)])
    _isolate_runtime(monkeypatch)

    class AdvancingClock:
        def __init__(self) -> None:
            self.value = 0.0

        def __call__(self) -> float:
            self.value += 0.6
            return self.value

    result = MODULE.evaluate_cohort(
        manifest_path=manifest,
        archives_root=archives,
        policy=_policy(),
        expected_case_count=1,
        detector=_detector,
        extractor=_extractor,
        case_deadline_seconds=0.5,
        cohort_deadline_seconds=60.0,
        clock=AdvancingClock(),
    )

    assert result["current"]["case_deadline_exceeded_count"] == 1
    assert result["current"]["partial_case_count"] == 1
    assert result["current"]["evaluation_completed_without_deadline"] is False
    assert result["current"]["target_met"] is False


def test_static_pipeline_partial_withholds_joint_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sample = b"MZ-remcos-static-partial"
    digest = hashlib.sha256(sample).hexdigest()
    manifest, archives, _manifest_sha256 = _write_fixture(tmp_path, [(digest, sample)])
    _isolate_runtime(monkeypatch)
    monkeypatch.setattr(
        MODULE,
        "recover_static_layers",
        lambda unit, **_kwargs: (
            [_root_layer(unit)],
            {
                "counts": {"limit_events": 1},
                "steps": [],
                "limit_events": [{"reason": "max_layers_reached"}],
            },
        ),
    )

    result = MODULE.evaluate_cohort(
        manifest_path=manifest,
        archives_root=archives,
        policy=_policy(),
        expected_case_count=1,
        detector=_detector,
        extractor=_extractor,
    )

    case = result["cases"][0]
    assert case["family_confirmed"] is True
    assert case["static_config_recovered"] is False
    assert case["qualified_c2"] is False
    assert case["strict_joint"] is False
    assert case["analysis_status"] == "partial"
    assert result["current"]["partial_case_count"] == 1
    assert result["current"]["target_met"] is False


def test_nested_unpacker_candidate_limit_withholds_joint_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """step成功でも内部候補が未走査ならcase全体をpartialへ閉じる。"""

    sample = b"MZ-remcos-nested-incomplete"
    digest = hashlib.sha256(sample).hexdigest()
    manifest, archives, _manifest_sha256 = _write_fixture(tmp_path, [(digest, sample)])
    _isolate_runtime(monkeypatch)
    monkeypatch.setattr(
        MODULE,
        "recover_static_layers",
        lambda unit, **_kwargs: (
            [_root_layer(unit)],
            {
                "counts": {"limit_events": 0},
                "steps": [
                    {
                        "status": "succeeded",
                        "report": {
                            "status": "candidate_limit_exceeded",
                            "candidate_set_complete": False,
                            "candidate_set_truncated": True,
                        },
                    }
                ],
                "limit_events": [],
            },
        ),
    )

    result = MODULE.evaluate_cohort(
        manifest_path=manifest,
        archives_root=archives,
        policy=_policy(),
        expected_case_count=1,
        detector=_detector,
        extractor=_extractor,
    )

    case = result["cases"][0]
    assert case["analysis_status"] == "partial"
    assert case["truncated"] is True
    assert case["strict_joint"] is False
    assert "static_unpacker_coverage_incomplete" in case["blockers"]


@pytest.mark.parametrize(
    ("report", "expected_reason"),
    [
        (
            {
                "status": "tool_not_configured",
                "candidate": True,
                "inventory_complete": False,
            },
            "tool_not_configured",
        ),
        (
            {
                "status": "artifacts_recovered",
                "complete": False,
            },
            "complete_false",
        ),
        (
            {
                "status": "extracted",
                "archive_test_complete": False,
                "full_archive_extraction_complete": False,
            },
            "archive_test_complete_false",
        ),
        (
            {
                "status": "analysis_budget_partial",
                "analysis_budget": {"selection_complete": False},
            },
            "selection_complete_false",
        ),
        (
            {
                "status": "partial_shared_budget_limit",
                "profile_evaluation_complete": False,
                "limit_reasons": ["profile_candidate_limit"],
            },
            "profile_evaluation_complete_false",
        ),
    ],
)
def test_nested_unpacker_incomplete_contract_fields_withhold_joint_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    report: dict,
    expected_reason: str,
) -> None:
    sample = b"MZ-remcos-nested-completeness"
    digest = hashlib.sha256(sample).hexdigest()
    manifest, archives, _manifest_sha256 = _write_fixture(tmp_path, [(digest, sample)])
    _isolate_runtime(monkeypatch)
    monkeypatch.setattr(
        MODULE,
        "recover_static_layers",
        lambda unit, **_kwargs: (
            [_root_layer(unit)],
            {
                "counts": {"limit_events": 0},
                "steps": [{"status": "succeeded", "report": report}],
                "limit_events": [],
            },
        ),
    )

    result = MODULE.evaluate_cohort(
        manifest_path=manifest,
        archives_root=archives,
        policy=_policy(),
        expected_case_count=1,
        detector=_detector,
        extractor=_extractor,
    )

    case = result["cases"][0]
    assert case["analysis_status"] == "partial"
    assert case["strict_joint"] is False
    assert case["static_incomplete_reason_counts"][expected_reason] >= 1


def test_negative_probe_validation_failure_is_not_pipeline_incomplete() -> None:
    """候補否定を示すvalidation_failedだけでcoverage不足へ誤昇格しない。"""

    assert (
        MODULE._pipeline_incomplete_reason_counts({"status": "validation_failed", "candidate_set_complete": True}) == {}
    )


def test_managed_il_runtime_target_diagnostic_is_not_recovery_incomplete() -> None:
    """CIL body全走査後のruntime dispatch診断は復元inventory不足と分離する。"""

    pipeline = {
        "steps": [
            {
                "status": "succeeded",
                "report": {
                    "pe": {
                        "managed_il_triage": {
                            "status": "analyzed",
                            "reference_coverage": {
                                "body_scan_complete": True,
                                "runtime_targets_complete": False,
                            },
                        }
                    }
                },
            }
        ]
    }

    assert MODULE._pipeline_incomplete_reason_counts(pipeline) == {}


def test_nsis_missing_member_crc_is_not_inventory_incomplete() -> None:
    """CRC欄のないNSISでも全member復元済みならcoverage不足へ誤昇格しない。"""

    pipeline = {
        "steps": [
            {
                "status": "succeeded",
                "report": {
                    "sevenzip": {
                        "inventory_complete": True,
                        "archive_test_complete": True,
                        "extraction_complete": True,
                        "full_archive_extraction_complete": True,
                        "crc_validation": {
                            "available_count": 0,
                            "verified_count": 0,
                            "unavailable_count": 6,
                            "complete": False,
                        },
                    }
                },
            }
        ]
    }

    assert MODULE._pipeline_incomplete_reason_counts(pipeline) == {}


@pytest.mark.parametrize(
    "crc_validation",
    (
        {
            "available_count": 1,
            "verified_count": 0,
            "unavailable_count": 0,
            "complete": False,
        },
        {
            "available_count": 0,
            "verified_count": 0,
            "unavailable_count": 0,
            "complete": False,
        },
    ),
)
def test_nsis_unverified_available_crc_remains_incomplete(
    crc_validation: dict[str, int | bool],
) -> None:
    """検証可能なCRCの未検証や空の診断は引き続きpartialへ閉じる。"""

    counts = MODULE._pipeline_incomplete_reason_counts({"sevenzip": {"crc_validation": crc_validation}})

    assert counts["complete_false"] == 1


def test_incomplete_managed_il_body_scan_remains_recovery_incomplete() -> None:
    """CIL body自体の未走査はruntime診断と異なりpartialのままにする。"""

    counts = MODULE._pipeline_incomplete_reason_counts(
        {
            "pe": {
                "managed_il_triage": {
                    "reference_coverage": {
                        "body_scan_complete": False,
                        "runtime_targets_complete": False,
                    }
                }
            }
        }
    )

    assert counts["body_scan_complete_false"] == 1
    assert counts["runtime_targets_complete_false"] == 1


@pytest.mark.parametrize(
    "status",
    (
        "archive_test_failed",
        "credential_or_archive_rejected",
        "encrypted_or_unsupported",
        "extract_failed",
        "input_size_rejected",
        "unsupported_nsis_script_pattern",
    ),
)
def test_explicit_recovery_failure_is_pipeline_incomplete(status: str) -> None:
    """既知の復元失敗statusはgeneric substringに依存せずpartialへ閉じる。"""

    assert MODULE._pipeline_incomplete_reason_counts({"status": status}) == {status: 1}


@pytest.mark.parametrize("container_format", ("rar", "7z", "apple-disk-image", "cab"))
def test_external_container_without_extractor_is_pipeline_incomplete(
    container_format: str,
) -> None:
    """外装containerの形式認識や部分carveだけを全走査済みと誤認しない。"""

    counts = MODULE._pipeline_incomplete_reason_counts(
        {
            "steps": [
                {
                    "status": "succeeded",
                    "report": {
                        "format": container_format,
                        "unpack_status": "artifacts_recovered",
                        "recovered": [{"kind": "carved-pe"}],
                    },
                }
            ]
        }
    )

    assert counts["container_extractor_unavailable"] == 1


def test_external_container_with_extractor_report_is_not_semantically_incomplete() -> None:
    """7-Zipの明示reportがある正常完了は構造gapを追加しない。"""

    counts = MODULE._pipeline_incomplete_reason_counts(
        {
            "steps": [
                {
                    "status": "succeeded",
                    "report": {
                        "format": "rar",
                        "sevenzip": {"status": "extracted"},
                    },
                }
            ]
        }
    )

    assert "container_extractor_unavailable" not in counts


def test_containerized_pe_requires_external_or_complete_inno_recovery() -> None:
    """containerized PEのcarveだけでは完了せず、完全Inno復元なら補完する。"""

    incomplete = MODULE._pipeline_incomplete_reason_counts(
        {
            "steps": [
                {
                    "status": "succeeded",
                    "report": {
                        "format": "pe",
                        "pe": {"containerized": True},
                    },
                }
            ]
        }
    )
    complete = MODULE._pipeline_incomplete_reason_counts(
        {
            "steps": [
                {
                    "status": "succeeded",
                    "report": {
                        "format": "pe",
                        "pe": {"containerized": True},
                        "inno": {
                            "candidate": True,
                            "inventory_complete": True,
                            "extraction_complete": True,
                            "status": "artifacts_recovered",
                        },
                    },
                }
            ]
        }
    )

    assert incomplete["pe_container_extractor_unavailable"] == 1
    assert "pe_container_extractor_unavailable" not in complete


def test_structural_recovery_blocker_is_pipeline_incomplete() -> None:
    """one-shot集約済みの構造復元blockerも専用評価器で失わない。"""

    counts = MODULE._pipeline_incomplete_reason_counts(
        {
            "steps": [],
            "structural_candidates": {
                "candidates": [
                    {
                        "blockers": [
                            "archive_extractor_not_run",
                            "non_blocking_diagnostic",
                        ]
                    }
                ]
            },
        }
    )

    assert counts["archive_extractor_not_run"] == 1
    assert "non_blocking_diagnostic" not in counts


@pytest.mark.parametrize(
    "status",
    (
        "input_size_rejected",
        "malformed_envelope",
        "parse_failed",
        "size_mismatch",
        "text_decode_failed",
    ),
)
def test_decoder_incomplete_status_is_propagated(status: str) -> None:
    """適用済み復号器の安全上限・構造失敗をcase完了判定まで伝播する。"""

    assert (
        MODULE._pipeline_incomplete_reason_counts(
            {"steps": [{"status": "succeeded", "report": {"decoder": {"status": status}}}]}
        )[status]
        == 1
    )


def test_container_coverage_gap_withholds_case_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """外部extractor未走査のRARはconfig候補があってもstrict成功にしない。"""

    sample = b"Rar!\x1a\x07\x01\x00-remcos-container-gap"
    digest = hashlib.sha256(sample).hexdigest()
    manifest, archives, _manifest_sha256 = _write_fixture(tmp_path, [(digest, sample)])
    _isolate_runtime(monkeypatch)
    monkeypatch.setattr(
        MODULE,
        "recover_static_layers",
        lambda unit, **_kwargs: (
            [_root_layer(unit)],
            {
                "counts": {"limit_events": 0},
                "steps": [
                    {
                        "status": "succeeded",
                        "report": {
                            "format": "rar",
                            "unpack_status": "artifacts_recovered",
                            "recovered": [{"kind": "carved-pe"}],
                        },
                    }
                ],
                "limit_events": [],
            },
        ),
    )

    result = MODULE.evaluate_cohort(
        manifest_path=manifest,
        archives_root=archives,
        policy=_policy(),
        expected_case_count=1,
        detector=_detector,
        extractor=_extractor,
    )

    case = result["cases"][0]
    assert case["analysis_status"] == "partial"
    assert case["static_config_recovered"] is False
    assert case["qualified_c2"] is False
    assert case["strict_joint"] is False
    assert case["static_incomplete_reason_counts"]["container_extractor_unavailable"] == 1
    assert "static_unpacker_coverage_incomplete" in case["blockers"]


def test_decoder_input_size_rejection_withholds_case_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """復号器の入力上限拒否をreport内で見落とさずstrict成功を抑止する。"""

    sample = b"MZ-remcos-decoder-input-size-rejected"
    digest = hashlib.sha256(sample).hexdigest()
    manifest, archives, _manifest_sha256 = _write_fixture(tmp_path, [(digest, sample)])
    _isolate_runtime(monkeypatch)
    monkeypatch.setattr(
        MODULE,
        "recover_static_layers",
        lambda unit, **_kwargs: (
            [_root_layer(unit)],
            {
                "counts": {"limit_events": 0},
                "steps": [
                    {
                        "status": "succeeded",
                        "report": {
                            "format": "script",
                            "remcos_powershell_base52": {"status": "input_size_rejected"},
                        },
                    }
                ],
                "limit_events": [],
            },
        ),
    )

    result = MODULE.evaluate_cohort(
        manifest_path=manifest,
        archives_root=archives,
        policy=_policy(),
        expected_case_count=1,
        detector=_detector,
        extractor=_extractor,
    )

    case = result["cases"][0]
    assert case["analysis_status"] == "partial"
    assert case["strict_joint"] is False
    assert case["static_incomplete_reason_counts"]["input_size_rejected"] == 1


def test_trusted_tool_paths_are_all_forwarded_to_static_pipeline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sample = b"MZ-remcos-forward-trusted-tools"
    digest = hashlib.sha256(sample).hexdigest()
    manifest, archives, _manifest_sha256 = _write_fixture(tmp_path, [(digest, sample)])
    observed: dict[str, Path | None] = {}
    expected = {
        "upx": tmp_path / "upx.exe",
        "sevenzip": tmp_path / "7z.exe",
        "innounp": tmp_path / "innounp.exe",
    }
    monkeypatch.setattr(MODULE, "_source_identity", lambda: {"fixture.py": "0" * 64})
    monkeypatch.setattr(MODULE, "detect_format", lambda _data, _name: "pe")
    monkeypatch.setattr(
        MODULE,
        "_verify_trusted_tool_contract",
        lambda _bundle, *, job_dir: (expected, {"verified": True}),
    )

    def recover(unit, **kwargs):
        observed.update({key: kwargs.get(key) for key in expected})
        return [_root_layer(unit)], _pipeline()

    monkeypatch.setattr(MODULE, "recover_static_layers", recover)

    result = MODULE.evaluate_cohort(
        manifest_path=manifest,
        archives_root=archives,
        policy=_policy(),
        expected_case_count=1,
        trusted_tools=object(),
        trusted_tools_job_dir=tmp_path,
        detector=_detector,
        extractor=_extractor,
    )

    assert observed == expected
    assert result["external_tools"]["used_tool_ids"] == ["innounp", "sevenzip", "upx"]


@pytest.mark.parametrize(
    ("mutation", "field"),
    [
        ({"host": "other.example"}, "host"),
        ({"endpoint": "private-c2.example:9999"}, "endpoint"),
        ({"contacted": True}, "contacted"),
        ({"third_field_kind": "absent"}, "third_field_kind"),
    ],
)
def test_config_contract_rejects_inconsistent_c2_records(
    mutation: dict,
    field: str,
) -> None:
    sample = b"MZ-remcos-invalid-c2-contract"
    report = _extractor(sample)
    report["c2"][0].update(mutation)

    assert MODULE._validated_config(sample, report) is None, field


def test_expected_case_count_is_pinned_before_analysis(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sample = b"MZ-remcos-count-pin"
    digest = hashlib.sha256(sample).hexdigest()
    manifest, archives, _manifest_sha256 = _write_fixture(tmp_path, [(digest, sample)])
    _isolate_runtime(monkeypatch)

    with pytest.raises(MODULE.AutomationEvaluationError) as raised:
        MODULE.evaluate_cohort(
            manifest_path=manifest,
            archives_root=archives,
            policy=_policy(),
            expected_case_count=50,
            detector=_detector,
            extractor=_extractor,
        )

    assert raised.value.reason == "manifest_case_count_mismatch"


def test_member_hash_mismatch_fails_closed_without_static_analysis(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    declared_digest = "a" * 64
    manifest, archives, _manifest_sha256 = _write_fixture(
        tmp_path,
        [(declared_digest, b"different-inner-content")],
    )
    _isolate_runtime(monkeypatch)
    called = {"detector": 0}

    def detector(_data: bytes, _path: Path | None) -> dict:
        called["detector"] += 1
        return {}

    result = MODULE.evaluate_cohort(
        manifest_path=manifest,
        archives_root=archives,
        policy=_policy(),
        expected_case_count=1,
        detector=detector,
        extractor=_extractor,
    )

    assert called["detector"] == 0
    assert result["current"]["strict_joint_case_count"] == 0
    assert result["current"]["unknown_root_kind_case_count"] == 1
    assert result["current"]["blocker_reason_case_counts"]["member_sha256_mismatch"] == 1
    assert result["cases"][0]["archive_authenticated_in_memory"] is False
    assert result["cases"][0]["inner_sha256_verified"] is False
    assert result["safety"]["archive_authenticated_before_analysis"] is False
    assert result["safety"]["inner_sha256_verified_before_analysis"] is False
    assert result["strict_contract"]["all_static_layers_evaluated"] is False


def test_malwarebazaar_style_aes128_archive_is_authenticated(
    tmp_path: Path,
) -> None:
    sample = b"MZ-aes128-provider-archive"
    digest = hashlib.sha256(sample).hexdigest()
    archive_bytes = _aes_zip(sample, bits=128)
    archive_path = tmp_path / "sample.zip"
    archive_path.write_bytes(archive_bytes)
    member, safe_name, archive_sha256, encryption_bits = MODULE.read_authenticated_member(
        archive_path,
        {
            "root_sha256": digest,
            "archive_sha256": hashlib.sha256(archive_bytes).hexdigest(),
            "archive_size": len(archive_bytes),
        },
        password=b"infected",
    )
    assert member == sample
    assert safe_name == f"{digest}.exe"
    assert archive_sha256 == hashlib.sha256(archive_bytes).hexdigest()
    assert encryption_bits == 128


def test_distinct_configs_across_layers_are_withheld_and_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root_data = b"MZ-root-layer"
    child_data = b"MZ-child-layer"
    digest = hashlib.sha256(root_data).hexdigest()
    manifest, archives, _manifest_sha256 = _write_fixture(tmp_path, [(digest, root_data)])
    monkeypatch.setattr(MODULE, "_source_identity", lambda: {"fixture.py": "0" * 64})
    monkeypatch.setattr(MODULE, "detect_format", lambda _data, _name: "pe")

    def recover(unit, **_kwargs):
        root = _root_layer(unit)
        child = MODULE.StaticLayer(
            name="child.exe",
            data=child_data,
            sha256=hashlib.sha256(child_data).hexdigest(),
            parent_sha256=root.sha256,
            depth=1,
            transform="synthetic-static-recovery",
        )
        return [root, child], _pipeline()

    monkeypatch.setattr(MODULE, "recover_static_layers", recover)

    result = MODULE.evaluate_cohort(
        manifest_path=manifest,
        archives_root=archives,
        policy=_policy(),
        expected_case_count=1,
        detector=_detector,
        extractor=lambda data: _extractor(
            data,
            endpoint=("first-private.example:2404" if data == root_data else "second-private.example:2404"),
        ),
    )

    case = result["cases"][0]
    assert case["family_confirmed"] is True
    assert case["configuration_conflict"] is True
    assert case["distinct_configuration_count"] == 2
    assert case["static_config_recovered"] is False
    assert case["qualified_c2"] is False
    assert case["strict_joint"] is False
    assert case["configuration_evidence_layers"] == []
    assert len(case["configuration_candidate_evidence_layers"]) == 2
    assert result["current"]["unique_configuration_count"] == 2
    assert result["current"]["unique_endpoint_count"] == 2
    assert result["current"]["blocker_reason_case_counts"]["conflicting_configuration_candidates"] == 1
    rendered = json.dumps(result)
    assert "first-private.example" not in rendered
    assert "second-private.example" not in rendered


def test_member_size_quota_rejection_is_a_counted_case_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sample = b"MZ-more-than-four-bytes"
    digest = hashlib.sha256(sample).hexdigest()
    manifest, archives, _manifest_sha256 = _write_fixture(tmp_path, [(digest, sample)])
    _isolate_runtime(monkeypatch)
    monkeypatch.setattr(MODULE, "MAX_MEMBER_BYTES", 4)

    result = MODULE.evaluate_cohort(
        manifest_path=manifest,
        archives_root=archives,
        policy=_policy(),
        expected_case_count=1,
        detector=_detector,
        extractor=_extractor,
    )

    assert result["current"]["root_case_count"] == 1
    assert result["current"]["strict_joint_case_count"] == 0
    assert result["current"]["blocker_reason_case_counts"]["member_size_limit"] == 1


def test_expected_manifest_hash_mismatch_aborts_before_archive_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sample = b"MZ-manifest-hash"
    digest = hashlib.sha256(sample).hexdigest()
    manifest, archives, actual_manifest_sha256 = _write_fixture(tmp_path, [(digest, sample)])
    _isolate_runtime(monkeypatch)
    wrong = "f" * 64 if actual_manifest_sha256 != "f" * 64 else "e" * 64

    with pytest.raises(MODULE.AutomationEvaluationError) as raised:
        MODULE.evaluate_cohort(
            manifest_path=manifest,
            archives_root=archives,
            policy=_policy(),
            expected_case_count=1,
            expected_manifest_sha256=wrong,
            detector=_detector,
            extractor=_extractor,
        )

    assert raised.value.reason == "manifest_sha256_mismatch"


def test_manifest_duplicate_case_and_case_quota_are_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = b"first"
    second = b"second"
    first_digest = hashlib.sha256(first).hexdigest()
    second_digest = hashlib.sha256(second).hexdigest()
    manifest, _archives, _manifest_sha256 = _write_fixture(
        tmp_path,
        [(first_digest, first), (second_digest, second)],
    )
    monkeypatch.setattr(MODULE, "MAX_CASES", 1)
    with pytest.raises(MODULE.AutomationEvaluationError) as quota:
        MODULE.load_manifest(manifest)
    assert quota.value.reason == "manifest_case_quota_exceeded"

    parsed = json.loads(manifest.read_text(encoding="utf-8"))
    parsed["selected_hashes"] = [first_digest, first_digest]
    parsed["items"][1]["sha256"] = first_digest
    parsed["items"][1]["metadata"]["sha256_hash"] = first_digest
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text(json.dumps(parsed), encoding="utf-8")
    monkeypatch.setattr(MODULE, "MAX_CASES", 256)
    with pytest.raises(MODULE.AutomationEvaluationError) as repeated:
        MODULE.load_manifest(duplicate)
    assert repeated.value.reason == "manifest_duplicate_case"


def test_cli_help_and_policy_limits_are_japanese_and_bounded() -> None:
    parser = MODULE.build_parser()
    help_text = parser.format_help()
    assert "使用法:" in help_text
    assert "検体実行・通信なし" in help_text
    assert "--sevenzip" not in help_text
    assert "--trusted-tools-manifest" in help_text
    with pytest.raises(SystemExit):
        parser.parse_args(
            [
                "--manifest",
                "manifest.json",
                "--archives-root",
                "archives",
                "--output",
                "result.json",
                "--max-layers",
                str(MODULE.MAX_POLICY_LAYERS + 1),
            ]
        )


def test_cli_rejects_arbitrary_sevenzip_executable_without_running_it(
    tmp_path: Path,
) -> None:
    arbitrary_pe = tmp_path / "arbitrary.exe"
    original = b"MZ arbitrary executable must not be accepted"
    arbitrary_pe.write_bytes(original)
    output = tmp_path / "result.json"
    completed = subprocess.run(
        [
            sys.executable,
            "-X",
            "utf8",
            "-I",
            str(EVALUATOR),
            "--manifest",
            str(tmp_path / "manifest.json"),
            "--archives-root",
            str(tmp_path / "archives"),
            "--output",
            str(output),
            "--sevenzip",
            str(arbitrary_pe),
        ],
        cwd=tmp_path,
        input="infected\n",
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
    )
    assert completed.returncode == 2
    assert not output.exists()
    assert arbitrary_pe.read_bytes() == original


def test_trusted_tool_manifest_pin_and_job_private_snapshot_are_required(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sample = b"MZ-trusted-tool-snapshot"
    digest = hashlib.sha256(sample).hexdigest()
    manifest, archives, _manifest_sha256 = _write_fixture(tmp_path, [(digest, sample)])
    configuration, operator_manifest, _sevenzip = _trusted_tool_configuration(tmp_path)
    bad_configuration = MODULE.TrustedToolConfiguration(
        manifest_path=operator_manifest,
        manifest_sha256="0" * 64,
    )
    with pytest.raises(MODULE.AutomationEvaluationError) as mismatch:
        MODULE._load_operator_trusted_tool_policy(
            bad_configuration,
            forbidden_roots=(archives, manifest),
        )
    assert mismatch.value.reason == "trusted_tool_manifest_pin_mismatch"

    tool_policy = MODULE._load_operator_trusted_tool_policy(
        configuration,
        forbidden_roots=(archives, manifest),
    )
    job_dir = tmp_path / "job-private"
    job_dir.mkdir()
    bundle = MODULE._stage_operator_trusted_tools(tool_policy, job_dir=job_dir)
    _isolate_runtime(monkeypatch)
    real_verify = MODULE.verify_trusted_tool_bundle
    verification_count = 0

    def counting_verify(current_bundle, *, job_dir):
        nonlocal verification_count
        verification_count += 1
        return real_verify(current_bundle, job_dir=job_dir)

    monkeypatch.setattr(MODULE, "verify_trusted_tool_bundle", counting_verify)
    result = MODULE.evaluate_cohort(
        manifest_path=manifest,
        archives_root=archives,
        policy=_policy(),
        expected_case_count=1,
        detector=_detector,
        extractor=_extractor,
        trusted_tools=bundle,
        trusted_tools_job_dir=job_dir,
    )
    provenance = result["external_tools"]["operator_managed_trusted_tools"]
    assert result["external_tools"]["used_tool_ids"] == ["sevenzip"]
    assert provenance["operator_manifest_sha256"] == configuration.manifest_sha256
    assert (
        provenance["tools"]["sevenzip"]["sha256"]
        == hashlib.sha256(b"MZ synthetic tool bytes; this file must never be executed").hexdigest()
    )
    assert verification_count >= 4
    assert result["safety"]["arbitrary_external_tool_path_accepted"] is False
    assert result["safety"]["trusted_tool_snapshot_verified"] is True
    assert str(operator_manifest.resolve()) not in json.dumps(result)


def test_trusted_tool_manifest_arguments_are_an_atomic_pair() -> None:
    parser = MODULE.build_parser()
    arguments = parser.parse_args(
        [
            "--manifest",
            "manifest.json",
            "--archives-root",
            "archives",
            "--output",
            "result.json",
            "--expected-manifest-sha256",
            "0" * 64,
            "--trusted-tools-manifest",
            "trusted-tools.json",
        ]
    )
    with pytest.raises(MODULE.AutomationEvaluationError) as incomplete:
        MODULE._trusted_tool_configuration_from_args(arguments)
    assert incomplete.value.reason == "trusted_tool_configuration_incomplete"


def test_main_stages_only_pinned_job_private_tool_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sample = b"MZ-main-trusted-tool-lifecycle"
    digest = hashlib.sha256(sample).hexdigest()
    manifest, archives, manifest_sha256 = _write_fixture(tmp_path, [(digest, sample)])
    configuration, operator_manifest, source_sevenzip = _trusted_tool_configuration(tmp_path)
    output = tmp_path / "evaluation.json"
    observed_snapshot: Path | None = None

    def fake_evaluate_cohort(**kwargs):
        nonlocal observed_snapshot
        bundle = kwargs["trusted_tools"]
        job_dir = kwargs["trusted_tools_job_dir"]
        snapshot = bundle.tools["sevenzip"]
        assert snapshot is not None
        MODULE.verify_trusted_tool_bundle(bundle, job_dir=job_dir)
        assert snapshot.path != source_sevenzip.resolve()
        assert snapshot.path.is_relative_to(job_dir)
        observed_snapshot = snapshot.path
        return {"current": {"target_met": True}}

    monkeypatch.setattr(MODULE, "_read_password_from_stdin", lambda: b"infected")
    monkeypatch.setattr(MODULE, "evaluate_cohort", fake_evaluate_cohort)
    return_code = MODULE.main(
        [
            "--manifest",
            str(manifest),
            "--archives-root",
            str(archives),
            "--output",
            str(output),
            "--expected-manifest-sha256",
            manifest_sha256,
            "--trusted-tools-manifest",
            str(operator_manifest),
            "--trusted-tools-manifest-sha256",
            configuration.manifest_sha256,
        ]
    )
    assert return_code == 0
    assert json.loads(output.read_text(encoding="utf-8")) == {"current": {"target_met": True}}
    assert observed_snapshot is not None
    assert not observed_snapshot.exists()


def test_direct_script_invocation_bootstraps_repository_imports(tmp_path: Path) -> None:
    completed = subprocess.run(
        [sys.executable, "-X", "utf8", "-I", str(EVALUATOR), "--help"],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
    assert "使用法:" in completed.stdout
    assert "検体実行・通信なし" in completed.stdout


def test_password_is_bounded_to_one_stdin_line() -> None:
    assert MODULE._read_password_from_stdin(io.BytesIO(b"infected\r\n")) == b"infected"

    class PipeWithoutEof:
        def readline(self, _maximum: int) -> bytes:
            return b"infected\n"

        def read(self, _maximum: int) -> bytes:  # pragma: no cover - 呼ばれた場合にtestが即失敗する。
            raise AssertionError("1行取得後にEOF待ちしてはなりません")

    assert MODULE._read_password_from_stdin(PipeWithoutEof()) == b"infected"


def test_output_target_rejects_input_overlap_and_writes_atomically(
    tmp_path: Path,
) -> None:
    sample = b"fixture"
    digest = hashlib.sha256(sample).hexdigest()
    manifest, archives, _manifest_sha256 = _write_fixture(tmp_path, [(digest, sample)])

    with pytest.raises(MODULE.AutomationEvaluationError) as same_manifest:
        MODULE._validate_output_target(
            manifest,
            manifest_path=manifest,
            archives_root=archives,
        )
    assert same_manifest.value.reason == "output_overlaps_manifest"

    manifest_alias = tmp_path / "manifest-hardlink.json"
    os.link(manifest, manifest_alias)
    with pytest.raises(MODULE.AutomationEvaluationError) as manifest_hardlink:
        MODULE._validate_output_target(
            manifest_alias,
            manifest_path=manifest,
            archives_root=archives,
        )
    assert manifest_hardlink.value.reason == "output_overlaps_manifest"

    with pytest.raises(MODULE.AutomationEvaluationError) as inside_archive:
        MODULE._validate_output_target(
            archives / "result.json",
            manifest_path=manifest,
            archives_root=archives,
        )
    assert inside_archive.value.reason == "output_overlaps_archives"

    with pytest.raises(MODULE.AutomationEvaluationError) as repository_source:
        MODULE._validate_output_target(
            EVALUATOR,
            manifest_path=manifest,
            archives_root=archives,
        )
    assert repository_source.value.reason == "output_overlaps_repository"

    protected = tmp_path / "trusted-tool-snapshot.exe"
    protected.write_bytes(b"pinned snapshot")
    protected_alias = tmp_path / "result-hardlink.json"
    os.link(protected, protected_alias)
    with pytest.raises(MODULE.AutomationEvaluationError) as protected_hardlink:
        MODULE._validate_output_target(
            protected_alias,
            manifest_path=manifest,
            archives_root=archives,
            protected_paths=(protected,),
        )
    assert protected_hardlink.value.reason == "output_overlaps_protected_path"

    output, parent_identity, output_identity = MODULE._validate_output_target(
        tmp_path / "result.json",
        manifest_path=manifest,
        archives_root=archives,
    )
    MODULE._write_output_safely(
        output,
        b'{"safe":true}\n',
        parent_identity=parent_identity,
        output_identity=output_identity,
    )
    assert output.read_bytes() == b'{"safe":true}\n'


def test_job_private_trusted_tool_snapshot_can_be_cleaned_without_output(
    tmp_path: Path,
) -> None:
    configuration, _manifest, _sevenzip = _trusted_tool_configuration(tmp_path)
    policy = MODULE._load_operator_trusted_tool_policy(configuration, forbidden_roots=())
    with tempfile.TemporaryDirectory(prefix="evaluator-job-", dir=tmp_path) as job_text:
        job_dir = Path(job_text)
        bundle = MODULE._stage_operator_trusted_tools(policy, job_dir=job_dir)
        MODULE._verify_trusted_tool_contract(bundle, job_dir=job_dir)
    assert not job_dir.exists()
