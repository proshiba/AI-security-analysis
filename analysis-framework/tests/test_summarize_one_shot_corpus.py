"""one-shot成果物コーパス集計の安全性と母数を検証する。"""

from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
COMMON = ROOT / "analysis-framework" / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import analysis_contract  # noqa: E402
import batch_error_contract  # noqa: E402
import summarize_one_shot_corpus as corpus  # noqa: E402

SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
IMPHASH = "1" * 32


@pytest.mark.parametrize(
    "script_name",
    ["summarize_one_shot_corpus.py", "evaluate_valleyrat_holdout.py"],
)
def test_command_line_help_runs_under_isolated_python(script_name: str) -> None:
    """運用手順どおりのisolated Pythonでもlocal moduleを解決できる。"""

    completed = subprocess.run(
        [sys.executable, "-I", str(COMMON / script_name), "--help"],
        check=False,
        capture_output=True,
        timeout=30,
    )

    assert completed.returncode == 0


def _write_json(path: Path, value: object) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = (
        json.dumps(
            value,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    path.write_text(payload, encoding="utf-8", newline="\n")
    return corpus._sha256_bytes(payload.encode("utf-8"))


def _logic_functions(*fingerprints: str) -> list[dict[str, object]]:
    return [
        {
            "role": f"role_{index}",
            "fingerprints": {
                "semantic_sequence_sha256": fingerprint,
                "semantic_token_count": 12,
            },
        }
        for index, fingerprint in enumerate(fingerprints)
    ]


def _write_case(
    run: Path,
    digest: str,
    *,
    family_status: str = "resolved",
    family: str | None = "valleyrat",
    config_recovered: bool = True,
    config_candidate: bool = False,
    config_required: bool | None = True,
    automation_status: str = "complete",
    case_status: str = "complete",
    blockers: list[str] | None = None,
    handler_statuses: tuple[str, ...] = (),
    candidate_status: str = "no_candidates",
    route_status: str = "assessment_rejected",
    projection_reason: str = "no_candidate_verification_routes",
    route_affects_overall: bool = False,
    imphash: str | None = None,
    telfhash: str | None = None,
    logic_fingerprints: tuple[str, ...] = (),
    source_name: str = "TOP-SECRET-SOURCE.exe",
) -> None:
    case_dir = run / "cases" / digest
    case_dir.mkdir(parents=True, exist_ok=True)
    resolved_family = family if family_status == "resolved" else None
    selected = [family] if family is not None else []
    case_blockers = list(blockers or [])
    if automation_status != "complete" and not case_blockers:
        case_blockers = ["function_analysis"]

    orchestration = {
        "schema_version": 2,
        "sample_sha256": digest,
        "status": automation_status,
        "family_resolution": {
            "status": family_status,
            "family": resolved_family,
            "reason": "fixture",
        },
        "outputs": {
            "config_recovered": config_recovered,
            "config_evidence": [
                {
                    "raw_config": "DO-NOT-PUBLISH-RAW-CONFIG",
                    "endpoint": "203.0.113.99:4444",
                }
            ],
        },
        "candidate_outputs": {
            "config_candidate_recovered": config_candidate,
            "config_candidate_evidence": [{"password": "DO-NOT-PUBLISH-PASSWORD"}],
        },
        "quality_gates": {
            "config": {
                "required": config_required,
                "satisfied": config_recovered,
                "status": (
                    "satisfied"
                    if config_recovered
                    else "required_missing"
                    if config_required is True
                    else "not_applicable"
                    if config_required is False
                    else "not_declared"
                ),
            }
        },
        "blockers": sorted(case_blockers),
        "automation": {
            "sample_executed": False,
            "network_contacted": False,
            "ai_used": False,
        },
    }
    candidate = {
        "schema_version": 1,
        "status": candidate_status,
        "candidate_count": 0,
        "planned_attempt_count": 0,
        "families": [],
        "executed_sample": False,
        "network_contacted": False,
        "filesystem_written_by_handlers": False,
    }
    route = {
        "schema_version": 1,
        "sha256": digest,
        "status": route_status,
        "status_scope": "route_candidate_projection_only",
        "projection_disposition": "not_applicable",
        "projection_reason": projection_reason,
        "overall_analysis_result_affected": route_affects_overall,
        "route_config_candidate_recovered": config_candidate,
        "safety": {
            "sample_executed": False,
            "network_contacted": False,
            "raw_config_included": False,
            "raw_payload_published": False,
            "credentials_published": False,
        },
    }
    static_logic = {
        "schema_version": 1,
        "sha256": digest,
        "functions": _logic_functions(*logic_fingerprints),
    }
    generic: dict[str, object] = {
        "schema_version": 1,
        "sha256": digest,
        "type": "pe" if imphash else "elf" if telfhash else "data",
        "executed_sample": False,
        "network_contacted": False,
    }
    if imphash:
        generic["pe"] = {"imphash": imphash}
    if telfhash:
        generic["elf"] = {"telfhash": telfhash}
    documents = {
        "orchestration.json": orchestration,
        "candidate-handler-assessment.json": candidate,
        "route-config-candidates.json": route,
        "static-logic.json": static_logic,
        "generic-triage.json": generic,
    }
    artifact_hashes = {name: _write_json(case_dir / name, document) for name, document in documents.items()}
    executions = [
        {"handler_id": f"valleyrat:fixture-{index}", "status": status} for index, status in enumerate(handler_statuses)
    ]
    report = {
        "schema_version": 1,
        "sample": {
            "sha256": digest,
            "source_name": source_name,
            "input_kind": "file",
        },
        "classification": {
            "family": family,
            "selected_family": family,
            "selected_families": selected,
            "automation_status": family_status,
            "automation_family": resolved_family,
        },
        "generic_triage": "complete",
        "analysis_contract": {
            "schema_version": 1,
            "sha256": "f" * 64,
        },
        "handler_executions": executions,
        "assessment_only": False,
        "executed_sample": False,
        "network_contacted": False,
        "ai_used": False,
        "case_state": {
            "status": case_status,
            "complete": case_status == "complete",
            "resumable": case_status == "complete",
            "blockers": sorted(case_blockers),
        },
        "artifact_sha256": artifact_hashes,
    }
    analysis_contract.seal_report(report)
    _write_json(case_dir / "report.json", report)


def _replace_case_artifacts(
    run: Path,
    digest: str,
    **documents: dict[str, object],
) -> None:
    case_dir = run / "cases" / digest
    report_path = case_dir / "report.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    for name, document in documents.items():
        relative = name.replace("__", "-").replace("_json", ".json")
        report["artifact_sha256"][relative] = _write_json(
            case_dir / relative,
            document,
        )
    analysis_contract.seal_report(report)
    _write_json(report_path, report)


def _classification_document(
    digest: str,
    layer_specs: list[dict[str, object] | None],
) -> dict[str, object]:
    records = []
    for index, spec in enumerate(layer_specs):
        layer_sha256 = corpus._sha256_bytes(f"{digest}:{index}".encode())
        evaluations: list[dict[str, object]] = []
        if spec is not None:
            error = spec.get("error")
            if error is not None:
                evaluation: dict[str, object] = {
                    "malware_type": "valleyrat",
                    "detector_matched": False,
                    "automatic_route_eligible": False,
                    "known_outer_sha256": False,
                    "known_inner_sha256": False,
                    "known_routing_sha256": False,
                    "error": error,
                }
            else:
                matched = spec.get("matched") is True
                observations: dict[str, object] = {}
                loader_profile = spec.get("loader_profile")
                route_profile = spec.get("route_profile")
                if loader_profile is not None:
                    observations["validated_static_loader_profile"] = {
                        "status": "validated_static_loader_component",
                        "profile": loader_profile,
                    }
                if route_profile is not None:
                    observations["validated_route_only_proxy_profile"] = route_profile
                evaluation = {
                    "malware_type": "valleyrat",
                    "detector_matched": matched,
                    "automatic_route_eligible": matched,
                    "known_outer_sha256": False,
                    "known_inner_sha256": False,
                    "known_routing_sha256": False,
                    "error": None,
                    "detection": {
                        "matched": matched,
                        "observations": observations,
                        "campaigns": [{"terminal_family_confirmed": (spec.get("terminal") is True)}],
                    },
                }
            evaluations.append(evaluation)
        records.append(
            {
                "layer": {
                    "sha256": layer_sha256,
                    "size": 1,
                    "format": "pe",
                    "parent_sha256": None,
                    "depth": index,
                    "transform": "fixture",
                    "name": "PRIVATE-LAYER-NAME.exe",
                },
                "classification": {"detector_evaluations": evaluations},
            }
        )
    return {
        "sample": "PRIVATE-CLASSIFICATION-SOURCE.exe",
        "layer_classifications": records,
    }


def _static_layers_document(*reasons: str) -> dict[str, object]:
    return {
        "schema_version": 1,
        "limit_events": [
            {
                "reason": reason,
                "kind": "PRIVATE-STATIC-KIND",
            }
            for reason in reasons
        ],
        "executed_sample": False,
        "network_contacted": False,
        "recovered_content_exported": False,
    }


def _write_run_summary(
    run: Path,
    digests: list[str],
    *,
    errors: list[dict[str, object]] | None = None,
    duplicates: list[str] | None = None,
) -> None:
    errors = list(errors or [])
    duplicates = list(duplicates or [])
    summary = {
        "schema_version": 1,
        "counts": {
            "input_files": len(digests) + len(errors) + len(duplicates),
            "analyzed": len(digests),
            "duplicates": len(duplicates),
            "errors": len(errors),
        },
        "cases": [{"sha256": digest, "report": f"cases/{digest}/report.json"} for digest in digests],
        "derived_cases": [],
        "duplicates": [{"sha256": digest, "source_name": "PRIVATE-DUPLICATE-NAME.exe"} for digest in duplicates],
        "errors": errors,
        "executed_sample": False,
        "network_contacted": False,
        "ai_used": False,
    }
    _write_json(run / "summary.json", summary)


def test_rates_ground_truth_config_boundary_and_secret_redaction(tmp_path: Path) -> None:
    run = tmp_path / "run"
    _write_case(run, SHA_A, imphash=IMPHASH)
    _write_case(
        run,
        SHA_B,
        config_recovered=False,
        automation_status="partial",
        case_status="partial",
        blockers=["203.0.113.99:4444", "config"],
        imphash=IMPHASH,
    )
    _write_case(
        run,
        SHA_C,
        family_status="unresolved",
        family=None,
        config_recovered=False,
        config_candidate=True,
        config_required=None,
        automation_status="triaged_unknown",
        case_status="triaged_unknown",
        blockers=["family_resolution"],
    )
    _write_case(
        run,
        SHA_D,
        family="agenttesla",
        config_recovered=False,
        config_required=False,
    )
    _write_run_summary(run, [SHA_D, SHA_B, SHA_A, SHA_C])

    summary = corpus.summarize_runs([run], expected_family="valleyrat")

    assert summary["rates"]["family_resolution"] == {
        "numerator": 3,
        "denominator": 4,
        "percentage": 75.0,
        "denominator_basis": "unique_valid_cases",
    }
    assert summary["rates"]["confirmed_config_all_cases"]["numerator"] == 1
    assert summary["rates"]["confirmed_config_when_required"]["denominator"] == 2
    assert summary["rates"]["expected_family_resolution"]["numerator"] == 2
    assert summary["rates"]["automation_complete"]["numerator"] == 2
    assert summary["config"]["status_counts"] == {
        "candidate_only": 1,
        "confirmed_recovered": 1,
        "not_required": 1,
        "required_missing": 1,
    }
    c_case = next(item for item in summary["cases"] if item["sha256"] == SHA_C)
    assert "route:projection:no_candidate_verification_routes" in c_case["diagnostic_reason_codes"]
    assert all(not item.startswith("route:") for item in c_case["failure_reason_codes"])
    serialized = json.dumps(summary, ensure_ascii=False)
    for secret in (
        "TOP-SECRET-SOURCE.exe",
        "DO-NOT-PUBLISH-RAW-CONFIG",
        "DO-NOT-PUBLISH-PASSWORD",
        "203.0.113.99:4444",
        "PRIVATE-DUPLICATE-NAME.exe",
    ):
        assert secret not in serialized


def test_namespaced_batch_case_gate_and_handler_reasons(tmp_path: Path) -> None:
    run = tmp_path / "run"
    _write_case(
        run,
        SHA_A,
        config_recovered=False,
        automation_status="partial",
        case_status="partial",
        blockers=["config"],
        handler_statuses=("failed", "no_evidence"),
    )
    error = batch_error_contract.build_record(
        input_index=1,
        stage="input_read",
        error=ValueError("private path must not escape"),
    )
    _write_run_summary(run, [SHA_A], errors=[error])

    summary = corpus.summarize_runs([run])

    assert summary["failure_reasons"]["batch_input_reason_counts"] == {"batch:input_read:input_read_failed": 1}
    reasons = summary["failure_reasons"]["case_reason_counts"]
    assert reasons["case:blocker:config"] == 1
    assert reasons["gate:blocker:config"] == 1
    assert reasons["handler:failed"] == 1
    assert reasons["handler:no_evidence"] == 1
    assert reasons["automation:status:partial"] == 1


def test_identical_sha_across_runs_is_deduplicated(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    for run in (first, second):
        _write_case(run, SHA_A)
        _write_run_summary(run, [SHA_A])

    summary = corpus.summarize_runs([second, first])

    assert summary["counts"]["case_observations"] == 2
    assert summary["counts"]["unique_valid_cases"] == 1
    assert summary["counts"]["duplicate_case_observations"] == 1
    assert len(summary["cases"]) == 1


def test_conflicting_sha_across_runs_is_not_silently_merged(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    _write_case(first, SHA_A, config_recovered=True)
    _write_case(
        second,
        SHA_A,
        config_recovered=False,
        automation_status="partial",
        case_status="partial",
        blockers=["config"],
    )
    _write_run_summary(first, [SHA_A])
    _write_run_summary(second, [SHA_A])

    summary = corpus.summarize_runs([first, second])

    assert summary["counts"]["unique_valid_cases"] == 0
    assert summary["counts"]["conflicting_case_sha256"] == 1
    assert summary["invalid_cases"] == [
        {
            "sha256": SHA_A,
            "observation_count": 2,
            "reason_codes": ["integrity:duplicate_case_conflict"],
        }
    ]


def test_selected_artifact_hash_mismatch_is_excluded(tmp_path: Path) -> None:
    run = tmp_path / "run"
    _write_case(run, SHA_A)
    orchestration_path = run / "cases" / SHA_A / "orchestration.json"
    orchestration = json.loads(orchestration_path.read_text(encoding="utf-8"))
    orchestration["status"] = "partial"
    _write_json(orchestration_path, orchestration)
    _write_run_summary(run, [SHA_A])

    summary = corpus.summarize_runs([run])

    assert summary["counts"]["unique_valid_cases"] == 0
    assert summary["rates"]["family_resolution"]["denominator"] == 0
    assert summary["invalid_cases"][0]["reason_codes"] == ["integrity:artifact_hash_mismatch_orchestration_json"]


def test_exact_clusters_require_strong_exact_axes(tmp_path: Path) -> None:
    run = tmp_path / "run"
    fingerprints = ("8" * 64, "9" * 64)
    _write_case(run, SHA_A, logic_fingerprints=fingerprints)
    _write_case(run, SHA_B, logic_fingerprints=tuple(reversed(fingerprints)))
    _write_case(run, SHA_C, logic_fingerprints=("8" * 64,))
    _write_run_summary(run, [SHA_C, SHA_A, SHA_B])

    summary = corpus.summarize_runs([run])

    assert summary["structure"]["cluster_count"] == 1
    cluster = summary["structure"]["exact_clusters"][0]
    assert cluster["axis"] == "static_logic_fingerprint_set"
    assert cluster["members"] == [SHA_A, SHA_B]
    assert summary["structure"]["unclustered_case_count"] == 1
    assert next(item for item in summary["cases"] if item["sha256"] == SHA_C)["structure_cluster_ids"] == []


def test_structure_cluster_output_is_input_order_independent(tmp_path: Path) -> None:
    run = tmp_path / "run"
    _write_case(run, SHA_A, imphash=IMPHASH)
    _write_case(run, SHA_B, imphash=IMPHASH)
    _write_run_summary(run, [SHA_B, SHA_A])

    first = corpus.summarize_runs([run])
    _write_run_summary(run, [SHA_A, SHA_B])
    second = corpus.summarize_runs([run])

    assert first["structure"] == second["structure"]
    assert first["cases"] == second["cases"]


def test_only_json_artifacts_are_opened(tmp_path: Path, monkeypatch) -> None:
    run = tmp_path / "run"
    _write_case(run, SHA_A)
    _write_run_summary(run, [SHA_A])
    sample = run / "cases" / SHA_A / "sample.exe"
    sample.write_bytes(b"must-not-be-read")
    original = analysis_contract._read_regular_file_snapshot
    observed: list[Path] = []

    def guarded(path: Path, *, max_bytes: int) -> bytes:
        candidate = Path(path)
        observed.append(candidate)
        assert candidate.suffix == ".json"
        return original(candidate, max_bytes=max_bytes)

    monkeypatch.setattr(analysis_contract, "_read_regular_file_snapshot", guarded)

    summary = corpus.summarize_runs([run])

    assert summary["counts"]["unique_valid_cases"] == 1
    assert sample not in observed
    assert summary["safety"]["scope"] == "aggregate_reader_process_only"
    assert summary["safety"]["samples_opened"] is False
    assert summary["safety"]["subprocess_started"] is False
    assert summary["safety"]["source_analysis_worker_processes_assessed_by_this_flag"] is False


def test_reparse_artifact_is_rejected_without_following_it(tmp_path: Path) -> None:
    run = tmp_path / "run"
    _write_case(run, SHA_A)
    _write_run_summary(run, [SHA_A])
    target = run / "cases" / SHA_A / "orchestration.json"
    external = tmp_path / "external.json"
    external.write_text(target.read_text(encoding="utf-8"), encoding="utf-8")
    target.unlink()
    try:
        os.symlink(external, target)
    except OSError:
        pytest.skip("この環境ではsymlinkを作成できません")

    summary = corpus.summarize_runs([run])

    assert summary["counts"]["unique_valid_cases"] == 0
    assert any(
        code.startswith("integrity:artifact_boundary_invalid_") for code in summary["invalid_cases"][0]["reason_codes"]
    )


def test_cli_writes_deterministic_json_and_japanese_markdown(tmp_path: Path) -> None:
    run = tmp_path / "run"
    _write_case(run, SHA_A)
    _write_run_summary(run, [SHA_A])
    output_json = tmp_path / "out" / "corpus.json"
    output_markdown = tmp_path / "out" / "CORPUS.md"

    assert (
        corpus.main(
            [
                "--run",
                str(run),
                "--expected-family",
                "valleyrat",
                "--output-json",
                str(output_json),
                "--output-markdown",
                str(output_markdown),
            ]
        )
        == 0
    )
    first_json = output_json.read_bytes()
    first_markdown = output_markdown.read_bytes()
    assert (
        corpus.main(
            [
                "--run",
                str(run),
                "--expected-family",
                "valleyrat",
                "--output-json",
                str(output_json),
                "--output-markdown",
                str(output_markdown),
            ]
        )
        == 0
    )

    assert output_json.read_bytes() == first_json
    assert output_markdown.read_bytes() == first_markdown
    markdown = output_markdown.read_text(encoding="utf-8")
    assert "母数" in markdown
    assert "検体本体の読込み・実行: なし" in markdown
    assert "TOP-SECRET-SOURCE.exe" not in markdown


def test_run_limits_and_summary_contract_fail_closed(tmp_path: Path) -> None:
    run = tmp_path / "run"
    _write_run_summary(run, [])
    with pytest.raises(corpus.CorpusSummaryError, match="1件以上"):
        corpus.summarize_runs([])
    with pytest.raises(corpus.CorpusSummaryError, match="64件以下"):
        corpus.summarize_runs([run] * 65)

    summary_path = run / "summary.json"
    value = json.loads(summary_path.read_text(encoding="utf-8"))
    value["counts"]["input_files"] = 1
    _write_json(summary_path, value)
    with pytest.raises(corpus.CorpusSummaryError, match="母数"):
        corpus.summarize_runs([run])


def test_expected_family_requires_independent_lowercase_identifier(tmp_path: Path) -> None:
    run = tmp_path / "run"
    _write_case(run, SHA_A)
    _write_run_summary(run, [SHA_A])

    without_expectation = corpus.summarize_runs([run])
    assert without_expectation["rates"]["expected_family_resolution"]["status"] == "not_available"
    with pytest.raises(corpus.CorpusSummaryError, match="expected family"):
        corpus.summarize_runs([run], expected_family="ValleyRAT")


def test_output_may_not_overwrite_input_or_enter_case_tree(tmp_path: Path) -> None:
    run = tmp_path / "run"
    _write_case(run, SHA_A)
    _write_run_summary(run, [SHA_A])

    with pytest.raises(corpus.CorpusSummaryError, match="上書き"):
        corpus.main(
            [
                "--run",
                str(run),
                "--output-json",
                str(run / "summary.json"),
            ]
        )
    with pytest.raises(corpus.CorpusSummaryError, match="case tree"):
        corpus.main(
            [
                "--run",
                str(run),
                "--output-json",
                str(run / "cases" / "corpus.json"),
            ]
        )


def test_cli_help_is_japanese() -> None:
    rendered = corpus.build_parser().format_help()
    assert "使用法:" in rendered
    assert "オプション:" in rendered
    assert "このヘルプを表示して終了します" in rendered
    assert "show this help message" not in rendered


def test_report_semantic_tampering_is_not_trusted(tmp_path: Path) -> None:
    run = tmp_path / "run"
    _write_case(run, SHA_A)
    report_path = run / "cases" / SHA_A / "report.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["classification"] = copy.deepcopy(report["classification"])
    report["classification"]["selected_families"] = ["agenttesla"]
    _write_json(report_path, report)
    _write_run_summary(run, [SHA_A])

    summary = corpus.summarize_runs([run])

    assert summary["counts"]["unique_valid_cases"] == 0
    assert summary["invalid_cases"][0]["reason_codes"] == ["integrity:report_semantics_invalid"]


def test_legacy_gap_artifacts_use_explicit_unknown_denominators(
    tmp_path: Path,
) -> None:
    run = tmp_path / "run"
    _write_case(run, SHA_A)
    _write_run_summary(run, [SHA_A])

    summary = corpus.summarize_runs([run])

    availability = summary["automation_gaps"]["availability"]
    for axis in (
        "detector_and_profiles",
        "candidate_attempt_accounting",
        "route_reason_accounting",
        "static_layer_limits",
    ):
        assert availability[axis]["status"] == "not_available"
        assert availability[axis]["known_case_denominator"] == 0
        assert availability[axis]["unknown_case_count"] == 1
    assert summary["automation_gaps"]["gap_status_case_counts"] == {"unknown_legacy_schema": 1}
    assert summary["cases"][0]["automation_gap"]["status"] == "unknown_legacy_schema"


def test_gap_aggregate_counts_attempts_profiles_rejections_and_limits(
    tmp_path: Path,
) -> None:
    run = tmp_path / "run"
    _write_case(
        run,
        SHA_A,
        config_recovered=False,
        automation_status="partial",
        case_status="partial",
        blockers=["config"],
    )
    case_dir = run / "cases" / SHA_A
    candidate = json.loads((case_dir / "candidate-handler-assessment.json").read_text(encoding="utf-8"))
    first_handler = "valleyrat:extractors.valleyrat.extractor.py:extract"
    second_handler = "valleyrat:analysis.framework.malware.valleyrat.campaigns.signed.proxy.sideload.analyze.py:analyze"
    candidate.update(
        {
            "status": "partial",
            "planned_attempt_count": 4,
            "actual_attempt_count": 3,
            "retained_attempt_detail_count": 3,
            "omitted_attempt_detail_count": 0,
            "unattempted_attempt_count": 1,
            "blockers": ["maximum_attempts_exhausted"],
            "budget": {"exhausted": True},
            "excluded_layers": [
                {"reason": "candidate_layer_size_limit"},
                {"reason": "candidate_layer_size_limit"},
            ],
            "families": [
                {
                    "status": "partial_budget_exhausted",
                    "attempts": [
                        {"handler_id": first_handler, "status": "no_evidence"},
                        {"handler_id": first_handler, "status": "failed"},
                        {
                            "handler_id": second_handler,
                            "status": "handler_evidence_without_detector",
                        },
                    ],
                }
            ],
        }
    )
    route = json.loads((case_dir / "route-config-candidates.json").read_text(encoding="utf-8"))
    route.update(
        {
            "status": "assessment_incomplete_no_route_config_candidate",
            "projection_disposition": "rejected",
            "projection_reason": "route_attempt_projection_rejected",
            "planned_handler_attempt_count": 4,
            "actual_handler_attempt_count": 3,
            "unattempted_handler_attempt_count": 1,
            "omitted_handler_attempt_detail_count": 0,
            "evaluated_route_attempt_count": 1,
            "observed_excluded_route_attempt_count": 2,
            "rejected_route_attempt_count": 1,
            "assessment_rejection_reasons": [],
            "assessment_exclusion_reason_counts": {
                "assessment_budget_exhausted": 1,
                "assessment_blocker_maximum_attempts_exhausted": 1,
                "excluded_layer_candidate_layer_size_limit": 2,
                "unattempted_handler_attempts": 1,
            },
            "route_attempt_exclusion_reason_counts": {
                "attempt_status_failed": 1,
                "attempt_status_no_evidence": 1,
            },
            "route_attempt_rejection_reason_counts": {"trusted_handler_lineage_invalid": 1},
        }
    )
    _replace_case_artifacts(
        run,
        SHA_A,
        candidate__handler__assessment_json=candidate,
        route__config__candidates_json=route,
        classification_json=_classification_document(
            SHA_A,
            [
                {
                    "matched": True,
                    "loader_profile": "d3dserver_debug_attribute_loader",
                },
                {"matched": True, "route_profile": "cef_proxy"},
            ],
        ),
        static__layers_json=_static_layers_document("layer_count_limit"),
    )
    _write_run_summary(run, [SHA_A])

    summary = corpus.summarize_runs([run])
    gaps = summary["automation_gaps"]

    assert gaps["candidate_attempt_status_counts"] == {
        "failed": 1,
        "handler_evidence_without_detector": 1,
        "no_evidence": 1,
    }
    assert gaps["candidate_handler_attempt_status_counts"][first_handler] == {
        "failed": 1,
        "no_evidence": 1,
    }
    assert gaps["loader_profile_case_counts"] == {"d3dserver_debug_attribute_loader": 1}
    assert gaps["route_profile_case_counts"] == {"cef_proxy": 1}
    assert gaps["route_rejection_reasons"]["attempt_rejection_reason_counts"] == {"trusted_handler_lineage_invalid": 1}
    assert gaps["budget_limit_reason_counts"] == {
        "candidate_budget:maximum_attempts_exhausted": 1,
        "candidate_layer:candidate_layer_size_limit": 2,
        "static_layer:layer_count_limit": 1,
    }
    assert gaps["availability"]["candidate_attempt_accounting"]["known_case_denominator"] == 1
    assert gaps["availability"]["route_reason_accounting"]["known_case_denominator"] == 1
    assert summary["cases"][0]["automation_gap"]["status"] == "loader_only"
    markdown = corpus.render_markdown(summary)
    for expected in (
        "## ValleyRAT自動化gap",
        "d3dserver_debug_attribute_loader",
        "cef_proxy",
        "trusted_handler_lineage_invalid",
        "candidate_budget:maximum_attempts_exhausted",
    ):
        assert expected in markdown


def test_partial_result_quota_status_remains_visible_in_candidate_summary() -> None:
    """worker-local quotaのfamily/attempt状態を未知codeへ畳み込まない。"""

    summarized = corpus._candidate_attempt_summary(
        {
            "status": "partial",
            "planned_attempt_count": 1,
            "actual_attempt_count": 1,
            "retained_attempt_detail_count": 1,
            "omitted_attempt_detail_count": 0,
            "unattempted_attempt_count": 0,
            "blockers": [],
            "budget": {"exhausted": False},
            "excluded_layers": [],
            "families": [
                {
                    "status": "partial_result_quota_exhausted",
                    "attempts": [
                        {
                            "handler_id": ("valleyrat:extractors.valleyrat.extractor.py:extract"),
                            "status": "partial_result_quota_exhausted",
                        }
                    ],
                }
            ],
        }
    )

    assert summarized["availability"]["attempt_accounting"] == "available"
    assert summarized["family_status_counts"] == {"partial_result_quota_exhausted": 1}
    assert summarized["attempt_status_counts"] == {"partial_result_quota_exhausted": 1}
    assert summarized["budget_exhausted"] is False
    assert summarized["budget_reason_counts"] == {}


def test_route_reason_accounting_requires_complete_attempt_partition(
    tmp_path: Path,
) -> None:
    """actual試行は評価・除外・省略のいずれかへ過不足なく属する必要がある。"""

    run = tmp_path / "run"
    _write_case(run, SHA_A)
    case_dir = run / "cases" / SHA_A
    route_path = case_dir / "route-config-candidates.json"
    route = json.loads(route_path.read_text(encoding="utf-8"))
    route.update(
        {
            "planned_handler_attempt_count": 0,
            "actual_handler_attempt_count": 0,
            "unattempted_handler_attempt_count": 0,
            "omitted_handler_attempt_detail_count": 0,
            "evaluated_route_attempt_count": 0,
            "observed_excluded_route_attempt_count": 0,
            "rejected_route_attempt_count": 0,
            "assessment_rejection_reasons": [],
            "assessment_exclusion_reason_counts": {
                "no_planned_handler_attempts": 1,
                "no_routing_candidates": 1,
            },
            "route_attempt_exclusion_reason_counts": {},
            "route_attempt_rejection_reason_counts": {},
        }
    )
    _replace_case_artifacts(
        run,
        SHA_A,
        route__config__candidates_json=route,
    )
    _write_run_summary(run, [SHA_A])

    valid = corpus.summarize_runs([run])
    valid_availability = valid["cases"][0]["automation_gap"]["route_projection"]["availability"]["reason_accounting"]
    assert valid_availability == "available"

    route["planned_handler_attempt_count"] = 1
    route["actual_handler_attempt_count"] = 1
    route["assessment_exclusion_reason_counts"] = {}
    _replace_case_artifacts(
        run,
        SHA_A,
        route__config__candidates_json=route,
    )

    inconsistent = corpus.summarize_runs([run])
    inconsistent_route = inconsistent["cases"][0]["automation_gap"]["route_projection"]
    assert inconsistent_route["availability"]["reason_accounting"] == ("unknown_invalid_schema")
    aggregate_availability = inconsistent["automation_gaps"]["availability"]["route_reason_accounting"]
    assert aggregate_availability["known_case_denominator"] == 0
    assert aggregate_availability["unknown_case_count"] == 1
    assert aggregate_availability["unknown_reason_case_counts"] == {"unknown_invalid_schema": 1}


def test_detector_unmatched_loader_and_unknown_states_are_separate(
    tmp_path: Path,
) -> None:
    run = tmp_path / "run"
    specifications = {
        SHA_A: [{"matched": False}],
        SHA_B: [{"matched": False}, None],
        SHA_C: [{"error": "PRIVATE-DETECTOR-ERROR"}],
        SHA_D: [
            {
                "matched": True,
                "loader_profile": "mingw_resource_stage_dropper",
            }
        ],
    }
    for digest, layer_specs in specifications.items():
        _write_case(run, digest)
        _replace_case_artifacts(
            run,
            digest,
            classification_json=_classification_document(digest, layer_specs),
        )
    _write_run_summary(run, list(specifications))

    summary = corpus.summarize_runs([run])

    assert summary["automation_gaps"]["gap_status_case_counts"] == {
        "detector_unmatched": 1,
        "loader_only": 1,
        "unknown_detector_error": 1,
        "unknown_incomplete_evaluations": 1,
    }
    availability = summary["automation_gaps"]["availability"]["detector_and_profiles"]
    assert availability["known_case_denominator"] == 2
    assert availability["unknown_case_count"] == 2
    assert availability["unknown_reason_case_counts"] == {
        "unknown_detector_error": 1,
        "unknown_incomplete_evaluations": 1,
    }
    assert summary["automation_gaps"]["loader_profile_case_counts"] == {"mingw_resource_stage_dropper": 1}
    assert "PRIVATE-DETECTOR-ERROR" not in json.dumps(summary, ensure_ascii=False)


def test_syntactically_safe_secret_codes_and_profiles_are_not_reflected(
    tmp_path: Path,
) -> None:
    run = tmp_path / "run"
    secret = "syntactically_safe_secret"
    _write_case(
        run,
        SHA_A,
        family=secret,
        blockers=[secret],
        candidate_status=secret,
        route_status=secret,
        projection_reason=secret,
    )
    case_dir = run / "cases" / SHA_A
    candidate = json.loads((case_dir / "candidate-handler-assessment.json").read_text(encoding="utf-8"))
    candidate.update(
        {
            "planned_attempt_count": 1,
            "actual_attempt_count": 1,
            "retained_attempt_detail_count": 1,
            "omitted_attempt_detail_count": 0,
            "unattempted_attempt_count": 0,
            "blockers": [secret],
            "budget": {"exhausted": False},
            "excluded_layers": [{"reason": secret}],
            "families": [
                {
                    "status": secret,
                    "attempts": [{"handler_id": secret, "status": secret}],
                }
            ],
        }
    )
    route = json.loads((case_dir / "route-config-candidates.json").read_text(encoding="utf-8"))
    route.update(
        {
            "projection_disposition": secret,
            "planned_handler_attempt_count": 1,
            "actual_handler_attempt_count": 1,
            "unattempted_handler_attempt_count": 0,
            "omitted_handler_attempt_detail_count": 0,
            "evaluated_route_attempt_count": 1,
            "observed_excluded_route_attempt_count": 0,
            "rejected_route_attempt_count": 1,
            "assessment_rejection_reasons": [secret],
            "assessment_exclusion_reason_counts": {secret: 1},
            "route_attempt_exclusion_reason_counts": {secret: 1},
            "route_attempt_rejection_reason_counts": {secret: 1},
        }
    )
    _replace_case_artifacts(
        run,
        SHA_A,
        candidate__handler__assessment_json=candidate,
        route__config__candidates_json=route,
        classification_json=_classification_document(
            SHA_A,
            [{"matched": True, "loader_profile": secret, "route_profile": secret}],
        ),
        static__layers_json=_static_layers_document(secret),
    )
    _write_run_summary(run, [SHA_A])

    summary = corpus.summarize_runs([run])
    serialized = json.dumps(summary, ensure_ascii=False)
    markdown = corpus.render_markdown(summary)

    assert secret not in serialized
    assert secret not in markdown
    assert "PRIVATE-LAYER-NAME.exe" not in serialized
    assert "PRIVATE-LAYER-NAME.exe" not in markdown
    assert "PRIVATE-CLASSIFICATION-SOURCE.exe" not in serialized
    assert "PRIVATE-CLASSIFICATION-SOURCE.exe" not in markdown
    assert "unrecognized_code" in serialized
    assert "unrecognized_handler" in serialized
    assert corpus.UNRECOGNIZED_FAMILY in serialized
    family = summary["cases"][0]["family"]
    assert family["selected_families"] == [corpus.UNRECOGNIZED_FAMILY]
    assert family["resolved_family"] == corpus.UNRECOGNIZED_FAMILY
    assert family["unrecognized_selected_family_count"] == 1
    assert family["resolved_family_publication_status"] == ("redacted_unregistered")
    assert summary["safety"]["unregistered_family_values_included"] is False


def test_registered_and_explicit_expected_families_remain_publishable(
    tmp_path: Path,
) -> None:
    """registry既知familyとoperator明示expected familyは意味を失わず保持する。"""

    registered_run = tmp_path / "registered"
    _write_case(registered_run, SHA_A, family="agenttesla")
    _write_run_summary(registered_run, [SHA_A])
    registered = corpus.summarize_runs([registered_run])
    registered_family = registered["cases"][0]["family"]
    assert registered_family["resolved_family"] == "agenttesla"
    assert registered_family["resolved_family_publication_status"] == "registered"

    expected_run = tmp_path / "expected"
    expected_family = "operator_reviewed_family"
    _write_case(expected_run, SHA_B, family=expected_family)
    _write_run_summary(expected_run, [SHA_B])
    expected = corpus.summarize_runs(
        [expected_run],
        expected_family=expected_family,
    )
    expected_record = expected["cases"][0]["family"]
    assert expected_record["resolved_family"] == expected_family
    assert expected_record["matches_expected"] is True
    assert expected_record["resolved_family_publication_status"] == ("explicit_expected_family")


def test_optional_gap_artifact_hash_mismatch_is_excluded(tmp_path: Path) -> None:
    run = tmp_path / "run"
    _write_case(run, SHA_A)
    _replace_case_artifacts(
        run,
        SHA_A,
        classification_json=_classification_document(
            SHA_A,
            [{"matched": False}],
        ),
    )
    classification_path = run / "cases" / SHA_A / "classification.json"
    value = json.loads(classification_path.read_text(encoding="utf-8"))
    value["layer_classifications"].append(value["layer_classifications"][0])
    _write_json(classification_path, value)
    _write_run_summary(run, [SHA_A])

    summary = corpus.summarize_runs([run])

    assert summary["counts"]["unique_valid_cases"] == 0
    assert summary["invalid_cases"][0]["reason_codes"] == ["integrity:artifact_hash_mismatch_classification_json"]
