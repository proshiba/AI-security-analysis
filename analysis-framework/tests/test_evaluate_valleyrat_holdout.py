"""ValleyRATオフラインholdout評価の分割・成功条件・非公開境界を検証する。"""

from __future__ import annotations

import copy
import hashlib
import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
COMMON = ROOT / "analysis-framework" / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import analysis_contract  # noqa: E402
import evaluate_valleyrat_holdout as holdout  # noqa: E402


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _evidence(
    label: str,
    *,
    digest: str | None = None,
    exact_axes: tuple[tuple[str, str], ...] = (),
    logic_tokens: tuple[str, ...] = (),
    profile_axes: tuple[str, ...] = (),
    successful: bool = True,
) -> holdout._CaseEvidence:
    return holdout._CaseEvidence(
        digest=digest or _digest(label),
        exact_axes=exact_axes,
        logic_fingerprints=frozenset(
            f"semantic:{_digest(token)}" for token in logic_tokens
        ),
        profile_axes=frozenset(profile_axes),
        family_confirmed=successful,
        family_failure_reason=None if successful else "family_not_resolved",
        c2_config_confirmed=successful,
        c2_failure_reason=None if successful else "confirmed_config_missing",
    )


def _public_corpus_summary(case_count: int) -> dict[str, object]:
    return {
        "scope": {"run_count": 1},
        "counts": {
            "input_units": case_count,
            "unique_valid_cases": case_count,
            "batch_errors": 0,
            "invalid_unique_cases": 0,
            "conflicting_case_sha256": 0,
        },
    }


def _registration(
    reference_cases: list[holdout._CaseEvidence],
    holdout_cases: list[holdout._CaseEvidence],
) -> dict[str, object]:
    return holdout.build_pre_registration(
        [case.digest for case in reference_cases],
        [case.digest for case in holdout_cases],
    )


def _write_json(path: Path, value: object) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True)
        + "\n"
    )
    path.write_text(payload, encoding="utf-8", newline="\n")
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _classification_document(digest: str, profile: str) -> dict[str, object]:
    return {
        "sample": "PRIVATE-CLASSIFICATION-SOURCE.exe",
        "layer_classifications": [
            {
                "layer": {
                    "sha256": _digest(f"{digest}:layer"),
                    "size": 1,
                    "format": "pe",
                    "parent_sha256": None,
                    "depth": 0,
                    "transform": "fixture",
                    "name": "PRIVATE-LAYER-NAME.exe",
                },
                "classification": {
                    "detector_evaluations": [
                        {
                            "malware_type": "valleyrat",
                            "detector_matched": True,
                            "automatic_route_eligible": True,
                            "known_outer_sha256": False,
                            "known_inner_sha256": False,
                            "known_routing_sha256": False,
                            "error": None,
                            "detection": {
                                "matched": True,
                                "observations": {
                                    "validated_static_loader_profile": {
                                        "status": "validated_static_loader_component",
                                        "profile": profile,
                                    }
                                },
                                "campaigns": [
                                    {"terminal_family_confirmed": False}
                                ],
                            },
                        }
                    ]
                },
            }
        ],
    }


def _source_strength(source: str) -> int:
    return {
        "known_hash": 4,
        "detector_selected": 3,
        "detector_candidate": 2,
        "external_metadata": 1,
    }.get(source, 0)


def _resolution(
    *,
    family: str | None,
    source: str,
    status: str = "resolved",
) -> dict[str, object]:
    if status != "resolved":
        return {
            "status": status,
            "family": None,
            "reason": "no_candidate_met_evidence_threshold",
            "candidates": [],
        }
    strength = _source_strength(source)
    tier = {
        "known_hash": 0,
        "detector_selected": 1,
        "detector_candidate": 2,
        "external_metadata": 4,
    }.get(source, 0)
    candidate = {
        "family": family,
        "source": source,
        "source_strength": strength,
        "routing_eligible": True,
        "attribution_eligible": source in {"known_hash", "detector_selected"},
        "metadata_only": source == "external_metadata",
        "layer_sha256": [_digest("PRIVATE-LAYER")],
        "confidence": "medium",
        "evidence_summary": {
            "known_hash": int(source == "known_hash"),
            "detector": int(source.startswith("detector_")),
            "external_metadata": int(source == "external_metadata"),
        },
        "requirements": {
            "config_required": True,
            "network_required": True,
        },
        "input_order": 0,
        "required_handler_tier": tier,
        "handler_tier": tier,
        "handler_score": tier,
        "handler_id": "valleyrat:fixture",
        "handler_corroborated": source in {
            "detector_candidate",
            "external_metadata",
        },
        "qualified": True,
        "rank": [strength, tier, tier],
    }
    return {
        "status": "resolved",
        "family": family,
        "reason": "unique_strongest_corroborated_candidate",
        "source": source,
        "source_strength": strength,
        "handler_tier": tier,
        "handler_id": "valleyrat:fixture",
        "requirements": {
            "config_required": True,
            "network_required": True,
        },
        "candidates": [candidate],
    }


def _write_case(
    run: Path,
    digest: str,
    *,
    family: str | None = "valleyrat",
    family_source: str = "detector_selected",
    family_status: str = "resolved",
    config_confirmed: bool = True,
    c2_record: bool = True,
    c2_basis: tuple[str, ...] = ("static_config_correlation",),
    imphash: str | None = None,
    logic_tokens: tuple[str, ...] = ("default-a", "default-b"),
    profile: str | None = None,
) -> None:
    case_dir = run / "cases" / digest
    case_dir.mkdir(parents=True, exist_ok=True)
    resolution = _resolution(
        family=family,
        source=family_source,
        status=family_status,
    )
    qualified = []
    if c2_record:
        qualified.append(
            {
                "host": "198.51.100.77",
                "port": 443,
                "scheme": "tcp",
                "path": None,
                "role": "c2",
                "protocol": "tcp",
                "contacted": False,
                "evidence_basis": list(c2_basis),
                "provenance": [
                    {
                        "family": "valleyrat",
                        "handler_id": "valleyrat:fixture",
                        "source": "selected_family_analysis",
                        "evidence_path": "PRIVATE.CONFIG.C2",
                    }
                ],
            }
        )
    orchestration = {
        "schema_version": 2,
        "sample_sha256": digest,
        "status": "complete" if family_status == "resolved" else "triaged_unknown",
        "family_resolution": resolution,
        "outputs": {
            "config_recovered": config_confirmed,
            "config_evidence": (
                [
                    {
                        "recovery_type": "static_config_recovered",
                        "correlated_keys": ["c2", "PRIVATE-RAW-CONFIG"],
                        "provenance": {
                            "family": "valleyrat",
                            "handler_id": "valleyrat:fixture",
                            "source": "selected_family_analysis",
                            "evidence_path": "C:\\PRIVATE\\CONFIG",
                        },
                    }
                ]
                if config_confirmed
                else []
            ),
            "qualified_network_endpoints": qualified,
        },
        "candidate_outputs": {
            "config_candidate_recovered": False,
            "config_candidate_evidence": [],
        },
        "quality_gates": {
            "config": {
                "required": True,
                "satisfied": config_confirmed,
                "status": "satisfied" if config_confirmed else "required_missing",
            }
        },
        "blockers": [] if config_confirmed else ["config"],
        "automation": {
            "sample_executed": False,
            "network_contacted": False,
            "ai_used": False,
        },
    }
    candidate = {
        "schema_version": 1,
        "status": "no_candidates",
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
        "status": "assessment_rejected",
        "status_scope": "route_candidate_projection_only",
        "projection_disposition": "not_applicable",
        "projection_reason": "no_candidate_verification_routes",
        "overall_analysis_result_affected": False,
        "route_config_candidate_recovered": False,
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
        "functions": [
            {
                "role": f"role_{index}",
                "fingerprints": {
                    "semantic_sequence_sha256": _digest(token),
                    "semantic_token_count": 12,
                },
            }
            for index, token in enumerate(logic_tokens)
        ],
    }
    generic: dict[str, object] = {
        "schema_version": 1,
        "sha256": digest,
        "type": "pe",
        "executed_sample": False,
        "network_contacted": False,
    }
    if imphash is not None:
        generic["pe"] = {"imphash": imphash}
    documents: dict[str, object] = {
        "orchestration.json": orchestration,
        "candidate-handler-assessment.json": candidate,
        "route-config-candidates.json": route,
        "static-logic.json": static_logic,
        "generic-triage.json": generic,
    }
    if profile is not None:
        documents["classification.json"] = _classification_document(
            digest,
            profile,
        )
    artifact_hashes = {
        name: _write_json(case_dir / name, document)
        for name, document in documents.items()
    }
    selected = [family] if family is not None else []
    report = {
        "schema_version": 1,
        "sample": {
            "sha256": digest,
            "source_name": "TOP-SECRET-SOURCE.exe",
            "input_kind": "file",
        },
        "classification": {
            "family": family,
            "selected_family": family,
            "selected_families": selected,
            "automation_status": family_status,
            "automation_family": family if family_status == "resolved" else None,
        },
        "generic_triage": "complete",
        "analysis_contract": {
            "schema_version": 1,
            "sha256": "f" * 64,
        },
        "handler_executions": [],
        "assessment_only": False,
        "executed_sample": False,
        "network_contacted": False,
        "ai_used": False,
        "case_state": {
            "status": "complete" if config_confirmed else "partial",
            "complete": config_confirmed,
            "resumable": True,
            "blockers": [] if config_confirmed else ["config"],
        },
        "artifact_sha256": artifact_hashes,
    }
    analysis_contract.seal_report(report)
    _write_json(case_dir / "report.json", report)


def _write_summary(run: Path, digests: list[str]) -> None:
    _write_json(
        run / "summary.json",
        {
            "schema_version": 1,
            "counts": {
                "input_files": len(digests),
                "analyzed": len(digests),
                "duplicates": 0,
                "errors": 0,
            },
            "cases": [
                {
                    "sha256": digest,
                    "report": f"cases/{digest}/report.json",
                }
                for digest in digests
            ],
            "derived_cases": [],
            "duplicates": [],
            "errors": [],
            "executed_sample": False,
            "network_contacted": False,
            "ai_used": False,
        },
    )


def test_success_contract_rejects_identity_hint_and_uncorrelated_c2(
    tmp_path: Path,
) -> None:
    run = tmp_path / "sealed-run"
    digests = [_digest(f"success-contract-{index}") for index in range(4)]
    _write_case(run, digests[0])
    _write_case(run, digests[1], family_source="known_hash")
    _write_case(run, digests[2], family_source="external_metadata")
    _write_case(
        run,
        digests[3],
        c2_basis=("reviewed_protocol_evidence",),
    )
    _write_summary(run, digests)

    cases, _summary = holdout._collect_case_evidence([run])
    by_digest = {case.digest: case for case in cases}

    assert by_digest[digests[0]].family_confirmed is True
    assert by_digest[digests[0]].c2_config_confirmed is True
    assert by_digest[digests[1]].family_failure_reason == (
        "family_sample_identity_only_disallowed"
    )
    assert by_digest[digests[2]].family_failure_reason == (
        "family_external_hint_disallowed"
    )
    assert by_digest[digests[3]].family_confirmed is True
    assert by_digest[digests[3]].c2_failure_reason == (
        "c2_config_correlation_missing"
    )


def test_candidate_without_independent_handler_corroboration_is_not_success() -> None:
    resolution = _resolution(
        family="valleyrat",
        source="detector_candidate",
    )
    resolution["candidates"][0]["handler_corroborated"] = False

    assert holdout._family_failure_reason(resolution) == (
        "family_resolution_contract_incomplete"
    )


def test_detector_family_ignores_external_metadata_that_is_not_the_winning_source() -> None:
    """独立detectorで確定したwinnerは外部metadataの併記へ依存しない。"""

    resolution = _resolution(
        family="valleyrat",
        source="detector_selected",
    )
    resolution["candidates"][0]["evidence_summary"]["external_metadata"] = 1

    assert holdout._family_failure_reason(resolution) is None

    external_candidate = copy.deepcopy(resolution["candidates"][0])
    resolution["candidates"][0]["evidence_summary"]["external_metadata"] = 0
    external_candidate["family"] = "other-family"
    external_candidate["evidence_summary"]["detector"] = 0
    external_candidate["evidence_summary"]["external_metadata"] = 1
    resolution["candidates"].append(external_candidate)

    assert holdout._family_failure_reason(resolution) is None

    known_hash_candidate = copy.deepcopy(external_candidate)
    known_hash_candidate["source"] = "known_hash"
    known_hash_candidate["evidence_summary"]["external_metadata"] = 0
    known_hash_candidate["evidence_summary"]["known_hash"] = 1
    resolution["candidates"].append(known_hash_candidate)

    assert holdout._family_failure_reason(resolution) is None


def test_detector_family_rejects_known_hash_in_winning_evidence() -> None:
    """既知hashがwinnerの根拠へ混在する場合は厳格成功へ数えない。"""

    resolution = _resolution(
        family="valleyrat",
        source="detector_selected",
    )
    resolution["candidates"][0]["evidence_summary"]["known_hash"] = 1

    assert holdout._family_failure_reason(resolution) == (
        "family_resolution_contract_incomplete"
    )


def test_candidate_only_config_is_not_c2_success() -> None:
    orchestration = {
        "outputs": {
            "config_recovered": False,
            "config_evidence": [],
            "qualified_network_endpoints": [],
        },
        "candidate_outputs": {
            "config_candidate_recovered": True,
            "config_candidate_evidence": [
                {"recovery_type": "route_config_candidate"}
            ],
        },
        "quality_gates": {
            "config": {
                "satisfied": False,
                "status": "required_missing",
            }
        },
    }

    assert holdout._c2_failure_reason(orchestration) == (
        "confirmed_config_missing"
    )


def _strict_c2_fixture(
    *,
    recovery_type: str = "static_config_recovered",
    config_handler: str = "valleyrat:config",
    endpoint_handler: str = "valleyrat:config",
    endpoint_family: str = "valleyrat",
) -> dict[str, object]:
    return {
        "outputs": {
            "config_recovered": True,
            "config_evidence": [
                {
                    "recovery_type": recovery_type,
                    "correlated_keys": ["c2"],
                    "provenance": {
                        "family": "valleyrat",
                        "handler_id": config_handler,
                        "source": "selected_family_analysis",
                        "evidence_path": "config.static_config_recovered",
                    },
                }
            ],
            "qualified_network_endpoints": [
                {
                    "role": "c2",
                    "contacted": False,
                    "evidence_basis": ["static_config_correlation"],
                    "provenance": [
                        {
                            "family": endpoint_family,
                            "handler_id": endpoint_handler,
                            "source": "selected_family_analysis",
                            "evidence_path": "config.c2",
                        }
                    ],
                }
            ],
        },
        "quality_gates": {
            "config": {
                "satisfied": True,
                "status": "satisfied",
            }
        },
    }


def test_config_candidate_labeled_as_confirmed_is_not_c2_success() -> None:
    """boolean自己申告がtrueでもroute候補型をstatic config確定へ昇格しない。"""

    orchestration = _strict_c2_fixture(recovery_type="route_config_candidate")

    assert holdout._c2_failure_reason(orchestration) == (
        "confirmed_config_evidence_missing"
    )


@pytest.mark.parametrize(
    ("endpoint_handler", "endpoint_family"),
    [
        ("valleyrat:network", "valleyrat"),
        ("valleyrat:config", "unrelated-family"),
    ],
)
def test_config_and_network_require_same_static_handler_lineage(
    endpoint_handler: str,
    endpoint_family: str,
) -> None:
    """別handlerまたは別family由来のnetwork自己申告を同時成功へ数えない。"""

    orchestration = _strict_c2_fixture(
        endpoint_handler=endpoint_handler,
        endpoint_family=endpoint_family,
    )

    assert holdout._c2_failure_reason(orchestration) == (
        "c2_config_correlation_missing"
    )


def test_static_config_and_network_with_same_lineage_remain_successful() -> None:
    """正規の同一handler静的lineageは従来どおりC2設定確定となる。"""

    assert holdout._c2_failure_reason(_strict_c2_fixture()) is None


def test_split_is_deterministic_and_keeps_exact_and_near_groups_together(
    tmp_path: Path,
) -> None:
    run = tmp_path / "sealed-run"
    digests = [_digest(f"split-{index}") for index in range(8)]
    shared_imphash = "1" * 32
    _write_case(
        run,
        digests[0],
        imphash=shared_imphash,
        logic_tokens=("exact-a", "exact-b"),
    )
    _write_case(
        run,
        digests[1],
        imphash=shared_imphash,
        logic_tokens=("exact-c", "exact-d"),
    )
    near_base = ("near-1", "near-2", "near-3", "near-4")
    _write_case(
        run,
        digests[2],
        logic_tokens=near_base,
        profile="mingw_resource_stage_dropper",
    )
    _write_case(
        run,
        digests[3],
        logic_tokens=(*near_base, "near-5"),
        profile="mingw_resource_stage_dropper",
    )
    for index, digest in enumerate(digests[4:], start=4):
        _write_case(
            run,
            digest,
            logic_tokens=(f"single-{index}-a", f"single-{index}-b"),
        )
    _write_summary(run, digests)

    first = holdout.evaluate_runs([run], holdout_count=3)
    cases, _summary = holdout._collect_case_evidence([run])
    clusters = holdout._cluster_cases(cases)
    selected, _partition = holdout._partition_cases(cases, clusters, 3)
    indexes = {case.digest: index for index, case in enumerate(cases)}

    assert (indexes[digests[0]] in selected) == (indexes[digests[1]] in selected)
    assert (indexes[digests[2]] in selected) == (indexes[digests[3]] in selected)
    assert first["split"]["actual_holdout_cases"] == 3
    assert first["split"]["exact_group_count"] == 1
    assert first["split"]["near_relationship_count"] == 1
    assert first["split"]["cross_partition_exact_group_count"] == 0
    assert first["split"]["cross_partition_near_relationship_count"] == 0

    _write_summary(run, list(reversed(digests)))
    second = holdout.evaluate_runs([run], holdout_count=3)
    assert second == first


def test_near_relation_requires_logic_and_independent_profile_axes(
    tmp_path: Path,
) -> None:
    run = tmp_path / "sealed-run"
    digests = [_digest(f"two-axis-{index}") for index in range(3)]
    common = ("two-axis-1", "two-axis-2", "two-axis-3", "two-axis-4")
    _write_case(
        run,
        digests[0],
        logic_tokens=common,
        profile="mingw_resource_stage_dropper",
    )
    _write_case(
        run,
        digests[1],
        logic_tokens=(*common, "two-axis-5"),
        profile="bin_hell_resource_dropper",
    )
    _write_case(
        run,
        digests[2],
        logic_tokens=("unrelated-a", "unrelated-b"),
    )
    _write_summary(run, digests)

    cases, _summary = holdout._collect_case_evidence([run])
    assert len(holdout._cluster_cases(cases).near_pairs) == 0

    _write_case(
        run,
        digests[1],
        logic_tokens=(*common, "two-axis-5"),
        profile="mingw_resource_stage_dropper",
    )
    cases, _summary = holdout._collect_case_evidence([run])
    assert len(holdout._cluster_cases(cases).near_pairs) == 1


def test_joint_target_cli_outputs_are_redacted_and_ci_exit_is_enforced(
    tmp_path: Path,
) -> None:
    run = tmp_path / "private" / "sealed-run"
    digests = [_digest(f"target-{index}") for index in range(7)]
    structures = {
        digest: (f"target-{index}-a", f"target-{index}-b")
        for index, digest in enumerate(digests)
    }
    for digest in digests:
        _write_case(
            run,
            digest,
            config_confirmed=False,
            c2_record=False,
            logic_tokens=structures[digest],
        )
    _write_summary(run, digests)

    cases, _summary = holdout._collect_case_evidence([run])
    clusters = holdout._cluster_cases(cases)
    selected, _partition = holdout._partition_cases(cases, clusters, 4)
    selected_digests = [cases[index].digest for index in sorted(selected)]
    for digest in selected_digests[:2]:
        _write_case(
            run,
            digest,
            logic_tokens=structures[digest],
        )
    cases_after, _summary = holdout._collect_case_evidence([run])
    clusters_after = holdout._cluster_cases(cases_after)
    selected_after, _partition = holdout._partition_cases(
        cases_after,
        clusters_after,
        4,
    )
    assert {
        cases_after[index].digest for index in selected_after
    } == set(selected_digests)

    expected = holdout.evaluate_runs(
        [run],
        holdout_count=4,
        minimum_success_percentage=50.0,
    )
    assert expected["metrics"]["joint_success"] == {
        "numerator": 2,
        "denominator": 4,
        "percentage": 50.0,
        "denominator_basis": "holdout_cases",
    }
    assert expected["target_gate"]["status"] == "passed"

    output_json = tmp_path / "ci" / "holdout.json"
    output_markdown = tmp_path / "ci" / "HOLDOUT.md"
    exit_code = holdout.main(
        [
            "--run",
            str(run),
            "--holdout-count",
            "4",
            "--minimum-success-percentage",
            "50",
            "--output-json",
            str(output_json),
            "--output-markdown",
            str(output_markdown),
            "--fail-below-target",
        ]
    )
    assert exit_code == 0
    written = json.loads(output_json.read_text(encoding="utf-8"))
    markdown = output_markdown.read_text(encoding="utf-8")
    assert written == expected
    assert "# ValleyRATオフラインholdout評価" in markdown

    serialized = output_json.read_text(encoding="utf-8") + markdown
    assert re.search(r"[0-9a-f]{64}", serialized) is None
    for secret in (
        "198.51.100.77",
        "TOP-SECRET-SOURCE.exe",
        "PRIVATE-RAW-CONFIG",
        "PRIVATE-LAYER-NAME.exe",
        str(run),
    ):
        assert secret not in serialized

    for digest in selected_digests:
        _write_case(
            run,
            digest,
            config_confirmed=False,
            c2_record=False,
            logic_tokens=structures[digest],
        )
    failed_json = tmp_path / "ci" / "failed.json"
    failed_exit = holdout.main(
        [
            "--run",
            str(run),
            "--holdout-count",
            "4",
            "--output-json",
            str(failed_json),
            "--fail-below-target",
        ]
    )
    assert failed_exit == 1
    assert json.loads(failed_json.read_text(encoding="utf-8"))[
        "target_gate"
    ]["status"] == "failed"


def test_cli_help_is_japanese() -> None:
    help_text = holdout.build_parser().format_help()
    assert "使用法:" in help_text
    assert "オプション:" in help_text
    assert "holdout件数" in help_text
    assert holdout.DEFAULT_HOLDOUT_COUNT == 100
    assert holdout.DEFAULT_MINIMUM_SUCCESS_PERCENTAGE == 50.0


def test_default_structural_split_selects_exactly_100_holdout_cases() -> None:
    cases = [
        holdout._CaseEvidence(
            digest=_digest(f"default-holdout-{index}"),
            exact_axes=(),
            logic_fingerprints=frozenset(),
            profile_axes=frozenset(),
            family_confirmed=True,
            family_failure_reason=None,
            c2_config_confirmed=True,
            c2_failure_reason=None,
        )
        for index in range(101)
    ]
    clusters = holdout._cluster_cases(cases)
    selected, partition = holdout._partition_cases(
        cases,
        clusters,
        holdout.DEFAULT_HOLDOUT_COUNT,
    )

    assert len(selected) == 100
    assert partition["actual_holdout_cases"] == 100
    assert partition["train_cases"] == 1
    assert partition["cross_partition_component_count"] == 0


def test_cli_error_does_not_reflect_private_input_path(
    tmp_path: Path,
    capsys,
) -> None:
    private_path = tmp_path / "VERY-SECRET-CORPUS-NAME"
    exit_code = holdout.main(
        [
            "--run",
            str(private_path),
            "--holdout-count",
            "1",
        ]
    )
    captured = capsys.readouterr()

    assert exit_code == 2
    assert captured.out == ""
    assert str(private_path) not in captured.err
    error = json.loads(captured.err)
    assert error["status"] == "error"
    assert error["error_code"].startswith("sealed_corpus_")


def test_pre_registration_cli_uses_pre_analysis_identity_manifest(
    tmp_path: Path,
    capsys,
) -> None:
    reference_run = tmp_path / "reference"
    reference_identities = [_digest("registration-reference")]
    holdout_identities = [
        _digest(f"registration-holdout-{index}") for index in range(100)
    ]
    _write_summary(reference_run, reference_identities)
    identity_manifest = tmp_path / "private-holdout-identities.json"
    _write_json(
        identity_manifest,
        {
            "schema_version": 1,
            "identity_type": "sha256",
            "identities": holdout_identities,
        },
    )
    output = tmp_path / "private-registration.json"

    exit_code = holdout.main(
        [
            "--reference-run",
            str(reference_run),
            "--holdout-identity-manifest",
            str(identity_manifest),
            "--write-pre-registration",
            str(output),
        ]
    )

    assert exit_code == 0
    assert "事前登録JSONを出力しました" in capsys.readouterr().out
    registration = json.loads(output.read_text(encoding="utf-8"))
    assert registration["target"]["holdout_cases"] == 100
    assert registration["target"]["required_joint_successes"] == 50
    assert registration["selection_contract"][
        "identity_commitment_uses_outcomes"
    ] is False
    assert not (reference_run / "cases").exists()
    serialized = output.read_text(encoding="utf-8")
    assert all(identity not in serialized for identity in holdout_identities)


def test_pre_registration_cli_rejects_post_analysis_holdout_run(
    monkeypatch,
    tmp_path: Path,
    capsys,
) -> None:
    reference_run = tmp_path / "reference"
    holdout_run = tmp_path / "post-analysis-holdout"
    identity_manifest = tmp_path / "private-holdout-identities.json"
    _write_json(
        identity_manifest,
        {
            "schema_version": 1,
            "identity_type": "sha256",
            "identities": [
                _digest(f"registered-before-analysis-{index}")
                for index in range(100)
            ],
        },
    )
    monkeypatch.setattr(
        holdout.corpus,
        "_validate_output_paths",
        lambda *_args: None,
    )

    exit_code = holdout.main(
        [
            "--reference-run",
            str(reference_run),
            "--run",
            str(holdout_run),
            "--holdout-identity-manifest",
            str(identity_manifest),
            "--write-pre-registration",
            str(tmp_path / "registration.json"),
        ]
    )

    assert exit_code == 2
    error = json.loads(capsys.readouterr().err)
    assert error["error_code"] == "pre_registration_run_input_disallowed"
    assert "post-analysis-holdout" not in json.dumps(
        error,
        ensure_ascii=False,
    )


def test_reference_cli_requires_pre_registration(capsys) -> None:
    exit_code = holdout.main(
        [
            "--reference-run",
            "PRIVATE-REFERENCE-ROOT",
            "--run",
            "PRIVATE-HOLDOUT-ROOT",
        ]
    )

    assert exit_code == 2
    error = json.loads(capsys.readouterr().err)
    assert error["error_code"] == "pre_registration_required"
    assert "PRIVATE-" not in json.dumps(error, ensure_ascii=False)


def test_reference_mode_evaluates_all_next_100_as_holdout(
    monkeypatch,
    capsys,
    tmp_path: Path,
) -> None:
    reference_path = Path("PRIVATE-REFERENCE-ROOT")
    holdout_path = Path("PRIVATE-NEXT-100-ROOT")
    reference_cases = [_evidence("reference-only")]
    holdout_cases = [
        _evidence(
            f"next-unknown-{index}",
            successful=index < 50,
        )
        for index in range(100)
    ]
    registration_path = tmp_path / "private-preregistration.json"
    _write_json(
        registration_path,
        _registration(reference_cases, holdout_cases),
    )

    def fake_collect(paths: list[Path]):
        if list(paths) == [reference_path]:
            return reference_cases, _public_corpus_summary(len(reference_cases))
        if list(paths) == [holdout_path]:
            return holdout_cases, _public_corpus_summary(len(holdout_cases))
        raise AssertionError("想定外のrun集合です")

    monkeypatch.setattr(holdout, "_collect_case_evidence", fake_collect)
    monkeypatch.setattr(
        holdout.corpus,
        "_validate_output_paths",
        lambda *_args: None,
    )

    exit_code = holdout.main(
        [
            "--reference-run",
            str(reference_path),
            "--run",
            str(holdout_path),
            "--pre-registration",
            str(registration_path),
            "--fail-below-target",
        ]
    )
    captured = capsys.readouterr()
    summary = json.loads(captured.out)

    assert exit_code == 0
    assert summary["evaluation_mode"] == "offline_sealed_reference_holdout"
    assert summary["split"]["full_holdout_evaluated"] is True
    assert summary["split"]["reference_cases"] == 1
    assert summary["split"]["actual_holdout_cases"] == 100
    assert summary["metrics"]["joint_success"] == {
        "numerator": 50,
        "denominator": 100,
        "percentage": 50.0,
        "denominator_basis": "holdout_cases",
    }
    assert summary["target"]["required_joint_successes"] == 50
    assert summary["pre_registration"]["status"] == "verified"
    assert summary["pre_registration"]["identity_commitments_included"] is False
    assert summary["pre_registration"][
        "temporal_order_proven_by_evaluator"
    ] is False
    assert summary["split"]["known_structure_holdout_cases"] == 0
    assert summary["split"]["new_structure_holdout_cases"] == 100
    assert summary["metrics"]["by_structure"]["new_structure"][
        "joint_success"
    ]["denominator"] == 100
    assert summary["target_gate"]["status"] == "passed"
    assert summary["target_gate"]["reason_codes"] == []
    assert str(reference_path) not in captured.out
    assert str(holdout_path) not in captured.out
    assert all(case.digest not in captured.out for case in holdout_cases)


def test_reference_structural_similarity_is_allowed_and_stratified_without_values() -> None:
    exact_commitment = _digest("PRIVATE-EXACT-COMMITMENT")
    profile = "loader:PRIVATE-VALIDATED-PROFILE"
    shared_logic = ("near-a", "near-b", "near-c", "near-d")
    reference_cases = [
        _evidence(
            "reference-exact",
            exact_axes=(("imphash", exact_commitment),),
        ),
        _evidence(
            "reference-near",
            logic_tokens=shared_logic,
            profile_axes=(profile,),
        ),
    ]
    holdout_cases = [
        _evidence(
            "holdout-exact",
            exact_axes=(("imphash", exact_commitment),),
        ),
        _evidence(
            "holdout-near",
            logic_tokens=(*shared_logic, "near-e"),
            profile_axes=(profile,),
        ),
        *[
            _evidence(
                f"holdout-new-{index}",
                successful=index < 48,
            )
            for index in range(98)
        ],
    ]

    summary = holdout._evaluate_reference_holdout_evidence(
        reference_cases,
        holdout_cases,
        _public_corpus_summary(len(reference_cases)),
        _public_corpus_summary(len(holdout_cases)),
        pre_registration=_registration(reference_cases, holdout_cases),
        expected_holdout_count=100,
        minimum_success_percentage=50.0,
    )

    split = summary["split"]
    assert split["actual_holdout_cases"] == 100
    assert split["cross_partition_identity_case_count"] == 0
    assert split["cross_partition_exact_group_count"] == 1
    assert split["cross_partition_near_relationship_count"] == 1
    assert split["cross_partition_component_count"] == 2
    assert split["known_structure_holdout_cases"] == 2
    assert split["new_structure_holdout_cases"] == 98
    assert summary["metrics"]["joint_success"]["numerator"] == 50
    assert summary["metrics"]["by_structure"]["known_structure"][
        "joint_success"
    ]["numerator"] == 2
    assert summary["metrics"]["by_structure"]["new_structure"][
        "joint_success"
    ] == {
        "numerator": 48,
        "denominator": 98,
        "percentage": 48.98,
        "denominator_basis": "new_structure_holdout_cases",
    }
    assert summary["target_gate"]["status"] == "passed"
    assert summary["target_gate"]["reason_codes"] == []
    assert summary["target_gate"]["reference_holdout_identity_disjoint"] is True
    assert summary["target_gate"]["reference_holdout_structurally_disjoint"] is False
    assert summary["target_gate"]["structural_similarity_allowed"] is True

    published = (
        json.dumps(summary, ensure_ascii=False, sort_keys=True)
        + holdout.render_markdown(summary)
    )
    for secret in (exact_commitment, profile):
        assert secret not in published
    assert "reference／holdout境界監査" in published
    assert "既知構造" in published
    assert "新規構造" in published
    assert "family確定 | C2設定確定 | 同時成功" in published
    assert "事前登録の作成時刻を証明しない" in published


def test_reference_identity_overlap_cannot_be_pre_registered() -> None:
    identity = _digest("PRIVATE-IDENTITY")
    reference_cases = [_evidence("reference-identity", digest=identity)]
    holdout_cases = [
        _evidence("holdout-identity", digest=identity),
        *[
            _evidence(f"holdout-unique-{index}")
            for index in range(99)
        ],
    ]

    with pytest.raises(holdout.HoldoutEvaluationError) as error:
        _registration(reference_cases, holdout_cases)
    assert error.value.code == "holdout_identity_not_new"
    assert identity not in str(error.value)


def test_pre_registration_mismatch_and_non_official_target_fail_closed() -> None:
    reference_cases = [_evidence("reference")]
    registered_holdout = [
        _evidence(f"registered-{index}") for index in range(100)
    ]
    actual_holdout = [
        *registered_holdout[:-1],
        _evidence("unregistered-replacement"),
    ]
    registration = _registration(reference_cases, registered_holdout)

    with pytest.raises(holdout.HoldoutEvaluationError) as mismatch:
        holdout._evaluate_reference_holdout_evidence(
            reference_cases,
            actual_holdout,
            _public_corpus_summary(len(reference_cases)),
            _public_corpus_summary(len(actual_holdout)),
            pre_registration=registration,
            expected_holdout_count=100,
            minimum_success_percentage=50.0,
        )
    assert mismatch.value.code == "pre_registration_commitment_mismatch"

    with pytest.raises(holdout.HoldoutEvaluationError) as target:
        holdout.build_pre_registration(
            [case.digest for case in reference_cases],
            [case.digest for case in registered_holdout],
            expected_holdout_count=99,
            minimum_success_percentage=50.0,
        )
    assert target.value.code == "official_acceptance_target_not_fixed"

    with pytest.raises(holdout.HoldoutEvaluationError) as denominator:
        holdout.build_pre_registration(
            [case.digest for case in reference_cases],
            [case.digest for case in registered_holdout[:-1]],
        )
    assert denominator.value.code == "pre_registration_holdout_count_not_exact"


def test_reference_official_gate_rejects_49_joint_successes() -> None:
    reference_cases = [_evidence("threshold-reference")]
    holdout_cases = [
        _evidence(
            f"threshold-holdout-{index}",
            successful=index < 49,
        )
        for index in range(100)
    ]

    summary = holdout._evaluate_reference_holdout_evidence(
        reference_cases,
        holdout_cases,
        _public_corpus_summary(len(reference_cases)),
        _public_corpus_summary(len(holdout_cases)),
        pre_registration=_registration(reference_cases, holdout_cases),
        expected_holdout_count=100,
        minimum_success_percentage=50.0,
    )

    assert summary["metrics"]["joint_success"]["numerator"] == 49
    assert summary["metrics"]["joint_success"]["denominator"] == 100
    assert summary["target_gate"]["required_joint_successes"] == 50
    assert summary["target_gate"]["status"] == "failed"
    assert summary["target_gate"]["reason_codes"] == [
        "joint_success_target_not_met"
    ]
