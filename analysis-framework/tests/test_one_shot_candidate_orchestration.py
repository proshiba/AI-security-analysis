"""AIを使わないone-shot候補検証と成果物契約を検証する。"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import uuid
from pathlib import Path

FRAMEWORK_ROOT = Path(__file__).resolve().parents[1]
COMMON_ROOT = FRAMEWORK_ROOT / "common"
CLASSIFIERS_ROOT = FRAMEWORK_ROOT / "classifiers"
REPOSITORY_ROOT = FRAMEWORK_ROOT.parent
for trusted in (REPOSITORY_ROOT, FRAMEWORK_ROOT, COMMON_ROOT, CLASSIFIERS_ROOT):
    value = str(trusted)
    if value not in sys.path:
        sys.path.insert(0, value)

import analyze_sample as one_shot

REGISTRY = FRAMEWORK_ROOT / "registry" / "malware_types.json"


def _fixture_classification(family: str) -> dict:
    return {
        "schema_version": 1,
        "malware_type": family,
        "malware_type_confidence": "high",
        "campaign_type": "unknown",
        "attribution_basis": "type_detector_structure",
        "observations": {},
        "campaign_candidates": [],
        "detector_evaluations": [
            {
                "malware_type": family,
                "known_outer_sha256": False,
                "known_inner_sha256": False,
                "detector_matched": True,
                "automatic_route_eligible": True,
                "error": None,
            }
        ],
    }


def _fixture_handler_spec(
    family: str,
    *,
    relative_path: str = "extractors/one_shot_fixture.py",
) -> one_shot.HandlerSpec:
    return one_shot.HandlerSpec(
        id=f"{family}:fixture:extract",
        family=family,
        relative_path=relative_path,
        callable_name="extract",
        invocation="bytes",
        source="fixture",
        automatic=True,
        campaign=None,
        supported_interface=True,
        reason="bounded_fixture",
        input_formats=("data",),
        input_contract_source="declared_contract",
        minimum_evidence_score=1,
    )


def _configure_selected_case(monkeypatch, data: bytes, family: str) -> one_shot.InputUnit:
    digest = hashlib.sha256(data).hexdigest()
    layer = one_shot.StaticLayer(
        name="fixture.bin",
        data=data,
        sha256=digest,
        parent_sha256=None,
        depth=0,
        transform="submission",
    )
    layer_report = {
        "schema_version": 1,
        "counts": {
            "layers": 1,
            "recovered_layers": 0,
            "recovered_bytes": 0,
            "limit_events": 0,
        },
        "steps": [],
        "limit_events": [],
        "layers": [layer.public()],
        "executed_sample": False,
        "network_contacted": False,
        "recovered_content_exported": False,
    }
    monkeypatch.setattr(
        one_shot,
        "recover_static_layers",
        lambda _unit, **_kwargs: ([layer], layer_report),
    )
    monkeypatch.setattr(
        one_shot.classify_sample,
        "classify_bytes",
        lambda *_args, **_kwargs: _fixture_classification(family),
    )
    monkeypatch.setattr(
        one_shot,
        "_run_generic_triage",
        lambda _layers, _case_dir, **_kwargs: (
            {
                "analysis_coverage": {"status": "complete"},
                "executed_sample": False,
                "network_contacted": False,
            },
            "complete",
        ),
    )
    return one_shot.InputUnit(
        source_name="fixture.bin",
        data=data,
        input_kind="raw",
        outer_sha256=digest,
        outer_size=len(data),
    )


def test_verification_candidates_are_fail_closed() -> None:
    """blockedまたは通常確定routeを候補handlerへ渡さない。"""

    eligible = {
        "family": "nanocore",
        "routing_eligible": True,
        "routing_mode": "candidate_verification",
        "routing_eligibility": {"candidate_verification": True},
    }
    routing = {
        "candidates": [
            eligible,
            {**eligible, "family": "blocked", "routing_eligible": False},
            {**eligible, "family": "selected", "routing_mode": "selected_family_analysis"},
            {
                **eligible,
                "family": "nested_blocked",
                "routing_eligibility": {"candidate_verification": False},
            },
        ]
    }

    assert one_shot._verification_candidates(routing) == [eligible]


def test_candidate_status_and_binary_requirement_are_preserved() -> None:
    """corroboratedを弱めず、binaryの未実施関数解析を必須gateにする。"""

    assessment = {
        "families": [
            {
                "family": "valleyrat",
                "attempts": [
                    {
                        "handler_id": "valleyrat:test",
                        "status": "corroborated",
                        "handler_evidence": {"tier": 3, "score": 300},
                        "layer": {"sha256": "1" * 64},
                        "result": {"result": {"configuration_recovered": True}},
                    }
                ],
            }
        ]
    }
    records = one_shot._candidate_outcome_handler_records(assessment)
    assert records[0]["status"] == "corroborated"
    assert records[0]["family"] == "valleyrat"

    layer = one_shot.StaticLayer(
        name="sample.exe",
        data=b"MZ" + b"\0" * 126,
        sha256=hashlib.sha256(b"MZ" + b"\0" * 126).hexdigest(),
        parent_sha256=None,
        depth=0,
        transform="submission",
    )
    candidates = one_shot._outcome_candidates(
        {"candidates": [{"family": "valleyrat", "routing_eligible": True}]},
        [layer],
        {"status": "function_analysis_required"},
        one_shot._load_family_analysis_requirements(),
    )
    assert candidates[0]["requirements"]["function_analysis_required"] is True


def test_manifest_routes_only_exact_root_and_seals_new_artifacts(tmp_path: Path) -> None:
    """root SHA完全一致hintだけを使い、新成果物をresume契約へ封印する。"""

    sample = tmp_path / "sample.sh"
    sample.write_bytes(b"#!/bin/sh\necho one-shot exact root metadata fixture\n")
    digest = hashlib.sha256(sample.read_bytes()).hexdigest()
    manifest = tmp_path / "hints.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "samples": {
                    digest: [
                        {
                            "family": "freepbx_k_php",
                            "source": "unit_test",
                            "provenance": "exact_root_fixture",
                            "confidence": "medium",
                        }
                    ],
                    "f" * 64: [
                        {
                            "family": "nanocore",
                            "source": "unit_test",
                            "provenance": "different_root_fixture",
                            "confidence": "high",
                        }
                    ],
                },
            }
        ),
        encoding="utf-8",
    )
    output = tmp_path / "out"

    summary = one_shot.run_batch(
        [sample],
        output,
        registry=REGISTRY,
        family_hint_manifest=manifest,
    )

    assert summary["counts"]["analyzed"] == 1
    case = summary["cases"][0]
    case_dir = output / "cases" / digest
    routing = json.loads((case_dir / "family-routing.json").read_text(encoding="utf-8"))
    assessment = json.loads(
        (case_dir / "candidate-handler-assessment.json").read_text(encoding="utf-8")
    )
    outcome = json.loads((case_dir / "orchestration.json").read_text(encoding="utf-8"))
    report = json.loads((case_dir / "report.json").read_text(encoding="utf-8"))

    assert [item["family"] for item in routing["candidates"]] == ["freepbx_k_php"]
    assert routing["metadata_hint_count"] == 1
    assert assessment["status"] == "no_confirmed_family"
    assert assessment["planned_attempt_count"] >= 1
    assert outcome["family_resolution"]["status"] == "unresolved"
    assert outcome["quality_gates"]["static_layers"]["status"] == "satisfied"
    assert case["automation_family"] is None
    assert summary["counts"]["automation_unknown"] == 1
    assert sum(
        summary["counts"][key]
        for key in ("automation_resolved", "automation_partial", "automation_unknown")
    ) == summary["counts"]["analyzed"]
    assert summary["counts"]["candidate_handler_attempts"] >= 1
    assert case["ai_used"] is False
    assert report["ai_used"] is False
    assert summary["ai_used"] is False
    assert outcome["automation"]["ai_used"] is False
    for relative in (
        "family-routing.json",
        "candidate-handler-assessment.json",
        "orchestration.json",
    ):
        assert relative in report["artifact_sha256"]
        assert (case_dir / relative).is_file()
    assert report["knowledge_artifacts"]["orchestration"] == "orchestration.json"
    assert summary["analysis_contract"]["settings"]["family_hint_manifest"][
        "canonical_sha256"
    ]

    resumed = one_shot.run_batch(
        [sample],
        output,
        registry=REGISTRY,
        family_hint_manifest=manifest,
        resume=True,
    )
    assert resumed["counts"]["resumed"] == 1
    assert resumed["counts"]["candidate_handler_attempts"] >= 1
    assert resumed["cases"][0]["ai_used"] is False


def test_cli_exposes_family_hint_manifest() -> None:
    """WebUI job runnerがCLIへstrict manifestを渡せる。"""

    parsed = one_shot.build_parser().parse_args(
        ["--input", "sample.bin", "--output", "out", "--family-hint-manifest", "hints.json"]
    )
    assert parsed.family_hint_manifest == Path("hints.json")


def _accepted_record(
    family: str,
    payload: dict,
    *,
    verified_binary_outputs: list[dict] | None = None,
    follow_on_analysis_complete: bool = False,
) -> dict:
    digest = "1" * 64
    record = {
        "source": "selected_family_analysis",
        "family": family,
        "handler_id": f"{family}:fixture",
        "status": "succeeded",
        "selected_layer_sha256": digest,
        "selected_evidence": one_shot.handler_result_quality(payload),
        "verified_binary_outputs": verified_binary_outputs or [],
        "result": {"result": payload},
    }
    if verified_binary_outputs:
        record["verified_binary_output_audit"] = _retention_audit(
            output_count=len(verified_binary_outputs),
            analysis_complete=follow_on_analysis_complete,
        )
    return record


def _retention_audit(*, output_count: int, analysis_complete: bool) -> dict:
    return {
        "schema_version": 1,
        "maximum_outputs": 64,
        "maximum_total_size": 256 * 1024 * 1024,
        "binary_values_seen": output_count,
        "binary_bytes_seen": 128 * output_count,
        "traversal_items": 4,
        "observed_output_count": output_count,
        "retained_output_count": output_count,
        "retained_for_follow_on_analysis": True,
        "follow_on_analysis_complete": analysis_complete,
        "observation_scope": "parent_rehashed_case_artifact",
        "truncated": False,
        "reasons": [],
    }


def _known_hash_candidate(family: str, policy: dict[str, dict]) -> dict:
    candidate = {
        "family": family,
        "source": "known_hash",
        "source_strength": 4,
        "routing_eligible": True,
        "routing_mode": "selected_family_analysis",
        "routing_eligibility": {
            "mode": "selected_family_analysis",
            "selected_family_analysis": True,
            "family_attribution": True,
        },
        "evidence": [
            {
                "kind": "known_outer_sha256",
                "layer_sha256": "1" * 64,
                "supports_attribution": True,
                "confidence": "high",
            }
        ],
    }
    return one_shot._outcome_candidates(
        {"candidates": [candidate]},
        [],
        {"status": "complete"},
        policy,
    )[0]


def test_requirements_policy_blocks_missing_valleyrat_outputs_and_unknown_family() -> None:
    """RAT必須成果物と未宣言familyをfail-closedにする。"""

    policy = one_shot._load_family_analysis_requirements()
    valley = _known_hash_candidate("valleyrat", policy)
    assert valley["requirements"] == {
        "policy_declared": True,
        "policy_category": "rat",
        "config_required": True,
        "network_required": True,
        "terminal_payload_required": False,
    }
    missing = one_shot.orchestration_outcome.build_outcome(
        sample_sha256="1" * 64,
        generic_status="complete",
        layer_status="complete",
        candidates=[valley],
        handler_records=[],
        function_analysis_available=True,
    )
    one_shot._apply_requirements_policy_gate(missing, policy)
    assert missing["status"] == "partial"
    assert {"config", "network"}.issubset(missing["blockers"])

    payload = {
        "configuration_recovered": True,
        "c2": ["valley.example.org:443"],
    }
    complete = one_shot.orchestration_outcome.build_outcome(
        sample_sha256="1" * 64,
        generic_status="complete",
        layer_status="complete",
        candidates=[valley],
        handler_records=[_accepted_record("valleyrat", payload)],
        function_analysis_available=True,
    )
    one_shot._apply_requirements_policy_gate(complete, policy)
    assert complete["status"] == "complete"

    undeclared = _known_hash_candidate("unclassified", policy)
    unknown = one_shot.orchestration_outcome.build_outcome(
        sample_sha256="1" * 64,
        generic_status="complete",
        layer_status="complete",
        candidates=[undeclared],
        handler_records=[],
        function_analysis_available=True,
    )
    one_shot._apply_requirements_policy_gate(unknown, policy)
    assert unknown["status"] == "partial"
    assert "requirements_policy" in unknown["blockers"]


def test_loader_requires_wrapper_verified_terminal_payload() -> None:
    """loaderの自己申告hashを拒否し、wrapper検証済みpayloadだけでgateを満たす。"""

    policy = one_shot._load_family_analysis_requirements()
    candidate = _known_hash_candidate("guloader", policy)
    missing = one_shot.orchestration_outcome.build_outcome(
        sample_sha256="1" * 64,
        generic_status="complete",
        layer_status="complete",
        candidates=[candidate],
        handler_records=[],
        function_analysis_available=True,
    )
    assert "terminal_payload" in missing["blockers"]
    assert "network" in missing["blockers"]

    output = {
        "role": "terminal_payload",
        "kind": "pe",
        "path": "handler-result/terminal_payload/payload.exe",
        "sha256": "2" * 64,
        "size": 128,
        "verification": {
            "status": "artifact_hash_verified",
            "sha256_matches": True,
            "size_matches": True,
        },
    }
    terminal_only = _accepted_record(
        "guloader",
        {"static_config_recovered": True, "config": {"campaign": "fixture"}},
        verified_binary_outputs=[output],
    )
    missing_network = one_shot.orchestration_outcome.build_outcome(
        sample_sha256="1" * 64,
        generic_status="complete",
        layer_status="complete",
        candidates=[candidate],
        handler_records=[terminal_only],
        function_analysis_available=True,
    )
    assert missing_network["outputs"]["terminal_payload"]["status"] == "retained_pending_analysis"
    assert missing_network["status"] == "partial"
    assert missing_network["blockers"] == ["network", "terminal_payload"]

    complete = one_shot.orchestration_outcome.build_outcome(
        sample_sha256="1" * 64,
        generic_status="complete",
        layer_status="complete",
        candidates=[candidate],
        handler_records=[
            _accepted_record(
                "guloader",
                {
                    "static_config_recovered": True,
                    "config": {"campaign": "fixture"},
                    "urls": ["https://stage.example.org/payload.bin"],
                },
                verified_binary_outputs=[output],
                follow_on_analysis_complete=True,
            )
        ],
        function_analysis_available=True,
    )
    assert complete["outputs"]["terminal_payload"]["status"] == "verified"
    assert complete["status"] == "complete"
    assert one_shot._verified_outputs_from_wrapper(
        {"result": {"verified_binary_outputs": [output], "payload_sha256": "2" * 64}}
    ) == []


def test_candidate_flat_record_preserves_corroboration_and_verified_output() -> None:
    """candidate flatten後もhandler・detector・lineage証拠とterminal metadataを保持する。"""

    payload = {
        "static_config_recovered": True,
        "config": {"campaign": "fixture"},
        "c2": ["rat.example.org:443"],
    }
    quality = one_shot.handler_result_quality(payload)
    output = {
        "role": "terminal_payload",
        "kind": "pe",
        "path": "handler-result/terminal_payload/payload.exe",
        "sha256": "3" * 64,
        "size": 64,
        "verification": {
            "status": "artifact_hash_verified",
            "sha256_matches": True,
            "size_matches": True,
        },
    }
    assessment = {
        "families": [
            {
                "family": "valleyrat",
                "attempts": [
                        {
                            "handler_id": "valleyrat:fixture",
                            "source": "candidate_verification",
                            "status": "corroborated",
                        "handler_evidence": quality,
                        "detector_corroboration": {
                            "corroborated": True,
                            "basis": "detector_structural_evidence",
                            "layer_sha256": "1" * 64,
                            "lineage_distance": 0,
                        },
                        "layer": {"sha256": "1" * 64},
                            "result": {
                                "result": payload,
                                "verified_binary_outputs": [output],
                                "verified_binary_output_audit": _retention_audit(
                                    output_count=1,
                                    analysis_complete=True,
                                ),
                            },
                    }
                ],
            }
        ]
    }
    records = one_shot._candidate_outcome_handler_records(assessment)
    assert records[0]["handler_evidence"] == quality
    assert records[0]["source"] == "candidate_verification"
    assert records[0]["status"] == "corroborated"
    assert records[0]["detector_corroboration"]["corroborated"] is True
    assert records[0]["selected_layer_sha256"] == "1" * 64
    assert records[0]["verified_binary_outputs"] == [output]
    assert records[0]["verified_binary_output_audit"]["follow_on_analysis_complete"] is True
    assert records[0]["result"] == assessment["families"][0]["attempts"][0]["result"]
    candidate = {
        "family": "valleyrat",
        "source": "detector_candidate",
        "source_strength": 2,
        "routing_eligible": True,
        "routing_mode": "candidate_verification",
        "routing_eligibility": {
            "mode": "candidate_verification",
            "candidate_verification": True,
            "family_attribution": False,
        },
        "evidence": [
            {
                "kind": "type_detector_structure",
                "layer_sha256": "1" * 64,
                "supports_attribution": True,
                "confidence": "medium",
            }
        ],
    }
    resolved = one_shot.orchestration_outcome.resolve_family([candidate], records)
    assert resolved["status"] == "resolved"
    outputs = one_shot.orchestration_outcome.summarize_handler_outputs(records)
    assert outputs["terminal_payload"]["status"] == "verified"


def test_selected_family_retained_output_stays_pending_end_to_end(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """worker payloadを保持しても後続静的解析前はcompleteへ昇格しない。"""

    unit = _configure_selected_case(monkeypatch, b"selected wrapper output fixture", "guloader")
    terminal_bytes = b"MZ" + b"P" * 126
    terminal_sha256 = hashlib.sha256(terminal_bytes).hexdigest()
    verified = {
        "role": "terminal_payload",
        "kind": "pe",
        "path": f"p/{terminal_sha256}.exe",
        "sha256": terminal_sha256,
        "size": 128,
        "verification": {
            "status": "artifact_hash_verified",
            "sha256_matches": True,
            "size_matches": True,
        },
    }

    def bounded(spec, _data, _source_name, **kwargs):
        destination = kwargs["artifact_directory"]
        (destination / f"{terminal_sha256}.exe").write_bytes(terminal_bytes)
        return {
            "status": "completed",
            "handler": spec.public(),
            "preflight": {"eligible": True, "blockers": []},
            "handler_timeout_seconds": 30.0,
            "execution": {
                "handler": spec.public(),
                "result": {
                    "decoded_config_recovered": True,
                    "config": {"campaign": "fixture"},
                    "urls": ["https://stage.example.org/payload.bin"],
                    "terminal_payload": {"sha256": "f" * 64},
                },
                "verified_binary_outputs": [verified],
                "verified_binary_output_audit": _retention_audit(
                    output_count=1,
                    analysis_complete=False,
                ),
                "executed_sample": False,
                "network_contacted": False,
            },
        }

    monkeypatch.setattr(one_shot, "execute_handler_bounded_for_assessment", bounded)
    output = tmp_path / "out"
    result = one_shot.analyze_unit(
        unit,
        output=output,
        registry=REGISTRY,
        specs=[_fixture_handler_spec("guloader")],
        registered={"guloader"},
        forced_family=None,
        minimum_confidence="medium",
        assessment_only=False,
        analysis_contract={"schema_version": 1, "sha256": "fixture-contract"},
    )
    case_dir = output / "cases" / result["sha256"]
    report = json.loads((case_dir / "report.json").read_text(encoding="utf-8"))
    execution = report["handler_executions"][0]
    wrapper = json.loads((case_dir / execution["result"]).read_text(encoding="utf-8"))
    outcome = json.loads((case_dir / "orchestration.json").read_text(encoding="utf-8"))

    assert wrapper["verified_binary_outputs"] == [verified]
    assert outcome["status"] == "partial"
    assert outcome["outputs"]["terminal_payload"]["status"] == "retained_pending_analysis"
    assert outcome["outputs"]["retained_terminal_payload_sha256"] == [terminal_sha256]
    assert outcome["outputs"]["terminal_payload_sha256"] == []
    assert "terminal_payload" in outcome["blockers"]
    assert "f" * 64 not in outcome["outputs"]["terminal_payload_sha256"]


def test_selected_family_timeout_keeps_legacy_failure_schema(tmp_path: Path, monkeypatch) -> None:
    """worker timeoutを従来のfailed executionへ正規化し、原因情報を保持する。"""

    unit = _configure_selected_case(monkeypatch, b"selected timeout fixture", "guloader")
    monkeypatch.setattr(
        one_shot,
        "execute_handler_bounded_for_assessment",
        lambda spec, *_args, **_kwargs: {
            "status": "timed_out",
            "handler": spec.public(),
            "preflight": {"eligible": True, "blockers": []},
            "handler_timeout_seconds": 0.1,
            "error": "handler_wall_clock_timeout",
        },
    )
    output = tmp_path / "out"
    result = one_shot.analyze_unit(
        unit,
        output=output,
        registry=REGISTRY,
        specs=[_fixture_handler_spec("guloader")],
        registered={"guloader"},
        forced_family=None,
        minimum_confidence="medium",
        assessment_only=False,
        analysis_contract={"schema_version": 1, "sha256": "fixture-contract"},
    )
    report = json.loads(
        (output / "cases" / result["sha256"] / "report.json").read_text(encoding="utf-8")
    )
    execution = report["handler_executions"][0]
    attempt = next(item for item in execution["attempts"] if item["status"] == "failed")
    assert execution["status"] == "failed"
    assert execution["error"] == "all_eligible_layers_failed"
    assert attempt["execution_boundary"] == "bounded_assessment_worker"
    assert attempt["worker_status"] == "timed_out"
    assert attempt["error"] == "handler_wall_clock_timeout"


def test_selected_family_does_not_import_handler_in_parent_process(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """import時副作用を持つhandlerでも親processではmoduleをloadしない。"""

    unit = _configure_selected_case(monkeypatch, b"parent import sentinel fixture", "guloader")
    fixture_dir = REPOSITORY_ROOT / ".work" / "one-shot-import-sentinel" / uuid.uuid4().hex
    module_path = fixture_dir / "handler.py"
    sentinel = tmp_path / "import-process-id.txt"
    fixture_dir.mkdir(parents=True, exist_ok=False)
    module_path.write_text(
        "import os\n"
        "from pathlib import Path\n"
        f"Path({str(sentinel)!r}).write_text(str(os.getpid()), encoding='utf-8')\n"
        "SUPPORTED_INPUT_FORMATS = ('data',)\n"
        "MINIMUM_EVIDENCE_SCORE = 1\n"
        "def extract(data: bytes) -> dict:\n"
        "    return {'static_config_recovered': True, 'config': {'fixture': 'ok'}}\n",
        encoding="utf-8",
    )
    try:
        output = tmp_path / "out"
        result = one_shot.analyze_unit(
            unit,
            output=output,
            registry=REGISTRY,
            specs=[
                _fixture_handler_spec(
                    "guloader",
                    relative_path=module_path.relative_to(REPOSITORY_ROOT).as_posix(),
                )
            ],
            registered={"guloader"},
            forced_family=None,
            minimum_confidence="medium",
            assessment_only=False,
            analysis_contract={"schema_version": 1, "sha256": "fixture-contract"},
        )
        report = json.loads(
            (output / "cases" / result["sha256"] / "report.json").read_text(encoding="utf-8")
        )
        attempt = report["handler_executions"][0]["attempts"][0]
        assert attempt["execution_boundary"] == "bounded_assessment_worker"
        assert attempt["worker_status"] in {"preflight_blocked", "failed"}
        if sentinel.exists():
            assert sentinel.read_text(encoding="utf-8") != str(os.getpid())
    finally:
        shutil.rmtree(fixture_dir)
