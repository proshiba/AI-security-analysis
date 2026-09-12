"""ValleyRAT候補検証からone-shot通信成果物までの統合契約を検証する。"""

from __future__ import annotations

import copy
import hashlib
import io
import json
import sys
import zipfile
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
COMMON = REPOSITORY_ROOT / "analysis-framework" / "common"
for import_root in (REPOSITORY_ROOT, COMMON):
    if str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))

import analyze_sample  # noqa: E402
import automated_case_analysis  # noqa: E402
import handler_catalog  # noqa: E402

HANDLER_ID = "valleyrat:extractors.valleyrat.extractor.py:extract"
REGISTRY = REPOSITORY_ROOT / "analysis-framework" / "registry" / "malware_types.json"


def _minimal_x86_pe(encoded_tail: bytes) -> bytes:
    data = bytearray(0x100)
    data[:2] = b"MZ"
    data[0x3C:0x40] = (0x80).to_bytes(4, "little")
    data[0x80:0x84] = b"PE\0\0"
    data[0x84:0x86] = (0x14C).to_bytes(2, "little")
    return bytes(data) + encoded_tail


def _classification(family: str | None) -> dict:
    """合成bundleの外装だけをValleyRATとして選択する最小分類結果を返す。"""

    if family is None:
        return {
            "schema_version": 1,
            "malware_type": "unknown",
            "malware_type_confidence": "low",
            "campaign_type": "unknown",
            "attribution_basis": "no_unique_detector_match",
            "observations": {},
            "campaign_candidates": [],
            "detector_evaluations": [],
        }
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


@pytest.fixture(scope="module")
def corroborated_assessment() -> dict:
    """反転vvaS設定を持つ合成bytesから候補検証wrapperを作る。"""

    plaintext = b"p1:198.51.100.22|o1:443"
    data = b"synthetic-vvas" + bytes([0]) + plaintext[::-1] + bytes([0])
    digest = hashlib.sha256(data).hexdigest()
    evidence = {
        "tier": 3,
        "tier_name": "validated_static_configuration",
        "score": 30_002,
        "minimum_score": 30_000,
        "sufficient": True,
        "structural_groups": [],
        "candidate_groups": ["endpoints", "findings"],
    }
    wrapper = {
        "handler": {
            "id": HANDLER_ID,
            "family": "valleyrat",
        },
        "result": {
            "schema_version": 1,
            "family": "valleyrat",
            "sample_sha256": digest,
            "config": {
                "variant": "dll_sideload_vvas_bundle",
                "decoded_vvas": {"endpoint_1": "198.51.100.22:443"},
                "static_config_recovered": True,
                "c2_liveness_confirmed": False,
                "endpoints": ["198.51.100.22:443"],
            },
            "findings": [
                {
                    "kind": "network.endpoint",
                    "value": "198.51.100.22:443",
                    "role": "static_config_c2",
                    "confidence": "confirmed_static_config",
                    "source": "decoded_vvas_config",
                }
            ],
            "executed": False,
            "network_contacted": False,
        },
        "result_quota": {"truncated": False},
        "verified_binary_outputs": [],
        "executed_sample": False,
        "network_contacted": False,
    }
    return {
        "schema_version": 1,
        "status": "confirmed",
        "confirmed_families": ["valleyrat"],
        "families": [
            {
                "family": "valleyrat",
                "status": "confirmed",
                "confirmed": True,
                "attempts": [
                    {
                        "handler_id": HANDLER_ID,
                        "family": "valleyrat",
                        "status": "corroborated",
                        "handler_evidence": evidence,
                        "detector_corroboration": {
                            "corroborated": True,
                            "score": 20_000,
                            "basis": "detector_structural_evidence",
                            "layer_sha256": digest,
                            "lineage_distance": 0,
                        },
                        "layer": {
                            "name": "synthetic-vvas.bin",
                            "sha256": digest,
                            "parent_sha256": None,
                            "depth": 0,
                            "transform": "submission",
                            "format": "data",
                            "size": len(data),
                        },
                        "result": wrapper,
                    }
                ],
            }
        ],
        "executed_sample": False,
        "network_contacted": False,
    }


def test_corroborated_candidate_config_reaches_communication_and_c2(
    corroborated_assessment: dict,
) -> None:
    """曖昧分類後の検証済みconfigを標準成果物から欠落させない。"""

    projected = analyze_sample._candidate_automation_handler_results(
        corroborated_assessment,
        resolved_family="valleyrat",
    )
    assert len(projected) == 1
    digest = corroborated_assessment["families"][0]["attempts"][0]["layer"]["sha256"]
    patterns, c2 = automated_case_analysis.build_case_automation_artifacts(
        sha256=digest,
        family="valleyrat",
        layer_report={"counts": {"recovered_layers": 0}},
        handler_results=projected,
    )

    assert patterns["family"] == "valleyrat"
    assert patterns["config"]["static_config_recovered"] is True
    assert patterns["communication"]["candidate_patterns"] == [
        {
            "value": "198.51.100.22:443",
            "source": (
                "handler:valleyrat:extractors.valleyrat.extractor.py:extract"
            ),
            "source_field": "result.config.endpoints",
            "status": "candidate_static_handler_output",
        }
    ]
    phases = {item["phase"]: item for item in c2["phase_evidence"]}
    assert phases["family_config_extraction"]["status"] == "completed"
    assert phases["c2_endpoint_extraction"]["status"] == "completed"
    assert c2["c2"]["protocol"]["status"] == "unresolved"
    assert patterns["safety"] == {
        "sample_executed": False,
        "network_contacted": False,
        "credentials_published": False,
        "raw_payload_published": False,
    }


def test_real_classifier_keeps_raw_xor_vvas_and_stage_loader_route_only() -> None:
    """raw XOR設定と次段loaderを分類器入口でfamily未確定のrouteに留める。"""

    vvas_plaintext = b"payload odaktomk |1:1t|944:1o|42.001.15.891:1p|"
    xor_vvas = bytes(value ^ 0x14 for value in vvas_plaintext)
    vvas = analyze_sample.classify_sample.classify_bytes(
        xor_vvas,
        Path("unknown-vvas.bin"),
        REGISTRY,
    )
    vvas_evaluation = next(
        item
        for item in vvas["detector_evaluations"]
        if item["malware_type"] == "valleyrat"
    )

    assert vvas["malware_type"] == "unknown"
    assert vvas_evaluation["detector_matched"] is True
    assert vvas_evaluation["automatic_route_eligible"] is True
    assert vvas_evaluation["supports_family_attribution"] is False
    vvas_campaign = vvas_evaluation["detection"]["campaigns"][0]
    assert vvas_campaign["campaign_type"] == "single_byte_xor_vvas_candidate"
    assert vvas_campaign["terminal_family_confirmed"] is False

    b1_plaintext = (
        b"wininet.dll GetProcAddress GetModuleHandleA InternetOpenA "
        b"InternetOpenUrlA InternetReadFile AddVectoredExceptionHandler VirtualAlloc "
        b"https://stage.example/payload.bin"
    )
    xor_b1 = bytes(value ^ 0xB1 for value in b1_plaintext)
    b1 = analyze_sample.classify_sample.classify_bytes(
        _minimal_x86_pe(xor_b1),
        Path("unknown-b1.exe"),
        REGISTRY,
    )
    valley_evaluation = next(
        item
        for item in b1["detector_evaluations"]
        if item["malware_type"] == "valleyrat"
    )

    assert b1["malware_type"] == "unknown"
    assert valley_evaluation["detector_matched"] is True
    assert valley_evaluation["automatic_route_eligible"] is True
    assert valley_evaluation["supports_family_attribution"] is False
    campaign = valley_evaluation["detection"]["campaigns"][0]
    assert campaign["campaign_type"] == (
        "x86_single_byte_xor_wininet_next_stage_loader"
    )
    assert campaign["terminal_family_confirmed"] is False


def test_selected_valleyrat_zip_routes_child_config_to_case_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """one-shotで外装family判定から子configと通信成果物まで自動到達する。"""

    child_data = b"p1:198.51.100.24|o1:449"
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("config.dat", child_data)
    root_data = stream.getvalue()
    root_hash = hashlib.sha256(root_data).hexdigest()
    child_hash = hashlib.sha256(child_data).hexdigest()

    monkeypatch.setattr(
        analyze_sample.classify_sample,
        "classify_bytes",
        lambda data, *_args, **_kwargs: _classification(
            "valleyrat" if data == root_data else None
        ),
    )
    monkeypatch.setattr(
        analyze_sample,
        "_preflight_applicable",
        lambda _specs, applicability: [
            {"handler_id": item["id"], "available": True, "error": None}
            for item in applicability
            if item["status"] == "applicable"
        ],
    )
    monkeypatch.setattr(
        analyze_sample,
        "_run_generic_triage",
        lambda _layers, _case_dir, **_kwargs: (
            {"analysis_coverage": {"status": "complete"}},
            "complete",
        ),
    )
    calls: list[bytes] = []

    def execute(_spec, data: bytes, _source_name: str, **_kwargs) -> dict:
        calls.append(data)
        result = {}
        if data == child_data:
            result = {
                "schema_version": 1,
                "family": "valleyrat",
                "sample_sha256": hashlib.sha256(data).hexdigest(),
                "static_config_recovered": True,
                "config": {
                    "variant": "synthetic_bundle_config",
                    "static_config_recovered": True,
                    "endpoints": ["198.51.100.24:449"],
                },
                "executed": False,
                "network_contacted": False,
            }
        return {
            "status": "completed",
            "preflight": {"eligible": True, "blockers": []},
            "handler_timeout_seconds": 30.0,
            "execution": {
                "result": result,
                "executed_sample": False,
                "network_contacted": False,
            },
        }

    monkeypatch.setattr(
        analyze_sample,
        "execute_handler_bounded_for_assessment",
        execute,
    )
    spec = analyze_sample.HandlerSpec(
        id=HANDLER_ID,
        family="valleyrat",
        relative_path="extractors/valleyrat/extractor.py",
        callable_name="extract",
        invocation="bytes",
        source="shared_extractor",
        automatic=True,
        campaign=None,
        supported_interface=True,
        reason="bounded_fixture",
        input_formats=("zip", "data"),
        input_contract_source="declared_contract",
        minimum_evidence_score=1,
    )
    unit = analyze_sample.InputUnit(
        source_name="valleyrat-bundle.zip",
        data=root_data,
        input_kind="raw",
        outer_sha256=root_hash,
        outer_size=len(root_data),
    )
    output = tmp_path / "out"

    analyze_sample.analyze_unit(
        unit,
        output=output,
        registry=REGISTRY,
        specs=[spec],
        registered={"valleyrat"},
        forced_family=None,
        minimum_confidence="medium",
        assessment_only=False,
        analysis_contract={"schema_version": 1, "sha256": "fixture-contract"},
    )

    case_dir = output / "cases" / root_hash
    report = json.loads((case_dir / "report.json").read_text(encoding="utf-8"))
    patterns = json.loads(
        (case_dir / "communication-patterns.json").read_text(encoding="utf-8")
    )
    c2 = json.loads((case_dir / "c2-analysis.json").read_text(encoding="utf-8"))
    execution = report["handler_executions"][0]
    attempts = {
        item["layer"]["sha256"]: item
        for item in execution["attempts"]
        if isinstance(item.get("layer"), dict)
    }

    assert root_data in calls
    assert child_data in calls
    assert attempts[child_hash]["routing_role"] == "descendant_candidate"
    assert attempts[child_hash]["evidence_status"] == "sufficient"
    assert execution["selected_layer_sha256"] == child_hash
    assert report["candidate_handler_assessment"]["status"] == "no_candidates"
    assert report["route_config_candidates"]["projection_disposition"] == (
        "not_applicable"
    )
    assert report["route_config_candidates"]["projection_reason"] == (
        "no_candidate_verification_routes"
    )
    assert patterns["family"] == "valleyrat"
    assert patterns["config"]["static_config_recovered"] is True
    assert patterns["communication"]["candidate_patterns"] == [
        {
            "value": "198.51.100.24:449",
            "source": f"handler:{HANDLER_ID}",
            "source_field": "result.config.endpoints",
            "status": "candidate_static_handler_output",
        }
    ]
    assert all(
        item.get("value") != "network.endpoint"
        for item in patterns["communication"]["candidate_patterns"]
    )
    phases = {item["phase"]: item for item in c2["phase_evidence"]}
    assert phases["family_config_extraction"]["status"] == "completed"
    assert phases["c2_endpoint_extraction"]["status"] == "completed"
    assert patterns["safety"]["sample_executed"] is False
    assert patterns["safety"]["network_contacted"] is False


def test_real_detector_does_not_promote_unlinked_raw_child_config(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """filenameだけの合成外層とraw子設定をValleyRAT familyへ昇格しない。"""

    vvas_data = b"odaktomk |944:1o|42.001.15.891:1p|"
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("chgport.exe", b"MZ" + bytes(126))
        archive.writestr("LoggerCollector.dll", b"MZ" + bytes(126))
        archive.writestr("vvaS.bin", vvas_data)
    root_data = stream.getvalue()
    root_hash = hashlib.sha256(root_data).hexdigest()
    spec = next(
        item
        for item in analyze_sample.discover_handlers()
        if item.id == HANDLER_ID
    )
    monkeypatch.setattr(
        analyze_sample,
        "_run_generic_triage",
        lambda _layers, _case_dir, **_kwargs: (
            {"analysis_coverage": {"status": "complete"}},
            "complete",
        ),
    )
    unit = analyze_sample.InputUnit(
        source_name="synthetic-vvas-bundle.zip",
        data=root_data,
        input_kind="raw",
        outer_sha256=root_hash,
        outer_size=len(root_data),
    )
    output = tmp_path / "out"

    analyze_sample.analyze_unit(
        unit,
        output=output,
        registry=REGISTRY,
        specs=[spec],
        registered={"valleyrat"},
        forced_family=None,
        minimum_confidence="medium",
        assessment_only=False,
        analysis_contract={"schema_version": 1, "sha256": "fixture-contract"},
    )

    case_dir = output / "cases" / root_hash
    report = json.loads((case_dir / "report.json").read_text(encoding="utf-8"))
    patterns = json.loads(
        (case_dir / "communication-patterns.json").read_text(encoding="utf-8")
    )
    routing = json.loads(
        (case_dir / "family-routing.json").read_text(encoding="utf-8")
    )

    # 外装のfilename相関とraw marker/configはどちらもroute-onlyであり、
    # loader→子componentの静的lineageがない限りcase全体を確定しない。
    assert report["classification"]["selected_family"] is None
    assert report["classification"]["selected_families"] == []
    assert report["classification"]["automation_family"] is None
    assert report["classification"]["automation_status"] == "unresolved"
    assert report["handler_executions"] == []
    assert routing["verification_only_families"] == ["valleyrat"]
    assert routing["candidates"][0]["routing_eligibility"][
        "family_attribution"
    ] is False
    assert patterns["family"] == "unclassified"
    assert patterns["config"]["static_config_recovered"] is False
    assert patterns["communication"]["candidate_patterns"] == []
    assert patterns["safety"]["sample_executed"] is False
    assert patterns["safety"]["network_contacted"] is False


def test_route_only_component_config_never_confirms_valleyrat_family(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """route-only hashからconfigが取れてもValleyRAT終端帰属を確定しない。"""

    data = b"odaktomk |944:1o|42.001.15.891:1p|"
    digest = hashlib.sha256(data).hexdigest()
    route_only = {
        "schema_version": 1,
        "malware_type": "unknown",
        "malware_type_confidence": "low",
        "campaign_type": "unknown",
        "attribution_basis": "no_unique_detector_match",
        "observations": {},
        "campaign_candidates": [],
        "detector_evaluations": [
            {
                "malware_type": "valleyrat",
                "known_outer_sha256": False,
                "known_inner_sha256": True,
                "detector_matched": True,
                "automatic_route_eligible": True,
                "supports_family_attribution": False,
                "error": None,
                "detection": {
                    "matched": True,
                    "observations": {"reviewed_component": "loader"},
                    "campaigns": [
                        {
                            "campaign_type": "onyx_qt_loader",
                            "confidence": "high",
                            "reasons": ["known inner SHA-256"],
                            "attribution_scope": "reviewed_component_handler_route",
                            "terminal_family_confirmed": False,
                        }
                    ],
                },
            }
        ],
    }
    monkeypatch.setattr(
        analyze_sample.classify_sample,
        "classify_bytes",
        lambda *_args, **_kwargs: copy.deepcopy(route_only),
    )
    monkeypatch.setattr(
        analyze_sample,
        "_run_generic_triage",
        lambda _layers, _case_dir, **_kwargs: (
            {"analysis_coverage": {"status": "complete"}},
            "complete",
        ),
    )

    def bounded(spec, _data: bytes, _source_name: str, **_kwargs) -> dict:
        return {
            "status": "completed",
            "handler": spec.public(),
            "preflight": {"eligible": True, "blockers": []},
            "handler_timeout_seconds": 30.0,
            "execution": {
                "handler": spec.public(),
                "result": {
                    "schema_version": 1,
                    "family": "valleyrat",
                    "sample_sha256": digest,
                    "static_config_recovered": True,
                    "config": {
                        "variant": "route_only_fixture",
                        "decoded_config_recovered": True,
                        "static_config_recovered": True,
                        "c2_liveness_confirmed": False,
                        "terminal_family_confirmed": False,
                        "attribution_scope": "component_handler_route",
                        "family_attribution_basis": "terminal_lineage_not_independently_confirmed",
                        "endpoints": ["198.51.100.24:449"],
                    },
                    "findings": [
                        {
                            "kind": "network.endpoint",
                            "value": "198.51.100.24:449",
                            "role": "static_config_c2",
                            "confidence": "confirmed_static_config",
                            "source": "validated_route_only_fixture",
                        }
                    ],
                    "executed": False,
                    "network_contacted": False,
                },
                "result_quota": {"truncated": False, "reasons": []},
                "executed_sample": False,
                "network_contacted": False,
            },
        }

    monkeypatch.setattr(
        handler_catalog,
        "execute_handler_bounded_for_assessment",
        bounded,
    )
    spec = next(
        item
        for item in analyze_sample.discover_handlers()
        if item.id == HANDLER_ID
    )
    unit = analyze_sample.InputUnit(
        source_name="reviewed-route-only.bin",
        data=data,
        input_kind="raw",
        outer_sha256=digest,
        outer_size=len(data),
    )
    output = tmp_path / "out"

    analyze_sample.analyze_unit(
        unit,
        output=output,
        registry=REGISTRY,
        specs=[spec],
        registered={"valleyrat"},
        forced_family=None,
        minimum_confidence="medium",
        assessment_only=False,
        analysis_contract={"schema_version": 1, "sha256": "fixture-contract"},
    )

    case_dir = output / "cases" / digest
    report = json.loads((case_dir / "report.json").read_text(encoding="utf-8"))
    routing = json.loads((case_dir / "family-routing.json").read_text(encoding="utf-8"))
    assessment = json.loads(
        (case_dir / "candidate-handler-assessment.json").read_text(encoding="utf-8")
    )
    outcome = json.loads((case_dir / "orchestration.json").read_text(encoding="utf-8"))
    patterns = json.loads(
        (case_dir / "communication-patterns.json").read_text(encoding="utf-8")
    )
    route_config = json.loads(
        (case_dir / "route-config-candidates.json").read_text(encoding="utf-8")
    )

    assert report["classification"]["selected_families"] == []
    assert report["handler_executions"] == []
    assert routing["verification_only_families"] == ["valleyrat"]
    assert routing["candidates"][0]["routing_eligibility"]["family_attribution"] is False
    assert assessment["confirmed_families"] == []
    assert assessment["families"][0]["status"] == "handler_evidence_route_only"
    assert assessment["families"][0]["detector_layers"][digest]["basis"] == (
        "detector_route_does_not_support_family_attribution"
    )
    attempt = assessment["families"][0]["attempts"][0]
    assert attempt["status"] == "handler_evidence_route_only"
    assert attempt["detector_corroboration"]["basis"] == (
        "no_corroborated_detector_in_lineage"
    )
    assert outcome["family_resolution"]["status"] == "unresolved"
    assert outcome["outputs"]["config_recovered"] is False
    assert outcome["candidate_outputs"]["config_recovered"] is False
    assert outcome["candidate_outputs"]["config_candidate_recovered"] is True
    assert patterns["family"] == "unclassified"
    assert patterns["config"]["static_config_recovered"] is False
    assert patterns["communication"]["candidate_patterns"] == []
    assert route_config["route_config_candidate_recovered"] is True
    assert route_config["family_attribution_confirmed"] is False
    assert route_config["used_for_family_resolution"] is False
    assert route_config["used_for_c2_confirmation"] is False
    assert route_config["candidates"][0]["candidate_family"] == "valleyrat"
    assert route_config["candidates"][0]["configured_network_candidates"] == [
        {
            "endpoint": "198.51.100.24:449",
            "host": "198.51.100.24",
            "port": 449,
            "role": "static_config_c2_candidate",
            "evidence": {
                "kind": "validated_static_config_route_candidate",
                "handler_source": "validated_route_only_fixture",
            },
            "contacted": False,
            "liveness_confirmed": False,
        }
    ]
    assert report["knowledge_artifacts"]["route_config_candidates"] == (
        "route-config-candidates.json"
    )
    assert report["route_config_candidates"]["status_scope"] == (
        "route_candidate_projection_only"
    )
    assert report["route_config_candidates"]["projection_disposition"] == "completed"
    assert report["route_config_candidates"]["overall_analysis_result_affected"] is False
    assert "route-config-candidates.json" in report["artifact_sha256"]


@pytest.mark.parametrize(
    "tamper",
    (
        "family_unresolved",
        "family_mismatch",
        "detector_uncorroborated",
        "handler_insufficient",
        "network_contacted",
        "handler_identity_mismatch",
    ),
)
def test_candidate_projection_remains_fail_closed(
    corroborated_assessment: dict,
    tamper: str,
) -> None:
    """独立検出・十分性・安全flag・identityのいずれかが欠ければ採用しない。"""

    assessment = copy.deepcopy(corroborated_assessment)
    resolved_family: str | None = "valleyrat"
    family = assessment["families"][0]
    attempt = family["attempts"][0]
    if tamper == "family_unresolved":
        resolved_family = None
    elif tamper == "family_mismatch":
        resolved_family = "quasarrat"
    elif tamper == "detector_uncorroborated":
        attempt["detector_corroboration"]["corroborated"] = False
    elif tamper == "handler_insufficient":
        attempt["handler_evidence"]["sufficient"] = False
    elif tamper == "network_contacted":
        attempt["result"]["network_contacted"] = True
    elif tamper == "handler_identity_mismatch":
        attempt["result"]["handler"]["id"] = "valleyrat:wrong:extract"

    assert analyze_sample._candidate_automation_handler_results(
        assessment,
        resolved_family=resolved_family,
    ) == []
