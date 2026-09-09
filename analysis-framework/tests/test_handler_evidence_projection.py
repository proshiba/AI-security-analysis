"""handler成果物のfamily・config identity投影境界を検証する。"""

from __future__ import annotations

import copy
import importlib
import sys
from pathlib import Path

import pytest

COMMON = Path(__file__).resolve().parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

handler_evidence = importlib.import_module("handler_evidence")
analysis_contract = importlib.import_module("analysis_contract")

ROOT_SHA256 = "a" * 64
LEFT_SHA256 = "b" * 64
RIGHT_SHA256 = "c" * 64


def _route_only_assessment() -> dict:
    """帰属未確定だが設定構造を復元済みのValleyRAT候補を返す。"""

    handler_id = "valleyrat:extractors.valleyrat.extractor.py:extract"
    result = {
        "schema_version": 1,
        "family": "valleyrat",
        "sample_sha256": LEFT_SHA256,
        "config": {
            "variant": "x86_codemark_resource_terminal",
            "decoded_config_recovered": True,
            "static_config_recovered": True,
            "c2_liveness_confirmed": False,
            "terminal_family_confirmed": False,
            "attribution_scope": "component_handler_route",
            "family_attribution_basis": "terminal_lineage_not_independently_confirmed",
            "endpoints": ["route.example.test:8443", "198.51.100.24:443"],
        },
        "findings": [
            {
                "kind": "network.endpoint",
                "value": "198.51.100.24:443",
                "role": "static_config_c2",
                "confidence": "confirmed_static_config",
                "source": "validated_x86_codemark_resource",
            },
            {
                "kind": "network.endpoint",
                "value": "route.example.test:8443",
                "role": "static_config_c2",
                "confidence": "confirmed_static_config",
                "source": "validated_x86_codemark_resource",
            },
        ],
        "executed": False,
        "network_contacted": False,
    }
    quality = analysis_contract.handler_result_quality(result, minimum_score=30_000)
    wrapper = {
        "handler": {"id": handler_id, "family": "valleyrat"},
        "result": result,
        "result_quota": {"truncated": False, "reasons": []},
        "executed_sample": False,
        "network_contacted": False,
    }
    attempt = {
        "handler_id": handler_id,
        "family": "valleyrat",
        "status": "handler_evidence_without_detector",
        "handler_evidence": quality,
        "detector_corroboration": {
            "corroborated": False,
            "score": 0,
            "basis": "no_corroborated_detector_in_lineage",
        },
        "layer": {
            "name": "route-only.exe",
            "sha256": LEFT_SHA256,
            "parent_sha256": ROOT_SHA256,
            "depth": 1,
            "transform": "pe-resource",
            "format": "pe",
            "size": 4096,
        },
        "result": wrapper,
    }
    return {
        "schema_version": 1,
        "status": "no_confirmed_family",
        "confirmed_families": [],
        "planned_attempt_count": 1,
        "actual_attempt_count": 1,
        "unattempted_attempt_count": 0,
        "omitted_attempt_detail_count": 0,
        "blockers": [],
        "budget": {"exhausted": False},
        "families": [
            {
                "family": "valleyrat",
                "routing_mode": "candidate_verification",
                "assessment_eligible": True,
                "status": "handler_evidence_without_detector",
                "confirmed": False,
                "attempts": [attempt],
            }
        ],
        "executed_sample": False,
        "network_contacted": False,
        "filesystem_written_by_handlers": False,
    }


def test_route_only_valleyrat_config_is_preserved_without_attribution() -> None:
    """厳格に復元した設定候補をfamily・C2確証へ昇格せず保持する。"""

    document = handler_evidence.build_route_config_candidate_document(
        sha256=ROOT_SHA256,
        assessment=_route_only_assessment(),
    )

    assert document["status"] == "route_config_candidates_recovered"
    assert document["route_config_candidate_recovered"] is True
    assert document["candidate_set_complete"] is True
    assert document["family_attribution_confirmed"] is False
    assert document["used_for_family_resolution"] is False
    assert document["used_for_c2_confirmation"] is False
    assert document["distinct_configuration_count"] == 1
    candidate = document["candidates"][0]
    assert candidate["candidate_family"] == "valleyrat"
    assert candidate["selected_layer_sha256"] == LEFT_SHA256
    assert candidate["variant"] == "x86_codemark_resource_terminal"
    assert [item["endpoint"] for item in candidate["configured_network_candidates"]] == [
        "route.example.test:8443",
        "198.51.100.24:443",
    ]
    assert all(item["contacted"] is False for item in candidate["configured_network_candidates"])
    assert "family" not in document
    assert "family" not in candidate


@pytest.mark.parametrize(
    "endpoint",
    (
        "127.0.0.1:80",
        "0.0.0.0:80",
        "169.254.20.1:80",
        "224.0.0.1:80",
        "[::1]:80",
        "[::]:80",
        "[fe80::1]:80",
        "[ff02::1]:80",
        "[::ffff:127.0.0.1]:80",
    ),
)
def test_route_config_rejects_local_or_special_ip_literals(endpoint: str) -> None:
    """loopback等のローカル・特殊IPを外部network候補へ投影しない。"""

    assert handler_evidence._canonical_route_config_endpoint(endpoint) is None


@pytest.mark.parametrize(
    ("endpoint", "expected"),
    (
        ("198.51.100.24:443", ("198.51.100.24:443", "198.51.100.24", 443)),
        ("10.20.30.40:8443", ("10.20.30.40:8443", "10.20.30.40", 8443)),
        (
            "[2001:4860:4860::8888]:53",
            ("[2001:4860:4860::8888]:53", "2001:4860:4860::8888", 53),
        ),
    ),
)
def test_route_config_accepts_external_and_rfc1918_ip_literals(
    endpoint: str,
    expected: tuple[str, str, int],
) -> None:
    """外部IPと内部配置で使われるRFC1918は構文候補として保持する。"""

    assert handler_evidence._canonical_route_config_endpoint(endpoint) == expected


def test_run_dll_route_config_keeps_only_external_primary() -> None:
    """run export DLLの静的tripletから外部primaryだけを候補へ縮約する。"""

    assessment = _route_only_assessment()
    attempt = assessment["families"][0]["attempts"][0]
    attempt["detector_corroboration"]["basis"] = (
        "detector_route_does_not_support_family_attribution"
    )
    result = attempt["result"]["result"]
    result["config"] = {
        "variant": "run_dll_native_core_static_triplet_candidate",
        "decoded_config_recovered": False,
        "static_config_recovered": True,
        "candidate_config_recovered": True,
        "c2_liveness_confirmed": False,
        "terminal_family_confirmed": False,
        "attribution_scope": "component_handler_route",
        "family_attribution_basis": "run_export_static_triplet_without_terminal_family_proof",
        "endpoints": ["198.51.100.24:441"],
        "excluded_placeholder_defaults": ["127.0.0.1:80"],
        "slots": [
            {"slot": 1, "host": "198.51.100.24", "port": 441, "role": "primary"},
            {"slot": 2, "host": "198.51.100.24", "port": 441, "role": "primary"},
            {"slot": 3, "host": "127.0.0.1", "port": 80, "role": "loopback_placeholder"},
        ],
    }
    result["findings"] = [
        {
            "kind": "network.endpoint",
            "value": "198.51.100.24:441",
            "role": "static_config_c2",
            "confidence": "confirmed_static_config",
            "source": "validated_run_export_static_config",
        }
    ]
    quality = analysis_contract.handler_result_quality(result, minimum_score=30_000)
    attempt["handler_evidence"] = quality

    document = handler_evidence.build_route_config_candidate_document(
        sha256=ROOT_SHA256,
        assessment=assessment,
    )

    assert quality["tier"] == 3
    assert quality["tier_name"] == "validated_static_configuration"
    assert quality["sufficient"] is True
    assert document["route_config_candidate_recovered"] is True
    assert document["candidates"][0]["recovery_type"] == "static_config_recovered"
    assert [
        item["endpoint"]
        for item in document["candidates"][0]["configured_network_candidates"]
    ] == ["198.51.100.24:441"]
    assert "127.0.0.1" not in repr(document)
    assert document["used_for_family_resolution"] is False
    assert document["used_for_c2_confirmation"] is False


def test_route_config_rejects_unknown_detector_non_corroboration_basis() -> None:
    """未定義のdetector非確証理由をroute候補の根拠へ流用しない。"""

    assessment = _route_only_assessment()
    assessment["families"][0]["attempts"][0]["detector_corroboration"][
        "basis"
    ] = "unreviewed_detector_state"

    document = handler_evidence.build_route_config_candidate_document(
        sha256=ROOT_SHA256,
        assessment=assessment,
    )

    assert document["route_config_candidate_recovered"] is False
    assert document["rejected_route_attempt_count"] == 1


def test_route_config_builder_rejects_loopback_endpoint() -> None:
    """抽出器が誤ってloopbackをendpointへ入れても候補全体をfail-closedにする。"""

    assessment = _route_only_assessment()
    attempt = assessment["families"][0]["attempts"][0]
    result = attempt["result"]["result"]
    result["config"]["endpoints"].append("127.0.0.1:80")
    result["findings"].append(
        {
            "kind": "network.endpoint",
            "value": "127.0.0.1:80",
            "role": "static_config_c2",
            "confidence": "confirmed_static_config",
            "source": "invalid_loopback_fixture",
        }
    )
    attempt["handler_evidence"] = analysis_contract.handler_result_quality(
        result,
        minimum_score=30_000,
    )

    document = handler_evidence.build_route_config_candidate_document(
        sha256=ROOT_SHA256,
        assessment=assessment,
    )

    assert document["route_config_candidate_recovered"] is False
    assert document["candidates"] == []
    assert document["rejected_route_attempt_count"] == 1


def test_partial_route_assessment_preserves_candidate_but_not_completeness() -> None:
    """budget枯渇前の有効候補は保持し、候補集合の網羅性は主張しない。"""

    assessment = _route_only_assessment()
    assessment["status"] = "partial"
    assessment["families"][0]["status"] = "partial_budget_exhausted"
    assessment["planned_attempt_count"] = 2
    assessment["unattempted_attempt_count"] = 1
    assessment["blockers"] = ["maximum_attempts_exhausted"]
    assessment["budget"]["exhausted"] = True

    document = handler_evidence.build_route_config_candidate_document(
        sha256=ROOT_SHA256,
        assessment=assessment,
    )

    assert document["status"] == "partial_route_config_candidates_recovered"
    assert document["route_config_candidate_recovered"] is True
    assert document["candidate_set_complete"] is False


def test_duplicate_route_config_attempt_is_deduplicated() -> None:
    """同一handler・layer・設定の重複試行を決定的に1件へ縮約する。"""

    assessment = _route_only_assessment()
    assessment["families"][0]["attempts"].append(
        copy.deepcopy(assessment["families"][0]["attempts"][0])
    )
    assessment["planned_attempt_count"] = 2
    assessment["actual_attempt_count"] = 2
    document = handler_evidence.build_route_config_candidate_document(
        sha256=ROOT_SHA256,
        assessment=assessment,
    )

    assert document["observed_candidate_count"] == 1
    assert document["candidate_count"] == 1


def test_route_config_does_not_copy_unrelated_url_fields() -> None:
    """証明書CRLやstage URLなどconfig endpoint以外の文字列を転記しない。"""

    assessment = _route_only_assessment()
    result = assessment["families"][0]["attempts"][0]["result"]["result"]
    result["urls"] = ["https://github.example.test/repository"]
    result["config"]["stage_urls"] = ["https://crl.example.test/certificate.crl"]
    assessment["families"][0]["attempts"][0]["handler_evidence"] = (
        analysis_contract.handler_result_quality(result, minimum_score=30_000)
    )

    document = handler_evidence.build_route_config_candidate_document(
        sha256=ROOT_SHA256,
        assessment=assessment,
    )

    rendered = repr(document)
    assert document["candidate_count"] == 1
    assert "github" not in rendered
    assert "certificate.crl" not in rendered


@pytest.mark.parametrize(
    "tamper",
    (
        "quality",
        "layer_sha256",
        "handler_family",
        "wrapper_execution",
        "inner_network",
        "quota",
        "boolean_flag",
        "finding_mismatch",
        "detector",
    ),
)
def test_route_config_projection_fails_closed(tamper: str) -> None:
    """lineage・品質・安全・設定相関の改変があればendpointを一切出さない。"""

    assessment = _route_only_assessment()
    attempt = assessment["families"][0]["attempts"][0]
    wrapper = attempt["result"]
    result = wrapper["result"]
    if tamper == "quality":
        attempt["handler_evidence"]["score"] += 1
    elif tamper == "layer_sha256":
        attempt["layer"]["sha256"] = RIGHT_SHA256
    elif tamper == "handler_family":
        wrapper["handler"]["family"] = "stealc"
    elif tamper == "wrapper_execution":
        wrapper["executed_sample"] = True
    elif tamper == "inner_network":
        result["network_contacted"] = True
    elif tamper == "quota":
        wrapper["result_quota"]["truncated"] = True
        wrapper["result_quota"]["reasons"] = ["maximum_entries"]
    elif tamper == "boolean_flag":
        result["config"]["static_config_recovered"] = 1
    elif tamper == "finding_mismatch":
        result["findings"][0]["value"] = "203.0.113.99:443"
    elif tamper == "detector":
        attempt["detector_corroboration"]["corroborated"] = True

    document = handler_evidence.build_route_config_candidate_document(
        sha256=ROOT_SHA256,
        assessment=assessment,
    )

    assert document["route_config_candidate_recovered"] is False
    assert document["candidates"] == []
    assert document["rejected_route_attempt_count"] == 1


def _pair(
    *,
    family: str,
    handler_name: str,
    layer_sha256: str,
    parent_sha256: str | None,
    host: str,
    candidate: str | None = None,
    evidence_kind: str = "decoded_config",
) -> tuple[dict, dict]:
    handler_id = f"{family}:{handler_name}.py:analyze"
    depth = 0 if parent_sha256 is None else 1
    result = {
        "sample_sha256": layer_sha256,
        "static_config_recovered": True,
        "c2": [
            {
                "host": host,
                "port": 443,
                "transport": "tls",
                "role": "tasking",
                "confidence": "confirmed_static_configuration",
                "evidence": {"kind": evidence_kind},
            }
        ],
        "config": {
            "static_config_recovered": True,
            "network_candidates": [candidate] if candidate is not None else [],
        },
    }
    execution = {
        "handler_id": handler_id,
        "status": "succeeded",
        "selected_layer_sha256": layer_sha256,
        "selected_evidence": {"sufficient": True, "tier": 4, "score": 8},
    }
    artifact = {
        "handler": {"id": handler_id, "family": family},
        "result": result,
        "selected_layer": {
            "sha256": layer_sha256,
            "parent_sha256": parent_sha256,
            "depth": depth,
        },
        "selected_evidence": {"sufficient": True, "tier": 4, "score": 8},
        "executed_sample": False,
        "network_contacted": False,
    }
    return execution, artifact


def test_winning_family_does_not_union_conflicting_family_output() -> None:
    """勝者familyへ別familyのendpoint・候補・handler IDを混入させない。"""

    winner = _pair(
        family="valleyrat",
        handler_name="winner",
        layer_sha256=ROOT_SHA256,
        parent_sha256=None,
        host="winner.example.test",
    )
    conflicting = _pair(
        family="stealc",
        handler_name="conflicting",
        layer_sha256=LEFT_SHA256,
        parent_sha256=ROOT_SHA256,
        host="other-family.example.test",
        candidate="https://user:secret@other-family.example/stage?token=secret",
    )

    document = handler_evidence.build_communication_pattern_document(
        sha256=ROOT_SHA256,
        family="ValleyRAT",
        handler_results=[winner, conflicting],
    )

    rendered = repr(document)
    assert document["config"]["static_config_recovered"] is True
    assert [record["host"] for record in document["communication"]["confirmed_static_endpoints"]] == [
        "winner.example.test"
    ]
    assert document["config"]["trusted_handler_ids"] == [winner[0]["handler_id"]]
    assert "other-family" not in rendered
    assert "user:secret" not in rendered
    assert "token=secret" not in rendered


def test_sibling_layers_with_conflicting_config_identity_fail_closed() -> None:
    """同一familyの兄弟layerが相反する完全configを示す場合は全確証を破棄する。"""

    left = _pair(
        family="valleyrat",
        handler_name="left",
        layer_sha256=LEFT_SHA256,
        parent_sha256=ROOT_SHA256,
        host="left.example.test",
    )
    right = _pair(
        family="valleyrat",
        handler_name="right",
        layer_sha256=RIGHT_SHA256,
        parent_sha256=ROOT_SHA256,
        host="right.example.test",
    )

    document = handler_evidence.build_communication_pattern_document(
        sha256=ROOT_SHA256,
        family="valleyrat",
        handler_results=[left, right],
    )

    assert document["status"] == "unresolved"
    assert document["config"]["static_config_recovered"] is False
    assert document["config"]["trusted_handler_ids"] == []
    assert document["communication"]["confirmed_static_endpoints"] == []
    assert document["communication"]["candidate_patterns"] == []
    assert "left.example" not in repr(document)
    assert "right.example" not in repr(document)


def test_same_family_and_layer_with_conflicting_identity_fail_closed() -> None:
    """lineageが同じでもendpoint集合が相反すればunionしない。"""

    first = _pair(
        family="valleyrat",
        handler_name="first",
        layer_sha256=LEFT_SHA256,
        parent_sha256=ROOT_SHA256,
        host="first.example.test",
    )
    second = _pair(
        family="valleyrat",
        handler_name="second",
        layer_sha256=LEFT_SHA256,
        parent_sha256=ROOT_SHA256,
        host="second.example.test",
    )

    document = handler_evidence.build_communication_pattern_document(
        sha256=ROOT_SHA256,
        family="valleyrat",
        handler_results=[first, second],
    )

    assert document["config"]["static_config_recovered"] is False
    assert document["communication"]["confirmed_static_endpoints"] == []
    assert document["communication"]["protocol_confirmed"] is False
    assert "first.example" not in repr(document)
    assert "second.example" not in repr(document)


def test_same_endpoint_with_conflicting_declared_identity_fails_closed() -> None:
    """endpointが同じでも既存の非秘密config identityが相反すれば確証しない。"""

    first = _pair(
        family="valleyrat",
        handler_name="identity_first",
        layer_sha256=LEFT_SHA256,
        parent_sha256=ROOT_SHA256,
        host="shared.example.test",
    )
    second = _pair(
        family="valleyrat",
        handler_name="identity_second",
        layer_sha256=LEFT_SHA256,
        parent_sha256=ROOT_SHA256,
        host="shared.example.test",
    )
    first[1]["result"]["config"]["vvas_recovery"] = {
        "configuration_identity_sha256": "1" * 64
    }
    second[1]["result"]["config"]["vvas_recovery"] = {
        "configuration_identity_sha256": "2" * 64
    }

    document = handler_evidence.build_communication_pattern_document(
        sha256=ROOT_SHA256,
        family="valleyrat",
        handler_results=[first, second],
    )

    assert document["config"]["static_config_recovered"] is False
    assert document["communication"]["confirmed_static_endpoints"] == []
    assert "configuration_identity" not in repr(document)
    assert "1" * 64 not in repr(document)
    assert "2" * 64 not in repr(document)


def test_same_lineage_and_config_identity_preserves_successful_projection() -> None:
    """同じendpoint集合を示す親子lineageの補完証拠は従来どおり投影する。"""

    parent = _pair(
        family="valleyrat",
        handler_name="parent",
        layer_sha256=ROOT_SHA256,
        parent_sha256=None,
        host="shared.example.test",
        candidate="https://parent-stage.example.test/payload",
        evidence_kind="decoded_config",
    )
    child = _pair(
        family="valleyrat",
        handler_name="child",
        layer_sha256=LEFT_SHA256,
        parent_sha256=ROOT_SHA256,
        host="shared.example.test",
        candidate="https://child-stage.example.test/payload",
        evidence_kind="validated_static_assignment",
    )
    parent[1]["result"]["config"]["vvas_recovery"] = {
        "configuration_identity_sha256": "3" * 64
    }
    child[1]["result"]["config"]["vvas_recovery"] = {
        "configuration_identity_sha256": "3" * 64
    }
    parent_duplicate = dict(parent[1]["result"]["c2"][0])
    parent_duplicate["evidence"] = {"kind": "second_validated_source"}
    parent[1]["result"]["c2"].append(parent_duplicate)

    document = handler_evidence.build_communication_pattern_document(
        sha256=ROOT_SHA256,
        family="valley-rat",
        handler_results=[parent, child],
    )

    assert document["status"] == "confirmed_static_configuration_patterns"
    assert document["config"]["static_config_recovered"] is True
    assert document["config"]["trusted_handler_ids"] == sorted(
        [parent[0]["handler_id"], child[0]["handler_id"]]
    )
    assert {
        record["host"]
        for record in document["communication"]["confirmed_static_endpoints"]
    } == {"shared.example.test"}
    assert {
        record["value"]
        for record in document["communication"]["candidate_patterns"]
    } == {
        "https://parent-stage.example.test/payload",
        "https://child-stage.example.test/payload",
    }
    assert "configuration_identity" not in repr(document)
    assert "3" * 64 not in repr(document)


def test_familyless_public_helpers_reject_multiple_family_projection() -> None:
    """勝者指定のない公開helperは複数familyを任意選択せずfail-closedにする。"""

    winner = _pair(
        family="valleyrat",
        handler_name="winner",
        layer_sha256=ROOT_SHA256,
        parent_sha256=None,
        host="winner.example.test",
    )
    other = _pair(
        family="stealc",
        handler_name="other",
        layer_sha256=LEFT_SHA256,
        parent_sha256=ROOT_SHA256,
        host="other.example.test",
    )

    assert handler_evidence.confirmed_static_handler_iocs([winner, other]) == []
    assert handler_evidence.static_config_recovered([winner, other], []) is False
    assert handler_evidence.candidate_communication_patterns([winner, other]) == []


def test_selected_layer_wrapper_mismatch_is_not_trusted() -> None:
    """executionとwrapperのselected layerを差し替えた成果物は投影しない。"""

    execution, artifact = _pair(
        family="valleyrat",
        handler_name="lineage_mismatch",
        layer_sha256=LEFT_SHA256,
        parent_sha256=ROOT_SHA256,
        host="must-not-project.example.test",
    )
    artifact["selected_layer"]["sha256"] = RIGHT_SHA256

    assert handler_evidence.trusted_handler_result(execution, artifact) is False
    document = handler_evidence.build_communication_pattern_document(
        sha256=ROOT_SHA256,
        family="valleyrat",
        handler_results=[(execution, artifact)],
    )
    assert document["status"] == "unresolved"
    assert "must-not-project" not in repr(document)


def test_selected_layer_requires_complete_artifact_lineage() -> None:
    """executionがlayerを選択した場合はwrapperとresultの両方へ同じhashを要求する。"""

    for mutation in ("missing_layer", "missing_layer_sha256", "missing_sample_sha256"):
        execution, artifact = _pair(
            family="valleyrat",
            handler_name=f"incomplete_{mutation}",
            layer_sha256=LEFT_SHA256,
            parent_sha256=ROOT_SHA256,
            host=f"{mutation}.example.test",
        )
        if mutation == "missing_layer":
            artifact.pop("selected_layer")
        elif mutation == "missing_layer_sha256":
            artifact["selected_layer"].pop("sha256")
        else:
            artifact["result"].pop("sample_sha256")

        assert handler_evidence.trusted_handler_result(execution, artifact) is False
        document = handler_evidence.build_communication_pattern_document(
            sha256=ROOT_SHA256,
            family="valleyrat",
            handler_results=[(execution, artifact)],
        )
        assert document["status"] == "unresolved"
        assert mutation not in repr(document)


def test_catalog_family_must_match_handler_id_prefix() -> None:
    """artifactのcatalog familyを別familyへ差し替えても投影しない。"""

    execution, artifact = _pair(
        family="valleyrat",
        handler_name="catalog_family_mismatch",
        layer_sha256=LEFT_SHA256,
        parent_sha256=ROOT_SHA256,
        host="catalog-family-mismatch.example.test",
    )
    artifact["handler"]["family"] = "stealc"

    assert handler_evidence.trusted_handler_result(execution, artifact) is False
    document = handler_evidence.build_communication_pattern_document(
        sha256=ROOT_SHA256,
        family="stealc",
        handler_results=[(execution, artifact)],
    )
    assert document["status"] == "unresolved"
    assert "catalog-family-mismatch" not in repr(document)


def test_handler_reported_family_must_match_catalog_family() -> None:
    """handler resultのfamily自己申告がcatalog／IDと異なる場合は投影しない。"""

    execution, artifact = _pair(
        family="valleyrat",
        handler_name="reported_family_mismatch",
        layer_sha256=LEFT_SHA256,
        parent_sha256=ROOT_SHA256,
        host="reported-family-mismatch.example.test",
    )
    artifact["result"]["family"] = "StealC"

    assert handler_evidence.trusted_handler_result(execution, artifact) is False
    document = handler_evidence.build_communication_pattern_document(
        sha256=ROOT_SHA256,
        family="valleyrat",
        handler_results=[(execution, artifact)],
    )
    assert document["status"] == "unresolved"
    assert "reported-family-mismatch" not in repr(document)


def test_handler_reported_family_allows_normalized_catalog_alias() -> None:
    """大文字・区切りだけが異なる同一familyの自己申告は従来どおり受理する。"""

    execution, artifact = _pair(
        family="valleyrat",
        handler_name="reported_family_alias",
        layer_sha256=LEFT_SHA256,
        parent_sha256=ROOT_SHA256,
        host="reported-family-alias.example.test",
    )
    artifact["result"]["family"] = "Valley-RAT"

    assert handler_evidence.trusted_handler_result(execution, artifact) is True
    document = handler_evidence.build_communication_pattern_document(
        sha256=ROOT_SHA256,
        family="valleyrat",
        handler_results=[(execution, artifact)],
    )
    assert document["config"]["static_config_recovered"] is True
    assert [
        record["host"]
        for record in document["communication"]["confirmed_static_endpoints"]
    ] == ["reported-family-alias.example.test"]
