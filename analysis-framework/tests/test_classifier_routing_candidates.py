"""既知family候補routingと外部hint manifestのfail-closed回帰テスト。"""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

import pytest

from classifiers import classify_sample


ROOT_SHA = "a" * 64
CHILD_SHA = "b" * 64


def _evaluation(
    family: str,
    *,
    matched: bool = False,
    known_outer: bool = False,
    known_inner: bool = False,
    error: str | None = None,
) -> dict:
    """テスト用のdetector評価を共通shapeで作る。"""

    return {
        "malware_type": family,
        "detector": f"malware/{family}/detect.py",
        "known_outer_sha256": known_outer,
        "known_inner_sha256": known_inner,
        "detector_matched": matched,
        "applicable": matched or known_outer or known_inner,
        "automatic_route_eligible": bool(not error and (matched or known_outer or known_inner)),
        "error": error,
        "detection": {"matched": matched, "observations": {}, "campaigns": []},
    }


def _layer(
    digest: str,
    *,
    selected: str = "unknown",
    confidence: str = "low",
    basis: str = "none",
    evaluations: list[dict] | None = None,
    depth: int = 0,
) -> dict:
    """テスト用の公開layer classificationを作る。"""

    return {
        "layer": {"sha256": digest, "depth": depth},
        "classification": {
            "malware_type": selected,
            "malware_type_confidence": confidence,
            "attribution_basis": basis,
            "detector_evaluations": evaluations or [],
            "observations": {"sha256": digest},
        },
    }


def _coverage(
    family: str,
    *,
    detector_registered: bool,
    automatic_handlers: list[str],
) -> dict:
    """one-shot family coverageと同じ最小shapeを作る。"""

    return {
        "family": family,
        "status": (
            "automatic_handler_available"
            if detector_registered
            else "handler_without_registered_detector"
        ),
        "detector_registered": detector_registered,
        "automatic_handlers": automatic_handlers,
        "manual_or_unsupported_handlers": [],
    }


def test_selected_family_and_metadata_verification_route_are_separated() -> None:
    """一意detector一致とmetadata-only候補を異なるrouteへ分離する。"""

    layers = [
        _layer(
            ROOT_SHA,
            selected="valleyrat",
            confidence="medium",
            basis="type_detector_structure",
            evaluations=[_evaluation("valleyrat", matched=True)],
        )
    ]
    hints = [
        {
            "family": "nanocore",
            "source": "malwarebazaar",
            "provenance": "reported_signature",
            "confidence": "high",
            "label": "NanoCore",
        }
    ]
    result = classify_sample.build_family_routing_candidates(
        layers,
        metadata_hints=hints,
        family_coverage=[
            _coverage(
                "valleyrat",
                detector_registered=True,
                automatic_handlers=["valleyrat.extract_config"],
            ),
            _coverage(
                "nanocore",
                detector_registered=False,
                automatic_handlers=["nanocore.extract_config"],
            ),
        ],
    )
    by_family = {item["family"]: item for item in result["candidates"]}

    assert result["selected_families"] == ["valleyrat"]
    assert result["automatic_analysis_families"] == ["valleyrat"]
    assert result["verification_only_families"] == ["nanocore"]
    assert result["metadata_hints_used_for_attribution"] is False
    assert by_family["valleyrat"]["routing_eligibility"] == {
        "mode": "selected_family_analysis",
        "selected_family_analysis": True,
        "candidate_verification": False,
        "family_attribution": True,
        "reason_codes": [
            "automatic_handler_available",
            "unambiguous_detector_selection",
        ],
    }
    assert by_family["nanocore"]["confidence"] == "unverified"
    assert by_family["nanocore"]["source"] == "external_metadata"
    assert by_family["nanocore"]["source_strength"] == "unverified"
    assert by_family["nanocore"]["routing_eligible"] is True
    assert by_family["nanocore"]["routing_mode"] == "candidate_verification"
    assert by_family["nanocore"]["layer_sha256"] == [ROOT_SHA]
    assert by_family["nanocore"]["metadata_only"] is True
    assert by_family["nanocore"]["capabilities"]["registry_detector_gap"] is True
    assert by_family["nanocore"]["routing_eligibility"]["family_attribution"] is False
    assert by_family["nanocore"]["routing_eligibility"]["candidate_verification"] is True


def test_metadata_hint_alone_never_selects_family() -> None:
    """provider confidenceがhighでもmetadata単独ではfamily確定しない。"""

    result = classify_sample.build_family_routing_candidates(
        [_layer(ROOT_SHA)],
        metadata_hints=[
            {
                "family": "wannacry",
                "source": "malwarebazaar",
                "provenance": "reported_signature",
                "confidence": "high",
            }
        ],
        family_coverage=[
            _coverage(
                "wannacry",
                detector_registered=False,
                automatic_handlers=["wannacry.unpack"],
            )
        ],
    )
    candidate = result["candidates"][0]

    assert result["selected_families"] == []
    assert result["automatic_analysis_families"] == []
    assert candidate["confidence"] == "unverified"
    assert candidate["routing_eligibility"]["mode"] == "candidate_verification"
    assert candidate["routing_eligibility"]["family_attribution"] is False
    assert all(item["supports_attribution"] is False for item in candidate["evidence"])


def test_ambiguous_detector_matches_are_verification_only() -> None:
    """同順位detector候補はregistry順で選ばず両方を検証候補にする。"""

    layers = [
        _layer(
            ROOT_SHA,
            basis="ambiguous_type_detection",
            evaluations=[
                _evaluation("asyncrat", matched=True),
                _evaluation("venomrat", matched=True),
            ],
        )
    ]
    result = classify_sample.build_family_routing_candidates(
        layers,
        family_coverage=[
            _coverage(
                "asyncrat",
                detector_registered=True,
                automatic_handlers=["asyncrat.extract"],
            ),
            _coverage(
                "venomrat",
                detector_registered=True,
                automatic_handlers=["venomrat.extract"],
            ),
        ],
    )

    assert result["selected_families"] == []
    assert result["automatic_analysis_families"] == []
    assert result["verification_only_families"] == ["asyncrat", "venomrat"]
    assert all(
        item["routing_eligibility"]["family_attribution"] is False
        for item in result["candidates"]
    )


def test_all_layer_detector_evidence_is_retained_and_ranked() -> None:
    """root以外の復元layerで得たdetector証拠とlayer identityを保持する。"""

    layers = [
        _layer(ROOT_SHA, evaluations=[_evaluation("valleyrat")]),
        _layer(
            CHILD_SHA,
            selected="valleyrat",
            confidence="high",
            basis="known_inner_sha256",
            evaluations=[_evaluation("valleyrat", matched=True, known_inner=True)],
            depth=1,
        ),
    ]
    result = classify_sample.build_family_routing_candidates(
        layers,
        family_coverage=[
            _coverage(
                "valleyrat",
                detector_registered=True,
                automatic_handlers=["valleyrat.extract"],
            )
        ],
    )
    candidate = result["candidates"][0]

    assert candidate["rank"] == 1
    assert candidate["confidence"] == "high"
    assert candidate["source"] == "detector"
    assert candidate["source_strength"] == "high"
    assert candidate["routing_eligible"] is True
    assert candidate["layer_sha256"] == [CHILD_SHA]
    assert {item["layer_sha256"] for item in candidate["layer_support"]} == {
        ROOT_SHA,
        CHILD_SHA,
    }
    assert any(
        item["kind"] == "known_inner_sha256" and item["layer_sha256"] == CHILD_SHA
        for item in candidate["evidence"]
    )
    assert candidate["selected_layer_indexes"] == [1]


def test_metadata_priority_cannot_outrank_detector_evidence() -> None:
    """metadataのprovider confidenceはdetector confidenceを上書きしない。"""

    layers = [
        _layer(
            ROOT_SHA,
            selected="valleyrat",
            confidence="medium",
            basis="type_detector_structure",
            evaluations=[_evaluation("valleyrat", matched=True)],
        )
    ]
    result = classify_sample.build_family_routing_candidates(
        layers,
        metadata_hints=[
            {
                "family": "nanocore",
                "source": "provider",
                "provenance": "signature",
                "confidence": "high",
            }
        ],
        family_coverage=[
            _coverage("valleyrat", detector_registered=True, automatic_handlers=[]),
            _coverage("nanocore", detector_registered=False, automatic_handlers=[]),
        ],
    )

    assert [item["family"] for item in result["candidates"]] == [
        "valleyrat",
        "nanocore",
    ]
    assert result["candidates"][0]["confidence"] == "medium"
    assert result["candidates"][1]["confidence"] == "unverified"


def test_routing_api_does_not_mutate_existing_classification() -> None:
    """候補生成は既存selected_family相当の分類結果を変更しない。"""

    layers = [_layer(ROOT_SHA)]
    before = deepcopy(layers)
    classify_sample.build_family_routing_candidates(
        layers,
        metadata_hints=[
            {
                "family": "nanocore",
                "source": "provider",
                "provenance": "signature",
                "confidence": "medium",
            }
        ],
    )
    assert layers == before
    assert layers[0]["classification"]["malware_type"] == "unknown"


def test_detector_error_suppresses_selected_family_analysis() -> None:
    """既知hashが一致してもdetector errorがあれば通常解析routeへ送らない。"""

    result = classify_sample.build_family_routing_candidates(
        [
            _layer(
                ROOT_SHA,
                selected="valleyrat",
                confidence="high",
                basis="known_outer_sha256",
                evaluations=[
                    _evaluation(
                        "valleyrat",
                        known_outer=True,
                        error="RuntimeError: detector failed",
                    )
                ],
            )
        ],
        family_coverage=[
            _coverage(
                "valleyrat",
                detector_registered=True,
                automatic_handlers=["valleyrat.extract"],
            )
        ],
    )
    candidate = result["candidates"][0]

    assert result["automatic_analysis_families"] == []
    assert result["verification_only_families"] == ["valleyrat"]
    assert candidate["routing_mode"] == "candidate_verification"
    assert candidate["layer_support"][0]["detector_error"]


def test_metadata_hint_without_any_layer_is_blocked() -> None:
    """解析対象layerがなければmetadata候補handlerも実行可能にしない。"""

    result = classify_sample.build_family_routing_candidates(
        [],
        metadata_hints=[
            {
                "family": "nanocore",
                "source": "provider",
                "provenance": "signature",
                "confidence": "medium",
            }
        ],
        family_coverage=[
            _coverage(
                "nanocore",
                detector_registered=False,
                automatic_handlers=["nanocore.extract"],
            )
        ],
    )
    candidate = result["candidates"][0]

    assert candidate["routing_eligible"] is False
    assert candidate["routing_mode"] == "blocked"
    assert candidate["layer_sha256"] == []


def test_publication_summary_conversion_preserves_provenance() -> None:
    """既存publication-summaryをSHA-256 keyed hintへ損失なく変換する。"""

    summary = {
        "cases": [
            {
                "sha256": ROOT_SHA,
                "family": "nanocore",
                "reported_signature": "NanoCore",
                "attribution_basis": "malwarebazaar_reported_signature",
                "first_seen": "2026-08-09 18:15:05",
            },
            {
                "sha256": CHILD_SHA,
                "family": "unclassified",
                "attribution_basis": "no_supported_family_evidence",
            },
        ]
    }
    manifest = classify_sample.family_hint_manifest_from_publication_summary(summary)
    hints = classify_sample.family_hints_for_sha256(manifest, ROOT_SHA)

    assert list(manifest["samples"]) == [ROOT_SHA]
    assert hints == [
        {
            "family": "nanocore",
            "source": "malwarebazaar_publication_summary",
            "provenance": "publication-summary:malwarebazaar_reported_signature",
            "confidence": "unverified",
            "label": "NanoCore",
            "observed_at": "2026-08-09 18:15:05",
        }
    ]


def test_hint_manifest_loader_is_strict_and_preserves_fields(tmp_path: Path) -> None:
    """loaderは正当なhintを保持し、未知fieldと重複keyを拒否する。"""

    path = tmp_path / "hints.json"
    document = {
        "schema_version": 1,
        "samples": {
            ROOT_SHA.upper(): [
                {
                    "family": "nanocore",
                    "source": "malwarebazaar",
                    "provenance": "reported_signature",
                    "confidence": "medium",
                    "label": "NanoCore",
                }
            ]
        },
    }
    path.write_text(json.dumps(document), encoding="utf-8")
    loaded = classify_sample.load_family_hint_manifest(path)

    assert list(loaded["samples"]) == [ROOT_SHA]
    assert loaded["samples"][ROOT_SHA][0]["source"] == "malwarebazaar"
    assert loaded["samples"][ROOT_SHA][0]["confidence"] == "medium"

    document["unexpected"] = True
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(classify_sample.FamilyHintManifestError, match="unknown fields"):
        classify_sample.load_family_hint_manifest(path)

    path.write_text(
        '{"schema_version":1,"schema_version":1,"samples":{}}',
        encoding="utf-8",
    )
    with pytest.raises(classify_sample.FamilyHintManifestError, match="duplicate JSON key"):
        classify_sample.load_family_hint_manifest(path)


@pytest.mark.parametrize(
    "document",
    [
        {"schema_version": 2, "samples": {}},
        {"schema_version": True, "samples": {}},
        {"schema_version": 1, "samples": {"not-a-hash": []}},
        {
            "schema_version": 1,
            "samples": {
                ROOT_SHA: [
                    {
                        "family": "unknown",
                        "source": "provider",
                        "provenance": "tag",
                        "confidence": "low",
                    }
                ]
            },
        },
        {
            "schema_version": 1,
            "samples": {
                ROOT_SHA: [
                    {
                        "family": "nanocore",
                        "source": "provider",
                        "provenance": "tag",
                        "confidence": "certain",
                    }
                ]
            },
        },
    ],
)
def test_hint_manifest_rejects_invalid_documents(document: dict) -> None:
    """不正schema、hash、sentinel family、confidenceをfail-closedで拒否する。"""

    with pytest.raises(classify_sample.FamilyHintManifestError):
        classify_sample.normalize_family_hint_manifest(document)


def test_routing_rejects_non_list_metadata_hints() -> None:
    """曖昧なmapping入力をhint列として黙って反復しない。"""

    with pytest.raises(TypeError, match="metadata_hints must be a list"):
        classify_sample.build_family_routing_candidates(
            [_layer(ROOT_SHA)],
            metadata_hints={"family": "nanocore"},  # type: ignore[arg-type]
        )
