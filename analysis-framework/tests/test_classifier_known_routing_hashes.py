"""既知hashのfamily帰属用集合と検証routing用集合の境界を検証する。"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from classifiers import classify_sample

FRAMEWORK_ROOT = Path(__file__).resolve().parents[1]
REGISTRY = FRAMEWORK_ROOT / "registry" / "malware_types.json"
B433_OUTER_SHA256 = (
    "b433ecdf855beaaf91d57522eebe9c9e1c3fc756f711bd79ac1b3ecf6c75016c"
)
FIVE_F8_OUTER_SHA256 = (
    "5f8daf53ef216151a72cb3fbb953886c74488b9d91b3a8afbc9bbf39e8d5eacf"
)
VALLEYRAT_ROUTING_HASHES = {
    "b856a8d469bae6f192b89f05c09a91b89682688a99a6c2bb8381d7d7cd28aab6",
    "2b3a2d1754db2dd0429d27c3636d1fd0050846fcd56c1440d4c879c58b536a76",
    "a81b2427fe5a5755207fd8a60d0e067cb212dac40f5f97f8854e614cf42d7e22",
    "8bf54a76924ad62e3b5562826f0e491c4c498f166276b071c177b694762199f6",
    B433_OUTER_SHA256,
    "f543dcf4f178e464c7b4dc24b463272417d8ada2a7d3a832e177f37e64f10cbd",
    "07ead27a736604b28876f4a0c940279983bd7076c2e1fed4039c4f0a81f3e0d5",
    "12b920865bc8bd9bad20650a0f7849fe2856de3d72bc5f1a93bb288e8eefaca2",
    "5876be168613a5e77024f79dad518662e8fd418f01d5839fc7e73ecb0f085a92",
    "9a9d372cc821b6d2f7e30abb80aff7cae841703db0fb78bd859e6581420fbc07",
    "0f963f03d73f3f874928d744e8188b3f61470f982ab1100a5645d0a3c27ee611",
    "a0eb29beacb4463ed88b579625a1483245dff067697b85d93fd62992c5512489",
    FIVE_F8_OUTER_SHA256,
    "b3369a20d7c603b4d1078010b008a9db1b49dccf694a05e6bd49ede2762a8075",
    "8715bb53fad907f12ab1b5ec7bad49d2a4f72bf07f81bb2a6621fd1f9f55ffa1",
    "edb371be39673ca248b4dcb168de0efd90e9d7a39d7cc096c83c435bd6fe260b",
    "a0d1e6b471522635bcf7ca0176d6ee8febcf90184078b5e8ce24e0eca970b532",
}


def _registry(
    tmp_path: Path,
    *,
    known_samples: list[str] | None = None,
    known_routing: list[str] | None = None,
) -> Path:
    path = tmp_path / "registry.json"
    path.write_text(
        json.dumps(
            {
                "malware_types": {
                    "valleyrat": {
                        "description": "test",
                        "detector": "malware/valleyrat/detect.py",
                        "known_sample_sha256": known_samples or [],
                        "known_routing_sha256": known_routing or [],
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    return path


def _unmatched_detector(_data: bytes, _source: Path) -> dict:
    return {"matched": False, "observations": {}, "campaigns": []}


def _strong_detector(_data: bytes, _source: Path) -> dict:
    return {
        "matched": True,
        "observations": {
            "validated_terminal_structure": {
                "static_config_recovered": True,
            }
        },
        "campaigns": [
            {
                "campaign_type": "vvas_reversed_config_terminal",
                "confidence": "high",
                "reasons": ["一意な復号設定と終端構造"],
                "supports_family_attribution": True,
                "terminal_family_confirmed": True,
                "attribution_scope": "validated_terminal_component_structure",
            }
        ],
    }


def _classify(
    data: bytes,
    registry: Path,
    monkeypatch: pytest.MonkeyPatch,
    detector,
) -> tuple[dict, dict]:
    monkeypatch.setattr(
        classify_sample,
        "load_detector",
        lambda _root, _path, _family=None: detector,
    )
    assessment = classify_sample.evaluate_detectors(
        data,
        Path("submitted.bin"),
        registry,
        malware_type="valleyrat",
    )
    classification = classify_sample._classify_evaluations(
        Path("submitted.bin"),
        assessment,
        None,
    )
    return assessment, classification


def _routing(classifications: list[tuple[str, int, dict]]) -> dict:
    return classify_sample.build_family_routing_candidates(
        [
            {
                "layer": {"sha256": digest, "depth": depth},
                "classification": classification,
            }
            for digest, depth, classification in classifications
        ],
        family_coverage=[
            {
                "family": "valleyrat",
                "status": "automatic_handler_available",
                "detector_registered": True,
                "automatic_handlers": ["extractors.valleyrat.extractor.py"],
                "manual_or_unsupported_handlers": [],
            }
        ],
    )


def test_real_registry_separates_all_valleyrat_routing_hashes() -> None:
    """現行17件は全て検証専用で、family帰属用集合は空に保つ。"""

    registry = classify_sample._validated_registry(REGISTRY)
    valleyrat = registry["valleyrat"]

    assert valleyrat["known_sample_sha256"] == []
    assert set(valleyrat["known_routing_sha256"]) == VALLEYRAT_ROUTING_HASHES
    assert len(valleyrat["known_routing_sha256"]) == len(
        set(valleyrat["known_routing_sha256"])
    )


@pytest.mark.parametrize(
    ("known_samples", "known_routing", "error"),
    (
        ([], ["x"], "known_routing_sha256 contains an invalid digest"),
        (["b" * 64, "B" * 64], [], "known_sample_sha256 contains a duplicate digest"),
        ([], ["a" * 64, "A" * 64], "known_routing_sha256 contains a duplicate digest"),
        (["a" * 64], ["A" * 64], "must be disjoint"),
    ),
)
def test_registry_rejects_invalid_duplicate_and_overlapping_hashes(
    tmp_path: Path,
    known_samples: list[str],
    known_routing: list[str],
    error: str,
) -> None:
    """両hash集合をcase-insensitiveに厳格検証し、曖昧なschemaを拒否する。"""

    registry = _registry(
        tmp_path,
        known_samples=known_samples,
        known_routing=known_routing,
    )
    with pytest.raises(TypeError, match=error):
        classify_sample._validated_registry(registry)


def test_routing_hash_alone_is_unknown_but_automatic_candidate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """routing hash単独では帰属せず、静的handler検証候補だけを生成する。"""

    data = b"routing-only outer fixture"
    digest = hashlib.sha256(data).hexdigest()
    registry = _registry(tmp_path, known_routing=[digest])
    assessment, classification = _classify(
        data,
        registry,
        monkeypatch,
        _unmatched_detector,
    )
    evaluation = assessment["evaluations"][0]
    routing = _routing([(digest, 0, classification)])
    candidate = routing["candidates"][0]

    assert evaluation["known_outer_sha256"] is False
    assert evaluation["known_routing_sha256"] is True
    assert evaluation["applicable"] is True
    assert evaluation["automatic_route_eligible"] is True
    assert evaluation["supports_family_attribution"] is False
    assert classification["malware_type"] == "unknown"
    assert routing["selected_families"] == []
    assert routing["verification_only_families"] == ["valleyrat"]
    assert candidate["routing_mode"] == "candidate_verification"
    assert candidate["layer_sha256"] == [digest]
    assert candidate["layer_support"][0]["known_routing_sha256"] is True
    assert any(
        item["kind"] == "known_routing_sha256"
        and item["supports_attribution"] is False
        for item in candidate["evidence"]
    )


def test_b433_outer_hash_does_not_regain_attribution_after_unwrap_miss(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """外装hashだけ一致し、unwrap後detectorが不一致でもhighへ戻さない。"""

    monkeypatch.setattr(
        classify_sample,
        "hashlib",
        SimpleNamespace(
            sha256=lambda _data: SimpleNamespace(
                hexdigest=lambda: B433_OUTER_SHA256
            )
        ),
    )
    assessment, classification = _classify(
        b"outer MSI bytes are intentionally not retained",
        REGISTRY,
        monkeypatch,
        _unmatched_detector,
    )
    evaluation = assessment["evaluations"][0]
    routing = _routing([(B433_OUTER_SHA256, 0, classification)])

    assert evaluation["known_routing_sha256"] is True
    assert evaluation["detector_matched"] is False
    assert evaluation["supports_family_attribution"] is False
    assert classification["malware_type"] == "unknown"
    assert routing["automatic_analysis_families"] == []
    assert routing["verification_only_families"] == ["valleyrat"]


def test_5f8_delivery_structure_does_not_confirm_terminal_family(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """配布MSI構造がmatchedでも終端明示なしではrouting hashを昇格しない。"""

    monkeypatch.setattr(
        classify_sample,
        "hashlib",
        SimpleNamespace(
            sha256=lambda _data: SimpleNamespace(
                hexdigest=lambda: FIVE_F8_OUTER_SHA256
            )
        ),
    )
    assessment, classification = _classify(
        b"outer MSI bytes are intentionally not retained",
        REGISTRY,
        monkeypatch,
        lambda _data, _source: {
            "matched": True,
            "observations": {"delivery_structure": {"msi": True}},
            "campaigns": [
                {
                    "campaign_type": "msi_embedded_cab_custom_actions",
                    "confidence": "medium",
                    "reasons": ["MSI/CABと保護PEの配布構造"],
                }
            ],
        },
    )
    evaluation = assessment["evaluations"][0]
    routing = _routing([(FIVE_F8_OUTER_SHA256, 0, classification)])

    assert evaluation["known_routing_sha256"] is True
    assert evaluation["detector_matched"] is True
    assert evaluation["supports_family_attribution"] is False
    assert classification["malware_type"] == "unknown"
    assert routing["automatic_analysis_families"] == []
    assert routing["verification_only_families"] == ["valleyrat"]


def test_routing_hash_allows_attribution_only_with_strong_detector(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """同じlayerに終端構造証拠がある場合だけ通常family帰属へ進める。"""

    data = b"routing hash with independently validated terminal structure"
    digest = hashlib.sha256(data).hexdigest()
    registry = _registry(tmp_path, known_routing=[digest])
    assessment, classification = _classify(
        data,
        registry,
        monkeypatch,
        _strong_detector,
    )
    routing = _routing([(digest, 0, classification)])
    evidence = routing["candidates"][0]["evidence"]

    assert assessment["evaluations"][0]["supports_family_attribution"] is True
    assert classification["malware_type"] == "valleyrat"
    assert classification["attribution_basis"] == "type_detector_structure"
    assert routing["automatic_analysis_families"] == ["valleyrat"]
    assert any(
        item["kind"] == "known_routing_sha256"
        and item["supports_attribution"] is False
        for item in evidence
    )
    assert any(
        item["kind"] == "type_detector_structure"
        and item["supports_attribution"] is True
        for item in evidence
    )


def test_routing_hash_rejects_bare_matched_boolean_without_campaign_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """matched booleanだけではrouting-only境界を越えてfamily帰属しない。"""

    data = b"routing hash with bare matched boolean"
    digest = hashlib.sha256(data).hexdigest()
    registry = _registry(tmp_path, known_routing=[digest])
    assessment, classification = _classify(
        data,
        registry,
        monkeypatch,
        lambda _data, _source: {
            "matched": True,
            "observations": {},
            "campaigns": [],
        },
    )
    routing = _routing([(digest, 0, classification)])

    assert assessment["evaluations"][0]["detector_matched"] is True
    assert assessment["evaluations"][0]["supports_family_attribution"] is False
    assert classification["malware_type"] == "unknown"
    assert routing["automatic_analysis_families"] == []
    assert routing["verification_only_families"] == ["valleyrat"]


def test_strong_descendant_evidence_resolves_routing_only_outer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """外装は候補のまま保ち、復元子の終端証拠で初めてfamilyを解決する。"""

    outer = b"routing-only outer"
    child = b"validated terminal child"
    outer_digest = hashlib.sha256(outer).hexdigest()
    child_digest = hashlib.sha256(child).hexdigest()
    registry = _registry(tmp_path, known_routing=[outer_digest])

    def detector(data: bytes, source: Path) -> dict:
        return _strong_detector(data, source) if data == child else _unmatched_detector(data, source)

    monkeypatch.setattr(
        classify_sample,
        "load_detector",
        lambda _root, _path, _family=None: detector,
    )
    outer_assessment = classify_sample.evaluate_detectors(
        outer,
        Path("outer.bin"),
        registry,
        malware_type="valleyrat",
    )
    child_assessment = classify_sample.evaluate_detectors(
        child,
        Path("child.bin"),
        registry,
        malware_type="valleyrat",
    )
    outer_classification = classify_sample._classify_evaluations(
        Path("outer.bin"), outer_assessment, None
    )
    child_classification = classify_sample._classify_evaluations(
        Path("child.bin"), child_assessment, None
    )
    routing = _routing(
        [
            (outer_digest, 0, outer_classification),
            (child_digest, 1, child_classification),
        ]
    )
    candidate = routing["candidates"][0]

    assert outer_classification["malware_type"] == "unknown"
    assert child_classification["malware_type"] == "valleyrat"
    assert routing["selected_families"] == ["valleyrat"]
    assert routing["automatic_analysis_families"] == ["valleyrat"]
    assert candidate["selected_layer_indexes"] == [1]
    assert {
        (item["kind"], item["layer_sha256"], item["supports_attribution"])
        for item in candidate["evidence"]
    } >= {
        ("known_routing_sha256", outer_digest, False),
        ("type_detector_structure", child_digest, True),
    }


def test_known_sample_hash_remains_attribution_bearing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """明示的にfamily確認済みのknown_sampleは従来どおりhigh帰属に使う。"""

    data = b"terminal family-confirmed fixture"
    digest = hashlib.sha256(data).hexdigest()
    registry = _registry(tmp_path, known_samples=[digest])
    assessment, classification = _classify(
        data,
        registry,
        monkeypatch,
        _unmatched_detector,
    )

    assert assessment["evaluations"][0]["known_outer_sha256"] is True
    assert assessment["evaluations"][0]["known_routing_sha256"] is False
    assert assessment["evaluations"][0]["supports_family_attribution"] is True
    assert classification["malware_type"] == "valleyrat"
    assert classification["malware_type_confidence"] == "high"
    assert classification["attribution_basis"] == "known_outer_sha256"
