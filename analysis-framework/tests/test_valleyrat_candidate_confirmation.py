"""ValleyRAT候補handlerのfamily確認境界を検証する。"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

COMMON_ROOT = Path(__file__).resolve().parents[1] / "common"
if str(COMMON_ROOT) not in sys.path:
    sys.path.insert(0, str(COMMON_ROOT))

import handler_catalog as catalog  # noqa: E402


def _spec() -> catalog.HandlerSpec:
    return catalog.HandlerSpec(
        id="valleyrat:fixture:extract",
        family="valleyrat",
        relative_path="unused-by-mocked-executor.py",
        callable_name="extract",
        invocation="bytes",
        source="shared_extractor",
        automatic=True,
        campaign=None,
        supported_interface=True,
        reason="synthetic_static_fixture",
        input_formats=("data",),
        input_contract_source="module_declaration",
        minimum_evidence_score=30_000,
    )


def _candidate() -> dict:
    return {
        "family": "valleyrat",
        "sources": ["detector"],
        "routing_eligible": True,
        "routing_mode": "candidate_verification",
        "routing_eligibility": {"candidate_verification": True},
        "rank": 1,
        "rank_score": 441,
    }


def _layer() -> dict:
    data = b"synthetic-valleyrat-candidate"
    return {
        "name": "candidate.bin",
        "data": data,
        "sha256": hashlib.sha256(data).hexdigest(),
        "parent_sha256": None,
        "depth": 0,
        "transform": "synthetic_fixture",
        "format": "data",
    }


def _detector(layer_sha256: str) -> dict:
    return {
        "valleyrat": {
            layer_sha256: {
                "known_outer_sha256": False,
                "known_inner_sha256": False,
                "known_routing_sha256": False,
                "detector_matched": True,
                "applicable": True,
                "automatic_route_eligible": True,
                "error": None,
                "supports_family_attribution": True,
                "detection": {
                    "matched": True,
                    "observations": {
                        "marker_hits": ["independent-terminal-marker"]
                    },
                    "campaigns": [],
                },
            }
        }
    }


def _completed(result: dict) -> dict:
    return {
        "status": "completed",
        "preflight": {"eligible": True, "blockers": []},
        "execution": {
            "result": result,
            "result_quota": {"truncated": False},
            "verified_binary_output_audit": {"observed_output_count": 0},
        },
    }


def _assess(
    monkeypatch: pytest.MonkeyPatch,
    handler_result: dict,
) -> dict:
    layer = _layer()
    monkeypatch.setattr(
        catalog,
        "execute_handler_bounded_for_assessment",
        lambda *_args, **_kwargs: _completed(handler_result),
    )
    return catalog.assess_candidate_handlers(
        [_candidate()],
        [layer],
        detector_evaluations=_detector(layer["sha256"]),
        specs=[_spec()],
        maximum_attempts=1,
    )


def test_route_only_static_config_cannot_confirm_candidate_family(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """明示的にroute-onlyの設定をdetector scoreでfamily確定へ昇格しない。"""

    result = _assess(
        monkeypatch,
        {
            "family": "valleyrat",
            "supports_family_attribution": False,
            "terminal_family_confirmed": False,
            "config": {
                "static_config_recovered": True,
                "terminal_family_confirmed": False,
                "attribution_scope": "component_handler_route",
                "endpoints": ["198.51.100.24:443"],
            },
            "executed": False,
            "network_contacted": False,
        },
    )

    family = result["families"][0]
    assert result["confirmed_families"] == []
    assert family["confirmed"] is False
    assert family["status"] == "handler_evidence_route_only"
    assert family["attempts"][0]["status"] == "handler_evidence_route_only"


def test_terminal_static_config_still_confirms_candidate_family(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """終端family・設定・detector裏付けが揃う既存の確認経路を維持する。"""

    result = _assess(
        monkeypatch,
        {
            "family": "valleyrat",
            "supports_family_attribution": True,
            "terminal_family_confirmed": True,
            "config": {
                "static_config_recovered": True,
                "terminal_family_confirmed": True,
                "attribution_scope": "validated_terminal_component_structure",
                "endpoints": ["198.51.100.24:443"],
            },
            "executed": False,
            "network_contacted": False,
        },
    )

    family = result["families"][0]
    assert result["confirmed_families"] == ["valleyrat"]
    assert family["confirmed"] is True
    assert family["attempts"][0]["status"] == "corroborated"


def test_non_boolean_attribution_flag_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """文字列による真偽値偽装をdetector scoreでfamily確定しない。"""

    result = _assess(
        monkeypatch,
        {
            "family": "valleyrat",
            "supports_family_attribution": "true",
            "config": {
                "static_config_recovered": True,
                "endpoints": ["198.51.100.24:443"],
            },
            "executed": False,
            "network_contacted": False,
        },
    )

    family = result["families"][0]
    attempt = family["attempts"][0]
    assert result["confirmed_families"] == []
    assert family["status"] == "handler_attribution_contract_invalid"
    assert attempt["status"] == "handler_attribution_contract_invalid"
    assert attempt["handler_family_attribution"]["basis"] == (
        "result_supports_family_attribution_not_boolean"
    )


def test_conflicting_nested_attribution_flags_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """top-levelとconfigの相反する帰属フラグを拒否する。"""

    result = _assess(
        monkeypatch,
        {
            "family": "valleyrat",
            "supports_family_attribution": True,
            "terminal_family_confirmed": True,
            "config": {
                "static_config_recovered": True,
                "supports_family_attribution": False,
                "terminal_family_confirmed": False,
                "attribution_scope": "component_handler_route",
            },
            "executed": False,
            "network_contacted": False,
        },
    )

    family = result["families"][0]
    attempt = family["attempts"][0]
    assert result["confirmed_families"] == []
    assert family["status"] == "handler_attribution_contract_invalid"
    assert attempt["handler_family_attribution"]["basis"] == (
        "handler_attribution_flags_conflict"
    )
