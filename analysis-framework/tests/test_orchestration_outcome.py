"""AI非依存オーケストレーションのfamily解決と品質ゲートを検証する。"""

from __future__ import annotations

from pathlib import Path
import sys


COMMON = Path(__file__).resolve().parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

from orchestration_outcome import (  # noqa: E402
    build_outcome,
    resolve_family,
    summarize_handler_outputs,
)


SHA256 = "a" * 64


def _record(family: str, payload: object, *, status: str = "succeeded") -> dict[str, object]:
    return {
        "family": family,
        "handler_id": f"{family}:extract",
        "status": status,
        "result": {"result": payload},
    }


def test_known_hash_can_resolve_without_handler() -> None:
    result = resolve_family(
        [{"family": "ValleyRAT", "source": "known_hash", "routing_eligible": True}],
        [],
    )
    assert result["status"] == "resolved"
    assert result["family"] == "valleyrat"


def test_external_metadata_requires_validated_static_configuration() -> None:
    candidate = [{"family": "nanocore", "source": "external_metadata"}]
    weak = _record("nanocore", {"capabilities": ["remote_shell"]})
    assert resolve_family(candidate, [weak])["status"] == "unresolved"

    strong = _record(
        "nanocore",
        {
            "static_config_recovered": True,
            "config": {"campaign": "fixture"},
        },
    )
    assert resolve_family(candidate, [strong])["family"] == "nanocore"


def test_detector_candidate_accepts_structural_corroboration() -> None:
    result = resolve_family(
        [{"family": "quasarrat", "source": "detector_candidate"}],
        [_record("quasarrat", {"capabilities": ["file_manager"]})],
    )
    assert result["status"] == "resolved"
    assert result["handler_tier"] == 2


def test_equal_best_families_remain_ambiguous() -> None:
    result = resolve_family(
        [
            {"family": "family-a", "source": "detector_candidate"},
            {"family": "family-b", "source": "detector_candidate"},
        ],
        [
            _record("family-a", {"capabilities": ["x"]}),
            _record("family-b", {"capabilities": ["x"]}),
        ],
    )
    assert result["status"] == "ambiguous"
    assert result["winning_families"] == ["family-a", "family-b"]


def test_network_output_drops_credentials_and_query() -> None:
    outputs = summarize_handler_outputs(
        [
            _record(
                "agenttesla",
                {
                    "decoded_config_recovered": True,
                    "config": {"protocol": "ftp"},
                    "c2_candidates": [
                        "ftp://operator:secret@example.test:2121/drop?id=secret",
                        "192.0.2.10:8080",
                    ],
                },
            )
        ]
    )
    assert outputs["config_recovered"] is True
    rendered = repr(outputs["network_endpoints"])
    assert "operator" not in rendered
    assert "secret" not in rendered
    assert "example.test" in rendered
    assert "192.0.2.10" in rendered


def test_required_capability_becomes_blocker_but_unknown_does_not() -> None:
    required = build_outcome(
        sample_sha256=SHA256,
        generic_status="complete",
        layer_status="complete",
        candidates=[
            {
                "family": "valleyrat",
                "source": "known_hash",
                "requirements": {"network_required": True},
            }
        ],
        handler_records=[],
        function_analysis_available=False,
    )
    assert required["status"] == "partial"
    assert required["blockers"] == ["network"]

    optional = build_outcome(
        sample_sha256=SHA256,
        generic_status="complete",
        layer_status="complete",
        candidates=[{"family": "wiper", "source": "known_hash"}],
        handler_records=[],
        function_analysis_available=False,
    )
    assert optional["status"] == "complete"
    assert optional["quality_gates"]["network"]["status"] == "not_declared"


def test_terminal_payload_requires_authenticated_sha256() -> None:
    record = _record(
        "loader",
        {"terminal_payload": {"sha256": "b" * 64, "size": 1234}},
    )
    outputs = summarize_handler_outputs([record])
    assert outputs["terminal_payload_sha256"] == ["b" * 64]
