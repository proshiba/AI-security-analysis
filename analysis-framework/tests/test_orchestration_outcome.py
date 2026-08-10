"""AI非依存オーケストレーションの証拠解決と公開品質ゲートを検証する。"""

from __future__ import annotations

import sys
from pathlib import Path

COMMON = Path(__file__).resolve().parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import orchestration_outcome as outcome  # noqa: E402
from analysis_contract import handler_result_quality  # noqa: E402
from orchestration_outcome import (  # noqa: E402
    build_outcome,
    resolve_family,
    summarize_handler_outputs,
)

SHA256 = "a" * 64
DETECTOR_SHA256 = "d" * 64


def _candidate(
    family: str,
    kind: str,
    *,
    requirements: dict[str, bool] | None = None,
    source_claim: str = "forged",
) -> dict[str, object]:
    if kind == "known_hash":
        evidence = {
            "kind": "known_outer_sha256",
            "confidence": "high",
            "layer_sha256": SHA256,
            "supports_attribution": True,
        }
        routing = {"mode": "blocked"}
    elif kind == "detector_selected":
        evidence = {
            "kind": "type_detector_structure",
            "confidence": "medium",
            "layer_sha256": SHA256,
            "supports_attribution": True,
        }
        routing = {
            "mode": "selected_family_analysis",
            "selected_family_analysis": True,
            "family_attribution": True,
        }
    elif kind == "detector_candidate":
        evidence = {
            "kind": "type_detector_structure",
            "confidence": "medium",
            "layer_sha256": DETECTOR_SHA256,
            "supports_attribution": True,
        }
        routing = {
            "mode": "candidate_verification",
            "candidate_verification": True,
            "family_attribution": False,
        }
    else:
        evidence = {
            "kind": "external_metadata_hint",
            "confidence": "unverified",
            "supports_attribution": False,
        }
        routing = {
            "mode": "candidate_verification",
            "candidate_verification": True,
            "family_attribution": False,
        }
    return {
        "family": family,
        "source": source_claim,
        "source_strength": 4,
        "evidence": [evidence],
        "routing_eligibility": routing,
        "requirements": requirements or {},
    }


def _record(
    family: str,
    payload: dict[str, object],
    *,
    status: str = "succeeded",
    verified_binary_outputs: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    enriched = {"capabilities": ["fixture"], **payload}
    quality = handler_result_quality(enriched)
    record: dict[str, object] = {
        "family": family,
        "handler_id": f"{family}:extract",
        "status": status,
        "result": {"result": enriched},
        "selected_layer_sha256": SHA256,
    }
    if status == "corroborated":
        record.update(
            {
                "source": "candidate_verification",
                "handler_evidence": quality,
                "detector_corroboration": {
                    "corroborated": True,
                    "basis": "detector_structural_evidence",
                    "layer_sha256": DETECTOR_SHA256,
                    "lineage_distance": 1,
                },
            }
        )
    else:
        record.update(
            {
                "source": "selected_family_analysis",
                "selected_evidence": quality,
            }
        )
    if verified_binary_outputs is not None:
        record["verified_binary_outputs"] = verified_binary_outputs
    return record


def _verified_output(*, matches: bool = True) -> dict[str, object]:
    return {
        "role": "terminal_payload",
        "kind": "pe",
        "path": "result.terminal_payload",
        "sha256": "b" * 64,
        "size": 1_234,
        "verification": {
            "status": "artifact_hash_verified",
            "sha256_matches": matches,
            "size_matches": True,
        },
    }


def test_forged_strength_and_operator_source_do_not_resolve() -> None:
    candidate = _candidate("nanocore", "external_metadata", source_claim="known_hash")
    candidate["basis"] = "explicit_operator_selection"
    result = resolve_family([candidate], [])

    assert result["status"] == "unresolved"
    assert result["candidates"][0]["source"] == "external_metadata"
    assert result["candidates"][0]["source_strength"] == 1


def test_known_hash_requires_canonical_evidence_kind() -> None:
    valid = resolve_family([_candidate("valleyrat", "known_hash")], [])
    forged = resolve_family(
        [{"family": "valleyrat", "source": "known_hash", "source_strength": 4}],
        [],
    )

    assert valid["family"] == "valleyrat"
    assert forged["status"] == "unresolved"


def test_external_metadata_never_confirms_with_selected_handler_status() -> None:
    candidate = _candidate("nanocore", "external_metadata")
    strong = _record(
        "nanocore",
        {"decoded_config_recovered": True, "config": {"campaign": "fixture"}},
    )
    assert resolve_family([candidate], [strong])["status"] == "unresolved"


def test_detector_candidate_requires_revalidated_corroboration() -> None:
    candidate = _candidate("quasarrat", "detector_candidate")
    succeeded = _record("quasarrat", {"capabilities": ["file_manager"]})
    corroborated = _record("quasarrat", {"capabilities": ["file_manager"]}, status="corroborated")

    assert resolve_family([candidate], [succeeded])["status"] == "unresolved"
    assert resolve_family([candidate], [corroborated])["family"] == "quasarrat"


def test_forged_corroborated_status_is_rejected() -> None:
    candidate = _candidate("quasarrat", "detector_candidate")
    forged = _record("quasarrat", {"capabilities": ["x"]}, status="corroborated")
    forged.pop("detector_corroboration")

    assert resolve_family([candidate], [forged])["status"] == "unresolved"


def test_equal_best_families_remain_ambiguous() -> None:
    result = resolve_family(
        [
            _candidate("family-a", "detector_candidate"),
            _candidate("family-b", "detector_candidate"),
        ],
        [
            _record("family-a", {"capabilities": ["x"]}, status="corroborated"),
            _record("family-b", {"capabilities": ["x"]}, status="corroborated"),
        ],
    )
    assert result["status"] == "ambiguous"
    assert result["winning_families"] == ["family-a", "family-b"]


def test_network_output_redacts_credentials_query_and_token_path() -> None:
    second = _record(
        "agenttesla",
        {"c2_candidates": ["ftp://another:credential@example.test:2121/token/0123456789abcdef"]},
    )
    second["handler_id"] = "agenttesla:secondary"
    records = [
        _record(
            "agenttesla",
            {
                "c2_candidates": [
                    "  ftp://operator:secret@example.test:2121/token/0123456789abcdef?id=query-secret",
                    "192.0.2.10:8080",
                ]
            },
        ),
        second,
    ]
    outputs = summarize_handler_outputs(records)
    rendered = repr(outputs["network_endpoints"])

    for secret in ("operator", "secret", "another", "credential", "query-secret", "0123456789abcdef"):
        assert secret not in rendered
    assert "example.test" in rendered
    assert "[redacted]" in rendered
    matching = [item for item in outputs["network_endpoints"] if item["host"] == "example.test"]
    assert len(matching[0]["provenance"]) == 2


def test_evidence_walk_terminates_on_cycle_and_huge_sequence() -> None:
    cycle: dict[str, object] = {}
    cycle["self"] = cycle
    assert list(outcome._walk_evidence(cycle)) == [(("self",), cycle)]

    huge = list(range(outcome.MAX_EVIDENCE_NODES * 2))
    assert list(outcome._walk_evidence(huge)) == []


def test_hash_only_terminal_payload_is_claimed_but_not_reached() -> None:
    record = _record(
        "loader",
        {"terminal_payload": {"sha256": "b" * 64, "size": 1_234}},
    )
    outputs = summarize_handler_outputs([record])

    assert outputs["terminal_payload"]["status"] == "claimed"
    assert outputs["terminal_payload"]["claimed_sha256"] == ["b" * 64]
    assert outputs["terminal_payload_sha256"] == []


def test_verified_binary_manifest_marks_terminal_reached() -> None:
    record = _record(
        "loader",
        {},
        verified_binary_outputs=[_verified_output()],
    )
    outputs = summarize_handler_outputs([record])

    assert outputs["terminal_payload"]["status"] == "verified"
    assert outputs["terminal_payload_sha256"] == ["b" * 64]
    assert outputs["verified_binary_outputs"][0]["size"] == 1_234


def test_invalid_verified_binary_manifest_remains_unresolved() -> None:
    record = _record(
        "loader",
        {},
        verified_binary_outputs=[_verified_output(matches=False)],
    )
    outputs = summarize_handler_outputs([record])

    assert outputs["terminal_payload"]["status"] == "unresolved"
    assert outputs["terminal_payload_sha256"] == []


def test_other_family_success_cannot_satisfy_handler_or_network_gate() -> None:
    result = build_outcome(
        sample_sha256=SHA256,
        generic_status="complete",
        layer_status="complete",
        candidates=[_candidate("valleyrat", "known_hash", requirements={"network_required": True})],
        handler_records=[_record("formbook", {"c2_candidates": ["formbook.example:443"]})],
        function_analysis_available=True,
    )

    assert result["outputs"]["network_endpoints"] == []
    assert result["quality_gates"]["handler_evidence"]["status"] == "required_missing"
    assert result["candidate_outputs"]["network_endpoints"]


def test_required_capability_has_only_its_missing_blocker() -> None:
    result = build_outcome(
        sample_sha256=SHA256,
        generic_status="complete",
        layer_status="complete",
        candidates=[_candidate("valleyrat", "known_hash", requirements={"network_required": True})],
        handler_records=[_record("valleyrat", {"capabilities": ["remote_shell"]})],
        function_analysis_available=False,
    )
    assert result["blockers"] == ["network"]


def test_output_is_deterministic_across_record_order() -> None:
    records = [
        _record("family", {"c2_candidates": ["same.example", "same.example:443"]}),
        _record("family", {"c2_candidates": ["same.example:443"]}),
    ]
    first = summarize_handler_outputs(records)
    second = summarize_handler_outputs(list(reversed(records)))

    assert first == second
    assert [item["port"] for item in first["network_endpoints"]] == [None, 443]
