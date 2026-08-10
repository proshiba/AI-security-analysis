"""AIを使わないone-shot候補検証と成果物契約を検証する。"""

from __future__ import annotations

import hashlib
import json
import sys
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
