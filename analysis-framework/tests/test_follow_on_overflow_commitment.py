"""follow-on省略上限超過時の多重集合commitmentを検証する。"""

from __future__ import annotations

import hashlib
import json
import sys
from collections import Counter
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest


FRAMEWORK_ROOT = Path(__file__).resolve().parents[1]
COMMON_ROOT = FRAMEWORK_ROOT / "common"
REPOSITORY_ROOT = FRAMEWORK_ROOT.parent
for trusted in (REPOSITORY_ROOT, FRAMEWORK_ROOT, COMMON_ROOT):
    value = str(trusted)
    if value not in sys.path:
        sys.path.insert(0, value)

import analysis_job_runner as runner  # noqa: E402
import analyze_sample as one_shot  # noqa: E402
from follow_on_commitment import (  # noqa: E402
    canonical_multiset_commitment,
    metadata_identity,
)


def _metadata(data: bytes, path: str = "p/payload.bin") -> dict[str, Any]:
    return {
        "role": "terminal_payload",
        "kind": "pe",
        "path": path,
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
        "verification": {
            "status": "artifact_hash_verified",
            "sha256_matches": True,
            "size_matches": True,
        },
    }


def _audit(count: int, total_size: int) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "maximum_outputs": 64,
        "maximum_total_size": 256 * 1024 * 1024,
        "binary_values_seen": count,
        "binary_bytes_seen": total_size,
        "traversal_items": count,
        "observed_output_count": count,
        "retained_output_count": count,
        "retained_for_follow_on_analysis": True,
        "follow_on_analysis_complete": False,
        "observation_scope": "parent_rehashed_case_artifact",
        "truncated": False,
        "reasons": [],
    }


def _commitment(parent: str, identity: tuple[str, str, str, str, int], count: int) -> dict[str, Any]:
    value = canonical_multiset_commitment(Counter({identity: count}))
    assert value is not None
    return {"parent_sha256": parent, **value}


def test_canonical_commitment_is_order_independent_and_does_not_expand_multiplicity() -> None:
    first = ("a" * 64, "p/a.bin", "terminal_payload", "pe", 10)
    second = ("b" * 64, "p/b.bin", "configuration", "data", 20)

    left = canonical_multiset_commitment({first: 1_000_000, second: 2})
    right = canonical_multiset_commitment({second: 2, first: 1_000_000})

    assert left == right
    assert left is not None and left["count"] == 1_000_002
    assert canonical_multiset_commitment({}) is None
    with pytest.raises(ValueError):
        canonical_multiset_commitment({first: 0})


def test_retained_scan_commits_every_record_beyond_explicit_omission_cap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = "a" * 64
    case_dir = tmp_path / "cases" / parent
    case_dir.mkdir(parents=True)
    (case_dir / "report.json").write_text("{}", encoding="utf-8")
    output = _metadata(b"same retained output")
    wrapper = {
        "verified_binary_outputs": [deepcopy(output) for _ in range(3)],
        "verified_binary_output_audit": _audit(3, output["size"] * 3),
    }
    monkeypatch.setattr(
        one_shot,
        "_case_wrapper_documents",
        lambda *_args: (
            [(case_dir / "wrapper.json", wrapper)],
            case_dir / "candidate.json",
            {},
        ),
    )

    records, errors, read_count, read_bytes, omitted, commitment = (
        one_shot._case_retained_payloads(
            tmp_path,
            parent,
            maximum_records=0,
            maximum_read_bytes=0,
            maximum_omitted_records=1,
            include_omitted_metadata=True,
            include_omitted_commitment=True,
        )
    )

    expected = canonical_multiset_commitment(
        Counter({metadata_identity(output): 2})
    )
    assert records == []
    assert read_count == 0 and read_bytes == 0
    assert len(omitted) == 1
    assert commitment == expected
    assert errors == [
        "verified_output_edge_limit",
        "verified_output_omitted_metadata_limit",
    ]


def test_fixed_point_commitment_forces_partial_and_disables_parent_promotion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = "a" * 64
    identity = ("b" * 64, "p/hidden.bin", "terminal_payload", "pe", 10)
    compact = canonical_multiset_commitment(Counter({identity: 3}))
    assert compact is not None

    monkeypatch.setattr(
        one_shot,
        "_case_retained_payloads",
        lambda *_args, **_kwargs: (
            [],
            ["verified_output_omitted_metadata_limit"],
            0,
            0,
            [],
            compact,
        ),
    )
    monkeypatch.setattr(
        one_shot,
        "_promote_parent_case_from_follow_on",
        lambda *_args, **_kwargs: pytest.fail("commitment付きgraphで親昇格してはならない"),
    )
    tmp_path.mkdir(exist_ok=True)

    result = one_shot._run_follow_on_fixed_point(
        root_digests=[parent],
        output=tmp_path,
        registry=FRAMEWORK_ROOT / "registry" / "malware_types.json",
        specs=[],
        requirements_policy={},
        minimum_confidence="medium",
        upx=None,
        sevenzip=None,
        diec=None,
        force_container_probe=False,
        max_static_layers=8,
        retry_max_static_layers=None,
        archive_password="infected",
        string_scan_limit=1000,
        analysis_contract={},
        root_analysis_contract={},
        resume=False,
    )

    assert result["status"] == "partial"
    assert result["parent_promotion_enabled"] is False
    assert result["promoted_parent_sha256"] == []
    assert result["omitted_metadata_commitments"] == [
        {"parent_sha256": parent, **compact}
    ]


def _provenance_fixture(tmp_path: Path) -> tuple[str, dict[str, Any], dict[str, Any]]:
    parent = "a" * 64
    case_dir = tmp_path / "cases" / parent
    case_dir.mkdir(parents=True)
    output = _metadata(b"committed retained output")
    wrapper = {
        "verified_binary_outputs": [deepcopy(output) for _ in range(3)],
        "verified_binary_output_audit": _audit(3, output["size"] * 3),
    }
    (case_dir / "handler.json").write_text(json.dumps(wrapper), encoding="utf-8")
    (case_dir / "candidate-handler-assessment.json").write_text(
        json.dumps({"families": []}),
        encoding="utf-8",
    )
    report = {"handler_executions": [{"result": "handler.json"}]}
    commitment = _commitment(parent, metadata_identity(output), 3)
    follow_on = {
        "verified_read_count": 0,
        "verified_read_bytes": 0,
        "edges": [],
        "omitted_metadata": [],
        "omitted_metadata_commitments": [commitment],
    }
    return parent, report, follow_on


def test_runner_recomputes_residual_counter_and_accepts_exact_commitment(tmp_path: Path) -> None:
    parent, report, follow_on = _provenance_fixture(tmp_path)

    runner._validate_follow_on_edge_provenance(
        tmp_path / "summary.json",
        follow_on=follow_on,
        validated_case_reports={parent: report},
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "empty",
        "empty_record",
        "duplicate",
        "unknown_parent",
        "count_mismatch",
        "sha_mismatch",
    ],
)
def test_runner_rejects_non_exact_residual_commitment(
    tmp_path: Path,
    mutation: str,
) -> None:
    parent, report, follow_on = _provenance_fixture(tmp_path)
    commitments = follow_on["omitted_metadata_commitments"]
    if mutation == "empty":
        follow_on["omitted_metadata_commitments"] = []
    elif mutation == "empty_record":
        follow_on["omitted_metadata_commitments"] = [{}]
    elif mutation == "duplicate":
        follow_on["omitted_metadata_commitments"] = [
            deepcopy(commitments[0]),
            deepcopy(commitments[0]),
        ]
    elif mutation == "unknown_parent":
        commitments[0]["parent_sha256"] = "c" * 64
    elif mutation == "count_mismatch":
        commitments[0]["count"] += 1
    elif mutation == "sha_mismatch":
        commitments[0]["sha256"] = "d" * 64

    with pytest.raises(runner.JobContractError) as caught:
        runner._validate_follow_on_edge_provenance(
            tmp_path / "summary.json",
            follow_on=follow_on,
            validated_case_reports={parent: report},
        )
    assert caught.value.code == "summary_invalid"


def _schema_graph(parent: str, commitment: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "status": "partial",
        "analysis_contract_sha256": "c" * 64,
        "limits": {
            "maximum_artifacts": runner.MAX_FOLLOW_ON_ARTIFACTS,
            "maximum_edges": runner.MAX_FOLLOW_ON_EDGES,
            "maximum_depth": runner.MAX_FOLLOW_ON_DEPTH,
            "maximum_total_bytes": runner.MAX_FOLLOW_ON_TOTAL_BYTES,
            "maximum_payload_size": runner.MAX_FOLLOW_ON_PAYLOAD_SIZE,
            "maximum_wall_seconds": runner.MAX_FOLLOW_ON_WALL_SECONDS,
            "maximum_child_seconds": runner.MAX_FOLLOW_ON_CHILD_SECONDS,
            "maximum_omitted_metadata": runner.MAX_FOLLOW_ON_OMITTED_METADATA,
        },
        "roots": [parent],
        "nodes": [{"sha256": parent, "depth": 0, "state": "root"}],
        "edges": [],
        "omitted_metadata": [],
        "omitted_metadata_commitments": [commitment],
        "errors": [f"{parent}:verified_output_omitted_metadata_limit"],
        "queued_artifact_count": 0,
        "queued_total_bytes": 0,
        "verified_read_count": 0,
        "verified_read_bytes": 0,
        "parent_promotion_enabled": False,
        "promoted_parent_sha256": [],
        "wall_clock_exhausted": False,
        "executed_sample": False,
        "network_contacted": False,
        "ai_used": False,
    }


def _validate_graph_artifact(tmp_path: Path, graph: dict[str, Any]) -> None:
    raw = (json.dumps(graph, sort_keys=True) + "\n").encode("utf-8")
    (tmp_path / "follow-on-analysis.json").write_bytes(raw)
    reference = {
        "follow_on_analysis": {
            "artifact": "follow-on-analysis.json",
            "sha256": hashlib.sha256(raw).hexdigest(),
            "status": graph["status"],
            "node_count": len(graph["nodes"]),
            "edge_count": len(graph["edges"]),
            "error_count": len(graph["errors"]),
        }
    }
    runner._validated_follow_on_artifact(tmp_path / "summary.json", reference)


def test_commitment_schema_requires_partial_and_disables_promotion(tmp_path: Path) -> None:
    parent = "a" * 64
    identity = ("b" * 64, "p/payload.bin", "terminal_payload", "pe", 10)
    graph = _schema_graph(parent, _commitment(parent, identity, 2))

    _validate_graph_artifact(tmp_path, graph)

    for mutation in ("complete", "promotion_enabled", "promoted_parent", "zero_count"):
        changed = deepcopy(graph)
        if mutation == "complete":
            changed["status"] = "complete"
        elif mutation == "promotion_enabled":
            changed["parent_promotion_enabled"] = True
        elif mutation == "promoted_parent":
            changed["promoted_parent_sha256"] = [parent]
        elif mutation == "zero_count":
            changed["omitted_metadata_commitments"][0]["count"] = 0
        with pytest.raises(runner.JobContractError):
            _validate_graph_artifact(tmp_path, changed)


@pytest.mark.parametrize("status", sorted(runner.FOLLOW_ON_DOCUMENT_KEYS_BY_STATUS))
def test_every_follow_on_status_requires_exact_commitment_top_level_key(
    tmp_path: Path,
    status: str,
) -> None:
    """通常、停止、失敗の全statusでcommitment field欠落を拒否する。"""

    document = {
        key: None
        for key in runner.FOLLOW_ON_DOCUMENT_KEYS_BY_STATUS[status]
    }
    document.update(
        {
            "schema_version": 1,
            "status": status,
            "roots": [],
            "nodes": [],
            "edges": [],
            "omitted_metadata": [],
            "omitted_metadata_commitments": [],
            "errors": [],
            "executed_sample": False,
            "network_contacted": False,
            "ai_used": False,
        }
    )
    del document["omitted_metadata_commitments"]

    with pytest.raises(runner.JobContractError) as caught:
        _validate_graph_artifact(tmp_path, document)
    assert caught.value.code == "summary_invalid"
