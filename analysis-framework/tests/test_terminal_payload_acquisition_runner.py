"""ジョブrunnerによる最終payload取得artifactの独立検証を確認する。"""

from __future__ import annotations

import hashlib
import importlib
import json
import sys
from pathlib import Path

import pytest

COMMON = Path(__file__).resolve().parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))
runner = importlib.import_module("analysis_job_runner")
acquisition = importlib.import_module("terminal_payload_acquisition")


def _follow_on() -> dict[str, object]:
    root = "a" * 64
    return {
        "schema_version": 1,
        "status": "no_retained_payloads",
        "roots": [root],
        "nodes": [{"sha256": root, "depth": 0, "state": "root"}],
        "edges": [],
        "omitted_metadata": [],
        "omitted_metadata_commitments": [],
        "errors": [],
        "wall_clock_exhausted": False,
        "executed_sample": False,
        "network_contacted": False,
        "ai_used": False,
    }


def _write_artifact(output: Path, document: dict[str, object]) -> dict[str, object]:
    raw = (json.dumps(document, ensure_ascii=False, sort_keys=True) + "\n").encode()
    (output / "terminal-payload-acquisition.json").write_bytes(raw)
    return {
        "cases": [{"sha256": "a" * 64, "case_state": "complete"}],
        "terminal_payload_acquisition": {
            "artifact": "terminal-payload-acquisition.json",
            "sha256": hashlib.sha256(raw).hexdigest(),
            "status": document["status"],
            "frontier_count": len(document["frontier"]),
            "selected_count": len(document["selected_sha256"]),
            "pending_count": len(document["pending_sha256"]),
        }
    }


def test_runner_recomputes_terminal_payload_acquisition(tmp_path: Path) -> None:
    graph = _follow_on()
    document = acquisition.build_terminal_payload_acquisition(graph)
    summary = _write_artifact(tmp_path, document)

    validated = runner._validated_terminal_payload_acquisition(
        tmp_path / "summary.json",
        summary,
        graph,
    )

    assert validated == document


def test_runner_rejects_graph_independent_acquisition_claim(tmp_path: Path) -> None:
    graph = _follow_on()
    document = acquisition.build_terminal_payload_acquisition(graph)
    document["status"] = "verified"
    document["selected_sha256"] = ["b" * 64]
    summary = _write_artifact(tmp_path, document)

    with pytest.raises(runner.JobContractError, match="follow-on graph"):
        runner._validated_terminal_payload_acquisition(
            tmp_path / "summary.json",
            summary,
            graph,
        )


def test_runner_rejects_acquisition_reference_count_tamper(tmp_path: Path) -> None:
    graph = _follow_on()
    document = acquisition.build_terminal_payload_acquisition(graph)
    summary = _write_artifact(tmp_path, document)
    summary["terminal_payload_acquisition"]["pending_count"] = 1

    with pytest.raises(runner.JobContractError) as caught:
        runner._validated_terminal_payload_acquisition(
            tmp_path / "summary.json",
            summary,
            graph,
        )
    assert caught.value.code == "summary_count_mismatch"


def test_runner_rebinds_shared_root_case_state(tmp_path: Path) -> None:
    left = "a" * 64
    right = "b" * 64
    graph = {
        "schema_version": 1,
        "status": "complete",
        "roots": [left, right],
        "nodes": [
            {"sha256": left, "depth": 0, "state": "root"},
            {"sha256": right, "depth": 0, "state": "root"},
        ],
        "edges": [
            {
                "parent_sha256": left,
                "child_sha256": right,
                "depth": 1,
                "path": "retained/shared.bin",
                "role": "payload",
                "kind": "binary",
                "size": 7,
                "status": "shared_sha256_reused_complete",
            }
        ],
        "omitted_metadata": [],
        "omitted_metadata_commitments": [],
        "errors": [],
        "wall_clock_exhausted": False,
        "executed_sample": False,
        "network_contacted": False,
        "ai_used": False,
    }
    root_states = {left: "complete", right: "complete"}
    document = acquisition.build_terminal_payload_acquisition(
        graph,
        root_case_states=root_states,
    )
    summary = _write_artifact(tmp_path, document)
    summary["cases"] = [
        {"sha256": left, "case_state": "complete"},
        {"sha256": right, "case_state": "complete"},
    ]

    validated = runner._validated_terminal_payload_acquisition(
        tmp_path / "summary.json",
        summary,
        graph,
    )

    assert validated["status"] == "verified"
    assert validated["selected_sha256"] == [right]
    assert validated["pending_sha256"] == []
