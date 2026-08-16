"""最終payload取得状態の決定的な導出を検証する。"""

from __future__ import annotations

import importlib.util
from pathlib import Path


MODULE_PATH = Path(__file__).parents[1] / "common" / "terminal_payload_acquisition.py"
SPEC = importlib.util.spec_from_file_location("terminal_payload_acquisition", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def _graph(*, status: str = "complete") -> dict[str, object]:
    root = "a" * 64
    return {
        "status": status,
        "nodes": [{"sha256": root, "depth": 0, "state": "root"}],
        "edges": [],
        "omitted_metadata": [],
        "omitted_metadata_commitments": [],
        "errors": [],
        "wall_clock_exhausted": False,
    }


def _edge(parent: str, child: str, *, depth: int, status: str) -> dict[str, object]:
    return {
        "parent_sha256": parent,
        "child_sha256": child,
        "depth": depth,
        "path": f"p/{child}.bin",
        "role": "terminal_payload",
        "kind": "pe",
        "size": 4096,
        "status": status,
    }


def test_no_retained_payload_is_explicitly_not_recovered() -> None:
    result = MODULE.build_terminal_payload_acquisition(_graph(status="no_retained_payloads"))

    assert result["status"] == "not_recovered"
    assert result["selected_sha256"] == []
    assert result["pending_sha256"] == []
    assert result["external_retrieval_attempted"] is False
    assert result["next_actions"] == ["implement_family_static_recovery"]


def test_deepest_strict_complete_leaf_is_selected() -> None:
    root, child, terminal = "a" * 64, "b" * 64, "c" * 64
    graph = _graph()
    graph["nodes"] = [
        {"sha256": root, "depth": 0, "state": "root"},
        {"sha256": child, "depth": 1, "size": 4096, "state": "analyzed", "case_state": "complete"},
        {"sha256": terminal, "depth": 2, "size": 4096, "state": "analyzed", "case_state": "complete"},
    ]
    graph["edges"] = [
        _edge(root, child, depth=1, status="child_complete"),
        _edge(child, terminal, depth=2, status="child_complete"),
    ]

    result = MODULE.build_terminal_payload_acquisition(graph)

    assert result["status"] == "verified"
    assert result["selected_sha256"] == [terminal]
    assert [item["sha256"] for item in result["frontier"]] == [terminal]
    assert result["frontier"][0]["reason"] == "strict_complete_leaf"


def test_incomplete_leaf_remains_pending_with_reason() -> None:
    root, child = "a" * 64, "b" * 64
    graph = _graph(status="partial")
    graph["nodes"] = [
        {"sha256": root, "depth": 0, "state": "root"},
        {"sha256": child, "depth": 1, "size": 4096, "state": "timeout"},
    ]
    graph["edges"] = [_edge(root, child, depth=1, status="child_incomplete")]

    result = MODULE.build_terminal_payload_acquisition(graph)

    assert result["status"] == "pending"
    assert result["pending_sha256"] == [child]
    assert result["frontier"][0]["reason"] == "child_timeout"
    assert result["next_actions"] == ["retry_child_static_analysis"]


def test_limit_boundary_is_a_pending_terminal_candidate() -> None:
    root, child = "a" * 64, "b" * 64
    graph = _graph(status="partial")
    graph["edges"] = [_edge(root, child, depth=5, status="depth_limit")]

    result = MODULE.build_terminal_payload_acquisition(graph)

    assert result["pending_sha256"] == [child]
    assert result["frontier"][0]["node_state"] == "not_queued"
    assert result["frontier"][0]["reason"] == "depth_limit"


def test_cycle_without_leaf_retains_machine_readable_blocker() -> None:
    root = "a" * 64
    graph = _graph(status="partial")
    graph["edges"] = [_edge(root, root, depth=1, status="cycle_excluded")]

    result = MODULE.build_terminal_payload_acquisition(graph)

    assert result["status"] == "pending"
    assert [item["sha256"] for item in result["frontier"]] == [root]
    assert result["frontier"][0]["reason"] == "cycle_detected"
    assert result["selected_sha256"] == []
    assert result["pending_sha256"] == [root]
    assert result["blockers"] == ["cycle_detected"]
    assert result["next_actions"] == ["review_payload_cycle"]


def test_omitted_metadata_is_bound_as_pending_without_raw_bytes() -> None:
    omitted = "d" * 64
    graph = _graph(status="partial")
    graph["omitted_metadata"] = [
        {
            "parent_sha256": "a" * 64,
            "sha256": omitted,
            "size": 8192,
            "path": "p/omitted.bin",
            "role": "final_payload",
            "kind": "data",
            "reason": "verified_output_edge_limit",
        }
    ]
    graph["errors"] = [f"{'a' * 64}:verified_output_edge_limit"]

    result = MODULE.build_terminal_payload_acquisition(graph)

    assert result["status"] == "pending"
    assert result["pending_sha256"] == [omitted]
    assert result["omitted_sha256"] == [omitted]
    assert result["blockers"] == ["follow_on_errors", "omitted_metadata"]
    assert "data" not in result


def test_disabled_mode_never_claims_acquisition() -> None:
    result = MODULE.build_terminal_payload_acquisition(_graph(status="disabled_assessment_only"))

    assert result["status"] == "disabled"
    assert result["selected_sha256"] == []
    assert result["blockers"] == ["disabled_assessment_only"]
