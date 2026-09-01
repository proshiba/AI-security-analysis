"""最終payload取得状態の決定的な導出を検証する。"""

from __future__ import annotations

import copy
import importlib.util
import sys
from pathlib import Path

import pytest

COMMON = Path(__file__).parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))
MODULE_PATH = COMMON / "terminal_payload_acquisition.py"
SPEC = importlib.util.spec_from_file_location("terminal_payload_acquisition", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def _graph(*, status: str = "complete") -> dict[str, object]:
    root = "a" * 64
    return {
        "status": status,
        "roots": [root],
        "nodes": []
        if status in {"disabled_assessment_only", "disabled_repository_output", "failed"}
        else [_node(root, depth=0, state="root")],
        "edges": [],
        "omitted_metadata": [],
        "omitted_metadata_commitments": [],
        "errors": [],
        "wall_clock_exhausted": False,
    }


def _node(
    digest: str,
    *,
    depth: int,
    state: str,
    size: int = 4096,
    case_state: str | None = None,
) -> dict[str, object]:
    if state == "root":
        return {"sha256": digest, "depth": depth, "state": state}
    node: dict[str, object] = {
        "sha256": digest,
        "depth": depth,
        "size": size,
        "state": state,
        "family_hint_count": 0,
        "family_hint_root_sha256": None,
        "family_hint_lineage_depth": None,
    }
    if state in {"analyzed", "resumed_complete", "incomplete_case_omitted"}:
        node["case_state"] = case_state
    elif state == "failed":
        node["error_type"] = "ValueError"
    return node


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


def _valid_complete_graph() -> dict[str, object]:
    root, child = "a" * 64, "b" * 64
    graph = _graph()
    graph["nodes"] = [
        _node(root, depth=0, state="root"),
        _node(child, depth=1, state="analyzed", case_state="complete"),
    ]
    graph["edges"] = [_edge(root, child, depth=1, status="child_complete")]
    return graph


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
        _node(root, depth=0, state="root"),
        _node(child, depth=1, state="analyzed", case_state="complete"),
        _node(terminal, depth=2, state="analyzed", case_state="complete"),
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
        _node(root, depth=0, state="root"),
        _node(child, depth=1, state="timeout"),
    ]
    graph["edges"] = [_edge(root, child, depth=1, status="child_incomplete")]

    result = MODULE.build_terminal_payload_acquisition(graph)

    assert result["status"] == "pending"
    assert result["pending_sha256"] == [child]
    assert result["frontier"][0]["reason"] == "child_timeout"
    assert result["next_actions"] == ["retry_child_static_analysis"]


def test_limit_boundary_is_a_pending_terminal_candidate() -> None:
    digests = [character * 64 for character in "abcdef"]
    graph = _graph(status="partial")
    graph["nodes"] = [
        _node(digests[0], depth=0, state="root"),
        *[
            _node(digest, depth=depth, state="analyzed", case_state="complete")
            for depth, digest in enumerate(digests[1:5], start=1)
        ],
    ]
    graph["edges"] = [
        *[_edge(digests[depth - 1], digests[depth], depth=depth, status="child_complete") for depth in range(1, 5)],
        _edge(digests[4], digests[5], depth=5, status="depth_limit"),
    ]

    result = MODULE.build_terminal_payload_acquisition(graph)

    assert result["pending_sha256"] == [digests[5]]
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


def test_cycle_excluded_accepts_an_actually_reachable_ancestor() -> None:
    root, child = "a" * 64, "b" * 64
    graph = _graph(status="partial")
    graph["nodes"] = [
        _node(root, depth=0, state="root"),
        _node(child, depth=1, state="analyzed", case_state="complete"),
    ]
    graph["edges"] = [
        _edge(root, child, depth=1, status="child_complete"),
        _edge(child, root, depth=2, status="cycle_excluded"),
    ]

    result = MODULE.build_terminal_payload_acquisition(graph)

    assert result["status"] == "partial"
    assert result["selected_sha256"] == [child]
    assert result["blockers"] == ["cycle_detected"]


def test_cycle_excluded_rejects_an_unrelated_lower_depth_branch() -> None:
    root, left, right = "a" * 64, "b" * 64, "c" * 64
    graph = _graph(status="partial")
    graph["nodes"] = [
        _node(root, depth=0, state="root"),
        _node(left, depth=1, state="analyzed", case_state="complete"),
        _node(right, depth=1, state="analyzed", case_state="complete"),
    ]
    graph["edges"] = [
        _edge(root, left, depth=1, status="child_complete"),
        _edge(root, right, depth=1, status="child_complete"),
        _edge(left, right, depth=2, status="cycle_excluded"),
    ]

    with pytest.raises(MODULE.TerminalPayloadAcquisitionError):
        MODULE.build_terminal_payload_acquisition(graph)


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


def test_all_generated_blockers_have_an_exact_registered_action() -> None:
    assert MODULE._GENERATED_BLOCKER_REASONS == (MODULE.remediation_registry.TERMINAL_ACQUISITION_REASONS)
    assert set(MODULE.remediation_registry.TERMINAL_NEXT_ACTION_BY_REASON) == set(MODULE._GENERATED_BLOCKER_REASONS)
    assert all(MODULE.remediation_registry.terminal_next_action(reason) for reason in MODULE._GENERATED_BLOCKER_REASONS)


def test_previous_fallback_reasons_are_explicitly_registered() -> None:
    root, child = "a" * 64, "b" * 64
    graph = _graph(status="partial")
    graph["nodes"] = [
        _node(root, depth=0, state="root"),
        _node(child, depth=1, state="wall_clock_limit"),
    ]
    graph["edges"] = [_edge(root, child, depth=1, status="child_incomplete")]

    result = MODULE.build_terminal_payload_acquisition(graph)

    assert result["frontier"][0]["reason"] == "wall_clock_limit"
    assert result["blockers"] == ["child_analysis_incomplete", "wall_clock_limit"]
    assert result["next_actions"] == ["continue_child_static_analysis"]

    graph = _graph(status="partial")
    graph["roots"] = [root, child]
    graph["nodes"] = [
        _node(root, depth=0, state="root"),
        _node(child, depth=0, state="root"),
    ]
    graph["edges"] = [_edge(root, child, depth=1, status="shared_sha256_excluded")]

    result = MODULE.build_terminal_payload_acquisition(graph)

    assert result["frontier"][0]["reason"] == "terminal_verification_incomplete"
    assert result["blockers"] == ["terminal_verification_incomplete"]
    assert result["next_actions"] == ["continue_child_static_analysis"]


def test_shared_complete_root_is_verified_with_exact_root_case_states() -> None:
    root, shared = "a" * 64, "b" * 64
    graph = _graph(status="complete")
    graph["roots"] = [root, shared]
    graph["nodes"] = [
        _node(root, depth=0, state="root"),
        _node(shared, depth=0, state="root"),
    ]
    graph["edges"] = [_edge(root, shared, depth=1, status="shared_sha256_reused_complete")]

    result = MODULE.build_terminal_payload_acquisition(
        graph,
        root_case_states={root: "complete", shared: "complete"},
    )

    assert result["status"] == "verified"
    assert result["selected_sha256"] == [shared]
    assert result["pending_sha256"] == []
    assert result["frontier"][0]["node_state"] == "root"
    assert result["frontier"][0]["case_state"] == "complete"
    assert result["frontier"][0]["reason"] == "strict_complete_leaf"


def test_root_case_states_rejects_a_missing_root_mapping() -> None:
    root, shared = "a" * 64, "b" * 64
    graph = _graph(status="complete")
    graph["roots"] = [root, shared]
    graph["nodes"] = [
        _node(root, depth=0, state="root"),
        _node(shared, depth=0, state="root"),
    ]
    graph["edges"] = [_edge(root, shared, depth=1, status="shared_sha256_reused_complete")]

    with pytest.raises(MODULE.TerminalPayloadAcquisitionError):
        MODULE.build_terminal_payload_acquisition(
            graph,
            root_case_states={root: "complete"},
        )


@pytest.mark.parametrize("invalid_status", [None, "", "future_status", 1, []])
def test_unknown_follow_on_status_is_rejected(invalid_status: object) -> None:
    graph = _valid_complete_graph()
    graph["status"] = invalid_status

    with pytest.raises(MODULE.TerminalPayloadAcquisitionError):
        MODULE.build_terminal_payload_acquisition(graph)


@pytest.mark.parametrize(
    "field",
    [
        "roots",
        "nodes",
        "edges",
        "omitted_metadata",
        "omitted_metadata_commitments",
        "errors",
    ],
)
def test_each_graph_array_requires_a_json_list(field: str) -> None:
    graph = _valid_complete_graph()
    graph[field] = ()

    with pytest.raises(MODULE.TerminalPayloadAcquisitionError):
        MODULE.build_terminal_payload_acquisition(graph)


@pytest.mark.parametrize(
    ("field", "maximum"),
    [
        ("roots", MODULE.MAX_ROOTS),
        ("nodes", MODULE.MAX_NODES),
        ("edges", MODULE.MAX_EDGES),
        ("omitted_metadata", MODULE.MAX_OMITTED_METADATA),
        ("omitted_metadata_commitments", MODULE.MAX_OMITTED_METADATA_COMMITMENTS),
        ("errors", MODULE.MAX_ERRORS),
    ],
)
def test_each_graph_array_has_a_hard_item_limit(field: str, maximum: int) -> None:
    graph = _valid_complete_graph()
    graph[field] = [None] * (maximum + 1)

    with pytest.raises(MODULE.TerminalPayloadAcquisitionError):
        MODULE.build_terminal_payload_acquisition(graph)


@pytest.mark.parametrize(
    ("field", "invalid_value"),
    [
        ("sha256", "not-a-sha256"),
        ("sha256", "A" * 64),
        ("depth", -1),
        ("depth", True),
        ("depth", MODULE.MAX_NODE_DEPTH + 1),
        ("size", -1),
        ("size", True),
        ("size", MODULE.MAX_PAYLOAD_SIZE + 1),
        ("state", "future_state"),
        ("case_state", "future_case_state"),
    ],
)
def test_invalid_child_node_fields_are_rejected(field: str, invalid_value: object) -> None:
    graph = _valid_complete_graph()
    child = graph["nodes"][1]
    child[field] = invalid_value

    with pytest.raises(MODULE.TerminalPayloadAcquisitionError):
        MODULE.build_terminal_payload_acquisition(graph)


def test_node_exact_schema_and_uniqueness_are_enforced() -> None:
    graph = _valid_complete_graph()
    graph["nodes"][1]["unexpected"] = "field"

    with pytest.raises(MODULE.TerminalPayloadAcquisitionError):
        MODULE.build_terminal_payload_acquisition(graph)

    graph = _valid_complete_graph()
    del graph["nodes"][1]["family_hint_count"]

    with pytest.raises(MODULE.TerminalPayloadAcquisitionError):
        MODULE.build_terminal_payload_acquisition(graph)

    graph = _valid_complete_graph()
    graph["nodes"].append(copy.deepcopy(graph["nodes"][1]))

    with pytest.raises(MODULE.TerminalPayloadAcquisitionError):
        MODULE.build_terminal_payload_acquisition(graph)


@pytest.mark.parametrize(
    ("field", "invalid_value"),
    [
        ("parent_sha256", "d" * 64),
        ("child_sha256", "not-a-sha256"),
        ("depth", -1),
        ("depth", True),
        ("depth", MODULE.MAX_EDGE_DEPTH + 1),
        ("size", -1),
        ("size", True),
        ("size", MODULE.MAX_ANALYSIS_OUTPUT_BYTES + 1),
        ("status", "unresolved"),
        ("status", []),
        ("path", "../payload.bin"),
        ("role", "bad\nrole"),
    ],
)
def test_invalid_edge_fields_are_rejected(field: str, invalid_value: object) -> None:
    graph = _valid_complete_graph()
    graph["edges"][0][field] = invalid_value

    with pytest.raises(MODULE.TerminalPayloadAcquisitionError):
        MODULE.build_terminal_payload_acquisition(graph)


def test_edge_exact_schema_is_enforced() -> None:
    graph = _valid_complete_graph()
    graph["edges"][0]["unexpected"] = "field"

    with pytest.raises(MODULE.TerminalPayloadAcquisitionError):
        MODULE.build_terminal_payload_acquisition(graph)

    graph = _valid_complete_graph()
    del graph["edges"][0]["kind"]

    with pytest.raises(MODULE.TerminalPayloadAcquisitionError):
        MODULE.build_terminal_payload_acquisition(graph)


def test_active_edge_requires_a_closed_and_consistent_child_endpoint() -> None:
    graph = _valid_complete_graph()
    graph["edges"][0]["child_sha256"] = "c" * 64

    with pytest.raises(MODULE.TerminalPayloadAcquisitionError):
        MODULE.build_terminal_payload_acquisition(graph)

    graph = _valid_complete_graph()
    graph["edges"][0]["depth"] = 2

    with pytest.raises(MODULE.TerminalPayloadAcquisitionError):
        MODULE.build_terminal_payload_acquisition(graph)

    graph = _valid_complete_graph()
    graph["edges"][0]["size"] = 4095

    with pytest.raises(MODULE.TerminalPayloadAcquisitionError):
        MODULE.build_terminal_payload_acquisition(graph)


def test_complete_edge_requires_a_strict_complete_child() -> None:
    graph = _valid_complete_graph()
    graph["status"] = "partial"
    graph["nodes"][1]["case_state"] = "partial"

    with pytest.raises(MODULE.TerminalPayloadAcquisitionError):
        MODULE.build_terminal_payload_acquisition(graph)


def test_nonroot_node_requires_an_active_incoming_edge() -> None:
    graph = _valid_complete_graph()
    graph["status"] = "partial"
    graph["nodes"].append(_node("c" * 64, depth=1, state="timeout"))

    with pytest.raises(MODULE.TerminalPayloadAcquisitionError):
        MODULE.build_terminal_payload_acquisition(graph)


def test_nonroot_node_rejects_multiple_active_incoming_edges() -> None:
    first_root, second_root, child = "a" * 64, "b" * 64, "c" * 64
    graph = _graph(status="complete")
    graph["roots"] = [first_root, second_root]
    graph["nodes"] = [
        _node(first_root, depth=0, state="root"),
        _node(second_root, depth=0, state="root"),
        _node(child, depth=1, state="analyzed", case_state="complete"),
    ]
    graph["edges"] = [
        _edge(first_root, child, depth=1, status="child_complete"),
        _edge(second_root, child, depth=1, status="child_complete"),
    ]

    with pytest.raises(MODULE.TerminalPayloadAcquisitionError):
        MODULE.build_terminal_payload_acquisition(graph)


def test_roots_must_match_operational_depth_zero_nodes() -> None:
    graph = _valid_complete_graph()
    graph["roots"] = ["d" * 64]

    with pytest.raises(MODULE.TerminalPayloadAcquisitionError):
        MODULE.build_terminal_payload_acquisition(graph)


def test_invalid_wall_clock_type_and_complete_status_contradiction_are_rejected() -> None:
    graph = _valid_complete_graph()
    graph["wall_clock_exhausted"] = 1

    with pytest.raises(MODULE.TerminalPayloadAcquisitionError):
        MODULE.build_terminal_payload_acquisition(graph)

    graph = _valid_complete_graph()
    graph["errors"] = ["unexpected_error"]

    with pytest.raises(MODULE.TerminalPayloadAcquisitionError):
        MODULE.build_terminal_payload_acquisition(graph)


@pytest.mark.parametrize(
    ("field", "invalid_value"),
    [
        ("sha256", "not-a-sha256"),
        ("size", -1),
        ("reason", "future_reason"),
        ("parent_sha256", "d" * 64),
        ("path", "../omitted.bin"),
    ],
)
def test_invalid_omitted_metadata_is_rejected(field: str, invalid_value: object) -> None:
    graph = _graph(status="partial")
    root = "a" * 64
    graph["omitted_metadata"] = [
        {
            "parent_sha256": root,
            "sha256": "c" * 64,
            "size": 4096,
            "path": "p/omitted.bin",
            "role": "terminal_payload",
            "kind": "pe",
            "reason": "verified_output_edge_limit",
        }
    ]
    graph["errors"] = [f"{root}:verified_output_edge_limit"]
    graph["omitted_metadata"][0][field] = invalid_value

    with pytest.raises(MODULE.TerminalPayloadAcquisitionError):
        MODULE.build_terminal_payload_acquisition(graph)


@pytest.mark.parametrize(
    ("field", "invalid_value"),
    [
        ("sha256", "not-a-sha256"),
        ("count", 0),
        ("count", True),
        ("parent_sha256", "d" * 64),
    ],
)
def test_invalid_omitted_metadata_commitment_is_rejected(field: str, invalid_value: object) -> None:
    graph = _graph(status="partial")
    root = "a" * 64
    graph["omitted_metadata_commitments"] = [{"parent_sha256": root, "count": 1, "sha256": "c" * 64}]
    graph["errors"] = [f"{root}:verified_output_omitted_metadata_limit"]
    graph["omitted_metadata_commitments"][0][field] = invalid_value

    with pytest.raises(MODULE.TerminalPayloadAcquisitionError):
        MODULE.build_terminal_payload_acquisition(graph)


def test_non_string_error_entry_is_rejected() -> None:
    graph = _valid_complete_graph()
    graph["errors"] = [1]

    with pytest.raises(MODULE.TerminalPayloadAcquisitionError):
        MODULE.build_terminal_payload_acquisition(graph)
