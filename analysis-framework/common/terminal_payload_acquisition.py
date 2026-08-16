"""保持payload graphから最終payload取得状態を決定的に要約する。"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence
from typing import Any


SCHEMA_VERSION = 1
METHOD = "offline_verified_retained_output_fixed_point"
DISABLED_STATUSES = frozenset({"disabled_assessment_only", "disabled_repository_output"})
COMPLETE_EDGE_STATUSES = frozenset({"child_complete", "shared_sha256_reused_complete"})

_EDGE_REASON_PRIORITY = (
    ("cycle_excluded", "cycle_detected"),
    ("depth_limit", "depth_limit"),
    ("payload_size_limit", "payload_size_limit"),
    ("artifact_count_limit", "artifact_count_limit"),
    ("total_bytes_limit", "total_bytes_limit"),
)
_NODE_REASON = {
    "timeout": "child_timeout",
    "failed": "child_analysis_failed",
    "wall_clock_limit": "wall_clock_limit",
    "incomplete_case_omitted": "child_case_invalid",
    "queued": "child_not_analyzed",
}
_NEXT_ACTION_BY_BLOCKER = {
    "artifact_count_limit": "prioritize_retained_payload_graph",
    "child_analysis_failed": "inspect_child_analysis_failure",
    "child_analysis_incomplete": "continue_child_static_analysis",
    "child_case_invalid": "repair_child_case_integrity",
    "child_not_analyzed": "continue_child_static_analysis",
    "child_timeout": "retry_child_static_analysis",
    "cycle_detected": "review_payload_cycle",
    "depth_limit": "continue_terminal_static_recovery",
    "disabled_assessment_only": "run_full_static_analysis",
    "disabled_repository_output": "use_isolated_output_directory",
    "fixed_point_failed": "repair_follow_on_analysis",
    "follow_on_errors": "inspect_follow_on_errors",
    "omitted_metadata": "prioritize_retained_payload_graph",
    "omitted_metadata_commitment": "prioritize_retained_payload_graph",
    "payload_size_limit": "review_oversized_payload_offline",
    "total_bytes_limit": "prioritize_retained_payload_graph",
    "wall_clock_exhausted": "retry_child_static_analysis",
}


class TerminalPayloadAcquisitionError(ValueError):
    """最終payload取得graphが決定的に解釈できない場合に送出する。"""


def _array(value: object, *, label: str) -> list[Any]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise TerminalPayloadAcquisitionError(f"{label} must be an array")
    return list(value)


def _frontier_reason(
    *,
    edge_statuses: set[str],
    node_state: str,
    case_state: str | None,
) -> str:
    for edge_status, reason in _EDGE_REASON_PRIORITY:
        if edge_status in edge_statuses:
            return reason
    if node_state in _NODE_REASON:
        return _NODE_REASON[node_state]
    if edge_statuses & {"shared_sha256_reused_incomplete", "child_incomplete"}:
        return "child_analysis_incomplete"
    if case_state in {"partial", "triaged_unknown", "failed"}:
        return "child_analysis_incomplete"
    return "terminal_verification_incomplete"


def build_terminal_payload_acquisition(graph: Mapping[str, Any]) -> dict[str, Any]:
    """follow-on graphからraw bytesを含まない終端frontierを生成する。"""

    follow_on_status = graph.get("status")
    if not isinstance(follow_on_status, str):
        raise TerminalPayloadAcquisitionError("follow-on status is invalid")
    nodes = _array(graph.get("nodes"), label="nodes")
    edges = _array(graph.get("edges"), label="edges")
    omissions = _array(graph.get("omitted_metadata"), label="omitted_metadata")
    commitments = _array(
        graph.get("omitted_metadata_commitments"),
        label="omitted_metadata_commitments",
    )
    errors = _array(graph.get("errors"), label="errors")

    node_by_digest: dict[str, Mapping[str, Any]] = {}
    for node in nodes:
        if not isinstance(node, Mapping) or not isinstance(node.get("sha256"), str):
            raise TerminalPayloadAcquisitionError("node is invalid")
        digest = str(node["sha256"])
        if digest in node_by_digest:
            raise TerminalPayloadAcquisitionError("node SHA-256 is duplicated")
        node_by_digest[digest] = node

    grouped_edges: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    parent_digests: set[str] = set()
    for edge in edges:
        if (
            not isinstance(edge, Mapping)
            or not isinstance(edge.get("parent_sha256"), str)
            or not isinstance(edge.get("child_sha256"), str)
        ):
            raise TerminalPayloadAcquisitionError("edge is invalid")
        if edge.get("status") != "cycle_excluded":
            parent_digests.add(str(edge["parent_sha256"]))
        grouped_edges[str(edge["child_sha256"])].append(edge)

    frontier: list[dict[str, Any]] = []
    selected: set[str] = set()
    pending: set[str] = set()
    blockers: set[str] = set()
    all_edge_statuses = {str(edge.get("status")) for edge in edges if isinstance(edge, Mapping)}
    for digest in sorted(grouped_edges):
        if digest in parent_digests:
            continue
        incoming = grouped_edges[digest]
        sizes = {edge.get("size") for edge in incoming}
        depths = {edge.get("depth") for edge in incoming}
        if (
            len(sizes) != 1
            or any(isinstance(value, bool) or not isinstance(value, int) for value in sizes)
            or any(isinstance(value, bool) or not isinstance(value, int) for value in depths)
        ):
            raise TerminalPayloadAcquisitionError("frontier size or depth is inconsistent")
        edge_statuses = {str(edge.get("status")) for edge in incoming}
        node = node_by_digest.get(digest)
        node_state = str(node.get("state")) if node is not None else "not_queued"
        raw_case_state = node.get("case_state") if node is not None else None
        case_state = str(raw_case_state) if isinstance(raw_case_state, str) else None
        verified = case_state == "complete" and bool(edge_statuses & COMPLETE_EDGE_STATUSES)
        reason = (
            "strict_complete_leaf"
            if verified
            else _frontier_reason(
                edge_statuses=edge_statuses,
                node_state=node_state,
                case_state=case_state,
            )
        )
        if verified:
            selected.add(digest)
        else:
            pending.add(digest)
            blockers.add(reason)
        frontier.append(
            {
                "sha256": digest,
                "size": next(iter(sizes)),
                "depth": min(int(value) for value in depths),
                "roles": sorted({str(edge.get("role")) for edge in incoming}),
                "kinds": sorted({str(edge.get("kind")) for edge in incoming}),
                "parent_sha256": sorted({str(edge.get("parent_sha256")) for edge in incoming}),
                "edge_statuses": sorted(edge_statuses),
                "node_state": node_state,
                "case_state": case_state,
                "disposition": "verified_terminal" if verified else "pending_terminal",
                "reason": reason,
            }
        )

    for edge_status, reason in _EDGE_REASON_PRIORITY:
        if edge_status in all_edge_statuses:
            blockers.add(reason)
    if all_edge_statuses & {"shared_sha256_reused_incomplete", "child_incomplete"}:
        blockers.add("child_analysis_incomplete")

    omitted_sha256 = sorted(
        {
            str(item.get("sha256"))
            for item in omissions
            if isinstance(item, Mapping) and isinstance(item.get("sha256"), str)
        }
    )
    pending.update(set(omitted_sha256) - selected)
    if omissions:
        blockers.add("omitted_metadata")
    if commitments:
        blockers.add("omitted_metadata_commitment")
    if errors:
        blockers.add("follow_on_errors")
    if graph.get("wall_clock_exhausted") is True:
        blockers.add("wall_clock_exhausted")

    if follow_on_status in DISABLED_STATUSES:
        status = "disabled"
        blockers.add(follow_on_status)
    elif follow_on_status == "failed":
        status = "failed"
        blockers.add("fixed_point_failed")
    elif selected:
        status = (
            "verified"
            if follow_on_status == "complete" and not pending and not blockers
            else "partial"
        )
    elif pending or blockers:
        status = "pending"
    else:
        status = "not_recovered"

    next_actions = sorted(
        {
            _NEXT_ACTION_BY_BLOCKER[blocker]
            for blocker in blockers
            if blocker in _NEXT_ACTION_BY_BLOCKER
        }
    )
    if set(next_actions) & {
        "inspect_child_analysis_failure",
        "repair_child_case_integrity",
        "retry_child_static_analysis",
    }:
        next_actions = [value for value in next_actions if value != "continue_child_static_analysis"]
    if status == "pending" and not next_actions:
        next_actions = ["continue_child_static_analysis"]
    elif status == "not_recovered":
        next_actions = ["implement_family_static_recovery"]

    return {
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "method": METHOD,
        "follow_on_status": follow_on_status,
        "external_retrieval_attempted": False,
        "executed_sample": False,
        "network_contacted": False,
        "frontier": frontier,
        "selected_sha256": sorted(selected),
        "pending_sha256": sorted(pending),
        "omitted_sha256": omitted_sha256,
        "blockers": sorted(blockers),
        "next_actions": next_actions,
    }
