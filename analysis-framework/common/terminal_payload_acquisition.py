"""保持payload graphから最終payload取得状態を決定的に要約する。"""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Mapping
from typing import Any

import remediation_registry

SCHEMA_VERSION = 1
METHOD = "offline_verified_retained_output_fixed_point"
MAX_ROOTS = 1_000
MAX_CHILD_NODES = 64
MAX_NODES = MAX_ROOTS + MAX_CHILD_NODES
MAX_EDGES = 128
MAX_OMITTED_METADATA = 4_096
MAX_OMITTED_METADATA_COMMITMENTS = MAX_NODES
MAX_ERRORS = 8_192
MAX_NODE_DEPTH = 4
MAX_EDGE_DEPTH = MAX_NODE_DEPTH + 1
MAX_PAYLOAD_SIZE = 128 * 1024 * 1024
MAX_ANALYSIS_OUTPUT_BYTES = 1024 * 1024 * 1024
MAX_FAMILY_HINTS = 16
MAX_FAMILY_HINT_LINEAGE_DEPTH = 64
MAX_PUBLIC_TEXT_CHARACTERS = 128
MAX_ERROR_CHARACTERS = 512
MAX_RELATIVE_PATH_CHARACTERS = 512

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
FOLLOW_ON_STATUSES = frozenset(
    {
        "complete",
        "partial",
        "failed",
        "no_retained_payloads",
        "disabled_assessment_only",
        "disabled_repository_output",
    }
)
DISABLED_STATUSES = frozenset({"disabled_assessment_only", "disabled_repository_output"})
NON_OPERATIONAL_STATUSES = DISABLED_STATUSES | {"failed"}
OPERATIONAL_STATUSES = frozenset({"complete", "partial", "no_retained_payloads"})
NODE_CASE_STATES = frozenset({"complete", "triaged_unknown", "partial", "failed"})
FAMILY_HINT_NODE_KEYS = frozenset({"family_hint_count", "family_hint_root_sha256", "family_hint_lineage_depth"})
NODE_KEYS_BY_STATE = {
    "root": frozenset({"sha256", "depth", "state"}),
    "queued": frozenset({"sha256", "depth", "size", "state"}) | FAMILY_HINT_NODE_KEYS,
    "timeout": frozenset({"sha256", "depth", "size", "state"}) | FAMILY_HINT_NODE_KEYS,
    "wall_clock_limit": frozenset({"sha256", "depth", "size", "state"}) | FAMILY_HINT_NODE_KEYS,
    "analyzed": frozenset({"sha256", "depth", "size", "state", "case_state"}) | FAMILY_HINT_NODE_KEYS,
    "resumed_complete": frozenset({"sha256", "depth", "size", "state", "case_state"}) | FAMILY_HINT_NODE_KEYS,
    "incomplete_case_omitted": frozenset({"sha256", "depth", "size", "state", "case_state"}) | FAMILY_HINT_NODE_KEYS,
    "failed": frozenset({"sha256", "depth", "size", "state", "error_type"}) | FAMILY_HINT_NODE_KEYS,
}
EDGE_KEYS = frozenset({"parent_sha256", "child_sha256", "depth", "path", "role", "kind", "size", "status"})
EDGE_STATUSES = frozenset(
    {
        "cycle_excluded",
        "depth_limit",
        "payload_size_limit",
        "shared_sha256_excluded",
        "shared_sha256_reused_complete",
        "shared_sha256_reused_incomplete",
        "artifact_count_limit",
        "total_bytes_limit",
        "child_complete",
        "child_incomplete",
    }
)
ACTIVE_EDGE_STATUSES = frozenset({"child_complete", "child_incomplete"})
REUSED_EDGE_STATUSES = frozenset({"shared_sha256_reused_complete", "shared_sha256_reused_incomplete"})
EDGE_STATUSES_REQUIRING_CHILD = (
    ACTIVE_EDGE_STATUSES
    | REUSED_EDGE_STATUSES
    | {
        "cycle_excluded",
        "shared_sha256_excluded",
    }
)
COMPLETE_EDGE_STATUSES = frozenset({"child_complete", "shared_sha256_reused_complete"})
OMISSION_KEYS = frozenset({"parent_sha256", "sha256", "size", "path", "role", "kind", "reason"})
OMISSION_REASONS = frozenset(
    {
        "verified_output_edge_limit",
        "verified_output_read_bytes_limit",
        "verified_output_read_wall_clock_limit",
        "artifact_verification_failed",
    }
)
COMMITMENT_KEYS = frozenset({"parent_sha256", "count", "sha256"})
RESERVED_WINDOWS_NAMES = {
    "aux",
    "clock$",
    "con",
    "nul",
    "prn",
    *(f"com{index}" for index in range(1, 10)),
    *(f"lpt{index}" for index in range(1, 10)),
}

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
_GENERATED_BLOCKER_REASONS = frozenset(
    {
        *(reason for _, reason in _EDGE_REASON_PRIORITY),
        *_NODE_REASON.values(),
        *DISABLED_STATUSES,
        "child_analysis_incomplete",
        "fixed_point_failed",
        "follow_on_errors",
        "omitted_metadata",
        "omitted_metadata_commitment",
        "terminal_verification_incomplete",
        "wall_clock_exhausted",
    }
)
if _GENERATED_BLOCKER_REASONS != remediation_registry.TERMINAL_ACQUISITION_REASONS:
    raise RuntimeError("terminal acquisition blocker生成器がregistryに対して閉じていません")


class TerminalPayloadAcquisitionError(ValueError):
    """最終payload取得graphが決定的に解釈できない場合に送出する。"""


def _array(value: object, *, label: str, maximum: int) -> list[Any]:
    if not isinstance(value, list):
        raise TerminalPayloadAcquisitionError(f"{label}はJSON arrayである必要があります")
    if len(value) > maximum:
        raise TerminalPayloadAcquisitionError(f"{label}が{maximum}件の上限を超えています")
    return value


def _sha256(value: object, *, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise TerminalPayloadAcquisitionError(f"{label}は小文字16進64文字のSHA-256である必要があります")
    return value


def _bounded_integer(
    value: object,
    *,
    label: str,
    minimum: int,
    maximum: int,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise TerminalPayloadAcquisitionError(f"{label}は{minimum}..{maximum}の整数である必要があります")
    return value


def _safe_public_text(value: object, *, label: str, maximum: int = MAX_PUBLIC_TEXT_CHARACTERS) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise TerminalPayloadAcquisitionError(f"{label}が安全な公開文字列ではありません")
    return value


def _relative_path(value: object, *, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > MAX_RELATIVE_PATH_CHARACTERS
        or "\\" in value
        or "\x00" in value
        or value.startswith(("/", "//"))
        or re.match(r"^[A-Za-z]:", value)
    ):
        raise TerminalPayloadAcquisitionError(f"{label}が正規化済み相対pathではありません")
    parts = value.split("/")
    if any(not part or part in {".", ".."} for part in parts):
        raise TerminalPayloadAcquisitionError(f"{label}に不正なpath componentがあります")
    for part in parts:
        stem = part.split(".", 1)[0].casefold()
        if (
            part.endswith((" ", "."))
            or any(ord(character) < 32 for character in part)
            or stem in RESERVED_WINDOWS_NAMES
        ):
            raise TerminalPayloadAcquisitionError(f"{label}に曖昧または予約済みのpath componentがあります")
    return value


def _validate_errors(raw_errors: list[Any]) -> set[str]:
    errors: set[str] = set()
    for index, value in enumerate(raw_errors):
        if not isinstance(value, str) or len(value) > MAX_ERROR_CHARACTERS:
            raise TerminalPayloadAcquisitionError(f"errors[{index}]が不正です")
        errors.add(value)
    return errors


def _validate_nodes(nodes: list[Any]) -> dict[str, dict[str, Any]]:
    node_by_digest: dict[str, dict[str, Any]] = {}
    child_count = 0
    for index, raw_node in enumerate(nodes):
        if not isinstance(raw_node, dict):
            raise TerminalPayloadAcquisitionError(f"nodes[{index}]はobjectである必要があります")
        state = raw_node.get("state")
        expected_keys = NODE_KEYS_BY_STATE.get(state) if isinstance(state, str) else None
        if expected_keys is None or set(raw_node) != expected_keys:
            raise TerminalPayloadAcquisitionError(f"nodes[{index}]のstateまたはschemaが不正です")
        digest = _sha256(raw_node.get("sha256"), label=f"nodes[{index}].sha256")
        if digest in node_by_digest:
            raise TerminalPayloadAcquisitionError("node SHA-256が重複しています")
        depth = _bounded_integer(
            raw_node.get("depth"),
            label=f"nodes[{index}].depth",
            minimum=0,
            maximum=MAX_NODE_DEPTH,
        )
        case_state = raw_node.get("case_state")
        if (
            "case_state" in raw_node
            and case_state is not None
            and (not isinstance(case_state, str) or case_state not in NODE_CASE_STATES)
        ):
            raise TerminalPayloadAcquisitionError(f"nodes[{index}].case_stateが許可domain外です")
        if depth == 0:
            if state != "root":
                raise TerminalPayloadAcquisitionError(f"nodes[{index}]のdepth 0 stateがrootではありません")
        else:
            child_count += 1
            if state == "root":
                raise TerminalPayloadAcquisitionError(f"nodes[{index}]の非root depthにroot stateがあります")
            _bounded_integer(
                raw_node.get("size"),
                label=f"nodes[{index}].size",
                minimum=0,
                maximum=MAX_PAYLOAD_SIZE,
            )
            hint_count = _bounded_integer(
                raw_node.get("family_hint_count"),
                label=f"nodes[{index}].family_hint_count",
                minimum=0,
                maximum=MAX_FAMILY_HINTS,
            )
            hint_root = raw_node.get("family_hint_root_sha256")
            hint_depth = raw_node.get("family_hint_lineage_depth")
            if hint_count == 0:
                if hint_root is not None or hint_depth is not None:
                    raise TerminalPayloadAcquisitionError(f"nodes[{index}]のfamily hint lineageが不正です")
            else:
                validated_hint_root = _sha256(
                    hint_root,
                    label=f"nodes[{index}].family_hint_root_sha256",
                )
                if validated_hint_root == digest:
                    raise TerminalPayloadAcquisitionError(f"nodes[{index}]のfamily hint rootが自己参照です")
                _bounded_integer(
                    hint_depth,
                    label=f"nodes[{index}].family_hint_lineage_depth",
                    minimum=1,
                    maximum=MAX_FAMILY_HINT_LINEAGE_DEPTH,
                )
        if state == "failed":
            _safe_public_text(raw_node.get("error_type"), label=f"nodes[{index}].error_type")
        node_by_digest[digest] = raw_node
    if child_count > MAX_CHILD_NODES:
        raise TerminalPayloadAcquisitionError(f"child nodeが{MAX_CHILD_NODES}件の上限を超えています")
    return node_by_digest


def _validate_root_case_states(
    root_case_states: Mapping[str, str] | None,
    *,
    roots: list[str],
) -> dict[str, str]:
    if root_case_states is None:
        return {}
    if not isinstance(root_case_states, Mapping):
        raise TerminalPayloadAcquisitionError("root_case_statesはmappingである必要があります")
    validated: dict[str, str] = {}
    for raw_digest, raw_case_state in root_case_states.items():
        digest = _sha256(raw_digest, label="root_case_states key")
        if digest in validated:
            raise TerminalPayloadAcquisitionError("root_case_statesのSHA-256が重複しています")
        if not isinstance(raw_case_state, str) or raw_case_state not in NODE_CASE_STATES:
            raise TerminalPayloadAcquisitionError("root_case_statesのcase_stateが許可domain外です")
        validated[digest] = raw_case_state
    if set(validated) != set(roots):
        raise TerminalPayloadAcquisitionError("root_case_statesのkeyがrootsと一致しません")
    return validated


def _validate_edges(
    edges: list[Any],
    *,
    node_by_digest: Mapping[str, Mapping[str, Any]],
) -> tuple[dict[str, list[dict[str, Any]]], set[str]]:
    grouped_edges: dict[str, list[dict[str, Any]]] = defaultdict(list)
    parent_digests: set[str] = set()
    active_incoming_parents: dict[str, list[str]] = defaultdict(list)
    cycle_edges: list[tuple[str, str]] = []
    sizes_by_child: dict[str, set[int]] = defaultdict(set)
    for index, raw_edge in enumerate(edges):
        if not isinstance(raw_edge, dict) or set(raw_edge) != EDGE_KEYS:
            raise TerminalPayloadAcquisitionError(f"edges[{index}]のschemaが不正です")
        parent_digest = _sha256(raw_edge.get("parent_sha256"), label=f"edges[{index}].parent_sha256")
        child_digest = _sha256(raw_edge.get("child_sha256"), label=f"edges[{index}].child_sha256")
        depth = _bounded_integer(
            raw_edge.get("depth"),
            label=f"edges[{index}].depth",
            minimum=1,
            maximum=MAX_EDGE_DEPTH,
        )
        size = _bounded_integer(
            raw_edge.get("size"),
            label=f"edges[{index}].size",
            minimum=0,
            maximum=MAX_ANALYSIS_OUTPUT_BYTES,
        )
        _relative_path(raw_edge.get("path"), label=f"edges[{index}].path")
        _safe_public_text(raw_edge.get("role"), label=f"edges[{index}].role")
        _safe_public_text(raw_edge.get("kind"), label=f"edges[{index}].kind")
        edge_status = raw_edge.get("status")
        if not isinstance(edge_status, str) or edge_status not in EDGE_STATUSES:
            raise TerminalPayloadAcquisitionError(f"edges[{index}].statusが許可domain外です")
        parent = node_by_digest.get(parent_digest)
        child = node_by_digest.get(child_digest)
        if parent is None or depth != parent["depth"] + 1:
            raise TerminalPayloadAcquisitionError(f"edges[{index}]のparent endpointまたはdepthが不正です")
        if edge_status in EDGE_STATUSES_REQUIRING_CHILD and child is None:
            raise TerminalPayloadAcquisitionError(f"edges[{index}]のchild endpointがありません")
        if edge_status in ACTIVE_EDGE_STATUSES:
            if child is None or child["depth"] != depth or child.get("size") != size:
                raise TerminalPayloadAcquisitionError(f"edges[{index}]のactive child endpointが不整合です")
            active_incoming_parents[child_digest].append(parent_digest)
        elif child is not None and child["depth"] > 0 and child.get("size") != size:
            raise TerminalPayloadAcquisitionError(f"edges[{index}]とchild nodeのsizeが一致しません")
        if edge_status == "cycle_excluded" and (child is None or child["depth"] >= depth):
            raise TerminalPayloadAcquisitionError(f"edges[{index}]のcycle endpointがancestorではありません")
        if edge_status == "cycle_excluded":
            cycle_edges.append((parent_digest, child_digest))
        if edge_status == "depth_limit" and depth != MAX_EDGE_DEPTH:
            raise TerminalPayloadAcquisitionError(f"edges[{index}]のdepth_limitが境界外です")
        if edge_status == "payload_size_limit" and size <= MAX_PAYLOAD_SIZE:
            raise TerminalPayloadAcquisitionError(f"edges[{index}]のpayload_size_limitがsize上限以下です")
        if edge_status == "child_complete" and (
            child is None
            or child.get("state") not in {"analyzed", "resumed_complete"}
            or child.get("case_state") != "complete"
        ):
            raise TerminalPayloadAcquisitionError(f"edges[{index}]のcomplete child状態が不正です")
        if (
            edge_status == "child_incomplete"
            and child is not None
            and (child.get("state") in {"analyzed", "resumed_complete"} and child.get("case_state") == "complete")
        ):
            raise TerminalPayloadAcquisitionError(f"edges[{index}]のincomplete child状態が不正です")
        if (
            edge_status == "shared_sha256_reused_complete"
            and child is not None
            and child["depth"] > 0
            and (child.get("state") not in {"analyzed", "resumed_complete"} or child.get("case_state") != "complete")
        ):
            raise TerminalPayloadAcquisitionError(f"edges[{index}]のreused complete child状態が不正です")
        if (
            edge_status == "shared_sha256_reused_incomplete"
            and child is not None
            and child["depth"] > 0
            and (child.get("state") in {"analyzed", "resumed_complete"} and child.get("case_state") == "complete")
        ):
            raise TerminalPayloadAcquisitionError(f"edges[{index}]のreused incomplete child状態が不正です")
        if edge_status != "cycle_excluded":
            parent_digests.add(parent_digest)
        grouped_edges[child_digest].append(raw_edge)
        sizes_by_child[child_digest].add(size)
    inconsistent_sizes = sorted(digest for digest, sizes in sizes_by_child.items() if len(sizes) != 1)
    if inconsistent_sizes:
        raise TerminalPayloadAcquisitionError("同一child SHA-256のedge sizeが一致しません")
    invalid_active_incoming = sorted(
        digest
        for digest, node in node_by_digest.items()
        if node["depth"] > 0 and len(active_incoming_parents.get(digest, ())) != 1
    )
    if invalid_active_incoming:
        raise TerminalPayloadAcquisitionError("非root child nodeのactive incoming edgeがexactly 1本ではありません")
    active_parent_by_child = {
        digest: parents[0]
        for digest, parents in active_incoming_parents.items()
    }
    for parent_digest, child_digest in cycle_edges:
        cursor = parent_digest
        visited: set[str] = set()
        while cursor != child_digest:
            if cursor in visited or cursor not in active_parent_by_child:
                raise TerminalPayloadAcquisitionError("cycle_excluded childがparentの実ancestorではありません")
            visited.add(cursor)
            cursor = active_parent_by_child[cursor]
    return grouped_edges, parent_digests


def _validate_omissions(
    omissions: list[Any],
    *,
    node_by_digest: Mapping[str, Mapping[str, Any]],
    errors: set[str],
    wall_clock_exhausted: bool,
) -> list[dict[str, Any]]:
    validated: list[dict[str, Any]] = []
    for index, raw_omission in enumerate(omissions):
        if not isinstance(raw_omission, dict) or set(raw_omission) != OMISSION_KEYS:
            raise TerminalPayloadAcquisitionError(f"omitted_metadata[{index}]のschemaが不正です")
        parent_digest = _sha256(
            raw_omission.get("parent_sha256"),
            label=f"omitted_metadata[{index}].parent_sha256",
        )
        payload_digest = _sha256(raw_omission.get("sha256"), label=f"omitted_metadata[{index}].sha256")
        _bounded_integer(
            raw_omission.get("size"),
            label=f"omitted_metadata[{index}].size",
            minimum=0,
            maximum=MAX_ANALYSIS_OUTPUT_BYTES,
        )
        _relative_path(raw_omission.get("path"), label=f"omitted_metadata[{index}].path")
        _safe_public_text(raw_omission.get("role"), label=f"omitted_metadata[{index}].role")
        _safe_public_text(raw_omission.get("kind"), label=f"omitted_metadata[{index}].kind")
        reason = raw_omission.get("reason")
        marker = (
            f"{parent_digest}:artifact_verification_failed:{payload_digest}"
            if reason == "artifact_verification_failed"
            else f"{parent_digest}:{reason}"
        )
        if (
            parent_digest not in node_by_digest
            or not isinstance(reason, str)
            or reason not in OMISSION_REASONS
            or marker not in errors
            or (reason == "verified_output_read_wall_clock_limit" and not wall_clock_exhausted)
        ):
            raise TerminalPayloadAcquisitionError(f"omitted_metadata[{index}]のfield整合性が不正です")
        validated.append(raw_omission)
    return validated


def _validate_commitments(
    commitments: list[Any],
    *,
    node_by_digest: Mapping[str, Mapping[str, Any]],
    errors: set[str],
) -> list[dict[str, Any]]:
    validated: list[dict[str, Any]] = []
    parents: list[str] = []
    for index, raw_commitment in enumerate(commitments):
        if not isinstance(raw_commitment, dict) or set(raw_commitment) != COMMITMENT_KEYS:
            raise TerminalPayloadAcquisitionError(f"omitted_metadata_commitments[{index}]のschemaが不正です")
        parent_digest = _sha256(
            raw_commitment.get("parent_sha256"),
            label=f"omitted_metadata_commitments[{index}].parent_sha256",
        )
        _bounded_integer(
            raw_commitment.get("count"),
            label=f"omitted_metadata_commitments[{index}].count",
            minimum=1,
            maximum=(1 << 63) - 1,
        )
        _sha256(raw_commitment.get("sha256"), label=f"omitted_metadata_commitments[{index}].sha256")
        if (
            parent_digest not in node_by_digest
            or f"{parent_digest}:verified_output_omitted_metadata_limit" not in errors
        ):
            raise TerminalPayloadAcquisitionError(
                f"omitted_metadata_commitments[{index}]のparentまたはerror markerが不正です"
            )
        parents.append(parent_digest)
        validated.append(raw_commitment)
    if parents != sorted(set(parents)):
        raise TerminalPayloadAcquisitionError("omitted metadata commitmentが重複または未整列です")
    return validated


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


def build_terminal_payload_acquisition(
    graph: Mapping[str, Any],
    *,
    root_case_states: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """follow-on graphからraw bytesを含まない終端frontierを生成する。"""

    follow_on_status = graph.get("status")
    if not isinstance(follow_on_status, str) or follow_on_status not in FOLLOW_ON_STATUSES:
        raise TerminalPayloadAcquisitionError("follow-on statusが許可domain外です")
    roots = _array(graph.get("roots"), label="roots", maximum=MAX_ROOTS)
    nodes = _array(graph.get("nodes"), label="nodes", maximum=MAX_NODES)
    edges = _array(graph.get("edges"), label="edges", maximum=MAX_EDGES)
    raw_omissions = _array(
        graph.get("omitted_metadata"),
        label="omitted_metadata",
        maximum=MAX_OMITTED_METADATA,
    )
    raw_commitments = _array(
        graph.get("omitted_metadata_commitments"),
        label="omitted_metadata_commitments",
        maximum=MAX_OMITTED_METADATA_COMMITMENTS,
    )
    raw_errors = _array(graph.get("errors"), label="errors", maximum=MAX_ERRORS)
    validated_roots = [_sha256(value, label=f"roots[{index}]") for index, value in enumerate(roots)]
    if validated_roots != sorted(set(validated_roots)):
        raise TerminalPayloadAcquisitionError("rootsが重複または未整列です")
    validated_root_case_states = _validate_root_case_states(
        root_case_states,
        roots=validated_roots,
    )
    wall_clock_raw = graph.get("wall_clock_exhausted")
    if "wall_clock_exhausted" in graph:
        if type(wall_clock_raw) is not bool:
            raise TerminalPayloadAcquisitionError("wall_clock_exhaustedはbooleanである必要があります")
        wall_clock_exhausted = bool(wall_clock_raw)
    elif follow_on_status in OPERATIONAL_STATUSES or follow_on_status == "disabled_repository_output":
        raise TerminalPayloadAcquisitionError("follow-on statusに必要なwall_clock_exhaustedがありません")
    else:
        wall_clock_exhausted = False
    if wall_clock_exhausted and follow_on_status != "partial":
        raise TerminalPayloadAcquisitionError("wall_clock_exhaustedとfollow-on statusが矛盾します")

    errors = _validate_errors(raw_errors)
    node_by_digest = _validate_nodes(nodes)
    node_roots = sorted(digest for digest, node in node_by_digest.items() if node["depth"] == 0)
    if follow_on_status in NON_OPERATIONAL_STATUSES:
        if nodes or edges or raw_omissions or raw_commitments:
            raise TerminalPayloadAcquisitionError("非実行follow-on statusにgraph要素があります")
    elif validated_roots != node_roots:
        raise TerminalPayloadAcquisitionError("rootsとdepth 0 nodeが一致しません")

    grouped_edges, parent_digests = _validate_edges(edges, node_by_digest=node_by_digest)
    omissions = _validate_omissions(
        raw_omissions,
        node_by_digest=node_by_digest,
        errors=errors,
        wall_clock_exhausted=wall_clock_exhausted,
    )
    commitments = _validate_commitments(
        raw_commitments,
        node_by_digest=node_by_digest,
        errors=errors,
    )
    if (omissions or commitments) and follow_on_status != "partial":
        raise TerminalPayloadAcquisitionError("omissionを持つfollow-on graphはpartialである必要があります")
    if follow_on_status == "complete" and (
        not edges
        or errors
        or wall_clock_exhausted
        or any(edge["status"] not in COMPLETE_EDGE_STATUSES for edge in edges)
    ):
        raise TerminalPayloadAcquisitionError("complete follow-on graphに未完了要素があります")
    if follow_on_status == "no_retained_payloads" and (
        edges or errors or omissions or commitments or wall_clock_exhausted
    ):
        raise TerminalPayloadAcquisitionError("no_retained_payloadsとgraph内容が矛盾します")

    frontier: list[dict[str, Any]] = []
    selected: set[str] = set()
    pending: set[str] = set()
    blockers: set[str] = set()
    all_edge_statuses = {edge["status"] for edge in edges}
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
        raw_case_state = (
            validated_root_case_states.get(digest)
            if node_state == "root"
            else node.get("case_state") if node is not None else None
        )
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

    omitted_sha256 = sorted({item["sha256"] for item in omissions})
    pending.update(set(omitted_sha256) - selected)
    if omissions:
        blockers.add("omitted_metadata")
    if commitments:
        blockers.add("omitted_metadata_commitment")
    if errors:
        blockers.add("follow_on_errors")
    if wall_clock_exhausted:
        blockers.add("wall_clock_exhausted")

    if follow_on_status in DISABLED_STATUSES:
        status = "disabled"
        blockers.add(follow_on_status)
    elif follow_on_status == "failed":
        status = "failed"
        blockers.add("fixed_point_failed")
    elif selected:
        status = "verified" if follow_on_status == "complete" and not pending and not blockers else "partial"
    elif pending or blockers:
        status = "pending"
    else:
        status = "not_recovered"

    try:
        next_actions = remediation_registry.terminal_next_actions(blockers)
    except remediation_registry.UnknownBlockerError as exc:
        raise TerminalPayloadAcquisitionError("terminal blockerがremediation registryに登録されていません") from exc
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
