#!/usr/bin/env python3
"""static unpacker reportを検証済みlineage selector入力へ変換する。"""

from __future__ import annotations

import hashlib
import re
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

try:
    from .lineage_child_selector import SelectionResult, select_lineage_children
except ImportError:  # pragma: no cover - common directoryを直接sys.pathへ置く実行形態。
    from lineage_child_selector import SelectionResult, select_lineage_children

_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_PARENT_PATH = "lineage/parent.bin"


@dataclass(frozen=True, slots=True)
class _ActualChild:
    """unpackerが返した実byteとselector内だけのsynthetic identity。"""

    index: int
    kind: str | None
    data: bytes
    sha256: str
    size: int
    path: str
    name: str


def _is_sequence(value: object) -> bool:
    return isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray))


def _non_negative_int(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def _digest(value: object) -> str | None:
    return value if isinstance(value, str) and _SHA256_RE.fullmatch(value) else None


def _parent_record(
    *,
    data: bytes,
    sha256: str,
    parent_sha256: str | None,
    depth: int,
) -> dict[str, object]:
    observed_sha256 = hashlib.sha256(data).hexdigest()
    return {
        "sha256": sha256,
        "size": len(data),
        "observed_sha256": observed_sha256,
        "observed_size": len(data),
        "path": _PARENT_PATH,
        "name": "parent.bin",
        "depth": depth,
        "parent_sha256": parent_sha256,
    }


def _ancestor_records(
    ancestors: Sequence[tuple[bytes, str, str | None, int]],
) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for index, (data, sha256, parent_sha256, depth) in enumerate(ancestors):
        observed_sha256 = hashlib.sha256(data).hexdigest()
        name = f"{index:06d}.bin"
        records.append(
            {
                "sha256": sha256,
                "size": len(data),
                "observed_sha256": observed_sha256,
                "observed_size": len(data),
                "path": f"lineage/ancestors/{name}",
                "name": name,
                "depth": depth,
                "parent_sha256": parent_sha256,
            }
        )
    return records


def _actual_children(
    artifacts: Sequence[object],
    *,
    parent_sha256: str,
    depth: int,
) -> tuple[list[_ActualChild], list[object]]:
    children: list[_ActualChild] = []
    records: list[object] = []
    for index, artifact in enumerate(artifacts):
        if not isinstance(artifact, tuple) or len(artifact) != 2:
            records.append({"invalid_returned_artifact": True})
            continue
        raw_kind, data = artifact
        if not isinstance(data, bytes):
            records.append({"invalid_returned_artifact": True})
            continue
        digest = hashlib.sha256(data).hexdigest()
        name = f"{index:06d}.bin"
        path = f"lineage/children/{name}"
        child = _ActualChild(
            index=index,
            kind=raw_kind if isinstance(raw_kind, str) else None,
            data=data,
            sha256=digest,
            size=len(data),
            path=path,
            name=name,
        )
        children.append(child)
        records.append(
            {
                "sha256": digest,
                "size": len(data),
                "observed_sha256": hashlib.sha256(data).hexdigest(),
                "observed_size": len(data),
                "path": path,
                "name": name,
                "depth": depth,
                "parent_sha256": parent_sha256,
            }
        )
    return children, records


def _edge(
    relation: str,
    parent: Mapping[str, object],
    child: _ActualChild,
    *,
    integrity: str = "complete",
) -> dict[str, object]:
    return {
        "relation": relation,
        "source_sha256": parent["sha256"],
        "source_size": parent["size"],
        "source_parent_sha256": parent["parent_sha256"],
        "source_path": parent["path"],
        "target_sha256": child.sha256,
        "target_size": child.size,
        "target_path": child.path,
        "target_name": child.name,
        "source_address": None,
        "integrity": integrity,
    }


def _unknown_edge(
    parent: Mapping[str, object],
    children: Sequence[_ActualChild],
) -> dict[str, object]:
    if children:
        return _edge("script_launch", parent, children[0], integrity="unknown")
    return {
        "relation": "script_launch",
        "source_sha256": parent["sha256"],
        "source_size": parent["size"],
        "source_parent_sha256": parent["parent_sha256"],
        "source_path": parent["path"],
        "target_sha256": parent["sha256"],
        "target_size": parent["size"],
        "target_path": parent["path"],
        "target_name": parent["name"],
        "source_address": None,
        "integrity": "unknown",
    }


def _inno_edges(
    value: object,
    *,
    parent: Mapping[str, object],
    children: Sequence[_ActualChild],
    digest_size_counts: Counter[tuple[str, int]],
) -> tuple[list[dict[str, object]], bool]:
    if value is None:
        return [], True
    if not isinstance(value, Mapping):
        return [], False
    inventory = value.get("inventory")
    selection = value.get("selection")
    script = value.get("install_script")
    tool = value.get("tool")
    members = value.get("recovered_members")
    if not all(isinstance(item, Mapping) for item in (inventory, selection, script, tool)):
        return [], False
    if not _is_sequence(members):
        return [], False
    assert isinstance(inventory, Mapping)
    assert isinstance(selection, Mapping)
    assert isinstance(script, Mapping)
    assert isinstance(tool, Mapping)
    if (
        value.get("candidate") is not True
        or value.get("status") != "artifacts_recovered"
        or value.get("inventory_complete") is not True
        or value.get("extraction_complete") is not True
        or tool.get("identity_unchanged") is not True
        or inventory.get("inventory_complete") is not True
        or _non_negative_int(inventory.get("invalid_member_count")) != 0
        or _non_negative_int(inventory.get("duplicate_member_count")) != 0
        or selection.get("complete_archive_extraction") is not True
        or _non_negative_int(selection.get("omitted_member_count")) != 0
        or selection.get("limit_reasons") != []
        or script.get("status") != "recovered_and_parsed"
        or script.get("decompiler_provenance_verified") is not True
        or script.get("payload_encrypted") is not False
        or _non_negative_int(script.get("dynamic_launch_target_count")) != 0
        or _non_negative_int(script.get("invalid_launch_target_count")) != 0
    ):
        return [], False

    launch_targets = script.get("launch_targets")
    launch_target_count = _non_negative_int(script.get("launch_target_count"))
    if not _is_sequence(launch_targets) or launch_target_count is None:
        return [], False
    folded_targets: list[str] = []
    for target in launch_targets:
        if not isinstance(target, str) or not target or len(target) > 1024:
            return [], False
        folded_targets.append(target.casefold())
    target_set = set(folded_targets)
    if len(target_set) != len(folded_targets) or launch_target_count != len(target_set):
        return [], False

    script_digest = _digest(script.get("sha256"))
    script_size = _non_negative_int(script.get("size"))
    if script_digest is None or script_size is None or script_size == 0:
        return [], False
    actual_scripts = [
        child
        for child in children
        if child.kind == "inno-install-script.iss"
    ]
    if len(actual_scripts) != 1:
        return [], False
    actual_script = actual_scripts[0]
    if (
        actual_script.sha256 != script_digest
        or actual_script.size != script_size
        or digest_size_counts[(script_digest, script_size)] != 1
    ):
        return [], False

    member_rows: list[tuple[str, str, int, bool]] = []
    for raw_member in members:
        if not isinstance(raw_member, Mapping):
            return [], False
        name = raw_member.get("name")
        digest = _digest(raw_member.get("sha256"))
        size = _non_negative_int(raw_member.get("size"))
        launch_target = raw_member.get("launch_target")
        if (
            not isinstance(name, str)
            or not name
            or len(name) > 1024
            or digest is None
            or size is None
            or size == 0
            or not isinstance(launch_target, bool)
        ):
            return [], False
        member_rows.append((name.casefold(), digest, size, launch_target))
    if len({name for name, _digest_value, _size_value, _launch in member_rows}) != len(
        member_rows
    ):
        return [], False
    if Counter(name for name, _digest_value, _size_value, launch in member_rows if launch) != Counter(
        target_set
    ):
        return [], False

    inventory_count = _non_negative_int(inventory.get("member_count"))
    selected_count = _non_negative_int(selection.get("selected_member_count"))
    launch_match_count = _non_negative_int(selection.get("launch_target_match_count"))
    if (
        inventory_count != len(member_rows) + 1
        or selected_count != len(member_rows) + 1
        or launch_match_count != len(target_set)
    ):
        return [], False

    actual_member_children = [
        child
        for child in children
        if child.kind is not None and child.kind.startswith("inno-member-")
    ]
    if len(actual_member_children) != len(member_rows):
        return [], False
    matched_indexes: set[int] = set()
    launch_children: list[_ActualChild] = []
    for _name, expected_digest, expected_size, launch_target in member_rows:
        matching = [
            child
            for child in actual_member_children
            if child.sha256 == expected_digest and child.size == expected_size
        ]
        if len(matching) != 1 or digest_size_counts[(expected_digest, expected_size)] != 1:
            return [], False
        child = matching[0]
        if child.index in matched_indexes:
            return [], False
        matched_indexes.add(child.index)
        if launch_target:
            launch_children.append(child)
    if len(matched_indexes) != len(actual_member_children):
        return [], False
    return [_edge("script_launch", parent, child) for child in launch_children], True


def _bcrypt_edges(
    value: object,
    *,
    parent: Mapping[str, object],
    children: Sequence[_ActualChild],
    digest_size_counts: Counter[tuple[str, int]],
) -> tuple[list[dict[str, object]], bool]:
    if value is None:
        return [], True
    if not isinstance(value, Mapping):
        return [], False
    if value.get("candidate") is not True:
        return [], True
    if (
        value.get("status") != "artifacts_recovered"
        or value.get("candidate_set_complete") is not True
        or value.get("recovery_attempts_complete") is not True
        or value.get("recovered_artifact_set_complete") is not True
    ):
        return [], False
    actual = [
        child
        for child in children
        if child.kind is not None and child.kind.startswith("bcrypt-resource-")
    ]
    count = _non_negative_int(value.get("recovered_artifact_count"))
    total_size = _non_negative_int(value.get("recovered_artifact_total_size"))
    if count is None or total_size is None or count == 0:
        return [], False
    if count != len(actual) or total_size != sum(child.size for child in actual):
        return [], False
    if any(child.size == 0 for child in actual):
        return [], False
    if any(digest_size_counts[(child.sha256, child.size)] != 1 for child in actual):
        return [], False
    return [_edge("resource_decode", parent, child) for child in actual], True


def select_static_layer_children(
    *,
    parent_data: bytes,
    parent_sha256: str,
    parent_parent_sha256: str | None,
    parent_depth: int,
    parent_ancestors: Sequence[tuple[bytes, str, str | None, int]],
    report: Mapping[str, object],
    artifacts: Sequence[object],
) -> SelectionResult:
    """実byteと完全な既存reportだけから、このstepのchild選択を返す。"""

    parent = _parent_record(
        data=parent_data,
        sha256=parent_sha256,
        parent_sha256=parent_parent_sha256,
        depth=parent_depth,
    )
    ancestor_records = _ancestor_records(parent_ancestors)
    children, child_records = _actual_children(
        artifacts,
        parent_sha256=parent_sha256,
        depth=parent_depth + 1,
    )
    digest_size_counts = Counter((child.sha256, child.size) for child in children)
    edges: list[object] = []
    try:
        inno_edges, inno_complete = _inno_edges(
            report.get("inno"),
            parent=parent,
            children=children,
            digest_size_counts=digest_size_counts,
        )
        bcrypt_edges, bcrypt_complete = _bcrypt_edges(
            report.get("bcrypt_resource"),
            parent=parent,
            children=children,
            digest_size_counts=digest_size_counts,
        )
        edges.extend(inno_edges)
        edges.extend(bcrypt_edges)
        if not inno_complete:
            edges.append(_unknown_edge(parent, children))
        if not bcrypt_complete:
            edges.append(_unknown_edge(parent, children))
    except Exception:  # noqa: BLE001 - nested unpacker reportは未信頼入力として閉じる。
        edges = [_unknown_edge(parent, children)]
    return select_lineage_children([*ancestor_records, parent, *child_records], edges)


__all__ = ["select_static_layer_children"]
