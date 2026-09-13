"""lineage-aware child selectorの安全境界と決定性を検証する。"""

from __future__ import annotations

import json
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

import pytest

COMMON = Path(__file__).resolve().parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

from lineage_child_selector import (
    MAX_ARTIFACTS,
    MAX_CHILD_BYTES,
    MAX_CHILDREN_PER_PARENT,
    MAX_DEPTH,
    MAX_EDGES,
    MAX_OVERFLOW_COMMITMENT_SAMPLES,
    MAX_SELECTED_CHILDREN,
    MAX_TOTAL_BYTES,
    SelectionPolicy,
    select_lineage_children,
)


def _digest(index: int) -> str:
    return f"{index:064x}"


def _artifact(
    index: int,
    *,
    depth: int,
    size: int = 1,
    path: str | None = None,
    name: str | None = None,
    parent_sha256: str | None = None,
    sha256: str | None = None,
) -> dict[str, object]:
    selected_path = path or f"layer-{depth}/artifact-{index:04d}.bin"
    selected_name = name or PureName(selected_path)
    digest = sha256 or _digest(index)
    return {
        "sha256": digest,
        "size": size,
        "observed_sha256": digest,
        "observed_size": size,
        "path": selected_path,
        "name": selected_name,
        "depth": depth,
        "parent_sha256": parent_sha256,
    }


def PureName(path: str) -> str:
    """テスト用POSIX pathのbasenameを返す。"""

    return path.rsplit("/", 1)[-1]


class _HugeSequence(Sequence[object]):
    """巨大な見かけ上の長さとsample読取回数を記録するSequence。"""

    def __init__(self, length: int) -> None:
        self.length = length
        self.read_indexes: list[int] = []

    def __len__(self) -> int:
        return self.length

    def __getitem__(self, index: int) -> object:
        self.read_indexes.append(index)
        if len(self.read_indexes) > MAX_OVERFLOW_COMMITMENT_SAMPLES:
            raise AssertionError("overflow sample capを超えました")
        return {"position": index}


class _ExplodingMapping(Mapping[str, object]):
    """全操作で例外を送出する未信頼Mapping。"""

    def __getitem__(self, key: str) -> object:
        raise RuntimeError("unreadable")

    def __iter__(self):
        raise RuntimeError("unreadable")

    def __len__(self) -> int:
        raise RuntimeError("unreadable")


class _ExplodingSequence(Sequence[object]):
    """長さ取得で例外を送出する未信頼Sequence。"""

    def __getitem__(self, index: int) -> object:
        raise RuntimeError("unreadable")

    def __len__(self) -> int:
        raise RuntimeError("unreadable")


def _edge(
    source: dict[str, object],
    target: dict[str, object],
    *,
    relation: str = "script_launch",
    target_path: bool = True,
    integrity: str = "complete",
    address: str | None = "0x401000",
) -> dict[str, object]:
    return {
        "relation": relation,
        "source_sha256": source["sha256"],
        "source_size": source["size"],
        "source_parent_sha256": source["parent_sha256"],
        "source_path": source["path"],
        "target_sha256": target["sha256"],
        "target_size": target["size"],
        "target_path": target["path"] if target_path else None,
        "target_name": target["name"],
        "source_address": address,
        "integrity": integrity,
    }


def test_resource_decode_is_a_positive_seed() -> None:
    """完全なresource decodeはsource未選択でもchildをseed選択する。"""

    root = _artifact(1, depth=0)
    child = _artifact(2, depth=1, parent_sha256=root["sha256"])

    result = select_lineage_children([root, child], [_edge(root, child, relation="resource_decode")])

    assert result.status == "complete_selected"
    assert result.selected_sha256 == (child["sha256"],)
    assert result.selected_digests == result.selected_sha256
    assert result.selected_relation_counts == (("resource_decode", 1),)


def test_non_root_artifact_requires_exact_parent_sha256_schema() -> None:
    """non-rootのparent欠落とartifact extra keyをexact schemaで拒否する。"""

    missing_parent = _artifact(5, depth=1)
    extra_key = _artifact(6, depth=0)
    extra_key["extra"] = True

    result = select_lineage_children([missing_parent, extra_key], [])

    assert result.status == "partial"
    assert dict(result.omitted_reason_counts) == {"invalid_artifact_schema": 2}


def test_parent_must_exist_once_at_previous_depth() -> None:
    """missing・wrong-depth・ambiguous・invalid-chain parentをartifact集合で拒否する。"""

    missing = _artifact(7, depth=1, parent_sha256=_digest(700))
    wrong_parent = _artifact(8, depth=0)
    wrong_depth = _artifact(9, depth=2, parent_sha256=wrong_parent["sha256"])
    shared_parent_digest = _digest(10)
    duplicate_parents = [
        _artifact(10, depth=0, path="first/container.bin", sha256=shared_parent_digest),
        _artifact(11, depth=0, path="second/container.bin", sha256=shared_parent_digest),
    ]
    ambiguous = _artifact(12, depth=1, parent_sha256=shared_parent_digest)
    invalid_parent = _artifact(13, depth=1, parent_sha256=_digest(701))
    invalid_chain = _artifact(14, depth=2, parent_sha256=invalid_parent["sha256"])

    result = select_lineage_children(
        [
            missing,
            wrong_parent,
            wrong_depth,
            *duplicate_parents,
            ambiguous,
            invalid_parent,
            invalid_chain,
        ],
        [],
    )

    assert result.status == "partial"
    assert dict(result.omitted_reason_counts) == {
        "parent_ambiguous": 1,
        "parent_depth_mismatch": 1,
        "parent_invalid": 1,
        "parent_not_found": 2,
    }


def test_fake_shared_parent_digest_cannot_authorize_sibling_edge() -> None:
    """実在しない同一parent digestの自己申告でsame-depth siblingにしない。"""

    fake_parent = _digest(702)
    source = _artifact(15, depth=1, parent_sha256=fake_parent)
    target = _artifact(16, depth=1, parent_sha256=fake_parent)

    result = select_lineage_children([source, target], [_edge(source, target)])

    assert result.status == "partial"
    assert result.selected_sha256 == ()
    assert dict(result.omitted_reason_counts)["parent_not_found"] == 2


def test_parent_failure_reasons_are_direct_and_fail_closed() -> None:
    """各parent検証failureを直接観測でき、childを一件も返さない。"""

    missing = _artifact(17, depth=1, parent_sha256=_digest(710))
    missing_result = select_lineage_children([missing], [])
    assert dict(missing_result.omitted_reason_counts) == {"parent_not_found": 1}

    root = _artifact(18, depth=0)
    wrong_depth = _artifact(19, depth=2, parent_sha256=root["sha256"])
    wrong_result = select_lineage_children([root, wrong_depth], [])
    assert dict(wrong_result.omitted_reason_counts) == {"parent_depth_mismatch": 1}

    duplicated_digest = _digest(20)
    parents = [
        _artifact(20, depth=0, path="one/root.bin", sha256=duplicated_digest),
        _artifact(21, depth=0, path="two/root.bin", sha256=duplicated_digest),
    ]
    ambiguous = _artifact(22, depth=1, parent_sha256=duplicated_digest)
    ambiguous_result = select_lineage_children([*parents, ambiguous], [])
    assert dict(ambiguous_result.omitted_reason_counts) == {"parent_ambiguous": 1}

    invalid_parent = _artifact(23, depth=1, parent_sha256=_digest(711))
    invalid_child = _artifact(24, depth=2, parent_sha256=invalid_parent["sha256"])
    invalid_result = select_lineage_children([invalid_parent, invalid_child], [])
    assert dict(invalid_result.omitted_reason_counts) == {
        "parent_invalid": 1,
        "parent_not_found": 1,
    }
    for result in (missing_result, wrong_result, ambiguous_result, invalid_result):
        assert result.status == "partial"
        assert result.selected_artifacts == ()


def test_unlaunched_import_is_not_a_seed() -> None:
    """未選択PEからのimportだけではchildを選択しない。"""

    container = _digest(900)
    parent = _artifact(900, depth=0)
    root = _artifact(3, depth=1, parent_sha256=container)
    imported = _artifact(4, depth=1, parent_sha256=container)

    result = select_lineage_children(
        [parent, root, imported], [_edge(root, imported, relation="pe_import")]
    )

    assert result.status == "complete_no_executable_child"
    assert result.selected_sha256 == ()
    assert result.unselected_non_seed_edge_count == 1


def test_transitive_edges_advance_only_from_selected_sources_through_depth_four() -> None:
    """seedから選択済みsourceをたどり、depth 4まで推移する。"""

    artifacts = [_artifact(10, depth=0)]
    for index in range(11, 15):
        artifacts.append(
            _artifact(
                index,
                depth=index - 10,
                parent_sha256=artifacts[-1]["sha256"],
            )
        )
    edges = [
        _edge(artifacts[0], artifacts[1], relation="resource_decode"),
        _edge(artifacts[1], artifacts[2], relation="resource_decode"),
        _edge(artifacts[2], artifacts[3], relation="resource_decode"),
        _edge(artifacts[3], artifacts[4], relation="resource_decode"),
    ]

    result = select_lineage_children(artifacts, edges)

    assert result.status == "complete_selected"
    assert result.selected_sha256 == tuple(sorted(item["sha256"] for item in artifacts[1:]))


def test_ambiguous_basename_is_fail_closed_partial() -> None:
    """同名artifactが複数あるbasename参照をdigestだけで救済しない。"""

    root = _artifact(20, depth=0)
    first = _artifact(
        21,
        depth=1,
        path="a/shared.dll",
        name="shared.dll",
        parent_sha256=root["sha256"],
    )
    second = _artifact(
        22,
        depth=1,
        path="b/shared.dll",
        name="shared.dll",
        parent_sha256=root["sha256"],
    )
    edge = _edge(root, first, target_path=False)

    result = select_lineage_children([root, first, second], [edge])

    assert result.status == "partial"
    assert result.selected_sha256 == ()
    assert dict(result.omitted_reason_counts) == {"target_ambiguous": 1}


def test_pe_import_advances_to_selected_source_sibling() -> None:
    """実際のscript起動からimport、literal loadへ同じ階層で推移する。"""

    container = _digest(24)
    parent = _artifact(24, depth=0)
    script = _artifact(25, depth=1, path="bundle/start.vbs", parent_sha256=container)
    host = _artifact(26, depth=1, path="bundle/host.exe", parent_sha256=container)
    imported = _artifact(27, depth=1, path="bundle/version.dll", parent_sha256=container)
    literal = _artifact(28, depth=1, path="bundle/stage.bin", parent_sha256=container)
    edges = [
        _edge(script, host, relation="script_launch"),
        _edge(host, imported, relation="pe_import"),
        _edge(imported, literal, relation="pe_literal_load"),
    ]

    result = select_lineage_children([parent, script, host, imported, literal], edges)

    assert result.status == "complete_selected"
    assert len(result.selected_sha256) == 3
    assert set(result.selected_sha256) == {host["sha256"], imported["sha256"], literal["sha256"]}


@pytest.mark.parametrize(
    ("relation", "source_depth", "target_depth"),
    [
        ("resource_decode", 1, 1),
        ("pe_import", 1, 2),
        ("pe_literal_load", 1, 2),
        ("script_launch", 1, 3),
    ],
)
def test_relation_specific_invalid_depth_is_partial(
    relation: str, source_depth: int, target_depth: int
) -> None:
    """relationごとの許可depth以外をlineageへ採用しない。"""

    container = _digest(80)
    parent = _artifact(80, depth=0)
    source = _artifact(81, depth=source_depth, parent_sha256=container)
    intermediate: list[dict[str, object]] = []
    if target_depth == source_depth + 2:
        middle = _artifact(83, depth=source_depth + 1, parent_sha256=source["sha256"])
        intermediate.append(middle)
        target_parent = middle["sha256"]
    else:
        target_parent = source["sha256"] if target_depth == source_depth + 1 else container
    target = _artifact(82, depth=target_depth, parent_sha256=target_parent)

    result = select_lineage_children(
        [parent, source, *intermediate, target],
        [_edge(source, target, relation=relation)],
    )

    assert result.status == "partial"
    assert result.selected_sha256 == ()
    assert dict(result.omitted_reason_counts) == {"invalid_depth_transition": 1}


def test_cross_container_same_depth_and_child_edges_are_partial() -> None:
    """同階層・直下relationのどちらもcontainment parent不一致を拒否する。"""

    first_parent = _artifact(901, depth=0)
    second_parent = _artifact(902, depth=0)
    third_root = _artifact(904, depth=0)
    wrong_parent = _artifact(903, depth=1, parent_sha256=third_root["sha256"])
    source = _artifact(90, depth=1, parent_sha256=first_parent["sha256"])
    sibling = _artifact(91, depth=1, parent_sha256=second_parent["sha256"])
    child = _artifact(92, depth=2, parent_sha256=wrong_parent["sha256"])

    sibling_result = select_lineage_children(
        [first_parent, second_parent, source, sibling],
        [_edge(source, sibling, relation="script_launch")],
    )
    child_result = select_lineage_children(
        [first_parent, third_root, wrong_parent, source, child],
        [_edge(source, child, relation="resource_decode")],
    )

    assert dict(sibling_result.omitted_reason_counts) == {"cross_container": 1}
    assert dict(child_result.omitted_reason_counts) == {"cross_container": 1}


def test_windows_casefold_paths_resolve_but_collisions_are_ambiguous() -> None:
    """大小文字だけの参照差は許可し、同一container内の衝突は拒否する。"""

    container = _digest(100)
    parent = _artifact(100, depth=0)
    source = _artifact(101, depth=1, path="Bundle/Host.EXE", parent_sha256=container)
    target = _artifact(102, depth=1, path="Bundle/Version.DLL", parent_sha256=container)
    edge = _edge(source, target, relation="script_launch")
    edge["source_path"] = "bundle/host.exe"
    edge["target_path"] = "bundle/version.dll"
    edge["target_name"] = "version.dll"

    accepted = select_lineage_children([parent, source, target], [edge])
    assert accepted.status == "complete_selected"

    source_collision = _artifact(
        103,
        depth=1,
        path="bundle/HOST.exe",
        parent_sha256=container,
    )
    source_ambiguous = select_lineage_children([parent, source, source_collision, target], [edge])
    assert dict(source_ambiguous.omitted_reason_counts) == {"source_ambiguous": 1}

    target_collision = _artifact(
        104,
        depth=1,
        path="bundle/VERSION.dll",
        parent_sha256=container,
    )
    target_ambiguous = select_lineage_children([parent, source, target, target_collision], [edge])
    assert dict(target_ambiguous.omitted_reason_counts) == {"target_ambiguous": 1}


def test_source_identity_is_unique_before_target_resolution() -> None:
    """source_path省略時にtarget/containerを使った後付けsource解決を許さない。"""

    parent = _artifact(105, depth=0)
    shared_digest = _digest(106)
    first = _artifact(
        106,
        depth=1,
        path="bundle/first.exe",
        parent_sha256=parent["sha256"],
        sha256=shared_digest,
    )
    second = _artifact(
        107,
        depth=1,
        path="bundle/second.exe",
        parent_sha256=parent["sha256"],
        sha256=shared_digest,
    )
    target = _artifact(108, depth=1, parent_sha256=parent["sha256"])
    edge = _edge(first, target)
    edge["source_path"] = None

    result = select_lineage_children([parent, first, second, target], [edge])

    assert result.status == "partial"
    assert dict(result.omitted_reason_counts) == {"source_ambiguous": 1}


def test_duplicate_source_digest_across_parents_requires_source_parent_field() -> None:
    """同じpath/digestの別container sourceをparent省略でroot扱いしない。"""

    parents = [_artifact(109, depth=0), _artifact(110, depth=0)]
    shared_digest = _digest(111)
    sources = [
        _artifact(
            111 + index,
            depth=1,
            path="same/source.exe",
            parent_sha256=parents[index]["sha256"],
            sha256=shared_digest,
        )
        for index in range(2)
    ]
    target = _artifact(113, depth=1, parent_sha256=parents[0]["sha256"])
    edge = _edge(sources[0], target)
    edge["source_parent_sha256"] = None

    result = select_lineage_children([*parents, *sources, target], [edge])

    assert result.status == "partial"
    assert result.selected_artifacts == ()
    assert dict(result.omitted_reason_counts) == {"source_not_found": 1}

    missing_field = _edge(sources[0], target)
    del missing_field["source_parent_sha256"]
    missing_result = select_lineage_children([*parents, *sources, target], [missing_field])
    assert dict(missing_result.omitted_reason_counts) == {"invalid_edge_schema": 1}


def test_same_path_and_digest_in_distinct_containers_remain_distinct() -> None:
    """同一digest/pathのartifactもcontainment parentが異なれば別childとして保持する。"""

    first_parent = _digest(110)
    second_parent = _digest(111)
    parent_artifacts = [_artifact(110, depth=0), _artifact(111, depth=0)]
    first_source = _artifact(112, depth=1, path="one/source.exe", parent_sha256=first_parent)
    second_source = _artifact(113, depth=1, path="two/source.exe", parent_sha256=second_parent)
    shared_digest = _digest(114)
    first_target = _artifact(
        115,
        depth=1,
        path="payload.dll",
        parent_sha256=first_parent,
        sha256=shared_digest,
    )
    second_target = _artifact(
        116,
        depth=1,
        path="payload.dll",
        parent_sha256=second_parent,
        sha256=shared_digest,
    )

    result = select_lineage_children(
        [*parent_artifacts, first_source, second_source, first_target, second_target],
        [
            _edge(first_source, first_target),
            _edge(second_source, second_target),
        ],
    )

    assert result.status == "complete_selected"
    assert result.selected_sha256 == (shared_digest, shared_digest)
    assert len(result.selected_artifacts) == 2


def test_self_edge_and_cycle_are_rejected() -> None:
    """自己edgeと同階層cycleをpartialとしてlineageから除く。"""

    container = _digest(120)
    parent = _artifact(120, depth=0)
    first = _artifact(121, depth=1, parent_sha256=container)
    second = _artifact(122, depth=1, parent_sha256=container)
    starter = _artifact(123, depth=1, parent_sha256=container)

    self_result = select_lineage_children(
        [parent, first], [_edge(first, first, relation="pe_import")]
    )
    assert dict(self_result.omitted_reason_counts) == {"self_edge": 1}

    cycle_result = select_lineage_children(
        [parent, starter, first, second],
        [
            _edge(starter, first),
            _edge(first, second, relation="pe_import"),
            _edge(second, first, relation="pe_literal_load"),
        ],
    )
    assert cycle_result.status == "partial"
    assert cycle_result.selected_sha256 == (first["sha256"],)
    assert dict(cycle_result.omitted_reason_counts) == {"cycle": 2}


@pytest.mark.parametrize("mismatch", ["artifact_digest", "artifact_size", "edge_digest", "edge_size"])
def test_digest_and_size_mismatches_are_fail_closed(mismatch: str) -> None:
    """artifact再hash値またはedge宣言値の不一致を選択へ使わない。"""

    root = _artifact(30, depth=0)
    child = _artifact(31, depth=1, parent_sha256=root["sha256"])
    edge = _edge(root, child)
    if mismatch == "artifact_digest":
        child["observed_sha256"] = _digest(99)
    elif mismatch == "artifact_size":
        child["observed_size"] = 2
    elif mismatch == "edge_digest":
        edge["target_sha256"] = _digest(99)
    else:
        edge["target_size"] = 2

    result = select_lineage_children([root, child], [edge])

    assert result.status == "partial"
    assert result.selected_sha256 == ()


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ({"integrity": "truncated"}, "edge_truncated"),
        ({"integrity": "ambiguous"}, "edge_ambiguous"),
        ({"integrity": "unknown"}, "edge_unknown"),
        ({"relation": "heuristic_name_match"}, "unknown_relation"),
        ({"extra": True}, "invalid_edge_schema"),
    ],
)
def test_unknown_truncated_ambiguous_and_non_exact_edges_are_partial(
    change: dict[str, object], reason: str
) -> None:
    """closed enumとexact schemaを外れたedgeを拒否する。"""

    root = _artifact(40, depth=0)
    child = _artifact(41, depth=1, parent_sha256=root["sha256"])
    edge = _edge(root, child)
    edge.update(change)

    result = select_lineage_children([root, child], [edge])

    assert result.status == "partial"
    assert result.selected_sha256 == ()
    assert dict(result.omitted_reason_counts) == {reason: 1}


def test_input_count_limits_accept_n_and_reject_n_plus_one() -> None:
    """artifact/edge件数のN境界を受理し、N+1を空のpartialへ倒す。"""

    artifacts_n = [_artifact(index + 100, depth=0) for index in range(MAX_ARTIFACTS)]
    assert select_lineage_children(artifacts_n, []).status == "complete_no_executable_child"

    artifacts_n1 = [*artifacts_n, _artifact(10_000, depth=0)]
    too_many_artifacts = select_lineage_children(artifacts_n1, [])
    assert too_many_artifacts.status == "partial"
    assert too_many_artifacts.selected_sha256 == ()
    assert too_many_artifacts.omitted_commitment.record_count == MAX_ARTIFACTS + 1

    root = _artifact(20_000, depth=0)
    child = _artifact(20_001, depth=1, parent_sha256=root["sha256"])
    edge = _edge(root, child)
    edges_n = [dict(edge, source_address=f"site-{index}") for index in range(MAX_EDGES)]
    assert (
        select_lineage_children([root, child], edges_n).status
        == "complete_selected"
    )

    too_many_edges = select_lineage_children(
        [root, child], [*edges_n, dict(edge, source_address="site-overflow")]
    )
    assert too_many_edges.status == "partial"
    assert too_many_edges.selected_sha256 == ()
    assert too_many_edges.omitted_commitment.record_count == MAX_EDGES + 1


def test_per_parent_limit_accepts_n_and_omits_n_plus_one_deterministically() -> None:
    """1 parentあたり16 childだけを選択し、17件目をcommitする。"""

    root = _artifact(30_000, depth=0)
    children = [
        _artifact(30_001 + index, depth=1, parent_sha256=root["sha256"])
        for index in range(MAX_CHILDREN_PER_PARENT + 1)
    ]
    first = select_lineage_children(
        [root, *children], [_edge(root, child) for child in children]
    )
    second = select_lineage_children(
        list(reversed([root, *children])),
        list(reversed([_edge(root, child) for child in children])),
    )

    assert first == second
    assert first.status == "partial"
    assert len(first.selected_sha256) == MAX_CHILDREN_PER_PARENT
    assert dict(first.omitted_reason_counts) == {"per_parent_limit": 1}
    assert first.omitted_commitment.record_count == 1


def test_per_parent_limit_combines_multiple_semantic_sources() -> None:
    """異なるsemantic sourceも同じcontainment parentの上限へ合算する。"""

    container = _digest(35_000)
    parent = _artifact(35_000, depth=0)
    sources = [
        _artifact(35_001 + index, depth=1, parent_sha256=container)
        for index in range(2)
    ]
    targets = [
        _artifact(35_010 + index, depth=1, parent_sha256=container)
        for index in range(3)
    ]
    policy = SelectionPolicy(max_children_per_parent=2)

    result = select_lineage_children(
        [parent, *sources, *targets],
        [
            _edge(sources[0], targets[0]),
            _edge(sources[0], targets[1]),
            _edge(sources[1], targets[2]),
        ],
        policy=policy,
    )

    assert result.status == "partial"
    assert len(result.selected_artifacts) == 2
    assert dict(result.omitted_reason_counts) == {"per_parent_limit": 1}


def test_global_selected_child_cap_combines_containers() -> None:
    """containment parentが異なってもglobal child hard capを超えない。"""

    parents = [_artifact(36_100 + index, depth=0) for index in range(3)]
    sources = [
        _artifact(36_000 + index, depth=1, parent_sha256=parents[index]["sha256"])
        for index in range(3)
    ]
    targets = [
        _artifact(36_010 + index, depth=1, parent_sha256=parents[index]["sha256"])
        for index in range(3)
    ]
    policy = SelectionPolicy(max_selected_children=2)

    result = select_lineage_children(
        [*parents, *sources, *targets],
        [_edge(source, target) for source, target in zip(sources, targets, strict=True)],
        policy=policy,
    )

    assert result.status == "partial"
    assert len(result.selected_artifacts) == 2
    assert dict(result.omitted_reason_counts) == {"selected_child_limit": 1}


@pytest.mark.parametrize(
    ("field", "maximum"),
    [
        ("max_depth", MAX_DEPTH),
        ("max_artifacts", MAX_ARTIFACTS),
        ("max_edges", MAX_EDGES),
        ("max_children_per_parent", MAX_CHILDREN_PER_PARENT),
        ("max_selected_children", MAX_SELECTED_CHILDREN),
        ("max_total_bytes", MAX_TOTAL_BYTES),
        ("max_child_bytes", MAX_CHILD_BYTES),
    ],
)
def test_custom_policy_cannot_exceed_compile_time_maximum(field: str, maximum: int) -> None:
    """caller指定policyでcompile-time hard capを拡張できない。"""

    with pytest.raises(ValueError, match="compile-time"):
        SelectionPolicy(**{field: maximum + 1})


def test_byte_limits_accept_n_and_reject_n_plus_one() -> None:
    """単体128MiBと合計256MiBの境界を超えたchildを選択しない。"""

    root = _artifact(40_000, depth=0)
    child_at_limit = _artifact(
        40_001,
        depth=1,
        size=MAX_CHILD_BYTES,
        parent_sha256=root["sha256"],
    )
    accepted = select_lineage_children([root, child_at_limit], [_edge(root, child_at_limit)])
    assert accepted.status == "complete_selected"
    assert accepted.selected_total_size == MAX_CHILD_BYTES

    child_over_limit = _artifact(
        40_002,
        depth=1,
        size=MAX_CHILD_BYTES + 1,
        parent_sha256=root["sha256"],
    )
    rejected = select_lineage_children([root, child_over_limit], [_edge(root, child_over_limit)])
    assert rejected.status == "partial"
    assert rejected.selected_sha256 == ()
    assert dict(rejected.omitted_reason_counts) == {"child_size_limit": 1}

    second = _artifact(40_003, depth=1, size=MAX_CHILD_BYTES, parent_sha256=root["sha256"])
    extra = _artifact(40_004, depth=1, size=1, parent_sha256=root["sha256"])
    total = select_lineage_children(
        [root, child_at_limit, second, extra],
        [_edge(root, child_at_limit), _edge(root, second), _edge(root, extra)],
    )
    assert total.status == "partial"
    assert total.selected_total_size == MAX_TOTAL_BYTES
    assert dict(total.omitted_reason_counts) == {"total_size_limit": 1}


def test_depth_n_plus_one_is_partial() -> None:
    """depth 5 artifactは選択対象へ入れない。"""

    policy = SelectionPolicy(max_depth=4)
    ancestors = [_artifact(49_996, depth=0)]
    for depth in range(1, 5):
        ancestors.append(
            _artifact(
                49_996 + depth,
                depth=depth,
                parent_sha256=ancestors[-1]["sha256"],
            )
        )
    source = ancestors[-1]
    child = _artifact(50_001, depth=5, parent_sha256=source["sha256"])

    result = select_lineage_children([*ancestors, child], [_edge(source, child)], policy=policy)

    assert result.status == "partial"
    assert result.selected_sha256 == ()
    assert "depth_limit" in dict(result.omitted_reason_counts)


def test_order_is_invariant_and_omitted_commitment_is_stable() -> None:
    """入力順に依存せず、選択・検証edge・省略commitmentを固定する。"""

    root = _artifact(60_000, depth=0)
    first = _artifact(60_001, depth=1, parent_sha256=root["sha256"])
    second = _artifact(
        60_002,
        depth=1,
        size=MAX_CHILD_BYTES + 1,
        parent_sha256=root["sha256"],
    )
    artifacts = [root, first, second]
    edges = [_edge(root, first, relation="resource_decode"), _edge(root, second)]

    forward = select_lineage_children(artifacts, edges)
    reversed_result = select_lineage_children(list(reversed(artifacts)), list(reversed(edges)))

    assert forward == reversed_result
    assert forward.omitted_commitment.record_count == 1


def test_huge_and_deep_invalid_objects_use_bounded_commitment_projection() -> None:
    """巨大文字列や深いobjectを再帰的にserializeせずpartialへ倒す。"""

    deep: object = "leaf"
    for _ in range(10_000):
        deep = [deep]
    huge = {"unexpected": "A" * 2_000_000}

    result = select_lineage_children([huge, {"unexpected": deep}], [])

    assert result.status == "partial"
    assert result.omitted_commitment.record_count == 2
    assert len(result.omitted_commitment.value) == 64
    assert "value" not in result.public()["omitted_commitment"]


def test_canonicalizer_is_total_for_surrogate_huge_int_and_exploding_objects() -> None:
    """特殊文字・巨大整数・例外providerでも固定長tokenのpartialを返す。"""

    invalid_records: list[object] = [
        {"unexpected": "\ud800control\x00"},
        {"unexpected": 1 << 1_000_000},
        _ExplodingMapping(),
        _ExplodingSequence(),
    ]

    result = select_lineage_children(invalid_records, [])

    assert result.status == "partial"
    assert result.selected_artifacts == ()
    assert result.omitted_commitment.record_count == len(invalid_records)
    assert len(result.omitted_commitment.value) == 64


def test_top_level_len_failure_is_invalid_input_partial() -> None:
    """top-level Sequenceのlen例外をinvalid_input_schemaへ閉じる。"""

    result = select_lineage_children(_ExplodingSequence(), [])

    assert result.status == "partial"
    assert result.selected_artifacts == ()
    assert dict(result.omitted_reason_counts) == {"invalid_input_schema": 1}


def test_huge_observed_count_reads_only_compile_time_sample_cap() -> None:
    """巨大lenのoverflowでもsample capを超えてgetitemを呼ばない。"""

    huge = _HugeSequence(10**12)

    result = select_lineage_children(huge, [])

    assert result.status == "partial"
    assert result.selected_artifacts == ()
    assert result.observed_artifact_count == 10**12
    assert len(huge.read_indexes) <= MAX_OVERFLOW_COMMITMENT_SAMPLES
    public_commitment = result.public()["omitted_commitment"]
    assert public_commitment == {
        "complete": False,
        "canonicalization": "bounded_overflow_sample_v1",
        "sampled_record_count": len(huge.read_indexes),
        "observed_record_count": 10**12,
        "commitment_recorded": True,
        "value_disclosure": "internal_only",
    }


def test_overflow_commitment_distinguishes_bounded_content_without_public_value() -> None:
    """同件数overflowの内容差をinternal commitmentへ結合し、公開値は伏せる。"""

    first = [_artifact(80_000 + index, depth=0) for index in range(MAX_ARTIFACTS + 1)]
    second = [dict(item) for item in first]
    middle = len(second) // 2
    second[middle]["path"] = "changed/middle.bin"
    second[middle]["name"] = "middle.bin"

    first_result = select_lineage_children(first, [])
    second_result = select_lineage_children(second, [])

    assert first_result.omitted_commitment.value != second_result.omitted_commitment.value
    assert first_result.public() == second_result.public()
    public_commitment = first_result.public()["omitted_commitment"]
    assert public_commitment["complete"] is False
    assert public_commitment["canonicalization"] == "bounded_overflow_sample_v1"

    unsampled = [dict(item) for item in first]
    unsampled[1]["path"] = "changed/unsampled.bin"
    unsampled[1]["name"] = "unsampled.bin"
    unsampled_result = select_lineage_children(unsampled, [])
    assert unsampled_result.omitted_commitment.value == first_result.omitted_commitment.value
    assert unsampled_result.omitted_commitment.complete is False


def test_public_projection_contains_no_private_identifier() -> None:
    """公開summaryへ個別digest/path/name/addressを転記しない。"""

    root = _artifact(70_000, depth=0, path="private/root-loader.exe")
    child = _artifact(
        70_001,
        depth=1,
        path="private/secret-child.dll",
        parent_sha256=root["sha256"],
    )
    address = "0xDEADBEEF"
    result = select_lineage_children([root, child], [_edge(root, child, address=address)])

    public = result.public()
    rendered = json.dumps(public, sort_keys=True)
    for identifier in (
        root["sha256"],
        child["sha256"],
        root["path"],
        child["path"],
        root["name"],
        child["name"],
        address,
    ):
        assert identifier not in rendered
    assert public["family_attribution_allowed"] is False
    assert public["c2_attribution_allowed"] is False
    assert public["maliciousness"] == "not_determined_from_lineage"
    assert public["executed_sample"] is False
    assert public["network_contacted"] is False
