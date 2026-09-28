"""認識済みloaderの深さ打切りとstrict child選択を人工stage graphで検証する。"""

from __future__ import annotations

from collections import Counter

import pytest

from extractors.valleyrat import extractor
from extractors.valleyrat import native_loader_lineage as lineage


ROOT = b"MZ synthetic root"
FIRST = b"MZ synthetic terminal one"
SECOND = b"MZ synthetic terminal two"


def _proof():
    return lineage.TerminalComponentProof(
        family="valleyrat", static_config_recovered=True, terminal_family_confirmed=True,
        supports_family_attribution=True, terminal_network_lineage_proven=True,
        terminal_protocol_lineage_proven=True, endpoint_count=1,
    )


def _graph(depth=5, *, first=True, first_order=True):
    nodes = [f"MZ synthetic loader {index}".encode() for index in range(1, depth)]
    children = (FIRST, nodes[0]) if first else (nodes[0],)
    if not first_order:
        children = tuple(reversed(children))
    edges = {ROOT: children}
    edges.update({left: (right,) for left, right in zip(nodes, nodes[1:])})
    edges[nodes[-1]] = (SECOND,)
    return edges, nodes


def _install(monkeypatch, edges, *, recognized=None, absent_context=(), probe_error=None):
    contexts = {data: object() for data in {ROOT, FIRST, SECOND, *edges, *(item for values in edges.values() for item in values)}}
    reverse = {id(context): data for data, context in contexts.items()}
    recognized = set(edges) if recognized is None else set(recognized)
    parses = Counter()
    stages = Counter()

    def load(data):
        parses[data] += 1
        if probe_error is not None and probe_error[0] == "context" and data == probe_error[1]:
            raise RuntimeError("synthetic context parse failure")
        return None if data in absent_context else contexts[data]

    def cluster(context):
        data = reverse[id(context)]
        if probe_error is not None and probe_error[0] == "predicate" and data == probe_error[1]:
            raise AssertionError("synthetic structural predicate failure")
        return "synthetic_loader_grammar" if data in recognized else None

    def stage(context):
        data = reverse[id(context)]
        stages[data] += 1
        children = edges.get(data)
        if children is None:
            return None
        return lineage._Stage(
            kind="synthetic_stage", executed_components=children,
            recovered_component_count=len(children), observation={"synthetic": True},
        )

    monkeypatch.setattr(lineage, "_load_context", load)
    monkeypatch.setattr(lineage, "_structural_cluster", cluster)
    monkeypatch.setattr(lineage, "_direct_resource_stage", stage)
    monkeypatch.setattr(lineage, "_kbnd_stage", lambda _context: None)
    return parses, stages


@pytest.mark.parametrize("first_order", [True, False])
def test_depth_four_recognized_loader_cannot_hide_other_terminal_branch(monkeypatch, first_order):
    """別branchにstrict終端があっても、capで止まったloader候補をcomplete扱いしない。"""
    edges, nodes = _graph(first_order=first_order)
    parses, stages = _install(monkeypatch, edges)
    result = lineage.analyze_native_loader_lineage(ROOT, terminal_proofs={FIRST: _proof(), SECOND: _proof()})
    assert result.terminal_component is None
    assert result.recovered_components == ()
    for flag in ("supports_family_attribution", "terminal_family_confirmed", "terminal_network_lineage_proven", "terminal_protocol_lineage_proven", "follow_on_candidate_set_complete"):
        assert result.observation[flag] is False
    assert result.observation["follow_on_components_truncated"] is True
    assert "native_loader_lineage_depth_limit_exhausted" in result.observation["missing_proof_codes"]
    assert "follow_on_candidate_set_incomplete" in result.observation["missing_proof_codes"]
    assert parses[nodes[-1]] == 1
    assert stages[nodes[-1]] == 0
    assert max(parses.values()) == 1


def test_recognized_loader_depth_exhaustion_is_incomplete_without_any_terminal(monkeypatch):
    edges, nodes = _graph(first=False)
    _install(monkeypatch, edges)
    result = lineage.analyze_native_loader_lineage(ROOT, terminal_proofs={})
    assert result.terminal_component is None
    assert result.observation["follow_on_candidate_set_complete"] is False
    assert "native_loader_lineage_depth_limit_exhausted" in result.observation["missing_proof_codes"]
    assert "valleyrat_terminal_component_unproven" in result.observation["missing_proof_codes"]


@pytest.mark.parametrize("no_context", [True, False])
def test_unknown_non_loader_leaf_is_still_natural_end_not_new_global_completeness(no_context, monkeypatch):
    """認識済みgrammarだけの保証で、未知leafの全branch完全性は主張しない。"""
    edges, nodes = _graph()
    parses, stages = _install(monkeypatch, edges, recognized=set(edges) - {nodes[-1]}, absent_context=(nodes[-1],) if no_context else ())
    result = lineage.analyze_native_loader_lineage(ROOT, terminal_proofs={FIRST: _proof()})
    assert result.terminal_component == FIRST
    assert result.observation["terminal_family_confirmed"] is True
    assert result.observation["follow_on_candidate_set_complete"] is True
    assert "native_loader_lineage_depth_limit_exhausted" not in result.observation["missing_proof_codes"]
    assert parses[nodes[-1]] == 1
    assert stages[nodes[-1]] == 0


def test_strict_terminal_at_exact_depth_four_remains_supported_before_cap(monkeypatch):
    edges, nodes = _graph(depth=4, first=False)
    parses, stages = _install(monkeypatch, edges)
    result = lineage.analyze_native_loader_lineage(ROOT, terminal_proofs={SECOND: _proof()})
    assert result.terminal_component == SECOND
    assert result.observation["terminal_family_confirmed"] is True
    assert result.observation["follow_on_candidate_set_complete"] is True
    assert parses[SECOND] == stages[SECOND] == 0


def test_two_strict_terminals_at_depth_one_and_four_remain_ambiguous(monkeypatch):
    edges, _nodes = _graph(depth=4)
    _install(monkeypatch, edges)
    result = lineage.analyze_native_loader_lineage(ROOT, terminal_proofs={FIRST: _proof(), SECOND: _proof()})
    assert result.terminal_component is None
    assert result.observation["terminal_family_confirmed"] is False
    assert result.observation["follow_on_candidate_set_complete"] is True
    assert "multiple_terminal_component_paths_ambiguous" in result.observation["missing_proof_codes"]


def test_duplicate_cycle_does_not_charge_or_parse_same_component_twice(monkeypatch):
    node = b"MZ synthetic cycle"
    edges = {ROOT: (FIRST, node, node), node: (node, FIRST)}
    parses, stages = _install(monkeypatch, edges)
    result = lineage.analyze_native_loader_lineage(ROOT, terminal_proofs={FIRST: _proof()})
    assert result.terminal_component == FIRST
    assert result.observation["follow_on_candidate_set_complete"] is True
    assert parses[node] == stages[node] == 1
    assert max(parses.values()) == 1


def test_deep_duplicate_already_scanned_at_shallow_depth_remains_complete(monkeypatch):
    one, two, three, shallow = [f"MZ synthetic alias {index}".encode() for index in range(4)]
    edges = {ROOT: (FIRST, shallow, one), shallow: (FIRST,), one: (two,), two: (three,), three: (shallow,)}
    parses, stages = _install(monkeypatch, edges)
    result = lineage.analyze_native_loader_lineage(ROOT, terminal_proofs={FIRST: _proof()})
    assert result.terminal_component == FIRST
    assert result.observation["follow_on_candidate_set_complete"] is True
    assert parses[shallow] == stages[shallow] == 1
    assert "native_loader_lineage_depth_limit_exhausted" not in result.observation["missing_proof_codes"]


@pytest.mark.parametrize("kind", ["context", "predicate"])
def test_additional_cap_parser_exception_is_fixed_incomplete_not_success(kind, monkeypatch):
    edges, nodes = _graph()
    _install(monkeypatch, edges, probe_error=(kind, nodes[-1]))
    result = lineage.analyze_native_loader_lineage(ROOT, terminal_proofs={FIRST: _proof()})
    assert result.terminal_component is None
    assert result.observation["terminal_family_confirmed"] is False
    assert result.observation["follow_on_candidate_set_complete"] is False
    assert "native_loader_lineage_depth_context_probe_failed" in result.observation["missing_proof_codes"]
    assert "synthetic context parse failure" not in str(result.observation)
    assert "synthetic structural predicate failure" not in str(result.observation)


def test_depth_incomplete_producer_is_rejected_by_strict_child_consumer(monkeypatch):
    """入力/子config helperをstub化し、不完全producerの後段選択だけを検証する。"""
    edges, _nodes = _graph()
    _install(monkeypatch, edges)
    incomplete = lineage.analyze_native_loader_lineage(ROOT, terminal_proofs={FIRST: _proof()})
    monkeypatch.setattr(extractor, "analyze_native_loader_lineage", lambda _data: incomplete)
    monkeypatch.setattr(extractor, "analyze_silverfox_loader_lineage", lambda _data: None)
    monkeypatch.setattr(extractor, "extract", lambda *_args: pytest.fail("未完了producerの子configを再確定しない"))
    selected, observations, follow_ons = extractor._extract_native_loader_lineage(ROOT, "synthetic.exe")
    assert selected is None
    assert follow_ons == ()
    assert observations["native_loader_lineage"]["terminal_family_confirmed"] is False
    assert observations["native_loader_lineage"]["follow_on_candidate_set_complete"] is False
    assert "native_loader_lineage_depth_limit_exhausted" in observations["native_loader_lineage"]["missing_proof_codes"]


def test_existing_fixed_caps_are_not_enlarged():
    assert lineage.MAXIMUM_LINEAGE_DEPTH == 4
    assert lineage.MAXIMUM_RECOVERED_COMPONENTS == 32
    assert lineage.MAXIMUM_INPUT_SIZE == 32 * 1024 * 1024
    assert lineage.MAXIMUM_COMPONENT_SIZE == 16 * 1024 * 1024
    assert lineage.MAXIMUM_FUNCTIONS == 8192
    assert lineage.MAXIMUM_INSTRUCTIONS == 250_000
    assert lineage.MAXIMUM_FOLLOW_ON_COMPONENTS == 8
    assert lineage.MAXIMUM_FOLLOW_ON_TOTAL_SIZE == 64 * 1024 * 1024


@pytest.mark.parametrize("children", [2, 3])
def test_existing_visited_component_cap_still_discards_partial_queue(children, monkeypatch):
    """元32visited条件を小さい3件枠で確認し、新cap分類で増量しない。"""
    leaves = tuple(f"MZ synthetic leaf {index}".encode() for index in range(children))
    parses, stages = _install(monkeypatch, {ROOT: leaves}, recognized={ROOT})
    monkeypatch.setattr(lineage, "MAXIMUM_RECOVERED_COMPONENTS", 3)
    result = lineage.analyze_native_loader_lineage(ROOT, terminal_proofs={})
    assert sum(parses.values()) == 3
    assert max(parses.values()) == 1
    if children == 2:
        assert result.observation["follow_on_candidate_set_complete"] is True
    else:
        assert result.observation["follow_on_candidate_set_complete"] is False
        assert result.recovered_components == ()
        assert "native_loader_lineage_component_limit_exhausted" in result.observation["missing_proof_codes"]
