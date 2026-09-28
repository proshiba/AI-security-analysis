"""KBND footerをcapで候補signalに留め、確定へ昇格させない人工graph対照。"""

from __future__ import annotations

from collections import Counter

import pytest

from extractors.valleyrat import native_loader_lineage as lineage


def _run(monkeypatch, *, footer, no_context):
    root = b"MZ synthetic root"
    terminal = b"MZ synthetic strict terminal"
    capped = b"MZ synthetic capped loader" + (b"KBND" if footer else b"LEAF")
    one, two, three = (f"MZ synthetic shallow loader {index}".encode() for index in range(1, 4))
    edges = {root: (terminal, one), one: (two,), two: (three,), three: (capped,)}
    contexts = {value: object() for value in (root, terminal, one, two, three, capped)}
    reverse = {id(context): data for data, context in contexts.items()}
    parses = Counter()
    stages = Counter()

    def load(data):
        parses[data] += 1
        return None if no_context and data == capped else contexts[data]

    def stage(context):
        data = reverse[id(context)]
        stages[data] += 1
        children = edges.get(data)
        if children is None:
            return None
        return lineage._Stage(kind="synthetic_stage", executed_components=children,
                              recovered_component_count=len(children), observation={"synthetic": True})

    monkeypatch.setattr(lineage, "_load_context", load)
    # cap nodeにclusterは無い。対応KBNDのAPI群が旧clusterに包含されない境界。
    monkeypatch.setattr(lineage, "_structural_cluster", lambda context: None if reverse[id(context)] == capped else "synthetic_loader")
    monkeypatch.setattr(lineage, "_direct_resource_stage", stage)
    monkeypatch.setattr(lineage, "_kbnd_stage", lambda _context: None)
    proof = lineage.TerminalComponentProof(
        family="valleyrat", static_config_recovered=True, terminal_family_confirmed=True,
        supports_family_attribution=True, terminal_network_lineage_proven=True,
        terminal_protocol_lineage_proven=True, endpoint_count=1,
    )
    result = lineage.analyze_native_loader_lineage(root, terminal_proofs={terminal: proof})
    assert parses[capped] == 1
    assert stages[capped] == 0
    return result


@pytest.mark.parametrize("no_context", [False, True])
def test_footer_only_is_conservative_incomplete_signal_not_family_proof(no_context, monkeypatch):
    """footer無しunknown leafは維持し、footer候補はcontext無しでもcompleteへ戻さない。"""
    ordinary_leaf = _run(monkeypatch, footer=False, no_context=no_context)
    assert ordinary_leaf.observation["terminal_family_confirmed"] is True
    assert ordinary_leaf.observation["follow_on_candidate_set_complete"] is True
    footer = _run(monkeypatch, footer=True, no_context=no_context)
    assert footer.terminal_component is None
    assert footer.recovered_components == ()
    for flag in ("terminal_family_confirmed", "supports_family_attribution", "terminal_network_lineage_proven", "terminal_protocol_lineage_proven", "follow_on_candidate_set_complete"):
        assert footer.observation[flag] is False
    assert footer.observation["follow_on_components_truncated"] is True
    assert "native_loader_lineage_depth_limit_exhausted" in footer.observation["missing_proof_codes"]
    assert footer.observation["terminal"]["endpoint_count"] == 0
