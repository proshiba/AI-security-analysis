"""既知family候補の安全なhandler試行と誤昇格防止を検証する。"""

from __future__ import annotations

import ast
import base64
import hashlib
import json
import os
import sys
import types
from dataclasses import replace
from pathlib import Path

import pytest

COMMON_ROOT = Path(__file__).resolve().parents[1] / "common"
if str(COMMON_ROOT) not in sys.path:
    sys.path.insert(0, str(COMMON_ROOT))

import bounded_process  # noqa: E402
import handler_catalog as catalog  # noqa: E402
from analysis_contract import handler_result_quality  # noqa: E402


@pytest.fixture
def isolated_catalog(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """一時allowlist内だけをhandler catalogとして使用する。"""

    repository = tmp_path / "repository"
    malware_root = repository / "analysis-framework" / "malware"
    extractors_root = repository / "extractors"
    malware_root.mkdir(parents=True)
    extractors_root.mkdir(parents=True)
    monkeypatch.setattr(catalog, "REPOSITORY_ROOT", repository)
    monkeypatch.setattr(catalog, "MALWARE_ROOT", malware_root)
    monkeypatch.setattr(catalog, "EXTRACTORS_ROOT", extractors_root)
    catalog.clear_handler_caches()
    yield repository, malware_root
    catalog.clear_handler_caches()


def _handler_spec(
    repository: Path,
    malware_root: Path,
    family: str,
    source: str,
    *,
    input_formats: tuple[str, ...] = ("data",),
) -> catalog.HandlerSpec:
    family_root = malware_root / family
    family_root.mkdir(parents=True, exist_ok=True)
    path = family_root / "extract_config.py"
    path.write_text(source, encoding="utf-8")
    return catalog.HandlerSpec(
        id=f"{family}:fixture:extract_config",
        family=family,
        relative_path=path.relative_to(repository).as_posix(),
        callable_name="extract_config",
        invocation="bytes",
        source="malware_family_script",
        automatic=True,
        campaign=None,
        supported_interface=True,
        reason="bounded_static_callable",
        input_formats=input_formats,
        input_contract_source="module_declaration",
        minimum_evidence_score=1,
    )


def _source(result_expression: str, formats: tuple[str, ...] = ("data",)) -> str:
    return (
        f'HANDLER_CONTRACT = {{"input_formats": {list(formats)!r}, '
        '"minimum_evidence_score": 1}\n'
        "def extract_config(data):\n"
        f"    return {result_expression}\n"
    )


def test_handler_discovery_streams_one_source_tree_and_clears_ast_cache(
    isolated_catalog,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """catalog発見は同一snapshotを共有し、全source ASTをprocessへ保持しない。"""

    repository, malware_root = isolated_catalog
    expected = _handler_spec(
        repository,
        malware_root,
        "candidate_family",
        _source("{'status': 'not_applicable'}"),
    )
    source_path = repository / expected.relative_path
    extractor_path = catalog.EXTRACTORS_ROOT / "sharedfixture.py"
    extractor_path.write_text(
        'HANDLER_CONTRACT = {"input_formats": ["data"], '
        '"minimum_evidence_score": 1}\n'
        "def extract(data):\n"
        "    return {'status': 'not_applicable'}\n",
        encoding="utf-8",
    )
    tracked_paths = {source_path, extractor_path}
    monkeypatch.setattr(
        catalog,
        "PROFILE_PATH",
        repository / "missing-profiles.json",
    )

    cached_path = repository / "legacy-cache-fixture.py"
    cached_path.write_text("value = 1\n", encoding="utf-8")
    catalog._module_tree(cached_path)
    assert catalog._module_tree.cache_info().currsize == 1

    original_parse = catalog._parse_module_tree
    original_shape = catalog._function_shape
    original_contract = catalog._handler_contract
    parsed_trees: dict[Path, list[ast.Module]] = {
        path: [] for path in tracked_paths
    }
    shape_trees: dict[Path, list[ast.Module | None]] = {
        path: [] for path in tracked_paths
    }
    contract_trees: dict[Path, list[ast.Module | None]] = {
        path: [] for path in tracked_paths
    }

    def parse(path: Path) -> ast.Module:
        tree = original_parse(path)
        if path in tracked_paths:
            parsed_trees[path].append(tree)
        return tree

    def shape(
        path: Path,
        callable_name: str,
        *,
        tree: ast.Module | None = None,
    ) -> tuple[str, bool, str]:
        if path in tracked_paths:
            shape_trees[path].append(tree)
        return original_shape(path, callable_name, tree=tree)

    def contract(
        path: Path,
        callable_name: str,
        invocation: str,
        source: str,
        *,
        tree: ast.Module | None = None,
    ) -> tuple[tuple[str, ...], str, int]:
        if path in tracked_paths:
            contract_trees[path].append(tree)
        return original_contract(
            path,
            callable_name,
            invocation,
            source,
            tree=tree,
        )

    monkeypatch.setattr(catalog, "_parse_module_tree", parse)
    monkeypatch.setattr(catalog, "_function_shape", shape)
    monkeypatch.setattr(catalog, "_handler_contract", contract)

    discovered = catalog.discover_handlers()

    assert [item.id for item in discovered] == [
        "candidate_family:analysis.framework.malware.candidate.family.extract.config.py:extract_config",
        "sharedfixture:extractors.sharedfixture.py:extract",
    ]
    assert all(len(parsed_trees[path]) == 1 for path in tracked_paths)
    assert shape_trees == parsed_trees
    assert contract_trees == parsed_trees
    assert catalog._module_tree.cache_info().currsize == 0


def _layer(data: bytes, name: str, parent: str | None = None) -> dict:
    return {
        "name": name,
        "data": data,
        "sha256": hashlib.sha256(data).hexdigest(),
        "parent_sha256": parent,
        "depth": 0 if parent is None else 1,
        "transform": "root" if parent is None else "fixture_extract",
    }


def _structural_detector() -> dict:
    return {
        "detector_matched": True,
        "detection": {
            "matched": True,
            "confidence": "high",
            "observations": {"marker_hits": ["independent-family-marker"]},
        },
    }


def _routing_detector(
    supports_attribution: bool | None,
    campaign_types: list[object],
) -> dict:
    """handler選択用のmatched detector評価を作る。"""

    result = {
        "known_outer_sha256": False,
        "known_inner_sha256": False,
        "known_routing_sha256": False,
        "detector_matched": True,
        "applicable": True,
        "automatic_route_eligible": True,
        "error": None,
        "detection": {
            "matched": True,
            "observations": {"marker_hits": ["independent-family-marker"]},
            "campaigns": [
                ({"campaign_type": campaign_type} if isinstance(campaign_type, str) else campaign_type)
                for campaign_type in campaign_types
            ],
        },
    }
    if supports_attribution is not None:
        result["supports_family_attribution"] = supports_attribution
    return result


def _candidate(family: str, source: str = "metadata_hint") -> dict:
    return {
        "family": family,
        "source": source,
        "routing_eligible": True,
        "routing_mode": "candidate_verification",
        "routing_eligibility": {"candidate_verification": True},
    }


def test_multiple_candidates_try_every_layer_and_confirm_only_correlated_family(
    isolated_catalog,
) -> None:
    repository, malware_root = isolated_catalog
    family_a = _handler_spec(
        repository,
        malware_root,
        "family_a",
        _source("{'marker_hits': ['family-a-config-marker']}"),
    )
    family_b = _handler_spec(
        repository,
        malware_root,
        "family_b",
        _source("{'confidence': 'high', 'family': 'family_b'}"),
    )
    root = _layer(b"MZ-root-container", "root.exe")
    child = _layer(b"family-a-inner-data", "inner.bin", root["sha256"])

    result = catalog.assess_candidate_handlers(
        [
            _candidate("family_a"),
            _candidate("family_b"),
        ],
        [root, child],
        specs=[family_a, family_b],
        detector_evaluations={
            "family_a": {root["sha256"]: _structural_detector()},
            "family_b": {root["sha256"]: {"matched": True, "confidence": "high"}},
        },
    )

    assert result["confirmed_families"] == ["family_a"]
    assert result["considered_pair_count"] == 4
    assert result["planned_attempt_count"] == 2
    assert result["skipped_pair_count"] == 2
    by_family = {item["family"]: item for item in result["families"]}
    assert by_family["family_a"]["status"] == "confirmed"
    assert [item["status"] for item in by_family["family_a"]["attempts"]] == ["corroborated"]
    assert by_family["family_a"]["attempts"][0]["detector_corroboration"]["lineage_distance"] == 1
    assert by_family["family_a"]["skipped_pairs"][0]["layer_sha256"] == [root["sha256"]]
    assert by_family["family_a"]["skipped_pairs"][0]["execution_quota_consumed"] is False
    assert by_family["family_b"]["status"] == "no_evidence"
    assert by_family["family_b"]["attempts"][0]["status"] == "no_evidence"
    assert result["metadata_hint_can_confirm"] is False


def test_handler_evidence_without_detector_is_not_confirmed(isolated_catalog) -> None:
    repository, malware_root = isolated_catalog
    spec = _handler_spec(
        repository,
        malware_root,
        "candidate_family",
        _source("{'marker_hits': ['strong-handler-marker']}"),
    )
    layer = _layer(b"candidate payload", "payload.bin")

    result = catalog.assess_candidate_handlers(
        [_candidate("candidate_family")],
        [layer],
        specs=[spec],
        detector_evaluations={"candidate_family": {layer["sha256"]: {"matched": True, "confidence": "high"}}},
    )

    family = result["families"][0]
    assert result["confirmed_families"] == []
    assert family["status"] == "handler_evidence_without_detector"
    assert family["attempts"][0]["detector_corroboration"]["basis"] == ("no_corroborated_detector_in_lineage")


def test_route_only_detector_evidence_never_corroborates_family() -> None:
    """既知hashでもcomponent route専用ならfamily確認根拠として受理しない。"""

    result = catalog.detector_corroboration(
        {
            "known_inner_sha256": True,
            "detector_matched": True,
            "supports_family_attribution": False,
            "detection": {
                "matched": True,
                "observations": {"reviewed_component": "loader"},
            },
        }
    )

    assert result == {
        "corroborated": False,
        "score": 0,
        "basis": "detector_route_does_not_support_family_attribution",
    }


def test_family_wide_handler_runs_before_campaign_handlers(
    isolated_catalog,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """global quota内では共通config extractorをcampaign詳細解析より先に試す。"""

    repository, malware_root = isolated_catalog
    base = _handler_spec(
        repository,
        malware_root,
        "candidate_family",
        _source("{}"),
    )
    shared = replace(base, id="candidate_family:z_shared", campaign=None)
    campaign = replace(base, id="candidate_family:a_campaign", campaign="fixture")
    layer = _layer(b"candidate payload", "payload.bin")
    calls: list[str] = []

    def bounded(spec, *_args, **_kwargs):
        calls.append(spec.id)
        return {
            "status": "completed",
            "preflight": {"eligible": True, "blockers": []},
            "execution": {
                "result": {},
                "executed_sample": False,
                "network_contacted": False,
            },
        }

    monkeypatch.setattr(catalog, "execute_handler_bounded_for_assessment", bounded)
    catalog.assess_candidate_handlers(
        [_candidate("candidate_family")],
        [layer],
        specs=[campaign, shared],
        maximum_attempts=2,
    )

    assert calls == [shared.id, campaign.id]


def test_external_metadata_uses_family_wide_then_bounded_campaign_fallback(
    isolated_catalog,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """未検証provider hintでもcampaignを代表層へ限定してcoverageを保つ。"""

    repository, malware_root = isolated_catalog
    base = _handler_spec(
        repository,
        malware_root,
        "valleyrat",
        _source("{}"),
    )
    shared = replace(
        base,
        id="valleyrat:shared",
        source="shared_extractor",
        campaign=None,
    )
    campaign = replace(
        base,
        id="valleyrat:campaign",
        campaign="fixture",
    )
    calls: list[str] = []

    def execute(handler, *_args, **_kwargs):
        calls.append(handler.id)
        return _mock_completed_handler_result()

    monkeypatch.setattr(catalog, "execute_handler_bounded_for_assessment", execute)
    result = catalog.assess_candidate_handlers(
        [_candidate("valleyrat", source="external_metadata")],
        [_layer(b"candidate payload", "payload.bin")],
        specs=[campaign, shared],
    )

    assert calls == [shared.id, campaign.id]
    assert result["planned_attempt_count"] == result["actual_attempt_count"] == 2
    assert result["pair_planning"]["deferred_campaign_handler_count"] == 0
    assert result["pair_planning"]["bounded_campaign_fallback_handler_count"] == 1
    selection = result["families"][0]["handler_selection"]
    assert selection == {
        "mode": "family_wide_then_bounded_campaign_fallback_external_metadata",
        "external_metadata_only": True,
        "automatic_handler_count": 2,
        "selected_handler_count": 2,
        "primary_handler_count": 1,
        "bounded_campaign_fallback_handler_count": 1,
        "deferred_campaign_handler_count": 0,
        "campaign_fallback_used": True,
        "bounded_campaign_fallback_enabled": True,
        "bounded_campaign_fallback_maximum_layers_per_handler": 2,
        "bounded_campaign_fallback_selection_basis": ("root_then_format_transform_depth_diversity"),
        "family_confirmation_affected": False,
        "deferred_handlers_require_changed_evidence": False,
        "detector_scope_status": "unknown",
        "detector_scope_basis": "detector_evaluations_not_supplied",
        "matched_detector_count": 0,
        "attribution_supporting_detector_count": 0,
        "route_only_detector_count": 0,
        "route_only_campaign_types": [],
        "matched_campaign_types": [],
        "matched_campaign_handler_count": 0,
        "campaign_selection_basis": ("external_metadata_family_wide_with_bounded_campaign_fallback"),
        "detector_scope_used_for_handler_selection": False,
        "detector_scope_used_for_family_confirmation": False,
    }


def test_external_metadata_without_family_wide_handler_keeps_campaign_fallback(
    isolated_catalog,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """共通extractorがないfamilyではmetadata候補でも既存coverageを維持する。"""

    repository, malware_root = isolated_catalog
    base = _handler_spec(
        repository,
        malware_root,
        "candidate_family",
        _source("{}"),
    )
    campaign = replace(base, id="candidate_family:campaign", campaign="fixture")
    calls: list[str] = []

    def execute(handler, *_args, **_kwargs):
        calls.append(handler.id)
        return _mock_completed_handler_result()

    monkeypatch.setattr(catalog, "execute_handler_bounded_for_assessment", execute)
    result = catalog.assess_candidate_handlers(
        [_candidate("candidate_family", source="external_metadata")],
        [_layer(b"candidate payload", "payload.bin")],
        specs=[campaign],
    )

    assert calls == [campaign.id]
    selection = result["families"][0]["handler_selection"]
    assert selection["mode"] == "bounded_campaign_fallback_external_metadata"
    assert selection["campaign_fallback_used"] is True
    assert selection["primary_handler_count"] == 0
    assert selection["bounded_campaign_fallback_handler_count"] == 1
    assert selection["deferred_campaign_handler_count"] == 0


def test_detector_and_external_metadata_keeps_campaign_handlers(
    isolated_catalog,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """独立detectorを伴う候補はcampaign固有解析も従来どおり実行する。"""

    repository, malware_root = isolated_catalog
    base = _handler_spec(
        repository,
        malware_root,
        "valleyrat",
        _source("{}"),
    )
    shared = replace(
        base,
        id="valleyrat:shared",
        source="shared_extractor",
        campaign=None,
    )
    campaign = replace(base, id="valleyrat:campaign", campaign="fixture")
    calls: list[str] = []

    def execute(handler, *_args, **_kwargs):
        calls.append(handler.id)
        return _mock_completed_handler_result()

    monkeypatch.setattr(catalog, "execute_handler_bounded_for_assessment", execute)
    result = catalog.assess_candidate_handlers(
        [_candidate("valleyrat", source="detector_and_external_metadata")],
        [_layer(b"candidate payload", "payload.bin")],
        specs=[campaign, shared],
    )

    assert calls == [shared.id, campaign.id]
    selection = result["families"][0]["handler_selection"]
    assert selection["mode"] == "all_automatic_handlers"
    assert selection["external_metadata_only"] is False
    assert selection["deferred_campaign_handler_count"] == 0


def test_attribution_supporting_detector_keeps_all_automatic_handlers(
    isolated_catalog,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """帰属を支持するmatched detectorがあれば従来の全handler coverageを維持する。"""

    repository, malware_root = isolated_catalog
    base = _handler_spec(
        repository,
        malware_root,
        "valleyrat",
        _source("{}"),
    )
    shared = replace(base, id="valleyrat:shared", campaign=None)
    matched = replace(
        base,
        id="valleyrat:matched",
        campaign="matched_campaign",
    )
    other = replace(base, id="valleyrat:other", campaign="other_campaign")
    calls: list[str] = []

    def execute(handler, *_args, **_kwargs):
        calls.append(handler.id)
        return _mock_completed_handler_result()

    monkeypatch.setattr(catalog, "execute_handler_bounded_for_assessment", execute)
    route_only_layer = _layer(b"route-only payload", "route-only.bin")
    attribution_layer = _layer(
        b"attribution payload",
        "attribution.bin",
        route_only_layer["sha256"],
    )
    result = catalog.assess_candidate_handlers(
        [_candidate("valleyrat", source="detector_and_external_metadata")],
        [route_only_layer, attribution_layer],
        specs=[other, matched, shared],
        detector_evaluations={
            "valleyrat": {
                route_only_layer["sha256"]: _routing_detector(
                    False,
                    ["other_campaign"],
                ),
                attribution_layer["sha256"]: _routing_detector(
                    True,
                    ["matched_campaign"],
                ),
            }
        },
    )

    assert calls == [
        shared.id,
        matched.id,
        other.id,
        shared.id,
        matched.id,
        other.id,
    ]
    selection = result["families"][0]["handler_selection"]
    assert selection["mode"] == "all_automatic_handlers"
    assert selection["detector_scope_status"] == "attribution_supporting"
    assert selection["attribution_supporting_detector_count"] == 1
    assert selection["route_only_detector_count"] == 1
    assert selection["selected_handler_count"] == 3
    assert selection["campaign_selection_basis"] == "not_applicable"
    assert selection["detector_scope_used_for_handler_selection"] is False
    assert selection["detector_scope_used_for_family_confirmation"] is False


def test_route_only_detector_selects_family_wide_and_exact_campaign(
    isolated_catalog,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """route-only detectorでは共通handlerと完全一致campaignだけを実行する。"""

    repository, malware_root = isolated_catalog
    base = _handler_spec(
        repository,
        malware_root,
        "valleyrat",
        _source("{}"),
    )
    shared = replace(base, id="valleyrat:shared", campaign=None)
    matched = replace(
        base,
        id="valleyrat:matched",
        campaign="matched_campaign",
    )
    other = replace(base, id="valleyrat:other", campaign="other_campaign")
    calls: list[str] = []

    def execute(handler, *_args, **_kwargs):
        calls.append(handler.id)
        completed = _mock_completed_handler_result()
        completed["execution"]["result"] = {"marker_hits": ["strong-route-handler-evidence"]}
        return completed

    monkeypatch.setattr(catalog, "execute_handler_bounded_for_assessment", execute)
    layer = _layer(b"candidate payload", "payload.bin")
    result = catalog.assess_candidate_handlers(
        [_candidate("valleyrat", source="detector_and_external_metadata")],
        [layer],
        specs=[other, matched, shared],
        detector_evaluations={
            "valleyrat": {
                layer["sha256"]: _routing_detector(
                    False,
                    ["matched_campaign"],
                )
            }
        },
    )

    assert calls == [shared.id, matched.id, other.id]
    selection = result["families"][0]["handler_selection"]
    assert selection["mode"] == ("family_wide_and_exact_campaign_then_bounded_fallback_route_only_detector")
    assert selection["detector_scope_status"] == "route_only"
    assert selection["detector_scope_basis"] == ("all_matched_detectors_are_route_only")
    assert selection["route_only_campaign_types"] == ["matched_campaign"]
    assert selection["matched_campaign_types"] == ["matched_campaign"]
    assert selection["matched_campaign_handler_count"] == 1
    assert selection["campaign_selection_basis"] == ("exact_campaign_type_match_with_bounded_remaining_campaigns")
    assert selection["selected_handler_count"] == 3
    assert selection["primary_handler_count"] == 2
    assert selection["bounded_campaign_fallback_handler_count"] == 1
    assert selection["deferred_campaign_handler_count"] == 0
    assert selection["detector_scope_used_for_handler_selection"] is True
    assert selection["family_confirmation_affected"] is False
    assert selection["detector_scope_used_for_family_confirmation"] is False
    assert result["confirmed_families"] == []
    assert result["families"][0]["status"] == ("handler_evidence_without_detector")


def test_generic_route_only_profile_uses_bounded_campaign_fallback(
    isolated_catalog,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """一致campaignがなくてもcampaign固有wrapperを代表層で試す。"""

    repository, malware_root = isolated_catalog
    base = _handler_spec(
        repository,
        malware_root,
        "valleyrat",
        _source("{}"),
    )
    shared = replace(base, id="valleyrat:shared", campaign=None)
    campaign = replace(
        base,
        id="valleyrat:campaign",
        campaign="signed_proxy_sideload",
    )
    calls: list[str] = []

    def execute(handler, *_args, **_kwargs):
        calls.append(handler.id)
        return _mock_completed_handler_result()

    monkeypatch.setattr(catalog, "execute_handler_bounded_for_assessment", execute)
    layer = _layer(b"candidate payload", "payload.bin")
    result = catalog.assess_candidate_handlers(
        [_candidate("valleyrat", source="detector_and_external_metadata")],
        [layer],
        specs=[campaign, shared],
        detector_evaluations={
            "valleyrat": {
                layer["sha256"]: _routing_detector(
                    False,
                    ["bin_hell_resource_dropper"],
                )
            }
        },
    )

    assert calls == [shared.id, campaign.id]
    selection = result["families"][0]["handler_selection"]
    assert selection["mode"] == ("family_wide_then_bounded_campaign_fallback_route_only_detector")
    assert selection["route_only_campaign_types"] == ["bin_hell_resource_dropper"]
    assert selection["matched_campaign_types"] == []
    assert selection["matched_campaign_handler_count"] == 0
    assert selection["campaign_selection_basis"] == ("no_exact_campaign_type_match_with_bounded_campaign_fallback")
    assert selection["bounded_campaign_fallback_handler_count"] == 1
    assert selection["deferred_campaign_handler_count"] == 0


def test_campaign_fallback_selects_root_and_format_transform_depth_diversity(
    isolated_catalog,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """多数層でも各fallback handlerは決定論的な代表2層だけへ試行する。"""

    repository, malware_root = isolated_catalog
    base = _handler_spec(
        repository,
        malware_root,
        "valleyrat",
        _source("{}", ("data", "pe")),
        input_formats=("data", "pe"),
    )
    shared = replace(base, id="valleyrat:shared", campaign=None)
    campaign_a = replace(base, id="valleyrat:campaign_a", campaign="campaign_a")
    campaign_b = replace(base, id="valleyrat:campaign_b", campaign="campaign_b")
    root = _layer(b"root-data", "root.bin")
    shallow = _layer(b"shallow-data", "shallow.bin", root["sha256"])
    shallow["depth"] = 1
    shallow["transform"] = "archive_member"
    pe_shallow = _layer(b"MZ" + b"A" * 30, "shallow.exe", root["sha256"])
    pe_shallow["depth"] = 2
    pe_shallow["transform"] = "pe_resource"
    pe_deep = _layer(b"MZ" + b"B" * 30, "deep.exe", root["sha256"])
    pe_deep["depth"] = 4
    pe_deep["transform"] = "pe_resource"
    data_deepest = _layer(b"deepest-data", "deepest.bin", root["sha256"])
    data_deepest["depth"] = 5
    data_deepest["transform"] = "xor_decode"
    layers = [root, shallow, pe_shallow, pe_deep, data_deepest]
    calls: list[tuple[str, str]] = []

    def execute(handler, _data, source_name, **_kwargs):
        calls.append((handler.id, source_name))
        return _mock_completed_handler_result()

    monkeypatch.setattr(catalog, "execute_handler_bounded_for_assessment", execute)
    result = catalog.assess_candidate_handlers(
        [_candidate("valleyrat", source="external_metadata")],
        layers,
        specs=[campaign_b, shared, campaign_a],
    )

    assert result["considered_pair_count"] == 15
    assert result["planned_attempt_count"] == result["actual_attempt_count"] == 9
    assert result["skipped_pair_count"] == 6
    assert result["format_incompatible_pair_count"] == 0
    assert result["fallback_policy_skipped_pair_count"] == 6
    planning = result["pair_planning"]
    assert planning["bounded_campaign_fallback_handler_count"] == 2
    assert planning["bounded_campaign_fallback_planned_attempt_count"] == 4
    assert planning["fallback_policy_skipped_pair_count"] == 6
    assert planning["worker_started_for_fallback_policy_skipped_pairs"] is False
    assert [call for call in calls if call[0] != shared.id] == [
        (campaign_a.id, root["name"]),
        (campaign_b.id, root["name"]),
        (campaign_a.id, pe_deep["name"]),
        (campaign_b.id, pe_deep["name"]),
    ]
    plans = {plan["handler_id"]: plan for plan in result["families"][0]["handler_layer_plan"]}
    for campaign in (campaign_a, campaign_b):
        plan = plans[campaign.id]
        assert plan["selection_role"] == "bounded_campaign_fallback"
        assert plan["format_compatible_pair_count"] == 5
        assert plan["compatible_layer_indexes"] == [0, 3]
        assert plan["compatible_pair_count"] == 2
        assert plan["fallback_policy_skipped_pair_count"] == 3
    assert result["confirmed_families"] == []
    assert result["metadata_hint_can_confirm"] is False


def test_route_only_exact_campaign_keeps_all_layers_and_bounds_other_campaigns(
    isolated_catalog,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """route完全一致は全層、その他campaignは代表層だけへ計画する。"""

    repository, malware_root = isolated_catalog
    base = _handler_spec(
        repository,
        malware_root,
        "valleyrat",
        _source("{}", ("data", "pe")),
        input_formats=("data", "pe"),
    )
    shared = replace(base, id="valleyrat:shared", campaign=None)
    matched = replace(base, id="valleyrat:matched", campaign="matched_campaign")
    other = replace(base, id="valleyrat:other", campaign="other_campaign")
    root = _layer(b"root-data", "root.bin")
    children = [_layer(f"child-{index}".encode(), f"child-{index}.bin", root["sha256"]) for index in range(4)]
    for index, layer in enumerate(children, start=1):
        layer["depth"] = index
        layer["transform"] = f"transform_{index}"
    layers = [root, *children]
    calls: list[str] = []

    def execute(handler, *_args, **_kwargs):
        calls.append(handler.id)
        return _mock_completed_handler_result()

    monkeypatch.setattr(catalog, "execute_handler_bounded_for_assessment", execute)
    result = catalog.assess_candidate_handlers(
        [_candidate("valleyrat", source="detector_and_external_metadata")],
        layers,
        specs=[other, matched, shared],
        detector_evaluations={"valleyrat": {root["sha256"]: _routing_detector(False, ["matched_campaign"])}},
    )

    assert calls.count(shared.id) == 5
    assert calls.count(matched.id) == 5
    assert calls.count(other.id) == 2
    assert result["planned_attempt_count"] == 12
    plans = {plan["handler_id"]: plan for plan in result["families"][0]["handler_layer_plan"]}
    assert plans[matched.id]["selection_role"] == "primary"
    assert plans[matched.id]["compatible_pair_count"] == 5
    assert plans[other.id]["selection_role"] == "bounded_campaign_fallback"
    assert plans[other.id]["compatible_layer_indexes"] == [0, 4]


@pytest.mark.parametrize(
    "evaluation, expected_basis",
    [
        (
            _routing_detector(False, ["Not Strict"]),
            "detector_campaign_identifier_invalid",
        ),
        (
            _routing_detector(None, ["matched_campaign"]),
            "supports_family_attribution_not_boolean",
        ),
        (
            {
                "known_outer_sha256": False,
                "known_inner_sha256": False,
                "known_routing_sha256": False,
                "detector_matched": True,
                "applicable": True,
                "automatic_route_eligible": True,
                "error": None,
                "supports_family_attribution": False,
                "detection": {"matched": True, "campaigns": "not-a-list"},
            },
            "detector_campaigns_not_list",
        ),
        (
            {
                **_routing_detector(False, ["matched_campaign"]),
                "error": "DetectorError: fixture failure",
            },
            "detector_error_present",
        ),
        (
            {
                **_routing_detector(False, ["matched_campaign"]),
                "automatic_route_eligible": False,
            },
            "automatic_route_eligible_not_true",
        ),
        (
            {
                **_routing_detector(False, ["matched_campaign"]),
                "automatic_route_eligible": "yes",
            },
            "automatic_route_eligible_not_boolean",
        ),
        (
            {
                **_routing_detector(False, ["matched_campaign"]),
                "applicable": False,
            },
            "detector_applicable_not_true",
        ),
        (
            {
                **_routing_detector(False, ["matched_campaign"]),
                "known_routing_sha256": 1,
            },
            "detector_known_flags_not_boolean",
        ),
    ],
    ids=[
        "invalid-campaign-id",
        "missing-attribution-scope",
        "campaigns-not-list",
        "detector-error",
        "automatic-route-ineligible",
        "automatic-route-nonboolean",
        "not-applicable",
        "known-flag-nonboolean",
    ],
)
def test_unknown_or_malformed_detector_scope_keeps_all_handlers(
    isolated_catalog,
    monkeypatch: pytest.MonkeyPatch,
    evaluation: dict,
    expected_basis: str,
) -> None:
    """detector情報が不正・不明なら絞り込まず既存coverageを維持する。"""

    repository, malware_root = isolated_catalog
    base = _handler_spec(
        repository,
        malware_root,
        "valleyrat",
        _source("{}"),
    )
    shared = replace(base, id="valleyrat:shared", campaign=None)
    first = replace(base, id="valleyrat:first", campaign="matched_campaign")
    second = replace(base, id="valleyrat:second", campaign="other_campaign")
    calls: list[str] = []

    def execute(handler, *_args, **_kwargs):
        calls.append(handler.id)
        return _mock_completed_handler_result()

    monkeypatch.setattr(catalog, "execute_handler_bounded_for_assessment", execute)
    layer = _layer(b"candidate payload", "payload.bin")
    result = catalog.assess_candidate_handlers(
        [_candidate("valleyrat", source="detector_and_external_metadata")],
        [layer],
        specs=[second, shared, first],
        detector_evaluations={"valleyrat": {layer["sha256"]: evaluation}},
    )

    assert calls == [shared.id, first.id, second.id]
    selection = result["families"][0]["handler_selection"]
    assert selection["mode"] == "all_automatic_handlers"
    assert selection["detector_scope_status"] == "unknown"
    assert selection["detector_scope_basis"] == expected_basis
    assert selection["selected_handler_count"] == 3
    assert selection["detector_scope_used_for_handler_selection"] is False
    assert selection["route_only_campaign_types"] == []
    assert selection["matched_campaign_types"] == []
    assert selection["campaign_selection_basis"] == "not_applicable"


def test_non_mapping_family_detector_value_keeps_coverage_without_confirmation(
    isolated_catalog,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """family detector値自体が不正でも全handlerを試し、帰属証拠には使わない。"""

    repository, malware_root = isolated_catalog
    base = _handler_spec(
        repository,
        malware_root,
        "valleyrat",
        _source("{}"),
    )
    shared = replace(base, id="valleyrat:shared", campaign=None)
    campaign = replace(
        base,
        id="valleyrat:campaign",
        campaign="matched_campaign",
    )
    calls: list[str] = []

    def execute(handler, *_args, **_kwargs):
        calls.append(handler.id)
        completed = _mock_completed_handler_result()
        completed["execution"]["result"] = {"marker_hits": ["strong-handler-evidence"]}
        return completed

    monkeypatch.setattr(catalog, "execute_handler_bounded_for_assessment", execute)
    result = catalog.assess_candidate_handlers(
        [_candidate("valleyrat", source="detector_and_external_metadata")],
        [_layer(b"candidate payload", "payload.bin")],
        specs=[campaign, shared],
        detector_evaluations={"valleyrat": ["not", "a", "mapping"]},
    )

    assert calls == [shared.id, campaign.id]
    selection = result["families"][0]["handler_selection"]
    assert selection["mode"] == "all_automatic_handlers"
    assert selection["detector_scope_status"] == "unknown"
    assert selection["detector_scope_basis"] == ("family_detector_evaluations_not_mapping")
    assert selection["detector_scope_used_for_handler_selection"] is False
    assert selection["detector_scope_used_for_family_confirmation"] is False
    assert result["confirmed_families"] == []
    assert result["families"][0]["status"] == ("handler_evidence_without_detector")


def test_deep_compatible_layer_runs_after_many_incompatible_layers_without_quota_use(
    isolated_catalog,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """非互換pairをworker試行へ数えず、深い互換config層まで必ず到達する。"""

    repository, malware_root = isolated_catalog
    spec = _handler_spec(
        repository,
        malware_root,
        "candidate_family",
        _source("{}", ("pe",)),
        input_formats=("pe",),
    )
    incompatible = [_layer(f"data-{index:02d}".encode(), f"{index:02d}.bin") for index in range(64)]
    deep = _layer(b"MZ-deep-compatible-config", "deep-config.exe", incompatible[-1]["sha256"])
    deep["depth"] = 64
    calls: list[tuple[str, str, str]] = []

    def bounded(handler, _data, name, *, actual_format, **_kwargs):
        calls.append((handler.id, name, actual_format))
        return _mock_completed_handler_result()

    monkeypatch.setattr(catalog, "execute_handler_bounded_for_assessment", bounded)
    result = catalog.assess_candidate_handlers(
        [_candidate("candidate_family")],
        [*incompatible, deep],
        specs=[spec],
        maximum_attempts=1,
    )

    assert calls == [(spec.id, "deep-config.exe", "pe")]
    assert result["considered_pair_count"] == 65
    assert result["planned_attempt_count"] == result["actual_attempt_count"] == 1
    assert result["skipped_pair_count"] == 64
    assert result["unattempted_attempt_count"] == 0
    assert result["blockers"] == []
    plan = result["pair_planning"]
    assert plan["format_compatibility_checked_before_execution_quota"] is True
    assert plan["incompatible_pairs_consume_execution_quota"] is False
    assert plan["worker_started_for_incompatible_pairs"] is False
    assert plan["executed_sample"] is False
    assert plan["network_contacted"] is False
    assert plan["filesystem_written_by_handlers"] is False
    assert plan["lineage_layers"][-1]["sha256"] == deep["sha256"]
    assert plan["lineage_layers"][-1]["parent_sha256"] == incompatible[-1]["sha256"]
    skipped = result["families"][0]["skipped_pairs"][0]
    assert skipped["layer_indexes"] == list(range(64))
    assert skipped["blockers"] == ["incompatible_input_format:data"]
    assert skipped["execution_quota_consumed"] is False
    assert skipped["sample_execution_allowed"] is False
    assert skipped["network_allowed"] is False
    assert skipped["filesystem_write_allowed"] is False


@pytest.mark.parametrize(
    "candidate",
    [
        {
            "family": "candidate_family",
            "source": "metadata_hint",
            "routing_eligible": False,
            "routing_mode": "blocked",
        },
        {"family": "candidate_family", "source": "metadata_hint"},
        {
            "family": "candidate_family",
            "source": "metadata_hint",
            "routing_eligible": True,
            "routing_mode": "candidate_verification",
            "routing_eligibility": {"candidate_verification": False},
        },
    ],
)
def test_mapping_candidate_without_complete_routing_authorization_is_blocked(
    isolated_catalog,
    monkeypatch: pytest.MonkeyPatch,
    candidate: dict,
) -> None:
    """routing許可が欠けるmapping候補はpreflightもworkerも起動しない。"""

    repository, malware_root = isolated_catalog
    spec = _handler_spec(
        repository,
        malware_root,
        "candidate_family",
        _source("{'marker_hits': ['marker']}"),
    )
    called = []
    monkeypatch.setattr(
        catalog,
        "_execute_handler_bounded",
        lambda *_args, **_kwargs: called.append(True),
    )
    result = catalog.assess_candidate_handlers(
        [candidate],
        [_layer(b"candidate payload", "payload.bin")],
        specs=[spec],
    )

    family = result["families"][0]
    assert family["status"] == "blocked"
    assert family["attempts"] == []
    assert result["planned_attempt_count"] == 0
    assert result["blocked_candidate_count"] == 1
    assert called == []


def test_string_candidate_is_explicit_caller_selected_compatibility(isolated_catalog) -> None:
    """文字列候補は後方互換としてcaller明示選択のverification候補に限定する。"""

    repository, malware_root = isolated_catalog
    spec = _handler_spec(
        repository,
        malware_root,
        "candidate_family",
        _source("{}"),
    )
    result = catalog.assess_candidate_handlers(
        ["candidate_family"],
        [_layer(b"candidate payload", "payload.bin")],
        specs=[spec],
    )
    family = result["families"][0]
    assert family["routing_eligible"] is True
    assert family["routing_mode"] == "candidate_verification"
    assert family["caller_selected_string"] is True
    assert family["sources"] == ["explicit_caller_candidate"]


@pytest.mark.parametrize(
    "result_expression",
    [
        "{}",
        "{'confidence': 'confirmed', 'family': 'candidate_family', 'matched': True}",
    ],
    ids=["empty_result", "self_reported_confidence"],
)
def test_empty_or_self_reported_result_is_not_evidence(
    isolated_catalog,
    result_expression: str,
) -> None:
    repository, malware_root = isolated_catalog
    spec = _handler_spec(
        repository,
        malware_root,
        "candidate_family",
        _source(result_expression),
    )
    layer = _layer(b"candidate payload", "payload.bin")
    result = catalog.assess_candidate_handlers(
        ["candidate_family"],
        [layer],
        specs=[spec],
        detector_evaluations={"candidate_family": {layer["sha256"]: _structural_detector()}},
    )

    attempt = result["families"][0]["attempts"][0]
    assert attempt["status"] == "no_evidence"
    assert attempt["handler_evidence"]["tier_name"] == "no_evidence"
    assert result["confirmed_families"] == []


@pytest.mark.parametrize("location", ["import_time", "reachable"])
def test_side_effect_is_blocked_before_handler_import(
    isolated_catalog,
    location: str,
) -> None:
    repository, malware_root = isolated_catalog
    touched = malware_root / "candidate_family" / "touched.txt"
    contract = 'HANDLER_CONTRACT = {"input_formats": ["data"], "minimum_evidence_score": 1}\n'
    if location == "import_time":
        source = (
            "from pathlib import Path\n"
            f'Path({str(touched)!r}).write_text("bad", encoding="utf-8")\n' + contract + "def extract_config(data):\n"
            "    return {'marker_hits': ['marker']}\n"
        )
    else:
        source = (
            "from pathlib import Path\n" + contract + "def write_result(data):\n"
            f'    Path({str(touched)!r}).write_text("bad", encoding="utf-8")\n'
            "    return {'marker_hits': ['marker']}\n" + "def extract_config(data):\n"
            "    return write_result(data)\n"
        )
    spec = _handler_spec(repository, malware_root, "candidate_family", source)
    layer = _layer(b"candidate payload", "payload.bin")

    result = catalog.assess_candidate_handlers(
        ["candidate_family"],
        [layer],
        specs=[spec],
        detector_evaluations={"candidate_family": {layer["sha256"]: _structural_detector()}},
    )

    attempt = result["families"][0]["attempts"][0]
    assert attempt["status"] == "preflight_blocked"
    assert any(location in blocker for blocker in attempt["preflight"]["blockers"])
    assert not touched.exists()


def test_unreachable_cli_writer_does_not_block_pure_handler(isolated_catalog) -> None:
    repository, malware_root = isolated_catalog
    source = (
        "from pathlib import Path\n"
        'HANDLER_CONTRACT = {"input_formats": ["data"], '
        '"minimum_evidence_score": 1}\n'
        "def extract_config(data):\n"
        "    return {'marker_hits': ['marker']}\n"
        "def main():\n"
        '    Path("cli-output.json").write_text("cli", encoding="utf-8")\n'
    )
    spec = _handler_spec(repository, malware_root, "candidate_family", source)
    preflight = catalog.preflight_handler_for_assessment(
        spec,
        actual_format="data",
        input_size=10,
    )
    assert preflight["eligible"] is True


@pytest.mark.parametrize("location", ["import_time", "reachable"])
def test_repository_local_import_alias_side_effect_is_blocked_recursively(
    isolated_catalog,
    location: str,
) -> None:
    """alias付きlocal helperのimport時・到達関数副作用をfile間で検出する。"""

    repository, malware_root = isolated_catalog
    family_root = malware_root / "candidate_family"
    family_root.mkdir(parents=True, exist_ok=True)
    touched = family_root / "touched.txt"
    if location == "import_time":
        helper = (
            "from pathlib import Path\n"
            f'Path({str(touched)!r}).write_text("bad", encoding="utf-8")\n'
            "def exfiltrate(data):\n"
            "    return {'marker_hits': ['marker']}\n"
        )
    else:
        helper = (
            "from pathlib import Path\n"
            "def exfiltrate(data):\n"
            f'    Path({str(touched)!r}).write_text("bad", encoding="utf-8")\n'
            "    return {'marker_hits': ['marker']}\n"
        )
    (family_root / "helper_module.py").write_text(helper, encoding="utf-8")
    source = (
        "from helper_module import exfiltrate as helper\n"
        'HANDLER_CONTRACT = {"input_formats": ["data"], "minimum_evidence_score": 1}\n'
        "def extract_config(data):\n"
        "    return helper(data)\n"
    )
    spec = _handler_spec(repository, malware_root, "candidate_family", source)
    preflight = catalog.preflight_handler_for_assessment(
        spec,
        actual_format="data",
        input_size=10,
    )
    assert preflight["eligible"] is False
    assert any(location in blocker for blocker in preflight["blockers"])
    assert preflight["dependency_audit"]["files_inspected"] == 2
    assert not touched.exists()


def test_dependency_source_manifest_rejects_forged_records(
    isolated_catalog,
) -> None:
    """workerへ渡す依存manifestはexact schema・安全path・現在hashへ結合する。"""

    repository, malware_root = isolated_catalog
    spec = _handler_spec(
        repository,
        malware_root,
        "candidate_family",
        _source("{'marker_hits': ['marker']}"),
    )
    source = repository / spec.relative_path
    relative = source.relative_to(repository).as_posix()
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    valid = [{"path": relative, "sha256": digest}]

    assert (
        catalog._validated_dependency_source_manifest(
            valid,
            repository=repository,
        )
        == valid
    )
    forged_values = [
        [{**valid[0], "extra": True}],
        [valid[0], valid[0]],
        [{"path": "../escape.py", "sha256": digest}],
        [{"path": relative.replace("/", "\\"), "sha256": digest}],
        [{"path": relative, "sha256": "0" * 64}],
    ]
    for forged in forged_values:
        with pytest.raises(catalog.HandlerLoadError):
            catalog._validated_dependency_source_manifest(
                forged,
                repository=repository,
            )

    directory = source.parent / "directory.py"
    directory.mkdir()
    with pytest.raises(catalog.HandlerLoadError):
        catalog._validated_dependency_source_manifest(
            [
                {
                    "path": directory.relative_to(repository).as_posix(),
                    "sha256": "0" * 64,
                }
            ],
            repository=repository,
        )


def test_worker_request_rejects_unknown_fields(tmp_path: Path) -> None:
    """isolated workerのrequestは未知fieldを受理しない。"""

    worker_root = tmp_path / "worker"
    worker_root.mkdir()
    (worker_root / "artifacts").mkdir()
    output = worker_root / "response.json"
    encoded = base64.urlsafe_b64encode(json.dumps({"unexpected": True}).encode("utf-8")).decode("ascii").rstrip("=")

    assert catalog._assessment_worker_main(encoded, str(output)) == 0
    response = json.loads(output.read_text(encoding="utf-8"))
    assert response == {
        "ok": False,
        "error": "handler_worker_failed",
        "error_type": "HandlerLoadError",
    }


def test_unresolved_dynamic_callable_fails_closed(isolated_catalog) -> None:
    """getattrで生成した未解決callableは候補handlerとして許可しない。"""

    repository, malware_root = isolated_catalog
    source = (
        'HANDLER_CONTRACT = {"input_formats": ["data"], "minimum_evidence_score": 1}\n'
        "def extract_config(data):\n"
        '    callback = getattr(data, "decode")\n'
        "    return callback()\n"
    )
    spec = _handler_spec(repository, malware_root, "candidate_family", source)
    preflight = catalog.preflight_handler_for_assessment(
        spec,
        actual_format="data",
        input_size=10,
    )
    assert preflight["eligible"] is False
    assert any("unresolved_higher_order_call:getattr" in item for item in preflight["blockers"])


def test_execute_handler_verifies_raw_terminal_binary_and_separates_self_report(
    isolated_catalog,
) -> None:
    """handler自己申告hashではなくraw bytesをwrapperがhashして公開する。"""

    repository, malware_root = isolated_catalog
    payload = b"MZ" + b"A" * 30
    source = (
        'HANDLER_CONTRACT = {"input_formats": ["data"], "minimum_evidence_score": 1}\n'
        "def extract_config(data):\n"
        "    return {\n"
        '        "verified_binary_outputs": [{"sha256": "0" * 64, "size": 999}],\n'
        f'        "terminal_payload": {{"name": "stage.exe", "data": {payload!r}}},\n'
        "    }\n"
    )
    spec = _handler_spec(repository, malware_root, "candidate_family", source)
    result = catalog.execute_handler(spec, b"input", "sample.bin")
    verified = result["verified_binary_outputs"]
    assert verified == [
        {
            "role": "terminal_payload",
            "kind": "pe",
            "path": "stage.exe",
            "sha256": hashlib.sha256(payload).hexdigest(),
            "size": len(payload),
            "verification": {
                "status": "artifact_hash_verified",
                "sha256_matches": True,
                "size_matches": True,
            },
        }
    ]
    assert result["result"]["verified_binary_outputs"][0]["sha256"] == "0" * 64
    assert result["result"]["terminal_payload"]["data"]["content_exported"] is False


def test_bounded_handler_retains_raw_payload_only_after_parent_rehash(
    isolated_catalog,
    tmp_path: Path,
) -> None:
    """隔離workerのraw bytesは親再検証後だけrepo外artifactへ保持する。"""

    repository, malware_root = isolated_catalog
    payload = b"MZ" + b"B" * 62
    source = (
        'HANDLER_CONTRACT = {"input_formats": ["data"], "minimum_evidence_score": 1}\n'
        "def extract_config(data):\n"
        f'    return {{"terminal_payload": {{"name": "stage.exe", "data": {payload!r}}}}}\n'
    )
    spec = _handler_spec(repository, malware_root, "candidate_family", source)
    artifact_directory = tmp_path / "retained"
    artifact_directory.mkdir()

    bounded = catalog.execute_handler_bounded_for_assessment(
        spec,
        b"input",
        "sample.bin",
        actual_format="data",
        artifact_directory=artifact_directory,
        artifact_path_prefix="recovered-payloads",
    )

    assert bounded["status"] == "completed"
    execution = bounded["execution"]
    digest = hashlib.sha256(payload).hexdigest()
    retained = artifact_directory / f"{digest}.exe"
    assert retained.read_bytes() == payload
    assert execution["verified_binary_outputs"][0]["path"] == (f"recovered-payloads/{digest}.exe")
    assert execution["verified_binary_output_audit"]["retained_for_follow_on_analysis"] is True
    assert execution["verified_binary_output_audit"]["follow_on_analysis_complete"] is False
    assert execution["verified_binary_output_audit"]["observation_scope"] == ("parent_rehashed_case_artifact")


def test_bounded_handler_without_destination_is_observed_only(
    isolated_catalog,
) -> None:
    """保存先なしのraw bytesはhash観測だけを残しterminal完了へ昇格しない。"""

    repository, malware_root = isolated_catalog
    source = (
        'HANDLER_CONTRACT = {"input_formats": ["data"], "minimum_evidence_score": 1}\n'
        "def extract_config(data):\n"
        '    return {"terminal_payload": b"MZ-observed"}\n'
    )
    spec = _handler_spec(repository, malware_root, "candidate_family", source)
    bounded = catalog.execute_handler_bounded_for_assessment(
        spec,
        b"input",
        "sample.bin",
        actual_format="data",
    )

    execution = bounded["execution"]
    assert execution["verified_binary_outputs"] == []
    assert len(execution["observed_binary_outputs"]) == 1
    assert execution["verified_binary_output_audit"]["retained_for_follow_on_analysis"] is False
    assert execution["verified_binary_output_audit"]["follow_on_analysis_complete"] is False


def test_yuanbao_unmatched_layer_is_no_evidence_not_worker_failure() -> None:
    """Yuanbao固有証拠のないPE層はworker障害ではなく対象外として完了する。"""

    spec = next(
        item
        for item in catalog.discover_handlers()
        if item.relative_path.endswith("yuanbao_sideload/analyze_bundle.py")
    )
    bounded = catalog.execute_handler_bounded_for_assessment(
        spec,
        b"MZ" + bytes(64),
        "synthetic.exe",
        actual_format="pe",
        timeout_seconds=30,
    )

    assert bounded["status"] == "completed"
    result = bounded["execution"]["result"]
    assert result["status"] == "not_applicable"
    quality = handler_result_quality(result, minimum_score=spec.minimum_evidence_score)
    assert quality["tier"] == 0
    assert quality["sufficient"] is False


def test_retention_rejects_repository_destination(
    isolated_catalog,
) -> None:
    """復号payloadをGit repository配下へ保存する指定は拒否する。"""

    repository, malware_root = isolated_catalog
    source = (
        'HANDLER_CONTRACT = {"input_formats": ["data"], "minimum_evidence_score": 1}\n'
        "def extract_config(data):\n"
        '    return {"terminal_payload": b"MZ-repository"}\n'
    )
    spec = _handler_spec(repository, malware_root, "candidate_family", source)
    forbidden = repository / "analysis-output"
    forbidden.mkdir()

    with pytest.raises(ValueError, match="repository"):
        catalog.execute_handler_bounded_for_assessment(
            spec,
            b"input",
            "sample.bin",
            actual_format="data",
            artifact_directory=forbidden,
        )


def test_verified_binary_scan_is_bounded_and_cycle_safe(monkeypatch: pytest.MonkeyPatch) -> None:
    """raw result走査はcycleと総byte上限で停止する。"""

    cyclic: dict = {}
    cyclic["terminal_payload"] = cyclic
    outputs, audit = catalog._verified_binary_outputs(cyclic)
    assert outputs == []
    assert "cycle_detected" in audit["reasons"]

    monkeypatch.setattr(catalog, "MAX_VERIFIED_BINARY_TOTAL_SIZE", 4)
    outputs, audit = catalog._verified_binary_outputs({"terminal_payload": b"MZ123"})
    assert outputs == []
    assert "maximum_total_binary_size" in audit["reasons"]
    assert audit["truncated"] is True


def test_truncated_raw_payload_is_not_staged(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """total-size上限を超えたraw bytesは一時artifactも生成しない。"""

    artifact_root = tmp_path / "worker-artifacts"
    artifact_root.mkdir()
    monkeypatch.setattr(catalog, "MAX_VERIFIED_BINARY_TOTAL_SIZE", 4)
    outputs, audit = catalog._verified_binary_outputs(
        {"terminal_payload": b"MZ123"},
        artifact_root=artifact_root,
    )

    assert outputs == []
    assert list(artifact_root.iterdir()) == []
    assert audit["retained_for_follow_on_analysis"] is False
    assert audit["truncated"] is True


def test_public_sanitizer_covers_keys_leading_url_and_set_order() -> None:
    """dict keyと先頭空白URLを秘匿し、setを決定順序で公開する。"""

    secret_key = "github_pat_" + "A" * 40
    sanitized = catalog.sanitize_public_value({secret_key: "value"})
    rendered_key = next(iter(sanitized))
    assert secret_key not in rendered_key
    assert "[REDACTED" in rendered_key
    assert (
        catalog.sanitize_public_value("  https://user:pass@example.test/token/secret?api_key=value  ")
        == "https://example.test/token/[REDACTED]"
    )
    assert catalog.sanitize_public_value({"z", "a", "m"}) == ["a", "m", "z"]


def test_load_handler_restores_sys_path(isolated_catalog) -> None:
    """handler importが変更したsys.pathを呼出し元processへ残さない。"""

    repository, malware_root = isolated_catalog
    marker = str(repository / "poisoned-import-path")
    source = (
        "import sys\n"
        f"sys.path.insert(0, {marker!r})\n"
        'HANDLER_CONTRACT = {"input_formats": ["data"], "minimum_evidence_score": 1}\n'
        "def extract_config(data):\n"
        "    return {}\n"
    )
    spec = _handler_spec(repository, malware_root, "candidate_family", source)
    original = list(sys.path)
    catalog.load_handler(spec)
    assert sys.path == original
    assert marker not in sys.path


def test_candidate_handler_wall_clock_timeout(isolated_catalog) -> None:
    """停止しないhandlerは別process treeごとtimeoutし、jobを継続可能にする。"""

    repository, malware_root = isolated_catalog
    source = (
        'HANDLER_CONTRACT = {"input_formats": ["data"], "minimum_evidence_score": 1}\n'
        "def extract_config(data):\n"
        "    while True:\n"
        "        pass\n"
    )
    spec = _handler_spec(repository, malware_root, "candidate_family", source)
    result = catalog.assess_candidate_handlers(
        ["candidate_family"],
        [_layer(b"candidate payload", "payload.bin")],
        specs=[spec],
        handler_timeout_seconds=0.2,
    )
    assert result["families"][0]["status"] == "handler_timed_out"
    assert result["families"][0]["attempts"][0]["status"] == "timed_out"


def test_public_bounded_assessment_api_returns_stable_execution_shape(
    isolated_catalog,
) -> None:
    """selected/candidate共通の公開境界が事前検査と隔離実行結果を返す。"""

    repository, malware_root = isolated_catalog
    spec = _handler_spec(
        repository,
        malware_root,
        "candidate_family",
        _source("{'marker_hits': ['bounded-public-api']}"),
    )
    result = catalog.execute_handler_bounded_for_assessment(
        spec,
        b"candidate payload",
        "payload.bin",
        actual_format="data",
        timeout_seconds=2.0,
    )
    assert result["status"] == "completed"
    assert result["preflight"]["eligible"] is True
    assert result["handler_timeout_seconds"] == 2.0
    assert result["execution"]["result"]["marker_hits"] == ["bounded-public-api"]


def test_worker_rechecks_dependency_manifest_immediately_before_import(
    isolated_catalog,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """親検証後にlocal dependencyを差し替えてもworkerはimportせずfail closedにする。"""

    repository, malware_root = isolated_catalog
    family_root = malware_root / "candidate_family"
    family_root.mkdir(parents=True, exist_ok=True)
    helper = family_root / "helper_module.py"
    helper.write_text(
        "def transform(data):\n    return {'marker_hits': ['safe-helper']}\n",
        encoding="utf-8",
    )
    spec = _handler_spec(
        repository,
        malware_root,
        "candidate_family",
        "from helper_module import transform\n"
        'HANDLER_CONTRACT = {"input_formats": ["data"], '
        '"minimum_evidence_score": 1}\n'
        "def extract_config(data):\n"
        "    return transform(data)\n",
    )
    touched = family_root / "worker-imported-mutated-helper.txt"
    original_run_bounded = bounded_process.run_bounded
    captured_request: dict = {}

    def mutate_after_parent_check(*args, **kwargs):
        command = args[0]
        token = command[-2]
        padding = "=" * (-len(token) % 4)
        captured_request.update(json.loads(base64.urlsafe_b64decode((token + padding).encode("ascii")).decode("utf-8")))
        helper.write_text(
            "from pathlib import Path\n"
            f'Path({str(touched)!r}).write_text("imported", encoding="utf-8")\n'
            "def transform(data):\n"
            "    return {'marker_hits': ['mutated-helper']}\n",
            encoding="utf-8",
        )
        return original_run_bounded(*args, **kwargs)

    monkeypatch.setattr(bounded_process, "run_bounded", mutate_after_parent_check)
    result = catalog.execute_handler_bounded_for_assessment(
        spec,
        b"candidate payload",
        "payload.bin",
        actual_format="data",
        timeout_seconds=5.0,
    )

    assert set(captured_request) == {
        "dependency_data_manifest",
        "dependency_module_manifest",
        "dependency_source_manifest",
        "extractors_root",
        "framework_root",
        "malware_root",
        "repository_root",
        "source_name",
        "spec",
    }
    assert [item["path"] for item in captured_request["dependency_source_manifest"]] == [
        spec.relative_path,
        helper.relative_to(repository).as_posix(),
    ]
    assert result["status"] == "failed"
    assert result["error_type"] == "HandlerLoadError"
    assert not touched.exists()


def test_worker_rechecks_root_source_after_matching_preflight_snapshots(
    isolated_catalog,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A/Bが一致してもworker直前にrootが変わればimportせず拒否する。"""

    repository, malware_root = isolated_catalog
    original_source = _source("{'marker_hits': ['verified-root']}")
    spec = _handler_spec(
        repository,
        malware_root,
        "candidate_family",
        original_source,
    )
    source_path = repository / spec.relative_path
    original_sha256 = hashlib.sha256(source_path.read_bytes()).hexdigest()
    touched = malware_root / "candidate_family" / "worker-imported-mutated-root.txt"
    original_run_bounded = bounded_process.run_bounded
    captured_request: dict = {}

    def mutate_after_parent_check(*args, **kwargs):
        command = args[0]
        token = command[-2]
        padding = "=" * (-len(token) % 4)
        captured_request.update(json.loads(base64.urlsafe_b64decode((token + padding).encode("ascii")).decode("utf-8")))
        source_path.write_text(
            (
                "from pathlib import Path\n"
                f'Path({str(touched)!r}).write_text("imported", encoding="utf-8")\n'
                + _source("{'marker_hits': ['mutated-root']}")
            ),
            encoding="utf-8",
        )
        return original_run_bounded(*args, **kwargs)

    monkeypatch.setattr(bounded_process, "run_bounded", mutate_after_parent_check)
    result = catalog.execute_handler_bounded_for_assessment(
        spec,
        b"candidate payload",
        "payload.bin",
        actual_format="data",
        timeout_seconds=5.0,
    )

    assert result["preflight"]["source_sha256"] == original_sha256
    assert (
        next(
            record["sha256"]
            for record in result["preflight"]["dependency_audit"]["files"]
            if record["path"] == spec.relative_path
        )
        == original_sha256
    )
    assert (
        next(
            record["sha256"]
            for record in captured_request["dependency_source_manifest"]
            if record["path"] == spec.relative_path
        )
        == original_sha256
    )
    assert result["status"] == "failed"
    assert result["error_type"] == "HandlerLoadError"
    assert not touched.exists()


def test_verified_source_snapshots_ignore_post_verification_path_replacement(
    isolated_catalog,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """検証完了後にpathを差し替えてもmain/helperとも検証済みbytesだけを実行する。"""

    repository, malware_root = isolated_catalog
    family_root = malware_root / "candidate_family"
    family_root.mkdir(parents=True, exist_ok=True)
    helper = family_root / "helper_module.py"
    helper.write_text(
        "def transform(data):\n    return {'marker_hits': ['verified-helper']}\n",
        encoding="utf-8",
    )
    spec = _handler_spec(
        repository,
        malware_root,
        "candidate_family",
        "from helper_module import transform\n"
        'HANDLER_CONTRACT = {"input_formats": ["data"], '
        '"minimum_evidence_score": 1}\n'
        "def extract_config(data):\n"
        "    return transform(data)\n",
    )
    preflight = catalog.preflight_handler_for_assessment(
        spec,
        actual_format="data",
        input_size=7,
    )
    manifest = preflight["dependency_audit"]["files"]
    original_snapshot = catalog._validated_dependency_source_snapshots
    touched_main = family_root / "mutated-main-imported.txt"
    touched_helper = family_root / "mutated-helper-imported.txt"

    def snapshot_then_replace(value, *, repository):
        snapshots = original_snapshot(value, repository=repository)
        (repository / spec.relative_path).write_text(
            "from pathlib import Path\n"
            f'Path({str(touched_main)!r}).write_text("bad", encoding="utf-8")\n'
            'HANDLER_CONTRACT = {"input_formats": ["data"], '
            '"minimum_evidence_score": 1}\n'
            "def extract_config(data):\n"
            "    return {'marker_hits': ['mutated-main']}\n",
            encoding="utf-8",
        )
        helper.write_text(
            "from pathlib import Path\n"
            f'Path({str(touched_helper)!r}).write_text("bad", encoding="utf-8")\n'
            "def transform(data):\n"
            "    return {'marker_hits': ['mutated-helper']}\n",
            encoding="utf-8",
        )
        return snapshots

    monkeypatch.setattr(
        catalog,
        "_validated_dependency_source_snapshots",
        snapshot_then_replace,
    )
    result = catalog._invoke_handler_from_verified_snapshots(
        spec,
        b"payload",
        "payload.bin",
        manifest,
    )

    assert result == {"marker_hits": ["verified-helper"]}
    assert not touched_main.exists()
    assert not touched_helper.exists()


def test_size_and_unbounded_format_contracts_fail_closed(isolated_catalog) -> None:
    repository, malware_root = isolated_catalog
    bounded = _handler_spec(
        repository,
        malware_root,
        "bounded_family",
        _source("{'marker_hits': ['marker']}"),
    )
    unbounded = _handler_spec(
        repository,
        malware_root,
        "unbounded_family",
        _source("{'marker_hits': ['marker']}", ("any",)),
        input_formats=("any",),
    )
    assert catalog.preflight_handler_for_assessment(
        bounded,
        actual_format="data",
        input_size=5,
        maximum_input_size=4,
    )["blockers"] == ["input_size_limit_exceeded"]
    assert (
        "unbounded_input_format_contract"
        in catalog.preflight_handler_for_assessment(
            unbounded,
            actual_format="data",
            input_size=5,
        )["blockers"]
    )


def test_sibling_layer_detector_does_not_corroborate_handler(isolated_catalog) -> None:
    repository, malware_root = isolated_catalog
    spec = _handler_spec(
        repository,
        malware_root,
        "candidate_family",
        _source("{'marker_hits': ['marker']}"),
    )
    root = _layer(b"MZ-root", "root.exe")
    detector_child = _layer(b"detector-child", "detector.bin", root["sha256"])
    handler_child = _layer(b"handler-child", "handler.bin", root["sha256"])
    result = catalog.assess_candidate_handlers(
        ["candidate_family"],
        [root, detector_child, handler_child],
        specs=[spec],
        detector_evaluations={"candidate_family": {detector_child["sha256"]: _structural_detector()}},
    )

    attempts = result["families"][0]["attempts"]
    handler_attempt = next(item for item in attempts if item["layer"]["sha256"] == handler_child["sha256"])
    assert handler_attempt["status"] == "handler_evidence_without_detector"


def test_child_detector_does_not_corroborate_ancestor_handler(isolated_catalog) -> None:
    """子artifactのdetector証拠を祖先handler結果へ逆流させない。"""

    repository, malware_root = isolated_catalog
    spec = _handler_spec(
        repository,
        malware_root,
        "candidate_family",
        _source("{'marker_hits': ['marker']}"),
    )
    root = _layer(b"ancestor-handler-layer", "root.bin")
    child = _layer(b"child-detector-layer", "child.bin", root["sha256"])
    result = catalog.assess_candidate_handlers(
        [_candidate("candidate_family")],
        [root, child],
        specs=[spec],
        detector_evaluations={"candidate_family": {child["sha256"]: _structural_detector()}},
    )

    attempts = result["families"][0]["attempts"]
    by_digest = {item["layer"]["sha256"]: item for item in attempts}
    assert by_digest[root["sha256"]]["status"] == "handler_evidence_without_detector"
    assert by_digest[root["sha256"]]["detector_corroboration"]["basis"] == ("no_corroborated_detector_in_lineage")
    assert by_digest[child["sha256"]]["status"] == "corroborated"


def test_attempt_limit_returns_partial_without_extra_handler_import(isolated_catalog) -> None:
    repository, malware_root = isolated_catalog
    spec = _handler_spec(
        repository,
        malware_root,
        "candidate_family",
        _source("{'marker_hits': ['marker']}"),
    )
    layers = [_layer(b"layer-one", "one.bin"), _layer(b"layer-two", "two.bin")]
    result = catalog.assess_candidate_handlers(
        ["candidate_family"],
        layers,
        specs=[spec],
        maximum_attempts=1,
    )

    assert result["status"] == "partial"
    assert result["actual_attempt_count"] == 1
    assert result["unattempted_attempt_count"] == 1
    assert result["blockers"] == ["maximum_attempts_exhausted"]


def test_worker_result_quota_isolated_to_attempt_and_remaining_layers_continue(
    isolated_catalog,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """公開result上限は当該証拠だけを破棄し、assessment全体を停止しない。"""

    repository, malware_root = isolated_catalog
    spec = _handler_spec(
        repository,
        malware_root,
        "candidate_family",
        _source("{}"),
    )
    calls = 0

    def execute(*_args, **_kwargs) -> dict:
        nonlocal calls
        calls += 1
        result = _mock_completed_handler_result()
        if calls == 1:
            result["execution"]["result"] = {"marker_hits": ["must-not-be-used-as-evidence"]}
            result["execution"]["result_quota"] = {
                "truncated": True,
                "reasons": ["maximum_total_entries"],
            }
        return result

    monkeypatch.setattr(
        catalog,
        "execute_handler_bounded_for_assessment",
        execute,
    )
    result = catalog.assess_candidate_handlers(
        [_candidate("candidate_family")],
        [
            _layer(b"first candidate layer", "first.bin"),
            _layer(b"second candidate layer", "second.bin"),
        ],
        specs=[spec],
    )

    assert calls == 2
    assert result["status"] == "partial"
    assert result["planned_attempt_count"] == 2
    assert result["actual_attempt_count"] == 2
    assert result["unattempted_attempt_count"] == 0
    assert result["retained_attempt_detail_count"] == 2
    assert result["omitted_attempt_detail_count"] == 0
    assert result["partial_result_attempt_count"] == 1
    assert result["partial_result_reason_counts"] == {"worker_result_structure_quota_exhausted": 1}
    assert result["blockers"] == []
    assert result["budget"]["exhausted"] is False
    family = result["families"][0]
    assert family["status"] == "partial_result_quota_exhausted"
    assert family["partial_result_attempt_count"] == 1
    assert [item["status"] for item in family["attempts"]] == [
        "partial_result_quota_exhausted",
        "no_evidence",
    ]
    partial = family["attempts"][0]
    assert partial["result_quota"] == {
        "truncated": True,
        "reasons": ["maximum_total_entries"],
    }
    assert "result" not in partial
    assert result["confirmed_families"] == []


def test_claimed_layer_format_cannot_override_static_detection(isolated_catalog) -> None:
    repository, malware_root = isolated_catalog
    spec = _handler_spec(
        repository,
        malware_root,
        "candidate_family",
        _source("{'marker_hits': ['marker']}"),
    )
    layer = _layer(b"plain data", "payload.bin")
    layer["format"] = "pe"
    with pytest.raises(ValueError, match="formatがdataの識別結果と一致しません"):
        catalog.assess_candidate_handlers(
            ["candidate_family"],
            [layer],
            specs=[spec],
        )


def test_layer_parent_must_exist_and_dag_must_be_acyclic(isolated_catalog) -> None:
    repository, malware_root = isolated_catalog
    spec = _handler_spec(
        repository,
        malware_root,
        "candidate_family",
        _source("{'marker_hits': ['marker']}"),
    )
    missing_parent = _layer(b"child", "child.bin", "a" * 64)
    with pytest.raises(ValueError, match="親SHA-256が入力集合にありません"):
        catalog.assess_candidate_handlers(
            ["candidate_family"],
            [missing_parent],
            specs=[spec],
        )

    first = _layer(b"first", "first.bin")
    second = _layer(b"second", "second.bin", first["sha256"])
    first["parent_sha256"] = second["sha256"]
    with pytest.raises(ValueError, match="親子関係に循環"):
        catalog.assess_candidate_handlers(
            ["candidate_family"],
            [first, second],
            specs=[spec],
        )


def test_all_discovered_automatic_handlers_pass_assessment_preflight() -> None:
    """現行automatic handlerを候補試行へ接続できる状態に保つ。"""

    blocked = {}
    automatic = [item for item in catalog.discover_handlers() if item.automatic]
    for spec in automatic:
        actual_format = next(
            (item for item in spec.input_formats if item != "any"),
            "data",
        )
        preflight = catalog.preflight_handler_for_assessment(
            spec,
            actual_format=actual_format,
            input_size=4_096,
        )
        if not preflight["eligible"]:
            blocked[spec.id] = preflight["blockers"]
    assert len(automatic) >= 90
    assert blocked == {}


@pytest.mark.parametrize(
    ("source", "blocker"),
    [
        (
            "from pathlib import Path\n" + _source("{'value': Path('secret.txt').read_text(encoding='utf-8')}"),
            "forbidden_side_effect_method",
        ),
        (
            "import numpy\n" + _source("{'value': numpy.fromfile('secret.bin')}"),
            "forbidden_unverified_filesystem_read:numpy.fromfile",
        ),
        (
            "import pefile\n" + _source("{'value': pefile.PE('secret.exe')}"),
            "forbidden_path_parser_input:pefile.PE",
        ),
    ],
    ids=["path_read_text", "numpy_fromfile", "pefile_path"],
)
def test_ast_audit_blocks_unverified_path_readers(
    isolated_catalog,
    source: str,
    blocker: str,
) -> None:
    repository, malware_root = isolated_catalog
    spec = _handler_spec(repository, malware_root, "candidate_family", source)

    preflight = catalog.preflight_handler_for_assessment(
        spec,
        actual_format="data",
        input_size=16,
    )

    assert preflight["eligible"] is False
    assert any(blocker in item for item in preflight["blockers"])


def test_ast_audit_blocks_higher_order_open_reader_bypass(isolated_catalog) -> None:
    """getattr→map→next→readの高階関数連鎖でもfilesystem readを許可しない。"""

    repository, malware_root = isolated_catalog
    source = (
        "import builtins\n"
        'HANDLER_CONTRACT = {"input_formats": ["data"], "minimum_evidence_score": 1}\n'
        "def extract_config(data):\n"
        '    reader = getattr(builtins, "open")\n'
        '    handle = next(map(reader, ["secret.txt"]))\n'
        '    return {"value": handle.read()}\n'
    )
    spec = _handler_spec(repository, malware_root, "candidate_family", source)

    preflight = catalog.preflight_handler_for_assessment(
        spec,
        actual_format="data",
        input_size=16,
    )

    assert preflight["eligible"] is False
    rendered = "\n".join(preflight["blockers"])
    assert "unresolved_higher_order_call:getattr" in rendered
    assert "unresolved_higher_order_call:map" in rendered
    assert "unverified_reader_capability" in rendered


def test_public_sanitizer_redacts_value_based_credentials_and_private_keys() -> None:
    aws_id = "AKIA" + "A" * 16
    aws_secret = "s" * 40
    slack_token = "xoxb-" + "B" * 30
    jwt = ".".join(("eyJ" + "C" * 16, "D" * 16, "E" * 16))
    private_key = "-----BEGIN PRIVATE KEY-----\n" + "F" * 64 + "\n-----END PRIVATE KEY-----"
    value = {
        "note": (
            f"aws_access_key_id={aws_id} "
            f"aws_secret_access_key={aws_secret} "
            f"token={slack_token} jwt={jwt}\n{private_key}"
        ),
        "AWS_SECRET_ACCESS_KEY": aws_secret,
    }

    rendered = json.dumps(
        catalog.sanitize_public_value(value),
        ensure_ascii=False,
        sort_keys=True,
    )

    for secret in (aws_id, aws_secret, slack_token, jwt, private_key):
        assert secret not in rendered
    assert "[REDACTED" in rendered


def test_public_result_quota_blocks_oversized_and_deep_values(
    isolated_catalog,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, malware_root = isolated_catalog
    spec = _handler_spec(repository, malware_root, "candidate_family", _source("{}"))

    monkeypatch.setattr(catalog, "_invoke_handler", lambda *_args, **_kwargs: list(range(5_000)))
    oversized = catalog.execute_handler(spec, b"input", "sample.bin")
    assert oversized["result_quota"]["truncated"] is True
    assert "maximum_total_entries" in oversized["result_quota"]["reasons"]
    assert len(json.dumps(oversized, ensure_ascii=False)) < 2_000_000

    deep: dict[str, object] = {"leaf": "value"}
    for _index in range(catalog.MAX_DEPTH + 4):
        deep = {"nested": deep}
    monkeypatch.setattr(catalog, "_invoke_handler", lambda *_args, **_kwargs: deep)
    nested = catalog.execute_handler(spec, b"input", "sample.bin")
    assert nested["result_quota"]["truncated"] is True
    assert "maximum_depth" in nested["result_quota"]["reasons"]

    non_finite = catalog.sanitize_public_value(float("nan"))
    assert non_finite == {"truncated": True, "reason": "non_finite_number"}


def test_raw_binary_materialization_requires_exact_terminal_schema() -> None:
    payload = b"MZ" + b"P" * 14
    nested, _nested_audit = catalog._verified_binary_outputs({"terminal_payload": {"nested": {"data": payload}}})
    extra, _extra_audit = catalog._verified_binary_outputs(
        {
            "record": {
                "role": "terminal_payload",
                "data": payload,
                "unexpected": True,
            }
        }
    )
    valid, _valid_audit = catalog._verified_binary_outputs({"record": {"role": "terminal_payload", "data": payload}})

    assert nested == []
    assert extra == []
    assert len(valid) == 1
    assert valid[0]["sha256"] == hashlib.sha256(payload).hexdigest()


def _mock_completed_handler_result() -> dict:
    return {
        "status": "completed",
        "preflight": {"eligible": True, "blockers": []},
        "execution": {
            "result": {},
            "result_quota": {"truncated": False},
            "verified_binary_output_audit": {"observed_output_count": 0},
        },
    }


def _mock_inner_handler_execution() -> dict:
    """subprocessを起動しないcandidate assessment用worker結果を返す。"""

    return {
        "result": {},
        "result_quota": {"truncated": False},
        "verified_binary_output_audit": {"observed_output_count": 0},
    }


def test_assessment_reuses_invariant_preflight_once_per_handler_spec(
    isolated_catalog,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """同一handlerの再帰依存監査は複数layerでもassessment内で1回にする。"""

    repository, malware_root = isolated_catalog
    spec = _handler_spec(
        repository,
        malware_root,
        "candidate_family",
        _source("{}"),
    )
    recursive_audit = catalog._recursive_handler_side_effect_audit
    audit_calls = 0
    worker_calls = 0

    def count_audit(path: Path, callable_name: str) -> dict:
        nonlocal audit_calls
        audit_calls += 1
        return recursive_audit(path, callable_name)

    def worker(*_args, **_kwargs) -> dict:
        nonlocal worker_calls
        worker_calls += 1
        return _mock_inner_handler_execution()

    monkeypatch.setattr(catalog, "_recursive_handler_side_effect_audit", count_audit)
    monkeypatch.setattr(catalog, "_execute_handler_bounded", worker)
    result = catalog.assess_candidate_handlers(
        [_candidate("candidate_family")],
        [
            _layer(b"first candidate layer", "first.bin"),
            _layer(b"second candidate layer", "second.bin"),
        ],
        specs=[spec],
    )

    assert audit_calls == 1
    assert worker_calls == 2
    assert result["actual_attempt_count"] == 2
    planning = result["pair_planning"]
    assert planning["invariant_preflight_cache_scope"] == "assessment_call"
    assert planning["invariant_preflight_evaluation_count"] == 1
    assert planning["invariant_preflight_reuse_count"] == 1
    assert planning["process_invariant_preflight_cache_scope"] == ("process_revalidated_once_per_assessment")
    assert planning["process_invariant_preflight_cache_hit_count"] == 0
    assert planning["process_invariant_preflight_cache_miss_count"] == 1
    assert planning["process_invariant_preflight_cache_revalidation_count"] == 0


def test_process_invariant_cache_revalidates_and_reuses_unchanged_audit(
    isolated_catalog,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """別assessmentでも全依存が同一なら高コスト監査結果を再利用する。"""

    repository, malware_root = isolated_catalog
    spec = _handler_spec(
        repository,
        malware_root,
        "candidate_family",
        _source("{}"),
    )
    recursive_audit = catalog._recursive_handler_side_effect_audit
    audit_calls = 0

    def count_audit(path: Path, callable_name: str) -> dict:
        nonlocal audit_calls
        audit_calls += 1
        return recursive_audit(path, callable_name)

    monkeypatch.setattr(catalog, "_recursive_handler_side_effect_audit", count_audit)
    monkeypatch.setattr(
        catalog,
        "_execute_handler_bounded",
        lambda *_args, **_kwargs: _mock_inner_handler_execution(),
    )
    layer = _layer(b"candidate layer", "candidate.bin")
    first = catalog.assess_candidate_handlers(
        [_candidate("candidate_family")],
        [layer],
        specs=[spec],
    )
    first["families"][0]["attempts"][0]["preflight"]["dependency_audit"]["files"].clear()
    second = catalog.assess_candidate_handlers(
        [_candidate("candidate_family")],
        [layer],
        specs=[spec],
    )

    assert audit_calls == 1
    first_plan = first["pair_planning"]
    second_plan = second["pair_planning"]
    assert first_plan["process_invariant_preflight_cache_hit_count"] == 0
    assert first_plan["process_invariant_preflight_cache_miss_count"] == 1
    assert first_plan["process_invariant_preflight_cache_revalidation_count"] == 0
    assert second_plan["process_invariant_preflight_cache_hit_count"] == 1
    assert second_plan["process_invariant_preflight_cache_miss_count"] == 0
    assert second_plan["process_invariant_preflight_cache_revalidation_count"] == 1
    assert second["families"][0]["attempts"][0]["status"] == "no_evidence"


def test_clear_handler_caches_discards_process_invariant_cache(
    isolated_catalog,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """明示的cache消去後はprocess監査cacheを再利用しない。"""

    repository, malware_root = isolated_catalog
    spec = _handler_spec(
        repository,
        malware_root,
        "candidate_family",
        _source("{}"),
    )
    recursive_audit = catalog._recursive_handler_side_effect_audit
    audit_calls = 0

    def count_audit(path: Path, callable_name: str) -> dict:
        nonlocal audit_calls
        audit_calls += 1
        return recursive_audit(path, callable_name)

    monkeypatch.setattr(catalog, "_recursive_handler_side_effect_audit", count_audit)
    monkeypatch.setattr(
        catalog,
        "_execute_handler_bounded",
        lambda *_args, **_kwargs: _mock_inner_handler_execution(),
    )
    layer = _layer(b"candidate layer", "candidate.bin")
    first = catalog.assess_candidate_handlers(
        [_candidate("candidate_family")],
        [layer],
        specs=[spec],
    )
    catalog.clear_handler_caches()
    second = catalog.assess_candidate_handlers(
        [_candidate("candidate_family")],
        [layer],
        specs=[spec],
    )

    assert audit_calls == 2
    assert first["pair_planning"]["process_invariant_preflight_cache_miss_count"] == 1
    assert second["pair_planning"]["process_invariant_preflight_cache_miss_count"] == 1
    assert second["pair_planning"]["process_invariant_preflight_cache_hit_count"] == 0


def test_process_invariant_cache_does_not_hide_unexpected_value_error(
    isolated_catalog,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """再検証境界の通常ValueErrorをcache missとして隠さない。"""

    repository, malware_root = isolated_catalog
    spec = _handler_spec(
        repository,
        malware_root,
        "candidate_family",
        _source("{}"),
    )
    monkeypatch.setattr(
        catalog,
        "_execute_handler_bounded",
        lambda *_args, **_kwargs: _mock_inner_handler_execution(),
    )
    layer = _layer(b"candidate layer", "candidate.bin")
    catalog.assess_candidate_handlers(
        [_candidate("candidate_family")],
        [layer],
        specs=[spec],
    )

    def fail_revalidation(*_args, **_kwargs) -> None:
        raise ValueError("fixture revalidation failure")

    monkeypatch.setattr(
        catalog,
        "_revalidate_cached_assessment_invariant",
        fail_revalidation,
    )
    with pytest.raises(ValueError, match="fixture revalidation failure"):
        catalog.assess_candidate_handlers(
            [_candidate("candidate_family")],
            [layer],
            specs=[spec],
        )


def test_process_invariant_cache_revalidates_cached_data_manifest(
    isolated_catalog,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """cacheへ結合したdata fileが変わればhitせず監査をやり直す。"""

    repository, malware_root = isolated_catalog
    spec = _handler_spec(
        repository,
        malware_root,
        "candidate_family",
        _source("{}"),
    )
    monkeypatch.setattr(
        catalog,
        "_execute_handler_bounded",
        lambda *_args, **_kwargs: _mock_inner_handler_execution(),
    )
    layer = _layer(b"candidate layer", "candidate.bin")
    catalog.assess_candidate_handlers(
        [_candidate("candidate_family")],
        [layer],
        specs=[spec],
    )
    data_file = repository / "analysis-framework" / "reviewed.json"
    data_file.write_text('{"version":1}', encoding="utf-8")
    cached = catalog._ASSESSMENT_INVARIANT_PREFLIGHT_CACHE[spec]
    audit = json.loads(json.dumps(cached.dependency_audit))
    audit["data_files"] = [
        {
            "path": data_file.relative_to(repository).as_posix(),
            "sha256": hashlib.sha256(data_file.read_bytes()).hexdigest(),
            "reason": "fixture reviewed data",
        }
    ]
    audit["data_files_inspected"] = 1
    catalog._ASSESSMENT_INVARIANT_PREFLIGHT_CACHE[spec] = replace(
        cached,
        dependency_audit=audit,
    )
    data_file.write_text('{"version":2}', encoding="utf-8")

    result = catalog.assess_candidate_handlers(
        [_candidate("candidate_family")],
        [layer],
        specs=[spec],
    )

    planning = result["pair_planning"]
    assert planning["process_invariant_preflight_cache_hit_count"] == 0
    assert planning["process_invariant_preflight_cache_miss_count"] == 1
    assert planning["process_invariant_preflight_cache_revalidation_count"] == 1


def test_process_invariant_cache_revalidates_cached_module_manifest(
    isolated_catalog,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """module bindingがsource snapshotと不整合ならhitせず再監査する。"""

    repository, malware_root = isolated_catalog
    spec = _handler_spec(
        repository,
        malware_root,
        "candidate_family",
        _source("{}"),
    )
    monkeypatch.setattr(
        catalog,
        "_execute_handler_bounded",
        lambda *_args, **_kwargs: _mock_inner_handler_execution(),
    )
    layer = _layer(b"candidate layer", "candidate.bin")
    catalog.assess_candidate_handlers(
        [_candidate("candidate_family")],
        [layer],
        specs=[spec],
    )
    cached = catalog._ASSESSMENT_INVARIANT_PREFLIGHT_CACHE[spec]
    audit = json.loads(json.dumps(cached.dependency_audit))
    audit["module_bindings"] = [
        {
            "name": "fixture_missing_module",
            "path": "analysis-framework/malware/missing.py",
            "is_package": False,
        }
    ]
    audit["module_bindings_inspected"] = 1
    catalog._ASSESSMENT_INVARIANT_PREFLIGHT_CACHE[spec] = replace(
        cached,
        dependency_audit=audit,
    )

    result = catalog.assess_candidate_handlers(
        [_candidate("candidate_family")],
        [layer],
        specs=[spec],
    )

    planning = result["pair_planning"]
    assert planning["process_invariant_preflight_cache_hit_count"] == 0
    assert planning["process_invariant_preflight_cache_miss_count"] == 1
    assert planning["process_invariant_preflight_cache_revalidation_count"] == 1


@pytest.mark.parametrize("invalid_kind", ["blocked", "spec_mismatch"])
def test_process_invariant_cache_hits_only_exact_blocker_free_entries(
    isolated_catalog,
    monkeypatch: pytest.MonkeyPatch,
    invalid_kind: str,
) -> None:
    """blocker付きまたは別specのentryはprocess cache hitにしない。"""

    repository, malware_root = isolated_catalog
    spec = _handler_spec(
        repository,
        malware_root,
        "candidate_family",
        _source("{}"),
    )
    monkeypatch.setattr(
        catalog,
        "_execute_handler_bounded",
        lambda *_args, **_kwargs: _mock_inner_handler_execution(),
    )
    layer = _layer(b"candidate layer", "candidate.bin")
    catalog.assess_candidate_handlers(
        [_candidate("candidate_family")],
        [layer],
        specs=[spec],
    )
    cached = catalog._ASSESSMENT_INVARIANT_PREFLIGHT_CACHE[spec]
    replacement = (
        replace(cached, blockers=("fixture_blocker",))
        if invalid_kind == "blocked"
        else replace(cached, spec=replace(spec, id="candidate_family:other"))
    )
    catalog._ASSESSMENT_INVARIANT_PREFLIGHT_CACHE[spec] = replacement

    result = catalog.assess_candidate_handlers(
        [_candidate("candidate_family")],
        [layer],
        specs=[spec],
    )

    planning = result["pair_planning"]
    assert planning["process_invariant_preflight_cache_hit_count"] == 0
    assert planning["process_invariant_preflight_cache_miss_count"] == 1
    assert planning["process_invariant_preflight_cache_revalidation_count"] == 0


def test_preflight_rejects_root_source_mutation_between_contract_and_audit(
    isolated_catalog,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """契約snapshot後・再帰監査root取得前の差替えをSHA不一致で拒否する。"""

    repository, malware_root = isolated_catalog
    original_source = _source("{}")
    replacement_source = _source("{'marker_hits': ['mutated-between-preflight-snapshots']}")
    spec = _handler_spec(
        repository,
        malware_root,
        "candidate_family",
        original_source,
    )
    source_path = repository / spec.relative_path
    original_sha256 = hashlib.sha256(source_path.read_bytes()).hexdigest()
    original_audit = catalog._recursive_handler_side_effect_audit
    audit_calls = 0
    worker_calls = 0

    def mutate_before_root_audit(path: Path, callable_name: str) -> dict:
        nonlocal audit_calls
        audit_calls += 1
        source_path.write_text(replacement_source, encoding="utf-8")
        return original_audit(path, callable_name)

    def worker(*_args, **_kwargs) -> dict:
        nonlocal worker_calls
        worker_calls += 1
        return _mock_inner_handler_execution()

    monkeypatch.setattr(
        catalog,
        "_recursive_handler_side_effect_audit",
        mutate_before_root_audit,
    )
    monkeypatch.setattr(catalog, "_execute_handler_bounded", worker)
    result = catalog.assess_candidate_handlers(
        [_candidate("candidate_family")],
        [
            _layer(b"first candidate layer", "first.bin"),
            _layer(b"second candidate layer", "second.bin"),
        ],
        specs=[spec],
    )

    assert audit_calls == 1
    assert worker_calls == 0
    attempts = result["families"][0]["attempts"]
    assert [attempt["status"] for attempt in attempts] == [
        "preflight_blocked",
        "preflight_blocked",
    ]
    replacement_sha256 = hashlib.sha256(source_path.read_bytes()).hexdigest()
    for attempt in attempts:
        preflight = attempt["preflight"]
        assert preflight["source_sha256"] == original_sha256
        root_records = [
            record for record in preflight["dependency_audit"]["files"] if record["path"] == spec.relative_path
        ]
        assert root_records == [{"path": spec.relative_path, "sha256": replacement_sha256}]
        assert preflight["blockers"] == ["dependency_source_changed_during_preflight"]


def test_cached_invariant_preflight_keeps_layer_format_and_size_blockers(
    isolated_catalog,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """不変監査を再利用してもformat計画・layer容量制約を省略しない。"""

    repository, malware_root = isolated_catalog
    spec = _handler_spec(
        repository,
        malware_root,
        "candidate_family",
        _source("{}", ("pe",)),
        input_formats=("pe",),
    )
    worker_calls = 0

    def worker(*_args, **_kwargs) -> dict:
        nonlocal worker_calls
        worker_calls += 1
        return _mock_inner_handler_execution()

    monkeypatch.setattr(catalog, "_execute_handler_bounded", worker)
    result = catalog.assess_candidate_handlers(
        [_candidate("candidate_family")],
        [
            _layer(b"plain data", "plain.bin"),
            _layer(b"MZsmall", "small.exe"),
            _layer(b"MZ" + b"L" * 30, "large.exe"),
        ],
        specs=[spec],
        maximum_layer_size=16,
    )

    assert worker_calls == 1
    assert result["considered_pair_count"] == 3
    assert result["planned_attempt_count"] == result["actual_attempt_count"] == 2
    assert result["skipped_pair_count"] == 1
    family = result["families"][0]
    assert family["skipped_pairs"][0]["blockers"] == ["incompatible_input_format:data"]
    assert [attempt["status"] for attempt in family["attempts"]] == [
        "no_evidence",
        "preflight_blocked",
    ]
    assert family["attempts"][0]["preflight"]["input_size"] == len(b"MZsmall")
    assert family["attempts"][1]["preflight"]["blockers"] == ["input_size_limit_exceeded"]
    assert result["pair_planning"]["layer_specific_preflight_checked_per_attempt"] is True


def test_cached_preflight_rejects_source_mutation_before_next_worker(
    isolated_catalog,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """cache後にsourceが変われば、次のworker起動前のmanifest再検証で拒否する。"""

    repository, malware_root = isolated_catalog
    spec = _handler_spec(
        repository,
        malware_root,
        "candidate_family",
        _source("{}"),
    )
    source_path = repository / spec.relative_path
    worker_calls = 0

    def mutate_after_first_snapshot(*_args, **_kwargs) -> dict:
        nonlocal worker_calls
        worker_calls += 1
        source_path.write_text(
            _source("{'marker_hits': ['mutated']}"),
            encoding="utf-8",
        )
        return _mock_inner_handler_execution()

    monkeypatch.setattr(
        catalog,
        "_execute_handler_bounded",
        mutate_after_first_snapshot,
    )
    result = catalog.assess_candidate_handlers(
        [_candidate("candidate_family")],
        [
            _layer(b"first candidate layer", "first.bin"),
            _layer(b"second candidate layer", "second.bin"),
        ],
        specs=[spec],
    )

    assert worker_calls == 1
    assert result["actual_attempt_count"] == 2
    attempts = result["families"][0]["attempts"]
    assert attempts[0]["status"] == "no_evidence"
    assert attempts[1]["status"] == "preflight_blocked"
    assert attempts[1]["preflight"]["eligible"] is False
    assert attempts[1]["preflight"]["blockers"] == ["dependency_source_changed_after_preflight"]
    assert result["pair_planning"]["dependency_manifests_revalidated_before_each_worker"] is True


def test_process_invariant_cache_reaudits_changed_dependency(
    isolated_catalog,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """別assessment前に依存sourceが変わればcacheを破棄して再監査する。"""

    repository, malware_root = isolated_catalog
    family_root = malware_root / "candidate_family"
    family_root.mkdir(parents=True, exist_ok=True)
    helper = family_root / "helper_module.py"
    helper.write_text(
        "def transform(data):\n    return {}\n",
        encoding="utf-8",
    )
    spec = _handler_spec(
        repository,
        malware_root,
        "candidate_family",
        "from helper_module import transform\n"
        'HANDLER_CONTRACT = {"input_formats": ["data"], "minimum_evidence_score": 1}\n'
        "def extract_config(data):\n"
        "    return transform(data)\n",
    )
    worker_calls = 0

    def worker(*_args, **_kwargs) -> dict:
        nonlocal worker_calls
        worker_calls += 1
        return _mock_inner_handler_execution()

    monkeypatch.setattr(catalog, "_execute_handler_bounded", worker)
    layer = _layer(b"candidate layer", "candidate.bin")
    first = catalog.assess_candidate_handlers(
        [_candidate("candidate_family")],
        [layer],
        specs=[spec],
    )
    touched = family_root / "touched.txt"
    helper.write_text(
        "from pathlib import Path\n"
        'Path("touched.txt").write_text("bad", encoding="utf-8")\n'
        "def transform(data):\n"
        "    return {}\n",
        encoding="utf-8",
    )
    second = catalog.assess_candidate_handlers(
        [_candidate("candidate_family")],
        [layer],
        specs=[spec],
    )

    assert first["families"][0]["attempts"][0]["status"] == "no_evidence"
    first_plan = first["pair_planning"]
    assert first_plan["process_invariant_preflight_cache_miss_count"] == 1
    assert first_plan["process_invariant_preflight_cache_revalidation_count"] == 0
    second_attempt = second["families"][0]["attempts"][0]
    assert second_attempt["status"] == "preflight_blocked"
    assert any(blocker.startswith("import_time:") for blocker in second_attempt["preflight"]["blockers"])
    assert worker_calls == 1
    second_plan = second["pair_planning"]
    assert second_plan["process_invariant_preflight_cache_hit_count"] == 0
    assert second_plan["process_invariant_preflight_cache_miss_count"] == 1
    assert second_plan["process_invariant_preflight_cache_revalidation_count"] == 1
    assert not touched.exists()


def test_2048_planned_attempts_stop_at_global_hard_cap(
    isolated_catalog,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, malware_root = isolated_catalog
    base = _handler_spec(
        repository,
        malware_root,
        "candidate_family",
        _source("{}"),
    )
    specs = [
        catalog.HandlerSpec(**{**base.public(), "id": f"candidate_family:fixture:{index:02d}"}) for index in range(32)
    ]
    layers = [_layer(f"layer-{index:02d}".encode(), f"{index:02d}.bin") for index in range(64)]
    monkeypatch.setattr(
        catalog,
        "execute_handler_bounded_for_assessment",
        lambda *_args, **_kwargs: _mock_completed_handler_result(),
    )

    result = catalog.assess_candidate_handlers(
        [_candidate("candidate_family")],
        layers,
        specs=specs,
    )

    assert result["considered_pair_count"] == 2_048
    assert result["planned_attempt_count"] == 2_048
    assert result["actual_attempt_count"] == catalog.MAX_ASSESSMENT_ATTEMPTS == 96
    assert result["skipped_pair_count"] == 0
    assert result["unattempted_attempt_count"] == 1_952
    assert result["status"] == "partial"
    assert result["blockers"] == ["maximum_attempts_exhausted"]
    assert result["pair_planning"]["compatible_pair_count"] == 2_048
    assert result["pair_planning"]["incompatible_pairs_consume_execution_quota"] is False


def test_77_planned_attempts_complete_with_96_attempt_contract(
    isolated_catalog,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """実corpusで観測した77試行を明細省略なしで完走できる。"""

    repository, malware_root = isolated_catalog
    spec = _handler_spec(
        repository,
        malware_root,
        "candidate_family",
        _source("{}"),
    )
    layers = [_layer(f"layer-{index:02d}".encode(), f"{index:02d}.bin") for index in range(77)]
    monkeypatch.setattr(
        catalog,
        "execute_handler_bounded_for_assessment",
        lambda *_args, **_kwargs: _mock_completed_handler_result(),
    )

    result = catalog.assess_candidate_handlers(
        [_candidate("candidate_family")],
        layers,
        specs=[spec],
    )

    assert catalog.MAX_ASSESSMENT_ATTEMPTS == 96
    assert catalog.MAX_ASSESSMENT_RETAINED_ATTEMPT_DETAILS == 96
    assert result["status"] == "no_confirmed_family"
    assert result["planned_attempt_count"] == 77
    assert result["actual_attempt_count"] == 77
    assert result["retained_attempt_detail_count"] == 77
    assert result["omitted_attempt_detail_count"] == 0
    assert result["unattempted_attempt_count"] == 0
    assert result["blockers"] == []
    assert result["budget"]["exhausted"] is False


def test_assessment_attempt_and_detail_limits_reject_values_above_96(
    isolated_catalog,
) -> None:
    """拡張後もcallerがhard capを超えて試行数を解除できない。"""

    repository, malware_root = isolated_catalog
    spec = _handler_spec(
        repository,
        malware_root,
        "candidate_family",
        _source("{}"),
    )
    candidates = [_candidate("candidate_family")]
    layers = [_layer(b"candidate layer", "candidate.bin")]

    with pytest.raises(ValueError, match="maximum_attemptsが不正"):
        catalog.assess_candidate_handlers(
            candidates,
            layers,
            specs=[spec],
            maximum_attempts=97,
        )
    with pytest.raises(ValueError, match="maximum_retained_attempt_details is invalid"):
        catalog.assess_candidate_handlers(
            candidates,
            layers,
            specs=[spec],
            maximum_retained_attempt_details=97,
        )


def test_candidate_execution_preserves_router_rank_before_global_quota(
    isolated_catalog,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """alphabet順の低順位familyが高順位ValleyRATの試行枠を奪わない。"""

    repository, malware_root = isolated_catalog
    low = _handler_spec(repository, malware_root, "asyncrat", _source("{}"))
    high = _handler_spec(repository, malware_root, "valleyrat", _source("{}"))
    called: list[str] = []

    def execute(spec, *_args, **_kwargs):
        called.append(spec.family)
        return _mock_completed_handler_result()

    monkeypatch.setattr(catalog, "execute_handler_bounded_for_assessment", execute)
    low_candidate = {**_candidate("asyncrat"), "rank": 2, "rank_score": 101}
    high_candidate = {**_candidate("valleyrat"), "rank": 1, "rank_score": 441}

    result = catalog.assess_candidate_handlers(
        [low_candidate, high_candidate],
        [_layer(b"one-layer", "one.bin")],
        specs=[low, high],
        maximum_attempts=1,
    )

    assert called == ["valleyrat"]
    assert [item["family"] for item in result["families"]] == [
        "valleyrat",
        "asyncrat",
    ]
    assert result["families"][0]["rank"] == 1
    assert result["families"][1]["rank"] == 2


def test_only_executable_candidate_keeps_router_rank_above_assessment_count_limit(
    isolated_catalog,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """全体rankが64超でも、絞り込み後の唯一候補を評価できる。"""

    repository, malware_root = isolated_catalog
    spec = _handler_spec(repository, malware_root, "valleyrat", _source("{}"))
    called: list[str] = []

    def execute(handler, *_args, **_kwargs):
        called.append(handler.family)
        return _mock_completed_handler_result()

    monkeypatch.setattr(catalog, "execute_handler_bounded_for_assessment", execute)
    candidate = {**_candidate("valleyrat"), "rank": 100, "rank_score": 10}
    result = catalog.assess_candidate_handlers(
        [candidate],
        [_layer(b"one-layer", "one.bin")],
        specs=[spec],
        maximum_attempts=1,
    )

    assert called == ["valleyrat"]
    assert result["families"][0]["rank"] == 100


def test_assessor_accepts_full_bounded_router_candidate_set() -> None:
    """routerと同じ128候補を受理し、129件目はfail closedにする。"""

    candidates = [{**_candidate(f"candidate_{index:03d}"), "rank": index + 1} for index in range(128)]

    assert len(catalog._candidate_records(candidates)) == 128
    with pytest.raises(ValueError, match="候補family数が不正"):
        catalog._candidate_records([*candidates, {**_candidate("candidate_128"), "rank": 128}])


def test_candidate_handlers_are_round_robin_before_global_attempt_limit(
    isolated_catalog,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """共有extractorが96枠を独占せず、campaignにも各roundで枠を渡す。"""

    repository, malware_root = isolated_catalog
    base = _handler_spec(repository, malware_root, "valleyrat", _source("{}"))
    shared = replace(base, id="valleyrat:shared", source="shared_extractor", campaign=None)
    campaign = replace(base, id="valleyrat:campaign", campaign="fixture")
    layers = [_layer(f"layer-{index:02d}".encode(), f"{index:02d}.bin") for index in range(64)]
    calls: list[str] = []

    def execute(handler, *_args, **_kwargs):
        calls.append(handler.id)
        return _mock_completed_handler_result()

    monkeypatch.setattr(catalog, "execute_handler_bounded_for_assessment", execute)
    result = catalog.assess_candidate_handlers(
        [_candidate("valleyrat")],
        layers,
        specs=[campaign, shared],
    )

    assert calls == [shared.id, campaign.id] * 48
    assert result["actual_attempt_count"] == catalog.MAX_ASSESSMENT_ATTEMPTS
    assert result["unattempted_attempt_count"] == 32
    assert result["pair_planning"]["execution_order"] == ("candidate_rank_then_handler_round_robin")
    assert result["pair_planning"]["each_handler_first_attempt_before_second"] is True


def test_candidate_round_robin_spans_ranked_families(
    isolated_catalog,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """高順位familyの第2試行より、低順位family handlerの初回を先に行う。"""

    repository, malware_root = isolated_catalog
    high = _handler_spec(repository, malware_root, "valleyrat", _source("{}"))
    low = _handler_spec(repository, malware_root, "asyncrat", _source("{}"))
    layers = [_layer(b"layer-zero", "zero.bin"), _layer(b"layer-one", "one.bin")]
    calls: list[str] = []

    def execute(handler, *_args, **_kwargs):
        calls.append(handler.family)
        return _mock_completed_handler_result()

    monkeypatch.setattr(catalog, "execute_handler_bounded_for_assessment", execute)
    result = catalog.assess_candidate_handlers(
        [
            {**_candidate("asyncrat"), "rank": 2},
            {**_candidate("valleyrat"), "rank": 1},
        ],
        layers,
        specs=[low, high],
        maximum_attempts=2,
    )

    assert calls == ["valleyrat", "asyncrat"]
    assert result["actual_attempt_count"] == 2
    assert result["unattempted_attempt_count"] == 2


def test_attempt_detail_and_verified_output_budgets_return_partial(
    isolated_catalog,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, malware_root = isolated_catalog
    spec = _handler_spec(repository, malware_root, "candidate_family", _source("{}"))
    layers = [_layer(f"layer-{index}".encode(), f"{index}.bin") for index in range(10)]
    monkeypatch.setattr(
        catalog,
        "execute_handler_bounded_for_assessment",
        lambda *_args, **_kwargs: _mock_completed_handler_result(),
    )

    details = catalog.assess_candidate_handlers(
        [_candidate("candidate_family")],
        layers,
        specs=[spec],
        maximum_retained_attempt_details=4,
    )
    assert details["status"] == "partial"
    assert details["actual_attempt_count"] == 5
    assert details["retained_attempt_detail_count"] == 4
    assert details["omitted_attempt_detail_count"] == 1
    assert details["blockers"] == ["maximum_retained_attempt_details_exhausted"]

    oversized_output = _mock_completed_handler_result()
    oversized_output["execution"]["verified_binary_output_audit"] = {
        "observed_output_count": catalog.MAX_ASSESSMENT_VERIFIED_OUTPUTS + 1
    }
    monkeypatch.setattr(
        catalog,
        "execute_handler_bounded_for_assessment",
        lambda *_args, **_kwargs: oversized_output,
    )
    outputs = catalog.assess_candidate_handlers(
        [_candidate("candidate_family")],
        layers[:1],
        specs=[spec],
    )
    assert outputs["status"] == "partial"
    assert outputs["blockers"] == ["maximum_verified_outputs_exhausted"]


@pytest.mark.parametrize(
    "raw",
    [
        b'{"ok":true,"ok":false}',
        b'{"value":NaN}',
        b'{"value":Infinity}',
        b'{"value":1e9999}',
    ],
    ids=["duplicate_key", "nan", "infinity", "overflow_float"],
)
def test_strict_json_loader_rejects_ambiguous_or_nonfinite_values(raw: bytes) -> None:
    with pytest.raises(catalog.HandlerLoadError, match="invalid JSON"):
        catalog._strict_json_loads(raw, description="fixture")


def test_regular_file_snapshot_rejects_hardlinks(tmp_path: Path) -> None:
    original = tmp_path / "original.json"
    linked = tmp_path / "linked.json"
    original.write_bytes(b"{}")
    try:
        os.link(original, linked)
    except OSError as exc:
        pytest.skip(f"hardlinkを作成できない環境です: {exc}")

    with pytest.raises(catalog.HandlerLoadError, match="single-link"):
        catalog._regular_file_snapshot(
            linked,
            maximum_size=1024,
            description="fixture",
        )


def test_bounded_worker_requires_process_and_memory_containment(
    isolated_catalog,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, malware_root = isolated_catalog
    spec = _handler_spec(repository, malware_root, "candidate_family", _source("{}"))
    captured: dict = {}

    def fake_run(command, **kwargs):
        captured.update(kwargs)
        Path(command[-1]).write_text(
            json.dumps({"ok": True, "result": {}}),
            encoding="utf-8",
        )
        return types.SimpleNamespace(returncode=0)

    monkeypatch.setattr(bounded_process, "run_bounded", fake_run)
    result = catalog._execute_handler_bounded(
        spec,
        b"input",
        "sample.bin",
        timeout_seconds=1.0,
        dependency_source_manifest=[],
        dependency_data_manifest=[],
        dependency_module_manifest=[],
    )

    assert result["verified_binary_outputs"] == []
    assert captured["require_containment"] is True
    assert captured["maximum_active_processes"] == 1
    assert captured["maximum_memory_bytes"] == bounded_process.DEFAULT_CONTAINED_MEMORY_BYTES
    temporary_paths = {Path(captured["env"][name]) for name in ("TEMP", "TMP", "TMPDIR")}
    assert len(temporary_paths) == 1
    child_temp = temporary_paths.pop()
    assert child_temp.name == "worker-temp"
    assert not child_temp.exists()


def test_windows_family_profile_data_is_read_from_verified_snapshot(
    isolated_catalog,
) -> None:
    repository, _malware_root = isolated_catalog
    profile = repository / "extractors" / "profiles" / "windows_family_profiles.json"
    profile.parent.mkdir(parents=True)
    original = '{"safe":true}\n'
    replacement = '{"evil":true}\n'
    assert len(original.encode()) == len(replacement.encode())
    profile.write_bytes(original.encode())
    metadata = profile.stat()
    relative = profile.relative_to(repository).as_posix()
    manifest = [
        {
            "path": relative,
            "sha256": hashlib.sha256(original.encode()).hexdigest(),
            "reason": "fixture profile snapshot",
        }
    ]
    snapshots = catalog._validated_dependency_data_snapshots(
        manifest,
        repository=repository,
    )
    profile.write_bytes(replacement.encode())
    os.utime(profile, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
    external = repository / "external.json"
    external.write_text('{"secret":true}', encoding="utf-8")

    with catalog._verified_data_read_environment(snapshots):
        assert profile.read_text(encoding="utf-8") == original
        with pytest.raises(catalog.HandlerLoadError, match="absent"):
            external.read_text(encoding="utf-8")


def test_preloaded_same_name_module_cannot_override_verified_snapshot(
    isolated_catalog,
) -> None:
    repository, malware_root = isolated_catalog
    family_root = malware_root / "candidate_family"
    family_root.mkdir(parents=True, exist_ok=True)
    helper = family_root / "helper_module.py"
    helper.write_text(
        "def transform(data):\n    return {'marker_hits': ['verified-helper']}\n",
        encoding="utf-8",
    )
    spec = _handler_spec(
        repository,
        malware_root,
        "candidate_family",
        "from helper_module import transform\n"
        'HANDLER_CONTRACT = {"input_formats": ["data"], "minimum_evidence_score": 1}\n'
        "def extract_config(data):\n"
        "    return transform(data)\n",
    )
    preflight = catalog.preflight_handler_for_assessment(
        spec,
        actual_format="data",
        input_size=7,
    )
    poisoned = types.ModuleType("helper_module")
    poisoned.transform = lambda _data: {"marker_hits": ["poisoned-module"]}
    previous = sys.modules.get("helper_module")
    sys.modules["helper_module"] = poisoned
    try:
        result = catalog._invoke_handler_from_verified_snapshots(
            spec,
            b"payload",
            "payload.bin",
            preflight["dependency_audit"]["files"],
            preflight["dependency_audit"]["data_files"],
            preflight["dependency_audit"]["module_bindings"],
        )
        assert result == {"marker_hits": ["verified-helper"]}
        assert sys.modules["helper_module"] is poisoned
    finally:
        if previous is None:
            sys.modules.pop("helper_module", None)
        else:
            sys.modules["helper_module"] = previous


def test_same_name_site_module_is_not_fallback_after_snapshot(
    isolated_catalog,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repository, malware_root = isolated_catalog
    family_root = malware_root / "candidate_family"
    family_root.mkdir(parents=True, exist_ok=True)
    helper = family_root / "helper_module.py"
    helper.write_text(
        "def transform(data):\n    return {'marker_hits': ['verified-helper']}\n",
        encoding="utf-8",
    )
    site = tmp_path / "site-packages"
    site.mkdir()
    (site / "helper_module.py").write_text(
        "def transform(data):\n    return {'marker_hits': ['site-fallback']}\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(site))
    spec = _handler_spec(
        repository,
        malware_root,
        "candidate_family",
        "from helper_module import transform\n"
        'HANDLER_CONTRACT = {"input_formats": ["data"], "minimum_evidence_score": 1}\n'
        "def extract_config(data):\n"
        "    return transform(data)\n",
    )
    preflight = catalog.preflight_handler_for_assessment(
        spec,
        actual_format="data",
        input_size=7,
    )
    original = catalog._validated_dependency_source_snapshots

    def snapshot_then_delete(value, *, repository):
        snapshots = original(value, repository=repository)
        helper.unlink()
        return snapshots

    monkeypatch.setattr(
        catalog,
        "_validated_dependency_source_snapshots",
        snapshot_then_delete,
    )
    result = catalog._invoke_handler_from_verified_snapshots(
        spec,
        b"payload",
        "payload.bin",
        preflight["dependency_audit"]["files"],
        preflight["dependency_audit"]["data_files"],
        preflight["dependency_audit"]["module_bindings"],
    )

    assert result == {"marker_hits": ["verified-helper"]}


def test_verified_package_and_submodule_bindings_load_from_snapshots(
    isolated_catalog,
) -> None:
    repository, malware_root = isolated_catalog
    family_root = malware_root / "candidate_family"
    package = family_root / "verified_pkg"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text(
        'PACKAGE_MARKER = "verified-package"\n',
        encoding="utf-8",
    )
    (package / "helper.py").write_text(
        'from verified_pkg import PACKAGE_MARKER\ndef transform(data):\n    return {"marker_hits": [PACKAGE_MARKER]}\n',
        encoding="utf-8",
    )
    spec = _handler_spec(
        repository,
        malware_root,
        "candidate_family",
        "from verified_pkg.helper import transform\n"
        'HANDLER_CONTRACT = {"input_formats": ["data"], "minimum_evidence_score": 1}\n'
        "def extract_config(data):\n"
        "    return transform(data)\n",
    )
    preflight = catalog.preflight_handler_for_assessment(
        spec,
        actual_format="data",
        input_size=7,
    )

    assert preflight["eligible"] is True
    assert {item["name"] for item in preflight["dependency_audit"]["module_bindings"]} >= {
        "verified_pkg",
        "verified_pkg.helper",
    }
    result = catalog._invoke_handler_from_verified_snapshots(
        spec,
        b"payload",
        "payload.bin",
        preflight["dependency_audit"]["files"],
        preflight["dependency_audit"]["data_files"],
        preflight["dependency_audit"]["module_bindings"],
    )
    assert result == {"marker_hits": ["verified-package"]}


def test_dynamic_file_loader_uses_snapshot_after_live_replacement(
    isolated_catalog,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, malware_root = isolated_catalog
    family_root = malware_root / "candidate_family"
    family_root.mkdir(parents=True, exist_ok=True)
    helper = family_root / "dynamic_helper.py"
    helper.write_text(
        "def transform(data):\n    return {'marker_hits': ['verified-dynamic']}\n",
        encoding="utf-8",
    )
    spec = _handler_spec(
        repository,
        malware_root,
        "candidate_family",
        "import importlib.util\n"
        "from pathlib import Path\n"
        '_path = Path(__file__).resolve().parent / "dynamic_helper.py"\n'
        '_spec = importlib.util.spec_from_file_location("dynamic_fixture", _path)\n'
        "assert _spec and _spec.loader\n"
        "_module = importlib.util.module_from_spec(_spec)\n"
        "_spec.loader.exec_module(_module)\n"
        'HANDLER_CONTRACT = {"input_formats": ["data"], "minimum_evidence_score": 1}\n'
        "def extract_config(data):\n"
        "    return _module.transform(data)\n",
    )
    source_paths = [repository / spec.relative_path, helper]
    manifest = [
        {
            "path": path.relative_to(repository).as_posix(),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
        for path in sorted(source_paths, key=lambda item: item.relative_to(repository).as_posix())
    ]
    original = catalog._validated_dependency_source_snapshots

    def snapshot_then_replace(value, *, repository):
        snapshots = original(value, repository=repository)
        helper.write_text(
            "def transform(data):\n    return {'marker_hits': ['mutated-dynamic']}\n",
            encoding="utf-8",
        )
        return snapshots

    monkeypatch.setattr(
        catalog,
        "_validated_dependency_source_snapshots",
        snapshot_then_replace,
    )
    result = catalog._invoke_handler_from_verified_snapshots(
        spec,
        b"payload",
        "payload.bin",
        manifest,
        [],
        [],
    )

    assert result == {"marker_hits": ["verified-dynamic"]}


def test_repository_reparse_import_is_rejected_before_snapshot(
    isolated_catalog,
    tmp_path: Path,
) -> None:
    repository, malware_root = isolated_catalog
    outside = tmp_path / "outside-package"
    outside.mkdir()
    (outside / "__init__.py").write_text("", encoding="utf-8")
    (outside / "helper.py").write_text(
        "def transform(data):\n    return {}\n",
        encoding="utf-8",
    )
    family_root = malware_root / "candidate_family"
    family_root.mkdir(parents=True, exist_ok=True)
    linked = family_root / "linked_pkg"
    try:
        os.symlink(outside, linked, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory reparse pointを作成できない環境です: {exc}")
    spec = _handler_spec(
        repository,
        malware_root,
        "candidate_family",
        "from linked_pkg.helper import transform\n"
        'HANDLER_CONTRACT = {"input_formats": ["data"], "minimum_evidence_score": 1}\n'
        "def extract_config(data):\n"
        "    return transform(data)\n",
    )

    preflight = catalog.preflight_handler_for_assessment(
        spec,
        actual_format="data",
        input_size=7,
    )

    assert preflight["eligible"] is False
    assert any("unsafe_local_import" in item for item in preflight["blockers"])


@pytest.mark.parametrize(
    "source",
    [
        (
            "import builtins\n"
            'HANDLER_CONTRACT = {"input_formats": ["data"], "minimum_evidence_score": 1}\n'
            "def extract_config(data):\n"
            '    return {"value": vars(builtins)["open"]("secret.txt").read()}\n'
        ),
        (
            "import builtins\n"
            'HANDLER_CONTRACT = {"input_formats": ["data"], "minimum_evidence_score": 1}\n'
            "def extract_config(data):\n"
            '    return {"value": builtins.__dict__["open"]("secret.txt").read()}\n'
        ),
        (
            "import functools\n"
            'HANDLER_CONTRACT = {"input_formats": ["data"], "minimum_evidence_score": 1}\n'
            "def extract_config(data):\n"
            '    callback = functools.partial(open, "secret.txt")\n'
            '    return {"value": callback().read()}\n'
        ),
        (
            "import operator\n"
            "from pathlib import Path\n"
            'HANDLER_CONTRACT = {"input_formats": ["data"], "minimum_evidence_score": 1}\n'
            "def extract_config(data):\n"
            '    callback = operator.methodcaller("read_text")\n'
            '    return {"value": callback(Path("secret.txt"))}\n'
        ),
    ],
    ids=["vars-builtins", "builtins-dict", "partial-open", "methodcaller-reader"],
)
def test_ast_audit_blocks_indirect_capability_construction(
    isolated_catalog,
    source: str,
) -> None:
    repository, malware_root = isolated_catalog
    spec = _handler_spec(repository, malware_root, "candidate_family", source)

    preflight = catalog.preflight_handler_for_assessment(
        spec,
        actual_format="data",
        input_size=16,
    )

    assert preflight["eligible"] is False
    assert preflight["blockers"]


@pytest.mark.parametrize(
    "source",
    [
        (
            "from pathlib import Path\n"
            "def len(value):\n"
            '    return Path(value).read_text(encoding="utf-8")\n'
            'HANDLER_CONTRACT = {"input_formats": ["data"], "minimum_evidence_score": 1}\n'
            "def extract_config(data):\n"
            '    return {"value": list(map(len, ["secret.txt"]))}\n'
        ),
        (
            "import re\n"
            "re.search = open\n"
            'HANDLER_CONTRACT = {"input_formats": ["data"], "minimum_evidence_score": 1}\n'
            "def extract_config(data):\n"
            '    return {"value": bool(re.search("secret.txt"))}\n'
        ),
        (
            "from re import search\n"
            "search = open\n"
            'HANDLER_CONTRACT = {"input_formats": ["data"], "minimum_evidence_score": 1}\n'
            "def extract_config(data):\n"
            '    return {"value": bool(search("secret.txt"))}\n'
        ),
    ],
    ids=["shadowed-builtin-callback", "mutated-module-alias", "mutated-import-symbol"],
)
def test_ast_audit_blocks_shadowed_or_mutated_safe_names(
    isolated_catalog,
    source: str,
) -> None:
    repository, malware_root = isolated_catalog
    spec = _handler_spec(repository, malware_root, "candidate_family", source)

    preflight = catalog.preflight_handler_for_assessment(
        spec,
        actual_format="data",
        input_size=16,
    )

    assert preflight["eligible"] is False
    assert preflight["blockers"]


@pytest.mark.parametrize(
    "source",
    [
        (
            'HANDLER_CONTRACT = {"input_formats": ["data"], "minimum_evidence_score": 1}\n'
            "def extract_config(data):\n"
            "    def nested():\n"
            '        return open("secret.txt").read()\n'
            '    return {"value": nested()}\n'
        ),
        (
            'HANDLER_CONTRACT = {"input_formats": ["data"], "minimum_evidence_score": 1}\n'
            "def extract_config(data):\n"
            "    class Nested:\n"
            '        leaked = open("secret.txt").read()\n'
            "    return {}\n"
        ),
        (
            "from pathlib import Path\n"
            "def decorator(function):\n"
            '    Path("marker.txt").write_text("x", encoding="utf-8")\n'
            "    return function\n"
            "@decorator\n"
            "def extract_config(data):\n"
            "    return {}\n"
            'HANDLER_CONTRACT = {"input_formats": ["data"], "minimum_evidence_score": 1}\n'
        ),
        (
            'HANDLER_CONTRACT = {"input_formats": ["data"], "minimum_evidence_score": 1}\n'
            'def extract_config(data=open("secret.txt").read()):\n'
            "    return {}\n"
        ),
        (
            'HANDLER_CONTRACT = {"input_formats": ["data"], "minimum_evidence_score": 1}\n'
            'def extract_config(data: open("secret.txt").read()):\n'
            "    return {}\n"
        ),
    ],
    ids=["nested-function", "nested-class-body", "local-decorator", "default-value", "annotation"],
)
def test_ast_audit_blocks_nested_and_definition_time_side_effects(
    isolated_catalog,
    source: str,
) -> None:
    repository, malware_root = isolated_catalog
    spec = _handler_spec(repository, malware_root, "candidate_family", source)

    preflight = catalog.preflight_handler_for_assessment(
        spec,
        actual_format="data",
        input_size=16,
    )

    assert preflight["eligible"] is False
    assert preflight["blockers"]


@pytest.mark.parametrize(
    "source",
    [
        (
            "from pathlib import Path\n"
            "class Evil:\n"
            "    def get(self):\n"
            '        return Path("secret.txt").read_text(encoding="utf-8")\n' + _source('{"value": Evil().get()}')
        ),
        (
            "class Evil:\n"
            "    def openstream(self, name):\n"
            "        return open(name)\n" + _source('{"value": Evil().openstream("secret.txt").read()}')
        ),
        (
            "class Evil:\n"
            "    def __iter__(self):\n"
            '        return iter(open("secret.txt"))\n' + _source('{"value": list(Evil())}')
        ),
        (
            "class Evil:\n"
            "    def __getattribute__(self, name):\n"
            '        return open("secret.txt").read\n' + _source('{"value": hasattr(Evil(), "value")}')
        ),
        (
            'HANDLER_CONTRACT = {"input_formats": ["data"], "minimum_evidence_score": 1}\n'
            "def extract_config(data):\n"
            "    callback = type.__subclasses__\n"
            '    return {"value": list(map(callback, [object]))}\n'
        ),
    ],
    ids=["local-get", "fake-openstream", "iter-protocol", "getattribute-protocol", "dunder-laundering"],
)
def test_ast_audit_blocks_local_object_and_reflection_capabilities(
    isolated_catalog,
    source: str,
) -> None:
    repository, malware_root = isolated_catalog
    spec = _handler_spec(repository, malware_root, "candidate_family", source)

    preflight = catalog.preflight_handler_for_assessment(
        spec,
        actual_format="data",
        input_size=16,
    )

    assert preflight["eligible"] is False
    assert preflight["blockers"]


def test_ast_audit_allows_safe_local_callback(isolated_catalog) -> None:
    repository, malware_root = isolated_catalog
    source = (
        "def normalize(value):\n"
        "    return str(value)\n"
        'HANDLER_CONTRACT = {"input_formats": ["data"], "minimum_evidence_score": 1}\n'
        "def extract_config(data):\n"
        '    return {"values": list(map(normalize, [1, 2]))}\n'
    )
    spec = _handler_spec(repository, malware_root, "candidate_family", source)

    preflight = catalog.preflight_handler_for_assessment(
        spec,
        actual_format="data",
        input_size=16,
    )

    assert preflight["eligible"] is True
    assert preflight["blockers"] == []


def test_capstone_constructor_allowlist_does_not_allow_unknown_calls(
    isolated_catalog,
) -> None:
    """許可したCs constructorからCapstone全APIへ許可を拡張しない。"""

    repository, malware_root = isolated_catalog
    source = (
        "from capstone import Cs\n"
        'HANDLER_CONTRACT = {"input_formats": ["data"], '
        '"minimum_evidence_score": 1}\n'
        "def extract_config(data):\n"
        '    return {"value": Cs.unknown_operation(data)}\n'
    )
    spec = _handler_spec(repository, malware_root, "candidate_family", source)

    preflight = catalog.preflight_handler_for_assessment(
        spec,
        actual_format="data",
        input_size=16,
    )

    assert preflight["eligible"] is False
    assert any("unapproved_external_call:capstone.Cs.unknown_operation" in blocker for blocker in preflight["blockers"])


@pytest.mark.parametrize(
    ("imports", "expression", "expected_blocker"),
    [
        ("import subprocess\n", "subprocess.run([])", "forbidden_call:subprocess.run"),
        ("import socket\n", "socket.socket()", "forbidden_call:socket.socket"),
        ("import requests\n", "requests.get('x')", "forbidden_call:requests.get"),
        ("", "eval('1 + 1')", "forbidden_call:eval"),
        ("", "exec('value = 1')", "forbidden_call:exec"),
        ("", "open('secret.txt')", "forbidden_call:open"),
        (
            "from pathlib import Path\n",
            "Path('result.txt').write_text('x')",
            "forbidden_side_effect_method:",
        ),
    ],
    ids=["subprocess", "socket", "requests", "eval", "exec", "open", "write"],
)
def test_static_lineage_source_allowlist_does_not_relax_dangerous_calls(
    isolated_catalog,
    imports: str,
    expression: str,
    expected_blocker: str,
) -> None:
    """静的decode用の局所許可後も外部副作用capabilityを拒否する。"""

    repository, malware_root = isolated_catalog
    source = (
        imports
        + 'HANDLER_CONTRACT = {"input_formats": ["data"], "minimum_evidence_score": 1}\n'
        + "def extract_config(data):\n"
        + f"    {expression}\n"
        + "    return {}\n"
    )
    spec = _handler_spec(repository, malware_root, "candidate_family", source)

    preflight = catalog.preflight_handler_for_assessment(
        spec,
        actual_format="data",
        input_size=16,
    )

    assert preflight["eligible"] is False
    assert any(expected_blocker in blocker for blocker in preflight["blockers"])


def test_static_lineage_source_allowlist_rejects_lookalike_module(
    isolated_catalog,
) -> None:
    """同じqueue/call名でもreview済みpath以外へ局所許可を転用しない。"""

    repository, malware_root = isolated_catalog
    source = (
        "import collections\n"
        "def _decode_function(data):\n"
        "    pending = collections.deque([data])\n"
        "    return pending.popleft()\n"
        'HANDLER_CONTRACT = {"input_formats": ["data"], "minimum_evidence_score": 1}\n'
        "def extract_config(data):\n"
        "    return {'value': _decode_function(data)}\n"
    )
    spec = _handler_spec(repository, malware_root, "candidate_family", source)

    preflight = catalog.preflight_handler_for_assessment(
        spec,
        actual_format="data",
        input_size=16,
    )

    assert preflight["eligible"] is False
    assert any("unapproved_external_call:collections.deque" in blocker for blocker in preflight["blockers"])
    assert any("unapproved_object_method:pending.popleft" in blocker for blocker in preflight["blockers"])


@pytest.mark.parametrize(
    ("source", "call_name", "expected_blocker"),
    [
        (
            "def extract_config(data):\n    return {'value': getattr(data, '__globals__', None)}\n",
            "getattr",
            "reviewed_source_call_shape_rejected:getattr",
        ),
        (
            "def extract_config(data):\n    archive = data\n    return {'value': archive.read(1)}\n",
            "archive.read",
            "reviewed_source_call_shape_rejected:archive.read",
        ),
        (
            "import os\ndef extract_config(data):\n    os.remove('x')\n    return {}\n",
            "os.remove",
            "forbidden_call:os.remove",
        ),
    ],
    ids=["dangerous-getattr", "unverified-read", "forbidden-side-effect"],
)
def test_reviewed_source_call_still_enforces_shape_and_forbidden_checks(
    isolated_catalog,
    monkeypatch: pytest.MonkeyPatch,
    source: str,
    call_name: str,
    expected_blocker: str,
) -> None:
    """source限定許可は危険な引数・receiver・副作用を上書きしない。"""

    repository, malware_root = isolated_catalog
    contract = 'HANDLER_CONTRACT = {"input_formats": ["data"], "minimum_evidence_score": 1}\n'
    spec = _handler_spec(
        repository,
        malware_root,
        "candidate_family",
        contract + source,
    )
    key = (spec.relative_path, "reachable:extract_config", call_name)
    monkeypatch.setattr(
        catalog,
        "_REVIEWED_SOURCE_CALLS",
        {**catalog._REVIEWED_SOURCE_CALLS, key: "test-only reviewed call"},
    )
    catalog.clear_handler_caches()
    try:
        preflight = catalog.preflight_handler_for_assessment(
            spec,
            actual_format="data",
            input_size=16,
        )
    finally:
        catalog.clear_handler_caches()

    assert preflight["eligible"] is False
    assert any(expected_blocker in blocker for blocker in preflight["blockers"])


def _reviewed_shape_result(
    source: str,
    key: tuple[str, str, str],
) -> bool:
    tree = ast.parse(source)
    function_name = key[1].removeprefix("reachable:")
    scope = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == function_name
    )
    call = next(
        node
        for node in ast.walk(scope)
        if isinstance(node, ast.Call) and catalog._ast_call_name(node.func) == key[2]
    )
    return catalog._reviewed_source_call_shape_allowed(
        call,
        key[2],
        tree,
        scope,
        catalog._import_aliases(tree),
        key=key,
    )


@pytest.mark.parametrize(
    ("archive_expression", "member_expression", "mode", "expected"),
    (
        ("zipfile.ZipFile(io.BytesIO(data))", "member", '"r"', True),
        ("data", "member", '"r"', False),
        ("zipfile.ZipFile(io.BytesIO(data))", '"outside"', '"r"', False),
        ("zipfile.ZipFile(io.BytesIO(data))", "member", '"w"', False),
    ),
    ids=("bounded", "rebound-archive", "unlisted-member", "write-mode"),
)
def test_acr_zip_member_open_review_requires_bytes_origin_and_read_mode(
    archive_expression: str,
    member_expression: str,
    mode: str,
    expected: bool,
) -> None:
    """ZIP open例外をpathやwrite modeへ差し替えられない。"""

    source = (
        "import io\nimport zipfile\n"
        "def _recover_pumped_zip(data):\n"
        f"    archive = {archive_expression}\n"
        "    members = archive.infolist()\n"
        "    for member in members:\n"
        f"        with archive.open({member_expression}, {mode}) as stream:\n"
        "            return stream.read(32 * 1024 * 1024)\n"
    )
    key = (
        "extractors/acrstealer/extractor.py",
        "reachable:_recover_pumped_zip",
        "archive.open",
    )

    assert _reviewed_shape_result(source, key) is expected


@pytest.mark.parametrize(
    ("candidate_expression", "mode", "expected"),
    (
        ("root / relative_path", '"rb"', True),
        ('Path("outside.json")', '"rb"', False),
        ("root / relative_path", '"wb"', False),
    ),
    ids=("bounded", "outside-path", "write-mode"),
)
def test_remus_json_open_review_requires_repository_relative_candidate(
    candidate_expression: str,
    mode: str,
    expected: bool,
) -> None:
    """JSON open例外をrepository外pathやwrite modeへ差し替えられない。"""

    source = (
        "import os\nfrom pathlib import Path\n"
        "def _read_bounded_json(repository_root, relative_path):\n"
        "    root = Path(os.path.abspath(os.fspath(repository_root)))\n"
        f"    candidate = {candidate_expression}\n"
        f"    with candidate.open({mode}) as stream:\n"
        "        return stream.read(min(16 * 1024, maximum_bytes - total + 1))\n"
    )
    key = (
        "analysis-framework/common/remus_profile_evidence.py",
        "reachable:_read_bounded_json",
        "candidate.open",
    )

    assert _reviewed_shape_result(source, key) is expected


@pytest.mark.parametrize(
    ("key", "source", "expected"),
    (
        (
            (
                "extractors/acrstealer/extractor.py",
                "reachable:_recover_pumped_zip",
                "stream.read",
            ),
            "import io\nimport zipfile\n"
            "def _recover_pumped_zip(data):\n"
            "    archive = zipfile.ZipFile(io.BytesIO(data))\n"
            "    members = archive.infolist()\n"
            "    for member in members:\n"
            '        with archive.open(member, "r") as stream:\n'
            "            return stream.read(32 * 1024 * 1024)\n",
            True,
        ),
        (
            (
                "extractors/acrstealer/extractor.py",
                "reachable:_recover_pumped_zip",
                "stream.read",
            ),
            "import io\nimport zipfile\n"
            "def _recover_pumped_zip(data):\n"
            "    archive = zipfile.ZipFile(io.BytesIO(data))\n"
            "    members = archive.infolist()\n"
            "    for member in members:\n"
            '        with archive.open(member, "r") as stream:\n'
            "            return stream.read()\n",
            False,
        ),
        (
            (
                "analysis-framework/common/remus_profile_evidence.py",
                "reachable:_read_bounded_json",
                "stream.read",
            ),
            "import os\nfrom pathlib import Path\n"
            "def _read_bounded_json(repository_root, relative_path):\n"
            "    root = Path(os.path.abspath(os.fspath(repository_root)))\n"
            "    candidate = root / relative_path\n"
            '    with candidate.open("rb") as stream:\n'
            "        return stream.read(min(16 * 1024, maximum_bytes - total + 1))\n",
            True,
        ),
        (
            (
                "analysis-framework/common/remus_profile_evidence.py",
                "reachable:_read_bounded_json",
                "stream.read",
            ),
            "import os\nfrom pathlib import Path\n"
            "def _read_bounded_json(repository_root, relative_path):\n"
            "    root = Path(os.path.abspath(os.fspath(repository_root)))\n"
            "    candidate = root / relative_path\n"
            '    with candidate.open("rb") as stream:\n'
            "        return stream.read(maximum_bytes)\n",
            False,
        ),
    ),
    ids=("acr-bounded", "acr-unbounded", "remus-bounded", "remus-unbounded"),
)
def test_reviewed_stream_read_requires_fixed_limit_and_verified_origin(
    key: tuple[str, str, str],
    source: str,
    expected: bool,
) -> None:
    """review済みstreamでも無制限・可変上限のreadへ拡張しない。"""

    assert _reviewed_shape_result(source, key) is expected


@pytest.mark.parametrize(
    ("receiver", "input_expression", "count", "expected"),
    (
        ("disassembler", "code[:15]", "1", True),
        ("disassembler", "code", "1", False),
        ("disassembler", "code[:15]", "2", False),
        ("code", "code[:15]", "1", False),
    ),
    ids=("bounded", "unbounded-input", "multiple-instructions", "wrong-receiver"),
)
def test_export_funnel_decode_review_requires_one_bounded_instruction(
    receiver: str,
    input_expression: str,
    count: str,
    expected: bool,
) -> None:
    """Capstone例外を15 byte超や複数命令decodeへ拡張できない。"""

    source = (
        "def _decode_one_x86(disassembler, code, address):\n"
        f"    return tuple({receiver}.disasm({input_expression}, address, count={count}))\n"
    )
    key = (
        "extractors/valleyrat/export_funnel.py",
        "reachable:_decode_one_x86",
        f"{receiver}.disasm",
    )
    reviewed_key = (
        key[0],
        key[1],
        "disassembler.disasm",
    )

    tree = ast.parse(source)
    scope = tree.body[0]
    assert isinstance(scope, ast.FunctionDef)
    call = next(
        node
        for node in ast.walk(scope)
        if isinstance(node, ast.Call) and catalog._ast_call_name(node.func) == key[2]
    )
    actual = catalog._reviewed_source_call_shape_allowed(
        call,
        reviewed_key[2],
        tree,
        scope,
        catalog._import_aliases(tree),
        key=reviewed_key,
    )

    assert actual is expected


def test_valleyrat_handler_dependency_preflight_accepts_reviewed_static_lineage_modules() -> None:
    """共通ValleyRAT handlerの実dependency graphが隔離workerへ到達できる。"""

    catalog.clear_handler_caches()
    try:
        specs = [
            spec
            for spec in catalog.discover_handlers()
            if spec.id == "valleyrat:extractors.valleyrat.extractor.py:extract"
        ]
        assert len(specs) == 1
        preflight = catalog.preflight_handler_for_assessment(
            specs[0],
            actual_format="pe",
            input_size=1024 * 1024,
        )
    finally:
        catalog.clear_handler_caches()

    assert preflight["eligible"] is True
    assert preflight["blockers"] == []
    assert preflight["sample_execution_allowed"] is False
    assert preflight["network_allowed"] is False
    assert preflight["filesystem_write_allowed"] is False
    assert preflight["dependency_audit"]["allowance_counts"]["reviewed_source_scoped_call"] >= 24


def test_valleyrat_dotnet_il_handler_preflight_accepts_fixed_token_tables() -> None:
    """.NET handlerは固定token table参照のまま隔離workerへ到達できる。"""

    catalog.clear_handler_caches()
    try:
        specs = [
            spec
            for spec in catalog.discover_handlers()
            if spec.id
            == ("valleyrat:analysis.framework.malware.valleyrat.campaigns.single.pe.analyze.dotnet.il.py:analyze")
        ]
        assert len(specs) == 1
        preflight = catalog.preflight_handler_for_assessment(
            specs[0],
            actual_format="pe",
            input_size=1024 * 1024,
        )
    finally:
        catalog.clear_handler_caches()

    assert preflight["eligible"] is True
    assert preflight["blockers"] == []
    assert preflight["sample_execution_allowed"] is False
    assert preflight["network_allowed"] is False
    assert preflight["filesystem_write_allowed"] is False
