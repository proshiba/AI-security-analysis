"""wide候補と既知loaderの優先順位・安全境界を人工fixtureだけで検証する。"""

from __future__ import annotations

import copy
import hashlib

import pytest

from extractors.common import build_result
from extractors.valleyrat import extractor
from extractors.valleyrat.native_loader_lineage import NativeLoaderLineage
from extractors.valleyrat.silverfox_loader_lineage import SilverFoxLoaderLineage

ROOT_BYTES = b"MZ synthetic candidate outer"

CHILD_BYTES = b"MZ synthetic independently-proven terminal"

def _wide(data, terminal=False):
    return build_result("valleyrat", data, {
        "variant": "winos_plaintext_pipe_bootstrap_terminal" if terminal else "winos_plaintext_pipe_config_candidate",
        "decoded_config_recovered": True, "static_config_recovered": terminal,
        "candidate_config_recovered": not terminal, "terminal_family_confirmed": terminal,
        "c2_liveness_confirmed": False, "source_name": "synthetic.exe",
        "endpoints": ["terminal.example:443"] if terminal else ["outer-candidate.example:449"],
        "ipv4": [], "urls": [],
    }, [{"kind": "network.endpoint", "value": "terminal.example:443" if terminal else "outer-candidate.example:449",
         "role": "static_config_c2" if terminal else "static_config_c2_candidate",
         "confidence": "confirmed_static_config" if terminal else "decoded_candidate_config", "source": "synthetic_producer"}],
        ["人工producer境界だけのfixture。実解析、実行、通信なし。"])

def _native(confirmed=True, **changes):
    value = {
        "schema_version": 1, "status": "validated_native_loader_to_valleyrat_terminal_lineage" if confirmed else "native_loader_candidate_terminal_unproven",
        "matched": True,
        "terminal": {"family": "valleyrat" if confirmed else None, "static_config_recovered": confirmed,
                     "endpoint_count": 1 if confirmed else 0, "candidate_only": not confirmed,
                     "endpoint_values_included": False},
        "supports_family_attribution": confirmed, "terminal_family_confirmed": confirmed,
        "terminal_network_lineage_proven": confirmed, "terminal_protocol_lineage_proven": confirmed,
        "endpoint_values_included": False, "raw_payload_included": False, "sample_executed": False,
        "network_contacted": False, "follow_on_candidate_set_complete": True,
    }
    value.update(changes)
    return value

def _bind(monkeypatch, module, observation, *, wide=None, child_result=None, recovered=()):
    candidate = wide if wide is not None else _wide(ROOT_BYTES)
    terminal = child_result if child_result is not None else _wide(CHILD_BYTES, terminal=True)
    monkeypatch.setattr(module, "_extract_wide_pipe_config",
        lambda data, _name: candidate if data == ROOT_BYTES else terminal if data == CHILD_BYTES else None)
    monkeypatch.setattr(module, "analyze_native_loader_lineage",
        lambda data: NativeLoaderLineage(observation=observation,
            terminal_component=CHILD_BYTES if observation.get("terminal_family_confirmed") is True else None,
            recovered_components=recovered) if data == ROOT_BYTES else None)
    monkeypatch.setattr(module, "analyze_silverfox_loader_lineage", lambda _data: None)
    return candidate

def test_candidate_cannot_shadow_strict_native_terminal(monkeypatch):
    candidate = _bind(monkeypatch, extractor, _native())
    original = copy.deepcopy(candidate)
    result = extractor.extract(ROOT_BYTES)
    assert result["sample_sha256"] == hashlib.sha256(ROOT_BYTES).hexdigest()
    assert result["config"]["variant"] == "native_loader_valleyrat_terminal_lineage"
    assert result["config"]["endpoints"] == ["terminal.example:443"]
    assert result["config"]["terminal_family_confirmed"] is True
    assert result["config"]["c2_liveness_confirmed"] is False
    assert result["terminal_payload"]["data"] == CHILD_BYTES
    assert "outer-candidate.example" not in repr(result)
    assert candidate == original

def test_confirmed_wide_precedence_does_not_call_other_lineage(monkeypatch):
    candidate = _bind(monkeypatch, extractor, _native(), wide=_wide(ROOT_BYTES, terminal=True))
    monkeypatch.setattr(extractor, "analyze_native_loader_lineage", lambda _data: pytest.fail("確定wideは既存優先順を維持する"))
    assert extractor.extract(ROOT_BYTES) is candidate

def test_candidate_preserved_and_only_safe_follow_on_added_without_mutation(monkeypatch):
    component = b"MZ synthetic route-only child"
    candidate = _bind(monkeypatch, extractor, _native(False), recovered=(component,))
    original = copy.deepcopy(candidate)
    result = extractor.extract(ROOT_BYTES)
    assert candidate == original
    assert result is not candidate
    assert result["config"] is not candidate["config"]
    assert result["config"]["static_config_recovered"] is False
    assert result["config"]["candidate_config_recovered"] is True
    assert result["config"]["terminal_family_confirmed"] is False
    assert result["config"]["endpoints"] == ["outer-candidate.example:449"]
    assert result["final_payload"]["role"] == "final_payload"
    assert result["final_payload"]["data"] == component
    assert "terminal_payload" not in result
    assert component.decode() not in repr(result["config"])

@pytest.mark.parametrize("field,value", [
    ("schema_version", True), ("schema_version", 1.0), ("schema_version", 2), ("schema_version", None),
    ("status", "future_profile"), ("status", None), ("status", []),
    ("matched", False), ("matched", 1), ("matched", 1.0),
    ("endpoint_values_included", True), ("raw_payload_included", True),
    ("sample_executed", True), ("network_contacted", True), ("network_contacted", None),
])
@pytest.mark.parametrize("confirmed", [True, False])
def test_unknown_or_unsafe_native_observation_never_mixes_terminal_or_child(monkeypatch, field, value, confirmed):
    candidate = _bind(monkeypatch, extractor, _native(confirmed, **{field: value}), recovered=(b"MZ forbidden child",))
    original = copy.deepcopy(candidate)
    result = extractor.extract(ROOT_BYTES)
    assert result == original
    assert "terminal_payload" not in result and "final_payload" not in result
    assert candidate == original

@pytest.mark.parametrize("field", ["supports_family_attribution", "terminal_network_lineage_proven", "terminal_protocol_lineage_proven"])
def test_missing_existing_terminal_proof_leaves_wide_candidate(monkeypatch, field):
    candidate = _bind(monkeypatch, extractor, _native(**{field: False}))
    result = extractor.extract(ROOT_BYTES)
    assert result["config"]["static_config_recovered"] is False
    assert result["config"]["endpoints"] == candidate["config"]["endpoints"]
    assert "terminal_payload" not in result and "final_payload" not in result

def test_incomplete_follow_on_set_does_not_add_prefix_child(monkeypatch):
    _bind(monkeypatch, extractor, _native(False, follow_on_candidate_set_complete=False), recovered=(b"MZ incomplete prefix",))
    result = extractor.extract(ROOT_BYTES)
    assert "final_payload" not in result
    assert result["config"]["terminal_family_confirmed"] is False

@pytest.mark.parametrize("field,value", [
    ("sample_sha256", "0" * 64), ("executed", True), ("network_contacted", True),
    ("credentials_published", True), ("family", "other-family"),
])
def test_child_contract_drift_raises_without_mutating_candidate(monkeypatch, field, value):
    child = _wide(CHILD_BYTES, terminal=True)
    child[field] = value
    candidate = _bind(monkeypatch, extractor, _native(), child_result=child)
    original = copy.deepcopy(candidate)
    with pytest.raises(RuntimeError, match="契約が一致しません"):
        extractor.extract(ROOT_BYTES)
    assert candidate == original

def test_reused_candidate_has_no_cross_input_observations_or_payloads(monkeypatch):
    candidate = _bind(monkeypatch, extractor, _native(False), recovered=(b"MZ one-call child",))
    original = copy.deepcopy(candidate)
    first = extractor.extract(ROOT_BYTES)
    assert "final_payload" in first
    monkeypatch.setattr(extractor, "analyze_native_loader_lineage", lambda _data: None)
    second = extractor.extract(ROOT_BYTES)
    assert second == original
    assert candidate == original
    assert "native_loader_lineage" not in second["config"]

@pytest.mark.parametrize("changes", [
    {"status": "native_loader_candidate_terminal_unproven"},
    {"terminal": {"family": "other", "static_config_recovered": True, "candidate_only": False, "endpoint_count": 1}},
    {"terminal": {"family": "valleyrat", "static_config_recovered": 1, "candidate_only": False, "endpoint_count": 1}},
    {"terminal": {"family": "valleyrat", "static_config_recovered": True, "candidate_only": None, "endpoint_count": 1}},
    {"terminal_network_lineage_proven": 1},
    {"terminal_protocol_lineage_proven": None},
])
def test_conflicting_or_partial_terminal_profile_keeps_candidate(monkeypatch, changes):
    candidate = _bind(monkeypatch, extractor, _native(**changes), recovered=(b"MZ conflicting child",))
    original = copy.deepcopy(candidate)
    assert extractor.extract(ROOT_BYTES) == original
    assert candidate == original

@pytest.mark.parametrize("changes", [
    {"status": "validated_native_loader_to_valleyrat_terminal_lineage"},
    {"terminal_network_lineage_proven": True},
    {"terminal_protocol_lineage_proven": True},
    {"terminal": {"family": None, "static_config_recovered": False, "candidate_only": True, "endpoint_count": False}},
    {"terminal": {"family": "valleyrat", "static_config_recovered": False, "candidate_only": True, "endpoint_count": 0}},
])
def test_conflicting_route_profile_never_attaches_prefix_child(monkeypatch, changes):
    candidate = _bind(monkeypatch, extractor, _native(False, **changes), recovered=(b"MZ conflicting route",))
    assert extractor.extract(ROOT_BYTES) == candidate

def test_unsafe_opaque_native_values_are_not_projected(monkeypatch):
    observation = _native(False, raw_payload_included=True, opaque_payload=b"PRIVATE_SYNTHETIC_MARKER")
    candidate = _bind(monkeypatch, extractor, observation, recovered=(b"MZ rejected bytes",))
    result = extractor.extract(ROOT_BYTES)
    assert result == candidate
    assert "PRIVATE_SYNTHETIC_MARKER" not in repr(result)


@pytest.mark.parametrize("confirmed", [True, False])
def test_conflicting_nested_endpoint_privacy_flag_cannot_project(monkeypatch, confirmed):
    observation = _native(confirmed)
    observation["terminal"]["endpoint_values_included"] = True
    observation["terminal"]["private_locator"] = "PRIVATE_SYNTHETIC_MARKER"
    candidate = _bind(monkeypatch, extractor, observation, recovered=(b"MZ forbidden child",))
    result = extractor.extract(ROOT_BYTES)
    assert result == candidate
    assert "PRIVATE_SYNTHETIC_MARKER" not in repr(result)

def _silverfox(**changes):
    value = {"schema_version": 1, "status": "validated_silverfox_style_infection_loader_lineage",
             "matched": True, "supports_family_attribution": False, "terminal_family_confirmed": False,
             "terminal_network_lineage_proven": False, "terminal_protocol_lineage_proven": False,
             "candidate_only": True, "endpoint_values_included": False, "raw_payload_included": False,
             "sample_executed": False, "network_contacted": False}
    value.update(changes)
    return value

def test_wide_candidate_preserves_known_silverfox_route_child(monkeypatch):
    candidate = _bind(monkeypatch, extractor, _native(False))
    monkeypatch.setattr(extractor, "analyze_native_loader_lineage", lambda _data: None)
    component = b"MZ synthetic SilverFox child"
    monkeypatch.setattr(extractor, "analyze_silverfox_loader_lineage", lambda _data:
        SilverFoxLoaderLineage(observation=_silverfox(), recovered_component=component))
    result = extractor.extract(ROOT_BYTES)
    assert result["config"]["endpoints"] == candidate["config"]["endpoints"]
    assert result["config"]["static_config_recovered"] is False
    assert result["config"]["terminal_family_confirmed"] is False
    assert result["final_payload"]["data"] == component
    assert "terminal_payload" not in result

@pytest.mark.parametrize("changes", [
    {"schema_version": True}, {"schema_version": 1.0}, {"schema_version": 2},
    {"status": "future_profile"}, {"status": []}, {"matched": 1},
    {"raw_payload_included": True}, {"sample_executed": True}, {"network_contacted": True},
    {"endpoint_values_included": True}, {"terminal_protocol_lineage_proven": True},
])
def test_unsafe_unknown_silverfox_does_not_mix_private_values_or_child(monkeypatch, changes):
    candidate = _bind(monkeypatch, extractor, _native(False))
    monkeypatch.setattr(extractor, "analyze_native_loader_lineage", lambda _data: None)
    observation = _silverfox(**changes, opaque_payload=b"PRIVATE_SYNTHETIC_MARKER")
    monkeypatch.setattr(extractor, "analyze_silverfox_loader_lineage", lambda _data:
        SilverFoxLoaderLineage(observation=observation, recovered_component=b"MZ forbidden silverfox"))
    result = extractor.extract(ROOT_BYTES)
    assert result == candidate
    assert "PRIVATE_SYNTHETIC_MARKER" not in repr(result)

EARLIER_PROFILES = (
    "_reviewed_pdfcore8_result", "_extract_ca01_sideload", "_extract_onyx_terminal",
    "_extract_run_dll_native_core", "_extract_x86_codemark_resource", "_extract_bin101",
    "_extract_codemark_stage", "_extract_raw_vvas_transport_shellcode", "_extract_n520",
    "_extract_xor_b1_downloader",
)

@pytest.mark.parametrize("profile", EARLIER_PROFILES)
def test_prior_reviewed_profile_ordinal_precedence_unchanged(monkeypatch, profile):
    chosen = _wide(ROOT_BYTES, terminal=True)
    for name in EARLIER_PROFILES:
        monkeypatch.setattr(extractor, name, lambda *_args: None)
    monkeypatch.setattr(extractor, profile, lambda *_args: chosen)
    monkeypatch.setattr(extractor, "_extract_wide_pipe_config", lambda *_args: pytest.fail("先行profileを追い越さない"))
    monkeypatch.setattr(extractor, "_extract_native_loader_lineage", lambda *_args: pytest.fail("先行profileを追い越さない"))
    assert extractor.extract(ROOT_BYTES) is chosen

def test_candidate_fallback_does_not_run_later_generic_profile(monkeypatch):
    candidate = _bind(monkeypatch, extractor, _native(False))
    monkeypatch.setattr(extractor, "analyze_native_loader_lineage", lambda _data: None)
    monkeypatch.setattr(extractor, "_decode_vvas_mapped_pe_config", lambda *_args: pytest.fail("候補fallback後のgeneric探索はしない"))
    assert extractor.extract(ROOT_BYTES) == candidate

def test_merge_preserves_existing_payload_and_candidate_alias(monkeypatch):
    candidate = _wide(ROOT_BYTES)
    candidate["final_payload"] = {"role": "final_payload", "name": "existing.bin", "data": b"MZ original child"}
    original = copy.deepcopy(candidate)
    _bind(monkeypatch, extractor, _native(False), wide=candidate, recovered=(b"MZ second child",))
    result = extractor.extract(ROOT_BYTES)
    assert [item["data"] for item in result["final_payloads"]] == [b"MZ original child", b"MZ second child"]
    assert candidate == original

def test_existing_input_budget_still_precedes_candidate_and_lineage(monkeypatch):
    monkeypatch.setattr(extractor, "MAXIMUM_INPUT_SIZE", 16)
    monkeypatch.setattr(extractor, "_extract_wide_pipe_config", lambda *_args: pytest.fail("入力上限後に解析しない"))
    monkeypatch.setattr(extractor, "analyze_native_loader_lineage", lambda *_args: pytest.fail("入力上限後に解析しない"))
    result = extractor.extract(ROOT_BYTES)
    assert result["config"]["recovery_status"] == "not_attempted_input_size_limit"
    assert result["config"]["static_config_recovered"] is False
    assert "terminal_payload" not in result and "final_payload" not in result
