"""最大55件の人工clear recordsだけで同keyの完全設定衝突を検証する。"""

from __future__ import annotations

import ast
from dataclasses import fields
import inspect

import pytest

from extractors.stealc import extractor
from extractors.stealc import integrated


METHOD = "v1-base64-rc4-skip-key"
KEY = "1" * 20
FIRST = ("http://first.fixture.example", "/first.php", "/deps/", "fixture-build")


def _records(*groups, count=55):
    values = [value for group in groups for value in group]
    assert len(values) <= count <= 55
    return values + [f"ordinary_padding_{index:02d}" for index in range(count - len(values))]


def _recover(monkeypatch, records, *, score=200):
    assert len(records) <= 55
    encoded = [b"artificial_encoded_record"] * len(records)
    key = KEY.encode("ascii")
    monkeypatch.setattr(extractor, "_pe", lambda _data: object())
    monkeypatch.setattr(extractor, "_candidate_strings", lambda *_args: [key])
    monkeypatch.setattr(extractor, "_base64_candidates", lambda _values: encoded)
    monkeypatch.setattr(extractor, "_key_candidates", lambda _values: [key])
    calls = []

    def decode(values, active_key):
        assert active_key == key and len(values) <= 55
        calls.append((active_key, len(values)))
        return score, list(records)

    monkeypatch.setattr(extractor, "_decode_base64_values", decode)
    try:
        return extractor._recover_rc4_profile(b"ordinary-synthetic"), calls
    except extractor._ProfileConflictError as exc:
        assert str(exc) == "conflicting_profiles"
        return "conflict", calls


def test_single_profile_all_existing_fields_remain_equal():
    profile = extractor._profile_from_strings(_records(FIRST), METHOD, KEY)
    assert profile == extractor.DecodedProfile(METHOD, FIRST[0], FIRST[1], FIRST[2], FIRST[3], 55, KEY)
    assert profile.c2_url == "http://first.fixture.example/first.php"
    assert profile.dll_url == "http://first.fixture.example/deps/"


@pytest.mark.parametrize("second", [
    ("http://other.fixture.example", FIRST[1], FIRST[2], FIRST[3]),
    (FIRST[0], "/other.php", FIRST[2], FIRST[3]),
    (FIRST[0], FIRST[1], "/other-deps/", FIRST[3]),
    (FIRST[0], FIRST[1], FIRST[2], "other-build"),
])
def test_each_variable_setting_conflict_is_rejected(second):
    with pytest.raises(extractor._ProfileConflictError, match="^conflicting_profiles$"):
        extractor._profile_from_strings(_records(FIRST, second), METHOD, KEY)


@pytest.mark.parametrize("reverse", [False, True])
def test_same_key_conflicting_complete_layouts_do_not_depend_on_order(monkeypatch, reverse):
    second = ("https://second.fixture.example", "/second.php", "/second-deps/", "second-build")
    groups = (second, FIRST) if reverse else (FIRST, second)
    profile, calls = _recover(monkeypatch, _records(*groups))
    assert profile == "conflict"
    assert calls == [(KEY.encode("ascii"), 55)] * 2


def test_exact_duplicate_keeps_first_existing_representation(monkeypatch):
    first = ("http://FiRsT.fixture.example", "/FiRsT.php", "/DePs/", "FiRsT-build")
    profile, _calls = _recover(monkeypatch, _records(first, first))
    assert profile == extractor.DecodedProfile(METHOD, *first, 55, KEY)
    assert profile.base_url == first[0] and profile.gate_path == first[1]


def test_case_only_representation_difference_is_not_silently_canonicalized():
    second = ("http://FIRST.fixture.example", FIRST[1], FIRST[2], FIRST[3])
    with pytest.raises(extractor._ProfileConflictError, match="^conflicting_profiles$"):
        extractor._profile_from_strings(_records(FIRST, second), METHOD, KEY)


def test_three_complete_layouts_do_not_hide_later_conflict():
    other = (FIRST[0], "/different.php", FIRST[2], FIRST[3])
    with pytest.raises(extractor._ProfileConflictError, match="^conflicting_profiles$"):
        extractor._profile_from_strings(_records(FIRST, FIRST, other), METHOD, KEY)


def test_first_incomplete_layout_is_not_rescued_by_later_complete_layout(monkeypatch):
    first = ("http://incomplete.fixture.example", *("missing_gate" for _ in range(8)))
    profile, _calls = _recover(monkeypatch, _records(first, FIRST))
    assert profile is None


@pytest.mark.parametrize("incomplete", [
    ("http://incomplete.fixture.example",),
    ("http://incomplete.fixture.example", "/missing-dll.php"),
])
def test_later_incomplete_layout_does_not_create_a_success_candidate(incomplete):
    profile = extractor._profile_from_strings(_records(FIRST, incomplete), METHOD, KEY)
    assert profile == extractor.DecodedProfile(METHOD, *FIRST, 55, KEY)


@pytest.mark.parametrize("records", [
    [], ["ordinary_without_url"], ["http://incomplete.fixture.example"],
    ["http://incomplete.fixture.example", "/no-dll.php"],
])
def test_existing_missing_schema_prerequisites_still_reject(records):
    assert extractor._profile_from_strings(records, METHOD, KEY) is None


@pytest.mark.parametrize("score,count", [(99, 55), (200, 49)])
def test_existing_score_and_count_thresholds_are_not_rescued(monkeypatch, score, count):
    profile, _calls = _recover(monkeypatch, _records(FIRST, count=count), score=score)
    assert profile is None


def test_all_seven_current_profile_fields_are_in_both_identity_tuples():
    assert tuple(field.name for field in fields(extractor.DecodedProfile)) == (
        "method", "base_url", "gate_path", "dll_path", "build_id", "decoded_count", "string_key",
    )
    tree = ast.parse(inspect.getsource(extractor._profile_from_strings))
    assignments = {node.targets[0].id: node.value for node in ast.walk(tree)
                   if isinstance(node, ast.Assign) and len(node.targets) == 1
                   and isinstance(node.targets[0], ast.Name)}
    assert ast.unparse(assignments["identity"]) == "(profile.method, profile.base_url, profile.gate_path, profile.dll_path, profile.build_id, profile.decoded_count, profile.string_key)"
    assert ast.unparse(assignments["candidate_identity"]) == "(method, strings[candidate_base], strings[candidate_gate], strings[candidate_dll], candidate_build, len(strings), key)"


def test_existing_search_limits_are_unchanged():
    assert (extractor.MAX_KEY_CANDIDATES, extractor.MAX_PROBE_VALUES,
            extractor.MAX_ENCODED_VALUES, extractor.MAX_ENCODED_LENGTH,
            extractor.MAX_FINAL_KEYS) == (512, 64, 4096, 4096, 4)


def test_conflicting_same_key_does_not_publish_confirmed_config(monkeypatch):
    other = ("https://second.fixture.example", "/second.php", "/second-deps/", "second-build")
    profile, _calls = _recover(monkeypatch, _records(FIRST, other))
    assert profile == "conflict"
    monkeypatch.setattr(extractor, "_recover_xor_profile", lambda _data: None)
    monkeypatch.setattr(extractor, "extract_protected_wrapper_profile", lambda _data: None)
    result = extractor.extract(b"ordinary-synthetic", "synthetic.bin")
    assert result["config"]["static_config_recovered"] is False
    assert result["config"]["profile"] is None
    assert result["config"]["profile_selection_error"] == "conflicting_profiles"
    assert result["findings"] == []
    assert result["executed"] is False and result["network_contacted"] is False


def _configure_key_records(monkeypatch, *, reverse, conflict_score, conflict=True):
    bad, good = b"1" * 20, b"2" * 20
    keys = [good, bad] if reverse else [bad, good]
    other = ("https://second.fixture.example", "/second.php", "/second-deps/", "second-build")
    bad_records = _records(FIRST, other) if conflict else _records(("ordinary_incomplete",))
    good_records = _records(FIRST)
    encoded = [b"artificial_encoded_record"] * 55
    monkeypatch.setattr(extractor, "_pe", lambda _data: object())
    monkeypatch.setattr(extractor, "_candidate_strings", lambda *_args: keys)
    monkeypatch.setattr(extractor, "_base64_candidates", lambda _values: encoded)
    monkeypatch.setattr(extractor, "_key_candidates", lambda _values: keys)
    calls = []

    def decode(values, key):
        assert len(values) <= 55
        calls.append(key)
        if len(calls) <= len(keys):
            return (conflict_score if key == bad else 200), []
        return 200, list(bad_records if key == bad else good_records)

    monkeypatch.setattr(extractor, "_decode_base64_values", decode)
    return bad, good, calls


@pytest.mark.parametrize("reverse,score", [(False, 300), (True, 300), (False, 100), (True, 100)])
def test_conflicting_key_cannot_be_skipped_for_another_valid_key(monkeypatch, reverse, score):
    _configure_key_records(monkeypatch, reverse=reverse, conflict_score=score)
    with pytest.raises(extractor._ProfileConflictError, match="^conflicting_profiles$"):
        extractor._recover_rc4_profile(b"ordinary-synthetic")


@pytest.mark.parametrize("reverse,score", [(False, 300), (True, 100)])
def test_incomplete_key_still_allows_the_existing_valid_other_key(monkeypatch, reverse, score):
    _bad, good, _calls = _configure_key_records(monkeypatch, reverse=reverse, conflict_score=score, conflict=False)
    profile = extractor._recover_rc4_profile(b"ordinary-synthetic")
    assert profile.string_key == good.decode("ascii")
    assert profile.base_url == FIRST[0]


def test_known_rc4_conflict_does_not_invoke_xor_or_protected_fallback(monkeypatch):
    def conflict(_data):
        raise extractor._ProfileConflictError("conflicting_profiles")
    monkeypatch.setattr(extractor, "_recover_rc4_profile", conflict)
    monkeypatch.setattr(extractor, "_recover_xor_profile", lambda _data: pytest.fail("既知相反からXORへ進まない"))
    monkeypatch.setattr(extractor, "extract_protected_wrapper_profile", lambda _data: pytest.fail("既知相反をwrapper成功へ変えない"))
    result = extractor.extract(b"ordinary-synthetic", "synthetic.bin")
    assert result["config"]["static_config_recovered"] is False
    assert result["config"]["profile_selection_error"] == "conflicting_profiles"
    assert result["findings"] == []


def test_known_xor_conflict_is_caught_by_the_public_extractor(monkeypatch):
    monkeypatch.setattr(extractor, "_recover_rc4_profile", lambda _data: None)
    def conflict(_data):
        raise extractor._ProfileConflictError("conflicting_profiles")
    monkeypatch.setattr(extractor, "_recover_xor_profile", conflict)
    monkeypatch.setattr(extractor, "extract_protected_wrapper_profile", lambda _data: pytest.fail("相反後fallback不可"))
    result = extractor.extract(b"ordinary-synthetic", "synthetic.bin")
    assert result["config"]["profile_selection_error"] == "conflicting_profiles"
    assert result["findings"] == []


def _base_result(*, recovered=False, error=None, protected=None):
    config = {"static_config_recovered": recovered, "profile": None, "protected_wrapper": protected}
    if error is not None:
        config["profile_selection_error"] = error
    return {"config": config, "findings": [], "limitations": [],
            "executed": False, "network_contacted": False}


def _deny_later_work(monkeypatch):
    for name in ("_v2_profile", "extract_v2_static_endpoint", "classify_module_role"):
        monkeypatch.setattr(integrated, name, lambda *_args: pytest.fail("既知相反後の処理はしない"))


def test_integrated_fixed_conflict_returns_the_same_base_result(monkeypatch):
    result = _base_result(error="conflicting_profiles")
    monkeypatch.setattr(integrated, "extract_v1", lambda *_args: result)
    _deny_later_work(monkeypatch)
    assert integrated.extract(b"ordinary-synthetic", "synthetic.bin") is result


@pytest.mark.parametrize("error", [None, "unknown_reason", False])
def test_integrated_does_not_treat_other_values_as_a_known_conflict(monkeypatch, error):
    result = _base_result(error=error)
    monkeypatch.setattr(integrated, "extract_v1", lambda *_args: result)
    calls = []
    monkeypatch.setattr(integrated, "_v2_profile", lambda _data: calls.append("v2") or None)
    monkeypatch.setattr(integrated, "extract_v2_static_endpoint", lambda _data: calls.append("endpoint") or None)
    monkeypatch.setattr(integrated, "classify_module_role", lambda _data: {"module_role": "ordinary"})
    monkeypatch.setattr(integrated, "protocol_guidance", lambda _profile: {})
    assert integrated.extract(b"ordinary-synthetic", "synthetic.bin") is result
    assert calls == ["v2", "endpoint"]


def test_integrated_normal_v1_still_avoids_v2_but_keeps_structural_work(monkeypatch):
    result = _base_result(recovered=True)
    monkeypatch.setattr(integrated, "extract_v1", lambda *_args: result)
    monkeypatch.setattr(integrated, "_v2_profile", lambda _data: pytest.fail("正常v1をv2へ上書きしない"))
    monkeypatch.setattr(integrated, "extract_v2_static_endpoint", lambda _data: pytest.fail("正常v1を縮めない"))
    structural = {"module_role": "ordinary"}
    monkeypatch.setattr(integrated, "classify_module_role", lambda _data: structural)
    monkeypatch.setattr(integrated, "protocol_guidance", lambda _profile: {"ordinary": True})
    assert integrated.extract(b"ordinary-synthetic", "synthetic.bin") is result
    assert result["config"]["structural_profile"] is structural
    assert result["config"]["protocol_analysis"] == {"ordinary": True}


def test_integrated_normal_protected_wrapper_without_conflict_keeps_fallback(monkeypatch):
    protected = {"reviewed_hash": True, "terminal_family_confirmed_from_wrapper_alone": False}
    result = _base_result(protected=protected)
    monkeypatch.setattr(integrated, "extract_v1", lambda *_args: result)
    calls = []
    monkeypatch.setattr(integrated, "_v2_profile", lambda _data: calls.append("v2") or None)
    monkeypatch.setattr(integrated, "extract_v2_static_endpoint", lambda _data: calls.append("endpoint") or None)
    monkeypatch.setattr(integrated, "classify_module_role", lambda _data: {"module_role": "ordinary"})
    monkeypatch.setattr(integrated, "protocol_guidance", lambda _profile: {})
    assert integrated.extract(b"ordinary-synthetic", "synthetic.bin") is result
    assert calls == ["v2", "endpoint"]
    assert result["config"]["protected_wrapper"] is protected

@pytest.mark.parametrize("reverse", [False, True])
def test_public_rc4_none_contract_still_rejects_known_conflict(monkeypatch, reverse):
    _configure_key_records(monkeypatch, reverse=reverse, conflict_score=300)
    assert extractor.extract_rc4_profile(b"ordinary-synthetic") is None


def test_public_xor_none_contract_still_rejects_known_conflict(monkeypatch):
    def conflict(_data):
        raise extractor._ProfileConflictError("conflicting_profiles")
    monkeypatch.setattr(extractor, "_recover_xor_profile", conflict)
    assert extractor.extract_xor_profile(b"ordinary-synthetic") is None


def test_public_rc4_normal_result_keeps_the_same_representation(monkeypatch):
    expected = extractor.DecodedProfile(METHOD, *FIRST, 55, KEY)
    monkeypatch.setattr(extractor, "_recover_rc4_profile", lambda _data: expected)
    assert extractor.extract_rc4_profile(b"ordinary-synthetic") is expected
