"""raw route候補とmapped exact定数を人工入力だけで分離する。"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from extractors.valleyrat import extractor

CANONICAL = "|p1:198.51.100.24|o1:443|t1:1|"
STORED = CANONICAL[::-1]
ENDPOINT = "198.51.100.24:443"


@pytest.mark.parametrize("prefix", ("", "odaktomk ", "payload odaktomk ", ":zf", "context :zf"))
def test_raw_prefix_preserves_exact_config_identity(prefix: str) -> None:
    """raw前置文脈だけを除き、slot・transport・identityはexact結果と一致する。"""
    exact, exact_evidence = extractor._decode_vvas_reversed_config([STORED])
    decoded, evidence = extractor._decode_vvas_raw_candidate_config([prefix + STORED])
    assert decoded == exact == {"endpoint_1": ENDPOINT}
    for key in exact_evidence:
        assert evidence[key] == exact_evidence[key]
    assert evidence["raw_candidate_scope"] == "non_pe_route_candidate_only"
    assert evidence["raw_candidate_scan_complete"] is True
    assert evidence["raw_prefix_stripped_count"] == int(bool(prefix))
    if prefix:
        assert extractor.decode_vvas_reversed_config([prefix + STORED]) == {}
        assert extractor._decode_vvas_reversed_config([prefix + STORED])[0] == {}


def test_raw_tilde_and_unknown_legacy_transport_are_not_inferred() -> None:
    """既存tilde grammarとselector無しunknownを維持する。"""
    tilde = CANONICAL.replace("|", "~")[::-1]
    assert extractor._decode_vvas_raw_candidate_config(["odaktomk " + tilde])[0] == {
        "endpoint_1": ENDPOINT,
    }
    legacy = "|p1:198.51.100.24|o1:443|"[::-1]
    result = extractor.extract(b"odaktomk " + legacy.encode("ascii"))
    assert result["config"]["decoded_vvas_slots"] == [
        {"slot": 1, "endpoint": ENDPOINT, "transport": "unknown"},
    ]
    assert result["config"]["static_config_recovered"] is False


@pytest.mark.parametrize("xor", (False, True))
def test_raw_normal_entry_remains_candidate_and_probe_hides_values(xor: bool) -> None:
    """通常extract/probe入口で候補を回収してもfamily・terminal・liveは確定しない。"""
    plaintext = b"payload odaktomk " + STORED.encode("ascii")
    data = bytes(value ^ 0x14 for value in plaintext) if xor else plaintext
    result = extractor.extract(data, "synthetic.bin")
    config = result["config"]
    assert config["endpoints"] == [ENDPOINT]
    assert config["candidate_config_recovered"] is True
    for flag in ("static_config_recovered", "decoded_config_recovered", "terminal_family_confirmed", "c2_liveness_confirmed"):
        assert config[flag] is False
    assert config["attribution_scope"] == "component_handler_route"
    assert "terminal_payload" not in result
    assert result["findings"] == [{
        "kind": "network.endpoint", "value": ENDPOINT, "role": "candidate_c2",
        "confidence": "inferred", "source": "decoded_vvas_candidate",
    }]
    probe = (extractor.probe_xor_vvas_config(data) if xor else
             extractor.probe_vvas_config(data, input_format="data"))
    assert probe["matched"] is True
    assert probe["family"] is None
    for flag in ("supports_family_attribution", "terminal_family_confirmed", "static_config_recovered", "sample_executed", "network_contacted"):
        assert probe[flag] is False
    assert probe["candidate_config_recovered"] is True
    assert probe["config"]["raw_network_values_included"] is False
    serialized = json.dumps(probe, sort_keys=True)
    assert "198.51.100.24" not in serialized
    assert "42.001.15.891" not in serialized
    assert "0x14" not in serialized


@pytest.mark.parametrize("prefix", (":1p", ":1o", ":1t", "p1:", "o1:", "t1:", ":4p", "p4:", ":12T", "O12:"))
def test_raw_prefix_cannot_hide_forward_or_reversed_slot_fields(prefix: str) -> None:
    """最初のdelimiterより前のp/o/t field痕跡を切り捨てて救済しない。"""
    assert extractor._decode_vvas_raw_candidate_config([prefix + STORED])[0] == {}
    probe = extractor.probe_vvas_config(b"odaktomk " + (prefix + STORED).encode("ascii"), input_format="data")
    assert probe["matched"] is False


@pytest.mark.parametrize("value", (
    "odaktomk " + STORED + "suffix",
    "odaktomk " + STORED[:-1],
    "odaktomk " + STORED[:-1] + "~",
    "context~" + STORED,
    "context|" + STORED.replace("|", "~"),
    "odaktomk " + "|p1:198.51.100.24|t1:1|"[::-1],
    "odaktomk " + "|p1:198.51.100.24|o1:443|t1:2|"[::-1],
    "odaktomk " + "|p1:198.51.100.24|o1:443|t1:1|p2:backup.example|o2:8443|"[::-1],
    "odaktomk " + "|p1:198.51.100.24|o1:443|t1:1|t1:0|"[::-1],
    "odaktomk " + "|p1:198.51.100.24|o1:443|p1:198.51.100.25|"[::-1],
))
def test_raw_malformed_suffix_partial_and_transport_conflict_rejected(value: str) -> None:
    """suffixを探して切り落とさず、完全設定の既存陰性を維持する。"""
    decoded, evidence = extractor._decode_vvas_raw_candidate_config([value])
    assert decoded == {}
    assert evidence["status"] != "decoded_unique"


def test_raw_complete_candidates_remain_ambiguous_across_strings() -> None:
    """別文字列の相反設定を最初の成功候補だけで確定しない。"""
    conflict = CANONICAL.replace("443", "8443")[::-1]
    decoded, evidence = extractor._decode_vvas_raw_candidate_config(["odaktomk " + STORED, "context " + conflict])
    assert decoded == {}
    assert evidence["status"] == "ambiguous_rejected"
    assert evidence["unique_configuration_count"] == 2
    transport_conflict = CANONICAL.replace("t1:1", "t1:0")[::-1]
    assert extractor._decode_vvas_raw_candidate_config([STORED, transport_conflict])[0] == {}
    data = b"odaktomk " + STORED.encode("ascii") + b"\0context " + conflict.encode("ascii")
    assert extractor.probe_vvas_config(data, input_format="data")["matched"] is False


@pytest.mark.parametrize("data", (
    STORED.encode("ascii"),
    b"odaktomk odaktomk " + STORED.encode("ascii"),
    b"odaktomk " + STORED.encode("ascii") + b" |3448:1o|52.001.15.891:1p|",
))
def test_raw_route_requires_one_marker_and_one_configuration(data: bytes) -> None:
    """文字列分離だけでmarkerの一意性・設定競合条件を緩めない。"""
    assert extractor.probe_vvas_config(data, input_format="data")["matched"] is False


def test_raw_legacy_placeholder_scope_preserves_all_assertions() -> None:
    """旧:zf fixtureはraw文脈で検査し、placeholder除外を変えない。"""
    stored = ":zf|1:lc|1:dd|1:3t|10801:3o|1.0.0.721:3p|1:2t|10801:2o|43.64.57.301:2p|1:1t|10801:1o|43.64.57.301:1p|"
    decoded, evidence = extractor._decode_vvas_raw_candidate_config([stored])
    assert decoded == {"endpoint_1": "103.75.46.34:10801", "endpoint_2": "103.75.46.34:10801"}
    assert evidence["excluded_placeholder_slot_count"] == 1
    assert extractor.decode_vvas_reversed_config([stored]) == {}
    probe = extractor.probe_vvas_config(b"odaktomk " + stored.encode("ascii"), input_format="data")
    assert probe["matched"] is True
    assert probe["evidence"]["vvas_reversed_config"]["excluded_placeholder_slot_count"] == 1
    assert extractor.decode_vvas_reversed_config(["|10801:1o|1.0.0.721:1p|"]) == {}


@pytest.mark.parametrize("limit", ("count", "length", "characters"))
def test_raw_bounds_include_unstripped_prefix_and_all_material(limit: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """切除後の短さで元の全件・単体長・総文字数上限を迂回しない。"""
    value = "payload odaktomk " + STORED
    values = [value, "noise"]
    if limit == "count":
        monkeypatch.setattr(extractor, "MAXIMUM_STRING_COUNT", 1)
    elif limit == "length":
        monkeypatch.setattr(extractor, "MAXIMUM_STRING_LENGTH", len(value) - 1)
    else:
        monkeypatch.setattr(extractor, "MAXIMUM_STRING_CHARACTERS", sum(map(len, values)) - 1)
    decoded, evidence = extractor._decode_vvas_raw_candidate_config(values)
    assert decoded == {}
    assert evidence["status"] == "raw_candidate_scan_limit_rejected"
    assert evidence["raw_candidate_scan_complete"] is False
    assert evidence["unique_configuration_count"] == 0


def test_raw_exact_budget_boundary_and_late_ignored_material(monkeypatch: pytest.MonkeyPatch) -> None:
    """上限以内の同じ入力は回収し、上限後の非設定文字列も省略しない。"""
    values = ["payload odaktomk " + STORED, "noise"]
    monkeypatch.setattr(extractor, "MAXIMUM_STRING_COUNT", 2)
    monkeypatch.setattr(extractor, "MAXIMUM_STRING_LENGTH", len(values[0]))
    monkeypatch.setattr(extractor, "MAXIMUM_STRING_CHARACTERS", sum(map(len, values)))
    assert extractor._decode_vvas_raw_candidate_config(values)[0] == {"endpoint_1": ENDPOINT}
    assert extractor._decode_vvas_raw_candidate_config(values + ["x"])[0] == {}


@pytest.mark.parametrize("limit", ("count", "length", "characters"))
@pytest.mark.parametrize("xor", (False, True))
def test_normal_raw_callers_reject_truncated_string_scan(limit: str, xor: bool, monkeypatch: pytest.MonkeyPatch) -> None:
    """通常入口でも打切り前の設定だけを一意な成功として採用しない。"""
    plain = b"odaktomk " + STORED.encode("ascii") + b"\0ignored-material\0late-material"
    if limit == "count":
        monkeypatch.setattr(extractor, "MAXIMUM_STRING_COUNT", 2)
    elif limit == "length":
        monkeypatch.setattr(extractor, "MAXIMUM_STRING_LENGTH", len(STORED))
    else:
        monkeypatch.setattr(extractor, "MAXIMUM_STRING_CHARACTERS", len("odaktomk " + STORED) + 1)
    data = bytes(value ^ 0x14 for value in plain) if xor else plain
    probe = (extractor.probe_xor_vvas_config(data) if xor else
             extractor.probe_vvas_config(data, input_format="data"))
    assert probe["matched"] is False
    result = extractor.extract(data)
    assert result["config"]["endpoints"] == []
    assert result["config"]["candidate_config_recovered"] is False
    assert result["config"]["static_config_recovered"] is False
    assert result["config"]["terminal_family_confirmed"] is False
    assert "terminal_payload" not in result


def test_raw_unknown_objects_are_rejected_without_methods() -> None:
    """helperの値型検証より先に未知objectのlenやiterationを呼ばない。"""
    class BadList(list):
        def __len__(self):
            raise AssertionError("未知listのlenは禁止")

    class BadString(str):
        def __len__(self):
            raise AssertionError("未知strのlenは禁止")

    for values in (None, (), BadList([STORED]), [BadString(STORED)], [object()]):
        decoded, evidence = extractor._decode_vvas_raw_candidate_config(values)
        assert decoded == {}
        assert evidence["raw_candidate_scan_complete"] is False


@pytest.mark.parametrize("prefix,suffix", (("", ""), ("payload odaktomk ", ""), ("", "suffix")))
def test_mapped_candidate_source_still_requires_exact_whole_string(prefix: str, suffix: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """raw helperをmapped sectionやresourceの設定定数へ転用しない。"""
    data = bytearray(0x600)
    data[:2] = b"MZ"
    stored = (prefix + STORED + suffix).encode("utf-16le")
    data[0x320:0x320 + len(stored)] = stored
    image = SimpleNamespace(
        sections=[
            SimpleNamespace(Name=b".text", VirtualAddress=0x1000, Misc_VirtualSize=0x100, PointerToRawData=0x200, SizeOfRawData=0x100, Characteristics=0x60000020),
            SimpleNamespace(Name=b".data", VirtualAddress=0x2000, Misc_VirtualSize=0x200, PointerToRawData=0x300, SizeOfRawData=0x200, Characteristics=0xC0000040),
        ],
        OPTIONAL_HEADER=SimpleNamespace(ImageBase=0x400000, AddressOfEntryPoint=0x1000),
    )
    monkeypatch.setattr(extractor.pefile, "PE", lambda **_kwargs: image)
    candidates, scan = extractor._vvas_mapped_config_candidates(bytes(data))
    assert scan["candidate_set_complete"] is True
    assert len(candidates) == int(not prefix and not suffix)
    assert scan["rejected_marker_hit_count"] == int(bool(prefix or suffix))


def test_mz_input_never_falls_back_to_raw_prefix() -> None:
    """無効PEのraw文字列を終端設定へfallbackしない。"""
    result = extractor.extract(b"MZ\0payload odaktomk " + STORED.encode("ascii"))
    assert result["config"]["static_config_recovered"] is False
    assert result["config"]["terminal_family_confirmed"] is False
    assert result["config"]["candidate_config_recovered"] is False
    assert result["config"]["endpoints"] == []
    assert "terminal_payload" not in result


def test_classifier_raw_xor_route_is_not_family_attribution(monkeypatch: pytest.MonkeyPatch) -> None:
    """現登録分類器の通常入口でraw XOR設定をroute候補に留める。"""
    root = Path(extractor.__file__).resolve().parents[2]
    monkeypatch.syspath_prepend(str(root / "analysis-framework"))
    from classifiers import classify_sample

    plaintext = b"payload odaktomk " + STORED.encode("ascii")
    encrypted = bytes(value ^ 0x14 for value in plaintext)
    result = classify_sample.classify_bytes(encrypted, Path("synthetic-vvas.bin"), root / "analysis-framework/registry/malware_types.json", "valleyrat")
    evaluation = next(item for item in result["detector_evaluations"] if item["malware_type"] == "valleyrat")
    assert result["malware_type"] == "unknown"
    assert evaluation["detector_matched"] is True
    assert evaluation["automatic_route_eligible"] is True
    assert evaluation["supports_family_attribution"] is False
    campaign = evaluation["detection"]["campaigns"][0]
    assert campaign["campaign_type"] == "single_byte_xor_vvas_candidate"
    assert campaign["terminal_family_confirmed"] is False
