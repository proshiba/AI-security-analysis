"""既存有限RC4探索内の完全profile選択を人工入力だけで検証する。"""

from __future__ import annotations

import base64
from dataclasses import fields, replace
import struct

import pytest

from extractors.stealc import extractor
from extractors.stealc import integrated

KEY_GOOD = b"1" * 20
KEY_NOISE = b"2" * 20


def _clear_profile(*, gate="/fixture.php", count=55):
    values = ["http://fixture.example", gate, "/deps/", "fixture-build",
              *[value.decode("ascii") for value in extractor.KNOWN_MARKERS]]
    return values + [f"good_fixture_{index}" for index in range(count - len(values))]


def _encoded(clear, key):
    return [base64.b64encode(extractor.rc4_skip(value.encode("ascii"), key)) for value in clear]


def _values(*, noise=True, conflict=False):
    values = [KEY_GOOD, *_encoded(_clear_profile(), KEY_GOOD)]
    if noise or conflict:
        clear = (_clear_profile(gate="/different.php", count=150) if conflict else
                 [*[value.decode("ascii") for value in extractor.KNOWN_MARKERS],
                  *[f"noise_fixture_{index}" for index in range(144)]])
        values += [KEY_NOISE, *_encoded(clear, KEY_NOISE)]
    return values


def _pe(values):
    """外部PEを参照しない最小の人工.rdata PE32を作る。ロード・実行なし。"""
    raw = b"\0".join(values) + b"\0"
    size = (len(raw) + 0x1FF) & ~0x1FF
    header = bytearray(0x200)
    header[:2] = b"MZ"
    struct.pack_into("<I", header, 0x3C, 0x80)
    header[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", header, 0x84, 0x14C, 1, 0, 0, 0, 0xE0, 0x102)
    struct.pack_into("<H", header, 0x98, 0x10B)
    struct.pack_into("<I", header, 0x98 + 28, 0x400000)
    struct.pack_into("<II", header, 0x98 + 32, 0x1000, 0x200)
    struct.pack_into("<II", header, 0x98 + 56, ((len(raw) + 0xFFF) & ~0xFFF) + 0x1000, 0x200)
    struct.pack_into("<I", header, 0x98 + 92, 16)
    section = 0x98 + 0xE0
    header[section:section + 8] = b".rdata\0\0"
    struct.pack_into("<IIII", header, section + 8, len(raw), 0x1000, size, 0x200)
    struct.pack_into("<I", header, section + 36, 0x40000040)
    return bytes(header) + raw.ljust(size, b"\0")


def test_actual_codec_rejects_high_score_incomplete_key_and_recovers_complete_profile():
    data = _pe(_values())
    profile = extractor.extract_rc4_profile(data)
    assert profile is not None
    assert profile.method == "v1-base64-rc4-skip-key"
    assert profile.base_url == "http://fixture.example"
    assert profile.gate_path == "/fixture.php"
    assert profile.dll_path == "/deps/"
    assert profile.build_id == "fixture-build"
    assert profile.string_key == KEY_GOOD.decode("ascii")
    assert profile.decoded_count == 55
    assert profile.c2_url == "http://fixture.example/fixture.php"
    assert profile.dll_url == "http://fixture.example/deps/"


def test_actual_codec_conflicting_complete_profiles_remain_unresolved():
    data = _pe(_values(conflict=True))
    assert extractor.extract_rc4_profile(data) is None
    result = extractor.extract(data, "synthetic.bin")
    assert result["config"]["static_config_recovered"] is False
    assert result["config"]["profile"] is None and result["findings"] == []


def test_single_profile_preserves_all_existing_config_findings_and_safety_fields():
    data = _pe(_values(noise=False))
    result = extractor.extract(data, "synthetic.bin")
    assert result["config"]["profile"] == {
        "generation": "StealC-v1", "method": "v1-base64-rc4-skip-key",
        "base_url": "http://fixture.example", "gate_path": "/fixture.php",
        "c2_url": "http://fixture.example/fixture.php", "dll_path": "/deps/",
        "dll_url": "http://fixture.example/deps/", "build_id": "fixture-build",
        "decoded_string_count": 55, "string_key": KEY_GOOD.decode("ascii")}
    assert result["config"]["static_config_recovered"] is True
    assert [finding["role"] for finding in result["findings"]] == ["stealc_c2_url", "stealc_dependency_directory"]
    assert all(finding["confidence"] == "confirmed_static_config" for finding in result["findings"])
    assert result["executed"] is False and result["network_contacted"] is False
    assert result["credentials_published"] is False


def _mock_candidates(monkeypatch, *, keys=None, count=65, full=None, probe_scores=None):
    keys = [KEY_GOOD, KEY_NOISE] if keys is None else keys
    encoded = [b"QUJDRA=="] * count
    calls = []
    monkeypatch.setattr(extractor, "_pe", lambda _data: object())
    monkeypatch.setattr(extractor, "_candidate_strings", lambda *_args: keys)
    monkeypatch.setattr(extractor, "_base64_candidates", lambda _values: encoded)
    monkeypatch.setattr(extractor, "_key_candidates", lambda _values: keys)
    seen = 0

    def decode(values, key):
        nonlocal seen
        seen += 1
        calls.append((key, len(values)))
        if seen <= len(keys):
            return (probe_scores or {}).get(key, 200 if key == KEY_NOISE else 100), []
        return full(key) if full else (200, _clear_profile())

    monkeypatch.setattr(extractor, "_decode_base64_values", decode)
    return calls


@pytest.mark.parametrize("missing", ["base", "gate", "dll"])
def test_malformed_higher_score_does_not_shadow_existing_complete_layout(monkeypatch, missing):
    malformed = _clear_profile()
    malformed[{"base": 0, "gate": 1, "dll": 2}[missing]] = "unrelated_fixture"
    _mock_candidates(monkeypatch, full=lambda key: (900, malformed) if key == KEY_NOISE else (100, _clear_profile()))
    assert extractor.extract_rc4_profile(b"synthetic").string_key == KEY_GOOD.decode("ascii")


@pytest.mark.parametrize("score,count", [(99, 55), (100, 49), (0, 55)])
def test_low_score_or_short_complete_layout_cannot_be_promoted(monkeypatch, score, count):
    _mock_candidates(monkeypatch, keys=[KEY_GOOD], full=lambda _key: (score, _clear_profile(count=count)))
    assert extractor.extract_rc4_profile(b"synthetic") is None


@pytest.mark.parametrize("score,count", [(100, 50), (100, 55), (101, 50)])
def test_exact_existing_score_and_string_thresholds_are_preserved(monkeypatch, score, count):
    _mock_candidates(monkeypatch, keys=[KEY_GOOD], full=lambda _key: (score, _clear_profile(count=count)))
    profile = extractor.extract_rc4_profile(b"synthetic")
    assert profile is not None and profile.decoded_count == count


@pytest.mark.parametrize("missing", ["pe", "encoded", "keys"])
def test_missing_existing_input_prerequisites_do_not_decode(monkeypatch, missing):
    _mock_candidates(monkeypatch)
    if missing == "pe":
        monkeypatch.setattr(extractor, "_pe", lambda _data: None)
    elif missing == "encoded":
        monkeypatch.setattr(extractor, "_base64_candidates", lambda _values: [])
    else:
        monkeypatch.setattr(extractor, "_key_candidates", lambda _values: [])
    monkeypatch.setattr(extractor, "_decode_base64_values", lambda *_args: pytest.fail("前提不足でdecodeしない"))
    assert extractor.extract_rc4_profile(b"synthetic") is None


@pytest.mark.parametrize("field,value", [
    ("method", "another-reviewed-method"), ("base_url", "http://other.example"),
    ("gate_path", "/other.php"), ("dll_path", "/other-deps/"),
    ("build_id", "different-build"), ("decoded_count", 56), ("string_key", "different-key"),
])
def test_every_profile_setting_and_evidence_field_participates_in_identity(monkeypatch, field, value):
    _mock_candidates(monkeypatch)
    first = extractor.DecodedProfile("v1-base64-rc4-skip-key", "http://fixture.example", "/fixture.php", "/deps/", "fixture-build", 55, "fixture-key")
    second = replace(first, **{field: value})
    profiles = iter((first, second))
    monkeypatch.setattr(extractor, "_profile_from_strings", lambda *_args: next(profiles))
    assert extractor.extract_rc4_profile(b"synthetic") is None


def test_exact_duplicate_profile_preserves_first_existing_representation(monkeypatch):
    _mock_candidates(monkeypatch)
    first = extractor.DecodedProfile("v1-base64-rc4-skip-key", "http://Fixture.EXAMPLE", "/fixture.php", "/Deps/", "Fixture-Build", 55, "Fixture-Key")
    second = replace(first)
    profiles = iter((first, second))
    monkeypatch.setattr(extractor, "_profile_from_strings", lambda *_args: next(profiles))
    assert extractor.extract_rc4_profile(b"synthetic") is first


def test_profile_identity_contract_lists_every_current_dataclass_field():
    assert tuple(field.name for field in fields(extractor.DecodedProfile)) == (
        "method", "base_url", "gate_path", "dll_path", "build_id", "decoded_count", "string_key")


@pytest.mark.parametrize("count", [64, 65])
def test_probe64_and_final4_budgets_are_unchanged(monkeypatch, count):
    keys = [f"{index:020d}".encode() for index in range(512)]
    calls = _mock_candidates(monkeypatch, keys=keys, count=count, full=lambda _key: (0, []))
    assert extractor.extract_rc4_profile(b"synthetic") is None
    assert len(calls) == 512 + 4
    assert all(size == 64 for _key, size in calls[:512])
    assert all(size == count for _key, size in calls[512:])


def test_fifth_probe_candidate_is_not_scanned_to_find_another_profile(monkeypatch):
    keys = [f"{index:020d}".encode() for index in range(5)]
    scores = {key: 5 - index for index, key in enumerate(keys)}
    calls = _mock_candidates(monkeypatch, keys=keys, probe_scores=scores,
        full=lambda key: (200, _clear_profile()) if key == keys[4] else (300, ["incomplete"] * 55))
    assert extractor.extract_rc4_profile(b"synthetic") is None
    assert keys[4] not in [key for key, _size in calls[5:]]


def test_key512_and_encoded4096_limits_still_apply(monkeypatch):
    keys = [f"{index:020d}".encode() for index in range(513)]
    encoded = [base64.b64encode(f"value_fixture_{index:06d}".encode()) for index in range(4097)]
    monkeypatch.setattr(extractor, "_pe", lambda _data: object())
    monkeypatch.setattr(extractor, "_candidate_strings", lambda *_args: [*keys, *encoded])
    calls = []
    monkeypatch.setattr(extractor, "_decode_base64_values", lambda values, key: (calls.append((key, len(values))) or (0, [])))
    assert extractor.extract_rc4_profile(b"synthetic") is None
    assert len(calls) == 516
    assert keys[512] not in [key for key, _size in calls]
    assert max(size for _key, size in calls) == 4096


def test_selected_v1_profile_does_not_enable_v2_or_live_work(monkeypatch):
    monkeypatch.setattr(integrated, "extract_v1", extractor.extract)
    monkeypatch.setattr(integrated, "_v2_profile", lambda _data: pytest.fail("完全v1をv2へ上書きしない"))
    monkeypatch.setattr(integrated, "extract_v2_static_endpoint", lambda _data: pytest.fail("完全v1をbase-onlyへ縮めない"))
    result = integrated.extract(_pe(_values()), "synthetic.bin")
    assert result["config"]["profile"]["generation"] == "StealC-v1"
    assert result["executed"] is False and result["network_contacted"] is False
    assert result["config"]["protocol_analysis"]["confirmed_c2"] == []
