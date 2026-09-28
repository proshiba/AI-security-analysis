"""StealC v1/v2統合adapterのテスト。"""

from __future__ import annotations

from extractors.stealc import integrated
from extractors.stealc.v2_memory import V2MemoryProfile


def _base_result() -> dict:
    return {
        "schema_version": 1,
        "family": "stealc",
        "sample_sha256": "0" * 64,
        "config": {"source_name": "fixture", "profile": None, "static_config_recovered": False},
        "findings": [],
        "limitations": [
            "静的抽出だけを実施し、検体は実行していません。",
            "復元したendpointへ接続せず、稼働状態も判定していません。",
            "対応する平文profileは復元できませんでした。packingや別世代のStealCでは、別途承認された展開手順が必要になる場合があります。",
        ],
        "credentials_published": False,
        "executed": False,
        "network_contacted": False,
    }


def test_v2_memory_profile_is_normalized(monkeypatch) -> None:
    monkeypatch.setattr(integrated, "extract_v1", lambda _data, _name: _base_result())
    monkeypatch.setattr(
        integrated,
        "extract_v2_memory_profile",
        lambda _data: V2MemoryProfile(
            base_url="http://192.0.2.10",
            gate_path="/fixture.php",
            build_id="8172045377",
            traffic_key_hex="224b4a27cdb24c8b",
            string_key="fixtureKey42",
            decoded_count=276,
            config_offset=510264,
        ),
    )
    monkeypatch.setattr(
        integrated,
        "classify_module_role",
        lambda _data: {"module_role": "collection_and_c2_core"},
    )
    monkeypatch.setattr(integrated, "protocol_guidance", lambda _profile: {})

    result = integrated.extract(b"fixture", "memory.dmp")
    profile = result["config"]["profile"]
    assert result["config"]["static_config_recovered"] is True
    assert profile["generation"] == "StealC-v2"
    assert profile["c2_url"] == "http://192.0.2.10/fixture.php"
    assert profile["active_probe"]["max_requests"] == 2
    assert result["network_contacted"] is False
    assert any(item["role"] == "stealc_c2_url" for item in result["findings"])
    assert not any(value.startswith("対応する平文profileは復元できませんでした") for value in result["limitations"])


def test_v1_success_is_not_overwritten(monkeypatch) -> None:
    base = _base_result()
    base["config"]["static_config_recovered"] = True
    base["config"]["profile"] = {"generation": "StealC-v1"}
    monkeypatch.setattr(integrated, "extract_v1", lambda _data, _name: base)
    monkeypatch.setattr(
        integrated,
        "extract_v2_memory_profile",
        lambda _data: (_ for _ in ()).throw(AssertionError("v2 must not run")),
    )
    monkeypatch.setattr(
        integrated,
        "classify_module_role",
        lambda _data: {"module_role": "unknown"},
    )
    monkeypatch.setattr(integrated, "protocol_guidance", lambda _profile: {})
    assert integrated.extract(b"fixture")["config"]["profile"]["generation"] == "StealC-v1"
