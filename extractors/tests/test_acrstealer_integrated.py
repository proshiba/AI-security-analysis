"""ACRStealer v4 memory統合adapterのテスト。"""

from __future__ import annotations

from extractors.acrstealer import integrated
from extractors.acrstealer.v4_config import V4StaticConfig


def _base_result() -> dict:
    return {
        "schema_version": 1,
        "family": "acrstealer",
        "sample_sha256": "0" * 64,
        "config": {
            "source_name": "fixture",
            "artifact_role": "unresolved_acrstealer_related_artifact",
            "static_config_recovered": False,
        },
        "findings": [],
        "limitations": [
            "検体と復元アーティファクトは実行していません。",
            "対応済みファイルポンプまたはレビュー済みnative loader layoutを検出できませんでした。",
        ],
        "credentials_published": False,
        "executed": False,
        "network_contacted": False,
    }


def test_v4_memory_config_is_normalized(monkeypatch) -> None:
    monkeypatch.setattr(integrated, "extract_base", lambda _data, _name: _base_result())
    monkeypatch.setattr(
        integrated,
        "extract_v4_config",
        lambda _data: V4StaticConfig(
            version="4.3.2-alpha3",
            final_c2_urls=(),
            final_c2_hosts=("wss.infrastructurecore.cc",),
            final_c2_paths=(),
            dead_drop_urls=("https://telegra.ph/example",),
            dns_resolvers=("cloudflare-dns.com", "dns.google"),
            decoy_hosts=("keycdn.com",),
            guids=("a6cdcc0b-6b38-49d6-9672-20be114d9eba",),
            user_agent=None,
            string_key_hex="e39310a767d939a4",
            protocol_fingerprint=("sspi_tls_http_1_1", "dns_over_https_resolver"),
            protocol_confidence="high",
            active_registration_supported=False,
            unresolved_fields=("final_c2_path", "request_body_schema_and_crypto"),
            decoded_count=573,
            layout="memory_mapped",
            generic_domain_findings=("generic-finding.example",),
        ),
    )

    result = integrated.extract(b"fixture", "memory.dmp")
    config = result["config"]
    assert config["static_config_recovered"] is True
    assert config["version"] == "4.3.2-alpha3"
    assert config["final_c2_hosts"] == ["wss.infrastructurecore.cc"]
    assert config["active_registration_supported"] is False
    assert result["network_contacted"] is False
    assert any(item["role"] == "acrstealer_dead_drop" for item in result["findings"])
    generic = next(
        item
        for item in result["findings"]
        if item["value"] == "generic-finding.example"
    )
    assert generic["role"] == "acrstealer_generic_domain_finding"
    assert generic["confidence"] == "decoded_string_only"
    assert not any(
        item["value"] == "generic-finding.example"
        and item["role"] == "acrstealer_final_c2_host"
        for item in result["findings"]
    )
    assert not any(value.startswith("対応済みファイルポンプ") for value in result["limitations"])


def test_non_v4_result_is_unchanged(monkeypatch) -> None:
    base = _base_result()
    monkeypatch.setattr(integrated, "extract_base", lambda _data, _name: base)
    monkeypatch.setattr(integrated, "extract_v4_config", lambda _data: None)
    assert integrated.extract(b"fixture") is base
