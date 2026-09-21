"""攻撃インフラSTIXの参照整合性と証拠境界を検証する。"""

from __future__ import annotations

from copy import deepcopy
from datetime import date, datetime, timezone
import json
from pathlib import Path
import sys

import pytest


COMMON = Path(__file__).parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import generate_infrastructure_stix as stix  # noqa: E402


def _knowledge() -> dict:
    return {
        "schema_version": 1,
        "sources": [{"id": "report", "source_name": "検証資料", "url": "https://example.org/report"}],
        "certificates": [{
            "id": "cert", "sha1": "a" * 40, "sha256": "b" * 64,
            "subject": "CN=example", "issuer": "CN=example", "is_self_signed": True,
            "source_ids": ["report"],
        }],
        "endpoints": [
            {
                "id": "known-c2", "ip": "8.8.8.8", "port": 443, "certificate_id": "cert",
                "classification": "confirmed-c2", "role": "c2", "protocol": "tls",
                "evidence_kind": "traffic", "family_id": "test-rat",
                "sample_sha256": "c" * 64, "source_ids": ["report"],
                "first_observed": "2026-09-19T01:00:00Z", "last_observed": "2026-09-20T01:00:00Z",
            },
            {
                "id": "cert-pivot", "ip": "1.1.1.1", "port": 443, "certificate_id": "cert",
                "classification": "pivot-only", "role": "unknown", "protocol": "tls",
                "evidence_kind": "certificate-only", "source_ids": ["report"],
            },
            {
                "id": "exact-page", "url": "https://telegra.ph/Functions-04-03",
                "classification": "confirmed-auxiliary", "role": "dead-drop", "protocol": "https",
                "evidence_kind": "sample-config", "family_id": "test-rat", "source_ids": ["report"],
            },
        ],
        "dns_resolutions": [],
        "groupings": [{"id": "cert-cluster", "name": "証明書共通候補", "description_ja": "同じ証明書が観測された。", "endpoint_ids": ["known-c2", "cert-pivot"], "source_ids": ["report"]}],
        "campaigns": [{"id": "case-a", "name": "検証攻撃", "description_ja": "検証用の攻撃活動。", "endpoint_ids": ["known-c2"], "family_ids": ["test-rat"], "source_ids": ["report"]}],
        "intrusion_sets": [],
    }


def _repo(tmp_path: Path, data: dict) -> Path:
    path = tmp_path / "analysis-framework/knowledge/stix_infrastructure_curated.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    return tmp_path


def test_generate_preserves_certificate_pivot_boundary(tmp_path: Path) -> None:
    outputs, index = stix.generate(_repo(tmp_path, _knowledge()), date(2026, 9, 21))
    bundle = json.loads(outputs["bundle.json"])
    stix._validate_bundle(bundle)
    objects = bundle["objects"]
    assert index["counts"]["network-traffic"] == sum(item["type"] == "network-traffic" for item in objects)
    assert sum(index["counts"].values()) == len(objects)
    assert index["confirmed_c2"] == 1
    assert index["confirmed_auxiliary"] == 1
    assert index["safety"]["sample_executed_during_generation"] is False
    assert index["safety"]["live_c2_contacted_during_generation"] is False
    assert "live_c2_contacted" not in index["safety"]
    assert len([item for item in objects if item["type"] == "infrastructure"]) == 2
    assert len([item for item in objects if item["type"] == "indicator"]) == 1
    assert len([item for item in objects if item["type"] == "url"]) == 1
    assert not any(item["type"] == "domain-name" and item["value"] == "telegra.ph" for item in objects)
    cert = next(item for item in objects if item["type"] == "x509-certificate")
    assert cert["is_self_signed"] is True
    file_id = next(item["id"] for item in objects if item["type"] == "file")
    assert not any(item.get("relationship_type") == "consists-of" and item["target_ref"] == file_id for item in objects)
    assert any(item["type"] == "note" and file_id in item["object_refs"] and any(ref.startswith("malware--") for ref in item["object_refs"]) for item in objects)
    assert not any(item.get("relationship_type") == "beacons-to" and item["target_ref"] == stix._identifier("infrastructure", "infra:endpoint:cert-pivot") for item in objects)
    assert any(item["type"] == "grouping" and item["context"] == "unspecified" for item in objects)


def test_domain_only_confirmed_c2_does_not_invent_port(tmp_path: Path) -> None:
    data = _knowledge()
    data["endpoints"][0].pop("ip")
    data["endpoints"][0].pop("port")
    data["endpoints"][0]["domain"] = "c2.example.org"
    bundle = json.loads(stix.generate(_repo(tmp_path, data), date(2026, 9, 21))[0]["bundle.json"])
    assert any(item["type"] == "indicator" and item["pattern"] == "[domain-name:value = 'c2.example.org']" for item in bundle["objects"])
    assert not any(item["type"] == "network-traffic" for item in bundle["objects"])


@pytest.mark.parametrize("mutator", [
    lambda data: data["endpoints"][0].update(evidence_kind="certificate-only"),
    lambda data: data["endpoints"][1].update(family_id="test-rat"),
    lambda data: data["campaigns"][0].update(endpoint_ids=["cert-pivot"]),
    lambda data: data["sources"][0].update(url="https://example.org/report?token=abc"),
    lambda data: data["endpoints"][0].update(sample_sha256="bad"),
    lambda data: data["endpoints"][2].update(url="https://telegra.ph/Functions-04-03?token=x"),
])
def test_unsafe_or_unproven_input_fails_closed(mutator) -> None:
    data = deepcopy(_knowledge())
    mutator(data)
    with pytest.raises(ValueError):
        stix._validate(data)


def test_attributed_grouping_needs_confirmed_endpoints_and_source() -> None:
    data = _knowledge()
    data["intrusion_sets"] = [{"id": "test-set", "name": "検証セット", "description_ja": "出典付きの活動集合。", "source_ids": ["report"]}]
    data["groupings"][0].update(intrusion_set_ids=["test-set"], attribution_source_ids=["report"], attribution_ja="資料が明示的に帰属する。")
    with pytest.raises(ValueError, match="groupingのintrusion set帰属"):
        stix._validate(data)
    data["groupings"][0]["endpoint_ids"] = ["known-c2"]
    stix._validate(data)


def test_attributed_grouping_emits_scoped_uses_relationships(tmp_path: Path) -> None:
    data = _knowledge()
    data["intrusion_sets"] = [{"id": "test-set", "name": "検証セット", "description_ja": "出典付きの活動集合。", "source_ids": ["report"]}]
    group = data["groupings"][0]
    group.update(endpoint_ids=["known-c2"], intrusion_set_ids=["test-set"], attribution_source_ids=["report"], attribution_ja="資料がこの設定を活動集合に明示帰属。")
    bundle = json.loads(stix.generate(_repo(tmp_path, data), date(2026, 9, 21))[0]["bundle.json"])
    actor_id = stix._identifier("intrusion-set", "infra:intrusion:test-set")
    uses = [item for item in bundle["objects"] if item.get("relationship_type") == "uses" and item["source_ref"] == actor_id]
    assert {item["target_ref"] for item in uses} == {
        stix._identifier("malware", "test-rat"),
        stix._identifier("infrastructure", "infra:endpoint:known-c2"),
    }
    assert all(item["external_references"] for item in uses)
    assert not any(item["target_ref"] == stix._identifier("infrastructure", "infra:endpoint:cert-pivot") for item in uses)


def test_observed_data_requires_actual_times(tmp_path: Path) -> None:
    data = _knowledge()
    data["endpoints"][0]["evidence_kind"] = "traffic"
    bundle = json.loads(stix.generate(_repo(tmp_path, data), date(2026, 9, 21))[0]["bundle.json"])
    assert len([item for item in bundle["objects"] if item["type"] == "observed-data"]) == 1
    data["endpoints"][0].pop("first_observed")
    data["endpoints"][0].pop("last_observed")
    bundle = json.loads(stix.generate(_repo(tmp_path, data), date(2026, 9, 21))[0]["bundle.json"])
    assert not any(item["type"] == "observed-data" for item in bundle["objects"])


def test_stage_and_configured_alternate_are_not_c2(tmp_path: Path) -> None:
    data = _knowledge()
    stage = data["endpoints"][0]
    stage["classification"] = "confirmed-auxiliary"
    stage["role"] = "delivery"
    stage["evidence_kind"] = "sample-config"
    stage.pop("first_observed")
    stage.pop("last_observed")
    data["campaigns"] = []
    alternate = data["endpoints"][1]
    alternate.pop("certificate_id")
    alternate["classification"] = "configured-only"
    alternate["role"] = "c2"
    alternate["evidence_kind"] = "sample-config"
    alternate["family_id"] = "test-rat"
    alternate["sample_sha256"] = "d" * 64
    bundle = json.loads(stix.generate(_repo(tmp_path, data), date(2026, 9, 21))[0]["bundle.json"])
    objects = bundle["objects"]
    assert not any(item.get("relationship_type") == "beacons-to" for item in objects)
    assert not any(item.get("relationship_type") == "communicates-with" for item in objects)
    assert not any(item["type"] == "infrastructure" and item["id"] == stix._identifier("infrastructure", "infra:endpoint:cert-pivot") for item in objects)
    assert any(item["type"] == "note" and "通信未観測" in item["content"] for item in objects)
    assert any(item["type"] == "note" and "非C2の攻撃補助 endpoint" in item["content"] for item in objects)
    assert not any(item["type"] == "note" and "C2 endpoint" in item["content"] for item in objects)


def test_certificate_only_observation_preserves_service_port(tmp_path: Path) -> None:
    data = _knowledge()
    pivot = data["endpoints"][1]
    pivot["first_observed"] = "2026-09-20T01:00:00Z"
    pivot["last_observed"] = "2026-09-20T01:00:00Z"
    output, index = stix.generate(_repo(tmp_path, data), date(2026, 9, 21))
    assert index["safety"]["historical_live_observation_in_sources"] is True
    bundle = json.loads(output["bundle.json"])
    objects = bundle["objects"]
    observed = next(item for item in objects if item["type"] == "observed-data" and item["id"] == stix._identifier("observed-data", "infra:cert-observed:cert-pivot"))
    observed_objects = [item for item in objects if item["id"] in observed["object_refs"]]
    service = next(item for item in observed_objects if item["type"] == "network-traffic")
    assert service["dst_port"] == 443
    assert service["protocols"] == ["tcp", "tls"]
    assert any(item.get("relationship_type") == "related-to" and item["source_ref"] == service["id"] for item in observed_objects)


def test_sample_embedded_pin_is_not_server_certificate_observation(tmp_path: Path) -> None:
    data = _knowledge()
    data["certificates"].append({
        "id": "expected-pin", "sha256": "d" * 64,
        "evidence_role": "sample-embedded-pin", "source_ids": ["report"],
    })
    data["endpoints"][0].pop("certificate_id")
    data["endpoints"][0]["expected_certificate_id"] = "expected-pin"
    data["endpoints"][0]["evidence_kind"] = "sample-config"
    data["endpoints"][0].pop("first_observed")
    data["endpoints"][0].pop("last_observed")
    output, _ = stix.generate(_repo(tmp_path, data), date(2026, 9, 21))
    objects = json.loads(output["bundle.json"])["objects"]
    expected = next(item for item in objects if item["type"] == "x509-certificate" and item["hashes"].get("SHA-256") == "d" * 64)
    assert any(item["type"] == "note" and "実サーバーが提示したという観測ではない" in item["content"] and expected["id"] in item["object_refs"] for item in objects)
    assert not any(item.get("relationship_type") == "consists-of" and item["target_ref"] == expected["id"] for item in objects)
    assert not any(item["type"] == "observed-data" and expected["id"] in item["object_refs"] for item in objects)

    data["endpoints"][0].pop("expected_certificate_id")
    data["endpoints"][0]["certificate_id"] = "expected-pin"
    with pytest.raises(ValueError, match="検体内pin"):
        stix._validate(data)
    data["endpoints"][0].pop("certificate_id")
    data["endpoints"][0]["expected_certificate_id"] = "expected-pin"
    data["certificates"][-1].pop("evidence_role")
    with pytest.raises(ValueError, match="期待証明書"):
        stix._validate(data)


def test_primary_analysis_c2_does_not_invent_sample_beacon(tmp_path: Path) -> None:
    data = _knowledge()
    endpoint = data["endpoints"][0]
    endpoint["evidence_kind"] = "primary-analysis"
    endpoint.pop("first_observed")
    endpoint.pop("last_observed")
    objects = json.loads(stix.generate(_repo(tmp_path, data), date(2026, 9, 21))[0]["bundle.json"])["objects"]
    target = stix._identifier("infrastructure", "infra:endpoint:known-c2")
    assert any(item.get("relationship_type") == "uses" and item["target_ref"] == target and item["source_ref"].startswith("malware--") for item in objects)
    assert not any(item.get("relationship_type") == "beacons-to" and item["target_ref"] == target for item in objects)
    assert not any(item["type"] == "observed-data" for item in objects)

    endpoint["evidence_kind"] = "osint-report"
    with pytest.raises(ValueError, match="confirmed-c2"):
        stix._validate(data)


def test_static_config_c2_uses_infrastructure_without_beacon_or_observation(tmp_path: Path) -> None:
    data = _knowledge()
    endpoint = data["endpoints"][0]
    endpoint["evidence_kind"] = "sample-config"
    endpoint.pop("first_observed")
    endpoint.pop("last_observed")
    objects = json.loads(stix.generate(_repo(tmp_path, data), date(2026, 9, 21))[0]["bundle.json"])["objects"]
    target = stix._identifier("infrastructure", "infra:endpoint:known-c2")
    assert any(item.get("relationship_type") == "uses" and item.get("target_ref") == target and "静的設定" in item.get("description", "") for item in objects)
    assert not any(item.get("relationship_type") == "beacons-to" and item["target_ref"] == target for item in objects)
    assert not any(item["type"] in {"indicator", "observed-data"} for item in objects)

    endpoint["first_observed"] = "2026-09-19T01:00:00Z"
    endpoint["last_observed"] = "2026-09-20T01:00:00Z"
    with pytest.raises(ValueError, match="観測日時"):
        stix._validate(data)


def test_fdmtp_certificate_pivot_matches_local_observation_and_historical_dns() -> None:
    repository = Path(__file__).parents[2]
    data = json.loads((repository / "analysis-framework/knowledge/stix_infrastructure_curated.json").read_text(encoding="utf-8"))
    source = json.loads((repository / "analysis-results/research/daily-news-malware/2026-08-06/infrastructure-summary.json").read_text(encoding="utf-8"))
    pivot = {item["ip"]: item for item in data["endpoints"] if item["id"].startswith("fdmtp-tls-") and "ip" in item}
    observed = {
        item["host"]: item["probed_at"].replace("+00:00", "Z")
        for item in source["results"]
        if item.get("tls", {}).get("certificate_sha256") == "ffe0435800af23ac24e6ab0b4b6f44de63de578138ad6db5f459049d572537e8"
        and item.get("tls", {}).get("status") == "ok"
    }
    assert len(pivot) == len(observed) == 25
    assert set(pivot) == set(observed)
    for address, endpoint in pivot.items():
        assert endpoint["first_observed"] == endpoint["last_observed"] == observed[address]
        assert endpoint["classification"] == "pivot-only"
        assert endpoint["evidence_kind"] == "certificate-only"
        assert "family_id" not in endpoint
    historical = {
        item["ip"] for item in data["dns_resolutions"]
        if item["domain"] == "www.wangmeng66.top" and "fortinet-quickfox-fdmtp" in item["source_ids"]
    }
    assert historical == set(pivot)
    domain_probe = next(item for item in source["results"] if item["host"] == "www.wangmeng66.top")
    assert domain_probe["tls"]["certificate_sha256"] == "f3aa1b05947d9434e3bd46ab323c070db4adde159a018b5386593d310aab7dfb"
    assert domain_probe["tls"]["certificate_sha256"] != next(
        item["sha256"] for item in data["certificates"] if item["id"] == "fdmtp-staging-shared-leaf"
    )
    sni_endpoint = next(item for item in data["endpoints"] if item["id"] == "fdmtp-tls-wangmeng66-sni")
    assert sni_endpoint["domain"] == "www.wangmeng66.top"
    assert sni_endpoint["certificate_id"] == "fdmtp-staging-domain-sni-leaf"
    assert sni_endpoint["classification"] == "pivot-only"
    assert "ip" not in sni_endpoint
    current_dns = {
        item["ip"] for item in data["dns_resolutions"]
        if item["domain"] == "www.wangmeng66.top" and "local-fdmtp-cert-observation" in item["source_ids"]
    }
    assert current_dns == set(domain_probe["dns"]["addresses"])
    assert current_dns - historical == {"13.231.163.122", "45.125.35.228"}
    direct_nodes = {item["ip"] for item in data["endpoints"] if item["id"].startswith("fdmtp-node-")}
    assert not direct_nodes & set(pivot)


def test_curated_remcos_five_destinations_keep_listener_and_certificate_boundaries() -> None:
    repository = Path(__file__).parents[2]
    data = json.loads((repository / "analysis-framework/knowledge/stix_infrastructure_curated.json").read_text(encoding="utf-8"))
    endpoints = {item["id"]: item for item in data["endpoints"]}
    confirmed = {"remcos-censys-rem25rem", "remcos-censys-sosten38999", "remcos-censys-gotemburgoxm"}
    configured = {"remcos-censys-trabajonuevos", "remcos-censys-remc21"}
    for endpoint_id in confirmed:
        assert endpoints[endpoint_id]["classification"] == "confirmed-c2"
    for endpoint_id in configured:
        assert endpoints[endpoint_id]["classification"] == "configured-only"
        assert endpoints[endpoint_id]["evidence_kind"] == "sample-config"
        assert "certificate_id" not in endpoints[endpoint_id]
    assert "certificate_id" not in endpoints["remcos-censys-gotemburgoxm"]
    campaign = next(item for item in data["campaigns"] if item["id"] == "remcos-sostener-2025")
    grouping = next(item for item in data["groupings"] if item["id"] == "remcos-censys-five-configs")
    assert set(campaign["endpoint_ids"]) == confirmed
    assert set(grouping["endpoint_ids"]) == confirmed | configured
    history = {
        item["ip"] for item in data["dns_resolutions"]
        if item["domain"] == "gotemburgoxm.duckdns.org"
    }
    assert history == {"188.126.90.5", "46.246.6.2", "46.246.12.11", "46.246.14.2"}


def test_curated_fdmtp_staging_domains_do_not_become_direct_c2() -> None:
    repository = Path(__file__).parents[2]
    data = json.loads((repository / "analysis-framework/knowledge/stix_infrastructure_curated.json").read_text(encoding="utf-8"))
    staging = [item for item in data["endpoints"] if item.get("family_id") == "fdmtp" and item.get("role") == "resolver"]
    assert {item["domain"] for item in staging} == {
        "www.wangmeng66.top", "www.yahoo-cdn.it.com", "www.google-apis.net",
        "www.icloud-cdn.net", "www.wangmeng.xyz", "www.wangmengsb.com",
        "www.techcheck1.com",
    }
    assert all(item["classification"] == "confirmed-auxiliary" for item in staging)


def test_contract_config_keeps_reported_period_without_fabricated_observation(tmp_path: Path) -> None:
    data = _knowledge()
    endpoint = data["endpoints"][0]
    endpoint.pop("ip")
    endpoint.pop("port")
    endpoint.pop("first_observed")
    endpoint.pop("last_observed")
    endpoint["domain"] = "contract.example.org"
    endpoint["evidence_kind"] = "contract-config"
    endpoint["period_ja"] = "2026-06-30から2026-07-30の契約履歴。"
    bundle = json.loads(stix.generate(_repo(tmp_path, data), date(2026, 9, 21))[0]["bundle.json"])
    objects = bundle["objects"]
    assert any(item["type"] == "note" and "2026-06-30から2026-07-30" in item["content"] and "オンチェーン契約" in item["content"] for item in objects)
    assert any(item.get("relationship_type") == "uses" and item["source_ref"].startswith("malware--") and "通信や現時点の稼働は観測されていない" in item["description"] for item in objects)
    assert not any(item.get("relationship_type") == "beacons-to" for item in objects)
    assert not any(item["type"] == "indicator" for item in objects)
    assert not any(item["type"] == "observed-data" for item in objects)


def test_patchcord_single_ip_does_not_turn_tls_pivot_into_c2() -> None:
    repository = Path(__file__).parents[2]
    data = json.loads((repository / "analysis-framework/knowledge/stix_infrastructure_curated.json").read_text(encoding="utf-8"))
    source = json.loads((repository / "analysis-results/research/daily-news-malware/2026-08-15/infrastructure-summary.json").read_text(encoding="utf-8"))
    matching = [
        item for item in source["results"]
        if item.get("tls", {}).get("certificate_sha256") == "b22c77c7f99555480b5be2e605d4f1ef2ab956182388f87388e4cdad40a7b61a"
    ]
    assert len(matching) == 14
    assert {address for item in matching for address in item["dns"]["addresses"]} == {"46.30.188.13"}
    observed_domains = {item["host"] for item in matching if item["host"] != "46.30.188.13"}
    recorded_domains = {item["domain"] for item in data["dns_resolutions"] if item["ip"] == "46.30.188.13"}
    assert observed_domains == recorded_domains
    endpoints = {item["id"]: item for item in data["endpoints"]}
    certificate_observations = {
        item["domain"]: item for item in data["endpoints"]
        if item["id"].startswith("patchcord-443-") and "domain" in item
    }
    assert set(certificate_observations) == observed_domains
    for observed in matching:
        if observed["host"] == "46.30.188.13":
            continue
        endpoint = certificate_observations[observed["host"]]
        observed_utc = datetime.fromisoformat(observed["probed_at"]).astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
        assert endpoint["first_observed"] == endpoint["last_observed"] == observed_utc
        assert endpoint["certificate_id"] == "patchcord-shared-443-leaf"
        assert endpoint["classification"] == "pivot-only"
    assert endpoints["patchcord-appstoore-8080"]["port"] == 8080
    assert endpoints["patchcord-c2-ip-8080"]["port"] == 8080
    pivot = endpoints["patchcord-443-cert-pivot"]
    assert pivot["port"] == 443
    assert pivot["classification"] == "pivot-only"
    assert "family_id" not in pivot
    campaign = next(item for item in data["campaigns"] if item["id"] == "patchcord-south-asia-2026")
    assert "patchcord-443-cert-pivot" not in campaign["endpoint_ids"]
    assert "sheetcord-nic-support-delivery" not in campaign["endpoint_ids"]


def test_asyncrat_ncc_config_is_not_joined_to_censys_certificate() -> None:
    repository = Path(__file__).parents[2]
    data = json.loads((repository / "analysis-framework/knowledge/stix_infrastructure_curated.json").read_text(encoding="utf-8"))
    ncc = [item for item in data["endpoints"] if item["id"].startswith(("asyncrat-ncc-hone-", "asyncrat-ncc-mora-"))]
    assert len(ncc) == 8
    assert {(item["domain"], item["port"]) for item in ncc} == {
        (domain, port)
        for domain in ("hone32.work.gd", "mora1987.work.gd")
        for port in (1800, 1801, 1802, 1803)
    }
    assert all(item["evidence_kind"] == "sample-config" and "certificate_id" not in item for item in ncc)
    certificate = next(item for item in data["certificates"] if item["id"] == "asyncrat-censys-fingerprint")
    assert certificate["evidence_role"] == "osint-report"
    assert not any(item.get("certificate_id") == certificate["id"] for item in data["endpoints"])
    pivots = [item for item in data["endpoints"] if item["id"].startswith("asyncrat-ncc-pivot-")]
    assert len(pivots) == 19
    assert all(item["classification"] == "reported-c2" and "port" not in item and "family_id" not in item for item in pivots)
