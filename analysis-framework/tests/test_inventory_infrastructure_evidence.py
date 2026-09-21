"""インフラ棚卸しCLIの証拠階層と秘密値非公開を検証する。"""

from __future__ import annotations

import json
from pathlib import Path
import sys

import pytest


COMMON = Path(__file__).parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import inventory_infrastructure_evidence as inventory  # noqa: E402


def _write(path: Path, document: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, ensure_ascii=False), encoding="utf-8")


def test_network_evidence_tiers_and_secret_exclusions(tmp_path: Path) -> None:
    path = tmp_path / "analysis-results/malware/test-rat/versions/unknown/cases/" / ("a" * 64) / "iocs.json"
    _write(path, {"network": [
        {"host": "c2.example", "port": 443, "role": "configured_c2", "confidence": "confirmed_static_configuration", "reachability": "not_tested", "source": "handler:test"},
        {"value": "https://control.example/ping", "role": "beacon_or_tasking", "confidence": "confirmed_static"},
        {"value": "https://candidate.example", "role": "c2_candidate", "confidence": "medium"},
        {"value": "https://sandbox.example", "role": "c2_candidate_external_sandbox_config", "confidence": "medium_external_sandbox_exact_hash"},
        {"value": "https://unknown.example", "role": "reported_network_ioc_c2_unverified", "confidence": "external_unverified"},
        {"value": "https://eth-sepolia.g.alchemy.com/v2/secret", "role": "configured_c2", "confidence": "confirmed_static"},
        {"value": "https://private.example/api?token=secret", "role": "configured_c2", "confidence": "confirmed_static"},
        {"value": "https://user:secret@host.example/", "role": "configured_c2", "confidence": "confirmed_static"},
        {"value": "https://context.example", "role": "context_only", "confidence": "confirmed_static"},
        {"value": "0xabcdef", "role": "wallet_replacement_configuration", "confidence": "confirmed_static"},
        {"value": "https://shared.example", "role": "configured_c2", "confidence": "confirmed_static", "shared_service": True},
        {"value": "https://other.example", "role": "secret=do-not-publish", "confidence": "medium"},
    ]})
    result = inventory.inventory(tmp_path)
    assert result["evidence_tiers"]["static_config_supported_c2"] == 2
    assert result["evidence_tiers"]["c2_candidate_not_confirmed"] == 1
    assert result["evidence_tiers"]["external_sandbox_candidate"] == 1
    assert result["evidence_tiers"]["external_unverified"] == 1
    assert result["counts"]["excluded_unsafe_or_shared_value"] == 3
    assert result["counts"]["excluded_shared_service"] == 1
    assert result["counts"]["excluded_context_or_non_c2"] == 2
    assert result["counts"]["unique_static_config_c2_values"] == 2
    assert result["network_observation_states"]["not_tested"] == 1
    assert "live_protocol_confirmed" not in result["network_observation_states"]
    assert result["network_source_classes"]["static_handler"] == 1
    serialized = json.dumps(result)
    assert "secret=" not in serialized
    assert "c2.example" not in serialized


def test_certificate_dns_and_ct_are_counts_not_family_proof(tmp_path: Path) -> None:
    _write(tmp_path / "analysis-results/clickfix/example.org/cases/one/infrastructure.json", {
        "evidence_layers": {
            "active_bounded_get": {
                "reachable": True,
                "tls_certificates": [{"sha256": "a" * 64, "subject": "CN=example.org"}],
            },
            "certificate_transparency": {"entries": [1]},
            "domain_rdap": {"registrar": "example"},
            "current_passive_dns": {"A": {"records": ["203.0.113.7"]}, "AAAA": {"records": []}},
            "historical_passive_dns": {"status": "not_collected"},
        },
    })
    result = inventory.inventory(tmp_path)
    counts = result["counts"]
    assert counts["files_with_tls_certificate"] == 1
    assert counts["unique_tls_certificate_sha256"] == 1
    assert counts["files_with_ct_data"] == 1
    assert counts["files_with_current_dns"] == 1
    assert counts["current_dns_records"] == 1
    assert "files_with_historical_passive_dns" not in counts
    assert result["assessment_boundary"]["certificate_or_dns_is_family_attribution"] is False
    assert "203.0.113.7" not in json.dumps(result)


def test_malformed_ioc_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "analysis-results/malware/test-rat/iocs.json"
    _write(path, {"network": "not-a-list"})
    with pytest.raises(ValueError, match="network"):
        inventory.inventory(tmp_path)


def test_network_value_validator_rejects_shared_and_sensitive() -> None:
    assert inventory._safe_network_value("https://sepolia.infura.io/v3/key") is None
    assert inventory._safe_network_value("https://example.org/?token=x") is None
    assert inventory._safe_network_value("https://user:pass@example.org/") is None
    assert inventory._safe_network_value("127.0.0.1:443") is None
    assert inventory._safe_network_value("example.org:443") == "example.org:443"
