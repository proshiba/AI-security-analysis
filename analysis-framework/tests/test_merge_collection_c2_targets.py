from __future__ import annotations

import json
import sys
from pathlib import Path


COMMON = Path(__file__).parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import merge_collection_c2_targets as merger  # noqa: E402


def test_endpoint_rejects_generic_and_local_values() -> None:
    assert merger.endpoint_from_network({"confidence": "candidate", "url": "http://c2.example/a"}) is None
    assert merger.endpoint_from_network({
        "confidence": "confirmed_static_configuration",
        "url": "http://127.0.0.1:9050/a",
    }) is None
    assert merger.endpoint_from_network({
        "confidence": "confirmed_static_configuration",
        "url": "http://fixtureexamplefixtureexamplefixtureexamplefixtureexample.onion/a",
        "transport": "tor-socks5",
    }) == ("fixtureexamplefixtureexamplefixtureexamplefixtureexample.onion", 80, "tor-socks5")


def test_endpoint_accepts_confirmed_host_and_port() -> None:
    assert merger.endpoint_from_network({
        "confidence": "confirmed_static_configuration",
        "host": "c2.example",
        "port": 443,
        "transport": "https",
    }) == ("c2.example", 443, "direct")
    assert merger.endpoint_from_network({
        "confidence": "confirmed_static_configuration",
        "host": "c2.example",
        "port": 0,
    }) is None

def test_merge_preserves_existing_count_and_deduplicates_case() -> None:
    plan = {
        "schema_version": 1,
        "targets": [{
            "target_id": "fixture",
            "family": "Efimer",
            "host": "c2.example",
            "port": 80,
            "protocol": "tcp",
            "method": "tcp_connect",
            "transport": "direct",
            "sample_sha256s": ["a" * 64],
            "associated_case_count": 91,
            "analyzed_dates": ["2026-08-01"],
            "sources": ["existing"],
        }],
    }
    observation = {
        "host": "c2.example",
        "port": 80,
        "transport": "direct",
        "family": "Efimer",
        "sha256": "b" * 64,
        "role": "beacon_or_tasking",
        "source": "case/iocs.json:network[0]",
    }
    result = merger.merge_targets(plan, [observation, dict(observation)], "2026-08-02")
    target = result["plan"]["targets"][0]
    assert result["added_endpoints"] == 0
    assert result["added_case_links"] == 1
    assert target["associated_case_count"] == 92
    assert target["sample_sha256s"] == ["a" * 64, "b" * 64]
    assert target["analyzed_dates"] == ["2026-08-01", "2026-08-02"]


def test_collects_only_confirmed_collection_iocs(tmp_path: Path, monkeypatch) -> None:
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    (case_dir / "iocs.json").write_text(json.dumps({
        "network": [
            {
                "confidence": "confirmed_static_configuration",
                "url": "https://c2.example/path",
                "role": "tasking",
            },
            {"confidence": "candidate", "url": "https://noise.example/"},
        ]
    }), encoding="utf-8")
    collection = tmp_path / "collection"
    collection.mkdir()
    (collection / "publication-summary.json").write_text(json.dumps({
        "cases": [{
            "sha256": "c" * 64,
            "family": "Fixture",
            "case_path": str(case_dir),
            "confirmed_static_c2_observations": 1,
        }]
    }), encoding="utf-8")
    observations = merger.collect_confirmed_endpoints(collection)
    assert len(observations) == 1
    assert observations[0]["host"] == "c2.example"
    assert observations[0]["port"] == 443
