from __future__ import annotations

import sys
from pathlib import Path

import pytest


COMMON = Path(__file__).parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import c2_validation  # noqa: E402


def manifest() -> dict:
    return {
        "batch_id": "fixture-0001",
        "samples": [
            {
                "sha256": "a" * 64,
                "family": "fixture",
                "c2_resolution_status": "recovered",
                "candidates": [
                    {
                        "host": "c2.example",
                        "port": 69,
                        "protocol": "tcp",
                        "role": "c2",
                        "source": "fixture offset 0x100",
                    }
                ],
            },
            {
                "sha256": "b" * 64,
                "family": "fixture",
                "c2_resolution_status": "recovered",
                "candidates": [
                    {
                        "host": "c2.example",
                        "port": 69,
                        "protocol": "tcp",
                        "role": "c2",
                        "source": "fixture offset 0x100",
                    }
                ],
            },
            {
                "sha256": "c" * 64,
                "family": "fixture",
                "c2_resolution_status": "not_recovered",
                "candidates": [],
            },
        ],
    }


def test_deduplicates_probe_and_associates_every_sample(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []

    def fake_probe(args):
        calls.append(args)
        return {
            "status": "tcp_open_no_banner",
            "alive": True,
            "c2_confirmed": False,
            "network_contacted": True,
            "application_data_sent": False,
            "sample_sha256s": args.sample_sha256,
            "target_role": args.target_role,
        }

    monkeypatch.setattr(c2_validation, "probe", fake_probe)
    value = c2_validation.validate_candidates(manifest(), allow_network=True)
    assert len(calls) == 1
    assert calls[0].sample_sha256 == ["a" * 64, "b" * 64]
    assert value["sample_count"] == 3
    assert value["unique_probe_count"] == 1
    assert value["samples"][0]["candidate_results"][0]["deduplicated_probe"] is True
    assert value["samples"][2]["connection_validation_status"] == (
        "not_performed_no_exact_target"
    )
    assert value["samples"][2]["c2_connection_validation_status"] == (
        "not_performed_no_exact_target")


def test_non_c2_endpoint_is_not_contacted_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    value = manifest()
    value["samples"] = [
        {
            "sha256": "d" * 64,
            "family": "fixture",
            "c2_resolution_status": "not_applicable",
            "candidates": [
                {
                    "host": "delivery.example",
                    "port": 80,
                    "protocol": "http",
                    "role": "distribution",
                    "source": "shell URL",
                }
            ],
        }
    ]
    monkeypatch.setattr(
        c2_validation,
        "probe",
        lambda _args: pytest.fail("non-C2 endpoint must be skipped"),
    )
    result = c2_validation.validate_candidates(value, allow_network=True)
    candidate = result["samples"][0]["candidate_results"][0]
    assert candidate["status"] == "not_performed_non_c2_role"
    assert candidate["network_contacted"] is False
    assert result["samples"][0]["c2_connection_validation_status"] == "not_applicable"
    assert result["samples"][0]["non_c2_connection_validation_status"] == "not_performed_by_policy"


def test_tor_candidate_uses_loopback_socks5(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    value = {
        "batch_id": "fixture-tor",
        "samples": [
            {
                "sha256": "f" * 64,
                "family": "fixture",
                "c2_resolution_status": "recovered",
                "candidates": [
                    {
                        "host": "exampleexampleexampleexampleexampleexampleexampleexample.onion",
                        "port": 80,
                        "protocol": "http",
                        "role": "c2",
                        "transport": "tor-socks5",
                        "source": "decrypted fixture string",
                    }
                ],
            }
        ],
    }
    calls = []

    def fake_probe(args):
        calls.append(args)
        return {
            "status": "tcp_open_no_banner",
            "alive": True,
            "c2_confirmed": False,
            "network_contacted": True,
            "application_data_sent": False,
            "target_role": args.target_role,
            "sample_sha256s": args.sample_sha256,
        }

    monkeypatch.setattr(c2_validation, "probe", fake_probe)
    result = c2_validation.validate_candidates(value, allow_network=True)
    sample = result["samples"][0]
    assert sample["connection_validation_status"] == "performed"
    assert calls[0].proxy_host == "127.0.0.1"
    assert calls[0].proxy_port == 9050
    assert sample["candidate_results"][0]["transport"] == "tor-socks5"


@pytest.mark.parametrize(
    "candidate",
    [
        {"host": "10.0.0.0/8", "port": 80, "source": "bad"},
        {"host": "c2.example", "port": 80, "ports": [80, 443], "source": "bad"},
        {"host": "c2.example", "port": 80, "send_hex": "00", "source": "bad"},
        {"host": "c2.example", "port": 80, "timeout": 6, "source": "bad"},
        {"host": "c2.example", "port": 80, "max_bytes": 257, "source": "bad"},
        {"host": "c2.example", "port": 80, "protocol": "vvas", "source": "bad"},
        {
            "host": "exampleexampleexampleexampleexampleexampleexampleexample.onion",
            "port": 80,
            "source": "bad",
        },
    ],
)
def test_rejects_scan_ranges_payloads_and_excessive_bounds(candidate: dict) -> None:
    value = {
        "batch_id": "fixture",
        "samples": [
            {
                "sha256": "e" * 64,
                "c2_resolution_status": "recovered",
                "candidates": [candidate],
            }
        ],
    }
    with pytest.raises(c2_validation.ManifestError):
        c2_validation.validate_manifest(value)
