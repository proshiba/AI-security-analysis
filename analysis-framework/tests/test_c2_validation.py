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

    def fake_probe(target, **kwargs):
        calls.append((target, kwargs))
        return {
            "status": "tcp_open_no_banner",
            "execution_engine": "nmap_nse",
            "alive": True,
            "c2_confirmed": False,
            "target_contact_attempted": True,
            "application_data_sent": False,
        }

    monkeypatch.setattr(c2_validation, "probe_target_with_nmap", fake_probe)
    value = c2_validation.validate_candidates(manifest(), allow_network=True)
    assert len(calls) == 1
    assert calls[0][0]["sample_sha256s"] == ["a" * 64, "b" * 64]
    assert calls[0][1]["allow_network"] is True
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
        "probe_target_with_nmap",
        lambda _args: pytest.fail("non-C2 endpoint must be skipped"),
    )
    result = c2_validation.validate_candidates(value, allow_network=True)
    candidate = result["samples"][0]["candidate_results"][0]
    assert candidate["status"] == "not_performed_non_c2_role"
    assert candidate["network_contacted"] is False
    assert result["samples"][0]["c2_connection_validation_status"] == "not_applicable"
    assert result["samples"][0]["non_c2_connection_validation_status"] == "not_performed_by_policy"


def test_tor_candidate_is_not_contacted_outside_nmap(
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
    monkeypatch.setattr(c2_validation, "probe_target_with_nmap", lambda *_args, **_kwargs: pytest.fail(
        "unsupported transport must not invoke Nmap"
    ))
    result = c2_validation.validate_candidates(value, allow_network=True)
    sample = result["samples"][0]
    candidate = sample["candidate_results"][0]
    assert sample["connection_validation_status"] == "not_performed_by_policy"
    assert candidate["status"] == "nmap_transport_unsupported"
    assert candidate["target_contact_attempted"] is False


def test_udp_candidate_is_not_contacted_outside_nmap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    value = manifest()
    value["samples"] = [{
        "sha256": "9" * 64,
        "family": "softbot",
        "c2_resolution_status": "recovered",
        "candidates": [{
            "host": "217.60.195.187",
            "port": 18129,
            "protocol": "udp",
            "role": "c2",
            "source": "静的sockaddr",
        }],
    }]
    monkeypatch.setattr(c2_validation, "probe_target_with_nmap", lambda *_args, **_kwargs: pytest.fail(
        "unsupported UDP must not invoke Nmap"
    ))
    result = c2_validation.validate_candidates(value, allow_network=True)
    candidate = result["samples"][0]["candidate_results"][0]
    assert candidate["status"] == "nmap_udp_transport_unsupported"
    assert candidate["target_contact_attempted"] is False
    assert result["policy"]["network_execution_backend"] == "nmap_nse_only"
    assert result["policy"]["python_direct_probe_used"] is False


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
