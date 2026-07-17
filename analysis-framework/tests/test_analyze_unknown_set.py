"""Tests for unknown-batch attribution, IOC sanitation, and clustering."""

from __future__ import annotations

import analyze_unknown_set as unknown

from analyze_unknown_set import (
    cluster_cases,
    external_evidence,
    ioc_worthy_url,
    internal_family_compatible,
    irahook_shape,
    family_from_text,
    normalize_case_iocs,
    resolve_attribution,
    sanitize_ip_candidate,
    sanitize_url,
)


def test_family_tokens_and_external_evidence() -> None:
    """Accept specific family tokens while ignoring generic stealer labels."""
    assert family_from_text("GenesisStealer_Installer_NSIS_MaaS_Template") == "genesisstealer"
    assert family_from_text("infostealer") is None
    evidence = external_evidence({
        "tags": ["infostealer", "Vidar"],
        "yara_rules": [{"rule_name": "GenesisStealer_Installer_NSIS_MaaS_Template"}],
        "vendor_intel": {
            "CAPE": [{"detection": "Stealc"}],
            "UnpacMe": ["unexpected", {"detection": "AgentTesla"}],
        },
    })
    assert {item["family"] for item in evidence} == {"vidar", "genesisstealer", "stealc", "agenttesla"}


def test_attribution_requires_internal_or_independent_evidence() -> None:
    """Keep tag-only family labels low and raise corroborated labels to high."""
    low = resolve_attribution([{"family": "vidar", "source": "source_tag", "detail": "Vidar"}])
    assert low["family"] == "vidar" and low["confidence"] == "low"
    high = resolve_attribution([
        {"family": "vidar", "source": "source_tag", "detail": "Vidar"},
        {"family": "vidar", "source": "internal_detector", "detail": "matched"},
        {"family": "vidar", "source": "internal_yara", "detail": "rule"},
    ])
    assert high["confidence"] == "high"


def test_sanitize_url_and_cluster_determinism() -> None:
    """Strip secrets from URLs and prefer family cluster keys deterministically."""
    assert sanitize_url("https://user:pass@example.test:8443/gate?q=secret#x") == "https://example.test:8443/gate"
    assert sanitize_url("https://discord.com/api/webhooks/123456/SECRET-TOKEN") == "https://discord.com/api/webhooks/123456"
    assert sanitize_url("https://api.telegram.org/bot123456789:SECRET/getMe") == "https://api.telegram.org/bot[REDACTED]/getMe"
    assert sanitize_url("https://hooks.slack.com/services/T123/B456/SECRET") == "https://hooks.slack.com/services/T123/B456"
    assert not ioc_worthy_url("https://developer.mozilla.org/docs/Web/API")
    assert ioc_worthy_url("https://rare-c2.example.xyz/api/check")
    assert sanitize_ip_candidate("216.126.225.243:8085") == "216.126.225.243:8085"
    assert sanitize_ip_candidate("127.0.0.1") is None
    assert sanitize_ip_candidate("999.1.1.1") is None
    assert sanitize_ip_candidate("4.0.0.0") is None
    normalized = normalize_case_iocs({
        "source": {"file_type": "exe"},
        "iocs": {"urls": [], "ips": ["13.3.3.7", "216.126.225.243:8085"]},
    })
    assert normalized["iocs"]["ips"] == ["216.126.225.243:8085"]
    cases = [{
        "sha256": "a" * 64,
        "attribution": {"family": "vidar", "confidence": "medium"},
        "layers": [],
        "source": {"imphash": "x", "file_type": "exe"},
        "root_unpack": {"format": "pe"},
    }]
    assert cluster_cases(cases) == {"family:vidar:medium": ["a" * 64]}


def test_format_sensitive_attribution_and_irahook_shape() -> None:
    """Reject native StealC heuristics on Java and corroborate IRAHook shape."""
    assert internal_family_compatible("stealc", "pe")
    assert not internal_family_compatible("stealc", "java-class")
    assert irahook_shape(
        ["fabric.mod.json", "ira.m.EasySleep", "dev/mdma/qprotect/runtime/VM.class"],
        "zip",
    )
    assert not irahook_shape(["fabric.mod.json", "Prestige Client"], "zip")


def test_large_pe_uses_structural_mode_instead_of_root_skip(monkeypatch) -> None:
    """Keep oversized PEs eligible for bounded structural and reachable-CFG work."""
    monkeypatch.setattr(unknown, "ROOT_FULL_SCAN_LIMIT", 1)
    observed = []

    def fake_unpack(data: bytes, name: str, **_kwargs):
        observed.append((data, name))
        return (
            {
                "format": "pe",
                "unpack_status": "no_artifact_recovered",
                "recovered": [],
                "pe": {"classification": "suspected_packed"},
            },
            [],
        )

    monkeypatch.setattr(unknown, "unpack_bytes", fake_unpack)
    report, layers, retained, strings = unknown.recursive_layers(b"MZxx", "large.exe", None, False)
    assert observed and report["large_file_mode"] == "bounded_pe_structural_and_reachable_cfg"
    assert layers == [] and retained == [] and strings == []
