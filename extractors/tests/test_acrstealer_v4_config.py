from __future__ import annotations

from extractors.acrstealer.v4_config import build_v4_config
from extractors.acrstealer.v4_memory import V4MemoryProfile


def test_dead_drop_is_not_promoted_to_final_c2() -> None:
    profile = V4MemoryProfile(
        version="4.3.2-alpha3",
        c2_urls=("https://telegra.ph/Executing-modules-as-scripts-06-16",),
        c2_hosts=("telegra.ph", "wss.infrastructurecore.cc"),
        c2_paths=("/Executing-modules-as-scripts-06-16", "/dns-query"),
        decoy_hosts=("keycdn.com",),
        dns_resolvers=("cloudflare-dns.com", "dns.google"),
        guids=("a6cdcc0b-6b38-49d6-9672-20be114d9eba",),
        user_agent=None,
        decoded_strings=(
            "Microsoft Unified Security Protocol Provider",
            "HTTP/1.1",
            "POST",
            "Host",
            "Content-Length",
            "/dns-query",
            "application/dns-message",
            "r.]",
            ")0(",
        ),
        decoded_count=573,
        decryptor_address=0x471F35,
        string_key_hex="e39310a767d939a4",
        string_key_sha256="unused",
        layout="memory_mapped",
        evidence_categories=("browser_collection", "network_endpoint", "network_protocol"),
        generic_domain_findings=("wss.infrastructurecore.cc",),
    )
    config = build_v4_config(profile)
    assert config.dead_drop_urls == (
        "https://telegra.ph/Executing-modules-as-scripts-06-16",
    )
    assert config.final_c2_urls == ()
    assert config.final_c2_hosts == ()
    assert config.generic_domain_findings == ("wss.infrastructurecore.cc",)
    assert "final_c2_endpoint" in config.unresolved_fields
    assert config.active_registration_supported is False
    assert "rfc6455_websocket_upgrade" not in config.protocol_fingerprint
    assert config.protocol_confidence == "high"
