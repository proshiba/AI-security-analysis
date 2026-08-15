"""ACRStealer v4 memory復元値をDDR、最終C2、protocolへ意味付けする。"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

from .v4_memory import V4MemoryProfile, extract_v4_memory_profile

DEAD_DROP_HOSTS = {"telegra.ph", "steamcommunity.com", "t.me", "telegram.me"}


@dataclass(frozen=True)
class V4StaticConfig:
    """memory image単体から確定できる設定と未解決境界。"""

    version: str | None
    final_c2_urls: tuple[str, ...]
    final_c2_hosts: tuple[str, ...]
    final_c2_paths: tuple[str, ...]
    dead_drop_urls: tuple[str, ...]
    dns_resolvers: tuple[str, ...]
    decoy_hosts: tuple[str, ...]
    guids: tuple[str, ...]
    user_agent: str | None
    string_key_hex: str
    protocol_fingerprint: tuple[str, ...]
    protocol_confidence: str
    active_registration_supported: bool
    unresolved_fields: tuple[str, ...]
    decoded_count: int
    layout: str
    generic_domain_findings: tuple[str, ...] = ()


def _host(value: str) -> str:
    return (urlsplit(value).hostname or "").lower()


def _protocol_fingerprint(strings: tuple[str, ...]) -> tuple[str, ...]:
    values = set(strings)
    lowered = {value.lower() for value in strings}
    markers: list[str] = []
    if "Microsoft Unified Security Protocol Provider" in values and "HTTP/1.1" in values:
        markers.append("sspi_tls_http_1_1")
    if {"POST", "Host", "Content-Length"}.issubset(values):
        markers.append("http_request_builder")
    if "/dns-query" in values and "application/dns-message" in values:
        markers.append("dns_over_https_resolver")
    # hostnameのwss prefixだけをWebSocket根拠にしない。
    if "sec-websocket-key" in lowered and "upgrade" in lowered and "websocket" in lowered:
        markers.append("rfc6455_websocket_upgrade")
    if "r.]" in values and ")0(" in values:
        markers.append("dead_drop_delimiter_pair")
    return tuple(markers)


def build_v4_config(profile: V4MemoryProfile) -> V4StaticConfig:
    """復号profileを誤ったC2昇格なしに静的設定へ変換する。"""

    dead_drop_urls = tuple(
        sorted(value for value in profile.c2_urls if _host(value) in DEAD_DROP_HOSTS)
    )
    final_c2_urls = tuple(
        sorted(value for value in profile.c2_urls if _host(value) not in DEAD_DROP_HOSTS)
    )
    excluded = set(profile.dns_resolvers) | set(profile.decoy_hosts) | DEAD_DROP_HOSTS
    url_hosts = {_host(value) for value in final_c2_urls}
    final_c2_hosts = tuple(
        sorted(
            value
            for value in profile.c2_hosts
            if value not in excluded and value in url_hosts
        )
    )
    final_hosts = set(final_c2_hosts)
    final_c2_paths = tuple(
        sorted(
            {
                urlsplit(value).path
                for value in final_c2_urls
                if _host(value) in final_hosts and urlsplit(value).path not in {"", "/"}
            }
        )
    )
    fingerprint = _protocol_fingerprint(profile.decoded_strings)
    unresolved: list[str] = []
    if not final_c2_hosts:
        unresolved.append("final_c2_endpoint")
    if final_c2_hosts and not final_c2_paths:
        unresolved.append("final_c2_path")
    if not profile.user_agent:
        unresolved.append("runtime_user_agent")
    if dead_drop_urls:
        unresolved.append("dead_drop_response_value")
    unresolved.append("request_body_schema_and_crypto")
    return V4StaticConfig(
        version=profile.version,
        final_c2_urls=final_c2_urls,
        final_c2_hosts=final_c2_hosts,
        final_c2_paths=final_c2_paths,
        dead_drop_urls=dead_drop_urls,
        dns_resolvers=profile.dns_resolvers,
        decoy_hosts=profile.decoy_hosts,
        guids=profile.guids,
        user_agent=profile.user_agent,
        string_key_hex=profile.string_key_hex,
        protocol_fingerprint=fingerprint,
        protocol_confidence="high" if len(fingerprint) >= 3 else "medium",
        active_registration_supported=False,
        unresolved_fields=tuple(sorted(set(unresolved))),
        decoded_count=profile.decoded_count,
        layout=profile.layout,
        generic_domain_findings=profile.generic_domain_findings,
    )


def extract_v4_config(data: bytes) -> V4StaticConfig | None:
    """取得済みPE memory imageからACRStealer v4設定を静的に復元する。"""

    profile = extract_v4_memory_profile(data)
    return build_v4_config(profile) if profile is not None else None


__all__ = ["V4StaticConfig", "build_v4_config", "extract_v4_config"]
