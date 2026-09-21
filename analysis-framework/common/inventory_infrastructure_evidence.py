#!/usr/bin/env python3
"""公開済みIOCとインフラ付帯情報の証拠階層を読み取り専用で棚卸しする。"""

from __future__ import annotations

import argparse
from collections import Counter
import ipaddress
import json
from pathlib import Path
import re
from urllib.parse import urlsplit


HEX_SHA256 = re.compile(r"[0-9a-fA-F]{64}\Z")
DOMAIN = re.compile(r"(?=.{1,253}\Z)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\Z")
CONFIG_C2_ROLES = {
    "beacon_or_tasking", "configured_c2", "c2", "c2_fallback", "c2_onion",
    "c2_url_from_static_config", "c2_domain_from_config", "c2_ipv4_from_static_config",
    "c2_endpoint_tcp_http_udp", "control", "stage_and_control", "stage_and_control_endpoint",
}
EXCLUDED_ROLES = {
    "wallet_replacement_configuration", "context_only", "not_ioc", "not_c2",
    "distribution_not_c2", "payload_distribution_not_c2",
}
PUBLIC_ROLE_LABELS = CONFIG_C2_ROLES | EXCLUDED_ROLES | {
    "c2_candidate", "c2_candidate_external_sandbox_config",
    "reported_network_ioc_c2_unverified", "file_exfiltration",
    "credential_exfiltration", "distribution", "distribution_url",
    "payload_distribution", "payload_distribution_url", "stage",
    "stage_download", "dead_drop_configuration", "static_url_candidate",
    "static_ip_candidate", "secondary_shell_candidate", "remote_management_relay",
}
SHARED_SERVICE_HOSTS = {
    "api.telegram.org", "ntfy.sh", "discord.com", "discordapp.com",
    "github.com", "raw.githubusercontent.com",
}


def _is_shared_service(host: str) -> bool:
    """共有APIや公開サービスを固有C2として数えない。"""
    host = host.lower().rstrip(".")
    return (
        host in SHARED_SERVICE_HOSTS
        or host.endswith(".infura.io")
        or host.endswith(".g.alchemy.com")
        or host.endswith(".alchemyapi.io")
    )


def _safe_network_value(value: object) -> str | None:
    """秘密値を含むURLと非公開IPを除外し、内部集計用の値だけ返す。"""
    if not isinstance(value, str) or not value or len(value) > 2048:
        return None
    if any(character in value for character in ("@", "?", "#", "\\", "\r", "\n")):
        return None
    try:
        parsed = urlsplit(value if "://" in value else "//" + value)
        if parsed.scheme and parsed.scheme not in {"http", "https"}:
            return None
        host = parsed.hostname
        port = parsed.port
    except ValueError:
        return None
    if not host or _is_shared_service(host):
        return None
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if not DOMAIN.fullmatch(host) or ("." not in host and not host.endswith(".onion")):
            return None
    else:
        if not address.is_global:
            return None
    if port is not None and not 1 <= port <= 65535:
        return None
    return value


def _record_network_value(item: dict) -> object:
    """既存IOCのvalue／url／host＋port形式を同じ検証入口へ渡す。"""
    if item.get("value") is not None:
        return item["value"]
    if item.get("url") is not None:
        return item["url"]
    host = item.get("host") or item.get("domain") or item.get("ip")
    if not isinstance(host, str):
        return None
    port = item.get("port")
    if port is None:
        return host
    if not isinstance(port, int) or isinstance(port, bool):
        return None
    return f"{host}:{port}"


def _read_json(path: Path) -> dict:
    """壊れた成果物を無視して過少集計しない。"""
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("JSONのルートがobjectではありません")
    return data


def inventory(repository: Path) -> dict:
    """値を公開せず、役割・証拠階層・観測状態のみ集計する。"""
    if not (repository / "analysis-results").is_dir():
        raise ValueError("analysis-results がありません")
    counts: Counter[str] = Counter()
    roles: Counter[str] = Counter()
    tiers: Counter[str] = Counter()
    families: Counter[str] = Counter()
    states: Counter[str] = Counter()
    source_classes: Counter[str] = Counter()
    certs: set[str] = set()
    config_endpoints: set[str] = set()

    malware_root = repository / "analysis-results" / "malware"
    for path in sorted(malware_root.rglob("iocs.json")):
        counts["malware_ioc_files"] += 1
        data = _read_json(path)
        family = path.relative_to(malware_root).parts[0]
        entries = data.get("network", [])
        if not isinstance(entries, list):
            raise ValueError("network が配列ではありません")
        for item in entries:
            counts["network_records"] += 1
            if not isinstance(item, dict):
                counts["excluded_invalid_record"] += 1
                continue
            role = str(item.get("role") or "unknown")
            confidence = str(item.get("confidence") or "unknown")
            roles[role if role in PUBLIC_ROLE_LABELS else "other_role"] += 1
            reachability = item.get("reachability")
            state = reachability if isinstance(reachability, str) and reachability in {"not_tested", "out_of_scope_onion"} else "unreviewed_or_not_recorded"
            states[state] += 1
            states["live_protocol_confirmed" if item.get("liveness_confirmed") is True else "live_protocol_not_confirmed"] += 1
            source = item.get("source")
            if isinstance(source, str) and source.startswith("handler:"):
                source_classes["static_handler"] += 1
            elif isinstance(source, str) and ("triage" in source.lower() or "sandbox" in source.lower()):
                source_classes["external_sandbox"] += 1
            elif isinstance(source, str) and ("ghidra" in source.lower() or "static_config" in source.lower()):
                source_classes["other_static_analysis"] += 1
            elif isinstance(source, str) and "dns" in source.lower():
                source_classes["dns_observation"] += 1
            else:
                source_classes["other_or_not_recorded"] += 1
            if role in EXCLUDED_ROLES or "context_only" in role or "not_c2" in role:
                counts["excluded_context_or_non_c2"] += 1
                continue
            if role == "c2_candidate_external_sandbox_config":
                tiers["external_sandbox_candidate"] += 1
                continue
            if confidence in {"external_unverified", "unverified"}:
                tiers["external_unverified"] += 1
                continue
            if item.get("shared_service") is True:
                counts["excluded_shared_service"] += 1
                continue
            value = _safe_network_value(_record_network_value(item))
            if value is None:
                counts["excluded_unsafe_or_shared_value"] += 1
                continue
            if role in CONFIG_C2_ROLES and confidence.startswith("confirmed_static"):
                tiers["static_config_supported_c2"] += 1
                families[family] += 1
                config_endpoints.add(value.lower())
            elif "c2" in role or "control" in role or "beacon" in role or "tasking" in role:
                tiers["c2_candidate_not_confirmed"] += 1
            else:
                tiers["other_network_role"] += 1

    clickfix_root = repository / "analysis-results" / "clickfix"
    for path in sorted(clickfix_root.rglob("infrastructure.json")):
        counts["clickfix_infrastructure_files"] += 1
        data = _read_json(path)
        evidence = data.get("evidence_layers") or {}
        if not isinstance(evidence, dict):
            raise ValueError("evidence_layers がobjectではありません")
        active = evidence.get("active_bounded_get") or {}
        if not isinstance(active, dict):
            raise ValueError("active_bounded_get がobjectではありません")
        certificates = active.get("tls_certificates") or []
        if not isinstance(certificates, list):
            raise ValueError("tls_certificates が配列ではありません")
        if certificates:
            counts["files_with_tls_certificate"] += 1
        for certificate in certificates:
            if not isinstance(certificate, dict):
                counts["invalid_certificate_records"] += 1
                continue
            digest = certificate.get("sha256")
            if isinstance(digest, str) and HEX_SHA256.fullmatch(digest):
                counts["tls_certificate_observations"] += 1
                certs.add(digest.lower())
            else:
                counts["invalid_certificate_records"] += 1
        if evidence.get("certificate_transparency"):
            counts["files_with_ct_data"] += 1
        if evidence.get("domain_rdap"):
            counts["files_with_domain_rdap"] += 1
        current_dns = evidence.get("current_passive_dns") or {}
        if not isinstance(current_dns, dict):
            raise ValueError("current_passive_dns がobjectではありません")
        dns_answers = 0
        for answer in current_dns.values():
            if isinstance(answer, dict) and isinstance(answer.get("records"), list):
                dns_answers += len(answer["records"])
        if dns_answers:
            counts["files_with_current_dns"] += 1
            counts["current_dns_records"] += dns_answers
        historical = evidence.get("historical_passive_dns") or {}
        if isinstance(historical, dict) and historical.get("status") not in (None, "not_collected"):
            counts["files_with_historical_passive_dns"] += 1
        if active.get("reachable") is True:
            counts["clickfix_http_reachable_observations"] += 1

    return {
        "schema_version": 1,
        "scope": "公開済みの検体別IOCとClickFixインフラ付帯情報",
        "counts": {**dict(sorted(counts.items())),
                   "unique_static_config_c2_values": len(config_endpoints),
                   "unique_tls_certificate_sha256": len(certs)},
        "evidence_tiers": dict(sorted(tiers.items())),
        "network_observation_states": dict(sorted(states.items())),
        "network_source_classes": dict(sorted(source_classes.items())),
        "network_roles": dict(sorted(roles.items())),
        "top_families_by_static_config_c2_records": [
            {"family": family, "record_count": count}
            for family, count in sorted(families.items(), key=lambda row: (-row[1], row[0]))[:15]
        ],
        "assessment_boundary": {
            "static_config_is_live_c2_confirmation": False,
            "certificate_or_dns_is_family_attribution": False,
            "external_sandbox_candidate_is_confirmed_c2": False,
            "raw_ioc_values_published": False,
        },
    }


def main() -> int:
    """指定リポジトリを読み、集計JSONだけを標準出力へ出す。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True, help="解析リポジトリのルート")
    args = parser.parse_args()
    print(json.dumps(inventory(args.repository.resolve()), ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
