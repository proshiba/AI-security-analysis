#!/usr/bin/env python3
"""C2観測IPへ証拠付きのインフラ種別と防弾ホスティング評価を付与する。"""

from __future__ import annotations

from copy import deepcopy
import ipaddress
import json
from pathlib import Path
from typing import Any


DEFAULT_REGISTRY = Path(__file__).with_name("c2_infrastructure_classifications.json")
HOSTING_MARKERS = (
    "hosting",
    "host",
    "server",
    "cloud",
    "vps",
    "datacenter",
    "data center",
    "colo",
    "namecheap",
    "digitalocean",
    "alexhost",
)
VPN_PROXY_MARKERS = (" vpn", "vpn ", "proxy", "anonymizer")
DOMAIN_SERVICE_MARKERS = ("namecheap", "godaddy", "registrar", "domain")


def load_registry(path: Path | None = None) -> dict[str, Any]:
    target = path or DEFAULT_REGISTRY
    value = json.loads(target.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise ValueError(f"インフラ分類registryはschema_version=1のobjectが必要です: {target}")
    if not isinstance(value.get("rules"), list):
        raise ValueError(f"インフラ分類registry.rulesはlistである必要があります: {target}")
    return value


def _tag(
    registry: dict[str, Any],
    identifier: str,
    *,
    confidence: float,
    basis: str,
    rule_id: str | None = None,
) -> dict[str, Any]:
    definitions = registry.get("tag_definitions") or {}
    value = {
        "id": identifier,
        "label": definitions.get(identifier, identifier),
        "confidence": confidence,
        "basis": basis,
    }
    if rule_id:
        value["rule_id"] = rule_id
    return value


def _rule_matches(rule: dict[str, Any], *, ip: str, asn: int | None, organization: str) -> bool:
    match = rule.get("match") if isinstance(rule.get("match"), dict) else {}
    if asn is not None and asn in match.get("asns", []):
        return True
    normalized = organization.casefold()
    if any(str(marker).casefold() in normalized for marker in match.get("organization_contains", [])):
        return True
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        address = None
    if address is not None:
        for value in match.get("cidrs", []):
            try:
                if address in ipaddress.ip_network(str(value), strict=False):
                    return True
            except ValueError:
                continue
    return False


def _default_bulletproof(shared_cdn_provider: str | None) -> dict[str, Any]:
    if shared_cdn_provider:
        return {
            "classification": "not_indicated",
            "label": "防弾ホスティング根拠なし（共有CDN）",
            "confidence": 0.8,
            "reason": (
                f"{shared_cdn_provider}の共有edge IPであり、このIPだけからoriginの"
                "防弾ホスティング利用を評価できない。"
            ),
            "sources": [],
        }
    return {
        "classification": "unknown",
        "label": "防弾ホスティング判定不能",
        "confidence": 0.0,
        "reason": "防弾ホスティングと評価する肯定的なprovider／ASN証拠がregistryにない。",
        "sources": [],
    }


def build_ip_detail(
    record: dict[str, Any],
    *,
    host: str,
    shared_cdn_provider: str | None,
    registry: dict[str, Any],
) -> dict[str, Any]:
    """MaxMind recordを履歴固定用のIP詳細とインフラ評価へ変換する。"""
    ip = str(record.get("ip") or "")
    as_record = record.get("as") if isinstance(record.get("as"), dict) else {}
    geo = record.get("geo") if isinstance(record.get("geo"), dict) else {}
    asn = as_record.get("autonomous_system_number")
    if not isinstance(asn, int) or isinstance(asn, bool):
        asn = None
    organization = str(as_record.get("autonomous_system_organization") or "")
    normalized = f" {organization.casefold()} "
    tags: dict[str, dict[str, Any]] = {}

    def add(identifier: str, confidence: float, basis: str, rule_id: str | None = None) -> None:
        candidate = _tag(
            registry,
            identifier,
            confidence=confidence,
            basis=basis,
            rule_id=rule_id,
        )
        current = tags.get(identifier)
        if current is None or candidate["confidence"] > current["confidence"]:
            tags[identifier] = candidate

    try:
        ipaddress.ip_address(host.rstrip("."))
        host_is_ip = True
    except ValueError:
        host_is_ip = False
    if not host_is_ip:
        add("dns_resolution", 1.0, "FQDNのA／AAAA解決結果")
    add("c2_candidate", 1.0, "レビュー済みC2監視対象から観測")
    if shared_cdn_provider:
        add("cdn", 0.98, f"ASN／organizationが共有CDN {shared_cdn_provider} と一致")
        add("anycast_shared_edge", 0.9, "共有CDN edgeとして観測")
    if any(marker in normalized for marker in HOSTING_MARKERS):
        add("hosting", 0.65, f"AS organizationのservice種別marker: {organization}")
    if any(marker in normalized for marker in VPN_PROXY_MARKERS):
        add("vpn_proxy", 0.55, f"AS organizationのVPN／Proxy marker: {organization}")
    if any(marker in normalized for marker in DOMAIN_SERVICE_MARKERS):
        add("domain_service", 0.6, f"AS organizationのdomain service marker: {organization}")

    bulletproof = _default_bulletproof(shared_cdn_provider)
    matched_rules: list[str] = []
    for rule in registry.get("rules", []):
        if not isinstance(rule, dict) or not _rule_matches(
            rule,
            ip=ip,
            asn=asn,
            organization=organization,
        ):
            continue
        rule_id = str(rule.get("id") or "unnamed-rule")
        matched_rules.append(rule_id)
        assessment = (
            rule.get("bulletproof_hosting")
            if isinstance(rule.get("bulletproof_hosting"), dict)
            else None
        )
        for identifier in rule.get("tags", []):
            confidence = float((assessment or {}).get("confidence", 0.8))
            add(str(identifier), confidence, f"classification registry: {rule_id}", rule_id)
        if assessment and float(assessment.get("confidence", 0.0)) >= float(
            bulletproof.get("confidence", 0.0)
        ):
            bulletproof = deepcopy(assessment)
            bulletproof["rule_id"] = rule_id

    return {
        "ip": ip,
        "as": {
            "asn": asn,
            "organization": organization or None,
        },
        "geo": {
            "continent_code": geo.get("continent_code"),
            "continent_name": geo.get("continent_name"),
            "country_iso_code": geo.get("country_iso_code"),
            "country_name": geo.get("country_name"),
            "subdivision_iso_code": geo.get("subdivision_iso_code"),
            "subdivision_name": geo.get("subdivision_name"),
            "city_name": geo.get("city_name"),
            "latitude": geo.get("latitude"),
            "longitude": geo.get("longitude"),
            "accuracy_radius_km": geo.get("accuracy_radius_km"),
            "time_zone": geo.get("time_zone"),
            "is_anycast": geo.get("is_anycast"),
        },
        "infrastructure": {
            "tags": sorted(tags.values(), key=lambda item: item["id"]),
            "bulletproof_hosting": bulletproof,
            "matched_rules": matched_rules,
        },
    }


def missing_ip_detail(
    ip: str,
    *,
    host: str,
    shared_cdn_provider: str | None,
    registry: dict[str, Any],
) -> dict[str, Any]:
    """MaxMind未一致IPにも欠損を明示したタグ構造を返す。"""
    return build_ip_detail(
        {"ip": ip, "as": {}, "geo": {}},
        host=host,
        shared_cdn_provider=shared_cdn_provider,
        registry=registry,
    )
