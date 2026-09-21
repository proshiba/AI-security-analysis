#!/usr/bin/env python3
"""審査済みインフラ知識を、根拠境界を維持したSTIX 2.1へ変換する。"""

from __future__ import annotations

import argparse
from datetime import date, datetime, timedelta, timezone
import ipaddress
import json
from pathlib import Path
import re
from urllib.parse import urlsplit
import uuid
from typing import Any

from generate_family_stix import _identifier, _reconcile_versions


SCO_NAMESPACE = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")
SLUG = re.compile(r"[a-z0-9][a-z0-9-]{0,79}\Z")
DOMAIN = re.compile(r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
UTC_TIME = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z\Z")
SECRET = re.compile(r"(?i)(?:github_pat_[a-z0-9_]+|gh[pousr]_[a-z0-9]+|\bBearer\s+\S+|\b(?:token|api[_-]?key|password|secret)\s*[:=]\s*\S+|\bAKIA[0-9A-Z]{16}\b)")
RAW_URL = re.compile(r"(?i)\b(?:https?|hxxps?)://\S+")
CLASSIFICATIONS = {"confirmed-c2", "confirmed-auxiliary", "configured-only", "reported-c2", "pivot-only"}
ROLES = {"c2", "delivery", "resolver", "dead-drop", "unknown"}
PROTOCOLS = {"tcp", "udp", "tls", "http", "https", "dns", "unknown"}
EVIDENCE = {"sample-config", "contract-config", "traffic", "primary-analysis", "osint-report", "certificate-only"}
CERTIFICATE_EVIDENCE = {"sample-embedded-pin", "observed-server-leaf", "osint-report"}


def _timestamp(value: str) -> datetime:
    if not isinstance(value, str) or not UTC_TIME.fullmatch(value):
        raise ValueError(f"UTC観測日時が不正: {value!r}")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"UTC観測日時が不正: {value!r}") from error


def _sco_id(kind: str, contributing: dict[str, Any]) -> str:
    """STIX推奨namespaceとID寄与属性の正規化でSCO IDを生成する。"""
    canonical = json.dumps(contributing, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return f"{kind}--{uuid.uuid5(SCO_NAMESPACE, canonical)}"


def _sdo(kind: str, key: str, stamp: str, **fields: Any) -> dict[str, Any]:
    return {"type": kind, "spec_version": "2.1", "id": _identifier(kind, key), "created": stamp, "modified": stamp, **fields}


def _refs(source_ids: list[str], sources: dict[str, dict[str, str]]) -> list[dict[str, str]]:
    if not isinstance(source_ids, list) or not source_ids or any(not isinstance(value, str) or value not in sources for value in source_ids):
        raise ValueError("出典IDが欠落または不正")
    if len(source_ids) != len(set(source_ids)):
        raise ValueError("出典IDが重複")
    return [{"source_name": sources[item]["source_name"], "url": sources[item]["url"]} for item in sorted(source_ids)]


def _public_ip(value: str) -> tuple[str, str]:
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError as error:
        raise ValueError(f"IPアドレスが不正: {value!r}") from error
    if not parsed.is_global or str(parsed) != value:
        raise ValueError(f"公開IPアドレスとして不正: {value!r}")
    return ("ipv4-addr" if parsed.version == 4 else "ipv6-addr", value)


def _domain(value: str) -> str:
    if not isinstance(value, str) or not DOMAIN.fullmatch(value) or value.lower() != value:
        raise ValueError(f"FQDNが不正: {value!r}")
    return value


def _exact_url(value: str) -> str:
    if not isinstance(value, str) or SECRET.search(value):
        raise ValueError("exact URLが不正")
    parsed = urlsplit(value)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment or not parsed.path or parsed.path == "/"
            or parsed.port is not None or value != parsed.geturl()):
        raise ValueError("exact URLはquery/fragmentのないHTTPSページが必要")
    _domain(parsed.hostname)
    return value


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or SECRET.search(value) or RAW_URL.search(value):
        raise ValueError(f"{label}が空、または秘密情報・raw URLを含む")
    return value.strip()


def _record_ids(items: Any, label: str) -> dict[str, dict[str, Any]]:
    if not isinstance(items, list):
        raise ValueError(f"{label}は配列が必要")
    found: dict[str, dict[str, Any]] = {}
    for item in items:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str) or not SLUG.fullmatch(item["id"]) or item["id"] in found:
            raise ValueError(f"{label}のIDが不正または重複")
        found[item["id"]] = item
    return found


def _validate(data: dict[str, Any]) -> dict[str, dict[str, dict[str, Any]]]:
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise ValueError("インフラ知識のschema_versionが不正")
    keys = ("sources", "certificates", "endpoints", "dns_resolutions", "groupings", "campaigns", "intrusion_sets")
    records = {key: _record_ids(data.get(key, []), key) for key in keys if key != "dns_resolutions"}
    if not isinstance(data.get("dns_resolutions", []), list):
        raise ValueError("dns_resolutionsは配列が必要")
    sources = records["sources"]
    for item in sources.values():
        _text(item.get("source_name"), "出典名")
        url = item.get("url")
        if not isinstance(url, str) or SECRET.search(url):
            raise ValueError("出典URLが不正")
        parsed = urlsplit(url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or not parsed.path:
            raise ValueError(f"出典URLはquery/fragment/資格情報を含まないHTTPSが必要: {item['id']}")
    for item in records["certificates"].values():
        _refs(item.get("source_ids"), sources)
        if "evidence_role" in item and item["evidence_role"] not in CERTIFICATE_EVIDENCE:
            raise ValueError("証明書evidence_roleが不正")
        if "evidence_note_ja" in item:
            _text(item["evidence_note_ja"], "証明書根拠注記")
        if "is_self_signed" in item and type(item["is_self_signed"]) is not bool:
            raise ValueError("証明書is_self_signedが不正")
        if not any(item.get(key) for key in ("sha1", "sha256")):
            raise ValueError("証明書hashが欠落")
        for key, size in (("sha1", 40), ("sha256", 64)):
            if key in item and (not isinstance(item[key], str) or not re.fullmatch(rf"[0-9a-f]{{{size}}}", item[key])):
                raise ValueError(f"証明書{key}が不正")
        for key in ("subject", "issuer", "serial_number", "subject_alternative_name"):
            if key in item:
                _text(item[key], key)
        for key in ("validity_not_before", "validity_not_after"):
            if key in item:
                _timestamp(item[key])
        if "validity_not_before" in item and "validity_not_after" in item and _timestamp(item["validity_not_after"]) < _timestamp(item["validity_not_before"]):
            raise ValueError("証明書有効期間が逆転")
    for item in records["endpoints"].values():
        _refs(item.get("source_ids"), sources)
        if not any(key in item for key in ("ip", "domain", "url")):
            raise ValueError("endpointにはIP、domain、またはexact URLが必要")
        if "ip" in item:
            _public_ip(item["ip"])
        if "domain" in item:
            _domain(item["domain"])
        if "url" in item:
            _exact_url(item["url"])
            if "domain" in item or "ip" in item:
                raise ValueError("exact URL endpointに共有サービスdomain/IPを混在させない")
        if "port" in item and (type(item["port"]) is not int or not 1 <= item["port"] <= 65535):
            raise ValueError("endpoint portが不正")
        for key, allowed in (("classification", CLASSIFICATIONS), ("role", ROLES), ("protocol", PROTOCOLS), ("evidence_kind", EVIDENCE)):
            if item.get(key) not in allowed:
                raise ValueError(f"endpoint {key}が不正: {item['id']}")
        if "certificate_id" in item and item["certificate_id"] not in records["certificates"]:
            raise ValueError("未知の証明書ID")
        if "certificate_id" in item and records["certificates"][item["certificate_id"]].get("evidence_role") == "sample-embedded-pin":
            raise ValueError("検体内pinをサーバー提示証明書として登録できない")
        if "certificate_id" in item and not set(item["source_ids"]) & set(records["certificates"][item["certificate_id"]]["source_ids"]):
            raise ValueError("endpointと証明書の出典が接続しない")
        if "expected_certificate_id" in item:
            expected_id = item["expected_certificate_id"]
            if (expected_id not in records["certificates"] or "certificate_id" in item
                    or records["certificates"][expected_id].get("evidence_role") != "sample-embedded-pin"
                    or item.get("evidence_kind") != "sample-config"
                    or item.get("classification") not in {"confirmed-c2", "configured-only"}
                    or not set(item["source_ids"]) & set(records["certificates"][expected_id]["source_ids"])):
                raise ValueError("検体内の期待証明書の根拠が不正")
        if "confidence" in item and (type(item["confidence"]) is not int or not 0 <= item["confidence"] <= 100):
            raise ValueError("endpoint confidenceが不正")
        if "period_ja" in item:
            _text(item["period_ja"], "endpoint利用期間")
        if "sample_sha256" in item and (not isinstance(item["sample_sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", item["sample_sha256"])):
            raise ValueError("検体SHA-256が不正")
        first, last = item.get("first_observed"), item.get("last_observed")
        if (first is None) != (last is None):
            raise ValueError("観測日時はfirst/lastの両方が必要")
        if first is not None and _timestamp(last) < _timestamp(first):
            raise ValueError("観測日時が逆転")
        if first is not None:
            _timestamp(first)
            if item["evidence_kind"] not in {"traffic", "certificate-only"}:
                raise ValueError("観測日時は通信実測または証明書実測の根拠に限定する")
        if item["classification"] == "confirmed-c2":
            if item["role"] != "c2" or item["evidence_kind"] not in {"sample-config", "contract-config", "traffic", "primary-analysis"} or not item.get("family_id") or "url" in item:
                raise ValueError("confirmed-c2には検体設定/通信/一次解析の根拠とfamily IDが必要")
        elif item["classification"] == "confirmed-auxiliary":
            if item["role"] not in {"dead-drop", "delivery", "resolver"} or item["evidence_kind"] not in {"sample-config", "traffic"} or not item.get("family_id"):
                raise ValueError("confirmed-auxiliaryには攻撃用途とfamily IDの根拠が必要")
        elif item["classification"] == "configured-only":
            if item["role"] != "c2" or item["evidence_kind"] != "sample-config" or not item.get("family_id"):
                raise ValueError("configured-onlyには検体設定、C2候補role、family IDが必要")
        elif item.get("family_id"):
            raise ValueError("未確定endpointにfamily IDを指定できない")
        if "sample_sha256" in item and item["classification"] not in {"confirmed-c2", "confirmed-auxiliary", "configured-only"}:
            raise ValueError("未確定endpointに検体を結び付けられない")
        if "family_id" in item and not SLUG.fullmatch(item["family_id"]):
            raise ValueError("family IDが不正")
        if item["evidence_kind"] == "certificate-only" and "certificate_id" not in item:
            raise ValueError("certificate-onlyにはcertificate_idが必要")
    for item in data.get("dns_resolutions", []):
        if not isinstance(item, dict):
            raise ValueError("dns_resolutions要素が不正")
        _domain(item.get("domain"))
        _public_ip(item.get("ip"))
        _refs(item.get("source_ids"), sources)
        if "period_ja" in item:
            _text(item["period_ja"], "DNS解決期間")
        first, last = item.get("first_observed"), item.get("last_observed")
        if (first is None) != (last is None):
            raise ValueError("DNS観測日時はfirst/lastの両方が必要")
        if first is not None and _timestamp(last) < _timestamp(first):
            raise ValueError("DNS観測日時が逆転")
    for item in records["groupings"].values():
        _refs(item.get("source_ids"), sources)
        _text(item.get("name"), "grouping名")
        _text(item.get("description_ja"), "grouping説明")
        ids = item.get("endpoint_ids")
        if not isinstance(ids, list) or not ids or len(ids) != len(set(ids)) or any(value not in records["endpoints"] for value in ids):
            raise ValueError("grouping endpoint参照が不正")
        if "intrusion_set_ids" in item:
            intrusion_ids = item["intrusion_set_ids"]
            if (not isinstance(intrusion_ids, list) or not intrusion_ids or len(intrusion_ids) != len(set(intrusion_ids))
                    or any(value not in records["intrusion_sets"] for value in intrusion_ids)
                    or any(records["endpoints"][value]["classification"] != "confirmed-c2" for value in ids)
                    or not item.get("attribution_source_ids")):
                raise ValueError("groupingのintrusion set帰属が不正")
            _refs(item["attribution_source_ids"], sources)
            _text(item.get("attribution_ja"), "groupingの帰属説明")
            if not set(item["attribution_source_ids"]) & set(item["source_ids"]):
                raise ValueError("grouping帰属の出典が結び付かない")
            if any(not set(item["attribution_source_ids"]) & set(records["endpoints"][value]["source_ids"]) for value in ids):
                raise ValueError("grouping帰属の出典がendpointと結び付かない")
        elif "attribution_source_ids" in item or "attribution_ja" in item:
            raise ValueError("intrusion set参照のないgrouping帰属")
    for item in records["intrusion_sets"].values():
        _refs(item.get("source_ids"), sources)
        _text(item.get("name"), "intrusion set名")
        _text(item.get("description_ja"), "intrusion set説明")
    for item in records["campaigns"].values():
        _refs(item.get("source_ids"), sources)
        _text(item.get("name"), "campaign名")
        _text(item.get("description_ja"), "campaign説明")
        endpoint_ids, family_ids = item.get("endpoint_ids"), item.get("family_ids")
        if not isinstance(endpoint_ids, list) or not endpoint_ids or len(endpoint_ids) != len(set(endpoint_ids)):
            raise ValueError("campaign endpoint参照が不正")
        if any(key not in records["endpoints"] or records["endpoints"][key]["classification"] != "confirmed-c2" for key in endpoint_ids):
            raise ValueError("campaignへ未確定C2を昇格できない")
        if not isinstance(family_ids, list) or not family_ids or len(family_ids) != len(set(family_ids)) or any(not isinstance(value, str) or not SLUG.fullmatch(value) for value in family_ids):
            raise ValueError("campaign family参照が不正")
        if any(records["endpoints"][key]["family_id"] not in family_ids for key in endpoint_ids):
            raise ValueError("campaignのendpoint/family参照が不一致")
        if any(not set(item["source_ids"]) & set(records["endpoints"][key]["source_ids"]) for key in endpoint_ids):
            raise ValueError("campaignとendpointの出典が接続しない")
        intrusion_id = item.get("intrusion_set_id")
        if intrusion_id is not None:
            if intrusion_id not in records["intrusion_sets"] or not item.get("attribution_source_ids") or not isinstance(item.get("attribution_ja"), str):
                raise ValueError("intrusion set帰属には出典と明示説明が必要")
            _refs(item["attribution_source_ids"], sources)
            _text(item["attribution_ja"], "帰属説明")
        elif "attribution_source_ids" in item or "attribution_ja" in item:
            raise ValueError("intrusion set参照のない帰属情報")
    return records


def _validate_bundle(bundle: dict[str, Any]) -> None:
    objects = bundle.get("objects")
    if bundle.get("type") != "bundle" or not isinstance(objects, list):
        raise ValueError("STIX Bundleが不正")
    by_id = {item.get("id"): item for item in objects if isinstance(item, dict)}
    if len(by_id) != len(objects) or None in by_id:
        raise ValueError("STIX object IDが不正または重複")
    for item in objects:
        if not item["id"].startswith(item["type"] + "--"):
            raise ValueError("STIX object type/IDが不一致")
        if item["type"] in {"ipv4-addr", "ipv6-addr", "domain-name", "url", "x509-certificate", "network-traffic", "file"}:
            if any(key in item for key in ("created", "modified", "confidence", "external_references")):
                raise ValueError("SCOに禁止された共通属性")
        else:
            if not item.get("created") or not item.get("modified") or item["modified"] < item["created"]:
                raise ValueError("STIX SDO/SRO版情報が不正")
        for key in ("source_ref", "target_ref", "sighting_of_ref", "dst_ref"):
            if key in item and item[key] not in by_id:
                raise ValueError(f"STIX参照先がない: {item[key]}")
        for key in ("object_refs",):
            if key in item and any(value not in by_id for value in item[key]):
                raise ValueError("STIX object_refs参照先がない")


def generate(repository: Path, as_of: date) -> tuple[dict[str, str], dict[str, Any]]:
    """外部通信なしで、審査済みJSONから単一のインフラBundleを構築する。"""
    input_path = repository / "analysis-framework/knowledge/stix_infrastructure_curated.json"
    data = json.loads(input_path.read_text(encoding="utf-8"))
    records = _validate(data)
    stamp = as_of.isoformat() + "T00:00:00.000Z"
    as_of_end = datetime.combine(as_of + timedelta(days=1), datetime.min.time(), tzinfo=timezone.utc)
    sources = records["sources"]
    objects: dict[str, dict[str, Any]] = {}
    endpoint_refs: dict[str, list[str]] = {}
    infrastructure_ids: dict[str, str] = {}

    def add(item: dict[str, Any]) -> str:
        old = objects.get(item["id"])
        if old is not None and old != item:
            raise ValueError(f"異なるSTIXオブジェクトが同じID: {item['id']}")
        objects[item["id"]] = item
        return item["id"]

    def address(ip: str) -> str:
        kind, value = _public_ip(ip)
        return add({"type": kind, "spec_version": "2.1", "id": _sco_id(kind, {"value": value}), "value": value})

    def domain(name: str) -> str:
        value = _domain(name)
        return add({"type": "domain-name", "spec_version": "2.1", "id": _sco_id("domain-name", {"value": value}), "value": value})

    def exact_url(value: str) -> str:
        value = _exact_url(value)
        return add({"type": "url", "spec_version": "2.1", "id": _sco_id("url", {"value": value}), "value": value})

    def malware(family_id: str, source_ids: list[str]) -> str:
        identifier = _identifier("malware", family_id)
        if identifier in objects:
            return identifier
        family_path = repository / "analysis-results/stix/families" / f"{family_id}.json"
        if family_path.is_file():
            existing = json.loads(family_path.read_text(encoding="utf-8"))
            matches = [item for item in existing.get("objects", []) if item.get("id") == identifier and item.get("type") == "malware"]
            if len(matches) != 1:
                raise ValueError(f"既存family STIXのMalware IDが不正: {family_id}")
            return add(matches[0].copy())
        return add(_sdo("malware", family_id, stamp, name=family_id, is_family=True, description="このBundleでは攻撃インフラとの関連のみを記録。ファミリー分類の根拠は添付出典に限定する。", external_references=_refs(source_ids, sources), lang="ja"))

    cert_ids: dict[str, str] = {}
    for cert in records["certificates"].values():
        hashes = {name: cert[key] for key, name in (("sha1", "SHA-1"), ("sha256", "SHA-256")) if key in cert}
        selected = {"SHA-1": cert["sha1"]} if "sha1" in cert else {"SHA-256": cert["sha256"]}
        contributing: dict[str, Any] = {"hashes": selected}
        if "serial_number" in cert:
            contributing["serial_number"] = cert["serial_number"]
        item: dict[str, Any] = {"type": "x509-certificate", "spec_version": "2.1", "id": _sco_id("x509-certificate", contributing), "hashes": hashes}
        for key in ("subject", "issuer", "serial_number", "validity_not_before", "validity_not_after", "is_self_signed"):
            if key in cert:
                item[key] = cert[key]
        if "subject_alternative_name" in cert:
            item["x509_v3_extensions"] = {"subject_alternative_name": cert["subject_alternative_name"]}
        cert_ids[cert["id"]] = add(item)
        cert_context = "検体に埋め込まれたTLS pin用証明書。実サーバーが提示したという観測ではない。" if cert.get("evidence_role") == "sample-embedded-pin" else "証明書の属性。共通証明書だけでは同一運用者・C2・攻撃キャンペーンを確定しない。"
        if "evidence_note_ja" in cert:
            cert_context += " " + cert["evidence_note_ja"]
        add(_sdo("note", "infra:cert:" + cert["id"], stamp, content=cert_context, object_refs=[item["id"]], external_references=_refs(cert["source_ids"], sources), lang="ja"))

    for endpoint in records["endpoints"].values():
        refs: list[str] = []
        if "ip" in endpoint:
            refs.append(address(endpoint["ip"]))
        if "domain" in endpoint:
            refs.append(domain(endpoint["domain"]))
        if "url" in endpoint:
            refs.append(exact_url(endpoint["url"]))
        if "certificate_id" in endpoint:
            refs.append(cert_ids[endpoint["certificate_id"]])
        component_refs = refs.copy()
        if "expected_certificate_id" in endpoint:
            refs.append(cert_ids[endpoint["expected_certificate_id"]])
        if "sample_sha256" in endpoint:
            sample_hash = endpoint["sample_sha256"]
            refs.append(add({"type": "file", "spec_version": "2.1", "id": _sco_id("file", {"hashes": {"SHA-256": sample_hash}}), "hashes": {"SHA-256": sample_hash}}))
        endpoint_refs[endpoint["id"]] = refs
        label = endpoint.get("ip", endpoint.get("domain", endpoint.get("url")))
        if "domain" in endpoint and "ip" in endpoint:
            label += " / " + endpoint["domain"]
        if "port" in endpoint:
            label += ":" + str(endpoint["port"])
        context = f"{label}。役割={endpoint['role']}、protocol={endpoint['protocol']}、分類={endpoint['classification']}、根拠={endpoint['evidence_kind']}。"
        if "period_ja" in endpoint:
            context += " 出典で確認できる利用期間: " + endpoint["period_ja"]
        if endpoint["evidence_kind"] == "contract-config":
            context += " オンチェーン契約から復元された設定値であり、接続観測や現時点の稼働を意味しない。"
        if endpoint["classification"] in {"reported-c2", "pivot-only"}:
            context += " マルウェア設定・通信によるC2確定ではない。証明書共有だけで同一campaignや攻撃者へ帰属しない。"
        elif endpoint["classification"] == "configured-only":
            context += " 検体に設定された代替接続先だが通信未観測。稼働するC2や攻撃キャンペーンと断定しない。"
            refs.append(malware(endpoint["family_id"], endpoint["source_ids"]))
        note = _sdo("note", "infra:endpoint:" + endpoint["id"], stamp, content=context, object_refs=refs, external_references=_refs(endpoint["source_ids"], sources), lang="ja")
        if "confidence" in endpoint:
            note["confidence"] = endpoint["confidence"]
        endpoint_refs[endpoint["id"]].append(add(note))
        if "expected_certificate_id" in endpoint:
            add(_sdo("note", "infra:expected-cert:" + endpoint["id"], stamp, content="検体の設定に埋め込まれた期待証明書。サーバー側の証明書提示、接続成功、現在の稼働は未確認。", object_refs=[cert_ids[endpoint["expected_certificate_id"]], note["id"]], external_references=_refs(endpoint["source_ids"], sources), lang="ja"))

        if endpoint["classification"] in {"confirmed-c2", "confirmed-auxiliary"}:
            is_c2 = endpoint["classification"] == "confirmed-c2"
            infrastructure = _sdo("infrastructure", "infra:endpoint:" + endpoint["id"], stamp, name=label, infrastructure_types=["command-and-control" if is_c2 else "staging"], description="検体設定、通信、または一次解析で確認された攻撃インフラendpoint。根拠種別は対応するNoteを参照。現時点の稼働や管理主体を保証しない。", external_references=_refs(endpoint["source_ids"], sources), lang="ja")
            if "confidence" in endpoint:
                infrastructure["confidence"] = endpoint["confidence"]
            infrastructure_ids[endpoint["id"]] = add(infrastructure)
            endpoint_refs[endpoint["id"]].append(infrastructure["id"])
            for target in component_refs:
                add(_sdo("relationship", "infra:component:" + endpoint["id"] + ":" + target, stamp, relationship_type="consists-of", source_ref=infrastructure["id"], target_ref=target, external_references=_refs(endpoint["source_ids"], sources)))
            family_id = malware(endpoint["family_id"], endpoint["source_ids"])
            if is_c2:
                if endpoint["evidence_kind"] == "contract-config":
                    add(_sdo("relationship", "infra:contract-config:" + endpoint["id"], stamp, relationship_type="uses", source_ref=family_id, target_ref=infrastructure["id"], description="オンチェーン契約に記載されたC2設定との関係。個別検体からの通信や現時点の稼働は観測されていない。", external_references=_refs(endpoint["source_ids"], sources), lang="ja"))
                else:
                    relation_type = "beacons-to" if endpoint["evidence_kind"] == "traffic" else "uses"
                    if endpoint["evidence_kind"] == "primary-analysis":
                        description = "一次解析のC2報告に基づく。個別検体設定・通信の観測はこの資料からは未確認。"
                    elif endpoint["evidence_kind"] == "sample-config":
                        description = "検体の静的設定にあるC2候補。実際のbeaconや現在の稼働は観測されていない。"
                    else:
                        description = "当該C2への通信観測に基づく。証明書の共有による帰属ではない。"
                    add(_sdo("relationship", "infra:beacon:" + endpoint["id"], stamp, relationship_type=relation_type, source_ref=family_id, target_ref=infrastructure["id"], description=description, external_references=_refs(endpoint["source_ids"], sources), lang="ja"))
            else:
                add(_sdo("note", "infra:auxiliary:" + endpoint["id"], stamp, content="検体設定または通信に基づく非C2の攻撃補助endpoint。C2チェックインやコマンド受領の証拠とは区別する。共有サービス全体への帰属ではない。", object_refs=[family_id, infrastructure["id"]] + component_refs, external_references=_refs(endpoint["source_ids"], sources), lang="ja"))
                if endpoint["evidence_kind"] == "traffic":
                    target = exact_url(endpoint["url"]) if "url" in endpoint else (address(endpoint["ip"]) if "ip" in endpoint else domain(endpoint["domain"]))
                    add(_sdo("relationship", "infra:auxiliary-traffic:" + endpoint["id"], stamp, relationship_type="communicates-with", source_ref=family_id, target_ref=target, description="観測通信に基づく非C2 endpoint。", external_references=_refs(endpoint["source_ids"], sources), lang="ja"))
            if "sample_sha256" in endpoint:
                sample_id = _sco_id("file", {"hashes": {"SHA-256": endpoint["sample_sha256"]}})
                endpoint_kind = "C2" if is_c2 else "非C2の攻撃補助"
                add(_sdo("note", "infra:sample:" + endpoint["id"], stamp, content=f"この検体の解析を根拠に当該ファミリーと{endpoint_kind} endpointを関連付けた。検体の発見・収集経路は攻撃経路ではないため含めない。", object_refs=[sample_id, family_id, infrastructure["id"]], external_references=_refs(endpoint["source_ids"], sources), lang="ja"))

            if is_c2 and "first_observed" in endpoint:
                observed_last = _timestamp(endpoint["last_observed"])
                if observed_last >= as_of_end:
                    raise ValueError("as-ofより未来のendpoint観測")
                valid_until = observed_last + timedelta(days=30)
                pattern_address = endpoint.get("ip", endpoint.get("domain"))
                if "port" in endpoint:
                    pattern = f"[network-traffic:dst_ref.value = '{pattern_address}' AND network-traffic:dst_port = {endpoint['port']}]"
                elif "domain" in endpoint:
                    pattern = f"[domain-name:value = '{endpoint['domain']}']"
                else:
                    pattern = f"[ipv4-addr:value = '{endpoint['ip']}']" if ":" not in endpoint["ip"] else f"[ipv6-addr:value = '{endpoint['ip']}']"
                indicator = _sdo("indicator", "infra:indicator:" + endpoint["id"], stamp, name=f"既知C2 {label}", description="過去の攻撃インフラに対する履歴ハント用。現時点の悪性・稼働を保証せず、30日後に自動失効する。", indicator_types=["malicious-activity"], pattern=pattern, pattern_type="stix", valid_from=endpoint["first_observed"], valid_until=valid_until.isoformat(timespec="milliseconds").replace("+00:00", "Z"), external_references=_refs(endpoint["source_ids"], sources), lang="ja")
                add(indicator)
                add(_sdo("relationship", "infra:indicates:" + endpoint["id"], stamp, relationship_type="indicates", source_ref=indicator["id"], target_ref=infrastructure["id"], external_references=_refs(endpoint["source_ids"], sources)))

        if endpoint["evidence_kind"] == "traffic" and "first_observed" in endpoint and "port" in endpoint and ("ip" in endpoint or "domain" in endpoint):
            destination = address(endpoint["ip"]) if "ip" in endpoint else domain(endpoint["domain"])
            protocol = "tcp" if endpoint["protocol"] in {"tcp", "tls", "http", "https"} else endpoint["protocol"]
            if protocol != "unknown":
                contributing = {"dst_ref": destination, "dst_port": endpoint["port"], "protocols": [protocol]}
                net = {"type": "network-traffic", "spec_version": "2.1", "id": _sco_id("network-traffic", contributing), **contributing}
                add(net)
                observed = _sdo("observed-data", "infra:observed:" + endpoint["id"], stamp, first_observed=endpoint["first_observed"], last_observed=endpoint["last_observed"], number_observed=1, object_refs=[destination, net["id"]], external_references=_refs(endpoint["source_ids"], sources))
                add(observed)
        elif endpoint["evidence_kind"] == "certificate-only" and "first_observed" in endpoint:
            destination = address(endpoint["ip"]) if "ip" in endpoint else domain(endpoint["domain"])
            cert_id = cert_ids[endpoint["certificate_id"]]
            service = destination
            members = [destination]
            if "port" in endpoint and endpoint["protocol"] in {"tcp", "tls", "https"}:
                protocols = ["tcp", "tls"] if endpoint["protocol"] in {"tls", "https"} else ["tcp"]
                contributing = {"dst_ref": destination, "dst_port": endpoint["port"], "protocols": protocols}
                service = add({"type": "network-traffic", "spec_version": "2.1", "id": _sco_id("network-traffic", contributing), **contributing})
                members.append(service)
            association = _sdo("relationship", "infra:cert-observed:" + endpoint["id"], stamp, relationship_type="related-to", source_ref=service, target_ref=cert_id, description="指定endpointのTLS証明書提示観測。マルウェアからの通信、C2機能、同一運用者の証拠ではない。", external_references=_refs(endpoint["source_ids"], sources), lang="ja")
            add(association)
            add(_sdo("observed-data", "infra:cert-observed:" + endpoint["id"], stamp, first_observed=endpoint["first_observed"], last_observed=endpoint["last_observed"], number_observed=1, object_refs=members + [cert_id, association["id"]], external_references=_refs(endpoint["source_ids"], sources)))

    for resolution in data.get("dns_resolutions", []):
        domain_id, ip_id = domain(resolution["domain"]), address(resolution["ip"])
        key = f"infra:dns:{resolution['domain']}:{resolution['ip']}"
        description = "出典に記載された過去のDNS解決先。現在の解決先や所有関係を意味しない。"
        if "period_ja" in resolution:
            description += " 記載期間: " + resolution["period_ja"]
        relationship = _sdo("relationship", key, stamp, relationship_type="resolves-to", source_ref=domain_id, target_ref=ip_id, description=description, external_references=_refs(resolution["source_ids"], sources), lang="ja")
        add(relationship)
        if "first_observed" in resolution:
            add(_sdo("observed-data", key, stamp, first_observed=resolution["first_observed"], last_observed=resolution["last_observed"], number_observed=1, object_refs=[domain_id, ip_id, relationship["id"]], external_references=_refs(resolution["source_ids"], sources)))

    for group in records["groupings"].values():
        refs = sorted({ref for endpoint_id in group["endpoint_ids"] for ref in endpoint_refs[endpoint_id]})
        if "intrusion_set_ids" in group:
            attribution_refs = _refs(group["attribution_source_ids"], sources)
            family_ids = sorted({records["endpoints"][endpoint_id]["family_id"] for endpoint_id in group["endpoint_ids"]})
            for intrusion_id in group["intrusion_set_ids"]:
                actor_ref = _identifier("intrusion-set", "infra:intrusion:" + intrusion_id)
                refs.append(actor_ref)
                for family_id in family_ids:
                    malware_ref = malware(family_id, group["attribution_source_ids"])
                    refs.append(malware_ref)
                    relation = _sdo("relationship", "infra:group-actor-malware:" + group["id"] + ":" + intrusion_id + ":" + family_id, stamp, relationship_type="uses", source_ref=actor_ref, target_ref=malware_ref, description=group["attribution_ja"] + " このgrouping内のファミリー利用だけに限定し、他の証明書ピボットへ波及させない。", external_references=attribution_refs, lang="ja")
                    refs.append(add(relation))
                for endpoint_id in group["endpoint_ids"]:
                    relation = _sdo("relationship", "infra:group-actor-endpoint:" + group["id"] + ":" + intrusion_id + ":" + endpoint_id, stamp, relationship_type="uses", source_ref=actor_ref, target_ref=infrastructure_ids[endpoint_id], description=group["attribution_ja"] + " このgrouping内の確認済みC2 endpointだけに限定する。", external_references=attribution_refs, lang="ja")
                    refs.append(add(relation))
        description = group["description_ja"] + " 証明書・IP等の共通性だけでは同一攻撃活動や運用者を意味しない。"
        if "attribution_ja" in group:
            description += " 出典に基づく限定的な帰属: " + group["attribution_ja"]
        add(_sdo("grouping", "infra:group:" + group["id"], stamp, name=group["name"], description=description, context="unspecified", object_refs=sorted(set(refs)), external_references=_refs(group["source_ids"], sources) + (_refs(group["attribution_source_ids"], sources) if "attribution_source_ids" in group else []), lang="ja"))

    for intrusion in records["intrusion_sets"].values():
        add(_sdo("intrusion-set", "infra:intrusion:" + intrusion["id"], stamp, name=intrusion["name"], description=intrusion["description_ja"], external_references=_refs(intrusion["source_ids"], sources), lang="ja"))
    for campaign in records["campaigns"].values():
        campaign_id = add(_sdo("campaign", "infra:campaign:" + campaign["id"], stamp, name=campaign["name"], description=campaign["description_ja"], external_references=_refs(campaign["source_ids"], sources), lang="ja"))
        for endpoint_id in campaign["endpoint_ids"]:
            add(_sdo("relationship", "infra:campaign-uses:" + campaign["id"] + ":" + endpoint_id, stamp, relationship_type="uses", source_ref=campaign_id, target_ref=infrastructure_ids[endpoint_id], external_references=_refs(campaign["source_ids"], sources)))
        for family_id in campaign["family_ids"]:
            malware_id = malware(family_id, campaign["source_ids"])
            add(_sdo("relationship", "infra:campaign-malware:" + campaign["id"] + ":" + family_id, stamp, relationship_type="uses", source_ref=campaign_id, target_ref=malware_id, external_references=_refs(campaign["source_ids"], sources)))
        if "intrusion_set_id" in campaign:
            add(_sdo("relationship", "infra:campaign-attribution:" + campaign["id"], stamp, relationship_type="attributed-to", source_ref=campaign_id, target_ref=_identifier("intrusion-set", "infra:intrusion:" + campaign["intrusion_set_id"]), description=campaign["attribution_ja"], external_references=_refs(campaign["attribution_source_ids"], sources), lang="ja"))

    ordered = sorted(objects.values(), key=lambda item: (item["type"], item["id"]))
    bundle = {"type": "bundle", "id": _identifier("bundle", "infrastructure:" + as_of.isoformat()), "objects": ordered}
    _reconcile_versions({"objects": [item for item in ordered if item["type"] not in {"ipv4-addr", "ipv6-addr", "domain-name", "url", "x509-certificate", "network-traffic", "file"}]}, repository / "analysis-results/stix/infrastructure/bundle.json", stamp)
    _validate_bundle(bundle)
    counts = {kind: sum(item["type"] == kind for item in ordered) for kind in ("campaign", "domain-name", "file", "grouping", "indicator", "infrastructure", "intrusion-set", "ipv4-addr", "ipv6-addr", "malware", "network-traffic", "note", "observed-data", "relationship", "url", "x509-certificate")}
    index = {"schema_version": 1, "stix_version": "2.1", "as_of": as_of.isoformat(), "counts": counts, "curated_endpoints": len(records["endpoints"]), "confirmed_c2": sum(item["classification"] == "confirmed-c2" for item in records["endpoints"].values()), "confirmed_auxiliary": sum(item["classification"] == "confirmed-auxiliary" for item in records["endpoints"].values()), "safety": {"sample_executed_during_generation": False, "live_c2_contacted_during_generation": False, "historical_live_observation_in_sources": any(item["evidence_kind"] in {"traffic", "certificate-only"} and "first_observed" in item for item in records["endpoints"].values()), "certificate_only_promoted_to_campaign": False, "discovery_route_excluded": True}}
    return {"bundle.json": json.dumps(bundle, ensure_ascii=False, indent=2, sort_keys=True) + "\n", "index.json": json.dumps(index, ensure_ascii=False, indent=2, sort_keys=True) + "\n"}, index


def main() -> int:
    """審査済みインフラSTIXを生成、または既存成果物と照合する。"""
    parser = argparse.ArgumentParser(description="審査済みの攻撃インフラ知識をSTIX 2.1へ生成・照合します。")
    parser.add_argument("--repository", type=Path, default=Path("."))
    parser.add_argument("--as-of", type=date.fromisoformat, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args()
    outputs, index = generate(args.repository.resolve(), args.as_of)
    root = args.repository.resolve() / "analysis-results/stix/infrastructure"
    for name, content in outputs.items():
        path = root / name
        if args.check:
            if not path.is_file() or path.read_text(encoding="utf-8") != content:
                raise SystemExit(f"インフラSTIX成果物が不一致: {name}")
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8", newline="\n")
    if args.check and {path.name for path in root.glob("*.json")} != set(outputs):
        raise SystemExit("インフラSTIX成果物の集合が不一致")
    print(json.dumps(index["counts"], ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
