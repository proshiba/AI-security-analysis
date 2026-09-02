#!/usr/bin/env python3
"""全解析履歴のIOCから、C2ライブチェック対象と監査在庫を生成する。"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
from collections import Counter, defaultdict
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from c2_protocol_probe_profiles import (
    PROFILE_METHODS,
    apply_profiles,
    profile_registry_metadata,
    remus_review_registry_metadata,
)
from daily_news_malware_intake import (
    SHARED_SERVICE_HOSTS,
    _daily_infrastructure_target_commitment,
    is_shared_service_host,
)
from immutable_snapshot import decode_strict_json, read_bounded_snapshot

MAX_IOC_JSON_BYTES = 16 * 1024 * 1024
SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
FQDN_RE = re.compile(
    r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
)
POSITIVE_ROLE_MARKERS = (
    "c2",
    "command",
    "control",
    "controller",
    "beacon",
    "task",
    "exfil",
    "secondary_shell",
    "heartbeat",
    "interactive",
    "wallet_replacement",
    "reverse_shell",
    "relay_upstream",
    "status_tracker",
    "stage channel",
    "auxiliary endpoint",
)
NEGATIVE_ROLE_MARKERS = (
    "not_c2",
    "not c2",
    "kill_switch",
    "context_only",
    "public_bootstrap",
    "dependency",
)
NON_DNS_SUFFIXES = (".onion", ".eth", ".sol", ".did", ".iid")
DEFAULT_PORTS = {"http": 80, "https": 443, "ftp": 21}
IOC_LIST_KEYS = ("network", "configured_c2", "configured_or_observed_c2", "indicators")
MALWARE_PROTOCOL_HINTS = frozenset(protocol for protocol, _method in PROFILE_METHODS.values())
DAILY_HANDOFF_SCHEMA_VERSION = 1
DAILY_IOC_SUMMARY_GLOB = "research/daily-news-malware/*/ioc-summary.json"


def _read_json(path: Path) -> dict[str, Any]:
    snapshot = read_bounded_snapshot(path, MAX_IOC_JSON_BYTES)
    value = decode_strict_json(snapshot.data)
    if not isinstance(value, dict):
        raise TypeError("IOC JSON rootはobjectである必要があります")
    return value


def _defang_restore(value: str) -> str:
    return (
        value.strip()
        .replace("[.]", ".")
        .replace("[:]", ":")
        .replace("hxxps://", "https://")
        .replace("hxxp://", "http://")
    )


def _split_endpoint(entry: dict[str, Any]) -> tuple[str | None, int | None, str | None]:
    """valueを最優先し、URL・host・IPの順でendpointを正規化する。"""
    raw = next(
        (
            str(entry[key])
            for key in ("value", "url", "host", "domain", "address", "ip")
            if entry.get(key) not in (None, "")
        ),
        "",
    )
    raw = _defang_restore(raw)
    scheme: str | None = None
    host: str | None = None
    port: int | None = None
    if "://" in raw:
        parsed = urlsplit(raw)
        scheme = parsed.scheme.casefold()
        host = parsed.hostname
        try:
            port = parsed.port
        except ValueError:
            return None, None, scheme
    elif raw.startswith("[") and "]" in raw:
        closing = raw.index("]")
        host = raw[1:closing]
        suffix = raw[closing + 1 :]
        if suffix.startswith(":") and suffix[1:].isdigit():
            port = int(suffix[1:])
    elif raw.count(":") == 1 and raw.rsplit(":", 1)[1].isdigit():
        host, raw_port = raw.rsplit(":", 1)
        port = int(raw_port)
    else:
        host = raw.split("/", 1)[0]

    if entry.get("port") not in (None, ""):
        try:
            port = int(entry["port"])
        except (TypeError, ValueError):
            return None, None, scheme
    protocol = str(entry.get("protocol") or entry.get("scheme") or scheme or "").casefold()
    if port is None and protocol in DEFAULT_PORTS:
        port = DEFAULT_PORTS[protocol]
    if host:
        host = host.strip().strip(".").casefold()
    return host or None, port, protocol or None


def _candidate_role(role: str, *, container: str) -> tuple[bool, str]:
    normalized = role.casefold()
    if any(marker in normalized for marker in NEGATIVE_ROLE_MARKERS):
        return False, "explicit_non_c2_role"
    if "distribution" in normalized and not any(
        marker in normalized for marker in ("c2", "control", "exfil", "command")
    ):
        return False, "distribution_only"
    if any(marker in normalized for marker in POSITIVE_ROLE_MARKERS):
        return True, "role_matches_c2_or_exfil"
    if container in {"configured_c2", "configured_or_observed_c2"}:
        return True, "configured_c2_container"
    return False, "role_not_c2"


def _host_classification(host: str) -> tuple[bool, str]:
    if host.endswith(".onion"):
        return False, "onion_excluded_by_policy"
    if host.endswith(NON_DNS_SUFFIXES[1:]):
        return False, "non_dns_name_excluded"
    # 利用者の区別がpath側にある共有ホストは、能動監視の対象にしない。
    # 判定は daily_news_malware_intake 側の定義に一本化する。
    if is_shared_service_host(host):
        return False, "shared_service_tenant_in_path_excluded"
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if not FQDN_RE.fullmatch(host):
            return False, "invalid_host"
        return True, "fqdn"
    if not address.is_global:
        return False, "non_global_ip_excluded"
    return True, "global_ip"


def _family_and_sample(path: Path, results_root: Path, payload: dict[str, Any]) -> tuple[str, str | None]:
    relative = path.relative_to(results_root)
    parts = relative.parts
    if results_root.name.casefold() == "malware":
        family = parts[0] if parts else "unknown"
    elif len(parts) >= 2 and parts[0] == "malware":
        family = parts[1]
    elif len(parts) >= 2 and parts[0] == "research":
        family = f"research-{parts[1]}"
    elif parts:
        family = parts[0]
    else:
        family = "unknown"
    sample = path.parent.name.casefold()
    if SHA256_RE.fullmatch(sample):
        return family, sample
    submitted = payload.get("submitted_sample")
    if isinstance(submitted, dict):
        value = str(submitted.get("sha256") or "").casefold()
        if SHA256_RE.fullmatch(value):
            return family, value
    return family, None


def _iter_ioc_entries(payload: dict[str, Any]):
    """既存のlist schemaとresearchのnetwork.c2 schemaを共通化する。"""
    for container in IOC_LIST_KEYS:
        values = payload.get(container)
        if not isinstance(values, list):
            continue
        for index, entry in enumerate(values):
            if isinstance(entry, dict):
                yield container, index, entry
    network = payload.get("network")
    if isinstance(network, dict):
        for index, value in enumerate(network.get("c2") or []):
            yield (
                "network.c2",
                index,
                {
                    "value": value,
                    "role": "c2",
                    "confidence": "research_campaign_record",
                },
            )


def _companion_c2_ports(entries: list[tuple[str, int, dict[str, Any]]]) -> list[int]:
    ports: set[int] = set()
    for _, _, entry in entries:
        role = str(entry.get("role") or "").casefold()
        raw = str(entry.get("value") or "").casefold()
        match = re.fullmatch(r"(\d{1,5})/(?:tcp|udp)", raw)
        if "c2_port" in role and match and 1 <= int(match.group(1)) <= 65535:
            ports.add(int(match.group(1)))
    return sorted(ports)


def _target_id(host: str, port: int, protocol: str) -> str:
    digest = hashlib.sha256(f"{host}|{port}|{protocol}".encode()).hexdigest()[:12]
    return f"all-history-{digest}"


def _canonical_json_sha256(value: Any) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _daily_source_dates(target: dict[str, Any]) -> tuple[str, ...]:
    values = target.get("daily_source_dates", [])
    if not isinstance(values, list) or values != sorted(set(values)):
        raise ValueError("daily_source_datesは重複のない昇順listである必要があります")
    normalized: list[str] = []
    for value in values:
        if not isinstance(value, str) or date.fromisoformat(value).isoformat() != value:
            raise ValueError("daily_source_datesにcanonical dateではない値があります")
        normalized.append(value)
    return tuple(normalized)


def _daily_monitoring_target_identity(target: dict[str, Any]) -> dict[str, Any]:
    host = str(target.get("host") or "").casefold().rstrip(".")
    port = target.get("port")
    target_id = target.get("target_id")
    if (
        not host
        or isinstance(port, bool)
        or not isinstance(port, int)
        or not 0 <= port <= 65535
        or not isinstance(target_id, str)
        or not target_id
    ):
        raise ValueError("daily handoff対象identityが不正です")
    return {
        "target_id": target_id,
        "host": host,
        "port": port,
        "protocol": str(target.get("protocol") or "tcp").casefold(),
        "transport": str(target.get("transport") or "direct").casefold(),
        "method": str(target.get("method") or "tcp_connect"),
        "http_path": str(target.get("http_path") or ""),
    }


def daily_effective_target_commitment(
    targets: Any,
    source_date: str,
) -> tuple[str, int, tuple[str, ...]]:
    """daily sourceへ帰属する実効endpoint集合をexact commitmentへ固定する。"""

    if not isinstance(targets, list):
        raise ValueError("daily handoffのtarget集合はlistである必要があります")
    normalized_date = date.fromisoformat(source_date).isoformat()
    if normalized_date != source_date:
        raise ValueError("daily handoffのsource_dateがcanonicalではありません")
    identities: list[dict[str, Any]] = []
    hosts: set[str] = set()
    for target in targets:
        if not isinstance(target, dict):
            raise ValueError("daily handoffのtargetはobjectである必要があります")
        if normalized_date not in _daily_source_dates(target):
            continue
        identity = _daily_monitoring_target_identity(target)
        identities.append(identity)
        hosts.add(identity["host"])
    identities.sort(
        key=lambda value: json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    if len({_canonical_json_sha256(value) for value in identities}) != len(identities):
        raise ValueError("daily handoffの実効endpoint identityが重複しています")
    commitment = _canonical_json_sha256(
        {
            "schema_version": DAILY_HANDOFF_SCHEMA_VERSION,
            "source_date": normalized_date,
            "targets": identities,
        }
    )
    return commitment, len(identities), tuple(sorted(hosts))


def _daily_ioc_entries(payload: dict[str, Any], source_date: str | None):
    items = payload.get("items")
    if not isinstance(items, list) or any(not isinstance(item, dict) for item in items):
        raise ValueError("daily ioc-summaryのitemsが不正です")
    for index, item in enumerate(items):
        if item.get("valid") is not True or str(item.get("category") or "") != "c2":
            continue
        if str(item.get("ioc_type") or "") not in {"domain", "ip", "url"}:
            continue
        # 共有ホストは daily infrastructure target の集合からも外れている
        # (daily_news_malware_intake 側で同じ判定をしている)。ここで拾うと
        # 「daily sourceのhostが実効targetへ結合されていない」ゲートに引っ掛かる
        # ので、両者の集合を一致させる。
        host, _port, _protocol = _split_endpoint({"value": item.get("ioc_value")})
        if host and is_shared_service_host(host):
            continue
        evidence = {
            "value": item.get("ioc_value"),
            "role": "c2",
            "confidence": "daily_news_ioc_label",
            "daily_malware": str(item.get("malware") or "unknown"),
        }
        if source_date is not None:
            evidence["daily_source_date"] = source_date
        yield (
            "daily_news_handoff",
            index,
            evidence,
        )


def build_inventory(
    results_root: Path,
    *,
    generated_date: str,
    daily_source_date: str | None = None,
    daily_source_summary_path: Path | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if daily_source_summary_path is not None and daily_source_date is None:
        raise ValueError("daily_source_summary_pathにはdaily_source_dateが必要です")
    if daily_source_date is not None:
        try:
            if date.fromisoformat(daily_source_date).isoformat() != daily_source_date:
                raise ValueError
        except (TypeError, ValueError) as exc:
            raise ValueError("daily_source_dateはcanonical YYYY-MM-DDである必要があります") from exc
    if daily_source_summary_path is not None and (
        daily_source_summary_path.name != "ioc-summary.json"
        or daily_source_summary_path.parent.name != daily_source_date
    ):
        raise ValueError("daily_source_summary_pathの日付/path bindingが不正です")
    records: list[dict[str, Any]] = []
    exclusions: list[dict[str, Any]] = []
    scanned = 0
    parse_errors: list[dict[str, str]] = []
    scanned_by_name: Counter[str] = Counter()
    duplicate_evidence: list[dict[str, str]] = []
    seen_evidence: dict[tuple[object, ...], str] = {}
    daily_source_handoffs: dict[str, dict[str, Any]] = {}
    daily_expected_hosts: dict[str, set[str]] = {}
    daily_input_paths = (
        {
            path
            for path in results_root.glob(DAILY_IOC_SUMMARY_GLOB)
            if path.parent.name == daily_source_date
        }
        if daily_source_date is not None
        else set()
    )
    if daily_source_summary_path is not None:
        daily_input_paths.add(daily_source_summary_path)
    input_paths = sorted(
        set(results_root.glob("**/iocs.json"))
        | set(results_root.glob("**/indicators.json"))
        | daily_input_paths,
        key=lambda value: value.as_posix(),
    )
    for path in input_paths:
        scanned += 1
        scanned_by_name[path.name] += 1
        is_daily_summary = path in daily_input_paths
        is_requested_daily_summary = (
            is_daily_summary and path.parent.name == daily_source_date
        )
        try:
            payload = _read_json(path)
        except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
            if is_requested_daily_summary:
                raise ValueError(f"指定daily source summaryを安全に読めません: {daily_source_date}") from exc
            parse_errors.append({"source": str(path), "error": str(exc)})
            continue
        if is_daily_summary:
            case_key = f"research/daily-news-malware/{path.parent.name}"
            source = f"analysis-results/{case_key}/ioc-summary.json"
        else:
            case_key = path.parent.relative_to(results_root).as_posix()
            relative_source = path.relative_to(results_root).as_posix()
            source = f"{results_root.name}/{relative_source}"
        if is_daily_summary:
            source_date = str(payload.get("source_date") or "")
            bind_daily_source = source_date == daily_source_date
            try:
                if date.fromisoformat(source_date).isoformat() != source_date or path.parent.name != source_date:
                    raise ValueError("daily ioc-summaryのsource_date/path bindingが不正です")
                entries = list(
                    _daily_ioc_entries(payload, source_date if bind_daily_source else None)
                )
                if bind_daily_source:
                    commitment, target_count = _daily_infrastructure_target_commitment(
                        payload.get("items") or [],
                        source_date,
                    )
            except (TypeError, ValueError) as exc:
                if is_requested_daily_summary:
                    raise ValueError(f"指定daily source summaryが不正です: {daily_source_date}") from exc
                parse_errors.append({"source": str(path), "error": str(exc)})
                continue
            if bind_daily_source:
                if source_date in daily_source_handoffs:
                    raise ValueError(f"指定daily source summaryが重複しています: {source_date}")
                daily_source_handoffs[source_date] = {
                    "schema_version": DAILY_HANDOFF_SCHEMA_VERSION,
                    "source_date": source_date,
                    "source_target_commitment_sha256": commitment,
                    "source_target_count": target_count,
                }
                daily_expected_hosts[source_date] = set()
            family, sample = "daily-news", None
        else:
            family, sample = _family_and_sample(path, results_root, payload)
            entries = list(_iter_ioc_entries(payload))
        companion_ports = _companion_c2_ports(entries)
        for container, index, entry in entries:
            role = str(entry.get("role") or "").strip()
            normalized_role = role.casefold()
            if "c2_port" in normalized_role and re.fullmatch(
                r"\d{1,5}/(?:tcp|udp)", str(entry.get("value") or "").casefold()
            ):
                continue
            candidate, reason = _candidate_role(role, container=container)
            if not candidate and container == "indicators" and str(entry.get("type") or "").casefold() == "endpoint":
                candidate, reason = True, "campaign_endpoint_evidence"
            evidence = {
                "source": f"{source}:{container}[{index}]",
                "container": container,
                "role": role or "未記載",
                "family": str(entry.get("daily_malware") or family),
                "sample_sha256": sample,
                "confidence": entry.get("confidence"),
            }
            if not candidate:
                exclusions.append({**evidence, "reason": reason})
                continue
            host, port, protocol_hint = _split_endpoint(entry)
            if port is None and "c2" in normalized_role and len(companion_ports) == 1:
                port = companion_ports[0]
            if not host:
                exclusions.append({**evidence, "reason": "endpoint_parse_failed"})
                continue
            record_daily_source_date = entry.get("daily_source_date")
            if isinstance(record_daily_source_date, str):
                daily_expected_hosts[record_daily_source_date].add(host)
            allowed, host_kind = _host_classification(host)
            if not allowed:
                exclusions.append({**evidence, "host": host, "port": port, "reason": host_kind})
                continue
            if port is not None and not 1 <= port <= 65535:
                exclusions.append({**evidence, "host": host, "port": port, "reason": "invalid_port"})
                continue
            confidence_key = json.dumps(
                entry.get("confidence"),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            evidence_key = (
                case_key,
                host,
                port,
                protocol_hint or "",
                normalized_role,
                reason,
                confidence_key,
            )
            if evidence_key in seen_evidence:
                duplicate_evidence.append(
                    {"kept_source": seen_evidence[evidence_key], "duplicate_source": evidence["source"]}
                )
                continue
            seen_evidence[evidence_key] = evidence["source"]
            records.append(
                {
                    **evidence,
                    "host": host,
                    "host_kind": host_kind,
                    "port": port,
                    "protocol_hint": protocol_hint,
                    "selection_reason": reason,
                    "daily_source_date": record_daily_source_date,
                }
            )
    if daily_source_date is not None and daily_source_date not in daily_source_handoffs:
        raise ValueError(
            f"指定daily source summaryが一意に見つかりません: {daily_source_date}"
        )
    known_ports: dict[str, set[int]] = defaultdict(set)
    for record in records:
        if isinstance(record["port"], int):
            known_ports[record["host"]].add(record["port"])

    expanded: list[tuple[tuple[str, int, str], dict[str, Any]]] = []
    for record in records:
        ports = [record["port"]] if record["port"] is not None else sorted(known_ports[record["host"]])
        if not ports:
            ports = [0]
        for port in ports:
            protocol = "dns" if port == 0 else "tcp"
            expanded.append(((record["host"], port, protocol), record))

    grouped: dict[tuple[str, int, str], list[dict[str, Any]]] = defaultdict(list)
    for key, record in expanded:
        grouped[key].append(record)

    targets = []
    for (host, port, protocol), evidence_records in sorted(grouped.items()):
        families = sorted({record["family"] for record in evidence_records})
        samples = sorted({record["sample_sha256"] for record in evidence_records if record["sample_sha256"]})
        sources = sorted({record["source"] for record in evidence_records})
        roles = sorted({record["role"] for record in evidence_records})
        protocol_hints = sorted(
            {
                str(record.get("protocol_hint") or "").casefold()
                for record in evidence_records
                if str(record.get("protocol_hint") or "").casefold() in MALWARE_PROTOCOL_HINTS
            }
        )
        target = {
            "target_id": _target_id(host, port, protocol),
            "family": "/".join(families),
            "host": host,
            "port": port,
            "protocol": protocol,
            "method": "dns_resolve" if port == 0 else "tcp_connect",
            "transport": "direct",
            "sample_sha256s": samples,
            "associated_case_count": len(samples)
            or len({record["source"].rsplit(":", 1)[0] for record in evidence_records}),
            "analyzed_dates": [],
            "sources": sources,
            "roles": roles,
            "selection_basis": "全解析履歴のC2/control/exfil候補",
            "timeout_seconds": 3.0,
            "protocol_hints": protocol_hints,
            "maximum_response_bytes": 256,
        }
        daily_source_dates = sorted(
            {
                record["daily_source_date"]
                for record in evidence_records
                if isinstance(record.get("daily_source_date"), str)
            }
        )
        if daily_source_dates:
            target["daily_source_dates"] = daily_source_dates
        targets.append(target)
    profile_registry = profile_registry_metadata()
    evidence_repository_root = results_root.parent
    registry_repository_root = Path(__file__).resolve().parents[2]
    remus_review_registry = remus_review_registry_metadata(repository_root=registry_repository_root)
    profile_rejections: list[dict[str, str]] = []

    targets, profile_only_target_count = apply_profiles(
        targets,
        repository_root=evidence_repository_root,
        rejections=profile_rejections,
        expected_profile_registry_sha256=profile_registry["sha256"],
        expected_remus_review_registry_sha256=remus_review_registry["sha256"],
    )
    reviewed_profile_hosts = {target["host"] for target in targets if target.get("protocol_profile_id")}
    if profile_registry_metadata() != profile_registry:
        raise ValueError("C2 protocol profile registry changed during plan generation")
    if remus_review_registry_metadata(repository_root=registry_repository_root) != remus_review_registry:
        raise ValueError("Remus review registry changed during plan generation")
    profile_rejections.sort(key=lambda value: (value["profile_id"], value["reason_code"]))
    ordinary_hosts = sorted({record["host"] for record in records} | reviewed_profile_hosts)
    for target in targets:
        protocol_hints = target.get("protocol_hints") or []
        if target.get("protocol_profile_id") or not protocol_hints or int(target.get("port") or 0) == 0:
            continue
        target.update(
            {
                "method": "protocol_profile_required",
                "protocol_profile_required": True,
                "protocol_profile_status": (
                    "reviewed_exact_profile_missing"
                    if len(protocol_hints) == 1
                    else "conflicting_explicit_protocol_hints"
                ),
            }
        )
    for source_date, handoff in sorted(daily_source_handoffs.items()):
        effective_commitment, effective_count, effective_hosts = daily_effective_target_commitment(
            targets,
            source_date,
        )
        if set(effective_hosts) != daily_expected_hosts[source_date]:
            raise ValueError(
                f"daily source対象が実効C2 targetへ完全に結合されていません: {source_date}"
            )
        if len(effective_hosts) != handoff["source_target_count"]:
            raise ValueError(
                f"daily source対象件数と実効C2 host件数が一致しません: {source_date}"
            )
        handoff.update(
            {
                "effective_target_commitment_sha256": effective_commitment,
                "effective_target_count": effective_count,
            }
        )
    reason_counts = Counter(item["reason"] for item in exclusions)
    inventory = {
        "schema_version": 2,
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "scope": "analysis-results配下のiocs.json／indicators.json全履歴（malware／clickfix／research）",
        "policy": {
            "onion_excluded": True,
            "ordinary_global_ip_and_fqdn_included": True,
            "known_port_check": "単一endpointへの限定probeを1回。レビュー済み完全一致profileはmalware固有protocolで確認",
            "unknown_port_check": "DNS解決のみ（C2稼働確認とは扱わない）",
            "distribution_only_and_explicit_non_c2_excluded": True,
            "shared_service_tenant_in_path_excluded": sorted(SHARED_SERVICE_HOSTS),
        },
        "scanned_ioc_file_count": scanned,
        "scanned_iocs_json_file_count": scanned_by_name["iocs.json"],
        "scanned_indicators_json_file_count": scanned_by_name["indicators.json"],
        "scanned_daily_ioc_summary_file_count": scanned_by_name["ioc-summary.json"],
        "duplicate_evidence_record_count": len(duplicate_evidence),
        "duplicate_evidence": duplicate_evidence,
        "parse_error_count": len(parse_errors),
        "candidate_evidence_record_count": len(records),
        "ordinary_candidate_host_count": len(ordinary_hosts),
        "planned_ordinary_host_count": len({target["host"] for target in targets}),
        "planned_endpoint_count": len(targets),
        "reviewed_protocol_target_count": sum(bool(target.get("protocol_profile_id")) for target in targets),
        "reviewed_profile_only_target_count": profile_only_target_count,
        "network_service_endpoint_count": sum(target["port"] != 0 for target in targets),
        "dns_only_target_count": sum(target["port"] == 0 for target in targets),
        "rejected_protocol_profile_count": len(profile_rejections),
        "rejected_protocol_profiles": profile_rejections,
        "ordinary_host_coverage_percent": round(
            100 * len({target["host"] for target in targets}) / len(ordinary_hosts), 2
        )
        if ordinary_hosts
        else 100.0,
        "exclusion_reason_counts": dict(sorted(reason_counts.items())),
        "exclusions": exclusions,
        "parse_errors": parse_errors,
    }
    plan = {
        "schema_version": 1,
        "analysis_window": {
            "start": "リポジトリ収録開始",
            "end": f"{generated_date}T23:59:59+09:00",
        },
        "collection_scope": "all_historical_c2",
        "onion_excluded_by_policy": True,
        "protocol_profile_registry": profile_registry,
        "remus_review_registry": remus_review_registry,
        "inventory_summary": {
            key: inventory[key]
            for key in (
                "scanned_ioc_file_count",
                "scanned_iocs_json_file_count",
                "scanned_indicators_json_file_count",
                "scanned_daily_ioc_summary_file_count",
                "duplicate_evidence_record_count",
                "parse_error_count",
                "candidate_evidence_record_count",
                "ordinary_candidate_host_count",
                "planned_ordinary_host_count",
                "planned_endpoint_count",
                "reviewed_protocol_target_count",
                "reviewed_profile_only_target_count",
                "rejected_protocol_profile_count",
                "network_service_endpoint_count",
                "dns_only_target_count",
                "ordinary_host_coverage_percent",
            )
        },
        "daily_source_handoffs": [daily_source_handoffs[key] for key in sorted(daily_source_handoffs)],
        "targets": targets,
    }
    return plan, inventory


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results-root", "--malware-root", dest="results_root", type=Path, required=True)
    parser.add_argument("--output-plan", type=Path, required=True)
    parser.add_argument("--output-inventory", type=Path, required=True)
    parser.add_argument("--date", required=True)
    parser.add_argument(
        "--daily-source-date",
        help="この日付のdaily ioc-summaryだけを実効targetへ厳密結合する",
    )
    parser.add_argument(
        "--daily-source-summary",
        type=Path,
        help="未昇格stagingにある当日ioc-summary.jsonを厳密結合する",
    )
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    plan, inventory = build_inventory(
        args.results_root,
        generated_date=args.date,
        daily_source_date=args.daily_source_date,
        daily_source_summary_path=args.daily_source_summary,
    )
    if args.write:
        args.output_plan.parent.mkdir(parents=True, exist_ok=True)
        args.output_inventory.parent.mkdir(parents=True, exist_ok=True)
        args.output_plan.write_text(json.dumps(plan, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        args.output_inventory.write_text(json.dumps(inventory, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({**plan["inventory_summary"], "write_performed": args.write}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
