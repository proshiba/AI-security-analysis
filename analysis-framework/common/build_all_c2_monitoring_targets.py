#!/usr/bin/env python3
"""全解析履歴のIOCから、C2ライブチェック対象と監査在庫を生成する。"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from c2_protocol_probe_profiles import apply_profiles


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


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    return value if isinstance(value, dict) else {}


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


def build_inventory(results_root: Path, *, generated_date: str) -> tuple[dict[str, Any], dict[str, Any]]:
    records: list[dict[str, Any]] = []
    exclusions: list[dict[str, Any]] = []
    scanned = 0
    parse_errors: list[dict[str, str]] = []
    for path in sorted(results_root.glob("**/iocs.json")):
        scanned += 1
        try:
            payload = _read_json(path)
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            parse_errors.append({"source": str(path), "error": str(exc)})
            continue
        family, sample = _family_and_sample(path, results_root, payload)
        source = path.as_posix()
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
                "family": family,
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
            allowed, host_kind = _host_classification(host)
            if not allowed:
                exclusions.append({**evidence, "host": host, "port": port, "reason": host_kind})
                continue
            if port is not None and not 1 <= port <= 65535:
                exclusions.append({**evidence, "host": host, "port": port, "reason": "invalid_port"})
                continue
            records.append(
                {
                    **evidence,
                    "host": host,
                    "host_kind": host_kind,
                    "port": port,
                    "protocol_hint": protocol_hint,
                    "selection_reason": reason,
                }
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
            "maximum_response_bytes": 256,
        }
        targets.append(target)

    targets, profile_only_target_count = apply_profiles(
        targets,
        repository_root=results_root.parent,
    )
    reviewed_profile_hosts = {target["host"] for target in targets if target.get("protocol_profile_id")}
    ordinary_hosts = sorted({record["host"] for record in records} | reviewed_profile_hosts)
    reason_counts = Counter(item["reason"] for item in exclusions)
    inventory = {
        "schema_version": 1,
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "scope": "analysis-results配下の全IOC履歴（malware／clickfix／research）",
        "policy": {
            "onion_excluded": True,
            "ordinary_global_ip_and_fqdn_included": True,
            "known_port_check": "単一endpointへの限定probeを1回。レビュー済み完全一致profileはmalware固有protocolで確認",
            "unknown_port_check": "DNS解決のみ（C2稼働確認とは扱わない）",
            "distribution_only_and_explicit_non_c2_excluded": True,
        },
        "scanned_ioc_file_count": scanned,
        "parse_error_count": len(parse_errors),
        "candidate_evidence_record_count": len(records),
        "ordinary_candidate_host_count": len(ordinary_hosts),
        "planned_ordinary_host_count": len({target["host"] for target in targets}),
        "planned_endpoint_count": len(targets),
        "reviewed_protocol_target_count": sum(bool(target.get("protocol_profile_id")) for target in targets),
        "reviewed_profile_only_target_count": profile_only_target_count,
        "network_service_endpoint_count": sum(target["port"] != 0 for target in targets),
        "dns_only_target_count": sum(target["port"] == 0 for target in targets),
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
        "inventory_summary": {
            key: inventory[key]
            for key in (
                "scanned_ioc_file_count",
                "candidate_evidence_record_count",
                "ordinary_candidate_host_count",
                "planned_ordinary_host_count",
                "planned_endpoint_count",
                "reviewed_protocol_target_count",
                "reviewed_profile_only_target_count",
                "network_service_endpoint_count",
                "dns_only_target_count",
                "ordinary_host_coverage_percent",
            )
        },
        "targets": targets,
    }
    return plan, inventory


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results-root", "--malware-root", dest="results_root", type=Path, required=True)
    parser.add_argument("--output-plan", type=Path, required=True)
    parser.add_argument("--output-inventory", type=Path, required=True)
    parser.add_argument("--date", required=True)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    plan, inventory = build_inventory(args.results_root, generated_date=args.date)
    if args.write:
        args.output_plan.parent.mkdir(parents=True, exist_ok=True)
        args.output_inventory.parent.mkdir(parents=True, exist_ok=True)
        args.output_plan.write_text(json.dumps(plan, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        args.output_inventory.write_text(json.dumps(inventory, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({**plan["inventory_summary"], "write_performed": args.write}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
