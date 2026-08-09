#!/usr/bin/env python3
"""C2のDNS/IP遷移と稼働ライフサイクルを日次観測から生成する。"""

from __future__ import annotations

import argparse
from copy import deepcopy
from datetime import UTC, datetime
import json
from pathlib import Path
import re
from typing import Any

from c2_infrastructure_tags import build_ip_detail, load_registry, missing_ip_detail


RETIREMENT_AFTER_DAYS = 7
MINIMUM_OFF_OBSERVATIONS = 2
SHARED_CDN_ASNS = {
    13335: "Cloudflare",
    16625: "Akamai",
    20940: "Akamai",
    54113: "Fastly",
}
SHARED_CDN_ORGANIZATION_MARKERS = {
    "cloudflare": "Cloudflare",
    "akamai": "Akamai",
    "fastly": "Fastly",
    "stackpath": "StackPath",
    "highwinds": "StackPath",
    "cachefly": "CacheFly",
    "bunny": "Bunny CDN",
    "incapsula": "Imperva",
    "imperva": "Imperva",
    "cloudfront": "Amazon CloudFront",
}
REACHABLE_STATES = {
    "c2_protocol_confirmed",
    "application_endpoint_reachable_c2_not_confirmed",
    "server_first_response_reachable_c2_not_confirmed",
    "tls_endpoint_reachable_c2_not_confirmed",
    "transport_reachable_c2_not_confirmed",
}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SAFE_ACTIVITY_TOKEN_RE = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,63}$")
REQUIRED_PROTOCOL_ACTIVITY_FALSE_FIELDS = (
    "task_executed",
    "real_effect_performed",
    "payload_download_attempted",
    "followup_network_attempted",
    "raw_transcript_published",
)


def _public_count(value: object, *, maximum: int = 1_000_000) -> int:
    if type(value) is int and 0 <= value <= maximum:
        return value
    return 0


def _safe_protocol_activity(entry: dict[str, Any]) -> dict[str, Any]:
    activity = (
        entry.get("rat_emulation")
        if isinstance(entry.get("rat_emulation"), dict)
        else {}
    )
    if any(
        activity.get(field) is not False
        for field in REQUIRED_PROTOCOL_ACTIVITY_FALSE_FIELDS
    ):
        return {}
    return activity


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON rootはobjectである必要があります: {path}")
    return value


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def endpoint_key(value: dict[str, Any]) -> str:
    """endpointを履歴間で安定して結合するkeyを返す。"""
    host = str(value.get("host") or "").casefold().rstrip(".")
    port = int(value.get("port") or 0)
    protocol = str(value.get("protocol") or "tcp").casefold()
    transport = str(value.get("transport") or "direct").casefold()
    path = str(value.get("http_path") or "")
    return "|".join((host, str(port), protocol, transport, path))


def _parse_timestamp(value: object, run_date: str) -> datetime:
    if isinstance(value, str) and value:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is not None:
                return parsed.astimezone(UTC)
        except ValueError:
            pass
    try:
        return datetime.fromisoformat(run_date).replace(tzinfo=UTC)
    except ValueError as exc:
        raise ValueError(f"観測日時を解釈できません: {run_date}") from exc


def _availability(entry: dict[str, Any], policy: dict[str, Any]) -> str:
    """観測をON、OFF、未観測へ正規化する。"""
    rat_emulation = _safe_protocol_activity(entry)
    if (
        _public_count(rat_emulation.get("c2_confirmed_session_count")) > 0
        or _public_count(rat_emulation.get("command_count")) > 0
    ):
        return "on"
    if policy.get("network_enabled") is not True:
        return "not_observed"
    assessment = entry.get("assessment") if isinstance(entry.get("assessment"), dict) else {}
    state = str(assessment.get("state") or "")
    if state in REACHABLE_STATES:
        return "on"
    if state == "not_reachable_at_observation":
        return "off"
    observation = entry.get("observation") if isinstance(entry.get("observation"), dict) else {}
    if observation.get("target_connection_established") or observation.get("alive"):
        return "on"
    if observation.get("target_contact_attempted"):
        return "off"
    return "not_observed"


def _cdn_provider(asn: object, organization: object) -> str | None:
    if isinstance(asn, int) and not isinstance(asn, bool) and asn in SHARED_CDN_ASNS:
        return SHARED_CDN_ASNS[asn]
    normalized = str(organization or "").casefold()
    for marker, provider in SHARED_CDN_ORGANIZATION_MARKERS.items():
        if marker in normalized:
            return provider
    return None


def _dns_point(
    entry: dict[str, Any],
    *,
    run_date: str,
    policy: dict[str, Any],
    registry: dict[str, Any],
) -> dict[str, Any]:
    observation = entry.get("observation") if isinstance(entry.get("observation"), dict) else {}
    resolved_ips = observation.get("resolved_ips")
    ips = sorted({str(value) for value in resolved_ips}) if isinstance(resolved_ips, list) else []
    maxmind = entry.get("maxmind") if isinstance(entry.get("maxmind"), dict) else {}
    records = maxmind.get("records") if isinstance(maxmind.get("records"), list) else []
    asn_by_ip: dict[str, int] = {}
    organization_by_ip: dict[str, str] = {}
    provider_by_ip: dict[str, str] = {}
    for record in records:
        if not isinstance(record, dict):
            continue
        address = str(record.get("ip") or "")
        as_record = record.get("as") if isinstance(record.get("as"), dict) else {}
        asn = as_record.get("autonomous_system_number")
        organization = str(as_record.get("autonomous_system_organization") or "")
        if address and isinstance(asn, int) and not isinstance(asn, bool):
            asn_by_ip[address] = asn
        if address and organization:
            organization_by_ip[address] = organization
        provider = _cdn_provider(asn, organization)
        if address and provider:
            provider_by_ip[address] = provider
    shared_provider = None
    providers = {provider_by_ip.get(address) for address in ips}
    if ips and None not in providers and len(providers) == 1:
        shared_provider = next(iter(providers))
    record_by_ip = {
        str(record.get("ip") or ""): record
        for record in records
        if isinstance(record, dict) and record.get("ip")
    }
    host = str(entry.get("host") or "")
    ip_details = [
        (
            build_ip_detail(
                record_by_ip[address],
                host=host,
                shared_cdn_provider=shared_provider,
                registry=registry,
            )
            if address in record_by_ip
            else missing_ip_detail(
                address,
                host=host,
                shared_cdn_provider=shared_provider,
                registry=registry,
            )
        )
        for address in ips
    ]
    timestamp = _parse_timestamp(observation.get("timestamp_utc"), run_date)
    return {
        "date": run_date,
        "observed_at_utc": timestamp.isoformat(),
        "ips": ips,
        "asns": sorted(set(asn_by_ip.values())),
        "organizations": sorted(set(organization_by_ip.values())),
        "shared_cdn_provider": shared_provider,
        "ip_details": ip_details,
        "availability": _availability(entry, policy),
        "assessment_state": (entry.get("assessment") or {}).get("state"),
        "raw_ip_changed": False,
        "infrastructure_ip_change": False,
        "change_classification": "initial_observation",
    }


def _protocol_activity_point(
    entry: dict[str, Any],
    *,
    run_date: str,
) -> dict[str, Any] | None:
    """公開済みRAT session要約を、到達性と独立した活動点へ正規化する。"""

    activity = _safe_protocol_activity(entry)
    session_count = _public_count(activity.get("session_count"), maximum=256)
    if session_count <= 0:
        return None
    commands = [
        command
        for command in activity.get("command_fingerprints", [])
        if isinstance(command, dict)
    ]
    command_fingerprints = sorted(
        {
            str(command.get("wire_sha256"))
            for command in commands
            if type(command.get("wire_sha256")) is str
            and SHA256_RE.fullmatch(command["wire_sha256"]) is not None
        }
    )
    message_kinds = sorted(
        {
            str(command.get("message_kind"))
            for command in commands
            if type(command.get("message_kind")) is str
            and SAFE_ACTIVITY_TOKEN_RE.fullmatch(command["message_kind"])
            is not None
        }
    )
    command_count = _public_count(activity.get("command_count"), maximum=64)
    if command_count != len(commands) or len(command_fingerprints) > command_count:
        return None
    connection_count = _public_count(
        activity.get("connection_established_count"),
        maximum=session_count,
    )
    handshake_count = _public_count(
        activity.get("handshake_confirmed_count"),
        maximum=session_count,
    )
    confirmed_count = _public_count(
        activity.get("c2_confirmed_session_count"),
        maximum=session_count,
    )
    reply_count = _public_count(
        activity.get("synthetic_reply_count"),
        maximum=64,
    )
    raw_status_counts = (
        activity.get("status_counts")
        if isinstance(activity.get("status_counts"), dict)
        else {}
    )
    status_counts = {
        key: count
        for key, value in raw_status_counts.items()
        if type(key) is str
        and SAFE_ACTIVITY_TOKEN_RE.fullmatch(key) is not None
        and (count := _public_count(value, maximum=session_count)) > 0
    }
    observed_at = _parse_timestamp(
        activity.get("latest_session_at_utc"),
        run_date,
    )
    return {
        "date": run_date,
        "observed_at_utc": observed_at.isoformat(),
        "session_count": session_count,
        "connection_established_count": connection_count,
        "handshake_confirmed_count": handshake_count,
        "c2_confirmed_session_count": confirmed_count,
        "command_count": command_count,
        "command_fingerprints": command_fingerprints,
        "message_kinds": message_kinds,
        "synthetic_reply_count": reply_count,
        "synthetic_reply_sent": reply_count > 0,
        "status_counts": dict(sorted(status_counts.items())),
        "task_executed": False,
        "real_effect_performed": False,
        "payload_download_attempted": False,
        "followup_network_attempted": False,
        "raw_transcript_published": False,
        "command_absence_is_off_evidence": False,
    }


def build_protocol_activity_tracking(
    points: list[dict[str, Any]],
) -> dict[str, Any]:
    """RAT sessionとcommand fingerprintの時系列を構築する。"""

    ordered = sorted(points, key=lambda point: point["observed_at_utc"])
    seen_fingerprints: set[str] = set()
    transitions: list[dict[str, Any]] = []
    for point in ordered:
        current = set(point["command_fingerprints"])
        new_fingerprints = sorted(current - seen_fingerprints)
        point["new_command_fingerprints"] = new_fingerprints
        point["activity_state"] = (
            "command_observed"
            if point["command_count"] > 0
            else (
                "protocol_confirmed_without_command"
                if point["c2_confirmed_session_count"] > 0
                else "session_without_confirmed_command"
            )
        )
        if new_fingerprints:
            transitions.append(
                {
                    "observed_at_utc": point["observed_at_utc"],
                    "event": "new_command_fingerprint_observed",
                    "fingerprints": new_fingerprints,
                    "message_kinds": point["message_kinds"],
                }
            )
        seen_fingerprints.update(current)
    command_points = [point for point in ordered if point["command_count"] > 0]
    return {
        "schema_version": 1,
        "history": ordered,
        "session_count": sum(point["session_count"] for point in ordered),
        "command_observation_count": sum(
            point["command_count"] for point in ordered
        ),
        "unique_command_fingerprint_count": len(seen_fingerprints),
        "synthetic_reply_count": sum(
            point["synthetic_reply_count"] for point in ordered
        ),
        "synthetic_reply_sent": any(
            point["synthetic_reply_sent"] for point in ordered
        ),
        "first_command_at_utc": (
            command_points[0]["observed_at_utc"] if command_points else None
        ),
        "last_command_at_utc": (
            command_points[-1]["observed_at_utc"] if command_points else None
        ),
        "transitions": transitions,
        "command_absence_is_off_evidence": False,
        "task_executed": False,
        "real_effect_performed": False,
    }


def classify_dns_transitions(points: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """共有CDN内のIPローテーションをインフラ変化から除外する。"""
    ordered = sorted(points, key=lambda point: point["observed_at_utc"])
    previous: dict[str, Any] | None = None
    for point in ordered:
        if previous is None:
            previous = point
            continue
        raw_changed = point["ips"] != previous["ips"]
        point["raw_ip_changed"] = raw_changed
        if not raw_changed:
            point["change_classification"] = "unchanged"
        elif not point["ips"] or not previous["ips"]:
            point["change_classification"] = "resolution_state_changed"
        elif (
            point.get("shared_cdn_provider")
            and point.get("shared_cdn_provider") == previous.get("shared_cdn_provider")
        ):
            point["change_classification"] = "shared_cdn_rotation_ignored"
        else:
            point["infrastructure_ip_change"] = True
            point["change_classification"] = "infrastructure_ip_change"
        if raw_changed:
            previous_details = {
                detail.get("ip"): detail
                for detail in previous.get("ip_details", [])
                if isinstance(detail, dict) and detail.get("ip")
            }
            current_details = {
                detail.get("ip"): detail
                for detail in point.get("ip_details", [])
                if isinstance(detail, dict) and detail.get("ip")
            }
            removed = sorted(set(previous_details) - set(current_details))
            added = sorted(set(current_details) - set(previous_details))
            point["transition"] = {
                "observed_at_utc": point["observed_at_utc"],
                "from": [previous_details[address] for address in sorted(previous_details)],
                "to": [current_details[address] for address in sorted(current_details)],
                "removed": [previous_details[address] for address in removed],
                "added": [current_details[address] for address in added],
                "classification": point["change_classification"],
                "infrastructure_ip_change": point["infrastructure_ip_change"],
                "shared_cdn_provider": point.get("shared_cdn_provider"),
            }
        else:
            point["transition"] = None
        previous = point
    return ordered


def _lifecycle(
    points: list[dict[str, Any]],
    *,
    retirement_days: int,
    minimum_off_observations: int,
) -> dict[str, Any]:
    latest = points[-1]
    latest_at = _parse_timestamp(latest["observed_at_utc"], latest["date"])
    last_on_index = max(
        (index for index, point in enumerate(points) if point["availability"] == "on"),
        default=-1,
    )
    trailing = points[last_on_index + 1 :]
    off_points = [point for point in trailing if point["availability"] == "off"]
    if last_on_index >= 0:
        inactive_since = _parse_timestamp(
            points[last_on_index]["observed_at_utc"],
            points[last_on_index]["date"],
        )
    elif off_points:
        inactive_since = _parse_timestamp(
            off_points[0]["observed_at_utc"],
            off_points[0]["date"],
        )
    else:
        inactive_since = None
    inactive_days = (
        max(0.0, (latest_at - inactive_since).total_seconds() / 86400)
        if inactive_since is not None
        else 0.0
    )
    previous_retired = any(
        point.get("prior_lifecycle_status") == "retired_stopped" for point in points[:-1]
    )
    transition = None
    if latest["availability"] == "on":
        status = "active_on"
        if previous_retired:
            transition = "monitoring_reactivated_after_new_evidence"
    elif (
        latest["availability"] == "off"
        and inactive_days >= retirement_days
        and len(off_points) >= minimum_off_observations
    ):
        status = "retired_stopped"
        if not previous_retired:
            transition = "monitoring_stopped_after_7d_without_on"
    elif latest["availability"] == "off":
        status = "active_grace"
    else:
        status = "active_unobserved"
    last_on = points[last_on_index]["observed_at_utc"] if last_on_index >= 0 else None
    return {
        "schema_version": 1,
        "status": status,
        "active": status != "retired_stopped",
        "first_observed_at_utc": points[0]["observed_at_utc"],
        "last_observed_at_utc": latest["observed_at_utc"],
        "last_on_at_utc": last_on,
        "inactive_since_utc": inactive_since.isoformat() if inactive_since else None,
        "inactive_days": round(inactive_days, 3),
        "off_observation_count_since_last_on": len(off_points),
        "retirement_threshold_days": retirement_days,
        "minimum_off_observations": minimum_off_observations,
        "retired_at_utc": latest["observed_at_utc"] if status == "retired_stopped" else None,
        "transition": transition,
    }


def _previous_runs(
    history_root: Path,
    *,
    current_run_name: str,
) -> list[tuple[str, dict[str, Any]]]:
    runs: list[tuple[str, dict[str, Any]]] = []
    if not history_root.is_dir():
        return runs
    for directory in sorted(path for path in history_root.iterdir() if path.is_dir()):
        if directory.name >= current_run_name:
            continue
        results = directory / "monitoring-results.json"
        if results.is_file():
            runs.append((directory.name, load_json(results)))
    return runs


def load_latest_active_plan(
    history_root: Path,
    *,
    current_run_name: str,
) -> dict[str, Any] | None:
    """直近runのactive対象を返し、旧成果物ではtargets.jsonへfallbackする。"""
    if not history_root.is_dir():
        return None
    directories = sorted(
        (
            path
            for path in history_root.iterdir()
            if path.is_dir() and path.name < current_run_name
        ),
        reverse=True,
    )
    for directory in directories:
        for filename in ("active-targets.json", "effective-targets.json", "targets.json"):
            candidate = directory / filename
            if candidate.is_file():
                return load_json(candidate)
    return None


def carry_forward_active_targets(
    plan: dict[str, Any],
    active_plan: dict[str, Any] | None,
) -> tuple[dict[str, Any], int]:
    """直近active対象を当日新規対象へ統合する。"""
    merged = deepcopy(plan)
    targets = merged.get("targets")
    if not isinstance(targets, list):
        raise ValueError("targetsはlistである必要があります")
    by_key = {endpoint_key(target): target for target in targets if isinstance(target, dict)}
    carried = 0
    for prior in (active_plan or {}).get("targets", []):
        if not isinstance(prior, dict):
            continue
        if (
            merged.get("onion_excluded_by_policy")
            and str(prior.get("host") or "").casefold().endswith(".onion")
        ):
            continue
        key = endpoint_key(prior)
        if key not in by_key:
            copied = deepcopy(prior)
            targets.append(copied)
            by_key[key] = copied
            carried += 1
            continue
        current = by_key[key]
        for field in ("sample_sha256s", "analyzed_dates", "sources", "roles"):
            values = current.setdefault(field, [])
            for value in prior.get(field, []):
                if value not in values:
                    values.append(value)
        current["associated_case_count"] = max(
            int(current.get("associated_case_count", 0)),
            int(prior.get("associated_case_count", 0)),
        )
    return merged, carried


def apply_monitoring_history(
    current: dict[str, Any],
    plan: dict[str, Any],
    *,
    history_root: Path,
    current_run_name: str,
    retirement_days: int = RETIREMENT_AFTER_DAYS,
    minimum_off_observations: int = MINIMUM_OFF_OBSERVATIONS,
    classification_registry: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """過去runと今回結果から履歴、注釈済み結果、次回active計画を返す。"""
    if retirement_days < 7:
        raise ValueError("retirement_daysは7以上である必要があります")
    if minimum_off_observations < 2:
        raise ValueError("minimum_off_observationsは2以上である必要があります")
    if classification_registry is None:
        classification_registry = load_registry()
    runs = _previous_runs(history_root, current_run_name=current_run_name)
    runs.append((current_run_name, current))
    points_by_endpoint: dict[str, list[dict[str, Any]]] = {}
    activity_points_by_endpoint: dict[str, list[dict[str, Any]]] = {}
    metadata_by_endpoint: dict[str, dict[str, Any]] = {}
    current_entries: dict[str, dict[str, Any]] = {}
    for run_date, payload in runs:
        policy = payload.get("policy") if isinstance(payload.get("policy"), dict) else {}
        for entry in payload.get("results", []):
            if not isinstance(entry, dict):
                continue
            key = endpoint_key(entry)
            point = _dns_point(
                entry,
                run_date=run_date,
                policy=policy,
                registry=classification_registry,
            )
            lifecycle = entry.get("monitoring_lifecycle")
            if isinstance(lifecycle, dict):
                point["prior_lifecycle_status"] = lifecycle.get("status")
                point["prior_transition"] = lifecycle.get("transition")
            points_by_endpoint.setdefault(key, []).append(point)
            activity_point = _protocol_activity_point(entry, run_date=run_date)
            if activity_point is not None:
                activity_points_by_endpoint.setdefault(key, []).append(activity_point)
            metadata_by_endpoint[key] = {
                "endpoint_key": key,
                "target_id": entry.get("target_id"),
                "family": entry.get("family"),
                "host": entry.get("host"),
                "port": entry.get("port"),
                "protocol": entry.get("protocol"),
                "transport": entry.get("transport"),
                "http_path": entry.get("http_path"),
            }
            if run_date == current_run_name:
                current_entries[key] = entry

    history_endpoints: list[dict[str, Any]] = []
    lifecycle_by_endpoint: dict[str, dict[str, Any]] = {}
    activity_tracking_by_endpoint: dict[str, dict[str, Any]] = {}
    for key, raw_points in points_by_endpoint.items():
        deduplicated = {
            (point["observed_at_utc"], tuple(point["ips"])): point for point in raw_points
        }
        points = classify_dns_transitions(list(deduplicated.values()))
        lifecycle = _lifecycle(
            points,
            retirement_days=retirement_days,
            minimum_off_observations=minimum_off_observations,
        )
        lifecycle_by_endpoint[key] = lifecycle
        events = [
            {
                "observed_at_utc": point["observed_at_utc"],
                "event": point["prior_transition"],
            }
            for point in points
            if point.get("prior_transition")
        ]
        if lifecycle.get("transition") and not any(
            event["event"] == lifecycle["transition"]
            and event["observed_at_utc"] == lifecycle["last_observed_at_utc"]
            for event in events
        ):
            events.append(
                {
                    "observed_at_utc": lifecycle["last_observed_at_utc"],
                    "event": lifecycle["transition"],
                }
            )
        dns_tracking = {
            "schema_version": 1,
            "history": [
                {key: value for key, value in point.items() if not key.startswith("prior_")}
                for point in points
            ],
            "raw_ip_change_count": sum(point["raw_ip_changed"] for point in points),
            "infrastructure_ip_change_count": sum(
                point["infrastructure_ip_change"] for point in points
            ),
            "shared_cdn_rotation_ignored_count": sum(
                point["change_classification"] == "shared_cdn_rotation_ignored"
                for point in points
            ),
            "transitions": [
                point["transition"] for point in points if point.get("transition")
            ],
        }
        raw_activity_points = activity_points_by_endpoint.get(key, [])
        activity_tracking = None
        if raw_activity_points:
            deduplicated_activity = {
                (
                    point["observed_at_utc"],
                    point["session_count"],
                    point["command_count"],
                    tuple(point["command_fingerprints"]),
                    point["synthetic_reply_count"],
                ): point
                for point in raw_activity_points
            }
            activity_tracking = build_protocol_activity_tracking(
                list(deduplicated_activity.values())
            )
            activity_tracking_by_endpoint[key] = activity_tracking
        current_entry = current_entries.get(key)
        if current_entry is not None:
            current_entry["availability_status"] = points[-1]["availability"]
            current_entry["dns_tracking"] = dns_tracking
            current_entry["monitoring_lifecycle"] = lifecycle
            if activity_tracking is not None:
                current_entry["protocol_activity_tracking"] = activity_tracking
        history_endpoint = {
            **metadata_by_endpoint[key],
            "dns_tracking": dns_tracking,
            "monitoring_lifecycle": lifecycle,
            "events": sorted(events, key=lambda event: event["observed_at_utc"]),
        }
        if activity_tracking is not None:
            history_endpoint["protocol_activity_tracking"] = activity_tracking
        history_endpoints.append(history_endpoint)

    targets = plan.get("targets") if isinstance(plan.get("targets"), list) else []
    active_targets = [
        deepcopy(target)
        for target in targets
        if lifecycle_by_endpoint.get(endpoint_key(target), {}).get("active", True)
    ]
    active_plan = deepcopy(plan)
    active_plan["targets"] = active_targets
    active_plan["lifecycle_policy"] = {
        "retirement_after_days_without_on": retirement_days,
        "minimum_off_observations": minimum_off_observations,
        "shared_cdn_rotation_counts_as_infrastructure_change": False,
    }
    active_plan["generated_from_run"] = current_run_name
    retired_count = sum(
        lifecycle.get("status") == "retired_stopped"
        for lifecycle in lifecycle_by_endpoint.values()
    )
    monitoring_history_summary = {
        "schema_version": 1,
        "endpoint_count": len(history_endpoints),
        "active_target_count": len(active_targets),
        "retired_target_count": retired_count,
        "retirement_after_days_without_on": retirement_days,
        "minimum_off_observations": minimum_off_observations,
        "shared_cdn_rotation_counts_as_infrastructure_change": False,
    }
    if activity_tracking_by_endpoint:
        monitoring_history_summary.update(
            {
                "protocol_activity_endpoint_count": len(
                    activity_tracking_by_endpoint
                ),
                "protocol_activity_session_count": sum(
                    item["session_count"]
                    for item in activity_tracking_by_endpoint.values()
                ),
                "protocol_command_observation_count": sum(
                    item["command_observation_count"]
                    for item in activity_tracking_by_endpoint.values()
                ),
                "protocol_synthetic_reply_count": sum(
                    item["synthetic_reply_count"]
                    for item in activity_tracking_by_endpoint.values()
                ),
                "protocol_synthetic_reply_sent": any(
                    item["synthetic_reply_sent"]
                    for item in activity_tracking_by_endpoint.values()
                ),
                "command_absence_is_off_evidence": False,
            }
        )
    current["monitoring_history_summary"] = monitoring_history_summary
    history = {
        "schema_version": 1,
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "current_run": current_run_name,
        "policy": current["monitoring_history_summary"],
        "endpoints": sorted(
            history_endpoints,
            key=lambda endpoint: (
                str(endpoint.get("host") or ""),
                int(endpoint.get("port") or 0),
            ),
        ),
    }
    return current, history, active_plan


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--targets", type=Path, required=True)
    parser.add_argument("--history-root", type=Path, required=True)
    parser.add_argument("--run-name", required=True)
    parser.add_argument("--output-directory", type=Path, required=True)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    try:
        result, history, active_plan = apply_monitoring_history(
            load_json(args.results),
            load_json(args.targets),
            history_root=args.history_root,
            current_run_name=args.run_name,
        )
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        parser.error(str(exc))
    if args.write:
        write_json(args.results, result)
        write_json(args.output_directory / "monitoring-history.json", history)
        write_json(args.output_directory / "active-targets.json", active_plan)
        write_json(args.output_directory / "effective-targets.json", load_json(args.targets))
        from run_c2_monitoring_pipeline import render_enriched_report

        (args.output_directory / "README.md").write_text(
            render_enriched_report(result),
            encoding="utf-8",
        )
    print(
        json.dumps(
            {
                **result["monitoring_history_summary"],
                "results": str(args.results),
                "write_performed": args.write,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
