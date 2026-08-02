#!/usr/bin/env python3
"""完全一致のレビュー済みC2 protocol probe profileを検証・適用する。"""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any


DEFAULT_PROFILE_PATH = Path(__file__).with_name("c2_protocol_probe_profiles.json")
PROFILE_METHODS = {
    "valleyrat_winos_reviewed": ("winos", "winos_heartbeat"),
    "c2_detector_vvas": ("vvas", "vvas_checkin"),
    "c2_detector_n520_server_first": ("n520", "n520_server_first"),
}


class ProtocolProfileError(ValueError):
    """profileが安全制約または完全一致条件を満たさない場合のエラー。"""


def load_profiles(path: Path | None = None) -> dict[str, dict[str, Any]]:
    """profile registryをfail-closedで読み込む。"""
    source = path or DEFAULT_PROFILE_PATH
    payload = json.loads(source.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        raise ProtocolProfileError("C2 protocol profileにはschema_version=1が必要です")
    values = payload.get("profiles")
    if not isinstance(values, list):
        raise ProtocolProfileError("C2 protocol profileのprofilesはlistである必要があります")
    profiles: dict[str, dict[str, Any]] = {}
    endpoints: set[tuple[str, int]] = set()
    for raw in values:
        if not isinstance(raw, dict):
            raise ProtocolProfileError("各C2 protocol profileはobjectである必要があります")
        profile = deepcopy(raw)
        profile_id = str(profile.get("profile_id") or "")
        host = str(profile.get("host") or "").casefold().rstrip(".")
        port = profile.get("port")
        handler = str(profile.get("handler") or "")
        expected = PROFILE_METHODS.get(handler)
        if not profile_id or profile_id in profiles:
            raise ProtocolProfileError(f"profile_idが空または重複しています: {profile_id}")
        if not host or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ProtocolProfileError(f"profile endpointが不正です: {profile_id}")
        if (host, port) in endpoints:
            raise ProtocolProfileError(f"profile endpointが重複しています: {host}:{port}")
        if expected != (profile.get("protocol"), profile.get("method")):
            raise ProtocolProfileError(f"handlerとprotocol/methodが一致しません: {profile_id}")
        timeout = float(profile.get("timeout_seconds", 3.0))
        maximum = int(profile.get("maximum_response_bytes", 64))
        if not 0.1 <= timeout <= 5.0 or not 1 <= maximum <= 64:
            raise ProtocolProfileError(f"active probeの上限が不正です: {profile_id}")
        if handler == "valleyrat_winos_reviewed":
            pinned = profile.get("pinned_ips")
            if not isinstance(pinned, list) or len(pinned) != 1:
                raise ProtocolProfileError("Winos profileには単一pinned IPが必要です")
        elif handler == "c2_detector_vvas":
            if profile.get("send_hex") != "333200":
                raise ProtocolProfileError("vvaS check-inはレビュー済み333200だけを許可します")
            if profile.get("expected_stage_size") != 307214 or profile.get("expected_header_size") != 14:
                raise ProtocolProfileError("vvaS応答境界がレビュー済み値と一致しません")
        elif handler == "c2_detector_n520_server_first":
            if profile.get("sni") != "update.microsoft.com" or maximum != 44:
                raise ProtocolProfileError("N520 server-first profileのSNIまたは応答上限が不正です")
            if any(key in profile for key in ("send_hex", "checkin", "artifact_zip")):
                raise ProtocolProfileError("N520 profileではcheck-in送信を許可しません")
        profile["host"] = host
        profiles[profile_id] = profile
        endpoints.add((host, port))
    return profiles


def resolve_profile(profile_id: str, host: str, port: int) -> dict[str, Any]:
    """IDと完全一致endpointの両方が一致したprofileだけを返す。"""
    profiles = load_profiles()
    profile = profiles.get(profile_id)
    normalized_host = host.casefold().rstrip(".")
    if profile is None:
        raise ProtocolProfileError(f"未レビューのprotocol_profile_idです: {profile_id}")
    if profile["host"] != normalized_host or profile["port"] != port:
        raise ProtocolProfileError(f"protocol profileとendpointが一致しません: {profile_id} / {normalized_host}:{port}")
    return deepcopy(profile)


def apply_profiles(
    targets: list[dict[str, Any]],
    *,
    repository_root: Path | None = None,
) -> tuple[list[dict[str, Any]], int]:
    """IOC対象へprofileをoverlayし、根拠fileが存在するレビュー済み対象を補完する。"""
    profiles = load_profiles()
    if repository_root is not None:
        profiles = {
            profile_id: profile
            for profile_id, profile in profiles.items()
            if (repository_root / str(profile["source"]).split(":", 1)[0]).is_file()
        }
    by_endpoint = {
        (str(target.get("host") or "").casefold().rstrip("."), int(target.get("port") or 0)): target
        for target in targets
    }
    added = 0
    for profile in profiles.values():
        key = (profile["host"], profile["port"])
        target = by_endpoint.get(key)
        if target is None:
            target = {
                "target_id": f"reviewed-{profile['profile_id']}",
                "family": profile["family"],
                "host": profile["host"],
                "port": profile["port"],
                "transport": "direct",
                "sample_sha256s": list(profile.get("sample_sha256s") or []),
                "associated_case_count": len(profile.get("sample_sha256s") or []) or 1,
                "analyzed_dates": [],
                "sources": [profile["source"]],
                "roles": [profile["role"]],
                "selection_basis": "レビュー済みmalware固有C2 protocol profile",
            }
            targets.append(target)
            by_endpoint[key] = target
            added += 1
        target.update(
            {
                "protocol": profile["protocol"],
                "method": profile["method"],
                "protocol_profile_id": profile["profile_id"],
                "timeout_seconds": profile["timeout_seconds"],
                "maximum_response_bytes": profile["maximum_response_bytes"],
            }
        )
        target["family"] = profile["family"]
        target["sample_sha256s"] = sorted(
            set(target.get("sample_sha256s", [])) | set(profile.get("sample_sha256s", []))
        )
        target["sources"] = sorted(set(target.get("sources", [])) | {profile["source"]})
        target["roles"] = sorted(set(target.get("roles", [])) | {profile["role"]})
    return sorted(targets, key=lambda value: (value["host"], value["port"], value["protocol"])), added
