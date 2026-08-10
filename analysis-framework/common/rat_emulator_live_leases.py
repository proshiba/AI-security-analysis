#!/usr/bin/env python3
"""防御的RATエミュレーターの短期live leaseを厳密に検証する。"""

from __future__ import annotations

import json
import re
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from immutable_snapshot import decode_strict_json, read_bounded_snapshot
from rat_emulator_profiles import RegistrySnapshot, load_registry

DEFAULT_LIVE_LEASE_REGISTRY_PATH = Path(__file__).with_name(
    "rat_emulator_live_leases.json"
)
LIVE_LEASE_REGISTRY_SOURCE = (
    "analysis-framework/common/rat_emulator_live_leases.json"
)
MAXIMUM_LIVE_LEASE_REGISTRY_BYTES = 64 * 1024
MAXIMUM_LEASE_DURATION = timedelta(hours=24)
UTC_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
REVIEW_OWNER_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,127}$")
REGISTRY_KEYS = frozenset({"schema_version", "profile_registry", "leases"})
PROFILE_REGISTRY_PIN_KEYS = frozenset({"source", "sha256"})
LEASE_KEYS = frozenset(
    {"profile_id", "reviewed_at_utc", "expires_at_utc", "review_owner"}
)


class RatEmulatorLiveLeaseError(ValueError):
    """短期live leaseが不正、未有効、または期限切れであることを表す。"""


@dataclass(frozen=True)
class LiveLease:
    """1件の検証済み短期live lease。"""

    profile_id: str
    reviewed_at_utc: str
    expires_at_utc: str
    review_owner: str
    reviewed_at: datetime
    expires_at: datetime

    def public_dict(self) -> dict[str, str]:
        """公開可能な監査項目だけを返す。"""

        return {
            "profile_id": self.profile_id,
            "reviewed_at_utc": self.reviewed_at_utc,
            "expires_at_utc": self.expires_at_utc,
            "review_owner": self.review_owner,
        }


@dataclass(frozen=True)
class LiveLeaseRegistrySnapshot:
    """検証済みlease registryとraw SHA-256。"""

    source: str
    sha256: str
    profile_registry: dict[str, str]
    leases: dict[str, LiveLease]


def _exact_keys(value: dict[str, Any], expected: frozenset[str], label: str) -> None:
    observed = set(value)
    if observed != expected:
        missing = sorted(expected - observed)
        extra = sorted(observed - expected)
        raise RatEmulatorLiveLeaseError(
            f"{label}のkeyが不正です: missing={missing}, extra={extra}"
        )


def _parse_utc_timestamp(value: object, label: str) -> datetime:
    if type(value) is not str or UTC_TIMESTAMP_RE.fullmatch(value) is None:
        raise RatEmulatorLiveLeaseError(
            f"{label}は秒精度のUTC時刻（YYYY-MM-DDTHH:MM:SSZ）で指定してください"
        )
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise RatEmulatorLiveLeaseError(f"{label}が実在するUTC時刻ではありません") from exc


def _validate_now(now_utc: datetime | None) -> datetime:
    value = datetime.now(UTC) if now_utc is None else now_utc
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise RatEmulatorLiveLeaseError("lease検証時刻はtimezone付きdatetimeが必要です")
    if value.utcoffset() != timedelta(0):
        raise RatEmulatorLiveLeaseError("lease検証時刻はUTCで指定してください")
    return value.astimezone(UTC)


def _validate_lease(value: object) -> LiveLease:
    if not isinstance(value, dict):
        raise RatEmulatorLiveLeaseError("leaseはobjectである必要があります")
    _exact_keys(value, LEASE_KEYS, "lease")
    profile_id = value.get("profile_id")
    owner = value.get("review_owner")
    if type(profile_id) is not str or not profile_id:
        raise RatEmulatorLiveLeaseError("lease profile_idが不正です")
    if type(owner) is not str or REVIEW_OWNER_RE.fullmatch(owner) is None:
        raise RatEmulatorLiveLeaseError("review_ownerが不正です")
    reviewed_text = value.get("reviewed_at_utc")
    expires_text = value.get("expires_at_utc")
    reviewed = _parse_utc_timestamp(reviewed_text, "reviewed_at_utc")
    expires = _parse_utc_timestamp(expires_text, "expires_at_utc")
    duration = expires - reviewed
    if duration <= timedelta(0) or duration > MAXIMUM_LEASE_DURATION:
        raise RatEmulatorLiveLeaseError("live leaseは0秒超24時間以内に限定します")
    return LiveLease(
        profile_id=profile_id,
        reviewed_at_utc=reviewed_text,
        expires_at_utc=expires_text,
        review_owner=owner,
        reviewed_at=reviewed,
        expires_at=expires,
    )


def load_live_lease_registry(
    path: Path = DEFAULT_LIVE_LEASE_REGISTRY_PATH,
    *,
    expected_sha256: str | None = None,
    profile_registry: RegistrySnapshot | None = None,
) -> LiveLeaseRegistrySnapshot:
    """lease registryと参照先profile registryを同時に検証する。"""

    try:
        snapshot = read_bounded_snapshot(path, MAXIMUM_LIVE_LEASE_REGISTRY_BYTES)
        document = decode_strict_json(snapshot.data)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise RatEmulatorLiveLeaseError(
            f"live lease registryを安全に読み取れません: {exc}"
        ) from exc
    if expected_sha256 is not None and snapshot.identity.sha256 != expected_sha256:
        raise RatEmulatorLiveLeaseError("live lease registry SHA-256 pinが一致しません")
    if not isinstance(document, dict):
        raise RatEmulatorLiveLeaseError("live lease registryはobjectである必要があります")
    _exact_keys(document, REGISTRY_KEYS, "live lease registry")
    if document.get("schema_version") != 1:
        raise RatEmulatorLiveLeaseError("live lease registryにはschema_version=1が必要です")

    profile_pin = document.get("profile_registry")
    if not isinstance(profile_pin, dict):
        raise RatEmulatorLiveLeaseError("profile_registry pinがありません")
    _exact_keys(profile_pin, PROFILE_REGISTRY_PIN_KEYS, "profile_registry pin")
    active_profiles = profile_registry or load_registry()
    expected_pin = {
        "source": active_profiles.source,
        "sha256": active_profiles.sha256,
    }
    if profile_pin != expected_pin:
        raise RatEmulatorLiveLeaseError(
            "profile registryのsource／SHA-256 pinが一致しません"
        )

    values = document.get("leases")
    if not isinstance(values, list) or not values:
        raise RatEmulatorLiveLeaseError("leasesは1件以上必要です")
    leases: dict[str, LiveLease] = {}
    for value in values:
        lease = _validate_lease(value)
        if lease.profile_id in leases:
            raise RatEmulatorLiveLeaseError("lease profile_idが重複しています")
        leases[lease.profile_id] = lease
    expected_profile_ids = set(active_profiles.profiles)
    observed_profile_ids = set(leases)
    unknown = sorted(observed_profile_ids - expected_profile_ids)
    missing = sorted(expected_profile_ids - observed_profile_ids)
    if unknown:
        raise RatEmulatorLiveLeaseError(f"未知profileのleaseがあります: {unknown}")
    if missing:
        raise RatEmulatorLiveLeaseError(f"leaseがないprofileがあります: {missing}")

    source = (
        LIVE_LEASE_REGISTRY_SOURCE
        if path.resolve() == DEFAULT_LIVE_LEASE_REGISTRY_PATH.resolve()
        else str(path)
    )
    return LiveLeaseRegistrySnapshot(
        source=source,
        sha256=snapshot.identity.sha256,
        profile_registry=deepcopy(expected_pin),
        leases=leases,
    )


def resolve_active_live_lease(
    profile_id: str,
    *,
    now_utc: datetime | None = None,
    path: Path = DEFAULT_LIVE_LEASE_REGISTRY_PATH,
    expected_registry_sha256: str | None = None,
    profile_registry: RegistrySnapshot | None = None,
) -> tuple[LiveLeaseRegistrySnapshot, LiveLease]:
    """現在時刻がreviewed以上expires未満の完全一致leaseだけを返す。"""

    registry = load_live_lease_registry(
        path,
        expected_sha256=expected_registry_sha256,
        profile_registry=profile_registry,
    )
    try:
        lease = registry.leases[profile_id]
    except KeyError as exc:
        raise RatEmulatorLiveLeaseError(
            f"短期live leaseがないprofileです: {profile_id}"
        ) from exc
    now = _validate_now(now_utc)
    if now < lease.reviewed_at:
        raise RatEmulatorLiveLeaseError(
            f"短期live leaseはまだ有効ではありません: {lease.reviewed_at_utc}"
        )
    if now >= lease.expires_at:
        raise RatEmulatorLiveLeaseError(
            f"短期live leaseが期限切れです: {lease.expires_at_utc}"
        )
    return registry, lease


__all__ = [
    "DEFAULT_LIVE_LEASE_REGISTRY_PATH",
    "LIVE_LEASE_REGISTRY_SOURCE",
    "MAXIMUM_LIVE_LEASE_REGISTRY_BYTES",
    "LiveLease",
    "LiveLeaseRegistrySnapshot",
    "RatEmulatorLiveLeaseError",
    "load_live_lease_registry",
    "resolve_active_live_lease",
]
