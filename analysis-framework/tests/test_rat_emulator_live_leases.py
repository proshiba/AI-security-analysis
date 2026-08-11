"""防御的RATエミュレーターの短期live lease検証。"""

from __future__ import annotations

import copy
import json
import os
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

COMMON = Path(__file__).parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

from rat_emulator_live_leases import (
    DEFAULT_LIVE_LEASE_REGISTRY_PATH,
    MAXIMUM_LIVE_LEASE_REGISTRY_BYTES,
    RatEmulatorLiveLeaseError,
    load_live_lease_registry,
    resolve_active_live_lease,
)
from rat_emulator_profiles import load_registry

PROFILE_REGISTRY_SHA256 = (
    "a0725e5ce5f8a6597193e2bde09a06740147186dc1f1818c7da7e59d9209a9d6"
)
REVIEWED = datetime(2026, 8, 9, 9, 30, tzinfo=UTC)
EXPIRES = datetime(2026, 8, 10, 9, 30, tzinfo=UTC)


def _document() -> dict:
    return json.loads(DEFAULT_LIVE_LEASE_REGISTRY_PATH.read_text(encoding="utf-8"))


def _write(path: Path, document: object) -> None:
    path.write_text(
        json.dumps(document, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def test_production_registry_is_bound_to_all_exact_profiles() -> None:
    profiles = load_registry()
    registry = load_live_lease_registry(profile_registry=profiles)
    assert profiles.sha256 == PROFILE_REGISTRY_SHA256
    assert registry.profile_registry == {
        "source": "analysis-framework/common/rat_emulator_profiles.json",
        "sha256": PROFILE_REGISTRY_SHA256,
    }
    expected_leases = {
        profile_id
        for profile_id, profile in profiles.profiles.items()
        if profile["live_scope"] == "leased_external"
    }
    assert set(registry.leases) == expected_leases
    assert "valleyrat-winos-heartbeat-20260803-ljdnxz" not in registry.leases
    for lease in registry.leases.values():
        assert lease.reviewed_at == REVIEWED
        assert lease.expires_at == EXPIRES
        assert lease.review_owner == "security-analysis-review"


@pytest.mark.parametrize(
    "now_utc",
    [REVIEWED, EXPIRES - timedelta(microseconds=1)],
)
def test_active_interval_includes_start_and_excludes_only_expiry(now_utc: datetime) -> None:
    registry, lease = resolve_active_live_lease(
        "valleyrat-n520-host-d11e793-9999",
        now_utc=now_utc,
    )
    assert registry.leases[lease.profile_id] == lease


@pytest.mark.parametrize(
    ("now_utc", "message"),
    [
        (REVIEWED - timedelta(microseconds=1), "まだ有効ではありません"),
        (EXPIRES, "期限切れ"),
        (EXPIRES + timedelta(seconds=1), "期限切れ"),
    ],
)
def test_inactive_time_boundaries_fail_closed(
    now_utc: datetime,
    message: str,
) -> None:
    with pytest.raises(RatEmulatorLiveLeaseError, match=message):
        resolve_active_live_lease(
            "valleyrat-n520-host-d11e793-9999",
            now_utc=now_utc,
        )


def test_naive_or_non_utc_validation_time_is_rejected() -> None:
    with pytest.raises(RatEmulatorLiveLeaseError, match="timezone"):
        resolve_active_live_lease(
            "valleyrat-n520-host-d11e793-9999",
            now_utc=datetime(2026, 8, 9, 9, 30),  # noqa: DTZ001 - naive日時の拒否を検証
        )
    offset = UTC
    assert offset is UTC


def test_profile_registry_pin_mutation_fails_closed(tmp_path: Path) -> None:
    document = _document()
    document["profile_registry"]["sha256"] = "0" * 64
    path = tmp_path / "wrong-profile-pin.json"
    _write(path, document)
    with pytest.raises(RatEmulatorLiveLeaseError, match="profile registry"):
        load_live_lease_registry(path)


def test_duplicate_unknown_and_missing_profiles_are_rejected(tmp_path: Path) -> None:
    duplicate = _document()
    duplicate["leases"].append(copy.deepcopy(duplicate["leases"][0]))
    duplicate_path = tmp_path / "duplicate.json"
    _write(duplicate_path, duplicate)
    with pytest.raises(RatEmulatorLiveLeaseError, match="重複"):
        load_live_lease_registry(duplicate_path)

    unknown = _document()
    unknown["leases"][0]["profile_id"] = "unknown-rat-profile"
    unknown_path = tmp_path / "unknown.json"
    _write(unknown_path, unknown)
    with pytest.raises(RatEmulatorLiveLeaseError, match="未知profile"):
        load_live_lease_registry(unknown_path)

    missing = _document()
    missing["leases"].pop()
    missing_path = tmp_path / "missing.json"
    _write(missing_path, missing)
    with pytest.raises(RatEmulatorLiveLeaseError, match="leaseがない"):
        load_live_lease_registry(missing_path)


def test_offline_only_profile_cannot_receive_a_live_lease(tmp_path: Path) -> None:
    document = _document()
    offline = copy.deepcopy(document["leases"][0])
    offline["profile_id"] = "valleyrat-winos-heartbeat-20260803-ljdnxz"
    document["leases"].append(offline)
    path = tmp_path / "offline-lease.json"
    _write(path, document)
    with pytest.raises(RatEmulatorLiveLeaseError, match="offline-only"):
        load_live_lease_registry(path)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("reviewed_at_utc", "2026-08-09T09:30:00+00:00", "秒精度"),
        ("expires_at_utc", "2026-08-10T09:30:01Z", "24時間以内"),
        ("expires_at_utc", "2026-08-09T09:30:00Z", "24時間以内"),
        ("review_owner", "Security Analysis", "review_owner"),
    ],
)
def test_noncanonical_time_window_and_owner_are_rejected(
    tmp_path: Path,
    field: str,
    value: str,
    message: str,
) -> None:
    document = _document()
    document["leases"][0][field] = value
    path = tmp_path / f"bad-{field}.json"
    _write(path, document)
    with pytest.raises(RatEmulatorLiveLeaseError, match=message):
        load_live_lease_registry(path)


def test_strict_utf8_duplicate_key_and_size_limit_are_enforced(tmp_path: Path) -> None:
    invalid_utf8 = tmp_path / "invalid-utf8.json"
    invalid_utf8.write_bytes(b"\xff")
    with pytest.raises(RatEmulatorLiveLeaseError):
        load_live_lease_registry(invalid_utf8)

    bom = tmp_path / "bom.json"
    bom.write_bytes(b"\xef\xbb\xbf" + DEFAULT_LIVE_LEASE_REGISTRY_PATH.read_bytes())
    with pytest.raises(RatEmulatorLiveLeaseError):
        load_live_lease_registry(bom)

    duplicate_key = tmp_path / "duplicate-key.json"
    duplicate_key.write_text(
        '{"schema_version":1,"schema_version":1,"profile_registry":{},"leases":[]}',
        encoding="utf-8",
    )
    with pytest.raises(RatEmulatorLiveLeaseError):
        load_live_lease_registry(duplicate_key)

    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b" " * (MAXIMUM_LIVE_LEASE_REGISTRY_BYTES + 1))
    with pytest.raises(RatEmulatorLiveLeaseError, match="上限"):
        load_live_lease_registry(oversized)


def test_hardlink_and_symlink_registry_inputs_are_rejected(tmp_path: Path) -> None:
    source = tmp_path / "source.json"
    source.write_bytes(DEFAULT_LIVE_LEASE_REGISTRY_PATH.read_bytes())
    hardlink = tmp_path / "hardlink.json"
    os.link(source, hardlink)
    with pytest.raises(RatEmulatorLiveLeaseError, match="hardlink"):
        load_live_lease_registry(hardlink)
    hardlink.unlink()

    symlink = tmp_path / "symlink.json"
    try:
        symlink.symlink_to(source)
    except OSError:
        pytest.skip("この環境ではsymlinkを作成できません")
    with pytest.raises(RatEmulatorLiveLeaseError, match="reparse point|symlink"):
        load_live_lease_registry(symlink)


def test_expected_lease_registry_hash_is_optional_but_enforced_when_supplied() -> None:
    with pytest.raises(RatEmulatorLiveLeaseError, match="lease registry SHA-256"):
        load_live_lease_registry(expected_sha256="0" * 64)
