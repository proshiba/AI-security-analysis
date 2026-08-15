"""PureRAT direct-TLS monitor統合のoffline安全契約。"""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path
from typing import Any

import pytest

COMMON = Path(__file__).parents[1] / "common"
ROOT = Path(__file__).parents[2]
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import monitor_recent_c2 as monitor
from c2_protocol_probe_profiles import (
    apply_profiles,
    profile_registry_metadata,
)

METHOD = "purerat_direct_tls_certificate_pin"
CERTIFICATE_SHA256 = (
    "b3ae061b0b14a89d5134c279775b8f77a42214323c6bddab07f4d81ca2fc5c57"
)


class FakeSocket:
    """実networkを持たず、application data送信を拒否するsocket。"""

    def __init__(self) -> None:
        self.timeout: float | None = None
        self.closed = False
        self.send_attempted = False

    def settimeout(self, value: float) -> None:
        self.timeout = value

    def sendall(self, _value: bytes) -> None:
        self.send_attempted = True
        raise AssertionError("certificate-only probeはapplication dataを送信できません")

    def close(self) -> None:
        self.closed = True


def _plan() -> dict[str, Any]:
    registry = profile_registry_metadata()
    targets, _added = apply_profiles(
        [],
        repository_root=ROOT,
        expected_profile_registry_sha256=registry["sha256"],
    )
    pure = next(target for target in targets if target.get("method") == METHOD)
    return {
        "schema_version": 1,
        "analysis_window": {
            "start": "2026-08-11T00:00:00Z",
            "end": "2026-08-11T23:59:59Z",
        },
        "collection_scope": "purerat_monitor_contract_fixture",
        "protocol_profile_registry": registry,
        "targets": [pure],
    }


def _validated_target() -> dict[str, Any]:
    return monitor.validate_plan(_plan())["targets"][0]


def _observe(
    *,
    version: str = "TLSv1",
    certificate_sha256: str = CERTIFICATE_SHA256,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, int], FakeSocket]:
    target = _validated_target()
    calls = {"resolver": 0, "connector": 0, "handshake": 0}
    raw = FakeSocket()

    def resolver(*_args: object, **_kwargs: object) -> list[tuple[Any, ...]]:
        calls["resolver"] += 1
        return [(2, 1, 6, "", ("45.192.211.77", 56001))]

    def connector(_endpoint: tuple[str, int], _timeout: float) -> FakeSocket:
        calls["connector"] += 1
        return raw

    def handshaker(sock: FakeSocket, profile: dict[str, Any]) -> dict[str, Any]:
        calls["handshake"] += 1
        assert sock is raw
        assert sock.send_attempted is False
        assert profile["tls_version"] == "TLSv1.0"
        return {
            "version": version,
            "cipher": "offline-fixture",
            "certificate_sha256": certificate_sha256,
        }

    observation = monitor._purerat_direct_tls_observation(
        target,
        True,
        True,
        resolver=resolver,
        connector=connector,
        tls_handshaker=handshaker,
    )
    return target, observation, calls, raw


def test_plan_accepts_zero_response_and_rejects_one_byte() -> None:
    plan = _plan()
    validated = monitor.validate_plan(copy.deepcopy(plan))
    target = validated["targets"][0]
    assert target["maximum_request_bytes"] == 0
    assert target["maximum_response_bytes"] == 0

    expanded = copy.deepcopy(plan)
    expanded["targets"][0]["maximum_response_bytes"] = 1
    with pytest.raises(monitor.PlanError):
        monitor.validate_plan(expanded)


@pytest.mark.parametrize(
    ("allow_network", "allow_legacy_tls", "expected_status"),
    [
        (False, True, "network_disabled"),
        (True, False, "legacy_tls_disabled"),
    ],
)
def test_both_gates_are_required_before_resolver_connector_or_handshake(
    allow_network: bool,
    allow_legacy_tls: bool,
    expected_status: str,
) -> None:
    calls = {"resolver": 0, "connector": 0, "handshake": 0}

    def forbidden(*_args: object, **_kwargs: object) -> Any:
        raise AssertionError("安全gate前にnetwork fixtureを呼び出してはいけません")

    def resolver(*args: object, **kwargs: object) -> Any:
        calls["resolver"] += 1
        return forbidden(*args, **kwargs)

    def connector(*args: object, **kwargs: object) -> Any:
        calls["connector"] += 1
        return forbidden(*args, **kwargs)

    def handshaker(*args: object, **kwargs: object) -> Any:
        calls["handshake"] += 1
        return forbidden(*args, **kwargs)

    observation = monitor._purerat_direct_tls_observation(
        _validated_target(),
        allow_network,
        allow_legacy_tls,
        resolver=resolver,
        connector=connector,
        tls_handshaker=handshaker,
    )
    assert observation["status"] == expected_status
    assert observation["target_contact_attempted"] is False
    assert observation["application_data_sent"] is False
    assert calls == {"resolver": 0, "connector": 0, "handshake": 0}


def test_preconnect_profile_validation_error_is_not_reported_as_contact() -> None:
    target = _validated_target()
    target["protocol_profile_registry_sha256"] = "0" * 64
    calls = 0

    def forbidden(*_args: object, **_kwargs: object) -> Any:
        nonlocal calls
        calls += 1
        raise AssertionError("profile pin失敗後にnetworkへ進んではいけません")

    observation = monitor._purerat_direct_tls_observation(
        target,
        True,
        True,
        resolver=forbidden,
        connector=forbidden,
        tls_handshaker=forbidden,
    )
    assert observation["status"] == "purerat_direct_tls_probe_error"
    assert observation["target_contact_attempted"] is False
    assert observation["target_connection_established"] is False
    assert calls == 0


def test_exact_tlsv1_and_certificate_pin_are_confirmed_at_point_92() -> None:
    target, observation, calls, raw = _observe()
    assessment = monitor.assess_observation(target, observation)
    assert calls == {"resolver": 0, "connector": 1, "handshake": 1}
    assert raw.closed is True
    assert raw.send_attempted is False
    assert observation["status"] == "confirmed_purerat_direct_tls_certificate"
    assert observation["c2_confirmed"] is True
    assert observation["application_data_sent"] is False
    assert observation["sent_bytes"] == 0
    assert observation["request_count"] == 0
    assert observation["victim_metadata_sent"] is False
    assert observation["raw_request_published"] is False
    assert observation["raw_response_published"] is False
    assert observation["tls"]["version"] == "TLSv1"
    assert observation["tls"]["version_exact_match"] is True
    assert observation["tls"]["certificate"]["exact_match"] is True
    assert assessment["state"] == "c2_protocol_confirmed"
    assert assessment["c2_operational_confidence"] == 0.92
    assert assessment["method_confidence_ceiling"] == 0.92


@pytest.mark.parametrize(
    ("version", "certificate", "expected_status"),
    [
        (
            "TLSv1",
            "b" * 64,
            "purerat_direct_tls_certificate_mismatch",
        ),
        (
            "TLSv1.2",
            CERTIFICATE_SHA256,
            "purerat_direct_tls_version_mismatch_inconclusive",
        ),
    ],
)
def test_certificate_or_tls_version_mismatch_is_inconclusive(
    version: str,
    certificate: str,
    expected_status: str,
) -> None:
    target, observation, calls, raw = _observe(
        version=version,
        certificate_sha256=certificate,
    )
    assessment = monitor.assess_observation(target, observation)
    assert calls == {"resolver": 0, "connector": 1, "handshake": 1}
    assert raw.closed is True
    assert observation["status"] == expected_status
    assert observation["c2_confirmed"] is False
    assert observation["certificate_mismatch_excludes_family_c2"] is False
    assert observation["tls_version_mismatch_excludes_family_c2"] is False
    assert assessment["state"] != "c2_protocol_confirmed"
    assert assessment["c2_operational_confidence"] == 0.0
    assert assessment["method_confidence_ceiling"] == 0.92
    assert assessment["negative_observation_confidence"] == 0.0


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("application_data_sent", True),
        ("victim_metadata_sent", True),
        ("raw_request_published", True),
        ("raw_response_published", True),
    ],
)
def test_confirmation_with_side_effect_flag_is_rejected(
    field: str,
    value: bool,
) -> None:
    target, exact, _calls, _raw = _observe()
    contradictory = copy.deepcopy(exact)
    contradictory[field] = value
    assessment = monitor.assess_observation(target, contradictory)
    assert assessment["state"] == "purerat_confirmation_inconsistent_c2_not_confirmed"
    assert assessment["c2_operational_confidence"] == 0.0
    assert assessment["method_confidence_ceiling"] == 0.92


def test_confirmation_with_tls_flag_contradiction_is_rejected() -> None:
    target, exact, _calls, _raw = _observe()
    contradictory = copy.deepcopy(exact)
    contradictory["tls"]["version_exact_match"] = False
    assessment = monitor.assess_observation(target, contradictory)
    assert assessment["state"] == "purerat_confirmation_inconsistent_c2_not_confirmed"
    assert assessment["c2_operational_confidence"] == 0.0


def test_monitor_uses_dedicated_dispatch_redacts_secrets_and_reports_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _target, exact, _calls, _raw = _observe()
    marker = "RAW-PFX-PRIVATE-KEY-PAYLOAD"
    injected = copy.deepcopy(exact)
    for key in (
        "raw_frame",
        "raw_protobuf",
        "payload_hex",
        "pfx",
        "pfx_bytes",
        "private_key",
        "private_key_bytes",
    ):
        injected[key] = marker
    injected["tls"].update(
        {
            "raw_frame": marker,
            "pfx": marker,
            "private_key": marker,
        }
    )
    injected["tls"]["certificate"]["raw_der"] = marker
    dispatch_calls: list[tuple[bool, bool]] = []

    def dedicated(
        _target: dict[str, Any],
        allow_network: bool,
        allow_legacy_tls: bool,
    ) -> dict[str, Any]:
        dispatch_calls.append((allow_network, allow_legacy_tls))
        return copy.deepcopy(injected)

    def generic_forbidden(*_args: object, **_kwargs: object) -> Any:
        raise AssertionError("PureRATをgeneric probeへdispatchしてはいけません")

    monkeypatch.setattr(monitor, "_purerat_direct_tls_observation", dedicated)
    monkeypatch.setattr(monitor, "probe", generic_forbidden)
    report = monitor.monitor(
        _plan(),
        allow_network=True,
        allow_purerat_legacy_tls=True,
    )
    assert dispatch_calls == [(True, True)]
    assert len(report["results"]) == 1
    result = report["results"][0]
    assert result["assessment"]["state"] == "c2_protocol_confirmed"
    assert result["assessment"]["c2_operational_confidence"] == 0.92
    assert marker not in json.dumps(report, ensure_ascii=False)
    policy = report["policy"]
    assert policy["network_enabled"] is True
    assert policy["purerat_legacy_tls_certificate_probe_enabled"] is True
    assert policy["maximum_response_bytes"] == 0
    assert policy["reviewed_protocol_probe_count"] == 1
    assert policy["malware_checkin_sent"] is False
    assert policy["reviewed_heartbeat_or_checkin_sent_count"] == 0
    assert policy["registration_attempted_count"] == 0
    assert policy["victim_metadata_sent"] is False
    assert policy["command_polling_performed"] is False
