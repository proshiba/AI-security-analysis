"""PureRAT profileが監視パイプラインに実際に載っていることを確認する。

以前は `purerat_tls_prelude` が `ACTIVE_PROFILE_METHODS` に無く、
tirakian.com:56001-3 は `tcp_connect`(confidence上限0.25)として運用されていた。
detectorは手動CLIからしか動かず、日次監視には反映されていなかった。

ここでは、
1. tcp_connect の対象が profile 適用でPureRAT methodへ昇格すること
2. 計画検証を通ること
3. 各観測結果が正しい state へ分類されること(特にfail-closed)
を固定する。ネットワークは一切使わない。
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest


COMMON = Path(__file__).parents[1] / "common"
if str(COMMON) in sys.path:
    sys.path.remove(str(COMMON))
sys.path.insert(0, str(COMMON))

# `c2_detector` や `detect` のような名前は family ディレクトリにも同名で
# 存在する。suite全体を走らせると先に走ったテストがそれらを sys.modules へ
# 載せてしまい、common 側のmoduleが別物に解決されてimportが失敗する。
# sys.path の順序では直らない(sys.modules のcacheが優先されるため)ので、
# common 配下から来ていないcacheだけを落としてから読み込む。
for _name in ("c2_detector", "detect", "emulator", "static_logic"):
    _cached = sys.modules.get(_name)
    _origin = getattr(getattr(_cached, "__spec__", None), "origin", None)
    if _cached is not None and (_origin is None or COMMON not in Path(_origin).parents):
        del sys.modules[_name]

import monitor_recent_c2 as monitor  # noqa: E402
from c2_protocol_probe_profiles import (  # noqa: E402
    PROFILE_METHODS,
    apply_profiles,
    profile_registry_metadata,
)


SAMPLE = "e55412555b4699c6d3ce2ac60df81eb1ee0d5aa412a303555c8f64037d5633d0"
PORTS = (56001, 56002, 56003)


def tcp_connect_targets() -> list[dict[str, Any]]:
    """日次監視が静的IOCから作る、昇格前の対象。"""
    return [
        {
            "target_id": f"tirakian-com-{port}-tcp",
            "family": "purehvnc",
            "host": "tirakian.com",
            "port": port,
            "protocol": "tcp",
            "method": "tcp_connect",
            "transport": "direct",
            "sample_sha256s": [SAMPLE],
            "associated_case_count": 1,
            "analyzed_dates": [],
            "sources": ["analysis-results/malware/purehvnc/versions/v4.4.1"],
            "roles": ["configured_c2"],
            "selection_basis": "全解析履歴のC2/control/exfil候補",
            "timeout_seconds": 3.0,
            "protocol_hints": [],
            "maximum_response_bytes": 256,
        }
        for port in PORTS
    ]


def promoted() -> tuple[list[dict[str, Any]], dict[str, str]]:
    registry = profile_registry_metadata()
    targets, _added = apply_profiles(
        tcp_connect_targets(),
        expected_profile_registry_sha256=registry["sha256"],
    )
    return [t for t in targets if t["host"] == "tirakian.com"], registry


def test_purerat_handler_is_registered_end_to_end() -> None:
    assert PROFILE_METHODS["purerat_tls_prelude"] == ("purehvnc", "purerat_tls_prelude")
    assert "purerat_tls_prelude" in monitor.ALLOWED_METHODS
    assert "purerat_tls_prelude" in monitor.ACTIVE_PROFILE_METHODS
    assert "purerat_tls_prelude" in monitor.METHOD_LABELS
    # 判定表(2026-08-05-purerat)のpin一致= 0.95 と揃っていること
    assert monitor.METHOD_CEILINGS["purerat_tls_prelude"] == 0.95


def test_tcp_connect_targets_are_promoted_to_the_reviewed_profile() -> None:
    targets, _ = promoted()
    assert len(targets) == len(PORTS)
    for target in targets:
        assert target["method"] == "purerat_tls_prelude"
        assert target["protocol"] == "purehvnc"
        assert target["protocol_profile_id"] == (
            f"purerat-441-e5541255-tirakian-{target['port']}"
        )
        # 送信は4 byte固定、応答は読まない
        assert target["maximum_request_bytes"] == 4
        assert target["maximum_response_bytes"] == 64
        assert target["timeout_seconds"] == 3.0


def test_plan_validation_accepts_promoted_targets_and_gates_the_probe() -> None:
    targets, registry = promoted()
    plan = {
        "schema_version": 1,
        "generated_at_utc": "2026-08-11T00:00:00+00:00",
        "analysis_window": {"start": "2026-08-01", "end": "2026-08-11"},
        "targets": targets,
        "protocol_profile_registry": registry,
    }
    report = monitor.monitor(plan, allow_network=False, allow_application_probes=False)
    assert len(report["results"]) == len(PORTS)
    for item in report["results"]:
        assert item["method"] == "purerat_tls_prelude"
        assert item["observation"]["status"] == "network_disabled"
        assert item["assessment"]["state"] == "not_observed_safety_gate"
        assert item["assessment"]["method_confidence_ceiling"] == 0.95
    assert report["policy"]["malware_checkin_sent"] is False


def test_plan_validation_rejects_relaxed_limits() -> None:
    targets, registry = promoted()
    targets[0]["maximum_request_bytes"] = 4096
    plan = {
        "schema_version": 1,
        "generated_at_utc": "2026-08-11T00:00:00+00:00",
        "analysis_window": {"start": "2026-08-01", "end": "2026-08-11"},
        "targets": targets,
        "protocol_profile_registry": registry,
    }
    with pytest.raises(monitor.PlanError):
        monitor.validate_plan(plan)


def observation(**overrides: Any) -> dict[str, Any]:
    base = {
        "status": "purerat_prelude_rejected",
        "alive": True,
        "c2_confirmed": False,
        "target_contact_attempted": True,
        "target_connection_established": True,
        "application_data_sent": True,
        "protocol_prelude_sent": True,
        "protocol_prelude_accepted": False,
        "protocol_response_received": False,
        "tls": {"handshake": False},
    }
    base.update(overrides)
    return base


CONFIRMED = observation(
    status="confirmed_purerat_prelude_tls_certificate",
    c2_confirmed=True,
    protocol_prelude_accepted=True,
    protocol_prelude_length=4,
    tls={
        "handshake": True,
        "version": "TLSv1.2",
        "cipher": "ECDHE-RSA-AES256-GCM-SHA384",
        "certificate": {"state": "exact_match", "exact_match": True},
    },
)


@pytest.mark.parametrize(
    ("case", "expected_state", "expected_confidence"),
    [
        (CONFIRMED, "c2_protocol_confirmed", 0.95),
        (
            observation(
                status="purerat_prelude_tls_certificate_mismatch",
                protocol_prelude_accepted=True,
                protocol_prelude_length=4,
                tls={
                    "handshake": True,
                    "certificate": {"state": "mismatch_inconclusive", "exact_match": False},
                },
            ),
            "purerat_certificate_mismatch_c2_not_confirmed",
            0.0,
        ),
        (observation(), "purerat_prelude_rejected_c2_not_confirmed", 0.0),
        (
            observation(status="purerat_prelude_tls_handshake_failed"),
            "purerat_handshake_failed_c2_not_confirmed",
            0.0,
        ),
        (
            # 到達しなかった観測にtlsキーは付かない
            {
                "status": "not_reachable_at_observation",
                "alive": False,
                "c2_confirmed": False,
                "target_contact_attempted": True,
                "target_connection_established": False,
                "application_data_sent": False,
                "protocol_prelude_sent": False,
            },
            "not_reachable_at_observation",
            0.0,
        ),
    ],
)
def test_observations_are_classified(
    case: dict[str, Any],
    expected_state: str,
    expected_confidence: float,
) -> None:
    targets, _ = promoted()
    assessment = monitor.assess_observation(targets[0], case)
    assert assessment["state"] == expected_state
    assert assessment["c2_operational_confidence"] == expected_confidence


@pytest.mark.parametrize(
    "broken",
    [
        # statusは確認済みなのに証明書が一致していない
        {"tls": {"handshake": True, "certificate": {"exact_match": False}}},
        # handshakeが成立していないのにC2確定を主張している
        {"tls": {"handshake": False}},
        # 送っていないはずのvictim metadataが立っている
        {"victim_metadata_sent": True},
        # 取得していないはずのtaskが立っている
        {"task_poll_attempted": True},
        # preludeの長さが4 byteでない
        {"protocol_prelude_length": 8},
    ],
)
def test_inconsistent_confirmation_is_refused(broken: dict[str, Any]) -> None:
    """statusとflagが食い違うときはC2確定させない。"""
    targets, _ = promoted()
    case = dict(CONFIRMED)
    case.update(broken)
    assessment = monitor.assess_observation(targets[0], case)
    assert assessment["state"] == "purerat_confirmation_inconsistent_c2_not_confirmed"
    assert assessment["c2_operational_confidence"] == 0.0


def test_failed_handshake_is_never_reported_as_a_reachable_tls_endpoint() -> None:
    """handshake失敗をTLS到達として扱わないことを固定する。

    共通の落ち穂拾い経路は `tls` の有無だけを見ていたため、
    `{"handshake": false}` が入った観測をTLS成立として 0.40 の確度で
    分類し得た。
    """
    targets, _ = promoted()
    case = observation(status="unmapped_future_status", tls={"handshake": False})
    assessment = monitor.assess_observation(targets[0], case)
    assert assessment["state"] != "tls_endpoint_reachable_c2_not_confirmed"
    assert assessment["c2_operational_confidence"] <= 0.25
