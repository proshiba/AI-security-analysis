"""PureLogs／PureRATのprobable-only監視契約を外部通信なしで固定する。"""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path
from typing import Any

COMMON = Path(__file__).parents[1] / "common"
if str(COMMON) in sys.path:
    sys.path.remove(str(COMMON))
sys.path.insert(0, str(COMMON))

import monitor_recent_c2 as monitor
from c2_protocol_probe_profiles import (
    apply_profiles,
    profile_registry_metadata,
)

PURELOGS_PROFILE_ID = "purelogs-0f2abaab-logs-uvexio-8443-ping-v1"


def _purelogs_plan() -> dict[str, Any]:
    registry = profile_registry_metadata()
    targets, _added = apply_profiles(
        [],
        expected_profile_registry_sha256=registry["sha256"],
    )
    target = next(item for item in targets if item.get("protocol_profile_id") == PURELOGS_PROFILE_ID)
    return {
        "schema_version": 1,
        "generated_at_utc": "2026-10-08T00:00:00+00:00",
        "analysis_window": {"start": "2026-10-08", "end": "2026-10-08"},
        "collection_scope": "purelogs_monitor_contract_fixture",
        "protocol_profile_registry": registry,
        "targets": [target],
    }


def _purelogs_probable_observation() -> dict[str, Any]:
    return {
        "execution_engine": "nmap_nse",
        "status": "purelogs_ping_probable_match_tls_version_unverified",
        "c2_confirmed": False,
        "probable_c2": True,
        "confidence": 0.70,
        "variant": "http_aes_v5",
        "generation_evidence_scope": "family_level_public_research",
        "sample_version_confirmed": False,
        "excluded_variant": "legacy_socket_3des",
        "legacy_codec_implemented": False,
        "target_contact_attempted": True,
        "target_connection_established": True,
        "application_data_sent": True,
        "certificate_exact_match": True,
        "http_status": 200,
        "body_exact_match": True,
        "response_hash_scope": "http_body",
        "response_size": 128,
        "received_bytes": 128,
        "request_count": 1,
        "sent_bytes": 143,
        "request_body_sent": False,
        "redirect_followed": False,
        "response_body_published": False,
        "raw_request_published": False,
        "raw_response_published": False,
        "tls_version_enforced_by_nse": False,
    }


def test_purelogs_monitor_layers_and_plan_are_registered() -> None:
    assert "purelogs_https_ping" in monitor.ALLOWED_METHODS
    assert "purelogs_https_ping" in monitor.ACTIVE_PROFILE_METHODS
    assert "purelogs_https_ping" in monitor.APPLICATION_LAYER_METHODS
    assert monitor.METHOD_CEILINGS["purelogs_https_ping"] == 0.70
    assert "probable" in monitor.METHOD_LABELS["purelogs_https_ping"]

    validated = monitor.validate_plan(copy.deepcopy(_purelogs_plan()))
    target = validated["targets"][0]
    assert target["protocol"] == "https"
    assert target["method"] == "purelogs_https_ping"
    assert target["maximum_request_bytes"] == 256
    assert target["maximum_response_bytes"] == 1024


def test_monitor_passes_exact_active_ack_and_keeps_purelogs_probable_only(
    monkeypatch,
) -> None:
    captured: dict[str, Any] = {}

    def fake_probe(_target: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        captured.update(kwargs)
        return _purelogs_probable_observation()

    monkeypatch.setattr(monitor, "probe_target_with_nmap", fake_probe)
    report = monitor.monitor(
        _purelogs_plan(),
        allow_network=True,
        allow_application_probes=True,
        acknowledged_active_profiles={PURELOGS_PROFILE_ID},
    )

    assert captured["acknowledged_active_profiles"] == frozenset({PURELOGS_PROFILE_ID})
    result = report["results"][0]
    assert result["assessment"]["state"] == ("purelogs_reviewed_ping_probable_c2_not_confirmed")
    assert result["assessment"]["c2_operational_confidence"] == 0.70
    assert result["assessment"]["method_confidence_ceiling"] == 0.70
    assert result["observation"]["c2_confirmed"] is False
    assert report["policy"]["acknowledged_active_profile_count"] == 1


def test_purelogs_confirmation_claim_or_raw_flag_fails_closed() -> None:
    target = monitor.validate_plan(copy.deepcopy(_purelogs_plan()))["targets"][0]
    for field, value in (
        ("c2_confirmed", True),
        ("raw_response_published", True),
        ("redirect_followed", True),
        ("sample_version_confirmed", True),
    ):
        observation = _purelogs_probable_observation()
        observation[field] = value
        assessment = monitor.assess_observation(target, observation)
        assert assessment["state"] == ("purelogs_confirmation_inconsistent_c2_not_confirmed")
        assert assessment["c2_operational_confidence"] == 0.0


def test_cli_propagates_exact_active_profile_acknowledgement(
    monkeypatch,
    tmp_path: Path,
) -> None:
    targets = tmp_path / "targets.json"
    targets.write_text("{}\n", encoding="utf-8")
    output = tmp_path / "output"
    captured: dict[str, Any] = {}

    def fake_monitor(_plan: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        captured.update(kwargs)
        return {"target_count": 0, "state_counts": {}, "policy": {}}

    monkeypatch.setattr(monitor, "monitor", fake_monitor)
    monkeypatch.setattr(monitor, "render_markdown", lambda _result: "# fixture\n")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "monitor_recent_c2.py",
            "--targets",
            str(targets),
            "--output-directory",
            str(output),
            "--acknowledge-profile",
            PURELOGS_PROFILE_ID,
        ],
    )

    assert monitor.main() == 0
    assert captured["acknowledged_active_profiles"] == {PURELOGS_PROFILE_ID}
    assert json.loads((output / "monitoring-results.json").read_text(encoding="utf-8"))["target_count"] == 0
