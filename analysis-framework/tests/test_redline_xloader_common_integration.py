from __future__ import annotations

import hashlib
import json
import sys
from copy import deepcopy
from pathlib import Path

import pytest

COMMON = Path(__file__).parents[1] / "common"
REPOSITORY = Path(__file__).resolve().parents[2]
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import c2_protocol_probe_profiles as profiles  # noqa: E402
import monitor_recent_c2  # noqa: E402
from build_all_c2_monitoring_targets import build_inventory  # noqa: E402

REDLINE_PROFILE_ID = "redline-3f3ac0a3-checkconnect-v1"


def _redline_plan() -> dict:
    registry = profiles.profile_registry_metadata()
    targets, _ = profiles.apply_profiles(
        [],
        repository_root=REPOSITORY,
        expected_profile_registry_sha256=registry["sha256"],
        expected_remus_review_registry_sha256=profiles.remus_review_registry_metadata(
            repository_root=REPOSITORY
        )["sha256"],
    )
    target = next(
        item
        for item in targets
        if item.get("protocol_profile_id") == REDLINE_PROFILE_ID
    )
    return {
        "schema_version": 1,
        "analysis_window": {
            "start": "2026-08-09T00:00:00+09:00",
            "end": "2026-08-09T23:59:59+09:00",
        },
        "protocol_profile_registry": registry,
        "targets": [target],
    }


def test_registry_has_redline_exact_profile_and_xloader_capability_only() -> None:
    loaded = profiles.load_profiles()
    redline = loaded[REDLINE_PROFILE_ID]
    assert redline["protocol"] == "redlinestealer"
    assert redline["method"] == "redline_checkconnect_soap11"
    assert redline["request_budget"] == 1
    assert redline["maximum_response_bytes"] == 4096
    binding = profiles.validate_redline_profile_binding(redline)
    assert binding["binding"]["terminal_mvid"] == redline["terminal_mvid"]
    assert (
        binding["binding"]["terminal_cil_semantic_sha256"]
        == redline["terminal_cil_semantic_sha256"]
    )
    assert binding["registry"]["sha256"] == redline[
        "family_profile_registry_sha256"
    ]

    assert profiles.PROFILE_METHODS["xloader_v8_get_registration"] == (
        "xloader_http_get_pkt2",
        "xloader_v8_get_registration",
    )
    assert all(
        item["handler"] != "xloader_v8_get_registration"
        for item in loaded.values()
    )


def _xloader_future_profile() -> dict:
    sample = "a" * 64
    return {
        "profile_id": "xloader-fixture-profile",
        "family": "xloader",
        "sample_sha256s": [sample],
        "sample_sha256": sample,
        "fully_recovered_image_sha256": "b" * 64,
        "host": "fixture.example",
        "port": 80,
        "protocol": "xloader_http_get_pkt2",
        "method": "xloader_v8_get_registration",
        "handler": "xloader_v8_get_registration",
        "reviewed": True,
        "candidate_classification": "reviewed_real_c2",
        "response_contract_evidence": "current_sample_static",
        "review_id": "xloader-review-fixture",
        "private_material_reference": "xloader-private:fixture",
        "private_material_sha256": "c" * 64,
        "selector_path_table_sha256": "d" * 64,
        "synthetic_template_id": "xloader-v8-pkt2-synthetic-v1",
        "pkt2_inner_plaintext_sha256": "6" * 64,
        "request_sha256": "7" * 64,
        "review_evidence_source": "analysis-results/research/fixture/evidence.json",
        "review_evidence_sha256": "e" * 64,
        "pinned_ips": ["8.8.8.8"],
        "scheme": "http",
        "transport": "raw_socket",
        "http_method": "GET",
        "http_path": "/abcd/",
        "request_budget": 1,
        "maximum_request_count": 1,
        "maximum_request_bytes": 4096,
        "maximum_response_bytes": 8192,
        "timeout_seconds": 3.0,
        "redirect_followed": False,
        "task_execution_allowed": False,
        "payload_download_allowed": False,
        "candidate_index": 0,
        "selector": 1,
        "record_sha1": "f" * 40,
        "data_parameter_position": "first",
        "data_parameter_name": "aa",
        "junk_parameter_name": "bb",
        "junk_value": "1",
        "user_agent": "fixture",
        "role": "XLoader review fixture",
        "source": "analysis-results/research/fixture/evidence.json:profile",
    }


def test_xloader_future_profile_rejects_bootstrap_candidate_activation(
    tmp_path: Path,
) -> None:
    profile = _xloader_future_profile()
    registry = tmp_path / "profiles.json"
    registry.write_text(
        json.dumps({"schema_version": 1, "profiles": [profile]}),
        encoding="utf-8",
    )
    assert profiles.load_profiles(registry)[profile["profile_id"]][
        "candidate_classification"
    ] == "reviewed_real_c2"

    profile["candidate_classification"] = (
        "reviewed_initial_bootstrap_candidate"
    )
    registry.write_text(
        json.dumps({"schema_version": 1, "profiles": [profile]}),
        encoding="utf-8",
    )
    with pytest.raises(
        profiles.ProtocolProfileError,
        match="XLoader",
    ):
        profiles.load_profiles(registry)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("synthetic_template_id", None),
        ("synthetic_template_id", "xloader-v8-pkt2-unreviewed"),
        ("pkt2_inner_plaintext_sha256", None),
        ("pkt2_inner_plaintext_sha256", "not-a-sha256"),
        ("request_sha256", None),
        ("request_sha256", "not-a-sha256"),
    ],
)
def test_xloader_future_profile_requires_synthetic_and_request_pins(
    tmp_path: Path,
    field: str,
    value: str | None,
) -> None:
    profile = _xloader_future_profile()
    if value is None:
        profile.pop(field)
    else:
        profile[field] = value
    registry = tmp_path / "profiles.json"
    registry.write_text(
        json.dumps({"schema_version": 1, "profiles": [profile]}),
        encoding="utf-8",
    )
    with pytest.raises(profiles.ProtocolProfileError, match="XLoader"):
        profiles.load_profiles(registry)


def test_xloader_overlay_and_plan_keep_new_exact_pins(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    evidence = (
        repository
        / "analysis-results"
        / "research"
        / "fixture"
        / "evidence.json"
    )
    evidence.parent.mkdir(parents=True)
    evidence.write_text('{"schema_version":1}\n', encoding="utf-8")
    evidence_sha256 = hashlib.sha256(evidence.read_bytes()).hexdigest()
    profile = _xloader_future_profile()
    profile["review_evidence_sha256"] = evidence_sha256
    registry = tmp_path / "profiles.json"
    registry.write_text(
        json.dumps({"schema_version": 1, "profiles": [profile]}),
        encoding="utf-8",
    )
    monkeypatch.setattr(profiles, "DEFAULT_PROFILE_PATH", registry)
    registry_pin = profiles.profile_registry_metadata()
    targets, added = profiles.apply_profiles(
        [],
        repository_root=repository,
        expected_profile_registry_sha256=registry_pin["sha256"],
    )
    assert added == 1
    target = targets[0]
    assert target["protocol_profile_synthetic_template_id"] == profile[
        "synthetic_template_id"
    ]
    assert target["protocol_profile_pkt2_inner_plaintext_sha256"] == profile[
        "pkt2_inner_plaintext_sha256"
    ]
    assert target["protocol_profile_request_sha256"] == profile[
        "request_sha256"
    ]
    plan = {
        "schema_version": 1,
        "analysis_window": {
            "start": "2026-08-09T00:00:00+09:00",
            "end": "2026-08-09T23:59:59+09:00",
        },
        "protocol_profile_registry": registry_pin,
        "targets": targets,
    }
    assert monitor_recent_c2.validate_plan(
        plan,
        repository_root=repository,
    ) == plan

    for field in (
        "protocol_profile_synthetic_template_id",
        "protocol_profile_pkt2_inner_plaintext_sha256",
        "protocol_profile_request_sha256",
    ):
        mismatched = deepcopy(plan)
        mismatched["targets"][0][field] = "0" * 64
        with pytest.raises(monitor_recent_c2.PlanError, match="XLoader"):
            monitor_recent_c2.validate_plan(
                mismatched,
                repository_root=repository,
            )


def test_redline_overlay_keeps_all_review_pins() -> None:
    target = _redline_plan()["targets"][0]
    profile = profiles.resolve_profile(
        REDLINE_PROFILE_ID,
        target["host"],
        target["port"],
    )
    assert target["sample_sha256s"] == profile["sample_sha256s"]
    assert (
        target["protocol_profile_evidence_sha256"]
        == profile["config_artifact_review_sha256"]
    )
    assert target["protocol_profile_terminal_mvid"] == profile["terminal_mvid"]
    assert (
        target["protocol_profile_terminal_cil_semantic_sha256"]
        == profile["terminal_cil_semantic_sha256"]
    )
    assert target["protocol_profile_request_sha256"] == profile["request_sha256"]
    assert (
        target["protocol_profile_family_registry_sha256"]
        == profile["family_profile_registry_sha256"]
    )


def test_redline_requires_dedicated_gate_and_exact_profile_ack(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict] = []

    def fake_probe(target: dict, **kwargs):
        calls.append({"target": target, **kwargs})
        if REDLINE_PROFILE_ID not in kwargs["acknowledged_redline_profiles"]:
            return {
                "execution_engine": "nmap_nse",
                "status": "profile_acknowledgement_missing_or_mismatch",
                "alive": False,
                "c2_confirmed": False,
                "target_contact_attempted": False,
                "target_connection_established": False,
                "application_data_sent": False,
                "protocol_response_received": False,
                "request_count": 0,
            }
        return {
            "execution_engine": "nmap_nse",
            "status": "confirmed_redline_checkconnect",
            "alive": True,
            "c2_confirmed": True,
            "confidence": 0.95,
            "target_contact_attempted": True,
            "target_connection_established": True,
            "application_data_sent": True,
            "protocol_response_received": True,
            "request_count": 1,
            "request_size": 357,
            "response_size": 256,
            "synthetic_identity_sent": False,
            "victim_metadata_sent": False,
            "registration_attempted": False,
            "task_poll_attempted": False,
            "task_content_published": False,
            "task_executed": False,
            "payload_download_attempted": False,
            "redirect_followed": False,
            "raw_request_published": False,
            "raw_response_published": False,
        }

    monkeypatch.setattr(
        monitor_recent_c2,
        "probe_target_with_nmap",
        fake_probe,
    )
    missing_ack = monitor_recent_c2.monitor(
        _redline_plan(),
        allow_network=True,
        allow_reviewed_checkconnect=True,
    )
    assert (
        missing_ack["results"][0]["assessment"]["state"]
        == "not_observed_safety_gate"
    )
    assert missing_ack["policy"]["redline_checkconnect_attempted_count"] == 0

    confirmed = monitor_recent_c2.monitor(
        _redline_plan(),
        allow_network=True,
        allow_reviewed_checkconnect=True,
        acknowledged_redline_profiles={REDLINE_PROFILE_ID},
    )
    assert confirmed["results"][0]["assessment"]["state"] == "c2_protocol_confirmed"
    assert confirmed["policy"]["redline_checkconnect_attempted_count"] == 1
    assert confirmed["policy"]["redline_checkconnect_confirmed_count"] == 1
    assert confirmed["policy"]["application_request_count"] == 1
    assert calls[-1]["allow_network"] is True
    assert calls[-1]["allow_reviewed_checkconnect"] is True
    assert REDLINE_PROFILE_ID in calls[-1]["acknowledged_redline_profiles"]
    assert (
        calls[-1]["target"]["protocol_profile_family_registry_sha256"]
        == _redline_plan()["targets"][0]["protocol_profile_family_registry_sha256"]
    )


def test_redline_dispatch_rechecks_common_registry_before_family_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = _redline_plan()["targets"][0]
    calls: list[str] = []

    class UnexpectedRedLineModule:
        @staticmethod
        def probe_reviewed_redline_checkconnect(*_args, **_kwargs):
            calls.append("called")
            raise AssertionError("family probe must not be called")

    monkeypatch.setattr(
        monitor_recent_c2,
        "_load_redline_active_probe_module",
        lambda: UnexpectedRedLineModule,
    )
    target["protocol_profile_registry_sha256"] = "0" * 64
    observation = monitor_recent_c2._redline_checkconnect_observation(
        target,
        True,
        True,
        frozenset({REDLINE_PROFILE_ID}),
    )
    assert observation["status"] == "redline_checkconnect_probe_error"
    assert observation["target_contact_attempted"] is False
    assert observation["request_count"] == 0
    assert calls == []


def test_redline_dispatch_rechecks_exact_target_pins_before_family_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = _redline_plan()["targets"][0]
    calls: list[str] = []

    class UnexpectedRedLineModule:
        @staticmethod
        def probe_reviewed_redline_checkconnect(*_args, **_kwargs):
            calls.append("called")
            raise AssertionError("family probe must not be called")

    monkeypatch.setattr(
        monitor_recent_c2,
        "_load_redline_active_probe_module",
        lambda: UnexpectedRedLineModule,
    )
    target["protocol_profile_request_sha256"] = "0" * 64
    observation = monitor_recent_c2._redline_checkconnect_observation(
        target,
        True,
        True,
        frozenset({REDLINE_PROFILE_ID}),
    )
    assert observation["status"] == "redline_checkconnect_probe_error"
    assert observation["target_contact_attempted"] is False
    assert observation["request_count"] == 0
    assert calls == []


def test_redline_confirmation_flag_contradiction_fails_closed() -> None:
    assessment = monitor_recent_c2.assess_observation(
        {"method": "redline_checkconnect_soap11"},
        {
            "status": "confirmed_redline_checkconnect",
            "c2_confirmed": True,
            "target_connection_established": True,
            "application_data_sent": True,
            "protocol_response_received": True,
            "request_count": 2,
            "request_budget_used": 2,
            "sent_bytes": 714,
            "received_bytes": 256,
        },
    )
    assert (
        assessment["state"]
        == "redline_confirmation_inconsistent_c2_not_confirmed"
    )
    assert assessment["c2_operational_confidence"] == 0.0


def test_xloader_hint_remains_dns_only_without_real_c2_profile(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sample = "a" * 64
    case = (
        tmp_path
        / "malware"
        / "xloader"
        / "versions"
        / "unknown"
        / "cases"
        / sample
        / "iocs.json"
    )
    case.parent.mkdir(parents=True)
    case.write_text(
        json.dumps(
            {
                "network": [
                    {
                        "host": "bootstrap.example",
                        "port": 80,
                        "role": "c2_candidate",
                        "protocol": "xloader_http_get_pkt2",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    plan, _ = build_inventory(tmp_path / "malware", generated_date="2026-08-09")
    target = next(
        item for item in plan["targets"] if item["host"] == "bootstrap.example"
    )
    assert target["method"] == "protocol_profile_required"
    assert target["protocol_hints"] == ["xloader_http_get_pkt2"]

    monkeypatch.setattr(
        monitor_recent_c2,
        "probe_target_with_nmap",
        lambda _target, **_kwargs: {
            "execution_engine": "nmap_nse",
            "status": "dns_resolved",
            "alive": False,
            "c2_confirmed": False,
            "target_contact_attempted": False,
            "target_connection_established": False,
            "application_data_sent": False,
            "resolved_ips": ["203.0.113.30"],
        },
    )
    result = monitor_recent_c2.monitor(plan, allow_network=True)
    entry = next(
        item for item in result["results"] if item["host"] == "bootstrap.example"
    )
    assert (
        entry["assessment"]["state"]
        == "protocol_profile_required_c2_unverified"
    )
    assert entry["observation"]["target_contact_attempted"] is False


def test_xloader_dispatch_requires_dedicated_gate_before_profile_resolution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        monitor_recent_c2,
        "resolve_profile",
        lambda *_args, **_kwargs: pytest.fail(
            "専用gateなしでXLoader profileを解決してはいけない"
        ),
    )
    observation = monitor_recent_c2._xloader_registration_observation(
        {
            "protocol_profile_id": "missing",
            "host": "example.invalid",
            "port": 80,
        },
        True,
        False,
        None,
        REPOSITORY,
    )
    assert observation["status"] == "xloader_registration_disabled"
    assert observation["target_contact_attempted"] is False


def test_xloader_dispatch_passes_common_registry_and_nine_exact_pins(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = {
        "profile_id": "xloader-fixture-profile",
        "host": "fixture.example",
        "port": 80,
    }
    target = {
        "protocol_profile_id": profile["profile_id"],
        "protocol_profile_registry_sha256": "1" * 64,
        "protocol_profile_payload_sha256": "2" * 64,
        "protocol_profile_private_material_sha256": "3" * 64,
        "protocol_profile_selector_path_table_sha256": "4" * 64,
        "protocol_profile_synthetic_template_id": (
            "xloader-v8-pkt2-synthetic-v1"
        ),
        "protocol_profile_pkt2_inner_plaintext_sha256": "5" * 64,
        "protocol_profile_request_sha256": "6" * 64,
        "protocol_profile_review_id": "xloader-review-fixture",
        "host": profile["host"],
        "port": profile["port"],
    }
    calls: list[dict] = []

    class FakeXLoaderModule:
        @staticmethod
        def load_private_material(path: Path, *, repository_root: Path | None):
            assert path == tmp_path / "private.json"
            assert repository_root == REPOSITORY
            return object()

        @staticmethod
        def probe_reviewed_xloader_registration(
            observed_profile: dict,
            **kwargs,
        ):
            assert observed_profile == profile
            calls.append(kwargs)
            return {
                "status": "xloader_v8_response_mismatch",
                "alive": True,
                "c2_confirmed": False,
                "target_contact_attempted": True,
                "target_connection_established": True,
                "application_data_sent": True,
                "registration_attempted": True,
                "synthetic_identity_sent": True,
                "task_poll_attempted": True,
                "task_content_published": False,
                "task_executed": False,
                "payload_download_attempted": False,
                "victim_metadata_sent": False,
                "request_count": 1,
                "request_evidence": {"request_bytes": 256},
                "http": {"status": 404, "response_body_length": 16},
            }

    monkeypatch.setattr(
        monitor_recent_c2,
        "resolve_profile",
        lambda *_args, **_kwargs: profile,
    )
    monkeypatch.setattr(
        monitor_recent_c2,
        "_load_xloader_active_probe_module",
        lambda: FakeXLoaderModule,
    )
    observation = monitor_recent_c2._xloader_registration_observation(
        target,
        True,
        True,
        tmp_path / "private.json",
        REPOSITORY,
    )
    kwargs = calls[0]
    assert kwargs["allow_network"] is True
    assert kwargs["allow_xloader_registration"] is True
    assert kwargs["allow_xloader_candidate_check"] is False
    assert kwargs["expected_profile_sha256"] == "2" * 64
    assert kwargs["expected_profile_registry_sha256"] == "1" * 64
    assert kwargs["expected_private_material_sha256"] == "3" * 64
    assert kwargs["expected_selector_path_table_sha256"] == "4" * 64
    assert (
        kwargs["expected_synthetic_template_id"]
        == "xloader-v8-pkt2-synthetic-v1"
    )
    assert kwargs["expected_pkt2_inner_plaintext_sha256"] == "5" * 64
    assert kwargs["expected_request_sha256"] == "6" * 64
    assert kwargs["expected_review_id"] == "xloader-review-fixture"
    assert kwargs["expected_profile_id"] == "xloader-fixture-profile"
    assert observation["request_budget_used"] == 1
    assert observation["sent_bytes"] == 256
    assert observation["received_bytes"] == 16


def test_xloader_assessment_requires_full_crypto_and_safety_flag_consistency() -> None:
    observation = {
        "status": "confirmed_xloader_v8_get_registration_command",
        "alive": True,
        "c2_confirmed": True,
        "target_connection_established": True,
        "application_data_sent": True,
        "protocol_response_received": True,
        "registration_attempted": True,
        "registration_accepted": True,
        "synthetic_identity_sent": True,
        "victim_metadata_sent": False,
        "real_victim_metadata_sent": False,
        "task_poll_attempted": True,
        "task_response_received": True,
        "task_content_published": False,
        "task_executed": False,
        "payload_download_attempted": False,
        "stage_requested": False,
        "operation_command_sent": False,
        "redirect_followed": False,
        "raw_request_published": False,
        "raw_response_published": False,
        "request_count": 1,
        "request_budget_used": 1,
        "sent_bytes": 256,
        "received_bytes": 64,
        "protocol_evidence": {
            "magic": "XLNG",
            "command_id_valid": True,
        },
    }
    confirmed = monitor_recent_c2.assess_observation(
        {"method": "xloader_v8_get_registration"},
        observation,
    )
    assert confirmed["state"] == "c2_protocol_confirmed"
    assert confirmed["c2_operational_confidence"] == 0.98

    contradictory = {
        **observation,
        "task_executed": True,
    }
    rejected = monitor_recent_c2.assess_observation(
        {"method": "xloader_v8_get_registration"},
        contradictory,
    )
    assert (
        rejected["state"]
        == "xloader_confirmation_inconsistent_c2_not_confirmed"
    )
    assert rejected["c2_operational_confidence"] == 0.0


def test_active_observation_sanitizer_removes_secret_material() -> None:
    sanitized = monitor_recent_c2._sanitize_observation(
        {
            "raw_request": "secret-request",
            "raw_response": "secret-response",
            "token": "secret-token",
            "http": {
                "status": 200,
                "body": "secret-body",
                "headers": {"server": "fixture", "set-cookie": "secret=1"},
            },
            "protocol_evidence": {
                "magic": "XLNG",
                "command_content": "secret-command",
            },
        }
    )
    rendered = json.dumps(sanitized)
    assert "secret" not in rendered
    assert sanitized["http"]["headers"] == {"server": "fixture"}
    assert sanitized["protocol_evidence"]["magic"] == "XLNG"
