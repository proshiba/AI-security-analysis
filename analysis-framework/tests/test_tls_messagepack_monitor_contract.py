from __future__ import annotations

import copy
import importlib
import json
import sys
from pathlib import Path

import pytest

COMMON = Path(__file__).parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

monitor = importlib.import_module("monitor_recent_c2")
detector = importlib.import_module("tls_messagepack_c2_detector")


def exact_observation(profile_id: str, *, certificate_match: bool = True) -> dict:
    binding = detector.resolve_detector_binding(profile_id)
    certificate_state = "exact_match" if certificate_match else "mismatch_inconclusive"
    observed_certificate = binding.certificate_sha256 if certificate_match else "c" * 64
    return {
        "status": "confirmed_tls_messagepack_c2",
        "detector_status": "confirmed_tls_messagepack_c2",
        "alive": True,
        "c2_confirmed": True,
        "target_contact_attempted": True,
        "target_connection_established": True,
        "application_data_sent": True,
        "protocol_response_received": True,
        "request_count": 1,
        "request_budget_used": 1,
        "sent_bytes": 48,
        "received_bytes": 42,
        "response_packet": binding.response_packet,
        "response_field_count": 1,
        "response_frame_size": 42,
        "response_frame_sha256": "a" * 64,
        "response_decoded_size": 15,
        "response_decoded_sha256": "b" * 64,
        "tls_version_exact": True,
        "tls": {
            "handshake": True,
            "observed_version": "TLSv1.2",
            "expected_version": "TLSv1.2",
            "version_exact": True,
            "certificate": {
                "state": certificate_state,
                "exact_match": certificate_match,
                "observed_sha256": observed_certificate,
                "expected_sha256": binding.certificate_sha256,
                "certificate_mismatch_excludes_c2": False,
            },
        },
        "certificate_mismatch_excludes_c2": False,
        "victim_metadata_sent": False,
        "stage_requested": False,
        "operation_command_sent": False,
        "command_polling_performed": False,
        "raw_request_published": False,
        "raw_response_published": False,
        "raw_response_retained": False,
        "synthetic_result_sent": False,
        "resolved_ips": ["93.184.216.34"],
    }


@pytest.mark.parametrize(
    ("profile_id", "method"),
    [
        (
            "asyncrat-058-20f21565-191-96-78-221-7788",
            "asyncrat_tls_messagepack",
        ),
        (
            "venomrat-603-6a24ba25-localto-6377",
            "venomrat_tls_messagepack",
        ),
    ],
)
def test_exact_response_confirms_without_requiring_certificate_match(
    profile_id: str,
    method: str,
) -> None:
    assessment = monitor.assess_observation(
        {"method": method, "protocol_profile_id": profile_id},
        exact_observation(profile_id, certificate_match=False),
    )
    assert assessment["state"] == "c2_protocol_confirmed"
    assert assessment["c2_operational_confidence"] == 0.95
    assert assessment["method_confidence_ceiling"] == 0.95


def test_tls_version_inconsistency_cannot_use_generic_confirmation() -> None:
    profile_id = "asyncrat-058-20f21565-191-96-78-221-7788"
    observation = exact_observation(profile_id)
    observation["tls_version_exact"] = False
    observation["tls"]["observed_version"] = "TLSv1.3"
    observation["tls"]["version_exact"] = False
    assessment = monitor.assess_observation(
        {
            "method": "asyncrat_tls_messagepack",
            "protocol_profile_id": profile_id,
        },
        observation,
    )
    assert assessment["state"] == "tls_messagepack_confirmation_inconsistent_c2_not_confirmed"
    assert assessment["c2_operational_confidence"] == 0.0


def test_response_mismatch_never_falls_through_to_generic_application_score() -> None:
    profile_id = "venomrat-603-6a24ba25-localto-6377"
    observation = exact_observation(profile_id)
    observation.update(
        {
            "status": "tls_messagepack_response_mismatch",
            "detector_status": "tls_messagepack_response_mismatch",
            "c2_confirmed": False,
            "response_packet": None,
        }
    )
    assessment = monitor.assess_observation(
        {
            "method": "venomrat_tls_messagepack",
            "protocol_profile_id": profile_id,
        },
        observation,
    )
    assert assessment["state"] == "tls_messagepack_endpoint_reachable_protocol_not_confirmed"
    assert assessment["reachability_confidence"] == 0.98
    assert assessment["c2_operational_confidence"] == 0.0


def test_method_specific_sanitizer_drops_raw_private_and_nested_material() -> None:
    profile_id = "venomrat-603-6a24ba25-localto-6377"
    raw = exact_observation(profile_id)
    raw.update(
        {
            "raw_response": "LEAK-MARKER",
            "private_key": "LEAK-MARKER",
            "pfx_bytes": "LEAK-MARKER",
            "payload_hex": "LEAK-MARKER",
        }
    )
    raw["tls"].update(
        {
            "raw_der": "LEAK-MARKER",
            "private_key": "LEAK-MARKER",
        }
    )
    sanitized = monitor._sanitize_tls_messagepack_observation(
        {
            "method": "venomrat_tls_messagepack",
            "protocol_profile_id": profile_id,
        },
        raw,
    )
    published = json.dumps(sanitized, ensure_ascii=False, sort_keys=True)
    assert "LEAK-MARKER" not in published
    assert sanitized["response_packet"] == "Po_ng"
    assert sanitized["response_frame_sha256"] == "a" * 64
    assert set(sanitized["tls"]) == {
        "handshake",
        "observed_version",
        "expected_version",
        "version_exact",
        "certificate",
    }


def test_sanitizer_rejects_boolean_and_integer_type_confusion() -> None:
    profile_id = "asyncrat-058-20f21565-191-96-78-221-7788"
    raw = copy.deepcopy(exact_observation(profile_id))
    raw["c2_confirmed"] = 1
    raw["request_count"] = True
    sanitized = monitor._sanitize_tls_messagepack_observation(
        {
            "method": "asyncrat_tls_messagepack",
            "protocol_profile_id": profile_id,
        },
        raw,
    )
    assert sanitized["c2_confirmed"] is False
    assert sanitized["request_count"] == -1
