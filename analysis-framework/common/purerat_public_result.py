#!/usr/bin/env python3
"""PureRAT host adapter result mapper with an exact offline policy."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

RESULT_SCOPE = "offline_or_loopback_only"
MAXIMUM_FRAME_BYTES = 65536
EMPTY_GCLASS4_SHA256 = (
    "102b51b9765a56a3e899f7cf0ee38e5251f9c503b357b330a49183eb7b155604"
)
EMPTY_GCLASS4_FRAME_SHA256 = (
    "fae7f27b56eed121c893860cd4764d64541fe1a0b67bc22da050e70161f44001"
)
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
EXPECTED_PROFILE = {
    "profile_id": "purerat-441-d025a296-direct-tls10-empty-gclass4",
    "protocol_profile_id": (
        "purerat-441-d025a296-45-192-211-77-56001-direct-tls10"
    ),
    "protocol_profile_object_sha256": (
        "01ef2619ccbcc772d95a1bb73291c900627522b5f45b6d7e72f2d2b8b0979cec"
    ),
    "family": "purehvnc",
    "adapter_id": "purerat_direct_tls_v1",
    "host": "45.192.211.77",
    "port": 56001,
    "pinned_ips": ["45.192.211.77"],
    "transport": "tls",
    "tls_version": "TLSv1.0",
    "sni": None,
    "expected_certificate_sha256": (
        "b3ae061b0b14a89d5134c279775b8f77a42214323c6bddab07f4d81ca2fc5c57"
    ),
    "certificate_mismatch_is_negative_evidence": False,
    "sample_sha256s": [
        "d025a29613e300d7755f878eb1d23d8a8a042cb2d3eb9005d66664ab9b97c677",
        "df0359edefe34a970af39227978dbe7f1caa09caf98a2c6db53f49187ec25dd7",
    ],
    "evidence_source": (
        "analysis-framework/malware/purehvnc/purerat_441_emulator_evidence.json"
    ),
    "evidence_sha256": (
        "73422aedd0227225850dc2df3edea996b3bd1c30ec334c0c079f93c8277822a8"
    ),
    "registration_mode": "fixed_empty_gclass4",
    "station_id_sent": False,
    "unknown_task_action": "no_response",
    "file_transfer_action": "reject_and_close",
    "fake_result_scope": "loopback_or_offline_only",
    "allow_live_fake_results": False,
    "live_scope": RESULT_SCOPE,
    "limits": {
        "duration_seconds": 3.0,
        "maximum_connections": 1,
        "maximum_outbound_frames": 1,
        "maximum_outbound_bytes": 26,
        "maximum_inbound_frames": 1,
        "maximum_inbound_read_calls": 64,
        "maximum_inbound_bytes": MAXIMUM_FRAME_BYTES,
        "maximum_frame_bytes": MAXIMUM_FRAME_BYTES,
        "maximum_commands": 1,
        "minimum_send_interval_seconds": 0.0,
    },
}
EXPECTED_DECISION = {
    1: (
        "client_registration",
        "client_origin_message_received_from_server",
        "no_response_and_terminate",
    ),
    2: (
        "heartbeat",
        "known_non_operation_message_observed",
        "no_response_and_terminate",
    ),
    3: (
        "status_or_error",
        "known_non_operation_message_observed",
        "no_response_and_terminate",
    ),
    4: (
        "plugin_result",
        "client_origin_message_received_from_server",
        "no_response_and_terminate",
    ),
    5: (
        "plugin_request",
        "plugin_request_refused",
        "refuse_plugin_or_file_and_terminate",
    ),
    35: (
        "auxiliary_message",
        "known_non_operation_message_observed",
        "no_response_and_terminate",
    ),
    38: (
        "configuration_update",
        "configuration_update_refused",
        "refuse_configuration_update_and_terminate",
    ),
    86: ("command", "command_refused", "refuse_command_and_terminate"),
}
UNKNOWN_DECISION = (
    "unknown",
    "unknown_discriminator_rejected",
    "no_response_and_terminate",
)
EXPECTED_REGISTRATION = {
    "attempted": True,
    "sent": True,
    "runtime_type": "GClass4",
    "protoinclude_type": 1,
    "schema_status": "confirmed_terminal_metadata_and_il",
    "real_identity_sent": False,
    "populated_member_count": 0,
    "protobuf_size": 2,
    "protobuf_sha256": EMPTY_GCLASS4_SHA256,
    "packet_size": 26,
    "packet_sha256": EMPTY_GCLASS4_FRAME_SHA256,
}
EXPECTED_SAFETY = {
    "sample_executed": False,
    "host_operation_executed": False,
    "operation_executed": False,
    "task_executed": False,
    "operation_command_sent": False,
    "plugin_or_file_retained": False,
    "plugin_or_file_executed": False,
    "configuration_applied": False,
    "command_reply_sent": False,
    "fake_result_sent": False,
    "application_send_count": 1,
    "additional_application_send_allowed": False,
    "pfx_loaded": False,
    "private_key_loaded": False,
    "client_certificate_sent": False,
    "raw_response_published": False,
    "session_continues": False,
}


class PureRatPublicResultError(ValueError):
    """The adapter result did not match the reviewed public contract."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise PureRatPublicResultError(message)


def _mapping(parent: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    value = parent.get(key)
    if not isinstance(value, Mapping):
        raise PureRatPublicResultError(f"PureRAT {key} must be an object")
    return value


def _scalar(source: Mapping[str, Any], key: str, expected_type: type) -> Any:
    value = source.get(key)
    if expected_type is int and isinstance(value, bool):
        raise PureRatPublicResultError(f"PureRAT {key} has an invalid type")
    if not isinstance(value, expected_type):
        raise PureRatPublicResultError(f"PureRAT {key} has an invalid type")
    return value


def _sha256(
    source: Mapping[str, Any], key: str, *, optional: bool = False
) -> str | None:
    value = source.get(key)
    if optional and value is None:
        return None
    if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
        raise PureRatPublicResultError(f"PureRAT {key} is not a SHA-256 digest")
    return value


def _validate_profile(profile: Mapping[str, Any]) -> None:
    for key, expected in EXPECTED_PROFILE.items():
        _require(
            profile.get(key) == expected,
            f"PureRAT profile.{key} does not match the reviewed pin",
        )


def _public_registration(result: Mapping[str, Any]) -> dict[str, Any]:
    registration = _mapping(result, "registration")
    public: dict[str, Any] = {}
    for key, expected in EXPECTED_REGISTRATION.items():
        expected_type = int if type(expected) is int else type(expected)
        value = (
            _sha256(registration, key)
            if key.endswith("sha256")
            else _scalar(registration, key, expected_type)
        )
        _require(value == expected, f"PureRAT registration.{key} is inconsistent")
        public[key] = value
    return public


def _public_safety(result: Mapping[str, Any]) -> dict[str, Any]:
    safety = _mapping(result, "safety")
    public: dict[str, Any] = {}
    for key, expected in EXPECTED_SAFETY.items():
        expected_type = int if type(expected) is int else bool
        value = _scalar(safety, key, expected_type)
        _require(value == expected, f"PureRAT safety.{key} is inconsistent")
        public[key] = value
    return public


def _public_decisions(
    result: Mapping[str, Any], response_size: int, response_sha256: str | None
) -> list[dict[str, Any]]:
    decisions = result.get("decisions")
    if not isinstance(decisions, list) or len(decisions) > 1:
        raise PureRatPublicResultError("PureRAT decisions must contain at most one item")
    public: list[dict[str, Any]] = []
    for decision in decisions:
        if not isinstance(decision, Mapping):
            raise PureRatPublicResultError("PureRAT decision must be an object")
        fingerprint = _mapping(decision, "fingerprint")
        discriminator = _scalar(decision, "discriminator", int)
        expected = EXPECTED_DECISION.get(discriminator, UNKNOWN_DECISION)
        actual = (
            _scalar(decision, "message_type", str),
            _scalar(decision, "classification", str),
            _scalar(decision, "action", str),
        )
        _require(discriminator > 0, "PureRAT discriminator must be positive")
        _require(actual == expected, "PureRAT discriminator classification mismatch")
        should_respond = _scalar(decision, "should_respond", bool)
        terminate_session = _scalar(decision, "terminate_session", bool)
        _require(should_respond is False, "PureRAT reply is not permitted")
        _require(terminate_session is True, "PureRAT session must terminate")
        frame_size = _scalar(fingerprint, "frame_size", int)
        frame_sha256 = _sha256(fingerprint, "frame_sha256")
        decoded_size = _scalar(fingerprint, "decoded_size", int)
        decoded_sha256 = _sha256(fingerprint, "decoded_sha256")
        _require(
            24 <= frame_size <= MAXIMUM_FRAME_BYTES,
            "PureRAT frame size exceeds the reviewed bound",
        )
        _require(
            2 <= decoded_size <= MAXIMUM_FRAME_BYTES,
            "PureRAT decoded size exceeds the reviewed bound",
        )
        _require(frame_size == response_size, "PureRAT frame/response size mismatch")
        _require(frame_sha256 == response_sha256, "PureRAT frame/response hash mismatch")
        public.append(
            {
                "discriminator": discriminator,
                "message_type": actual[0],
                "classification": actual[1],
                "action": actual[2],
                "should_respond": should_respond,
                "terminate_session": terminate_session,
                "frame_size": frame_size,
                "frame_sha256": frame_sha256,
                "decoded_size": decoded_size,
                "decoded_sha256": decoded_sha256,
            }
        )
    return public


def build_public_purerat_result(
    result: Mapping[str, Any], profile: Mapping[str, Any]
) -> dict[str, Any]:
    """Return only reviewed scalars and never promote an offline result to C2 proof."""

    if not isinstance(result, Mapping) or not isinstance(profile, Mapping):
        raise PureRatPublicResultError("PureRAT result/profile must be objects")
    _validate_profile(profile)
    top = {
        "schema_version": _scalar(result, "schema_version", int),
        "family": _scalar(result, "family", str),
        "variant": _scalar(result, "variant", str),
        "protocol": _scalar(result, "protocol", str),
        "status": _scalar(result, "status", str),
    }
    for key, expected in {
        "schema_version": 1,
        "family": "purehvnc",
        "variant": "purerat_4_4_1",
        "protocol": "purerat_direct_tls",
    }.items():
        _require(top[key] == expected, f"PureRAT {key} is inconsistent")
    collection_source = _mapping(result, "collection")
    response_size = _scalar(collection_source, "response_size", int)
    response_sha256 = _sha256(
        collection_source, "response_sha256", optional=True
    )
    frame_count = _scalar(collection_source, "frame_count", int)
    collection = {
        "response_size": response_size,
        "response_sha256": response_sha256,
        "frame_count": frame_count,
        "timed_out": _scalar(collection_source, "timed_out", bool),
        "peer_closed": _scalar(collection_source, "peer_closed", bool),
    }
    decisions = _public_decisions(result, response_size, response_sha256)
    _require(frame_count in {0, 1}, "PureRAT frame_count must be zero or one")
    _require(len(decisions) == frame_count, "PureRAT decision/frame count mismatch")
    if frame_count == 0:
        _require(response_size == 0, "PureRAT no-frame result retained bytes")
        _require(response_sha256 is None, "PureRAT no-frame result retained a hash")
        _require(
            top["status"] == "registration_sent_no_frame_observed",
            "PureRAT no-frame status is inconsistent",
        )
    else:
        _require(
            24 <= response_size <= MAXIMUM_FRAME_BYTES,
            "PureRAT response size exceeds the reviewed bound",
        )
        _require(response_sha256 is not None, "PureRAT response hash is required")
        _require(
            top["status"] == decisions[0]["classification"],
            "PureRAT status/classification mismatch",
        )
    return {
        "c2_confirmed": False,
        "result_scope": RESULT_SCOPE,
        **top,
        "certificate_mismatch_is_negative_evidence": False,
        "registration": _public_registration(result),
        "collection": collection,
        "decisions": decisions,
        "safety": _public_safety(result),
    }


__all__ = ["PureRatPublicResultError", "build_public_purerat_result"]
