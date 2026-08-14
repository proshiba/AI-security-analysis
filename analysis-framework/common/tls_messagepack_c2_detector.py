#!/usr/bin/env python3
"""AsyncRAT／VenomRATのTLS MessagePack応答をofflineで完全一致判定する。"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Mapping

from tls_messagepack_rat_host_emulator import (
    ASYNC_PROFILE_ID,
    VENOM_PROFILE_ID,
    SessionLimits,
    TlsMessagePackHostError,
    decode_frame,
    resolve_profile as resolve_host_profile,
)


class TlsMessagePackDetectorError(ValueError):
    """profileまたは応答がreview済みの検出境界に一致しないことを示す。"""


@dataclass(frozen=True)
class DetectorBinding:
    profile_id: str
    family: str
    handler: str
    host: str
    port: int
    packet_key: str
    response_packet: str
    certificate_sha256: str
    sample_sha256: str


_BINDINGS = {
    ASYNC_PROFILE_ID: DetectorBinding(
        profile_id=ASYNC_PROFILE_ID,
        family="asyncrat",
        handler="asyncrat_tls_messagepack",
        host="191.96.78.221",
        port=7788,
        packet_key="Packet",
        response_packet="pong",
        certificate_sha256="86b87d08f7c6f01acf68204715cc33d160b69561b15bceaee50fb6cf95466e02",
        sample_sha256="20f21565d7e77f3b3b7247099af91da43dcde0078c173f8e6efc74a6d40b44c3",
    ),
    VENOM_PROFILE_ID: DetectorBinding(
        profile_id=VENOM_PROFILE_ID,
        family="venomrat",
        handler="venomrat_tls_messagepack",
        host="s2gj9tonn.localto.net",
        port=6377,
        packet_key="Pac_ket",
        response_packet="Po_ng",
        certificate_sha256="4370b606ee51b67ab75611600406eb74762f5c134309358d042d696d789c5e22",
        sample_sha256="6a24ba25482c73d193fcc208d8ae267236b870b9ab30c44cabe2dc8bfb7a1073",
    ),
}


def _detector_limits() -> SessionLimits:
    return SessionLimits(
        timeout_seconds=3.0,
        maximum_frame_bytes=64,
        maximum_decoded_bytes=1024,
        maximum_map_entries=4,
        maximum_string_bytes=256,
        maximum_binary_bytes=1,
        maximum_opcode_bytes=64,
        maximum_read_calls=8,
        maximum_send_bytes=96,
    )


def resolve_detector_binding(profile: str | Mapping[str, Any]) -> DetectorBinding:
    """完全一致profile IDまたはregistry objectを検出契約へ束縛する。"""

    if isinstance(profile, str):
        profile_id = profile
        supplied: Mapping[str, Any] | None = None
    elif isinstance(profile, Mapping):
        profile_id = str(profile.get("profile_id") or "")
        supplied = profile
    else:
        raise TypeError("profile must be a reviewed profile ID or mapping")
    binding = _BINDINGS.get(profile_id)
    if binding is None:
        raise TlsMessagePackDetectorError("未レビューのTLS MessagePack detector profileです")
    host_profile = resolve_host_profile(profile_id)
    if (
        host_profile.family != binding.family
        or host_profile.handler != binding.handler
        or host_profile.packet_key != binding.packet_key
        or host_profile.heartbeat_response_opcode != binding.response_packet
        or host_profile.sample_sha256 != binding.sample_sha256
    ):
        raise TlsMessagePackDetectorError("host emulatorとdetectorのprofile bindingが不一致です")
    if supplied is None:
        return binding
    expected: dict[str, Any] = {
        "profile_id": binding.profile_id,
        "family": binding.family,
        "protocol": binding.family,
        "method": binding.handler,
        "handler": binding.handler,
        "host": binding.host,
        "port": binding.port,
        "sni": binding.host,
        "role": (
            "AsyncRAT 0.5.8 TLS MessagePack C2"
            if binding.family == "asyncrat"
            else "VenomRAT 6.0.3 TLS MessagePack C2"
        ),
        "source": (
            "analysis-results/research/c2-protocol-profiles/2026-08-04/"
            f"profiles-evidence.json:analysis[{0 if binding.family == 'asyncrat' else 1}]"
        ),
        "packet_key": binding.packet_key,
        "message_key": "Message",
        "request_packet": "Ping",
        "expected_response_packets": [binding.response_packet],
        "expected_certificate_sha256": binding.certificate_sha256,
        "sample_sha256s": [binding.sample_sha256],
        "timeout_seconds": 3.0,
        "maximum_request_bytes": 96,
        "maximum_response_bytes": 64,
    }
    for key, value in expected.items():
        if supplied.get(key) != value:
            raise TlsMessagePackDetectorError(f"detector profile binding mismatch: {key}")
    return binding


def certificate_assessment(observed_der: bytes, expected_sha256: str | None) -> dict[str, Any]:
    """証明書一致をbuild互換性とし、不一致だけではfamily C2を除外しない。"""

    if not isinstance(observed_der, bytes) or not observed_der:
        raise TlsMessagePackDetectorError("certificate DER must be non-empty bytes")
    observed = hashlib.sha256(observed_der).hexdigest()
    expected = expected_sha256.casefold() if expected_sha256 else None
    matched = expected == observed if expected else None
    if matched is True:
        state = "exact_match"
        reason = "検体内蔵証明書SHA-256と観測証明書が一致"
    elif matched is False:
        state = "mismatch_inconclusive"
        reason = "証明書は不一致だが、改変build・fork・rotationの可能性があるためfamily C2を除外しない"
    else:
        state = "observed_without_static_pin"
        reason = "観測証明書SHA-256は取得したが検体側期待値は未復元"
    return {
        "observed_sha256": observed,
        "expected_sha256": expected,
        "exact_match": matched,
        "state": state,
        "certificate_mismatch_excludes_c2": False,
        "reason": reason,
    }


def classify_reviewed_response(
    profile: str | Mapping[str, Any],
    frame: bytes | bytearray | memoryview,
    *,
    negotiated_tls_version: str | None,
    certificate_der: bytes | None = None,
) -> dict[str, Any]:
    """1個のresponse frameをraw値を保持せずにfail-closed判定する。"""

    binding = resolve_detector_binding(profile)
    version_exact = negotiated_tls_version == "TLSv1.2"
    try:
        decoded = decode_frame(frame, _detector_limits())
    except (TypeError, TlsMessagePackHostError) as exc:
        raise TlsMessagePackDetectorError("TLS MessagePack response frameが不正です") from exc
    expected_values = {binding.packet_key: binding.response_packet}
    response_exact = decoded.values == expected_values
    confirmed = version_exact and response_exact
    if not version_exact:
        status = "tls_version_mismatch"
    elif not response_exact:
        status = "tls_messagepack_response_mismatch"
    else:
        status = "confirmed_tls_messagepack_c2"
    certificate = (
        certificate_assessment(certificate_der, binding.certificate_sha256)
        if certificate_der is not None
        else None
    )
    exact_build_compatible = (
        confirmed and certificate is not None and certificate["exact_match"] is True
    )
    return {
        "schema_version": 1,
        "profile_id": binding.profile_id,
        "family": binding.family,
        "protocol": "tls_messagepack",
        "status": status,
        "c2_confirmed": confirmed,
        "exact_build_compatible": exact_build_compatible,
        "tls": {
            "observed_version": negotiated_tls_version,
            "expected_version": "TLSv1.2",
            "version_exact": version_exact,
            "certificate": certificate,
        },
        "application": {
            "response_exact": response_exact,
            "response_packet": binding.response_packet if response_exact else None,
            "response_field_count": len(decoded.values),
            "frame_size": decoded.frame_size,
            "frame_sha256": decoded.frame_sha256,
            "decoded_size": decoded.decoded_size,
            "decoded_sha256": decoded.decoded_sha256,
        },
        "safety": {
            "raw_frame_retained": False,
            "response_values_published": False,
            "victim_metadata_sent": False,
            "operation_command_sent": False,
            "operation_executed": False,
            "synthetic_result_sent": False,
        },
    }
