"""AsyncRAT／VenomRAT C2 response detectorの完全一致契約を検証する。"""

from __future__ import annotations

import gzip
import importlib
import struct
import sys
from pathlib import Path

import pytest

COMMON = Path(__file__).parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

PROFILES = importlib.import_module("c2_protocol_probe_profiles")
DETECTOR = importlib.import_module("tls_messagepack_c2_detector")
HOST = importlib.import_module("tls_messagepack_rat_host_emulator")


def _profile(profile_id: str) -> dict:
    return PROFILES.load_profiles()[profile_id]


@pytest.mark.parametrize(
    ("profile_id", "packet_key", "response"),
    [
        (HOST.ASYNC_PROFILE_ID, "Packet", "pong"),
        (HOST.VENOM_PROFILE_ID, "Pac_ket", "Po_ng"),
    ],
)
def test_exact_tls12_response_confirms_family_c2(
    profile_id: str,
    packet_key: str,
    response: str,
) -> None:
    frame = HOST.encode_frame({packet_key: response})
    result = DETECTOR.classify_reviewed_response(
        _profile(profile_id),
        frame,
        negotiated_tls_version="TLSv1.2",
    )

    assert result["c2_confirmed"] is True
    assert result["status"] == "confirmed_tls_messagepack_c2"
    assert result["application"]["response_exact"] is True
    assert result["application"]["response_packet"] == response
    assert result["safety"]["raw_frame_retained"] is False
    assert result["safety"]["response_values_published"] is False
    assert result["safety"]["operation_executed"] is False


def test_cross_family_and_extra_fields_are_not_confirmed() -> None:
    profile = _profile(HOST.ASYNC_PROFILE_ID)
    for values in (
        {"Pac_ket": "Po_ng"},
        {"Packet": "pong", "Message": "unexpected"},
    ):
        result = DETECTOR.classify_reviewed_response(
            profile,
            HOST.encode_frame(values),
            negotiated_tls_version="TLSv1.2",
        )
        assert result["c2_confirmed"] is False
        assert result["status"] == "tls_messagepack_response_mismatch"
        assert result["application"]["response_packet"] is None


def test_tls_version_mismatch_is_inconclusive() -> None:
    result = DETECTOR.classify_reviewed_response(
        _profile(HOST.VENOM_PROFILE_ID),
        HOST.encode_frame({"Pac_ket": "Po_ng"}),
        negotiated_tls_version="TLSv1.3",
    )
    assert result["c2_confirmed"] is False
    assert result["status"] == "tls_version_mismatch"
    assert result["tls"]["version_exact"] is False
    assert result["application"]["response_exact"] is True


def test_certificate_mismatch_does_not_cancel_exact_family_response() -> None:
    result = DETECTOR.classify_reviewed_response(
        _profile(HOST.ASYNC_PROFILE_ID),
        HOST.encode_frame({"Packet": "pong"}),
        negotiated_tls_version="TLSv1.2",
        certificate_der=b"synthetic-rotated-certificate",
    )
    certificate = result["tls"]["certificate"]
    assert result["c2_confirmed"] is True
    assert result["exact_build_compatible"] is False
    assert certificate["exact_match"] is False
    assert certificate["certificate_mismatch_excludes_c2"] is False


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("packet_key", "Pac_ket"),
        ("sni", "wrong.example"),
        ("role", "unreviewed role"),
        ("source", "unreviewed/source.json"),
        ("expected_response_packets", ["Po_ng"]),
        ("maximum_response_bytes", 65),
        ("timeout_seconds", 2.0),
        ("sample_sha256s", ["0" * 64]),
    ],
)
def test_profile_mutation_fails_closed(field: str, value: object) -> None:
    profile = _profile(HOST.ASYNC_PROFILE_ID)
    profile[field] = value
    with pytest.raises(DETECTOR.TlsMessagePackDetectorError, match="binding mismatch"):
        DETECTOR.resolve_detector_binding(profile)


def test_duplicate_key_and_declared_size_bomb_are_rejected() -> None:
    duplicate = b"\x82\xa6Packet\xa4pong\xa6Packet\xa4pong"
    duplicate_payload = struct.pack("<I", len(duplicate)) + gzip.compress(
        duplicate,
        mtime=0,
    )
    duplicate_frame = struct.pack("<I", len(duplicate_payload)) + duplicate_payload
    with pytest.raises(DETECTOR.TlsMessagePackDetectorError, match="frameが不正"):
        DETECTOR.classify_reviewed_response(
            _profile(HOST.ASYNC_PROFILE_ID),
            duplicate_frame,
            negotiated_tls_version="TLSv1.2",
        )

    expanded = HOST.encode_messagepack_map({"Packet": "pong"}) + b"padding"
    bomb_payload = struct.pack("<I", 1) + gzip.compress(expanded, mtime=0)
    bomb_frame = struct.pack("<I", len(bomb_payload)) + bomb_payload
    with pytest.raises(DETECTOR.TlsMessagePackDetectorError, match="frameが不正"):
        DETECTOR.classify_reviewed_response(
            _profile(HOST.ASYNC_PROFILE_ID),
            bomb_frame,
            negotiated_tls_version="TLSv1.2",
        )
