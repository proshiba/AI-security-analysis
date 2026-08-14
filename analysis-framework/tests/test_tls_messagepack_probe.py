from __future__ import annotations

import hashlib
import struct
import sys
from pathlib import Path

import pytest


COMMON = Path(__file__).parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

from c2_protocol_probe_profiles import load_profiles  # noqa: E402
from tls_messagepack_probe import (  # noqa: E402
    MessagePackProbeError,
    certificate_assessment,
    decode_compressed_payload,
    encode_compressed_frame,
    exchange_reviewed_packet,
)


class FakeTlsStream:
    def __init__(self, response: bytes) -> None:
        self.response = bytearray(response)
        self.sent = b""

    def sendall(self, value: bytes) -> None:
        self.sent += value

    def recv(self, size: int) -> bytes:
        value = bytes(self.response[:size])
        del self.response[:size]
        return value


def profile(packet_key: str, response: str) -> dict:
    profile_id = (
        "asyncrat-058-20f21565-191-96-78-221-7788"
        if packet_key == "Packet"
        else "venomrat-603-6a24ba25-localto-6377"
    )
    value = load_profiles()[profile_id]
    assert value["packet_key"] == packet_key
    assert value["expected_response_packets"] == [response]
    return value


@pytest.mark.parametrize(
    ("packet_key", "response"),
    [("Packet", "pong"), ("Pac_ket", "Po_ng")],
)
def test_reviewed_packet_round_trip_confirms_family_variant(
    packet_key: str,
    response: str,
) -> None:
    reply = encode_compressed_frame({packet_key: response})
    stream = FakeTlsStream(reply)
    result = exchange_reviewed_packet(stream, profile(packet_key, response))
    request_size = struct.unpack("<I", stream.sent[:4])[0]
    request = decode_compressed_payload(stream.sent[4 : 4 + request_size])
    assert request == {packet_key: "Ping", "Message": ""}
    assert result["c2_confirmed"] is True
    assert result["victim_metadata_sent"] is False
    assert result["stage_requested"] is False
    assert result["command_polling_performed"] is False


def test_certificate_mismatch_is_inconclusive_not_exclusion() -> None:
    evidence = certificate_assessment(b"observed-certificate", "a" * 64)
    assert evidence["observed_sha256"] == hashlib.sha256(b"observed-certificate").hexdigest()
    assert evidence["exact_match"] is False
    assert evidence["state"] == "mismatch_inconclusive"
    assert evidence["certificate_mismatch_excludes_c2"] is False
    assert "C2を除外しない" in evidence["reason"]


def test_response_packet_mismatch_does_not_confirm() -> None:
    reply = encode_compressed_frame({"Packet": "not-pong"})
    result = exchange_reviewed_packet(FakeTlsStream(reply), profile("Packet", "pong"))
    assert result["protocol_response_received"] is True
    assert result["c2_confirmed"] is False


def test_oversized_declared_response_is_rejected_before_body_read() -> None:
    stream = FakeTlsStream(struct.pack("<I", 65))
    with pytest.raises(MessagePackProbeError, match="response frame長"):
        exchange_reviewed_packet(stream, profile("Packet", "pong"))