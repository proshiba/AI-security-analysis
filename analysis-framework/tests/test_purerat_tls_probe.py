from __future__ import annotations

import sys
from pathlib import Path

import pytest


COMMON = Path(__file__).parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

from purerat_tls_probe import (  # noqa: E402
    PURE_PROTOCOL_PRELUDE,
    PureRatProbeError,
    probe_reviewed_purerat_tls,
)


CERTIFICATE = "a" * 64


def profile() -> dict:
    return {
        "profile_id": "fixture-purerat",
        "handler": "purerat_tls_prelude",
        "host": "rat.example.test",
        "port": 56001,
        "send_hex": "04000000",
        "sni": None,
        "tls_version": "TLSv1.2",
        "expected_certificate_sha256": CERTIFICATE,
        "timeout_seconds": 3.0,
        "maximum_request_bytes": 4,
        "maximum_response_bytes": 64,
    }


class FakeSocket:
    def __init__(self) -> None:
        self.sent: list[bytes] = []
        self.timeout: float | None = None
        self.closed = False

    def settimeout(self, value: float) -> None:
        self.timeout = value

    def sendall(self, value: bytes) -> None:
        self.sent.append(value)

    def close(self) -> None:
        self.closed = True


def resolver(*_args, **_kwargs):
    return [(2, 1, 6, "", ("93.184.216.34", 56001))]


def test_probe_is_fail_closed_without_both_gates() -> None:
    no_network = probe_reviewed_purerat_tls(profile())
    assert no_network["status"] == "network_disabled"
    assert no_network["target_contact_attempted"] is False
    no_prelude = probe_reviewed_purerat_tls(profile(), allow_network=True)
    assert no_prelude["status"] == "purerat_protocol_prelude_disabled"
    assert no_prelude["protocol_prelude_sent"] is False


def test_exact_prelude_and_certificate_confirm_c2() -> None:
    raw = FakeSocket()
    connected: list[tuple[tuple[str, int], float]] = []

    def connector(endpoint, timeout):
        connected.append((endpoint, timeout))
        return raw

    def handshake(sock, reviewed_profile):
        assert sock is raw
        assert reviewed_profile["sni"] is None
        return {
            "version": "TLSv1.2",
            "cipher": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "certificate_sha256": CERTIFICATE,
        }

    result = probe_reviewed_purerat_tls(
        profile(),
        allow_network=True,
        allow_protocol_prelude=True,
        resolver=resolver,
        connector=connector,
        tls_handshaker=handshake,
    )
    assert connected == [(('93.184.216.34', 56001), 3.0)]
    assert raw.sent == [PURE_PROTOCOL_PRELUDE]
    assert raw.closed is True
    assert result["status"] == "confirmed_purerat_prelude_tls_certificate"
    assert result["c2_confirmed"] is True
    assert result["protocol_prelude_accepted"] is True
    assert result["victim_metadata_sent"] is False
    assert result["registration_attempted"] is False
    assert result["task_poll_attempted"] is False


def test_certificate_mismatch_is_inconclusive_not_negative_family_match() -> None:
    raw = FakeSocket()
    result = probe_reviewed_purerat_tls(
        profile(),
        allow_network=True,
        allow_protocol_prelude=True,
        resolver=resolver,
        connector=lambda *_args: raw,
        tls_handshaker=lambda *_args: {
            "version": "TLSv1.2",
            "cipher": "fixture",
            "certificate_sha256": "b" * 64,
        },
    )
    assert result["c2_confirmed"] is False
    assert result["tls"]["certificate"]["state"] == "mismatch_inconclusive"
    assert result["certificate_mismatch_excludes_c2"] is False


def test_unreviewed_prelude_and_dns_pin_mismatch_are_rejected_before_connect() -> None:
    invalid = profile()
    invalid["send_hex"] = "00000000"
    with pytest.raises(PureRatProbeError):
        probe_reviewed_purerat_tls(
            invalid,
            allow_network=True,
            allow_protocol_prelude=True,
        )

    pinned = profile()
    pinned["pinned_ips"] = ["1.1.1.1"]
    with pytest.raises(PureRatProbeError):
        probe_reviewed_purerat_tls(
            pinned,
            allow_network=True,
            allow_protocol_prelude=True,
            resolver=resolver,
            connector=lambda *_args: pytest.fail("DNS pin不一致時は接続してはいけない"),
        )
