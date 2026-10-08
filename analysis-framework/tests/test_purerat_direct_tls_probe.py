"""PureRAT direct-TLS probeとoffline frame codecのunit test。"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

COMMON = Path(__file__).parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

from purerat_direct_tls_probe import (
    PureRatDirectTlsError,
    classify_inner_frame,
    decode_inner_frame,
    encode_inner_frame,
    probe_reviewed_purerat_direct_tls,
    reviewed_profile,
)

CERTIFICATE = "b3ae061b0b14a89d5134c279775b8f77a42214323c6bddab07f4d81ca2fc5c57"


def profile() -> dict:
    return reviewed_profile()


class FakeSocket:
    def __init__(self) -> None:
        self.timeout: float | None = None
        self.closed = False
        self.send_attempted = False

    def settimeout(self, value: float) -> None:
        self.timeout = value

    def sendall(self, _value: bytes) -> None:
        self.send_attempted = True
        raise AssertionError("TLS確立前後を問わずapplication dataを送ってはいけません")

    def close(self) -> None:
        self.closed = True


def resolver(*_args, **_kwargs):
    return [(2, 1, 6, "", ("127.0.0.1", 56001))]


def test_offline_codec_and_protoinclude_classification() -> None:
    # field 1/wire 2は、確認済みProtoInclude表ではclient registration。
    payload = b"\x0a\x03abc"
    frame = encode_inner_frame(payload)
    assert decode_inner_frame(frame) == payload
    report = classify_inner_frame(frame)
    assert report["protoinclude_type"] == "client_registration"
    assert report["embedded_size"] == 3
    assert report["single_root_envelope_exact"] is True
    assert report["family_attribution_confirmed"] is False
    assert report["offline_only"] is True
    assert report["frame_sha256"] == hashlib.sha256(frame).hexdigest()
    assert report["protobuf_sha256"] == hashlib.sha256(payload).hexdigest()


def test_empty_registration_frame_is_cross_platform_deterministic() -> None:
    payload = b"\x0a\x00"
    frame = encode_inner_frame(payload)
    assert len(frame) == 26
    assert frame.hex() == "160000001f8b08000000000002ffe362000075fa36bb02000000"
    assert frame[13] == 0xFF
    assert hashlib.sha256(frame).hexdigest() == "fae7f27b56eed121c893860cd4764d64541fe1a0b67bc22da050e70161f44001"
    assert decode_inner_frame(frame) == payload


def test_offline_codec_rejects_bad_lengths_and_truncated_protobuf() -> None:
    frame = encode_inner_frame(b"\x0a\x01x")
    with pytest.raises(PureRatDirectTlsError):
        decode_inner_frame(frame + b"x")
    with pytest.raises(PureRatDirectTlsError):
        classify_inner_frame(encode_inner_frame(b"\x0a\x05x"))


def test_offline_codec_normalizes_malformed_gzip() -> None:
    compressed = b"not-a-gzip-payload!!"
    frame = len(compressed).to_bytes(4, "little") + compressed
    with pytest.raises(PureRatDirectTlsError, match="GZip payload"):
        decode_inner_frame(frame)


def test_offline_codec_rejects_ambiguous_types_ratio_bomb_and_trailing_root_field() -> None:
    """暗黙bytes変換、過大展開、複数root fieldをfail-closedで拒否する。"""
    with pytest.raises(PureRatDirectTlsError, match="bytes"):
        encode_inner_frame(bytearray(b"\x0a\x00"))  # type: ignore[arg-type]
    with pytest.raises(PureRatDirectTlsError, match="整数"):
        encode_inner_frame(b"\x0a\x00", maximum_size=True)  # type: ignore[arg-type]

    compressed_bomb = encode_inner_frame(
        b"A" * 4096,
        maximum_expansion_ratio=128,
    )
    with pytest.raises(PureRatDirectTlsError, match="展開率"):
        decode_inner_frame(compressed_bomb, maximum_expansion_ratio=2)

    multiple_root_fields = b"\x0a\x00\x12\x00"
    with pytest.raises(PureRatDirectTlsError, match="trailing"):
        classify_inner_frame(encode_inner_frame(multiple_root_fields))


def test_offline_codec_rejects_non_length_delimited_and_overlong_varint() -> None:
    """ProtoInclude envelopeに不正なwire typeや64-bit超過varintを許可しない。"""
    with pytest.raises(PureRatDirectTlsError, match="wire type 2"):
        classify_inner_frame(encode_inner_frame(b"\x08\x00"))
    overlong = b"\x80" * 9 + b"\x02"
    with pytest.raises(PureRatDirectTlsError, match="64-bit"):
        classify_inner_frame(encode_inner_frame(overlong))


def test_probe_requires_two_gates() -> None:
    assert probe_reviewed_purerat_direct_tls(profile())["status"] == "network_disabled"
    disabled = probe_reviewed_purerat_direct_tls(profile(), allow_network=True)
    assert disabled["status"] == "legacy_tls_disabled"
    assert disabled["target_contact_attempted"] is False
    no_backend = probe_reviewed_purerat_direct_tls(profile(), allow_network=True, allow_legacy_tls=True)
    assert no_backend["status"] == "external_backend_disabled"
    assert no_backend["external_target_contact_allowed"] is False


def test_reviewed_profile_copy_and_arbitrary_target_mutation_are_rejected_before_connect() -> None:
    first = reviewed_profile()
    first["host"] = "93.184.216.34"
    assert reviewed_profile()["host"] == "45.192.211.77"

    called = False

    def connector(*_args):
        nonlocal called
        called = True
        raise AssertionError("変更済みtargetへ接続してはいけません")

    for key, value in (
        ("host", "93.184.216.34"),
        ("profile_id", "arbitrary-profile"),
        ("terminal_sample_sha256", "0" * 64),
        ("maximum_request_bytes", 1),
    ):
        mutated = reviewed_profile()
        mutated[key] = value
        with pytest.raises(PureRatDirectTlsError):
            probe_reviewed_purerat_direct_tls(
                mutated,
                allow_network=True,
                allow_legacy_tls=True,
                resolver=resolver,
                connector=connector,
            )
    assert called is False


def test_direct_tls_is_first_and_exact_pin_is_probable_only() -> None:
    raw = FakeSocket()
    handshake_calls: list[FakeSocket] = []

    def handshake(sock, reviewed_profile):
        assert reviewed_profile["tls_version"] == "TLSv1.0"
        assert sock.send_attempted is False
        handshake_calls.append(sock)
        return {"version": "TLSv1", "cipher": "fixture", "certificate_sha256": CERTIFICATE}

    result = probe_reviewed_purerat_direct_tls(
        profile(),
        allow_network=True,
        allow_legacy_tls=True,
        resolver=resolver,
        connector=lambda *_args: raw,
        tls_handshaker=handshake,
    )
    assert handshake_calls == [raw]
    assert raw.send_attempted is False
    assert raw.closed is True
    assert result["status"] == "purerat_direct_tls_certificate_match_probable_loopback"
    assert result["profile_id"] == "purerat-441-d025a296-45-192-211-77-56001-direct-tls10"
    assert result["c2_confirmed"] is False
    assert result["probable_c2"] is True
    assert result["confidence"] == 0.75
    assert result["target_contact_attempted"] is False
    assert result["target_connection_established"] is False
    assert result["loopback_connection_established"] is True
    assert result["connected_ip"] == "127.0.0.1"
    assert result["external_target_contact_allowed"] is False
    assert result["plaintext_prelude_sent"] is False
    assert result["application_data_sent"] is False
    assert result["registration_attempted"] is False
    assert result["certificate_mismatch_excludes_exact_build_endpoint"] is True
    assert result["certificate_mismatch_excludes_family_c2"] is False


def test_exact_certificate_with_wrong_tls_version_is_inconclusive() -> None:
    raw = FakeSocket()
    result = probe_reviewed_purerat_direct_tls(
        profile(),
        allow_network=True,
        allow_legacy_tls=True,
        resolver=resolver,
        connector=lambda *_args: raw,
        tls_handshaker=lambda *_args: {
            "version": "TLSv1.2",
            "cipher": "fixture",
            "certificate_sha256": CERTIFICATE,
        },
    )

    assert raw.send_attempted is False
    assert raw.closed is True
    assert result["status"] == "purerat_direct_tls_version_mismatch_inconclusive"
    assert result["alive"] is False
    assert result["c2_confirmed"] is False
    assert result["application_data_sent"] is False
    assert result["tls"]["version"] == "TLSv1.2"
    assert result["tls"]["expected_version"] == "TLSv1"
    assert result["tls"]["version_exact_match"] is False
    assert result["tls"]["certificate"]["state"] == "exact_match"
    assert result["tls"]["certificate"]["exact_match"] is True
    assert result["tls_version_mismatch_excludes_c2"] is False
    assert result["tls_version_mismatch_excludes_exact_build_endpoint"] is True
    assert result["tls_version_mismatch_excludes_family_c2"] is False


def test_pin_mismatch_is_inconclusive_and_application_send_profile_is_rejected() -> None:
    raw = FakeSocket()
    result = probe_reviewed_purerat_direct_tls(
        profile(),
        allow_network=True,
        allow_legacy_tls=True,
        resolver=resolver,
        connector=lambda *_args: raw,
        tls_handshaker=lambda *_args: {
            "version": "TLSv1",
            "cipher": "fixture",
            "certificate_sha256": "b" * 64,
        },
    )
    assert result["c2_confirmed"] is False
    assert result["tls"]["certificate"]["state"] == "mismatch_inconclusive"
    assert result["certificate_mismatch_excludes_c2"] is False
    assert result["certificate_mismatch_excludes_exact_build_endpoint"] is True
    assert result["certificate_mismatch_excludes_family_c2"] is False

    disabled = probe_reviewed_purerat_direct_tls(profile())
    assert disabled["certificate_mismatch_excludes_exact_build_endpoint"] is True
    assert disabled["certificate_mismatch_excludes_family_c2"] is False

    invalid = reviewed_profile()
    invalid["send_hex"] = "04000000"
    invalid["maximum_request_bytes"] = 4
    with pytest.raises(PureRatDirectTlsError):
        probe_reviewed_purerat_direct_tls(
            invalid,
            allow_network=True,
            allow_legacy_tls=True,
        )


@pytest.mark.parametrize("address", ["45.192.211.77", "93.184.216.34", "::ffff:7f00:1"])
def test_injected_backend_rejects_every_non_loopback_target_before_connect(
    address: str,
) -> None:
    """明示注入backendでもnumeric loopback外へはconnectorを呼ばない。"""

    called = False

    def non_loopback_resolver(*_args, **_kwargs):
        return [(2, 1, 6, "", (address, 56001))]

    def connector(*_args):
        nonlocal called
        called = True
        raise AssertionError("非loopbackへ接続してはいけません")

    with pytest.raises(PureRatDirectTlsError, match="numeric loopback"):
        probe_reviewed_purerat_direct_tls(
            profile(),
            allow_network=True,
            allow_legacy_tls=True,
            resolver=non_loopback_resolver,
            connector=connector,
        )
    assert called is False


def test_injected_resolver_result_count_is_bounded_before_connect() -> None:
    """注入resolverも無制限の応答列をconsumerへ渡せない。"""

    called = False

    def excessive_resolver(*_args, **_kwargs):
        return [(2, 1, 6, "", ("127.0.0.1", 56001)) for _ in range(17)]

    def connector(*_args):
        nonlocal called
        called = True
        raise AssertionError("resolver上限超過後に接続してはいけません")

    with pytest.raises(PureRatDirectTlsError, match="応答件数"):
        probe_reviewed_purerat_direct_tls(
            profile(),
            allow_network=True,
            allow_legacy_tls=True,
            resolver=excessive_resolver,
            connector=connector,
        )
    assert called is False
