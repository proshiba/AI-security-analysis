from __future__ import annotations

import copy
import socket
import sys
from pathlib import Path

import pytest

COMMON = Path(__file__).parents[1] / "common"
REPOSITORY_ROOT = Path(__file__).parents[2]
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import darkcomet_server_first_probe as darkcomet
from c2_protocol_probe_profiles import load_profiles
from darkcomet_profile_evidence import validate_darkcomet_profile_evidence

KEY = b"#KCMDDC5#-"


def reviewed_profile() -> dict:
    value = copy.deepcopy(load_profiles()["darkcomet-b9b052df-f168-name-1604"])
    evidence = validate_darkcomet_profile_evidence(value, repository_root=REPOSITORY_ROOT)
    value["evidence_sha256"] = evidence["sha256"]
    value["evidence_source"] = evidence["source"]
    value["timeout_seconds"] = 1.0
    return value


def encrypted_idtype() -> bytes:
    return darkcomet.rc4_crypt(b"IDTYPE", KEY)


@pytest.mark.parametrize(
    ("wire", "encoding"),
    [
        (encrypted_idtype(), "raw"),
        (encrypted_idtype().hex().encode("ascii"), "ascii_hex"),
        (encrypted_idtype().hex().upper().encode("ascii"), "ascii_hex"),
    ],
)
def test_strict_decoder_accepts_only_idtype_raw_or_ascii_hex(
    wire: bytes,
    encoding: str,
) -> None:
    result = darkcomet.decode_server_first_response(wire, KEY)
    assert result["status"] == "confirmed_darkcomet_idtype"
    assert result["matched"] is True
    assert result["wire_encoding"] == encoding
    assert result["decrypted_plaintext_published"] is False
    assert result["rc4_key_published"] is False


def test_wrong_key_never_confirms() -> None:
    result = darkcomet.decode_server_first_response(encrypted_idtype(), b"wrong-key")
    assert result["status"] == "darkcomet_idtype_mismatch"
    assert result["matched"] is False


@pytest.mark.parametrize(
    ("wire", "status"),
    [
        (b"abc", "darkcomet_ciphertext_partial"),
        (b"00112233", "darkcomet_ciphertext_partial"),
        (b"not-hex-data", "darkcomet_ciphertext_malformed"),
        (b"00112233445Z", "darkcomet_ciphertext_malformed"),
        (b"A" * 13, "darkcomet_ciphertext_overlong"),
    ],
)
def test_partial_malformed_and_overlong_are_rejected(wire: bytes, status: str) -> None:
    result = darkcomet.decode_server_first_response(wire, KEY)
    assert result["status"] == status
    assert result["matched"] is False


class FakeSocket:
    def __init__(self, chunks: list[bytes | BaseException], connect_error: OSError | None = None) -> None:
        self.chunks = list(chunks)
        self.connect_error = connect_error
        self.recv_sizes: list[int] = []
        self.timeouts: list[float] = []
        self.connected_to: tuple | None = None
        self.closed = False

    def settimeout(self, value: float) -> None:
        self.timeouts.append(value)

    def connect(self, sockaddr: tuple) -> None:
        self.connected_to = sockaddr
        if self.connect_error is not None:
            raise self.connect_error

    def getpeername(self):
        return (self.connected_to or ("203.0.113.8", 1604))

    def recv(self, size: int) -> bytes:
        self.recv_sizes.append(size)
        if not self.chunks:
            return b""
        value = self.chunks.pop(0)
        if isinstance(value, BaseException):
            raise value
        if len(value) > size:
            raise AssertionError("fixtureが要求sizeを超えています")
        return value

    def close(self) -> None:
        self.closed = True


def install_network(
    monkeypatch: pytest.MonkeyPatch,
    streams: list[FakeSocket],
    addresses: list[str] | None = None,
) -> None:
    values = addresses or ["203.0.113.8"]
    monkeypatch.setattr(
        darkcomet.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (address, 1604))
            for address in values
        ],
    )
    pending = list(streams)
    monkeypatch.setattr(darkcomet.socket, "socket", lambda *_args: pending.pop(0))


@pytest.mark.parametrize(
    ("chunks", "expected_encoding"),
    [
        ([encrypted_idtype(), b""], "raw"),
        ([encrypted_idtype().hex().encode("ascii")[:6], encrypted_idtype().hex().encode("ascii")[6:], b""], "ascii_hex"),
    ],
)
def test_eof_raw_and_delayed_six_plus_six_are_confirmed_without_send(
    monkeypatch: pytest.MonkeyPatch,
    chunks: list[bytes],
    expected_encoding: str,
) -> None:
    stream = FakeSocket(chunks)
    install_network(monkeypatch, [stream])
    result = darkcomet.probe_reviewed_darkcomet_server_first(
        reviewed_profile(), allow_network=True, repository_root=REPOSITORY_ROOT
    )
    assert result["status"] == "confirmed_darkcomet_idtype"
    assert result["c2_confirmed"] is True
    assert result["wire_encoding"] == expected_encoding
    assert result["server_first_bytes_received"] in {6, 12}
    assert result["application_data_sent"] is False
    assert result["sent_bytes"] == 0
    assert max(stream.recv_sizes) <= 13
    assert not hasattr(stream, "send")


def test_delayed_twelve_plus_one_is_overlong(monkeypatch: pytest.MonkeyPatch) -> None:
    stream = FakeSocket([b"0" * 12, b"1"])
    install_network(monkeypatch, [stream])
    result = darkcomet.probe_reviewed_darkcomet_server_first(
        reviewed_profile(), allow_network=True, repository_root=REPOSITORY_ROOT
    )
    assert result["status"] == "darkcomet_ciphertext_overlong"
    assert result["server_first_bytes_received"] == 13
    assert result["c2_confirmed"] is False


def test_network_disabled_never_resolves_or_connects(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        darkcomet.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: pytest.fail("network gate無効時にDNS解決してはいけない"),
    )
    result = darkcomet.probe_reviewed_darkcomet_server_first(reviewed_profile(), allow_network=False)
    assert result["status"] == "network_disabled"
    assert result["target_contact_attempted"] is False


def test_arbitrary_profile_is_rejected_before_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    value = reviewed_profile()
    value.pop("evidence_sha256")
    monkeypatch.setattr(
        darkcomet.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: pytest.fail("証拠未固定profileでDNS解決してはいけない"),
    )
    with pytest.raises(darkcomet.DarkCometProbeError, match="証拠 SHA-256"):
        darkcomet.probe_reviewed_darkcomet_server_first(
            value, allow_network=True, repository_root=REPOSITORY_ROOT
        )


def test_second_address_uses_only_remaining_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    first = FakeSocket([], ConnectionRefusedError())
    second = FakeSocket([b""])
    install_network(monkeypatch, [first, second], ["203.0.113.1", "203.0.113.2"])
    times = iter([0.0, 0.0, 0.4, 0.5, 0.6])
    monkeypatch.setattr(darkcomet.time, "monotonic", lambda: next(times))
    result = darkcomet.probe_reviewed_darkcomet_server_first(
        reviewed_profile(), allow_network=True, repository_root=REPOSITORY_ROOT
    )
    assert result["address_attempt_count"] == 2
    assert second.timeouts[0] == pytest.approx(0.6)


def test_deadline_exhaustion_prevents_next_address(monkeypatch: pytest.MonkeyPatch) -> None:
    first = FakeSocket([], ConnectionRefusedError())
    install_network(monkeypatch, [first], ["203.0.113.1", "203.0.113.2"])
    times = iter([0.0, 0.0, 1.1, 1.2])
    monkeypatch.setattr(darkcomet.time, "monotonic", lambda: next(times))
    with pytest.raises(socket.timeout, match="deadline"):
        darkcomet.probe_reviewed_darkcomet_server_first(
            reviewed_profile(), allow_network=True, repository_root=REPOSITORY_ROOT
        )


def test_connect_success_after_deadline_skips_receive(monkeypatch: pytest.MonkeyPatch) -> None:
    stream = FakeSocket([AssertionError("期限切れ後にrecvしてはいけない")])
    install_network(monkeypatch, [stream])
    times = iter([0.0, 0.0, 1.1])
    monkeypatch.setattr(darkcomet.time, "monotonic", lambda: next(times))
    result = darkcomet.probe_reviewed_darkcomet_server_first(
        reviewed_profile(), allow_network=True, repository_root=REPOSITORY_ROOT
    )
    assert result["status"] == "receive_skipped_deadline_exhausted"
    assert result["target_connection_established"] is True
    assert result["receive_skipped_deadline_exhausted"] is True
    assert result["c2_confirmed"] is False
    assert stream.recv_sizes == []
