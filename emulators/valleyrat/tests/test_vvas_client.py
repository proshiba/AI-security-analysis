from __future__ import annotations

import pytest

from emulators.valleyrat import vvas_client
from emulators.valleyrat.vvas_client import parse_vvas_header


def test_valid_vvas_header_matches() -> None:
    raw = (307214).to_bytes(4, "little") + b"\0" * 10 + b"prefix"
    parsed = parse_vvas_header(raw, expected_stage_size=307214, expected_header_size=14)
    assert parsed["header_matches"] is True
    assert parsed["status"] == "confirmed_vvas_c2"


def test_short_response_is_mismatch() -> None:
    parsed = parse_vvas_header(b"\x0e", expected_stage_size=307214, expected_header_size=14)
    assert parsed["header_matches"] is False
    assert parsed["declared_stage2_size"] is None
    assert parsed["status"] == "protocol_mismatch"


def test_wrong_stage_size_is_mismatch() -> None:
    raw = (1234).to_bytes(4, "little") + b"\0" * 10
    parsed = parse_vvas_header(raw, expected_stage_size=307214, expected_header_size=14)
    assert parsed["header_matches"] is False
    assert parsed["declared_stage2_size"] == 1234


def test_nonzero_padding_is_mismatch() -> None:
    raw = (307214).to_bytes(4, "little") + b"\0" * 9 + b"X"
    parsed = parse_vvas_header(raw, expected_stage_size=307214, expected_header_size=14)
    assert parsed["header_matches"] is False


def test_empty_response_is_connected_no_response() -> None:
    parsed = parse_vvas_header(b"", expected_stage_size=307214, expected_header_size=14)
    assert parsed["header_matches"] is False
    assert parsed["status"] == "connected_no_response"


def test_probe_defaults_to_preflight_without_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    """networkが明示許可されない限り、直接API呼出もofflineに保つ。"""
    monkeypatch.setattr(
        vvas_client.socket,
        "getaddrinfo",
        lambda *args, **kwargs: pytest.fail("DNS must not run during preflight"),
    )
    monkeypatch.setattr(
        vvas_client.socket,
        "create_connection",
        lambda *args, **kwargs: pytest.fail("socket must not open during preflight"),
    )
    result = vvas_client.probe_vvas_target(
        "203.0.113.10",
        6666,
        "333200",
        307214,
        14,
        64,
        1.0,
    )
    assert result["status"] == "dry_run"
    assert result["network_contacted"] is False
    assert result["application_data_sent"] is False


def test_cli_network_opt_in_defaults_off() -> None:
    """live probeには明示的なnetwork許可を要求する。"""
    parser = vvas_client.build_parser()
    offline = parser.parse_args(["--host", "203.0.113.10", "--port", "6666"])
    online = parser.parse_args([
        "--host", "203.0.113.10", "--port", "6666", "--allow-network",
    ])
    assert offline.allow_network is False
    assert online.allow_network is True


def test_offline_stage_download_flags_never_expand_read_or_permission(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        vvas_client.socket,
        "create_connection",
        lambda *args, **kwargs: pytest.fail("offline preflight must not open a socket"),
    )
    result = vvas_client.probe_vvas_target(
        "203.0.113.10",
        6666,
        "414243",
        1234,
        14,
        4096,
        8.0,
        allow_stage_download=True,
        risk_accepted=True,
    )
    assert result["status"] == "dry_run"
    assert result["maximum_response_bytes"] == 64
    assert result["stage_download_requested"] is True
    assert result["stage_download_permitted"] is False
    assert result["stage_download_live_allowed"] is False


def test_live_arbitrary_target_is_rejected_before_dns_or_socket(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*_args, **_kwargs):
        pytest.fail("profile gate must run before DNS or socket")

    monkeypatch.setattr(vvas_client.socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(vvas_client.socket, "create_connection", forbidden)
    with pytest.raises(PermissionError, match="protocol-profile-id"):
        vvas_client.probe_vvas_target(
            "203.0.113.10",
            6666,
            "333200",
            307214,
            14,
            64,
            3.0,
            allow_network=True,
        )


def test_live_profile_mismatch_and_stage_download_fail_before_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = vvas_client.reviewed_live_target("valleyrat-vvas-8bf54-6666")

    def forbidden(*_args, **_kwargs):
        pytest.fail("profile mismatch must not reach the network")

    monkeypatch.setattr(vvas_client.socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(vvas_client.socket, "create_connection", forbidden)
    with pytest.raises(PermissionError, match="中央profile"):
        vvas_client.probe_vvas_target(
            target["host"],
            target["port"],
            "414243",
            target["expected_stage_size"],
            target["expected_header_size"],
            target["maximum_response_bytes"],
            target["timeout_seconds"],
            allow_network=True,
            protocol_profile_id=target["protocol_profile_id"],
        )
    with pytest.raises(PermissionError, match="stage download"):
        vvas_client.probe_vvas_target(
            target["host"],
            target["port"],
            target["send_hex"],
            target["expected_stage_size"],
            target["expected_header_size"],
            target["maximum_response_bytes"],
            target["timeout_seconds"],
            allow_stage_download=True,
            risk_accepted=True,
            allow_network=True,
            protocol_profile_id=target["protocol_profile_id"],
        )


def test_reviewed_profile_live_path_sends_only_fixed_checkin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = vvas_client.reviewed_live_target("valleyrat-vvas-8bf54-6666")
    response = (307214).to_bytes(4, "little") + b"\0" * 10

    class FakeConnection:
        def __init__(self) -> None:
            self.sent: list[bytes] = []
            self.timeout: float | None = None
            self.chunks = [response, b""]

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def settimeout(self, value: float) -> None:
            self.timeout = value

        def sendall(self, value: bytes) -> None:
            self.sent.append(bytes(value))

        def recv(self, maximum: int) -> bytes:
            value = self.chunks.pop(0)
            assert len(value) <= maximum
            return value

    connection = FakeConnection()
    monkeypatch.setattr(
        vvas_client.socket,
        "getaddrinfo",
        lambda host, port, **_kwargs: [
            (vvas_client.socket.AF_INET, vvas_client.socket.SOCK_STREAM, 6, "", (host, port))
        ],
    )

    def connect(endpoint, *, timeout):
        assert endpoint == (target["host"], target["port"])
        assert timeout == target["timeout_seconds"]
        return connection

    monkeypatch.setattr(vvas_client.socket, "create_connection", connect)
    result = vvas_client.probe_vvas_target(
        target["host"],
        target["port"],
        target["send_hex"],
        target["expected_stage_size"],
        target["expected_header_size"],
        target["maximum_response_bytes"],
        target["timeout_seconds"],
        allow_network=True,
        protocol_profile_id=target["protocol_profile_id"],
    )
    assert connection.sent == [bytes.fromhex("333200")]
    assert connection.timeout == 3.0
    assert result["protocol_profile_id"] == target["protocol_profile_id"]
    assert result["maximum_response_bytes"] == 64
    assert result["application_data_sent"] is True
    assert result["stage_download_permitted"] is False
    assert result["status"] == "confirmed_vvas_c2"


def test_cli_live_requires_central_profile_but_offline_arbitrary_parse_remains(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        vvas_client.socket,
        "create_connection",
        lambda *args, **kwargs: pytest.fail("rejected CLI must not open a socket"),
    )
    assert vvas_client.main(["--host", "203.0.113.10", "--port", "6666"]) == 0
    assert '"status": "dry_run"' in capsys.readouterr().out
    with pytest.raises(SystemExit):
        vvas_client.main([
            "--host", "203.0.113.10", "--port", "6666", "--allow-network",
        ])
