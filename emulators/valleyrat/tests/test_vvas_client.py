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
    """Keep direct API calls offline unless network is explicitly allowed."""
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
    """Require the positive acknowledgement for a live probe."""
    parser = vvas_client.build_parser()
    offline = parser.parse_args(["--host", "203.0.113.10", "--port", "6666"])
    online = parser.parse_args([
        "--host", "203.0.113.10", "--port", "6666", "--allow-network",
    ])
    assert offline.allow_network is False
    assert online.allow_network is True
