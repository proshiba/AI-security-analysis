"""Tests for the profile-defined loopback family lab."""

from __future__ import annotations

import threading

import pytest

from emulators.families import lab


def test_profiles_messages_and_frames() -> None:
    """Cover all family categories, synthetic fields, and frame validation."""
    categories = {lab.emulation_profile(family)["category"] for family in lab.load_profiles()}
    assert categories == {"rat", "stealer", "loader"}
    value = lab.synthetic_message("asyncrat")
    assert value["client_id"] == "LAB-FIXTURE" and value["capabilities"] == []
    assert lab.decode_frame(lab.encode_frame(value)) == value
    with pytest.raises(ValueError, match="lab marker"):
        lab.decode_frame(lab.encode_frame({"lab_emulator": False}))
    with pytest.raises(ValueError, match="loopback"):
        lab.require_loopback("8.8.8.8")


def test_loopback_exchange_for_every_profile() -> None:
    """Exchange synthetic registrations and verify no commands are returned."""
    server = lab.build_server("127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        for family in lab.load_profiles():
            result = lab.send(family, "127.0.0.1", server.server_address[1])
            assert result["response_is_lab_emulator"] is True
            assert result["commands_returned"] is False
            assert result["wire_compatible_with_malware"] is False
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_parser_preview() -> None:
    """Exercise the no-network preview parser."""
    args = lab.build_parser().parse_args(["preview", "--family", "guloader"])
    assert args.command == "preview" and args.family == "guloader"
    assert lab.main(["preview", "--family", "guloader"]) == 0
