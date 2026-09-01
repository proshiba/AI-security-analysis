"""Tests for the profile-defined loopback family lab."""

from __future__ import annotations

import socket
import struct
import threading

import pytest

from emulators.families import lab


def test_profiles_messages_and_frames() -> None:
    """Cover all family categories, synthetic fields, and frame validation."""
    categories = {
        lab.emulation_profile(family)["category"] for family in lab.load_profiles()
    }
    assert categories == {"rat", "stealer", "loader"}
    value = lab.synthetic_message("asyncrat")
    assert value["client_id"] == "LAB-FIXTURE" and value["capabilities"] == []
    assert lab.decode_frame(lab.encode_frame(value)) == value
    with pytest.raises(ValueError, match="lab marker"):
        lab.decode_frame(lab.encode_frame({"lab_emulator": False}))
    with pytest.raises(ValueError, match="loopback"):
        lab.require_loopback("8.8.8.8")
    duplicate = b'{"lab_emulator":true,"lab_emulator":true}'
    with pytest.raises(ValueError, match="重複JSON key"):
        lab.decode_frame(struct.pack(">I", len(duplicate)) + duplicate)


def test_loopback_exchange_for_every_profile() -> None:
    """Exchange synthetic registrations and verify no commands are returned."""
    server = lab.build_server("127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        for family in lab.load_profiles():
            result = lab.send(family, "127.0.0.1", server.server_address[1])
            assert result["response_is_lab_emulator"] is True
            assert result["accepted"] is True
            assert result["profile_matched"] is True
            assert result["response_family_matched"] is True
            assert result["commands_returned"] is False
            assert result["wire_compatible_with_malware"] is False
            assert result["request_bytes"] > 4 and len(result["request_sha256"]) == 64
            assert result["response_bytes"] > 4 and len(result["response_sha256"]) == 64
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_parser_preview() -> None:
    """Exercise the no-network preview parser."""
    args = lab.build_parser().parse_args(["preview", "--family", "guloader"])
    assert args.command == "preview" and args.family == "guloader"
    assert lab.main(["preview", "--family", "guloader"]) == 0


def test_server_rejects_extra_fields_without_response() -> None:
    """lab markerがあっても完全一致しないidentity／fieldを受理しない。"""
    server = lab.build_server("127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        value = lab.synthetic_message("asyncrat")
        value["hostname"] = "REAL-HOST"
        with socket.create_connection(
            ("127.0.0.1", server.server_address[1]), timeout=1
        ) as client:
            client.settimeout(1)
            client.sendall(lab.encode_frame(value))
            assert client.recv(1) == b""
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_client_rejects_oversized_response_before_body_read() -> None:
    """loopback serverの過大宣言長をbody読込前に拒否する。"""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)

    def serve_once() -> None:
        client, _address = listener.accept()
        with client:
            client.recv(4096)
            client.sendall(struct.pack(">I", lab.MAX_FRAME + 1))
        listener.close()

    thread = threading.Thread(target=serve_once, daemon=True)
    thread.start()
    with pytest.raises(ValueError, match="宣言長"):
        lab.send("asyncrat", "127.0.0.1", listener.getsockname()[1], timeout=1)
    thread.join(timeout=2)


def test_ipv6_loopback_exchange() -> None:
    """IPv6 loopbackでも同じ完全一致contractを維持する。"""
    try:
        server = lab.build_server("::1", 0)
    except OSError as exc:
        pytest.skip(f"IPv6 loopbackを利用できません: {exc}")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = lab.send("quasarrat", "::1", server.server_address[1], timeout=2)
        assert result["profile_matched"] is True
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
