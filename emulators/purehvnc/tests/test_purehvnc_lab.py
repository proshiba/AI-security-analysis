"""Unit tests for the loopback-only PureHVNC laboratory."""

from __future__ import annotations

import socket

import pytest

from emulators.purehvnc.lab import LoopbackCollector, pack_managed_message, pack_native_frame, parse_managed_message, parse_native_frame, require_loopback


def test_native_and_managed_round_trips() -> None:
    """Round-trip both observed offline framing helpers."""
    frame = pack_native_frame(1, b"{}")
    assert parse_native_frame(frame + b"tail") == (1, b"{}", b"tail")
    managed = pack_managed_message({1: b"lab"})
    assert parse_managed_message(managed)[1] == [b"lab"]
    with pytest.raises(ValueError):
        parse_native_frame(b"short")


def test_loopback_guard_and_collector() -> None:
    """Reject remote targets and collect one local fixture without responding."""
    assert require_loopback("127.0.0.1") == "127.0.0.1"
    with pytest.raises(ValueError):
        require_loopback("192.0.2.1")
    collector = LoopbackCollector()
    port = collector.start()
    with socket.create_connection(("127.0.0.1", port), timeout=1) as client:
        client.sendall(b"fixture")
    collector.stop()
    assert collector.received == [b"fixture"]
