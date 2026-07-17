"""Tests for emulator-wide loopback enforcement."""

from __future__ import annotations

import socket
import pytest

from emulators.common import LoopbackCollector, require_loopback


def test_require_loopback_accepts_only_literal_loopback() -> None:
    """Canonicalize localhost and refuse external or DNS-named targets."""
    assert require_loopback("localhost") == "127.0.0.1"
    assert require_loopback("::1") == "::1"
    with pytest.raises(ValueError, match="loopback-only"):
        require_loopback("8.8.8.8")
    with pytest.raises(ValueError, match="loopback-only"):
        require_loopback("example.org")


def test_loopback_collector_receives_without_reply() -> None:
    """Collect one bounded local fixture and stop without the close-before-recv race."""
    collector = LoopbackCollector()
    port = collector.start()
    with socket.create_connection(("127.0.0.1", port), timeout=1.0) as client:
        client.sendall(b"fixture")
    collector.stop()
    assert collector.received == [b"fixture"]
