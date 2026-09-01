"""Tests for emulator-wide loopback enforcement."""

from __future__ import annotations

import socket

import pytest

from emulators.common import (
    LoopbackCollector,
    load_strict_json_object,
    require_loopback,
    require_loopback_http_base_url,
    require_timeout,
)


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


def test_loopback_http_url_rejects_ambiguous_or_stateful_targets() -> None:
    """credential、path、query、fragment、外部hostを接続前に拒否する。"""
    assert (
        require_loopback_http_base_url("http://localhost:8080/")
        == "http://127.0.0.1:8080"
    )
    assert require_loopback_http_base_url("http://[::1]:8080") == "http://[::1]:8080"
    for target in (
        "https://127.0.0.1:8080",
        "http://user:pass@127.0.0.1:8080",
        "http://127.0.0.1:8080/path",
        "http://127.0.0.1:8080?query=1",
        "http://127.0.0.1:8080#fragment",
        "http://example.org:8080",
        "http://127.0.0.1",
    ):
        with pytest.raises(ValueError):
            require_loopback_http_base_url(target)


def test_strict_json_rejects_duplicates_constants_and_non_objects() -> None:
    """曖昧なJSONをfamily handlerへ渡す前に拒否する。"""
    assert load_strict_json_object(b'{"lab_emulator":true}', label="fixture") == {
        "lab_emulator": True
    }
    for payload in (b'{"a":1,"a":1}', b'{"a":NaN}', b"[]", b"\xff"):
        with pytest.raises(ValueError):
            load_strict_json_object(payload, label="fixture")


def test_collector_context_manager_and_bounds() -> None:
    """context終了でthreadを閉じ、再入と過大上限を拒否する。"""
    collector = LoopbackCollector(maximum_bytes=7)
    with collector:
        assert collector.running is True
        with pytest.raises(RuntimeError, match="すでに"):
            collector.start()
        with socket.create_connection(
            ("127.0.0.1", collector.port), timeout=1.0
        ) as client:
            client.sendall(b"fixture-over-limit")
    assert collector.running is False
    assert collector.received == [b"fixture"]
    with pytest.raises(ValueError, match="1 MiB"):
        LoopbackCollector(maximum_bytes=1024 * 1024 + 1).start()
    for timeout in (0, float("inf"), 31):
        with pytest.raises(ValueError):
            require_timeout(timeout)
