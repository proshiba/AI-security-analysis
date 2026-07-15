"""Tests for the loopback-only stealer lab."""

from __future__ import annotations

import json
import threading

import pytest

from emulators.stealers import lab


def test_profiles_bodies_and_loopback() -> None:
    """Cover profiles, synthetic payloads, and containment checks."""
    assert lab.require_loopback("127.0.0.1") == "127.0.0.1"
    with pytest.raises(ValueError, match="loopback"):
        lab.require_loopback("8.8.8.8")
    assert lab.profile_for("amosstealer")["path"].startswith("/ledger/")
    assert json.loads(lab.synthetic_body("formbook"))["items"] == []


def test_server_and_client() -> None:
    """Exchange synthetic requests for every family over loopback only."""
    server = lab.build_server("127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{server.server_port}"
        for family in lab.PROFILES:
            result = lab.send(family, base)
            assert (
                result["response_is_lab_emulator"] and not result["commands_returned"]
            )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_parser() -> None:
    """Exercise the lab command-line parser."""
    args = lab.build_parser().parse_args(["client", "--family", "vidar"])
    assert args.command == "client" and args.family == "vidar"
