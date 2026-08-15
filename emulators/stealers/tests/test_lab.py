"""6系統のloopback限定stealer labを検証する。"""

from __future__ import annotations

import base64
import json
import threading
from urllib import error, request

import pytest

from emulators.stealers import lab


def test_profiles_cover_six_families_and_state_scope() -> None:
    assert set(lab.PROFILES) == {
        "stealc", "lummastealer", "remusstealer", "formbook", "vidar", "amosstealer"
    }
    assert lab.profile_for("lumma")["family"] == "lummastealer"
    assert lab.profile_for("remus")["family"] == "remusstealer"
    assert lab.profile_for("amos")["family"] == "amosstealer"
    assert lab.profile_for("stealc")["wire_compatibility"] == "registration_request_and_token_response"
    assert lab.profile_for("formbook")["emulation_scope"] == "passive_sink"


def test_loopback_and_synthetic_bodies() -> None:
    assert lab.require_loopback("127.0.0.1") == "127.0.0.1"
    with pytest.raises(ValueError, match="loopback"):
        lab.require_loopback("8.8.8.8")
    content_type, body = lab.synthetic_body("stealc")
    assert content_type == "application/json"
    plain = lab._rc4(base64.b64decode(body, validate=True), lab.LAB_STEALC_KEY)
    assert json.loads(plain) == {
        "build": "LAB-FIXTURE", "hwid": lab.LAB_UUID, "type": "create"
    }
    assert b"LAB-FIXTURE" not in body
    assert json.loads(lab.synthetic_body("amos")[1])["items"] == []


def test_server_and_client_cover_every_family() -> None:
    server = lab.build_server("127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{server.server_port}"
        for family in lab.PROFILES:
            result = lab.send(family, base)
            assert result["accepted"] is True
            assert result["commands_returned"] is False
            assert result["c2_confirmed"] is False
            assert result["redirect_followed"] is False
            assert result["victim_metadata_sent"] is False
        assert lab.send("stealc", base)["registration_token_shape_matched"] is True
        assert lab.send("amos", base)["request_count"] == 2
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_passive_sink_rejects_missing_lab_marker() -> None:
    server = lab.build_server("127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        req = request.Request(
            f"http://127.0.0.1:{server.server_port}/lab/formbook/passive-sink",
            data=b'{}', method="POST", headers={"Content-Type": "application/json"},
        )
        with pytest.raises(error.HTTPError) as caught:
            request.urlopen(req, timeout=5)
        assert caught.value.code == 403
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_server_rejects_oversized_declared_body() -> None:
    server = lab.build_server("127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        req = request.Request(
            f"http://127.0.0.1:{server.server_port}/lab/formbook/passive-sink",
            data=b"{}", method="POST",
            headers={"Content-Type": "application/json", "Content-Length": str(lab.MAX_REQUEST_BYTES + 1)},
        )
        with pytest.raises(error.HTTPError) as caught:
            request.urlopen(req, timeout=5)
        assert caught.value.code == 413
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_parser() -> None:
    args = lab.build_parser().parse_args(["client", "--family", "vidar"])
    assert args.command == "client" and args.family == "vidar"
