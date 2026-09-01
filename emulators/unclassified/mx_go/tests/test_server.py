from __future__ import annotations

import http.client
import json
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler
from urllib.request import Request, urlopen

import pytest

from emulators.common import build_loopback_http_server
from emulators.unclassified.mx_go.client import heartbeat, require_loopback, run
from emulators.unclassified.mx_go.protocol import MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES
from emulators.unclassified.mx_go.server import (
    CONTENT,
    SYNTHETIC_RECIPIENTS,
    build_server,
)


def test_loopback_only() -> None:
    try:
        build_server("0.0.0.0", 0)
    except ValueError as exc:
        assert "loopback" in str(exc)
    else:
        raise AssertionError("non-loopback bind was accepted")


def test_synthetic_content_and_heartbeat() -> None:
    server = build_server("127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        recipients = urlopen(base + "/jp01.txt", timeout=2).read().decode().splitlines()
        assert recipients == list(SYNTHETIC_RECIPIENTS)
        assert all(value.endswith(".invalid") for value in recipients)
        body = json.dumps(heartbeat(), separators=(",", ":")).encode()
        request = Request(
            base + "/api/v1/heartbeat_direct",
            data=body,
            headers={"Content-Type": "application/json"},
        )
        response = json.loads(urlopen(request, timeout=2).read())
        assert response["lab_emulator"] is True
        assert response["commands"]["do_exit_mx"] is False
        assert server.mxgo_state.heartbeat_count == 1  # type: ignore[attr-defined]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_all_fixture_addresses_are_synthetic() -> None:
    assert all(".invalid" in value for value in CONTENT["/jp01.txt"].splitlines())


def test_common_c2_detector_remains_offline() -> None:
    server = build_server("127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    detector = (
        __import__("pathlib").Path(__file__).resolve().parents[4]
        / "analysis-framework"
        / "common"
        / "c2_detector.py"
    )
    command = [
        sys.executable,
        str(detector),
        "127.0.0.1",
        str(server.server_port),
        "--protocol",
        "mxgo",
        "--allow-network",
        "--mxgo-allow-loopback-network",
        "--mxgo-mode",
        "checkin",
    ]
    try:
        completed = subprocess.run(
            command, capture_output=True, text=True, check=False, timeout=10
        )
        assert completed.returncode == 1
        result = json.loads(completed.stdout)
        assert result["status"] == "python_direct_c2_probe_disabled"
        assert result["network_contacted"] is False
        assert result["target_contact_attempted"] is False
        assert result["application_data_sent"] is False
        assert server.mxgo_state.heartbeat_count == 0  # type: ignore[attr-defined]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_standalone_client() -> None:
    server = build_server("127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = run(f"http://127.0.0.1:{server.server_port}", "both")
        assert result["redirect_followed"] is False
        assert result["proxy_used"] is False
        assert result["checkin"]["lab_emulator"] is True
        assert result["checkin"]["response_validated"] is True
        assert result["recipients"]["count"] == 2
        assert result["recipients"]["response_validated"] is True
        assert result["recipients"]["values_redacted"] is True
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_client_rejects_non_loopback() -> None:
    try:
        require_loopback("http://43.165.179.173:5000")
    except ValueError as exc:
        assert "loopback" in str(exc)
    else:
        raise AssertionError("non-loopback client target was accepted")


def test_server_rejects_real_identity_duplicate_json_and_bad_lengths() -> None:
    """実identity、重複key、負値・過大Content-Lengthをfail-closedにする。"""
    server = build_server("127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=2)
    try:
        body = json.dumps({"client_id": "REAL-HOST", "lab_emulator": True}).encode()
        connection.request(
            "POST",
            "/api/v1/heartbeat_direct",
            body=body,
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
            },
        )
        assert connection.getresponse().status == 403
        connection.close()

        duplicate = b'{"lab_emulator":true,"lab_emulator":true}'
        connection = http.client.HTTPConnection(
            "127.0.0.1", server.server_port, timeout=2
        )
        connection.request(
            "POST",
            "/api/v1/heartbeat_direct",
            body=duplicate,
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(len(duplicate)),
            },
        )
        assert connection.getresponse().status == 400
        connection.close()

        for declared, expected in (("-1", 400), (str(MAX_REQUEST_BYTES + 1), 413)):
            connection = http.client.HTTPConnection(
                "127.0.0.1", server.server_port, timeout=2
            )
            connection.putrequest("POST", "/api/v1/heartbeat_direct")
            connection.putheader("Content-Type", "application/json")
            connection.putheader("Content-Length", declared)
            connection.endheaders()
            assert connection.getresponse().status == expected
            connection.close()
        assert server.mxgo_state.heartbeat_count == 0  # type: ignore[attr-defined]
    finally:
        connection.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_client_never_follows_redirect() -> None:
    """loopback redirectでも追跡せず、転送先へrequestを送らない。"""

    class TargetHandler(BaseHTTPRequestHandler):
        hits = 0

        def do_GET(self) -> None:  # noqa: N802
            type(self).hits += 1
            self.send_response(204)
            self.end_headers()

        def log_message(self, _format: str, *_args: object) -> None:
            return

    target = build_loopback_http_server(
        "127.0.0.1", 0, TargetHandler, label="redirect target"
    )

    class RedirectHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            self.send_response(302)
            self.send_header(
                "Location", f"http://127.0.0.1:{target.server_port}/jp01.txt"
            )
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, _format: str, *_args: object) -> None:
            return

    redirect = build_loopback_http_server(
        "127.0.0.1", 0, RedirectHandler, label="redirect source"
    )
    threads = [
        threading.Thread(target=target.serve_forever, daemon=True),
        threading.Thread(target=redirect.serve_forever, daemon=True),
    ]
    for thread in threads:
        thread.start()
    try:
        with pytest.raises(ValueError, match="redirect"):
            run(f"http://127.0.0.1:{redirect.server_port}", "recipients")
        assert TargetHandler.hits == 0
    finally:
        redirect.shutdown()
        target.shutdown()
        redirect.server_close()
        target.server_close()
        for thread in threads:
            thread.join(timeout=2)


def test_client_rejects_oversized_response() -> None:
    """上限を1 byte超えたcontentを切り詰めて成功扱いしない。"""

    class OversizedHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            body = b"x" * (MAX_RESPONSE_BYTES + 1)
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format: str, *_args: object) -> None:
            return

    server = build_loopback_http_server(
        "127.0.0.1", 0, OversizedHandler, label="oversize fixture"
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with pytest.raises(ValueError, match="size上限"):
            run(f"http://127.0.0.1:{server.server_port}", "recipients")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_client_rejects_ambiguous_url_and_unknown_mode() -> None:
    """credential／path／query付きURLと未知modeを接続前に拒否する。"""
    for target in (
        "http://user@127.0.0.1:5000",
        "http://127.0.0.1:5000/path",
        "http://127.0.0.1:5000?x=1",
    ):
        with pytest.raises(ValueError):
            run(target, "both")
    with pytest.raises(ValueError, match="mode"):
        run("http://127.0.0.1:5000", "unknown")


def test_ipv6_loopback_exchange() -> None:
    """IPv6 loopbackでcheck-inとcontent取得を同じ契約で検証する。"""
    try:
        server = build_server("::1", 0)
    except OSError as exc:
        pytest.skip(f"IPv6 loopbackを利用できません: {exc}")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = run(f"http://[::1]:{server.server_port}", "both", timeout=2)
        assert result["checkin"]["response_validated"] is True
        assert result["recipients"]["response_validated"] is True
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
