from __future__ import annotations

import json
import subprocess
import sys
import threading
from urllib.request import Request, urlopen

from emulators.unclassified.mx_go.client import require_loopback, run
from emulators.unclassified.mx_go.server import CONTENT, SYNTHETIC_RECIPIENTS, build_server


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
        body = json.dumps({"client_id": "LAB-MXGO", "license_key": "LAB_ONLY"}).encode()
        request = Request(base + "/api/v1/heartbeat_direct", data=body, headers={"Content-Type": "application/json"})
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

def test_c2_detector_lab_checkin_and_recipient_summary() -> None:
    server = build_server("127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    detector = __import__("pathlib").Path(__file__).resolve().parents[4] / "analysis-framework" / "common" / "c2_detector.py"
    common = [sys.executable, str(detector), "127.0.0.1", str(server.server_port), "--protocol", "mxgo", "--mxgo-allow-loopback-network"]
    try:
        checkin = subprocess.run(common + ["--mxgo-mode", "checkin"], capture_output=True, text=True, check=True, timeout=10)
        checkin_result = json.loads(checkin.stdout)
        assert checkin_result["c2_confirmed"] is True
        assert checkin_result["mxgo_checkin"]["real_machine_identity_sent"] is False

        recipients = subprocess.run(common + ["--mxgo-mode", "recipients"], capture_output=True, text=True, check=True, timeout=10)
        recipient_result = json.loads(recipients.stdout)
        assert recipient_result["mxgo_recipients"]["count"] == 2
        assert recipient_result["mxgo_recipients"]["values_redacted"] is True
        assert recipient_result["mxgo_recipients"]["all_addresses_use_invalid_tld"] is True
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
        assert result["checkin"]["lab_emulator"] is True
        assert result["recipients"]["count"] == 2
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