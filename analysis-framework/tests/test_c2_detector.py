from __future__ import annotations

import base64
import json
import subprocess
from pathlib import Path
import socket
import sys
import threading
import time
from types import SimpleNamespace
import zlib

import pytest


COMMON = Path(__file__).parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import c2_detector  # noqa: E402
from c2_detector import build_mxgo_heartbeat, mxgo_loopback_target, parse_n520_handshake  # noqa: E402


KNOWN_N520_HANDSHAKE = base64.b64decode(
    "VedMRkxG6ePmvrff01cXjuWZG+aqQh24G//XqST3EZ6HtDJGPpyDZkEDR1c="
)


def test_parse_confirmed_n520_handshake() -> None:
    result = parse_n520_handshake(KNOWN_N520_HANDSHAKE)
    assert result["length"] == 44
    assert result["crc_matches"] is True
    assert result["magic_matches"] is True
    assert result["header_matches"] is True
    assert result["session_id_hex"] == "0x464ce755"
    assert result["received_magic_hex"] == "0xe3e9464c"
    assert result["derived_session_key_sha256"] == (
        "e0998d2ce1aa4f3e7d1401ba4cdf50686a7295a5bb154b953357c0af02791f20"
    )


def test_rejects_n520_crc_mismatch() -> None:
    modified = bytearray(KNOWN_N520_HANDSHAKE)
    modified[12] ^= 0x01
    result = parse_n520_handshake(bytes(modified))
    assert result["crc_matches"] is False
    assert result["header_matches"] is False


def test_rejects_n520_magic_mismatch_with_valid_crc() -> None:
    modified = bytearray(KNOWN_N520_HANDSHAKE)
    modified[4] ^= 0x01
    modified[40:44] = (zlib.crc32(modified[:40]) & 0xFFFFFFFF).to_bytes(4, "little")
    result = parse_n520_handshake(bytes(modified))
    assert result["crc_matches"] is True
    assert result["magic_matches"] is False
    assert result["header_matches"] is False


def test_rejects_truncated_n520_handshake() -> None:
    result = parse_n520_handshake(KNOWN_N520_HANDSHAKE[:43])
    assert result["header_matches"] is False
    assert result["validation_error"] == "N520 handshake must be exactly 44 bytes"


def test_mxgo_heartbeat_is_synthetic() -> None:
    value = build_mxgo_heartbeat("LAB-CLIENT")
    assert value["client_id"] == "LAB-CLIENT"
    assert value["license_key"] == "LAB_ONLY"
    assert value["lab_emulator"] is True
    assert "hostname" not in value
    assert "mac" not in value


def test_mxgo_active_target_is_loopback_only() -> None:
    assert mxgo_loopback_target("127.0.0.1") is True
    assert mxgo_loopback_target("localhost") is True
    assert mxgo_loopback_target("43.165.179.173") is False


def test_shodan_queries_exclude_loopback_and_private_addresses() -> None:
    args = SimpleNamespace(host="127.0.0.2", port=23)
    value = c2_detector.build_shodan_queries(
        args,
        {"resolved_ips": ["127.0.0.2", "10.0.0.1", "192.0.2.10"]},
    )
    assert value["applicable"] is False
    assert value["queries"] == []
    assert value["recommended_combination"] is None


def test_shodan_queries_keep_public_hostname_and_address() -> None:
    args = SimpleNamespace(host="c2.example", port=69)
    value = c2_detector.build_shodan_queries(
        args,
        {"resolved_ips": ["41.216.189.236", "127.0.0.1"]},
    )
    assert value["queries"] == [
        "hostname:c2.example port:69",
        "ip:41.216.189.236 port:69",
    ]
    assert "127.0.0.1" not in json.dumps(value)


def test_shodan_query_does_not_treat_onion_as_public_hostname() -> None:
    args = SimpleNamespace(
        host="exampleexampleexampleexampleexampleexampleexampleexample.onion",
        port=80,
    )
    value = c2_detector.build_shodan_queries(args, {"resolved_ips": []})
    assert value["applicable"] is False
    assert value["queries"] == []


def test_socks5_connect_negotiates_exact_target(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeSocket:
        def __init__(self) -> None:
            self.sent: list[bytes] = []
            self.responses = [
                b"\x05\x00",
                b"\x05\x00\x00\x01",
                b"\x7f\x00\x00\x01",
                b"\x23\x5a",
            ]
            self.closed = False

        def settimeout(self, _timeout: float) -> None:
            pass

        def sendall(self, value: bytes) -> None:
            self.sent.append(value)

        def recv(self, _size: int) -> bytes:
            return self.responses.pop(0)

        def close(self) -> None:
            self.closed = True

    fake = FakeSocket()
    monkeypatch.setattr(
        c2_detector.socket,
        "create_connection",
        lambda *_args, **_kwargs: fake,
    )
    metadata = {}
    connection = c2_detector.socks5_connect(
        "127.0.0.1", 9050,
        "exampleexampleexampleexampleexampleexampleexampleexample.onion",
        80, 3.0, result=metadata,
    )
    assert connection is fake
    assert fake.sent[0] == b"\x05\x01\x00"
    assert fake.sent[1].startswith(b"\x05\x01\x00\x03")
    assert fake.sent[1].endswith(b"\x00\x50")
    assert b".onion" in fake.sent[1]
    assert metadata == {
        "proxy_connection_established": True,
        "proxy_control_data_sent": True,
        "target_contact_attempted": True,
    }


def test_socks5_proxy_refusal_is_not_recorded_as_target_attempt(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*_args, **_kwargs):
        raise ConnectionRefusedError("proxy unavailable")

    monkeypatch.setattr(c2_detector.socket, "create_connection", refuse)
    args = SimpleNamespace(
        proxy_host="127.0.0.1",
        proxy_port=9050,
        host="exampleexampleexampleexampleexampleexampleexampleexample.onion",
        port=80,
        timeout=3.0,
    )
    metadata = {
        "network_contacted": False,
        "target_contact_attempted": False,
        "target_connection_established": False,
    }
    with pytest.raises(ConnectionRefusedError):
        c2_detector.open_bounded_connection(args, metadata)
    assert metadata["network_contacted"] is True
    assert metadata["proxy_connection_established"] is False
    assert metadata["proxy_control_data_sent"] is False
    assert metadata["target_contact_attempted"] is False
    assert metadata["target_connection_established"] is False


def test_cli_records_target_role_and_sample_association() -> None:
    script = COMMON / "c2_detector.py"
    digest = "a" * 64
    completed = subprocess.run(
        [
            sys.executable, str(script), "203.0.113.10", "443",
            "--target-role", "distribution", "--sample-sha256", digest,
        ],
        capture_output=True, text=True, check=True, timeout=5,
    )
    result = json.loads(completed.stdout)
    assert result["target_role"] == "distribution"
    assert result["sample_sha256s"] == [digest]
    assert result["application_data_sent"] is False


def test_mxgo_cli_preview_does_not_contact_network() -> None:
    script = COMMON / "c2_detector.py"
    completed = subprocess.run(
        [sys.executable, str(script), "43.165.179.173", "5000", "--protocol", "mxgo", "--mxgo-mode", "preview"],
        capture_output=True, text=True, check=True, timeout=5,
    )
    result = json.loads(completed.stdout)
    assert result["status"] == "dry_run"
    assert result["network_contacted"] is False
    assert result["mxgo_request_preview"]["uses_real_machine_identity"] is False


def test_mxgo_cli_rejects_external_active_target() -> None:
    script = COMMON / "c2_detector.py"
    completed = subprocess.run(
        [
            sys.executable, str(script), "43.165.179.173", "5000", "--protocol", "mxgo",
            "--mxgo-mode", "checkin", "--mxgo-allow-loopback-network",
        ],
        capture_output=True, text=True, check=False, timeout=5,
    )
    assert completed.returncode == 2
    assert "loopback-only" in completed.stderr


def test_direct_probe_defaults_to_offline_preflight(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep direct API callers offline when the acknowledgement is absent."""
    monkeypatch.setattr(
        c2_detector.socket,
        "getaddrinfo",
        lambda *args, **kwargs: pytest.fail("DNS must not run during preflight"),
    )
    monkeypatch.setattr(
        c2_detector.socket,
        "create_connection",
        lambda *args, **kwargs: pytest.fail("socket must not open during preflight"),
    )
    result = c2_detector.probe(SimpleNamespace(
        host="203.0.113.10",
        port=443,
        protocol="tcp",
        timeout=1.0,
        max_bytes=64,
    ))
    assert result["status"] == "dry_run"
    assert result["network_contacted"] is False
    assert result["application_data_sent"] is False


def test_cli_defaults_to_offline_preflight() -> None:
    """Return a useful plan instead of contacting an external target by default."""
    script = COMMON / "c2_detector.py"
    completed = subprocess.run(
        [sys.executable, str(script), "203.0.113.10", "443", "--protocol", "https"],
        capture_output=True, text=True, check=True, timeout=5,
    )
    result = json.loads(completed.stdout)
    assert result["status"] == "dry_run"
    assert result["network_contacted"] is False
    assert result["http_request_preview"]["host"] == "203.0.113.10"


def test_udp_probe_sends_only_empty_datagram_to_loopback() -> None:
    received: list[bytes] = []
    ready = threading.Event()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.bind(("127.0.0.1", 0))
        port = server.getsockname()[1]

        def serve() -> None:
            ready.set()
            packet, peer = server.recvfrom(1)
            received.append(packet)
            server.sendto(b"OK", peer)

        worker = threading.Thread(target=serve, daemon=True)
        worker.start()
        assert ready.wait(1)
        result = c2_detector.probe(SimpleNamespace(
            host="127.0.0.1",
            port=port,
            protocol="udp",
            timeout=1.0,
            max_bytes=16,
            allow_network=True,
            proxy_host=None,
            collect_jarm=False,
            send_hex=None,
            target_role="c2",
            sample_sha256=[],
            http_host=None,
            http_path="/",
            sni=None,
            mxgo_recipient_path="/fixture.txt",
            mxgo_mode="preview",
        ))
        worker.join(1)
    assert received == [b""]
    assert result["status"] == "udp_response_received"
    assert result["application_data_sent"] is False
    assert result["datagram_payload_length"] == 0
    assert result["c2_confirmed"] is False
    assert result["banner"]["length"] == 2


@pytest.mark.parametrize(
    ("option", "value"),
    [
        ("--http-host", "example.test\r\nX-Injected: yes"),
        ("--http-path", "/safe\nInjected: yes"),
    ],
)
def test_cli_rejects_http_crlf(option: str, value: str) -> None:
    """Reject request-line and Host-header injection before any network opt-in."""
    script = COMMON / "c2_detector.py"
    completed = subprocess.run(
        [
            sys.executable, str(script), "203.0.113.10", "80", "--protocol", "http",
            option, value,
        ],
        capture_output=True, text=True, check=False, timeout=5,
    )
    assert completed.returncode == 2
    assert "must not contain CR/LF" in completed.stderr


def test_collect_jarm_accepts_small_fingerprint_output(tmp_path: Path) -> None:
    """Recover a valid fingerprint while retaining only bounded helper output."""
    script = tmp_path / "small_jarm.py"
    script.write_text("print('a' * 62)\n", encoding="utf-8")
    result = c2_detector.collect_jarm(
        "fixture.invalid", 443, script, 0.1, allow_network=True,
    )
    assert result["status"] == "collected"
    assert result["fingerprint"] == "a" * 62
    assert result["stdout_retained_bytes"] <= c2_detector.JARM_STDOUT_LIMIT_BYTES
    assert result["stderr_retained_bytes"] <= c2_detector.JARM_STDERR_LIMIT_BYTES
    assert result["stdout_truncated"] is False
    assert result["stderr_truncated"] is False


def test_collect_jarm_defaults_to_offline_without_spawning(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Do not start the external helper when direct callers omit network opt-in."""
    script = tmp_path / "unused_jarm.py"
    script.write_text("raise AssertionError('must not execute')\n", encoding="utf-8")
    monkeypatch.setattr(
        c2_detector.subprocess,
        "Popen",
        lambda *args, **kwargs: pytest.fail("JARM helper must not start offline"),
    )
    result = c2_detector.collect_jarm("fixture.invalid", 443, script, 0.1)
    assert result == {
        "status": "not_collected",
        "reason": "network collection disabled",
        "network_contacted": False,
    }


@pytest.mark.parametrize(
    ("stream_expression", "prefix"),
    [
        ("sys.stdout.buffer", "stdout"),
        ("sys.stderr.buffer", "stderr"),
    ],
)
def test_collect_jarm_bounds_huge_helper_output(
    tmp_path: Path,
    stream_expression: str,
    prefix: str,
) -> None:
    """Stop the helper when either output pipe exceeds its fixed retention cap."""
    script = tmp_path / f"huge_{prefix}_jarm.py"
    script.write_text(
        "import sys\n"
        f"stream = {stream_expression}\n"
        "stream.write(b'Z' * (256 * 1024))\n"
        "stream.flush()\n",
        encoding="utf-8",
    )
    result = c2_detector.collect_jarm(
        "fixture.invalid", 443, script, 0.1, allow_network=True,
    )
    assert result["status"] == "output_limit"
    assert result["fingerprint"] is None
    assert result[f"{prefix}_truncated"] is True
    assert result[f"{prefix}_retained_bytes"] <= getattr(
        c2_detector, f"JARM_{prefix.upper()}_LIMIT_BYTES",
    )
    assert result["stdout_retained_bytes"] <= c2_detector.JARM_STDOUT_LIMIT_BYTES
    assert result["stderr_retained_bytes"] <= c2_detector.JARM_STDERR_LIMIT_BYTES
    assert len(result["output_tail"].encode("utf-8")) <= 1000


def test_collect_jarm_timeout_terminates_helper(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Wait for timeout cleanup and prevent a terminated child from continuing."""
    monkeypatch.setattr(c2_detector, "JARM_MIN_PROCESS_TIMEOUT_SECONDS", 0.2)
    monkeypatch.setattr(c2_detector, "JARM_PROCESS_TIMEOUT_MULTIPLIER", 1.0)
    marker_base = tmp_path / "timeout-child"
    marker = Path(f"{marker_base}.done")
    script = tmp_path / "slow_jarm.py"
    script.write_text(
        "from pathlib import Path\n"
        "import sys\n"
        "import time\n"
        "time.sleep(0.75)\n"
        "Path(sys.argv[-1] + '.done').write_text('escaped', encoding='utf-8')\n",
        encoding="utf-8",
    )
    started = time.monotonic()
    result = c2_detector.collect_jarm(
        str(marker_base), 443, script, 0.1, allow_network=True,
    )
    elapsed = time.monotonic() - started
    assert result["status"] == "timeout"
    assert result["fingerprint"] is None
    assert result["cleanup_action"] in {"terminated", "killed"}
    assert result["exit_code"] is not None
    assert elapsed < 3.0
    time.sleep(0.9)
    assert not marker.exists()
