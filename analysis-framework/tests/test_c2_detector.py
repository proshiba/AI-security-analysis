from __future__ import annotations

import base64
import json
import subprocess
from pathlib import Path
import sys
import zlib


COMMON = Path(__file__).parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

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
