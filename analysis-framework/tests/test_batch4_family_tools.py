"""第4バッチで追加・拡張した静的抽出器と検知資材の回帰試験。"""

from __future__ import annotations

import base64
import importlib.util
import json
from pathlib import Path
import struct
import sys

import pytest


FRAMEWORK = Path(__file__).parents[1]
COMMON = FRAMEWORK / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import passive_c2_detector  # noqa: E402


def load_module(family: str):
    path = FRAMEWORK / "malware" / family / "extract_config.py"
    spec = importlib.util.spec_from_file_location(f"batch4_{family}", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def minimal_elf(machine: int, payload: bytes, *, big_endian: bool = False) -> bytes:
    byte_order = ">" if big_endian else "<"
    ident = b"\x7fELF" + bytes([1, 2 if big_endian else 1, 1]) + b"\0" * 9
    header = struct.pack(f"{byte_order}HHIIIIIHHHHHH", 2, machine, 1, 0, 0, 0, 0, 52, 32, 0, 0, 0, 0)
    return ident + header + payload


def mirai_plaintext() -> bytes:
    values = {
        "cnc_hosts": "ewqqwt2.duckdns.org,ewqqwt.duckdns.org",
        "cnc_port": "43833",
        "doh1": "1.1.1.1",
        "doh2": "8.8.8.8",
        "doh3": "9.9.9.9",
        "doh_port1": "443",
        "doh_port2": "443",
        "doh_port3": "5053",
        "ens_gateways": "https://cloudflare-eth.com",
        "bot_version": "1",
        "group_id": "0",
        "ping_interval": "90",
        "pong_timeout": "10",
        "reconnect_initial": "1",
        "reconnect_max": "300",
        "reconnect_multiplier": "2",
        "killer_scan_interval": "300",
        "watchdog_check_sec": "60",
        "persist_cron_interval": "60",
        "locker_watch_dirs": "/tmp:/var/tmp:/dev/shm:/var/run",
        "selfrep_enabled": "1",
    }
    rendered = "\n".join(f"{key}={value}" for key, value in values.items()).encode()
    assert len(rendered) <= 445
    return rendered.ljust(445, b"\0")


def test_mirai_ens_doh_extracts_standard_and_trailing_layouts() -> None:
    module = load_module("mirai_ens_doh_bot")
    key = bytes(range(32))
    nonce = bytes(range(12))
    ciphertext = module._decrypt(key, nonce, mirai_plaintext())
    marker = b"selfrep_enabled\0" + b"\0" * 12

    powerpc = minimal_elf(
        20,
        marker + key + nonce + ciphertext + b"7ujMko0admin\0iptables-sync\0watchdog_check_sec",
        big_endian=True,
    )
    result = module.extract_config(powerpc)
    assert result["architecture"] == "powerpc"
    assert result["configuration_crypto"]["layout"] == "key_nonce_ciphertext"
    assert result["c2"][0]["port"] == 43833
    assert result["name_resolution"]["doh_resolvers"][2]["port"] == 5053

    trailing = ciphertext + b"\0" * 3 + nonce + key
    mips = minimal_elf(8, marker + trailing + b"7ujMko0admin\0iptables-sync")
    result = module.extract_config(mips)
    assert result["architecture"] == "mips"
    assert result["configuration_crypto"]["layout"] == "ciphertext_nonce_key"
    assert {item["host"] for item in result["c2"]} == {
        "ewqqwt.duckdns.org",
        "ewqqwt2.duckdns.org",
    }


def test_mirai_profile_does_not_confirm_unknown_protocol() -> None:
    profile = json.loads(
        (FRAMEWORK / "malware" / "mirai_ens_doh_bot" / "c2_profile.json").read_text(
            encoding="utf-8"
        )
    )
    detected = passive_c2_detector.detect(
        profile,
        [{"destination_host": "ewqqwt.duckdns.org", "destination_port": 43833}],
    )
    assert detected["matches"][0]["verdict"] == "possible_c2"
    assert detected["matches"][0]["c2_confirmed"] is False
    assert detected["shodan"]["queries"] == [
        "hostname:ewqqwt.duckdns.org port:43833",
        "hostname:ewqqwt2.duckdns.org port:43833",
    ]


def test_chud_extracts_arm_and_persistence_markers() -> None:
    module = load_module("chud_bot")
    data = minimal_elf(
        40,
        b"CHUD-HANDSHAKE-V2\0 127.0.0.2\0"
        b"systemd\0/etc/init.d\0rc.common\0S99\0@reboot\0rc.local\0chattr\0",
    )
    result = module.extract_config(data)
    assert result["architecture"] == "arm"
    assert all(result["persistence"].values())
    assert result["controller"][0]["role"] == "local_controller"


def _custom_base64(value: str) -> str:
    standard = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
    custom = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/="
    encoded = base64.b64encode(value.encode()).decode()
    return encoded.translate(str.maketrans(standard, custom))


def test_electron_loader_deobfuscates_without_javascript_execution() -> None:
    module = load_module("electron_payload_loader")
    values = [_custom_base64("placeholder") for _ in range(1213)]
    values[0x478] = _custom_base64("url")
    values[0x262] = _custom_base64("name")
    source = (
        "var a0_0x222=a0_0x111;"
        "var _0xabc=" + repr(values) + ";"
        "a0_0x999=function(){return _0xabc;};"
        "var obj={};obj[a0_0x222(0x478)]='http://example.invalid/payload.exe';"
    )
    decoded, metadata = module.deobfuscate_in_memory(source)
    assert "obj[\"url\"]" in decoded
    assert metadata == {"array_size": 1213, "left_rotation": 0}


def test_electron_loader_parses_non_c2_distribution_and_empty_telemetry() -> None:
    module = load_module("electron_payload_loader")
    source = """
require('electron'); require('child_process');
obj["url"]="http://62.60.226.198/uploads/file.exe"; obj["name"]="payload.exe";
const CONFIG={'TG_TOKEN':'','TG_CHAT_ID':'','FAKE_REPO':'Runtime Components',
'FAKE_BRANCH':'3.2.1','FAKE_FILES_COUNT':0x4df,'FAKE_SIZE_MB':'187.4 MB',
'AUTO_CLOSE_AFTER':0xea60};
https://api.ipify.org https://ipwho.is/ Add-MpPreference -ExclusionPath MSFT_MpPreference
ProgramData net_ createHash md5 exec( spawn( Launching
"""
    result = module.extract_from_decoded_source(source, {"array_size": 1, "left_rotation": 0})
    assert result["payloads"][0]["is_c2"] is False
    assert result["payloads"][0]["name"] == "payload.exe"
    assert result["telemetry"]["functional"] is False
    assert result["defense_evasion"]["defender_path_exclusion"] is True
    assert result["fake_installer"]["auto_close_after_ms"] == 60000


def test_go_stack_vm_workload_is_non_networked() -> None:
    module = load_module("go_synthetic_workload")
    data = (
        b"MZGo build ID:runtime.main\0PUSH\0MOD\0PRINTREG\0chart.pxcztfnnqycucam\0"
        + "Стековая виртуальная машина исполняет байткод".encode()
        + "Программа вычисляет 5!".encode()
        + "НОД(48, 36)".encode()
        + "Рендер SVG-диаграммы телеметрии".encode()
    )
    result = module.extract_config(data)
    assert result["workload_profiles"] == ["stack_vm_svg_telemetry"]
    assert result["c2"] == []
    assert not any(result["network_capability_markers"].values())
    assert result["generated_files"] == ["chart.pxcztfnnqycucam"]


def test_batch4_yara_rules_compile() -> None:
    yara = pytest.importorskip("yara")
    for family in (
        "chud_bot",
        "electron_payload_loader",
        "go_synthetic_workload",
        "mirai_ens_doh_bot",
    ):
        rule = next((FRAMEWORK / "malware" / family / "rules").glob("*.yar"))
        yara.compile(filepath=str(rule))
