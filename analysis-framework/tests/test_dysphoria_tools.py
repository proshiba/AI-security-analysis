from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
FAMILY = ROOT / "analysis-framework" / "malware" / "dysphoria"


def load(name: str):
    path = FAMILY / name
    spec = importlib.util.spec_from_file_location(f"dysphoria_{path.stem}", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def elf(payload: bytes, machine: int = 40) -> bytes:
    header = bytearray(64)
    header[:6] = b"\x7fELF\x01\x01"
    header[18:20] = machine.to_bytes(2, "little")
    return bytes(header) + payload


def test_extractor_classifies_ddos_and_relay_roles() -> None:
    extractor = load("extract_config.py")
    ddos = extractor.extract_config(
        elf(extractor.RC4_KEY + b" hail china mainland busybox wget /proc/net/tcp")
    )
    assert ddos["variant_role"] == "ddos_bot"
    assert ddos["protocol"]["login_packet_length"] == 78
    assert ddos["safety"]["network_contacted"] is False

    relay = extractor.extract_config(
        elf(b" c2.saintpetersburgresident.ru peer.saintpetersburgresident.ru")
    )
    assert relay["variant_role"] == "relay_proxy"
    assert {item["role"] for item in relay["c2"]} == {
        "relay_control", "relay_peer_distribution"
    }

    upnp = extractor.extract_config(
        elf(b" login.trees4sale.net www.trees4sale.net AddPortMapping WANIPConnection 239.255.255.250")
    )
    assert upnp["variant_role"] == "relay_proxy_upnp"


def test_network_detector_requires_exact_length_and_prefix() -> None:
    detector = load("network_detector.py")
    emulator = load("emulator.py")
    packets = emulator.build_synthetic_packets("node-a")
    login = bytes.fromhex(packets["login_hex"])
    heartbeat = bytes.fromhex(packets["heartbeat_hex"])
    assert detector.detect_payload(login)["packet_kind"] == "login"
    assert detector.detect_payload(heartbeat)["packet_kind"] == "heartbeat"
    assert detector.detect_payload(login[:-1])["matched"] is False
    assert packets["network_contacted"] is False
    assert packets["bot_registered"] is False


def test_static_detector_fails_closed() -> None:
    detector = load("detect.py")
    assert detector.detect(elf(b"generic busybox wget"))["matched"] is False
    assert detector.detect(elf(detector.RC4_KEY))["matched"] is True


def test_yara_compiles() -> None:
    yara = pytest.importorskip("yara")
    yara.compile(filepath=str(FAMILY / "rules" / "dysphoria.yar"))


def test_snort_rules_keep_fixed_length_and_unique_sids() -> None:
    rules = (FAMILY / "rules" / "dysphoria.rules").read_text(encoding="utf-8")
    assert rules.count("dsize:78") == 2
    assert "sid:420072901" in rules and "sid:420072902" in rules
    assert "02 00 00 80 00 5A" in rules
    assert "00 00 22 BA 15 24" in rules