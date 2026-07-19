from __future__ import annotations

import importlib.util
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

import elf_utils  # noqa: E402
import loopback_emulator  # noqa: E402
import passive_c2_detector  # noqa: E402


def load_family_module(family: str):
    directory = FRAMEWORK / "malware" / family
    if str(directory) not in sys.path:
        sys.path.insert(0, str(directory))
    spec = importlib.util.spec_from_file_location(f"test_{family}_extractor", directory / "extract_config.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def minimal_elf32(payload: bytes = b"") -> bytes:
    ident = b"\x7fELF" + bytes([1, 1, 1]) + b"\0" * 9
    header = struct.pack("<HHIIIIIHHHHHH", 2, 3, 1, 0x8048054, 52, 0, 0, 52, 32, 1, 0, 0, 0)
    segment = struct.pack("<IIIIIIII", 1, 0, 0x8048000, 0x8048000, 84 + len(payload), 84 + len(payload), 5, 0x1000)
    return ident + header + segment + payload


def test_elf_layout_maps_virtual_address() -> None:
    data = minimal_elf32(b"ABCD")
    layout = elf_utils.parse_elf_layout(data)
    assert layout.bits == 32
    assert layout.byte_order == "little"
    assert layout.virtual_to_offset(0x8048054, 4) == 84


def test_condi_xor_endpoint_and_distribution_roles() -> None:
    module = load_family_module("condi")
    decoded = b"jkqhdbbbqwiujkaz.hopto.org\x00\x22\x00\x45"
    encoded = bytes(value ^ 0x22 for value in decoded)
    data = encoded + b"/tmp/condi/var/condibotzxcr9999 http://203.0.113.8/nz.x86"
    result = module.extract_config(data)
    assert result["c2"][0]["host"] == "jkqhdbbbqwiujkaz.hopto.org"
    assert result["c2"][0]["port"] == 69
    assert result["c2"][0]["confidence"] == "confirmed"
    assert result["distribution_urls"] == ["http://203.0.113.8/nz.x86"]


def test_ens_cipher_matches_reviewed_fragment() -> None:
    module = load_family_module("linux_ens_sns_bot")
    state = module.build_state(bytes.fromhex("0df0ad8bcefaedfeea1dadab0dd001c0"))
    ciphertext = bytes.fromhex("e93e66591e5ea35ce7eb5d")
    assert module.decrypt_entry(ciphertext, state) == b"roanoke.sol"
    assert len(module.STRING_DESCRIPTORS) == 53


def test_chud_endpoint_is_local_controller() -> None:
    module = load_family_module("chud_bot")
    result = module.extract_config(b"\x7fELF\x00CHUD-HANDSHAKE-V2\x00127.0.0.2\x00ppc\x00")
    assert result["controller"][0]["role"] == "local_controller"
    assert result["controller"][0]["port"] == 23


def test_efimer_xor_phase_and_literal_collapse() -> None:
    module = load_family_module("efimer")
    phase = b"tgn5AIyxKkQi"
    encrypted = module.xor_repeating(module.KNOWN_XML_PREFIX, phase)
    assert module.derive_stream_phase(encrypted) == phase
    assert module.collapse_string_concatenations("'http://'+'abc.onion/'+'route.php'") == repr(
        "http://abc.onion/route.php"
    )


def test_passive_detector_separates_endpoint_and_protocol_confirmation() -> None:
    profile = {
        "family": "fixture",
        "endpoints": [{"host": "c2.example", "port": 443, "role": "c2"}],
        "protocol_indicators": [{"id": "path", "field": "http.path", "equals": "/gate"}],
        "minimum_protocol_matches": 1,
    }
    possible = passive_c2_detector.detect(
        profile, [{"destination_host": "c2.example", "destination_port": 443, "http": {"path": "/"}}]
    )
    confirmed = passive_c2_detector.detect(
        profile, [{"destination_host": "c2.example", "destination_port": 443, "http": {"path": "/gate"}}]
    )
    assert possible["matches"][0]["verdict"] == "possible_c2"
    assert possible["matches"][0]["c2_confirmed"] is False
    assert confirmed["matches"][0]["c2_confirmed"] is True


def test_shodan_suppresses_onion_loopback_and_non_c2_roles() -> None:
    profile = {
        "family": "fixture",
        "endpoints": [
            {"host": "127.0.0.2", "port": 23, "role": "c2"},
            {"host": "x" * 56 + ".onion", "port": 80, "role": "c2"},
            {"host": "example.com", "port": 80, "role": "kill_switch"},
        ],
    }
    assert passive_c2_detector.detect(profile, [])["shodan"]["queries"] == []


def test_loopback_emulator_rejects_external_bind_and_serves_synthetic_banner() -> None:
    with pytest.raises(ValueError):
        loopback_emulator.validate_loopback("0.0.0.0")
    reserve = socket.socket()
    reserve.bind(("127.0.0.1", 0))
    port = reserve.getsockname()[1]
    reserve.close()
    output: list[dict] = []
    worker = threading.Thread(
        target=lambda: output.append(loopback_emulator.serve_once("127.0.0.1", port, "fixture", 2.0)),
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


def test_batch1_yara_rules_compile() -> None:
    yara = pytest.importorskip("yara")
    for path in (FRAMEWORK / "malware").glob("*/rules/*.yar"):
        if path.parent.parent.name in {"condi", "linux_ens_sns_bot", "chud_bot", "efimer", "wannacry"}:
            yara.compile(filepath=str(path))
