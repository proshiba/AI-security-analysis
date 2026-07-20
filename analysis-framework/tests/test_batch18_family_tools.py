from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import struct

import pytest


ROOT = Path(__file__).resolve().parents[2]


def load(relative: str, name: str):
    path = ROOT / relative
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_javascript_unicode_separator_reconstruction_and_detection_profiles() -> None:
    module = load(
        "analysis-framework/malware/windows_script_stager/javascript_unicode_separator_stager.py",
        "b18_js_stager",
    )
    clean = "Write-Output synthetic-offline"
    separator = "◇区切り◇"
    fragments = [part + (separator if index < 14 else "") for index, part in enumerate([
        clean[:1], clean[1:2], clean[2:3], clean[3:4], clean[4:5],
        clean[5:6], clean[6:7], clean[7:8], clean[8:9], clean[9:10],
        clean[10:11], clean[11:12], clean[12:13], clean[13:14], clean[14:],
    ])]
    lines = ['var synthetic = "";']
    lines.extend(f"synthetic += {json.dumps(fragment, ensure_ascii=False)};" for fragment in fragments)
    lines.append(f"synthetic=synthetic.split({json.dumps(separator, ensure_ascii=False)}).join(\"\");")
    restored, evidence = module.reconstruct(
        "\n".join(lines),
        "synthetic",
        hashlib.sha256(clean.encode()).hexdigest(),
    )
    assert restored == clean
    assert evidence["fragment_count"] == 15
    detector = load("analysis-framework/malware/windows_script_stager/detect.py", "b18_script_detector")
    assert set(module.PROFILES) <= detector.REVIEWED
    network = load(
        "analysis-framework/malware/windows_script_stager/network_detector.py",
        "b18_script_network",
    )
    report = network.detect_events([{
        "host": "misty-cherry-cea3.uploadsimg.workers.dev",
        "path": "/iFBWg",
        "method": "GET",
        "wscript_or_powershell_parent": True,
    }])
    assert report["matched"] is True
    assert report["c2_confirmed"] is False


def test_macos_build_info_parser_and_emulator_are_offline() -> None:
    extractor = load("analysis-framework/malware/macos_stealer_v2/extract_config.py", "b18_macos_extract")

    def sized(value: str) -> bytes:
        raw = value.encode()
        return len(raw).to_bytes(2, "little") + raw

    plaintext = struct.pack("<II", 131, 256) + sized("Vozeyuy")
    urls = ["https://fewfwfwfwfwf.info", "http://196.251.107.171:3000"]
    plaintext += len(urls).to_bytes(2, "little") + b"".join(map(sized, urls))
    extensions = ["pdf", "txt", "rtf"]
    plaintext += len(extensions).to_bytes(2, "little") + b"".join(map(sized, extensions))
    plaintext += (0).to_bytes(2, "little")
    plaintext += b"".join(map(sized, [
        "System  Preferences",
        "You need to configure system settings before running  application.\n\nPlease enter  password.",
        "System  Preferences",
        "Your Mac does not support  application. Try reinstalling or downloading version for your  system.",
    ]))
    plaintext += bytes([1, 1, 1, 0, 1, 1, 0, 0])
    assert hashlib.sha256(plaintext).hexdigest() == extractor.PLAINTEXT_SHA256
    parsed = extractor.parse_plaintext(plaintext)
    assert parsed["campaign"] == "Vozeyuy"
    assert parsed["target_extensions"] == extensions
    emulator = load("analysis-framework/malware/macos_stealer_v2/emulator.py", "b18_macos_emulator")
    assert emulator.emulate_synthetic(b"synthetic-build-info")["round_trip"] is True
    detector = load("analysis-framework/malware/macos_stealer_v2/network_detector.py", "b18_macos_network")
    report = detector.detect([
        {"host": "196.251.107.171", "port": 3000},
        {"fake_system_preferences_dialog": True},
    ])
    assert report["matched"] is True
    assert report["c2_confirmed"] is False


def _synthetic_bmp_2x2() -> bytes:
    top = [(1, 2, 3), (4, 5, 6)]
    bottom = [(7, 8, 9), (10, 11, 12)]
    pixels = bytearray()
    for row in (bottom, top):
        for red, green, blue in row:
            pixels.extend((blue, green, red, 255))
    file_size = 54 + len(pixels)
    header = bytearray(b"BM")
    header.extend(struct.pack("<IHHI", file_size, 0, 0, 54))
    header.extend(struct.pack("<IiiHHIIiiII", 40, 2, 2, 1, 32, 0, len(pixels), 0, 0, 0, 0))
    return bytes(header + pixels)


def test_dotnet_bitmap_decoder_emulator_and_negative_c2_model() -> None:
    loader = load(
        "analysis-framework/malware/dotnet_resource_loader/bitmap_stego_loader.py",
        "b18_bitmap_loader",
    )
    child, metadata = loader.decode_bmp_rgb(_synthetic_bmp_2x2(), expected_dimensions=(2, 2))
    assert child == bytes([1, 2, 3, 7, 8, 9, 4, 5, 6, 10, 11, 12])
    assert metadata["bits_per_pixel"] == 32
    emulator = load(
        "analysis-framework/malware/dotnet_resource_loader/bitmap_stego_emulator.py",
        "b18_bitmap_emulator",
    )
    modeled = emulator.emulate(123, 122)
    assert modeled["modeled_output_size"] == 45018
    assert modeled["assembly_loaded"] is False
    network = load(
        "analysis-framework/malware/dotnet_resource_loader/bitmap_network_detector.py",
        "b18_bitmap_network",
    )
    report = network.detect([])
    assert report["matched"] is False
    assert report["c2_confirmed"] is False
    assert set(loader.PROFILES) == {
        "b393bd767c142e171dd1b2928bae16fff2f63b3d319b2c1acb37129d8d538cc9",
        "4d033b83aec65390c6d90f9d87224fddd3bcd568cf490d9dc02bbb0f7db0d58f",
    }


def test_puta_mips_profiles_keep_loopback_separate_from_external_c2() -> None:
    extractor = load("analysis-framework/malware/putita_v3/extract_config.py", "b18_puta_extract")
    unpacked = "714f761f1994d2c647aa8feeee06272f5ede71dc704842d9bee2141fa94c22a8"
    packed = "e88bf785ff3ee84df31a16ce5b6f9ecfc38cce7e5c01bdfb2dcdca21f33dbbf0"
    arm = "ff5a682bad6c911fd08c90622b7fa13ab22a608e501eed511a40fe43a9b53a1e"
    assert extractor.HASH_PROFILES[unpacked]["controller"] == ("127.0.0.2", 23)
    assert extractor.HASH_PROFILES[packed]["unpacked_sha256"] == unpacked
    assert extractor.HASH_PROFILES[arm]["architecture"] == "armv5"
    assert extractor.HASH_PROFILES[arm]["ghidra"]["main_address"] == "0x00010618"
    network = load("analysis-framework/malware/putita_v3/network_detector.py", "b18_puta_network")
    report = network.detect([{
        "host": "127.0.0.2",
        "port": 23,
        "puta_v3_authenticated_frame": True,
    }])
    assert report["matched"] is True
    assert report["controller_role"] == "loopback_controller"
    assert report["external_c2_confirmed"] is False


def test_efimer_batch18_reviewed_hashes_are_registered() -> None:
    detector = load("analysis-framework/malware/efimer/detect.py", "b18_efimer_detector")
    assert detector.KNOWN == {
        "39ec954d66b2484f72787a62cc472fc1c8cf95042c2dae1e045f972731ee51e2",
        "2c8bc292d127ec5fb5da2a9c8cbb8e4ec911f6b62437cb5f3a082ac196dc5784",
    }


def test_batch18_yara_rules_compile() -> None:
    yara = pytest.importorskip("yara")
    for relative in (
        "analysis-framework/malware/windows_script_stager/rules/javascript_unicode_separator_stager.yar",
        "analysis-framework/malware/macos_stealer_v2/rules/macos_stealer_v2.yar",
        "analysis-framework/malware/dotnet_resource_loader/rules/bitmap_stego_loader.yar",
        "analysis-framework/malware/putita_v3/rules/putita_v3.yar",
        "analysis-framework/malware/efimer/rules/efimer_batch18.yar",
    ):
        yara.compile(filepath=str(ROOT / relative))
