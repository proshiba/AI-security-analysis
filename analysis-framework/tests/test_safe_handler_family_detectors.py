"""safe handler向けfamily detectorの保守的な境界を検証する。"""

from __future__ import annotations

import importlib.util
import struct
import sys
from pathlib import Path

import pytest


FRAMEWORK = Path(__file__).parents[1]
REPOSITORY = FRAMEWORK.parent
for import_root in (str(FRAMEWORK), str(REPOSITORY)):
    if import_root not in sys.path:
        sys.path.insert(0, import_root)

FAMILIES = (
    "amosstealer",
    "donutloader",
    "electron_payload_loader",
    "formbook",
    "lummastealer",
    "nanocore",
    "remusstealer",
)


def _load_detector(family: str):
    detector_path = FRAMEWORK / "malware" / family / "detect.py"
    spec = importlib.util.spec_from_file_location(f"safe_handler_detector_{family}", detector_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.detect


DETECTORS = {family: _load_detector(family) for family in FAMILIES}


def _pe(*markers: str, managed: bool = False, wide: bool = False) -> bytes:
    """検出器境界に必要な最小PE headerと静的literalだけを組み立てる。"""

    data = bytearray(0x200)
    data[:2] = b"MZ"
    data[0x3C:0x40] = (0x80).to_bytes(4, "little")
    data[0x80:0x84] = b"PE\0\0"
    data[0x84:0x86] = (0x14C).to_bytes(2, "little")
    data[0x86:0x88] = (3).to_bytes(2, "little")
    data[0x94:0x96] = (0xE0).to_bytes(2, "little")
    if managed:
        data.extend(b"BSJB\0")
    encoder = "utf-16le" if wide else "ascii"
    for marker in markers:
        data.extend(marker.encode(encoder))
        data.extend(b"\0\0" if wide else b"\0")
    return bytes(data)


def _donut_fixture() -> bytes:
    """復号後instanceまで検証できる最小Donut shellcodeを生成する。"""

    payload = b"MZterminal"
    module = bytearray(1320 + len(payload))
    struct.pack_into("<III", module, 0, 2, 0, 1)
    module[12:22] = b"v4.0.30319"
    struct.pack_into("<II", module, 1312, len(payload), len(payload))
    module[1320:] = payload
    instance = bytearray(0xDB0 + len(module))
    struct.pack_into("<I", instance, 0x234, 0)
    struct.pack_into("<I", instance, 0x290, 3)
    instance[0x294:0x2A0] = b"ole32;wininet"
    struct.pack_into("<I", instance, 0x974, 2)
    struct.pack_into("<Q", instance, 0xDA8, len(module))
    instance[0xDB0:] = module
    return b"\xe8" + struct.pack("<I", len(instance)) + instance + b"YU\x48\x89\xe5"


POSITIVE_FIXTURES = {
    "amosstealer": (
        b"\xcf\xfa\xed\xfe"
        + b"\0" * 32
        + b"keychain Login Data Cookies Electrum "
        + b"https://example.invalid/ledger/"
        + b"a" * 64
        + b" "
    ),
    "donutloader": _donut_fixture(),
    "electron_payload_loader": (
        b"const e=require('electron'); const c=require('child_process'); c.exec('fixture'); "
        b"TG_TOKEN TG_CHAT_ID PAYLOADS api.ipify.org ProgramData Add-MpPreference -ExclusionPath"
    ),
    "formbook": _pe(
        "FormBook",
        "NtSetContextThread",
        "GetThreadContext",
        "Login Data",
        "Thunderbird",
    ),
    "lummastealer": _pe(
        "LummaC2",
        "build_id",
        "hwid",
        "Login Data",
        "Local State",
        "MetaMask",
    ),
    "nanocore": _pe(
        "NanoCore.ClientPlugin.IClientNetwork",
        "PrimaryConnectionHost",
        "ConnectionPort",
        managed=True,
        wide=True,
    ),
    "remusstealer": _pe(
        "RemusStealer",
        "Login Data",
        "Local State",
        "wallet.dat",
    ),
}


@pytest.mark.parametrize("family", FAMILIES)
def test_positive_fixture_matches_only_its_intended_family(family: str) -> None:
    """内部構造を相関したfixtureだけが意図したfamilyへ帰属する。"""

    sample = POSITIVE_FIXTURES[family]
    matches = {
        candidate
        for candidate, detector in DETECTORS.items()
        if detector(sample, Path("fixture"))["matched"]
    }
    assert matches == {family}


NEGATIVE_FIXTURES = {
    "amosstealer": (
        b"\xcf\xfa\xed\xfe" + b"\0" * 32 + b"keychain Login Data Cookies Electrum",
        b"keychain Login Data Cookies Electrum https://x.invalid/ledger/" + b"a" * 64,
    ),
    "donutloader": (
        b"\xe8" + struct.pack("<I", 0x300) + bytes(0x300) + b"YU\x48\x89\xe5",
        bytes(range(256)) * 8,
    ),
    "electron_payload_loader": (
        b"require('electron'); require('child_process'); exec('x'); api.ipify.org ProgramData createHash",
        b"TG_TOKEN TG_CHAT_ID PAYLOADS api.ipify.org ProgramData Add-MpPreference -ExclusionPath",
    ),
    "formbook": (
        _pe("NtSetContextThread", "GetThreadContext", "Login Data", "Thunderbird"),
        _pe("FormBook", "NtSetContextThread", "GetThreadContext", "Login Data"),
    ),
    "lummastealer": (
        _pe("LummaC2", "build_id", "hwid", "Login Data", "Local State"),
        _pe("build_id", "hwid", "Login Data", "Local State", "MetaMask"),
    ),
    "nanocore": (
        _pe("PrimaryConnectionHost", "BackupConnectionHost", "ConnectionPort", managed=True),
        _pe("NanoCore.ClientPlugin.IClientNetwork", "PrimaryConnectionHost", "ConnectionPort"),
    ),
    "remusstealer": (
        _pe("RemusStealer", "Login Data", "Local State"),
        _pe("Login Data", "Local State", "wallet.dat"),
    ),
}


@pytest.mark.parametrize(
    ("family", "sample"),
    [(family, sample) for family, samples in NEGATIVE_FIXTURES.items() for sample in samples],
)
def test_single_axis_and_generic_lookalikes_are_rejected(family: str, sample: bytes) -> None:
    """format、family名、一般的機能の一軸だけでは一致させない。"""

    result = DETECTORS[family](sample, Path("misleading-family-name.bin"))
    assert result["matched"] is False
    assert result["campaigns"] == []


def test_generic_packer_traits_do_not_attribute_any_family() -> None:
    """一般的なpacker／injection特徴を特定familyへ昇格させない。"""

    sample = _pe(
        "UPX0",
        "UPX1",
        "VirtualAlloc",
        "WriteProcessMemory",
        "GetProcAddress",
        "LoadLibraryA",
    )
    assert not any(detector(sample, Path("amosstealer.exe"))["matched"] for detector in DETECTORS.values())


def test_detectors_are_bounded_and_never_execute_or_contact_network() -> None:
    """上限超過入力は探索せず、観測値も非実行・非通信を保つ。"""

    for family, detector in DETECTORS.items():
        result = detector(b"A" * (33 * 1024 * 1024), Path(f"{family}.bin"))
        assert result == {
            "matched": False,
            "observations": {"input_within_limit": False},
            "campaigns": [],
        }
