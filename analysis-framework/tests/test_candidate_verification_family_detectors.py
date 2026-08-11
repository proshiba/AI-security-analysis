"""candidate verification限定family detectorの高精度境界を検証する。"""

from __future__ import annotations

import importlib.util
import itertools
import json
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
    "pony",
    "vidar",
    "wannacry",
    "xmrig",
    "credential_phishing_html",
)


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MODULES = {
    family: _load_module(
        FRAMEWORK / "malware" / family / "detect.py",
        f"candidate_verification_detector_{family}",
    )
    for family in FAMILIES
}


def _pe(*markers: bytes) -> bytes:
    """検出境界に必要な最小PE headerへ任意の静的markerを付加する。"""

    data = bytearray(0x200)
    data[:2] = b"MZ"
    data[0x3C:0x40] = (0x80).to_bytes(4, "little")
    data[0x80:0x84] = b"PE\0\0"
    data[0x84:0x86] = (0x14C).to_bytes(2, "little")
    data[0x86:0x88] = (3).to_bytes(2, "little")
    data[0x94:0x96] = (0xE0).to_bytes(2, "little")
    for marker in markers:
        data.extend(marker)
        data.append(0)
    return bytes(data)


def _elf(*markers: bytes) -> bytes:
    """整合する64-bit little-endian ELF headerを組み立てる。"""

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
    return ident + header + b"\0".join(markers)


def _vidar_blob(*, metadata: bool = True, artifacts: bool = True) -> bytes:
    """反復XOR fieldを持つ最小Vidar設定fixtureを作る。"""

    key = b"0123456789abcdef"
    blob = bytearray(0x072 + 0x243 * 2)
    blob[:16] = key

    def store(base: int, value_offset: int, length_offset: int, value: bytes) -> None:
        blob[base + length_offset] = len(value)
        encrypted = bytes(left ^ right for left, right in zip(value, itertools.cycle(key)))
        blob[base + value_offset : base + value_offset + len(value)] = encrypted

    store(0, 0x010, 0x030, b"1.8")
    store(0, 0x031, 0x071, b"fixture")
    store(0x072, 0, 0x100, b"https://198.51.100.4/gate")
    if metadata:
        store(0x072, 0x101, 0x141, b"tag")
        store(0x072, 0x142, 0x242, b"FixtureAgent/1")
    suffix = b" information.txt passwords.txt wallets" if artifacts else b""
    return bytes(blob) + suffix


PONY_POST = (
    b"Content-Encoding: binary\r\n"
    b"User-Agent: Mozilla/4.0 (compatible; MSIE 5.0; Windows 98)"
)
PONY_PUSH_RET = b"\x55\x8b\xec\x5d\x68\x11\x22\x40\x00\xf8\x72\x01\xc3"
WANNACRY_KILL = b"iuqerfsodp9ifjaposdfjhgosurijfaewrwergwff.com"
PHISHING_ACTION = "https://smartforms.dev/submit/6a5ac8f0c184545ccc22c342"

POSITIVE_FIXTURES = {
    "pony": _pe(
        b"YUIPWDFILE0 YUIPKDFILE0 Client Hash STATUS-IMPORT-OK",
        PONY_POST,
        PONY_PUSH_RET,
    ),
    "vidar": _vidar_blob(),
    "wannacry": _pe(
        b"PlayGame mssecsvc2.1 tasksche.exe",
        WANNACRY_KILL,
    ),
    "xmrig": _elf(
        b"XMRIG_VERSION",
        b"XMRig",
        b"RandomX",
        b"stratum+ssl",
    ),
    "credential_phishing_html": (
        f"<!doctype html><html><title>Microsoft Sign in</title>"
        f"<form method='post' action='{PHISHING_ACTION}'>"
        "<input name='email'><input name='password' type='password'>"
        "</form></html>"
    ).encode(),
}


@pytest.mark.parametrize("family", FAMILIES)
def test_positive_fixture_matches_only_intended_family(family: str) -> None:
    """複数の内部証拠軸が揃うfixtureだけを意図したfamilyへ帰属する。"""

    sample = POSITIVE_FIXTURES[family]
    matches = {
        candidate
        for candidate, module in MODULES.items()
        if module.detect(sample, Path("misleading-name.bin"))["matched"]
    }
    assert matches == {family}


NEGATIVE_FIXTURES = {
    "pony": (
        b"YUIPWDFILE0 YUIPKDFILE0 Client Hash STATUS-IMPORT-OK" + PONY_POST + PONY_PUSH_RET,
        _pe(b"YUIPWDFILE0 YUIPKDFILE0 Client Hash STATUS-IMPORT-OK", PONY_POST),
    ),
    "vidar": (
        b"information.txt passwords.txt wallets Vidar",
        _vidar_blob(metadata=False),
    ),
    "wannacry": (
        b"PlayGame mssecsvc2.1 tasksche.exe " + WANNACRY_KILL,
        _pe(b"PlayGame mssecsvc2.1 tasksche.exe"),
    ),
    "xmrig": (
        b"\x7fELF XMRIG_VERSION XMRig RandomX stratum+ssl",
        _elf(b"XMRIG_VERSION", b"XMRig", b"RandomX"),
        _elf(b"RandomX", b"stratum+tcp", b"donate.ssl.xmrig.com"),
    ),
    "credential_phishing_html": (
        (
            f"<html>Microsoft<form method='post' action='{PHISHING_ACTION}'>"
            "<input type='password'></form></html>"
        ).encode().replace(b"Microsoft", b"generic"),
        (
            "<html>Microsoft Sign in<form method='post' action='https://login.example.invalid/'>"
            "<input type='password'></form></html>"
        ).encode(),
        (
            f"<html>Microsoft Sign in<form method='post' action='{PHISHING_ACTION}'>"
            "<input type='password'>"
        ).encode(),
    ),
}


@pytest.mark.parametrize(
    ("family", "sample"),
    [(family, sample) for family, samples in NEGATIVE_FIXTURES.items() for sample in samples],
)
def test_missing_axis_and_broken_structure_are_rejected(family: str, sample: bytes) -> None:
    """一軸欠落、壊れたheader、未完了formを誤検出しない。"""

    result = MODULES[family].detect(sample, Path(f"{family}.bin"))
    assert result["matched"] is False
    assert result["campaigns"] == []


def test_vidar_complete_config_does_not_require_output_artifact_names() -> None:
    """取得済みメモリは完全な暗号化設定だけでVidar候補を検証できる。"""

    result = MODULES["vidar"].detect(
        _vidar_blob(artifacts=False),
        Path("vidar-memory.bin"),
    )
    assert result["matched"] is True
    assert result["observations"]["repeated_xor_config_valid"] is True
    assert result["observations"]["output_artifact_hits"] == []


def test_invalid_phishing_action_port_is_rejected_without_exception() -> None:
    """不正portを持つactionでもparserから例外を漏らさない。"""

    sample = (
        "<html>Microsoft Sign in<form method='post' "
        "action='https://smartforms.dev:999999/submit/6a5ac8f0c184545ccc22c342'>"
        "<input type='password'></form></html>"
    ).encode()
    result = MODULES["credential_phishing_html"].detect(sample, Path("broken.html"))
    assert result["matched"] is False


def test_phishing_tag_limit_fails_closed() -> None:
    """小容量でも過剰tagを持つHTMLは上限到達時点でfail closedにする。"""

    form = POSITIVE_FIXTURES["credential_phishing_html"]
    sample = form + b"<div></div>" * 4097
    result = MODULES["credential_phishing_html"].detect(sample, Path("tag-bomb.html"))
    assert result["matched"] is False
    assert result["observations"]["tag_limit_exceeded"] is True
    assert result["observations"]["parsed_tag_count"] == 4097


@pytest.mark.parametrize("family", FAMILIES)
def test_oversize_input_is_rejected_before_family_scan(family: str) -> None:
    """familyごとの上限を1 byte超えた入力を解析しない。"""

    module = MODULES[family]
    sample = b"A" * (module.MAX_INPUT_BYTES + 1)
    assert module.detect(sample, Path("oversize.bin")) == {
        "matched": False,
        "observations": {"input_within_limit": False},
        "campaigns": [],
    }


def test_registry_maps_each_family_to_its_bounded_detector() -> None:
    """registryがfamily配下の正確なdetector pathだけを参照する。"""

    registry = json.loads(
        (FRAMEWORK / "registry" / "malware_types.json").read_text(encoding="utf-8")
    )["malware_types"]
    classifier = _load_module(
        FRAMEWORK / "classifiers" / "classify_sample.py",
        "candidate_verification_classifier",
    )
    for family in FAMILIES:
        expected = f"malware/{family}/detect.py"
        assert registry[family]["detector"] == expected
        assert callable(classifier.load_detector(FRAMEWORK, expected, family))


def test_detectors_do_not_use_filename_execute_or_contact_network() -> None:
    """filename labelを無視し、positiveでも非実行・非通信を明示する。"""

    for family, module in MODULES.items():
        negative = module.detect(b"MZ generic packed payload", Path(f"{family}.exe"))
        assert negative["matched"] is False
        positive = module.detect(POSITIVE_FIXTURES[family], Path("unknown.bin"))
        observations = positive["observations"]
        assert observations["sample_executed"] is False
        assert observations["network_contacted"] is False
