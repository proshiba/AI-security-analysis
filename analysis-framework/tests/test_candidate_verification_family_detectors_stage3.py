"""第3段candidate-only family detectorの高精度境界を検証する。"""

from __future__ import annotations

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
    "phorpiex_spam",
    "proxyrack_pop_deployer",
    "traffmonetizer_deployer",
    "condi",
    "chud_bot",
)
DEFERRED_REASONS = {
    "linux_ens_sns_bot": "既存READMEでreview済みprofileがJackSkidへ再帰属済みのため旧familyへ重複帰属しない",
    "sobfox_launcher": "exact hashと汎用NRV2E配置、build path由来の暫定名以外に独立family証拠がない",
}


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MODULES = {
    family: _load_module(
        FRAMEWORK / "malware" / family / "detect.py",
        f"candidate_stage3_detector_{family}",
    )
    for family in FAMILIES
}


def _pe(*markers: bytes, managed: bool = False, wide: bool = False) -> bytes:
    """検出境界に必要な最小PE headerへ静的markerを付加する。"""

    data = bytearray(0x200)
    data[:2] = b"MZ"
    data[0x3C:0x40] = (0x80).to_bytes(4, "little")
    data[0x80:0x84] = b"PE\0\0"
    data[0x84:0x86] = (0x14C).to_bytes(2, "little")
    data[0x86:0x88] = (3).to_bytes(2, "little")
    data[0x94:0x96] = (0xE0).to_bytes(2, "little")
    if managed:
        data.extend(b"BSJB\0")
    for marker in markers:
        data.extend(marker.decode("ascii").encode("utf-16le") if wide else marker)
        data.extend(b"\0\0" if wide else b"\0")
    return bytes(data)


def _elf(*markers: bytes) -> bytes:
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


PHORPIEX_KEY = b"Tmlr"
PHORPIEX_CIPHER = bytes.fromhex("b0acaca8e2f7f7e9efe0f6e9eef6ededf6eaece8f7")
PHORPIEX_CAMPAIGN = (
    b"I RECORDED YOU! 1QKNMjsLUuaS4hVDMzy4cWBhuaqz58xxCc 5235355"
)
PROXYRACK_PAYLOAD = (b"PoP_go.exe", b"proxyrack-pop-client", b"point-of-presence.sock.sh")
PROXYRACK_CONTEXT = (
    b"--homeIp",
    b"--homePort",
    b"DiagnosticsTrackMonitorService",
    b"C:\\Windows\\DiagTrack\\DiagTrack",
)
TRAFF_PAYLOAD = (b"tm_setup.exe", b"Traffmonetizer.exe")
TRAFF_CONTEXT = (
    b"DiagnosticsTrackMonitorService",
    b"C:\\Windows\\DiagTrack\\Globalization",
    b"Hiding all windows for process ID",
)
CONDI_CIPHER = bytes.fromhex("4849534a4640404053554b57484943580c4a4d52564d0c4d5045")
CONDI_MARKERS = (b"/tmp/condi", b"/var/condibot", b"zxcr9999")
CHUD_PROTOCOL = (b"CHUD-HANDSHAKE-V2", b"127.0.0.2")
CHUD_PERSISTENCE = (b"systemd", b"/etc/init.d", b"rc.common")

POSITIVE_FIXTURES = {
    "phorpiex_spam": _pe(
        PHORPIEX_KEY,
        PHORPIEX_KEY,
        PHORPIEX_CIPHER,
        PHORPIEX_CAMPAIGN,
    ),
    "proxyrack_pop_deployer": _pe(
        *PROXYRACK_PAYLOAD,
        *PROXYRACK_CONTEXT,
        managed=True,
        wide=True,
    ),
    "traffmonetizer_deployer": _pe(
        *TRAFF_PAYLOAD,
        *TRAFF_CONTEXT,
        managed=True,
        wide=True,
    ),
    "condi": _elf(CONDI_CIPHER, *CONDI_MARKERS),
    "chud_bot": _elf(*CHUD_PROTOCOL, *CHUD_PERSISTENCE),
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
    "phorpiex_spam": (
        PHORPIEX_KEY + PHORPIEX_KEY + PHORPIEX_CIPHER + PHORPIEX_CAMPAIGN,
        _pe(PHORPIEX_KEY, PHORPIEX_KEY, PHORPIEX_CIPHER),
        _pe(PHORPIEX_CAMPAIGN),
    ),
    "proxyrack_pop_deployer": (
        _pe(*PROXYRACK_PAYLOAD, managed=True, wide=True),
        _pe(*PROXYRACK_CONTEXT, managed=True, wide=True),
        _pe(*PROXYRACK_PAYLOAD, *PROXYRACK_CONTEXT, wide=True),
    ),
    "traffmonetizer_deployer": (
        _pe(*TRAFF_PAYLOAD, managed=True, wide=True),
        _pe(*TRAFF_CONTEXT, managed=True, wide=True),
        _pe(*TRAFF_PAYLOAD, *TRAFF_CONTEXT, wide=True),
    ),
    "condi": (
        b"\x7fELF" + CONDI_CIPHER + b"".join(CONDI_MARKERS),
        _elf(CONDI_CIPHER),
        _elf(*CONDI_MARKERS),
    ),
    "chud_bot": (
        b"\x7fELF" + b"".join(CHUD_PROTOCOL + CHUD_PERSISTENCE),
        _elf(*CHUD_PROTOCOL),
        _elf(*CHUD_PERSISTENCE),
    ),
}


@pytest.mark.parametrize(
    ("family", "sample"),
    [(family, sample) for family, samples in NEGATIVE_FIXTURES.items() for sample in samples],
)
def test_missing_axis_and_broken_format_are_rejected(family: str, sample: bytes) -> None:
    """一軸欠落、壊れたheader、managed metadata欠落を誤検出しない。"""

    result = MODULES[family].detect(sample, Path(f"{family}.bin"))
    assert result["matched"] is False
    assert result["campaigns"] == []


def test_mutated_condi_cipher_is_not_treated_as_valid_config() -> None:
    """1 byte改変したXOR blobをfamily設定として受理しない。"""

    mutated = bytearray(CONDI_CIPHER)
    mutated[-1] ^= 1
    result = MODULES["condi"].detect(
        _elf(bytes(mutated), *CONDI_MARKERS),
        Path("mutated.bin"),
    )
    assert result["matched"] is False
    assert result["observations"]["validated_xor_endpoint_profile_indexes"] == []


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


def test_registry_maps_added_families_and_omits_deferred_aliases() -> None:
    """追加対象だけをregistryへ登録し、根拠不足の旧分類を昇格しない。"""

    registry = json.loads(
        (FRAMEWORK / "registry" / "malware_types.json").read_text(encoding="utf-8")
    )["malware_types"]
    classifier = _load_module(
        FRAMEWORK / "classifiers" / "classify_sample.py",
        "candidate_stage3_classifier",
    )
    for family in FAMILIES:
        expected = f"malware/{family}/detect.py"
        assert registry[family]["detector"] == expected
        assert callable(classifier.load_detector(FRAMEWORK, expected, family))
    for family, reason in DEFERRED_REASONS.items():
        assert family not in registry
        assert not (FRAMEWORK / "malware" / family / "detect.py").exists()
        assert len(reason) >= 20


def test_detectors_ignore_filename_and_never_execute_or_contact_network() -> None:
    """filename labelを無視し、positiveでも非実行・非通信を明示する。"""

    for family, module in MODULES.items():
        negative = module.detect(b"generic packed payload", Path(f"{family}.bin"))
        assert negative["matched"] is False
        positive = module.detect(POSITIVE_FIXTURES[family], Path("unknown.bin"))
        observations = positive["observations"]
        assert observations["sample_executed"] is False
        assert observations["network_contacted"] is False
