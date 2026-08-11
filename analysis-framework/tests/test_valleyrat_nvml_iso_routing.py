"""ValleyRAT NVML compact DAT型ISOのhash非依存routing回帰テスト。"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


MODULE_PATH = Path(__file__).resolve().parents[1] / "malware" / "valleyrat" / "detect.py"
SPEC = importlib.util.spec_from_file_location("valleyrat_nvml_iso_detect", MODULE_PATH)
assert SPEC and SPEC.loader
DETECT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DETECT)


def _iso_record(name: bytes, extent: int, size: int, flags: int = 0) -> bytes:
    length = 33 + len(name) + (1 if len(name) % 2 == 0 else 0)
    record = bytearray(length)
    record[0] = length
    record[2:6] = extent.to_bytes(4, "little")
    record[10:14] = size.to_bytes(4, "little")
    record[25] = flags
    record[32] = len(name)
    record[33 : 33 + len(name)] = name
    return bytes(record)


def _iso_image(
    members: list[tuple[str, bytes]],
    *,
    corrupt_first_extent: bool = False,
) -> bytes:
    directory_sectors = max(1, (sum(40 + len(name) for name, _ in members) + 2047) // 2048)
    first_file_extent = 20 + directory_sectors
    image = bytearray((first_file_extent + len(members) + 2) * 2048)
    pvd = 16 * 2048
    image[pvd] = 1
    image[pvd + 1 : pvd + 6] = b"CD001"
    image[pvd + 6] = 1
    image[pvd + 40 : pvd + 48] = b"TEST-ISO"
    root = _iso_record(b"\x00", 20, directory_sectors * 2048, flags=2)
    image[pvd + 156 : pvd + 156 + len(root)] = root

    directory_start = 20 * 2048
    cursor = 0
    for index, (name, payload) in enumerate(members):
        raw_name = f"{name};1".encode("ascii")
        extent = first_file_extent + index
        if index == 0 and corrupt_first_extent:
            extent = len(image) // 2048 + 20
        record = _iso_record(raw_name, extent, len(payload))
        sector_offset = cursor % 2048
        if sector_offset + len(record) > 2048:
            cursor = ((cursor // 2048) + 1) * 2048
        image[directory_start + cursor : directory_start + cursor + len(record)] = record
        cursor += len(record)
        if extent * 2048 < len(image):
            start = extent * 2048
            image[start : start + len(payload)] = payload
    return bytes(image)


def _rc4(data: bytes, key: bytes) -> bytes:
    state = list(range(256))
    j = 0
    for i in range(256):
        j = (j + state[i] + key[i % len(key)]) & 0xFF
        state[i], state[j] = state[j], state[i]
    output = bytearray(data)
    i = j = 0
    for offset in range(len(output)):
        i = (i + 1) & 0xFF
        j = (j + state[i]) & 0xFF
        state[i], state[j] = state[j], state[i]
        output[offset] ^= state[(state[i] + state[j]) & 0xFF]
    return bytes(output)


def _nvml_dat() -> bytes:
    stage = bytearray(b"\x90" * 1_024)
    marker_offset = 0x200
    host1, host2 = b"192.0.2.10\0", b"198.51.100.20\0"
    header = bytearray(0x38)
    header[0:8] = b"codemark"
    header[0x20:0x24] = len(host1).to_bytes(4, "little")
    header[0x24:0x28] = (6_666).to_bytes(4, "little")
    header[0x28:0x2C] = (1).to_bytes(4, "little")
    header[0x2C:0x30] = len(host2).to_bytes(4, "little")
    header[0x30:0x34] = (7_777).to_bytes(4, "little")
    header[0x34:0x38] = (1).to_bytes(4, "little")
    stage[marker_offset : marker_offset + 0x38 + len(host1) + len(host2)] = (
        bytes(header) + host1 + host2
    )
    key = bytes(range(16))
    xor_a, xor_b, seed = 0x36, 0x79, len(stage)
    scattered = _rc4(bytes(stage), key)
    table = list(range(len(stage) // 4))
    state = seed ^ 0x5A5A5A5A
    for index in range(len(table) - 1, 0, -1):
        state = (state * 0x41C64E6D + 0x3039) & 0xFFFFFFFF
        swap_index = state % (index + 1)
        table[index], table[swap_index] = table[swap_index], table[index]
    transformed = bytearray(len(stage))
    for source, destination in enumerate(table):
        transformed[source * 4 : source * 4 + 4] = scattered[
            destination * 4 : destination * 4 + 4
        ]
    encrypted = bytes(((~(value ^ xor_a)) & 0xFF) ^ xor_b for value in transformed)
    return (
        encrypted
        + len(stage).to_bytes(4, "little")
        + bytes((xor_a, xor_b))
        + seed.to_bytes(4, "little")
        + key
    )


def _proxy_result() -> dict:
    return {
        "components": [
            {
                "name": "NVML.DLL",
                "sha256": "1" * 64,
                "proxy_type": "nvml_compact_dat_loader",
                "export_count": 9,
                "loader_markers": ["nvml.dat", "runtimebroker.exe"],
                "injection_or_decryption_apis": [
                    "QueueUserAPC",
                    "ReadFile",
                    "VirtualAlloc",
                    "VirtualProtect",
                ],
            }
        ],
        "sideload_edges": [
            {
                "host": "HOST.EXE",
                "loaded_library": "NVML.DLL",
                "child_proxy_type": "nvml_compact_dat_loader",
            }
        ],
        "structural_proxy_detected": True,
    }


def test_hash_independent_iso_structure_recovers_two_c2(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """未知hashでもhost・proxy・DAT・codemarkが揃えばhighで選択する。"""

    monkeypatch.setattr(DETECT, "analyze_signed_proxy_sideload", lambda *_args: _proxy_result())
    image = _iso_image(
        [("HOST.EXE", b"MZhost"), ("NVML.DLL", b"MZproxy"), ("NVML.DAT", _nvml_dat())]
    )
    result = DETECT.detect(image, Path("unknown.img"))

    assert result["matched"] is True
    assert result["campaigns"][0]["campaign_type"] == "signed_proxy_sideload"
    assert result["campaigns"][0]["confidence"] == "high"
    assert result["observations"]["nvml_dat"]["summary"]["codemark_config"]["endpoints"] == [
        "192.0.2.10:6666",
        "198.51.100.20:7777",
    ]


def test_iso_with_valid_trailer_but_unresolved_stage_is_medium(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """host edgeとproxyが強くてもcodemark未解決ならmediumへ留める。"""

    monkeypatch.setattr(DETECT, "analyze_signed_proxy_sideload", lambda *_args: _proxy_result())
    dat = bytearray(_nvml_dat())
    dat[-1] ^= 0xFF
    image = _iso_image(
        [("HOST.EXE", b"MZhost"), ("NVML.DLL", b"MZproxy"), ("NVML.DAT", bytes(dat))]
    )
    result = DETECT.detect(image, Path("unknown.img"))

    assert result["matched"] is True
    assert result["campaigns"][0]["confidence"] == "medium"
    assert result["observations"]["nvml_dat"]["status"] == "trailer_valid_stage_unresolved"


def test_missing_dat_and_ordinary_iso_are_not_attributed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """companion DAT欠落と一般ISOをValleyRATへ誤帰属しない。"""

    monkeypatch.setattr(DETECT, "analyze_signed_proxy_sideload", lambda *_args: _proxy_result())
    missing = DETECT.detect(
        _iso_image([("HOST.EXE", b"MZhost"), ("NVML.DLL", b"MZproxy")]),
        Path("missing.img"),
    )
    assert missing["matched"] is False

    monkeypatch.setattr(
        DETECT,
        "analyze_signed_proxy_sideload",
        lambda *_args: {
            "components": [],
            "sideload_edges": [],
            "structural_proxy_detected": False,
        },
    )
    ordinary = DETECT.detect(
        _iso_image([("README.TXT", b"ordinary documentation")]),
        Path("benign.iso"),
    )
    assert ordinary["matched"] is False


def test_malformed_iso_and_member_limit_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """境界外extentと件数上限超過ではproxy解析前に停止する。"""

    def must_not_run(*_args):
        raise AssertionError("invalid ISO must not reach proxy analyzer")

    monkeypatch.setattr(DETECT, "analyze_signed_proxy_sideload", must_not_run)
    malformed = DETECT.detect(
        _iso_image([("NVML.DAT", _nvml_dat())], corrupt_first_extent=True),
        Path("broken.img"),
    )
    assert malformed["matched"] is False
    assert malformed["observations"]["iso9660"]["status"] == "invalid_iso9660"

    too_many = DETECT.detect(
        _iso_image([(f"F{index:03}.BIN", b"x") for index in range(129)]),
        Path("too-many.iso"),
    )
    assert too_many["matched"] is False
    assert too_many["observations"]["iso9660"]["status"] == "member_limit_blocked"


def test_raw_dat_and_compact_proxy_layers_route_to_valleyrat(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """one-shot子layerのDATとcompact proxyも同じcampaignへ結合する。"""

    dat_result = DETECT.detect(_nvml_dat(), Path("NVML.DAT"))
    assert dat_result["matched"] is True
    assert dat_result["campaigns"][0]["confidence"] == "high"

    monkeypatch.setattr(DETECT, "analyze_signed_proxy_sideload", lambda *_args: _proxy_result())
    dll_result = DETECT.detect(b"MZproxy-fixture", Path("NVML.DLL"))
    assert dll_result["matched"] is True
    assert dll_result["campaigns"][0]["campaign_type"] == "signed_proxy_sideload"
