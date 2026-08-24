from __future__ import annotations

import importlib.util
from pathlib import Path
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
MODULE_ROOT = (
    ROOT
    / "malware"
    / "valleyrat"
    / "campaigns"
    / "signed_proxy_sideload"
)
sys.path.insert(0, str(MODULE_ROOT))
spec = importlib.util.spec_from_file_location("winos_pcap", MODULE_ROOT / "winos_pcap.py")
assert spec and spec.loader
MODULE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(MODULE)


def test_parse_endpoint_rejects_filter_injection() -> None:
    assert MODULE.parse_endpoint("121.127.253.206:8856") == ("121.127.253.206", 8856)
    with pytest.raises(ValueError):
        MODULE.parse_endpoint("121.127.253.206:8856 || tcp")


def test_reassemble_deduplicates_and_parses_stage_control() -> None:
    # 実観測と同形式のcommand 0x04フレーム。重複segmentは一度だけ採用する。
    payload = "100000009f25590e00000000ca00d1d5"
    row = f"48|1|10.127.0.82|49930|121.127.253.206|8856|{payload}"
    result = MODULE.analyze_rows(
        [row, row], [("121.127.253.206", 8856)]
    )
    stream = result["streams"][0]
    assert stream["direction"] == "client_to_server"
    assert stream["parsed_frame_count"] == 1
    assert stream["frames"][0]["command"] == 4
    assert stream["frames"][0]["role"] == "stage_channel_control"
    assert result["safety"]["pcap_replayed"] is False


def test_reassemble_parses_ca01_fixed_xor_stage_frames() -> None:
    # 2026-08-20検体のca01 mode。payloadは固定0xCCでXORされる。
    control = bytes([0x04])
    metadata = bytes([0x05]) + "登录模块.dll_bin".encode("utf-16le")
    header = bytes.fromhex("74af580e00000000ca01")

    def frame(payload: bytes) -> bytes:
        encrypted = bytes(value ^ 0xCC for value in payload)
        return (14 + len(payload)).to_bytes(4, "little") + header + encrypted

    stream = (frame(control) + frame(metadata)).hex()
    row = f"1|1|10.0.0.2|50001|170.62.130.47|449|{stream}"
    result = MODULE.analyze_rows([row], [("170.62.130.47", 449)])
    frames = result["streams"][0]["frames"]
    assert [item["command"] for item in frames] == [4, 5]
    assert frames[0]["role"] == "stage_channel_control"
    assert frames[1]["role"] == "stage_channel_metadata"


def test_reassembly_stops_at_sequence_gap() -> None:
    first = "100000009f25590e00000000ca00d1d5"
    rows = [
        f"1|1|10.0.0.1|50000|121.127.253.206|8856|{first}",
        "1|100|10.0.0.1|50000|121.127.253.206|8856|41414141",
    ]
    streams = MODULE.reassemble_rows(rows)
    assert len(next(iter(streams.values()))) == 16
