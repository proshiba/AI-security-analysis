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


def test_reassembly_stops_at_sequence_gap() -> None:
    first = "100000009f25590e00000000ca00d1d5"
    rows = [
        f"1|1|10.0.0.1|50000|121.127.253.206|8856|{first}",
        "1|100|10.0.0.1|50000|121.127.253.206|8856|41414141",
    ]
    streams = MODULE.reassemble_rows(rows)
    assert len(next(iter(streams.values()))) == 16
