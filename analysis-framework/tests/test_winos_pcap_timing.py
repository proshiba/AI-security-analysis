"""分割frameの先頭到着時刻を、受信完了やmalware timerと混同しない。"""

import importlib
import sys
from pathlib import Path

import pytest

DIRECTORY = Path(__file__).resolve().parents[1] / "malware/valleyrat/campaigns/signed_proxy_sideload"
sys.path.insert(0, str(DIRECTORY))
PCAP = importlib.import_module("winos_pcap")
PROTOCOL = importlib.import_module("winos_protocol")
FRAME = PROTOCOL.build_frame(b"\xc9", bytes.fromhex("3800000000000000ca01"))


def row(timestamp, sequence, payload):
    return f"{timestamp}|1|{sequence}|192.0.2.1|50000|192.0.2.2|6666|{payload.hex()}"


def timing(rows):
    return PCAP.analyze_rows(rows, [("192.0.2.2", 6666)])["events"][0]["timing"]


def test_split_frame_completion_is_latest_fragment_not_header_time():
    result = timing([row("100.0", 1, FRAME[:4]), row("100.2", 5, FRAME[4:])])
    assert result["first_fragment_timestamp_epoch"] == 100
    assert result["frame_complete_timestamp_epoch"] == 100.2
    assert abs(result["fragment_span_seconds"] - 0.2) < 1e-10
    assert result["contributing_segment_count"] == 2
    assert result["timestamps_complete"] is True


def test_out_of_order_arrival_uses_latest_time_not_last_sequence():
    result = timing([row("100.2", 1, FRAME[:4]), row("100.0", 5, FRAME[4:])])
    assert result["frame_complete_timestamp_epoch"] == 100.2
    assert result["first_fragment_timestamp_epoch"] == 100


@pytest.mark.parametrize("missing", ["", "NaN", "Infinity"])
def test_unknown_timestamps_do_not_become_zero_or_a_timer(missing):
    result = timing([row("100.0", 1, FRAME[:4]), row(missing, 5, FRAME[4:])])
    assert result["timestamps_complete"] is False
    assert result["frame_complete_timestamp_epoch"] is None
    assert result["fragment_span_seconds"] is None


def test_coalesced_frames_share_capture_time_without_invented_delay():
    events = PCAP.analyze_rows([row("100.0", 1, FRAME * 2)], [("192.0.2.2", 6666)])["events"]
    assert len(events) == 2
    assert all(e["timing"]["frame_complete_timestamp_epoch"] == 100 for e in events)
    assert all(e["timing"]["fragment_span_seconds"] == 0 for e in events)


def test_duplicate_retransmission_does_not_create_an_extra_heartbeat():
    rows = [row("100.0", 1, FRAME), row("101.0", 1, FRAME)]
    events = PCAP.analyze_rows(rows, [("192.0.2.2", 6666)])["events"]
    assert len(events) == 1
    assert events[0]["timing"]["frame_complete_timestamp_epoch"] == 100
