"""Winosの時刻・通信順・受信非実行境界を仮想時計とKali loopbackで検証する。"""

import importlib
import json
import socket
import struct
import sys
import threading
from pathlib import Path

import pytest

VALLEY = Path(__file__).resolve().parents[1] / "malware" / "valleyrat"
sys.path.insert(0, str(VALLEY))
LAB = importlib.import_module("winos_flow_lab")
PROFILE = "winos-ca01-x64-fixed-807361fe"


def response(session, payload=b"\xc9"):
    return LAB.build_frame(payload, session.header, cipher_mode=session.profile.cipher_mode)


@pytest.mark.parametrize("profile", [PROFILE, "winos-ca00-x86-4df8bda2", "winos-nvml-bootstrap-39b20658"])
def test_absolute_timing_and_cipher_binding(profile):
    session = LAB.FlowSession(profile, LAB.LabPolicy(), started_ms=50)
    assert session.advance(50) == response(session)
    assert session.advance(1049) is None
    assert session.advance(1050) == response(session)
    assert session.advance(2050) == response(session)
    assert session.advance(3050) is None
    assert session.closed
    assert [e["scheduled_ms"] for e in session.events if e["event"] == "heartbeat_due"] == [0, 1000, 2000]


def test_late_clock_does_not_create_a_burst_or_drift_future_deadline():
    session = LAB.FlowSession(PROFILE, LAB.LabPolicy(heartbeat_offsets_ms=(0, 100, 200, 500)))
    assert session.advance(250) is not None
    assert session.events[-1]["skipped_due_count"] == 2
    assert session.events[-1]["lateness_ms"] == 50
    assert session.advance(250) is None
    assert session.advance(500) is not None
    assert session.events[-1]["lateness_ms"] == 0


def test_fragmented_coalesced_commands_are_discarded_without_response():
    session = LAB.FlowSession(PROFILE, LAB.LabPolicy())
    challenge = response(session, b"\xc9\x01")
    unknown = response(session, b"\xfe" + b"DO-NOT-EXECUTE-SECRET")
    session.receive(challenge[:3], 10)
    session.receive(challenge[3:] + unknown + response(session), 30)
    events = [e for e in session.events if e["event"] == "frame_classified_and_discarded"]
    assert [e["command"] for e in events] == [0xC9, 0xFE, 0xC9]
    assert events[0]["first_fragment_ms"] == 10
    assert events[0]["elapsed_ms"] == 30
    assert not session.pending
    assert not session.closed
    assert all(not e["operation_executed"] and not e["reply_sent"] for e in events)
    assert "SECRET" not in json.dumps(session.events)
    assert not any(e["event"] == "heartbeat_due" for e in events)


@pytest.mark.parametrize("via_receive", [False, True])
def test_slow_drip_does_not_reset_partial_deadline(via_receive):
    session = LAB.FlowSession(PROFILE, LAB.LabPolicy(partial_frame_timeout_ms=100))
    frame = response(session)
    session.receive(frame[:1], 10)
    session.receive(frame[1:2], 70)
    if via_receive:
        session.receive(frame[2:], 110)
    else:
        assert session.advance(110) is None
    assert session.closed
    assert session.events[-1]["event"] == "partial_frame_timeout"
    assert not session.pending


def test_fragment_completion_before_deadline_is_accepted():
    session = LAB.FlowSession(PROFILE, LAB.LabPolicy(partial_frame_timeout_ms=100))
    frame = response(session)
    session.receive(frame[:1], 0)
    session.receive(frame[1:], 99)
    assert not session.closed
    assert session.advance(100) is not None


@pytest.mark.parametrize("length", [0, 14, 65537, 0xFFFFFFFF])
def test_length_bomb_stops_before_reading_body(length):
    session = LAB.FlowSession(PROFILE, LAB.LabPolicy())
    session.receive(struct.pack("<I", length), 1)
    assert session.closed and not session.pending
    assert session.events[-1]["event"] == "invalid_frame"


@pytest.mark.parametrize("policy", [
    {"maximum_received_frames": 1}, {"maximum_received_bytes": 15}, {"maximum_read_calls": 1},
])
def test_receive_limits_cannot_be_reset_by_commands(policy):
    session = LAB.FlowSession(PROFILE, LAB.LabPolicy(**policy))
    frame = response(session)
    session.receive(frame, 1)
    if not session.closed:
        session.receive(frame, 2)
    assert session.closed and not session.pending


@pytest.mark.parametrize("options", [
    {"duration_ms": True}, {"duration_ms": 28800001}, {"duration_ms": 0},
    {"heartbeat_offsets_ms": (1,)}, {"heartbeat_offsets_ms": (0, 0)},
    {"heartbeat_offsets_ms": (0, 10, 5)}, {"heartbeat_offsets_ms": (0, 3000)},
    {"heartbeat_offsets_ms": [0, 1]}, {"heartbeat_offsets_ms": (False,)},
    {"reconnect_delays_ms": (1, 1, 1, 1)}, {"reconnect_delays_ms": (0,)},
    {"partial_frame_timeout_ms": 0}, {"maximum_read_calls": 4097},
])
def test_bad_policy_is_rejected(options):
    with pytest.raises(ValueError):
        LAB.LabPolicy(**options)


def test_invalid_profile_and_clock_fail_closed():
    with pytest.raises(ValueError):
        LAB.FlowSession("automatic-detect", LAB.LabPolicy())
    session = LAB.FlowSession(PROFILE, LAB.LabPolicy())
    session.advance(5)
    with pytest.raises(ValueError):
        session.advance(4)
    with pytest.raises(ValueError):
        session.advance(float("nan"))
    session.close(10)
    with pytest.raises(ValueError):
        session.receive(response(session), 11)


def test_eight_hour_virtual_deadline_cannot_send_or_receive_after_expiry():
    session = LAB.FlowSession(PROFILE, LAB.LabPolicy(duration_ms=28800000, heartbeat_offsets_ms=(0, 28799999)))
    session.advance(0)
    assert session.advance(28800000) is None
    assert session.events[-1]["event"] == "deadline"
    assert session.received_frames == 0


def test_loopback_keeps_one_connection_and_never_executes_or_replies(monkeypatch):
    import subprocess

    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: pytest.fail("外部process実行は禁止"))
    received = bytearray()
    errors = []
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(2)
        port = listener.getsockname()[1]
        reference = LAB.FlowSession(PROFILE, LAB.LabPolicy())

        def peer():
            try:
                with listener.accept()[0] as connection:
                    connection.settimeout(2)
                    incoming = response(reference, b"\xc9\x01") + response(reference, b"\xfeSECRET")
                    connection.sendall(incoming[:2])
                    connection.sendall(incoming[2:])
                    while chunk := connection.recv(4096):
                        received.extend(chunk)
            except OSError as error:
                errors.append(error)

        worker = threading.Thread(target=peer, daemon=True)
        worker.start()
        result = LAB.run_loopback(PROFILE, port, LAB.LabPolicy(
            duration_ms=250, heartbeat_offsets_ms=(0, 50, 100)))
        worker.join(3)
    assert not worker.is_alive() and not errors
    assert bytes(received) == reference.heartbeat * 3
    assert len([e for e in result["events"] if e["event"] == "connect_attempt"]) == 1
    assert len([e for e in result["events"] if e["event"] == "frame_classified_and_discarded"]) == 2
    assert result["timing_basis"] == "synthetic_lab_policy_not_sample_derived"
    assert all(result["safety"][key] is False for key in (
        "external_network_contacted", "operation_executed", "registration_sent", "task_reply_sent"))
    assert "SECRET" not in json.dumps(result)
    kinds = [e["event"] for e in result["events"]]
    assert kinds.index("connected") < kinds.index("heartbeat_due") < kinds.index("heartbeat_sent")


def test_connection_refused_is_limited_to_initial_plus_three_retries():
    # bindしたままlistenしないportは、別processが再利用できず接続拒否になる。
    with socket.socket() as reserved:
        reserved.bind(("127.0.0.1", 0))
        result = LAB.run_loopback(PROFILE, reserved.getsockname()[1], LAB.LabPolicy(
            duration_ms=500, heartbeat_offsets_ms=(0,), reconnect_delays_ms=(1, 2, 3)))
    attempts = [e["attempt"] for e in result["events"] if e["event"] == "connect_attempt"]
    assert attempts == [0, 1, 2, 3]
    assert result["stop_reason"] == "retry_limit"
    assert not any(e["event"] == "heartbeat_sent" for e in result["events"])
