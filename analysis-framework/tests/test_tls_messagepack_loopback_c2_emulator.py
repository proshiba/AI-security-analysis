"""AsyncRAT／VenomRAT application-layer loopback C2 fixtureを検証する。"""

from __future__ import annotations

import importlib
import queue
import socket
import sys
import threading
from pathlib import Path
from typing import Any

import pytest

COMMON = Path(__file__).parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

HOST = importlib.import_module("tls_messagepack_rat_host_emulator")
LOOPBACK = importlib.import_module("tls_messagepack_loopback_c2_emulator")


def _start_server(profile_id: str) -> tuple[threading.Thread, queue.Queue[int], list[dict[str, Any]]]:
    ready: queue.Queue[int] = queue.Queue(maxsize=1)
    results: list[dict[str, Any]] = []

    def worker() -> None:
        results.append(
            LOOPBACK.serve_once(
                profile_id,
                timeout_seconds=2.0,
                ready_callback=ready.put,
            )
        )

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    return thread, ready, results


@pytest.mark.parametrize(
    "profile_id",
    [HOST.ASYNC_PROFILE_ID, HOST.VENOM_PROFILE_ID],
)
def test_host_emulator_and_loopback_c2_complete_one_heartbeat(
    profile_id: str,
) -> None:
    thread, ready, server_results = _start_server(profile_id)
    port = ready.get(timeout=2.0)
    with socket.create_connection(("127.0.0.1", port), timeout=2.0) as stream:
        host_result = HOST.run_host_session(
            stream,
            profile_id,
            allow_registration=True,
            allow_heartbeat_request=True,
        )
    thread.join(timeout=2.0)

    assert thread.is_alive() is False
    assert host_result["status"] == "heartbeat_response_observed"
    assert host_result["command"]["packet_kind"] == "heartbeat"
    assert host_result["command"]["should_respond"] is False
    assert host_result["safety"]["arbitrary_fake_result_sent"] is False
    assert len(server_results) == 1
    server = server_results[0]
    assert server["status"] == "reviewed_heartbeat_response_sent"
    assert server["registration_exact"] is True
    assert server["ping_exact"] is True
    assert server["received_frame_count"] == 2
    assert server["safety"]["task_sent"] is False
    assert server["safety"]["arbitrary_result_sent"] is False
    assert server["safety"]["operation_executed"] is False


def test_ping_mismatch_receives_no_response() -> None:
    thread, ready, server_results = _start_server(HOST.ASYNC_PROFILE_ID)
    port = ready.get(timeout=2.0)
    with socket.create_connection(("127.0.0.1", port), timeout=2.0) as stream:
        stream.sendall(
            HOST.encode_frame(
                HOST.build_synthetic_client_info(HOST.ASYNC_PROFILE_ID)
            )
        )
        stream.sendall(HOST.encode_frame({"Packet": "plugin", "Message": ""}))
        stream.shutdown(socket.SHUT_WR)
        assert stream.recv(1) == b""
    thread.join(timeout=2.0)

    assert thread.is_alive() is False
    assert server_results[0]["status"] == "ping_mismatch_no_response"
    assert server_results[0]["response"] is None
    assert server_results[0]["safety"]["raw_frame_retained"] is False


@pytest.mark.parametrize("bind", ["192.0.2.1", "localhost", "0.0.0.0"])
def test_non_numeric_or_non_loopback_bind_is_rejected_before_socket(bind: str) -> None:
    with pytest.raises(LOOPBACK.LoopbackC2EmulatorError, match="loopback"):
        LOOPBACK.serve_once(HOST.ASYNC_PROFILE_ID, bind=bind)


def test_abstract_operation_result_stays_metadata_only() -> None:
    for profile_id, opcode in (
        (HOST.ASYNC_PROFILE_ID, "plugin"),
        (HOST.VENOM_PROFILE_ID, "runningapp"),
    ):
        decision = HOST.synthetic_result_decision(
            profile_id,
            opcode,
            "not_executed",
        )
        assert decision["wire_bytes"] is None
        assert decision["send_allowed"] is False
        assert decision["operation_executed"] is False
        assert decision["real_effect_performed"] is False
        assert decision["arbitrary_fake_result_sent"] is False
