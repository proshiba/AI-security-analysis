"""vvaS loopback facadeのheader-only契約を検証する。"""

from __future__ import annotations

import socket
import threading
import time

import pytest

from emulators.valleyrat import vvas_client, vvas_loopback_emulator


def test_exact_checkin_can_build_header_only_fixture() -> None:
    decision = vvas_loopback_emulator.synthetic_response_decision(
        b"32\x00",
        allow_header_only=True,
    ).to_dict()
    response = vvas_loopback_emulator.build_synthetic_response(
        b"32\x00",
        allow_header_only=True,
    )

    assert decision["checkin_valid"] is True
    assert decision["send_allowed"] is True
    assert decision["response_kind"] == "synthetic_stage_header_only"
    assert decision["stage_body_bytes"] == 0
    assert len(response) == 14
    parsed = vvas_client.parse_vvas_header(response, 307214, 14)
    assert parsed["header_matches"] is True
    assert len(response[14:]) == 0


def test_header_only_requires_explicit_flag_and_exact_checkin() -> None:
    assert vvas_loopback_emulator.build_synthetic_response(b"32\x00") == b""
    assert (
        vvas_loopback_emulator.build_synthetic_response(
            b"31\x00",
            allow_header_only=True,
        )
        == b""
    )


def test_task_result_is_abstract_and_never_serialized() -> None:
    result = vvas_loopback_emulator.synthetic_task_result_decision(
        outcome="no_output"
    ).to_dict()

    assert result["outcome"] == "no_output"
    assert result["send_allowed"] is False
    assert result["wire_schema_status"] == "terminal_stage_and_operator_protocol_unrecovered"
    assert result["wire_bytes"] is None
    assert result["operation_executed"] is False
    assert vvas_loopback_emulator.STAGE_BODY_TRANSMISSION_ALLOWED is False
    assert vvas_loopback_emulator.TASK_RESULT_TRANSMISSION_ALLOWED is False


@pytest.mark.parametrize("outcome", ["", "ok", "SUCCESS", None, True])
def test_task_result_outcome_is_exact(outcome: object) -> None:
    with pytest.raises(ValueError):
        vvas_loopback_emulator.synthetic_task_result_decision(  # type: ignore[arg-type]
            outcome=outcome
        )


def test_nonloopback_bind_is_rejected_before_socket_use() -> None:
    with pytest.raises(ValueError, match="loopback"):
        vvas_loopback_emulator.serve_once("0.0.0.0", 0)


def test_loopback_server_sends_header_but_no_stage_body() -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    port = int(listener.getsockname()[1])
    listener.close()
    results: list[dict] = []
    errors: list[BaseException] = []

    def _serve() -> None:
        try:
            results.append(
                vvas_loopback_emulator.serve_once(
                    "127.0.0.1",
                    port,
                    allow_header_only=True,
                )
            )
        except BaseException as exc:  # pragma: no cover - surfaced below
            errors.append(exc)

    thread = threading.Thread(target=_serve)
    thread.start()
    client = None
    for _ in range(50):
        try:
            client = socket.create_connection(("127.0.0.1", port), timeout=3.0)
            break
        except ConnectionRefusedError:
            time.sleep(0.01)
    assert client is not None
    with client:
        client.sendall(b"32\x00")
        response = client.recv(64)
        assert len(response) == 14
        assert client.recv(1) == b""
    thread.join(timeout=3.0)

    assert not thread.is_alive()
    assert errors == []
    assert results[0]["sent_bytes"] == 14
    assert results[0]["safety"]["stage_body_sent"] is False
    assert results[0]["safety"]["fake_task_result_sent"] is False
