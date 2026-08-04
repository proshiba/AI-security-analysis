from __future__ import annotations

import base64
import json
import re
import sys
from pathlib import Path
from urllib.parse import parse_qs

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms


COMMON = Path(__file__).parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import stealer_registration_probe as probe  # noqa: E402


def response(
    body: bytes,
    *,
    status: int = 200,
    content_type: str = "application/json",
    truncated: bool = False,
) -> probe.BoundedHttpResponse:
    return probe.BoundedHttpResponse(
        status=status,
        content_type=content_type,
        body=body,
        truncated=truncated,
        resolved_ips=("203.0.113.10",),
        connected_ip="203.0.113.10",
    )


def base_profile(handler: str) -> dict:
    return {
        "handler": handler,
        "host": "c2.example",
        "port": 80,
        "http_path": "/",
        "http_host": "c2.example",
        "pinned_ips": ["203.0.113.10"],
        "timeout_seconds": 3.0,
        "maximum_request_bytes": 4096,
        "maximum_response_bytes": 65536,
    }


def test_safety_gates_prevent_registration() -> None:
    calls = []

    def post(*args):
        calls.append(args)
        raise AssertionError("安全gate未充足時は送信しない")

    profile = base_profile("lumma_v6_registration_task")
    assert probe.probe_reviewed_stealer_registration(profile, post=post)["status"] == "network_disabled"
    result = probe.probe_reviewed_stealer_registration(profile, allow_network=True, post=post)
    assert result["status"] == "malware_registration_tasking_disabled"
    assert calls == []


def test_stealc_registers_synthetic_hwid_and_polls_loader_once() -> None:
    key = b"reviewed-rc4-key"
    token = "a" * 72
    calls: list[dict] = []
    profile = {
        **base_profile("stealc_v2_registration_task"),
        "build": "fixture-build",
        "network_rc4_key_base64": base64.b64encode(key).decode("ascii"),
        "maximum_response_bytes": 16384,
    }

    def post(_profile: dict, body: bytes, _headers: dict[str, str]):
        decoded = probe._stealc_decode(body, key)
        assert decoded is not None
        calls.append(decoded)
        if len(calls) == 1:
            return response(probe._stealc_encode({"access_token": token}, key))
        return response(
            probe._stealc_encode(
                {"opcode": "success", "loader": [{"url": "https://payload.invalid/secret"}]},
                key,
            )
        )

    result = probe.probe_reviewed_stealer_registration(
        profile,
        allow_network=True,
        allow_registration_tasking=True,
        post=post,
    )
    assert calls[0]["build"] == "fixture-build"
    assert calls[0]["type"] == "create"
    assert re.fullmatch(r"[0-9A-F-]{36}", calls[0]["hwid"])
    assert calls[1] == {"access_token": token, "type": "loader"}
    assert result["status"] == "confirmed_stealc_registration_task"
    assert result["request_count"] == 2
    assert result["task_available"] is True
    assert result["task_entry_count"] == 1
    published = json.dumps(result)
    assert token not in published
    assert "payload.invalid" not in published
    assert calls[0]["hwid"] not in published
    assert result["task_executed"] is False
    assert result["payload_download_attempted"] is False


def test_lumma_v6_requests_configuration_then_task_with_synthetic_hwid() -> None:
    calls: list[dict[str, list[str]]] = []
    profile = {
        **base_profile("lumma_v6_registration_task"),
        "uid": "f" * 40,
        "cid": "",
    }

    def post(_profile: dict, body: bytes, _headers: dict[str, str]):
        calls.append(parse_qs(body.decode("ascii"), keep_blank_values=True))
        body_value = b"{}" if len(calls) == 1 else b"[]"
        return response(body_value, content_type="application/octet-stream")

    result = probe.probe_reviewed_stealer_registration(
        profile,
        allow_network=True,
        allow_registration_tasking=True,
        post=post,
    )
    assert calls[0] == {"uid": ["f" * 40], "cid": [""]}
    assert calls[1]["uid"] == ["f" * 40]
    assert calls[1]["cid"] == [""]
    assert re.fullmatch(r"[0-9A-F]{32}", calls[1]["hwid"][0])
    assert result["status"] == "confirmed_lumma_v6_registration_task"
    assert result["task_response_decrypted"] is True
    assert result["task_available"] is False
    assert result["task_entry_count"] == 0
    assert calls[1]["hwid"][0] not in json.dumps(result)


def test_lumma_opaque_task_response_is_not_protocol_confirmation() -> None:
    calls = 0
    profile = {**base_profile("lumma_v6_registration_task"), "uid": "f" * 40, "cid": ""}

    def post(_profile: dict, _body: bytes, _headers: dict[str, str]):
        nonlocal calls
        calls += 1
        return response(bytes([calls]) * 64, content_type="application/octet-stream")

    result = probe.probe_reviewed_stealer_registration(
        profile, allow_network=True, allow_registration_tasking=True, post=post
    )
    assert calls == 2
    assert result["task_response_received"] is True
    assert result["task_response_decrypted"] is False
    assert result["c2_confirmed"] is False


def remus_encrypted(value: dict, key_byte: int, nonce_byte: int) -> bytes:
    key = bytes([key_byte]) * 32
    nonce = bytes([nonce_byte]) * 8
    plain = json.dumps(value, separators=(",", ":")).encode("utf-8") + b"\0"
    transform = Cipher(algorithms.ChaCha20(key, b"\0" * 8 + nonce), mode=None).encryptor()
    return key + nonce + transform.update(plain) + transform.finalize()


def test_remus_decrypts_token_and_polls_step_one_without_publishing_task() -> None:
    token = "9702295b-244d-4bc7-95ed-a2597ae41d4b"
    calls: list[dict[str, list[str]]] = []
    profile = {
        **base_profile("remus_registration_task"),
        "tag": "b" * 32,
        "exp": 1785860014,
        "http_host": "microsoft.com",
        "maximum_response_bytes": 8192,
    }

    def post(_profile: dict, body: bytes, _headers: dict[str, str]):
        calls.append(parse_qs(body.decode("ascii")))
        if len(calls) == 1:
            return response(
                remus_encrypted({"vm": False, "ss": True, "access_token": token}, 1, 2),
                status=201,
                content_type="application/octet-stream",
            )
        return response(
            remus_encrypted(
                {"type": 0, "name": "secret-task-name", "data": {"secret": "value"}},
                3,
                4,
            ),
            status=201,
            content_type="application/octet-stream",
        )

    result = probe.probe_reviewed_stealer_registration(
        profile,
        allow_network=True,
        allow_registration_tasking=True,
        post=post,
    )
    assert calls[0]["tag"] == ["b" * 32]
    assert calls[0]["exp"] == ["1785860014"]
    assert re.fullmatch(r"[0-9a-f]{32}", calls[0]["hwid"][0])
    assert calls[1] == {"access_token": [token], "step": ["1"]}
    assert result["status"] == "confirmed_remus_registration_task"
    assert result["task_type"] == 0
    assert result["task_available"] is True
    published = json.dumps(result)
    assert token not in published
    assert "secret-task-name" not in published
    assert "secret" not in published
    assert calls[0]["hwid"][0] not in published


def test_registration_truncation_never_advances_to_task_poll() -> None:
    calls = 0
    profile = {**base_profile("lumma_v6_registration_task"), "uid": "f" * 40, "cid": ""}

    def post(_profile: dict, _body: bytes, _headers: dict[str, str]):
        nonlocal calls
        calls += 1
        return response(b"x" * 10, content_type="application/octet-stream", truncated=True)

    result = probe.probe_reviewed_stealer_registration(
        profile,
        allow_network=True,
        allow_registration_tasking=True,
        post=post,
    )
    assert calls == 1
    assert result["c2_confirmed"] is False
    assert result["task_poll_attempted"] is False
