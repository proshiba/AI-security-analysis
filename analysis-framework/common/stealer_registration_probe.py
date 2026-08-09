#!/usr/bin/env python3
"""レビュー済みStealC・Lumma・Remus C2へ合成端末を限定登録する。"""

from __future__ import annotations

import base64
import hashlib
import http.client
import ipaddress
import json
import math
import re
import socket
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from c2_protocol_probe_profiles import (
    ProtocolProfileError,
    profile_registry_metadata,
)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from remus_profile_evidence import (
    RemusEvidenceError,
    validate_remus_profile_evidence,
)

TOKEN_RE = re.compile(r"[0-9a-f]{64,128}", re.IGNORECASE)
UUID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    re.IGNORECASE,
)
STEALC_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
LUMMA_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.5414.120 Safari/537.36"
)
REMUS_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36"
)


class StealerProbeError(ValueError):
    """能動probeのprofileまたは応答が安全境界を満たさない場合のエラー。"""


@dataclass(frozen=True)
class BoundedHttpResponse:
    """本文を上限付きで保持する内部HTTP応答。"""

    status: int
    content_type: str
    body: bytes
    truncated: bool
    resolved_ips: tuple[str, ...]
    connected_ip: str


PostFunction = Callable[[dict[str, Any], bytes, dict[str, str]], BoundedHttpResponse]


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for value in data:
        counts[value] += 1
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts if count)


def _rc4(data: bytes, key: bytes) -> bytes:
    if not key:
        raise StealerProbeError("StealC RC4 keyが空です")
    state = list(range(256))
    index = 0
    for offset in range(256):
        index = (index + state[offset] + key[offset % len(key)]) & 0xFF
        state[offset], state[index] = state[index], state[offset]
    left = right = 0
    output = bytearray()
    for value in data:
        left = (left + 1) & 0xFF
        right = (right + state[left]) & 0xFF
        state[left], state[right] = state[right], state[left]
        output.append(value ^ state[(state[left] + state[right]) & 0xFF])
    return bytes(output)


def _json_object(data: bytes) -> dict[str, Any] | None:
    try:
        value = json.loads(data.rstrip(b"\0").decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _json_value(data: bytes) -> Any | None:
    try:
        return json.loads(data.rstrip(b"\0").decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None


def _public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def _resolve_and_pin(profile: dict[str, Any]) -> tuple[tuple[str, ...], str]:
    host = str(profile["host"])
    port = int(profile["port"])
    pinned = tuple(str(value) for value in profile.get("pinned_ips") or [])
    if len(pinned) != 1 or not _public_ip(pinned[0]):
        raise StealerProbeError("能動HTTP probeには単一global pinned IPが必要です")
    if _public_ip(host):
        answers = (host,)
    else:
        answers = tuple(
            sorted(
                {
                    item[4][0]
                    for item in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
                    if _public_ip(item[4][0])
                }
            )
        )
    if pinned[0] not in answers:
        raise StealerProbeError("現在のDNS応答とreview済みpinned IPが一致しません")
    return answers, pinned[0]


def _post_http(
    profile: dict[str, Any],
    body: bytes,
    headers: dict[str, str],
) -> BoundedHttpResponse:
    maximum_request = int(profile["maximum_request_bytes"])
    maximum_response = int(profile["maximum_response_bytes"])
    if len(body) > maximum_request:
        raise StealerProbeError("HTTP要求がreview済み上限を超えています")
    resolved, connect_ip = _resolve_and_pin(profile)
    path = str(profile.get("http_path") or "/")
    host_header = str(profile.get("http_host") or profile["host"])
    connection = http.client.HTTPConnection(
        connect_ip,
        int(profile["port"]),
        timeout=float(profile["timeout_seconds"]),
    )
    try:
        connection.putrequest("POST", path, skip_host=True, skip_accept_encoding=True)
        connection.putheader("Host", host_header)
        connection.putheader("Connection", "close")
        connection.putheader("Content-Length", str(len(body)))
        for key, value in headers.items():
            if "\r" in key or "\n" in key or "\r" in value or "\n" in value:
                raise StealerProbeError("HTTP headerに改行を含められません")
            connection.putheader(key, value)
        connection.endheaders(body)
        response = connection.getresponse()
        response_body = response.read(maximum_response + 1)
        truncated = len(response_body) > maximum_response
        response_body = response_body[:maximum_response]
        return BoundedHttpResponse(
            status=int(response.status),
            content_type=str(response.getheader("Content-Type") or "").split(";", 1)[0].casefold(),
            body=response_body,
            truncated=truncated,
            resolved_ips=resolved,
            connected_ip=connect_ip,
        )
    finally:
        connection.close()


def _response_evidence(response: BoundedHttpResponse) -> dict[str, Any]:
    return {
        "http_status": response.status,
        "content_type": response.content_type,
        "body_size": len(response.body),
        "body_sha256": _sha256(response.body),
        "body_truncated": response.truncated,
    }


def _disabled(status: str) -> dict[str, Any]:
    return {
        "status": status,
        "alive": False,
        "c2_confirmed": False,
        "target_contact_attempted": False,
        "target_connection_established": False,
        "application_data_sent": False,
        "registration_attempted": False,
        "registration_accepted": False,
        "task_poll_attempted": False,
        "task_response_received": False,
        "task_available": None,
        "task_content_published": False,
        "task_executed": False,
        "payload_download_attempted": False,
        "victim_metadata_sent": False,
        "synthetic_identity_sent": False,
        "resolved_ips": [],
        "request_count": 0,
    }


def _base_result(responses: list[BoundedHttpResponse]) -> dict[str, Any]:
    return {
        "alive": bool(responses),
        "target_contact_attempted": True,
        "target_connection_established": bool(responses),
        "application_data_sent": True,
        "protocol_response_received": bool(responses),
        "registration_attempted": True,
        "task_content_published": False,
        "task_executed": False,
        "payload_download_attempted": False,
        "victim_metadata_sent": False,
        "synthetic_identity_sent": True,
        "resolved_ips": list(responses[0].resolved_ips) if responses else [],
        "connected_ip": responses[0].connected_ip if responses else None,
        "request_count": len(responses),
        "maximum_request_count": 2,
        "response_evidence": [_response_evidence(response) for response in responses],
    }


def _stealc_encode(value: dict[str, Any], key: bytes) -> bytes:
    plain = json.dumps(value, ensure_ascii=True, indent=4).encode("utf-8")
    return base64.b64encode(_rc4(plain, key))


def _stealc_decode(body: bytes, key: bytes) -> dict[str, Any] | None:
    try:
        encrypted = base64.b64decode(body.strip(), validate=True)
    except ValueError:
        return None
    return _json_object(_rc4(encrypted, key))


def _probe_stealc(profile: dict[str, Any], post: PostFunction) -> dict[str, Any]:
    key = base64.b64decode(str(profile["network_rc4_key_base64"]), validate=True)
    synthetic_hwid = str(uuid.uuid4()).upper()
    registration = _stealc_encode(
        {"build": str(profile["build"]), "hwid": synthetic_hwid, "type": "create"},
        key,
    )
    headers = {"Content-Type": "application/json", "User-Agent": STEALC_USER_AGENT}
    first = post(profile, registration, headers)
    responses = [first]
    decoded = _stealc_decode(first.body, key) if not first.truncated else None
    token = decoded.get("access_token") if decoded else None
    registration_accepted = bool(first.status in {200, 201} and isinstance(token, str) and TOKEN_RE.fullmatch(token))
    if not registration_accepted:
        return {
            **_base_result(responses),
            "status": "stealc_registration_rejected_or_unparseable",
            "c2_confirmed": False,
            "registration_accepted": False,
            "task_poll_attempted": False,
            "task_response_received": False,
            "task_available": None,
            "access_token_published": False,
        }
    task_body = _stealc_encode({"access_token": token, "type": "loader"}, key)
    second = post(profile, task_body, headers)
    responses.append(second)
    task = _stealc_decode(second.body, key) if not second.truncated else None
    loader = task.get("loader") if task else None
    task_valid = bool(
        second.status in {200, 201} and task and task.get("opcode") == "success" and isinstance(loader, list)
    )
    return {
        **_base_result(responses),
        "status": "confirmed_stealc_registration_task" if task_valid else "stealc_task_response_mismatch",
        "c2_confirmed": task_valid,
        "registration_accepted": True,
        "task_poll_attempted": True,
        "task_response_received": second.status in {200, 201} and bool(second.body),
        "task_available": bool(loader) if isinstance(loader, list) else None,
        "task_entry_count": len(loader) if isinstance(loader, list) else None,
        "access_token_published": False,
    }


def _decode_lumma_response(body: bytes) -> Any | None:
    direct = _json_value(body)
    if direct is not None:
        return direct
    candidates: list[bytes] = []
    if len(body) > 32:
        prefix_key = body[:32]
        candidates.append(bytes(value ^ prefix_key[index % 32] for index, value in enumerate(body[32:])))
        suffix_key = body[-32:]
        candidates.append(bytes(value ^ suffix_key[index % 32] for index, value in enumerate(body[:-32])))
    if len(body) > 40:
        layouts = (
            (body[40:], body[:32], body[32:40]),
            (body[:-40], body[-40:-8], body[-8:]),
            (body[:-40], body[-32:], body[-40:-32]),
        )
        for encrypted, key, nonce in layouts:
            try:
                candidates.append(_chacha20_crypt(encrypted, key, nonce))
            except ValueError:
                continue
    for candidate in candidates:
        value = _json_value(candidate)
        if value is not None:
            return value
    return None


def _lumma_response_valid(response: BoundedHttpResponse) -> bool:
    if response.status not in {200, 201} or not response.body or response.truncated:
        return False
    prefix = response.body[:64].lstrip().lower()
    if prefix.startswith((b"<html", b"<!doctype")):
        return False
    return response.content_type in {"application/octet-stream", "application/json", "text/plain", ""}


def _probe_lumma(profile: dict[str, Any], post: PostFunction) -> dict[str, Any]:
    headers = {"Content-Type": "application/x-www-form-urlencoded", "User-Agent": LUMMA_USER_AGENT}
    identity = {"uid": str(profile["uid"]), "cid": str(profile.get("cid") or "")}
    first = post(profile, urlencode(identity).encode("ascii"), headers)
    responses = [first]
    registration_accepted = _lumma_response_valid(first)
    if not registration_accepted:
        return {
            **_base_result(responses),
            "status": "lumma_registration_response_mismatch",
            "c2_confirmed": False,
            "registration_accepted": False,
            "task_poll_attempted": False,
            "task_response_received": False,
            "task_available": None,
        }
    synthetic_hwid = uuid.uuid4().hex.upper()
    second_body = urlencode({**identity, "hwid": synthetic_hwid}).encode("ascii")
    second = post(profile, second_body, headers)
    responses.append(second)
    task_valid = _lumma_response_valid(second)
    decoded = _decode_lumma_response(second.body) if task_valid else None
    if isinstance(decoded, list):
        task_available: bool | None = bool(decoded)
        task_entry_count: int | None = len(decoded)
    elif isinstance(decoded, dict):
        task_available = True
        task_entry_count = 1
    else:
        task_available = None
        task_entry_count = None
    confirmed = registration_accepted and task_valid and decoded is not None
    return {
        **_base_result(responses),
        "status": "confirmed_lumma_v6_registration_task" if confirmed else "lumma_task_response_mismatch",
        "c2_confirmed": confirmed,
        "registration_accepted": registration_accepted,
        "task_poll_attempted": True,
        "task_response_received": task_valid,
        "task_response_decrypted": decoded is not None,
        "task_available": task_available,
        "task_entry_count": task_entry_count,
        "response_entropy": [round(_entropy(response.body), 3) for response in responses],
    }


def _chacha20_crypt(data: bytes, key: bytes, nonce: bytes) -> bytes:
    """8 byte nonce・counter 0のChaCha20を既存依存だけで処理する。"""
    if len(key) != 32 or len(nonce) != 8:
        raise ValueError("ChaCha20 keyまたはnonce長が不正です")
    transform = Cipher(algorithms.ChaCha20(key, b"\0" * 8 + nonce), mode=None).encryptor()
    return transform.update(data) + transform.finalize()


def _decode_remus_response(body: bytes) -> dict[str, Any] | None:
    if len(body) <= 40:
        return None
    key, nonce, ciphertext = body[:32], body[32:40], body[40:]
    try:
        plain = _chacha20_crypt(ciphertext, key, nonce)
    except ValueError:
        return None
    return _json_object(plain)


def _probe_remus(profile: dict[str, Any], post: PostFunction) -> dict[str, Any]:
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": REMUS_USER_AGENT,
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
    }
    registration_body = urlencode(
        {
            "tag": str(profile["tag"]),
            "exp": str(profile["exp"]),
            "hwid": uuid.uuid4().hex,
        }
    ).encode("ascii")
    first = post(profile, registration_body, headers)
    responses = [first]
    decoded = _decode_remus_response(first.body) if not first.truncated else None
    token = decoded.get("access_token") if decoded else None
    registration_accepted = bool(
        first.status == 201
        and isinstance(token, str)
        and UUID_RE.fullmatch(token)
        and isinstance(decoded.get("vm"), bool)
        and isinstance(decoded.get("ss"), bool)
    )
    if not registration_accepted:
        return {
            **_base_result(responses),
            "status": "remus_registration_rejected_or_unparseable",
            "c2_confirmed": False,
            "registration_accepted": False,
            "task_poll_attempted": False,
            "task_response_received": False,
            "task_available": None,
            "access_token_published": False,
        }
    second_body = urlencode({"access_token": token, "step": "1"}).encode("ascii")
    second = post(profile, second_body, headers)
    responses.append(second)
    task = _decode_remus_response(second.body) if not second.truncated else None
    task_type = task.get("type") if type(task) is dict else None
    task_type_valid = type(task_type) is int and 0 <= task_type <= 5
    task_envelope_candidate = bool(
        second.status == 201 and type(task) is dict and set(task) == {"type", "name", "data"} and task_type_valid
    )
    task_schema_status = (
        "name_data_protocol_types_not_static_verified"
        if task_envelope_candidate
        else "invalid_or_unparseable_task_envelope"
    )
    return {
        **_base_result(responses),
        "status": ("remus_task_schema_unverified" if task_envelope_candidate else "remus_task_response_mismatch"),
        "c2_confirmed": False,
        "registration_accepted": True,
        "task_poll_attempted": True,
        "task_response_received": second.status == 201 and bool(second.body),
        "task_available": None,
        "task_type": task_type if task_type_valid else None,
        "task_terminal_signal": None,
        "task_schema_confirmed": False,
        "task_schema_status": task_schema_status,
        "task_name_protocol_type": "unresolved",
        "task_data_protocol_type": "unresolved",
        "access_token_published": False,
    }


def probe_reviewed_stealer_registration(
    profile: dict[str, Any],
    *,
    allow_network: bool = False,
    allow_registration_tasking: bool = False,
    post: PostFunction | None = None,
    repository_root: Path | None = None,
    expected_evidence_sha256: str | None = None,
    expected_evidence_source: str | None = None,
    expected_profile_registry_source: str | None = None,
    expected_profile_registry_sha256: str | None = None,
    expected_registry_source: str | None = None,
    expected_registry_sha256: str | None = None,
    expected_flow_artifact_source: str | None = None,
    expected_flow_artifact_sha256: str | None = None,
    expected_review_id: str | None = None,
) -> dict[str, Any]:
    """完全一致profileへ合成登録とtask取得を最大2要求で行う。

    task本文、access token、合成IDは返さず、取得したtaskを実行・追跡しない。
    """

    if not allow_network:
        return _disabled("network_disabled")
    if not allow_registration_tasking:
        return _disabled("malware_registration_tasking_disabled")
    handler = str(profile.get("handler") or "")
    sender = post or _post_http
    if handler == "stealc_v2_registration_task":
        return _probe_stealc(profile, sender)
    if handler == "lumma_v6_registration_task":
        return _probe_lumma(profile, sender)
    if handler == "remus_registration_task":
        try:
            current_profile_registry = profile_registry_metadata()
        except ProtocolProfileError as exc:
            raise StealerProbeError(f"Remus profile registry pre-probe validation failed: {exc}") from exc
        if (
            expected_profile_registry_source is None
            or expected_profile_registry_sha256 is None
            or current_profile_registry
            != {
                "source": expected_profile_registry_source,
                "sha256": expected_profile_registry_sha256,
            }
        ):
            raise StealerProbeError("Remus profile registry pin mismatch")
        if (
            expected_evidence_source is None
            or expected_evidence_sha256 is None
            or expected_registry_source is None
            or expected_registry_sha256 is None
            or expected_flow_artifact_source is None
            or expected_flow_artifact_sha256 is None
            or expected_review_id is None
            or expected_evidence_source != profile.get("evidence_source")
            or expected_registry_source != profile.get("review_registry_source")
            or expected_flow_artifact_source != profile.get("flow_artifact_source")
            or expected_review_id != profile.get("review_id")
        ):
            raise StealerProbeError("Remus evidence/review/flow source pin mismatch")
        try:
            validate_remus_profile_evidence(
                profile,
                repository_root=repository_root,
                expected_sha256=expected_evidence_sha256,
                expected_registry_sha256=expected_registry_sha256,
                expected_flow_artifact_sha256=expected_flow_artifact_sha256,
            )
        except RemusEvidenceError as exc:
            raise StealerProbeError(f"Remus profile evidence pre-probe validation failed: {exc}") from exc
        return _probe_remus(profile, sender)
    raise StealerProbeError(f"未対応のstealer registration handlerです: {handler}")
