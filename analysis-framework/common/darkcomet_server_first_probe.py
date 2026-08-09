#!/usr/bin/env python3
"""DarkComet の server-first IDTYPE challenge を受信だけで検証する。"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
import socket
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from darkcomet_profile_evidence import (
    DarkCometEvidenceError,
    validate_darkcomet_profile_evidence,
)

EXPECTED_PLAINTEXT = b"IDTYPE"
RAW_CIPHERTEXT_BYTES = len(EXPECTED_PLAINTEXT)
ASCII_HEX_BYTES = RAW_CIPHERTEXT_BYTES * 2
MAXIMUM_WIRE_BYTES = ASCII_HEX_BYTES
ASCII_HEX_RE = re.compile(rb"[0-9A-Fa-f]{12}")


class DarkCometProbeError(ValueError):
    """profile または応答が安全境界を満たさない場合のエラー。"""


def rc4_crypt(data: bytes, key: bytes) -> bytes:
    """標準 RC4 KSA/PRGA で同じ長さの bytes を変換する。"""

    if not 1 <= len(key) <= 256:
        raise DarkCometProbeError("RC4 key は 1～256 byte である必要があります")
    state = list(range(256))
    right = 0
    for left in range(256):
        right = (right + state[left] + key[left % len(key)]) & 0xFF
        state[left], state[right] = state[right], state[left]
    left = right = 0
    output = bytearray()
    for value in data:
        left = (left + 1) & 0xFF
        right = (right + state[left]) & 0xFF
        state[left], state[right] = state[right], state[left]
        output.append(value ^ state[(state[left] + state[right]) & 0xFF])
    return bytes(output)


def decode_server_first_response(wire: bytes, key: bytes) -> dict[str, Any]:
    """raw RC4 または 12 桁 ASCII-hex だけを受理し、IDTYPE 完全一致を判定する。"""

    length = len(wire)
    common = {
        "wire_length": length,
        "wire_sha256": hashlib.sha256(wire).hexdigest() if wire else None,
        "expected_plaintext": "IDTYPE",
        "decrypted_plaintext_published": False,
        "rc4_key_published": False,
    }
    if length == 0:
        return {**common, "status": "connected_no_response", "matched": False, "wire_encoding": None}
    if length > MAXIMUM_WIRE_BYTES:
        return {
            **common,
            "status": "darkcomet_ciphertext_overlong",
            "matched": False,
            "wire_encoding": None,
        }
    if length == RAW_CIPHERTEXT_BYTES:
        ciphertext = wire
        encoding = "raw"
    elif length == ASCII_HEX_BYTES and ASCII_HEX_RE.fullmatch(wire):
        ciphertext = bytes.fromhex(wire.decode("ascii"))
        encoding = "ascii_hex"
    elif length < RAW_CIPHERTEXT_BYTES or (
        length < ASCII_HEX_BYTES and all(value in b"0123456789abcdefABCDEF" for value in wire)
    ):
        return {
            **common,
            "status": "darkcomet_ciphertext_partial",
            "matched": False,
            "wire_encoding": None,
        }
    else:
        return {
            **common,
            "status": "darkcomet_ciphertext_malformed",
            "matched": False,
            "wire_encoding": None,
        }
    plain = rc4_crypt(ciphertext, key)
    matched = plain == EXPECTED_PLAINTEXT
    return {
        **common,
        "status": "confirmed_darkcomet_idtype" if matched else "darkcomet_idtype_mismatch",
        "matched": matched,
        "wire_encoding": encoding,
    }


def _profile_key(profile: dict[str, Any], repository_root: Path | None) -> bytes:
    evidence_sha256 = profile.get("evidence_sha256")
    if profile.get("evidence_source") != profile.get("source"):
        raise DarkCometProbeError("profile の証拠 source が固定されていません")
    if not isinstance(evidence_sha256, str):
        raise DarkCometProbeError("profile の証拠 SHA-256 が固定されていません")
    try:
        validate_darkcomet_profile_evidence(
            profile,
            repository_root=repository_root,
            expected_sha256=evidence_sha256,
        )
    except DarkCometEvidenceError as exc:
        raise DarkCometProbeError(str(exc)) from exc
    try:
        key = base64.b64decode(str(profile["network_rc4_key_base64"]), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise DarkCometProbeError("network RC4 key の base64 が不正です") from exc
    return key


def _receive_bounded(
    stream: socket.socket,
    *,
    deadline: float,
    maximum_wire_bytes: int,
) -> bytes:
    """EOF または単一の全体期限まで、判定上限に超過検知 1 byte を加えて受信する。"""

    value = bytearray()
    while len(value) <= maximum_wire_bytes:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        stream.settimeout(remaining)
        try:
            chunk = stream.recv(maximum_wire_bytes + 1 - len(value))
        except TimeoutError:
            break
        if not chunk:
            break
        value.extend(chunk)
        if len(value) > maximum_wire_bytes:
            break
    return bytes(value)


def _resolved_addresses(host: str, port: int) -> list[tuple[int, int, int, tuple[Any, ...]]]:
    """DNS を 1 回だけ実施し、接続先 tuple を順序保持で重複排除する。"""

    records = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    values: list[tuple[int, int, int, tuple[Any, ...]]] = []
    seen: set[tuple[int, int, int, tuple[Any, ...]]] = set()
    for family, socktype, protocol, _canonname, sockaddr in records:
        key = (family, socktype, protocol, tuple(sockaddr))
        if key not in seen:
            values.append(key)
            seen.add(key)
    if not values:
        raise socket.gaierror("接続可能な address がありません")
    return values


def probe_reviewed_darkcomet_server_first(
    profile: dict[str, Any],
    *,
    allow_network: bool,
    repository_root: Path | None = None,
) -> dict[str, Any]:
    """証拠が固定された profile へ接続し、application data を送らず challenge だけを受信する。"""

    timestamp = datetime.now(UTC).isoformat()
    disabled = {
        "timestamp_utc": timestamp,
        "status": "network_disabled",
        "alive": False,
        "c2_confirmed": False,
        "target_contact_attempted": False,
        "target_connection_established": False,
        "application_data_sent": False,
        "sent_bytes": 0,
        "protocol_response_received": False,
        "server_first_response_received": False,
        "server_first_bytes_received": 0,
        "resolved_ips": [],
        "dns_timeout_bounded": False,
        "deadline_scope": "post_dns_connect_receive",
        "stage_requested": False,
        "victim_metadata_sent": False,
        "operation_command_sent": False,
    }
    if not allow_network:
        return disabled

    key = _profile_key(profile, repository_root)
    timeout = float(profile["timeout_seconds"])
    maximum = int(profile["maximum_response_bytes"])
    if not 0.1 <= timeout <= 5.0:
        raise DarkCometProbeError("timeout は 0.1～5 秒に限定します")
    if maximum != MAXIMUM_WIRE_BYTES:
        raise DarkCometProbeError("DarkComet 応答上限は 12 byte 固定です")

    addresses = _resolved_addresses(str(profile["host"]), int(profile["port"]))
    resolved_ips = list(dict.fromkeys(str(sockaddr[0]) for *_prefix, sockaddr in addresses))
    deadline = time.monotonic() + timeout
    last_error: OSError | None = None
    attempted = 0
    connected = False
    peer = ""
    wire = b""
    receive_skipped_deadline_exhausted = False
    for family, socktype, protocol, sockaddr in addresses:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        attempted += 1
        stream = socket.socket(family, socktype, protocol)
        try:
            stream.settimeout(remaining)
            stream.connect(sockaddr)
        except OSError as exc:
            last_error = exc
            stream.close()
            continue
        connected = True
        try:
            try:
                peer = str(stream.getpeername()[0])
            except (OSError, IndexError, TypeError):
                peer = str(sockaddr[0])
            if deadline - time.monotonic() > 0:
                wire = _receive_bounded(
                    stream,
                    deadline=deadline,
                    maximum_wire_bytes=maximum,
                )
            else:
                receive_skipped_deadline_exhausted = True
        finally:
            stream.close()
        break
    if not connected:
        if deadline - time.monotonic() <= 0:
            raise TimeoutError("post-DNS connect/receive deadline を超過しました")
        if last_error is not None:
            raise last_error
        raise OSError("DarkComet endpoint へ接続できません")

    decoded = (
        {
            "status": "receive_skipped_deadline_exhausted",
            "matched": False,
            "wire_encoding": None,
            "wire_sha256": None,
        }
        if receive_skipped_deadline_exhausted
        else decode_server_first_response(wire, key)
    )
    confirmed = bool(decoded["matched"])
    return {
        "timestamp_utc": timestamp,
        "status": decoded["status"],
        "alive": True,
        "c2_confirmed": confirmed,
        "target_contact_attempted": True,
        "target_connection_established": True,
        "application_data_sent": False,
        "sent_bytes": 0,
        "protocol_response_received": bool(wire),
        "server_first_response_received": bool(wire),
        "server_first_bytes_received": len(wire),
        "received_bytes": len(wire),
        "wire_encoding": decoded["wire_encoding"],
        "wire_sha256": decoded["wire_sha256"],
        "idtype_exact_match": confirmed,
        "decrypted_plaintext_published": False,
        "rc4_key_published": False,
        "resolved_ips": resolved_ips,
        "connected_ip": peer or None,
        "address_attempt_count": attempted,
        "receive_skipped_deadline_exhausted": receive_skipped_deadline_exhausted,
        "dns_timeout_bounded": False,
        "deadline_scope": "post_dns_connect_receive",
        "evidence_sha256": profile["evidence_sha256"],
        "evidence_source": profile["evidence_source"],
        "stage_requested": False,
        "victim_metadata_sent": False,
        "operation_command_sent": False,
    }
