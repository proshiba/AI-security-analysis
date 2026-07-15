"""Offline and loopback-only helpers for the documented SpyGlace protocol."""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import socket
import threading
import urllib.parse

DEFAULT_RC4_KEY = bytes.fromhex("90b149c69b149c4b99c04d1dc9b940b9")


def custom_rc4(key: bytes, data: bytes) -> bytes:
    """Apply SpyGlace's three-round KSA and modified PRGA symmetrically."""
    if not key:
        raise ValueError("key must be non-empty")
    state = list(range(256))
    for _round in range(3):
        j = 0
        for i in range(256):
            j = (j + state[i] + key[i % len(key)]) & 255
            state[i], state[j] = state[j], state[i]
    i = j = 0
    output = bytearray()
    for value in data:
        i = (i + 1) & 255
        j = (j + state[i]) & 255
        first = state[(state[i] + j) & 255]
        state[i], state[j] = state[j], state[i]
        index = (
            (
                state[((i >> 3) ^ (0x20 * j)) & 255]
                + state[((0x20 * i) ^ (j >> 3)) & 255]
            )
            ^ 0xAA
        ) & 255
        second = state[index] + state[(state[j] + state[i]) & 255]
        output.append((value ^ first ^ second) & 255)
    return bytes(output)


def encode_a004(system_profile: str, key: bytes = DEFAULT_RC4_KEY) -> str:
    """Encode one semicolon-delimited system profile for a local fixture."""
    return base64.b64encode(custom_rc4(key, system_profile.encode("utf-8"))).decode(
        "ascii"
    )


def decode_a004(value: str, key: bytes = DEFAULT_RC4_KEY) -> str:
    """Decode one Base64/custom-RC4 system-profile fixture."""
    try:
        raw = base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise ValueError("a004 is not strict Base64") from exc
    return custom_rc4(key, raw).decode("utf-8")


def build_initial_form(
    userid: str,
    system_info: str,
    mode: str,
    system_profile: str,
    key: bytes = DEFAULT_RC4_KEY,
) -> bytes:
    """Build the documented four-field initial request body without sending it."""
    if mode not in {"uid", "info"}:
        raise ValueError("mode must be uid or info")
    fields = {
        "a001": hashlib.md5(userid.encode("utf-8"), usedforsecurity=False).hexdigest(),
        "a002": hashlib.md5(
            system_info.encode("utf-8"), usedforsecurity=False
        ).hexdigest(),
        "a003": mode,
        "a004": encode_a004(system_profile, key),
    }
    return urllib.parse.urlencode(fields).encode("ascii")


def parse_initial_form(body: bytes, key: bytes = DEFAULT_RC4_KEY) -> dict[str, str]:
    """Parse and decode a local four-field SpyGlace request fixture."""
    parsed = urllib.parse.parse_qs(body.decode("ascii"), strict_parsing=True)
    if set(parsed) != {"a001", "a002", "a003", "a004"} or any(
        len(value) != 1 for value in parsed.values()
    ):
        raise ValueError("unexpected SpyGlace form structure")
    result = {name: value[0] for name, value in parsed.items()}
    result["profile"] = decode_a004(result["a004"], key)
    return result


def require_loopback(host: str) -> str:
    """Resolve and require an IPv4/IPv6 loopback address."""
    address = ipaddress.ip_address(socket.gethostbyname(host))
    if not address.is_loopback:
        raise ValueError("SpyGlace lab permits loopback addresses only")
    return str(address)


class LoopbackCollector:
    """Collect one local request and never return tasks or commands."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        """Initialize a stopped collector."""
        self.host = host
        self.port = port
        self.received: list[bytes] = []
        self._socket: socket.socket | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> int:
        """Start one loopback listener and return its selected port."""
        host = require_loopback(self.host)
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.settimeout(2.0)
        self._socket.bind((host, self.port))
        self._socket.listen(1)
        self.port = self._socket.getsockname()[1]
        self._thread = threading.Thread(target=self._collect_once, daemon=True)
        self._thread.start()
        return self.port

    def _collect_once(self) -> None:
        """Collect one connection without transmitting a response."""
        assert self._socket is not None
        try:
            client, _address = self._socket.accept()
            with client:
                client.settimeout(0.2)
                chunks = []
                while True:
                    try:
                        chunk = client.recv(65536)
                    except socket.timeout:
                        break
                    if not chunk:
                        break
                    chunks.append(chunk)
                self.received.append(b"".join(chunks))
        except (OSError, socket.timeout):
            return

    def stop(self) -> None:
        """Close the listener and briefly join its worker."""
        if self._socket is not None:
            self._socket.close()
        if self._thread is not None:
            self._thread.join(timeout=2.5)
