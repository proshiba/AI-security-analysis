"""Safe loopback-only helpers for studying observed PureHVNC wire formats."""

from __future__ import annotations

import gzip
import ipaddress
import socket
import struct
import threading
from dataclasses import dataclass, field
from typing import Any

from extractors.purehvnc.extractor import parse_protobuf, read_varint

NATIVE_MAGIC = 0x58463031
HEADER = struct.Struct("<III")


def pack_native_frame(message_type: int, payload: bytes, magic: int = NATIVE_MAGIC) -> bytes:
    """Pack an observed 12-byte 10FX native frame for offline fixtures."""
    if not 0 <= message_type <= 0xFFFFFFFF:
        raise ValueError("message type must fit uint32")
    return HEADER.pack(magic, len(payload), message_type) + payload


def parse_native_frame(data: bytes, magic: int = NATIVE_MAGIC) -> tuple[int, bytes, bytes]:
    """Parse one native frame and return type, payload, and unconsumed bytes."""
    if len(data) < HEADER.size:
        raise ValueError("truncated native frame header")
    observed, length, message_type = HEADER.unpack_from(data)
    if observed != magic:
        raise ValueError("native frame magic mismatch")
    end = HEADER.size + length
    if end > len(data):
        raise ValueError("truncated native frame payload")
    return message_type, data[HEADER.size:end], data[end:]


def encode_varint(value: int) -> bytes:
    """Encode a non-negative protobuf varint for test traffic."""
    if value < 0:
        raise ValueError("protobuf varints must be non-negative")
    output = bytearray()
    while value > 0x7F:
        output.append((value & 0x7F) | 0x80)
        value >>= 7
    output.append(value)
    return bytes(output)


def encode_bytes_field(number: int, value: bytes) -> bytes:
    """Encode one length-delimited protobuf field."""
    if number <= 0:
        raise ValueError("protobuf field numbers must be positive")
    return encode_varint(number << 3 | 2) + encode_varint(len(value)) + value


def pack_managed_message(fields: dict[int, bytes]) -> bytes:
    """Build a GZip-compressed protobuf fixture used only with the loopback lab."""
    clear = b"".join(encode_bytes_field(number, fields[number]) for number in sorted(fields))
    return gzip.compress(clear, mtime=0)


def parse_managed_message(data: bytes) -> dict[int, list[Any]]:
    """Decompress and parse a managed PureRAT protobuf fixture."""
    return parse_protobuf(gzip.decompress(data))


def require_loopback(host: str) -> str:
    """Validate that a bind or target address is strictly loopback."""
    address = ipaddress.ip_address(socket.gethostbyname(host))
    if not address.is_loopback:
        raise ValueError("PureHVNC lab permits loopback addresses only")
    return str(address)


@dataclass
class LoopbackCollector:
    """Minimal collector that records bytes and never dispatches commands."""

    host: str = "127.0.0.1"
    port: int = 0
    received: list[bytes] = field(default_factory=list)
    _socket: socket.socket | None = field(default=None, init=False, repr=False)
    _thread: threading.Thread | None = field(default=None, init=False, repr=False)

    def start(self) -> int:
        """Start one loopback listener and return its ephemeral port."""
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
        """Collect one connection without sending any response."""
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
        """Close the listener and join its worker briefly."""
        if self._socket is not None:
            self._socket.close()
        if self._thread is not None:
            self._thread.join(timeout=2.5)
