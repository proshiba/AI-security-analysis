"""Shared safety helpers for synthetic malware protocol laboratories."""

from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
import socket
import threading


def require_loopback(host: str, label: str = "emulator") -> str:
    """Return a canonical loopback address and reject DNS names or external targets."""
    if host.lower() == "localhost":
        return "127.0.0.1"
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ValueError(f"{label} is loopback-only") from exc
    if not address.is_loopback:
        raise ValueError(f"{label} is loopback-only")
    return str(address)


@dataclass
class LoopbackCollector:
    """Collect one bounded local connection and never transmit commands or responses."""

    host: str = "127.0.0.1"
    port: int = 0
    label: str = "malware lab"
    received: list[bytes] = field(default_factory=list)
    _socket: socket.socket | None = field(default=None, init=False, repr=False)
    _thread: threading.Thread | None = field(default=None, init=False, repr=False)

    def start(self) -> int:
        """Start one loopback listener and return its selected port."""
        host = require_loopback(self.host, self.label)
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        self._socket = socket.socket(family, socket.SOCK_STREAM)
        self._socket.settimeout(2.0)
        self._socket.bind((host, self.port))
        self._socket.listen(1)
        self.port = self._socket.getsockname()[1]
        self._thread = threading.Thread(target=self._collect_once, daemon=True)
        self._thread.start()
        return self.port

    def _collect_once(self) -> None:
        """Collect at most one connection and 1 MiB without transmitting data."""
        assert self._socket is not None
        chunks: list[bytes] = []
        total = 0
        try:
            client, _address = self._socket.accept()
            with client:
                client.settimeout(0.2)
                while total < 1024 * 1024:
                    try:
                        chunk = client.recv(min(65_536, 1024 * 1024 - total))
                    except socket.timeout:
                        break
                    if not chunk:
                        break
                    chunks.append(chunk)
                    total += len(chunk)
        except (OSError, socket.timeout):
            return
        self.received.append(b"".join(chunks))

    def stop(self) -> None:
        """Allow an accepted client to finish, then close and join the worker."""
        if self._thread is not None:
            self._thread.join(timeout=0.5)
        if self._socket is not None:
            self._socket.close()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
