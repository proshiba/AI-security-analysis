"""合成マルウェア通信labで共有する安全境界と有界I/O helper。"""

from __future__ import annotations

import ipaddress
import json
import math
import socket
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit

DEFAULT_MAX_FRAME_BYTES = 65_536
DEFAULT_MAX_COLLECT_BYTES = 1024 * 1024
MAX_EMULATOR_TIMEOUT_SECONDS = 30.0


def require_loopback(host: str, label: str = "エミュレーター") -> str:
    """DNS解決を行わず、literal loopbackをcanonical addressとして返す。"""
    if not isinstance(host, str) or not host:
        raise ValueError(f"{label}はloopback-onlyです")
    if host.lower() == "localhost":
        return "127.0.0.1"
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ValueError(f"{label}はloopback-onlyです") from exc
    if not address.is_loopback:
        raise ValueError(f"{label}はloopback-onlyです")
    return str(address)


def require_timeout(timeout: float, *, label: str = "timeout") -> float:
    """有限かつ正の短時間timeoutだけを受理する。"""
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise ValueError(f"{label}は有限の秒数で指定してください")
    value = float(timeout)
    if not math.isfinite(value) or not 0 < value <= MAX_EMULATOR_TIMEOUT_SECONDS:
        raise ValueError(f"{label}は0秒超30秒以下で指定してください")
    return value


def require_port(port: int, *, allow_zero: bool, label: str = "port") -> int:
    """bind用の0または接続用の1から65535までのportだけを受理する。"""
    minimum = 0 if allow_zero else 1
    if (
        isinstance(port, bool)
        or not isinstance(port, int)
        or not minimum <= port <= 65_535
    ):
        raise ValueError(f"{label}は{minimum}から65535の整数で指定してください")
    return port


def require_loopback_http_base_url(base_url: str, label: str = "HTTP lab") -> str:
    """credential・path・query・fragmentのないloopback HTTP URLを正規化する。"""
    if (
        not isinstance(base_url, str)
        or not base_url
        or any(c in base_url for c in "\r\n\t")
    ):
        raise ValueError(f"{label}のURLが不正です")
    try:
        parsed = urlsplit(base_url)
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"{label}のURLが不正です") from exc
    if (
        parsed.scheme.lower() != "http"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or port is None
    ):
        raise ValueError(
            f"{label}はcredential・path・query・fragmentなしのHTTP loopback URLである必要があります"
        )
    host = require_loopback(parsed.hostname, label)
    require_port(port, allow_zero=False, label=f"{label} port")
    return f"http://[{host}]:{port}" if ":" in host else f"http://{host}:{port}"


def load_strict_json_object(
    payload: bytes, *, label: str, maximum_bytes: int = DEFAULT_MAX_FRAME_BYTES
) -> dict[str, Any]:
    """UTF-8、重複key禁止、非標準数値禁止の有界JSON objectを読む。"""
    if not isinstance(payload, bytes):
        raise ValueError(f"{label}はbytesで指定してください")
    if (
        not isinstance(maximum_bytes, int)
        or isinstance(maximum_bytes, bool)
        or maximum_bytes < 1
    ):
        raise ValueError("JSON size上限が不正です")
    if len(payload) > maximum_bytes:
        raise ValueError(f"{label}がsize上限を超えています")

    def pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"{label}に重複JSON keyがあります: {key}")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise ValueError(f"{label}に非標準JSON数値があります: {value}")

    try:
        value = json.loads(
            payload.decode("utf-8", errors="strict"),
            object_pairs_hook=pairs_hook,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError(f"{label}はstrict UTF-8 JSONではありません") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label}のrootはobjectである必要があります")
    return value


def read_exact_bounded(
    sock: socket.socket, length: int, *, maximum_bytes: int, label: str
) -> bytes:
    """宣言長を先に検証し、socketからその長さだけを有界に読む。"""
    if (
        isinstance(length, bool)
        or not isinstance(length, int)
        or length < 0
        or length > maximum_bytes
    ):
        raise ValueError(f"{label}の宣言長が不正です")
    chunks: list[bytes] = []
    remaining = length
    while remaining:
        chunk = sock.recv(min(remaining, 65_536))
        if not chunk:
            raise ValueError(f"{label}が途中で切断されました")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


class LoopbackThreadingHTTPServer(ThreadingHTTPServer):
    """短命threadと小さい待受queueだけを使うIPv4 loopback HTTP server。"""

    allow_reuse_address = True
    daemon_threads = True
    block_on_close = False
    request_queue_size = 8


class LoopbackThreadingHTTPServerV6(LoopbackThreadingHTTPServer):
    """IPv6 loopback用のHTTP server。"""

    address_family = socket.AF_INET6


def build_loopback_http_server(
    host: str,
    port: int,
    handler: type[BaseHTTPRequestHandler],
    *,
    label: str,
) -> ThreadingHTTPServer:
    """IPv4／IPv6のliteral loopbackだけへHTTP serverをbindする。"""
    host = require_loopback(host, label)
    require_port(port, allow_zero=True, label=f"{label} port")
    server_type = (
        LoopbackThreadingHTTPServerV6 if ":" in host else LoopbackThreadingHTTPServer
    )
    return server_type((host, port), handler)


@dataclass
class LoopbackCollector:
    """応答せず、loopback接続1件だけを有界に収集するcollector。"""

    host: str = "127.0.0.1"
    port: int = 0
    label: str = "malware lab"
    maximum_bytes: int = DEFAULT_MAX_COLLECT_BYTES
    accept_timeout: float = 2.0
    read_timeout: float = 0.2
    received: list[bytes] = field(default_factory=list)
    _socket: socket.socket | None = field(default=None, init=False, repr=False)
    _thread: threading.Thread | None = field(default=None, init=False, repr=False)
    _lock: threading.Lock = field(
        default_factory=threading.Lock, init=False, repr=False
    )

    @property
    def running(self) -> bool:
        """collector threadが現在動作中か返す。"""
        with self._lock:
            return self._thread is not None and self._thread.is_alive()

    def start(self) -> int:
        """loopback listenerを1件起動し、選択されたportを返す。"""
        host = require_loopback(self.host, self.label)
        require_port(self.port, allow_zero=True, label=f"{self.label} port")
        if (
            isinstance(self.maximum_bytes, bool)
            or not isinstance(self.maximum_bytes, int)
            or not 1 <= self.maximum_bytes <= DEFAULT_MAX_COLLECT_BYTES
        ):
            raise ValueError("collector size上限は1 byteから1 MiBで指定してください")
        accept_timeout = require_timeout(
            self.accept_timeout, label="collector accept timeout"
        )
        read_timeout = require_timeout(
            self.read_timeout, label="collector read timeout"
        )
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        with self._lock:
            if self._socket is not None or (
                self._thread is not None and self._thread.is_alive()
            ):
                raise RuntimeError("collectorはすでに動作中です")
            listener = socket.socket(family, socket.SOCK_STREAM)
            try:
                listener.settimeout(accept_timeout)
                listener.bind((host, self.port))
                listener.listen(1)
            except BaseException:
                listener.close()
                raise
            self._socket = listener
            self.port = listener.getsockname()[1]
            self._thread = threading.Thread(
                target=self._collect_once,
                args=(listener, read_timeout),
                daemon=True,
                name=f"{self.label}-collector",
            )
            self._thread.start()
        return self.port

    def _collect_once(self, listener: socket.socket, read_timeout: float) -> None:
        """1接続から設定上限まで読み、応答せずに終了する。"""
        chunks: list[bytes] = []
        total = 0
        try:
            client, address = listener.accept()
            require_loopback(str(address[0]), self.label)
            with client:
                client.settimeout(read_timeout)
                while total < self.maximum_bytes:
                    try:
                        chunk = client.recv(min(65_536, self.maximum_bytes - total))
                    except TimeoutError:
                        break
                    if not chunk:
                        break
                    chunks.append(chunk)
                    total += len(chunk)
        except (TimeoutError, OSError, ValueError):
            return
        finally:
            listener.close()
            with self._lock:
                if self._socket is listener:
                    self._socket = None
        self.received.append(b"".join(chunks))

    def stop(self) -> None:
        """listenerを閉じ、collector threadを有界時間内で終了させる。"""
        with self._lock:
            listener = self._socket
            thread = self._thread
        if listener is not None:
            listener.close()
        if thread is not None:
            thread.join(timeout=self.accept_timeout + self.read_timeout + 1.0)
            if thread.is_alive():
                raise RuntimeError("collector threadを終了できませんでした")
        with self._lock:
            if self._socket is listener:
                self._socket = None
            if self._thread is thread:
                self._thread = None

    def __enter__(self) -> LoopbackCollector:
        """context managerとしてlistenerを起動する。"""
        self.start()
        return self

    def __exit__(self, _exc_type: object, _exc: object, _traceback: object) -> None:
        """context終了時にlistenerを必ず停止する。"""
        self.stop()
