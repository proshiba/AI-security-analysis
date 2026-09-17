#!/usr/bin/env python3
"""Windows Ghidra MCPのUnix domain socketをlocalhost TCPへ有界中継する。"""

from __future__ import annotations

import argparse
import ctypes
import ipaddress
import json
import os
import socket
import sys
import threading
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any

DEFAULT_LISTEN_HOST = "127.0.0.1"
DEFAULT_LISTEN_PORT = 18089
DEFAULT_CONNECT_TIMEOUT = 5.0
DEFAULT_IDLE_TIMEOUT = 185.0
DEFAULT_MAX_CONNECTIONS = 4
DEFAULT_MAX_REQUEST_BYTES = 16 * 1024 * 1024
DEFAULT_MAX_RESPONSE_BYTES = 64 * 1024 * 1024
MAX_CONNECTIONS = 32
MAX_DIRECTION_BYTES = 256 * 1024 * 1024
BUFFER_SIZE = 64 * 1024
WINDOWS_AF_UNIX = 1
WINDOWS_SOCK_STREAM = 1
WINDOWS_SOCKET_ERROR = -1
WINDOWS_FIONBIO = 0x8004667E
WINDOWS_WOULD_BLOCK = frozenset({10035, 10036, 10037})


class RelayConfigurationError(ValueError):
    """安全境界に違反したrelay設定。"""


class RelayLimitExceeded(OSError):
    """方向別byte上限を超過した接続。"""


@dataclass(frozen=True)
class RelayConfiguration:
    """検証済みrelay設定。"""

    uds_path: str
    listen_host: str
    listen_port: int
    connect_timeout: float
    idle_timeout: float
    max_connections: int
    max_request_bytes: int
    max_response_bytes: int

    @property
    def listen_url(self) -> str:
        return f"http://{self.listen_host}:{self.listen_port}"


def _bounded_positive_int(value: Any, *, label: str, maximum: int) -> int:
    if type(value) is not int or not 1 <= value <= maximum:
        raise RelayConfigurationError(f"{label}は1以上{maximum}以下で指定してください")
    return value


def _bounded_timeout(value: Any, *, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise RelayConfigurationError(f"{label}は秒数で指定してください")
    normalized = float(value)
    if not 0.1 <= normalized <= 600.0:
        raise RelayConfigurationError(f"{label}は0.1秒以上600秒以下で指定してください")
    return normalized


def validate_configuration(args: argparse.Namespace) -> RelayConfiguration:
    """CLI値をlocalhost・有界resource契約へ正規化する。"""

    try:
        address = ipaddress.ip_address(args.listen_host)
    except ValueError as exc:
        raise RelayConfigurationError("listen hostはnumeric loopback addressに限定します") from exc
    # 実装はAF_INETだけに固定し、名前解決・dual-stack・外部interfaceを排除する。
    if address.version != 4 or not address.is_loopback or address.compressed != DEFAULT_LISTEN_HOST:
        raise RelayConfigurationError("listen hostは127.0.0.1に限定します")
    uds_path = args.uds_path
    if (
        not isinstance(uds_path, str)
        or not uds_path
        or uds_path != uds_path.strip()
        or "\x00" in uds_path
        or len(os.fsencode(uds_path)) > 107
    ):
        raise RelayConfigurationError("UDS pathの形式または長さが不正です")
    if os.name != "nt" and not hasattr(socket, "AF_UNIX"):
        raise RelayConfigurationError("このPython runtimeはAF_UNIXを提供していません")
    return RelayConfiguration(
        uds_path=uds_path,
        listen_host=address.compressed,
        listen_port=_bounded_positive_int(args.listen_port, label="listen port", maximum=65535),
        connect_timeout=_bounded_timeout(args.connect_timeout, label="connect timeout"),
        idle_timeout=_bounded_timeout(args.idle_timeout, label="idle timeout"),
        max_connections=_bounded_positive_int(
            args.max_connections,
            label="max connections",
            maximum=MAX_CONNECTIONS,
        ),
        max_request_bytes=_bounded_positive_int(
            args.max_request_bytes,
            label="max request bytes",
            maximum=MAX_DIRECTION_BYTES,
        ),
        max_response_bytes=_bounded_positive_int(
            args.max_response_bytes,
            label="max response bytes",
            maximum=MAX_DIRECTION_BYTES,
        ),
    )


def _shutdown(socket_object: socket.socket, direction: int) -> None:
    try:
        socket_object.shutdown(direction)
    except OSError:
        pass


def _connect_windows_uds(path: str, timeout: float) -> socket.socket:
    """PythonがAF_UNIXを公開しないWindowsでもWinsock handleを標準ctypesで接続する。"""

    if os.name != "nt":
        raise OSError("Windows AF_UNIX adapterはWindows専用です")
    path_bytes = os.fsencode(path)
    if not path_bytes or len(path_bytes) > 107 or b"\x00" in path_bytes:
        raise OSError("Windows AF_UNIX pathがsockaddr_un上限を超えています")

    class SockaddrUn(ctypes.Structure):
        _fields_ = [("sun_family", ctypes.c_ushort), ("sun_path", ctypes.c_char * 108)]

    winsock = ctypes.WinDLL("Ws2_32.dll", use_last_error=True)
    socket_type = ctypes.c_uint64 if ctypes.sizeof(ctypes.c_void_p) == 8 else ctypes.c_uint32
    winsock.WSASocketW.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32]
    winsock.WSASocketW.restype = socket_type
    winsock.connect.argtypes = [socket_type, ctypes.c_void_p, ctypes.c_int]
    winsock.connect.restype = ctypes.c_int
    winsock.ioctlsocket.argtypes = [socket_type, ctypes.c_long, ctypes.POINTER(ctypes.c_ulong)]
    winsock.ioctlsocket.restype = ctypes.c_int
    winsock.closesocket.argtypes = [socket_type]
    winsock.closesocket.restype = ctypes.c_int
    winsock.WSAGetLastError.restype = ctypes.c_int

    handle = winsock.WSASocketW(WINDOWS_AF_UNIX, WINDOWS_SOCK_STREAM, 0, None, 0, 0)
    invalid_socket = (1 << (ctypes.sizeof(socket_type) * 8)) - 1
    if int(handle) == invalid_socket:
        raise OSError(winsock.WSAGetLastError(), "WSASocketW(AF_UNIX) failed")
    wrapped: socket.socket | None = None
    try:
        nonblocking = ctypes.c_ulong(1)
        if winsock.ioctlsocket(handle, WINDOWS_FIONBIO, ctypes.byref(nonblocking)) == WINDOWS_SOCKET_ERROR:
            raise OSError(winsock.WSAGetLastError(), "AF_UNIX nonblocking setup failed")
        address = SockaddrUn()
        address.sun_family = WINDOWS_AF_UNIX
        address.sun_path = path_bytes
        result = winsock.connect(handle, ctypes.byref(address), ctypes.sizeof(address))
        if result == WINDOWS_SOCKET_ERROR:
            error = winsock.WSAGetLastError()
            if error not in WINDOWS_WOULD_BLOCK:
                raise OSError(error, "Windows AF_UNIX connect failed")
        wrapped = socket.socket(socket.AF_INET, socket.SOCK_STREAM, fileno=int(handle))
        if result == WINDOWS_SOCKET_ERROR:
            import select

            _readable, writable, exceptional = select.select([], [wrapped], [wrapped], timeout)
            if exceptional or not writable:
                raise TimeoutError("Windows AF_UNIX connect timeout")
            pending_error = wrapped.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            if pending_error:
                raise OSError(pending_error, "Windows AF_UNIX connect failed")
        wrapped.setblocking(True)
        wrapped.settimeout(timeout)
        return wrapped
    except BaseException:
        if wrapped is not None:
            wrapped.close()
        else:
            winsock.closesocket(handle)
        raise


def connect_uds(path: str, timeout: float) -> socket.socket:
    """platformごとのAF_UNIX接続をsocket互換objectとして返す。"""

    if os.name == "nt":
        return _connect_windows_uds(path, timeout)
    upstream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    upstream.settimeout(timeout)
    upstream.connect(path)
    return upstream


def _copy_bounded(
    source: socket.socket,
    destination: socket.socket,
    *,
    maximum_bytes: int,
    stop: threading.Event,
) -> None:
    transferred = 0
    try:
        while not stop.is_set():
            chunk = source.recv(min(BUFFER_SIZE, maximum_bytes - transferred + 1))
            if not chunk:
                _shutdown(destination, socket.SHUT_WR)
                return
            transferred += len(chunk)
            if transferred > maximum_bytes:
                raise RelayLimitExceeded("relay方向別byte上限を超過しました")
            destination.sendall(chunk)
    except (OSError, RelayLimitExceeded):
        stop.set()
        _shutdown(source, socket.SHUT_RDWR)
        _shutdown(destination, socket.SHUT_RDWR)


def relay_connection(client: socket.socket, config: RelayConfiguration) -> None:
    """1接続をbyte無変更でUDSへ中継し、両方向へ独立上限を適用する。"""

    upstream: socket.socket | None = None
    stop = threading.Event()
    try:
        client.settimeout(config.idle_timeout)
        upstream = connect_uds(config.uds_path, config.connect_timeout)
        upstream.settimeout(config.idle_timeout)
        request_thread = threading.Thread(
            target=_copy_bounded,
            args=(client, upstream),
            kwargs={"maximum_bytes": config.max_request_bytes, "stop": stop},
            name="ghidra-mcp-request-relay",
            daemon=True,
        )
        response_thread = threading.Thread(
            target=_copy_bounded,
            args=(upstream, client),
            kwargs={"maximum_bytes": config.max_response_bytes, "stop": stop},
            name="ghidra-mcp-response-relay",
            daemon=True,
        )
        request_thread.start()
        response_thread.start()
        request_thread.join(config.idle_timeout + 1.0)
        response_thread.join(config.idle_timeout + 1.0)
        if request_thread.is_alive() or response_thread.is_alive():
            stop.set()
            _shutdown(client, socket.SHUT_RDWR)
            _shutdown(upstream, socket.SHUT_RDWR)
            request_thread.join(1.0)
            response_thread.join(1.0)
    except OSError:
        _shutdown(client, socket.SHUT_RDWR)
    finally:
        stop.set()
        if upstream is not None:
            upstream.close()
        client.close()


def serve(config: RelayConfiguration) -> None:
    """numeric loopback listenerを開始し、接続数上限を超えた接続を即時拒否する。"""

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if os.name == "nt" and hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
    listener.bind((config.listen_host, config.listen_port))
    listener.listen(config.max_connections)
    listener.settimeout(1.0)
    permits = threading.BoundedSemaphore(config.max_connections)
    futures: set[Future[None]] = set()

    def completed(future: Future[None]) -> None:
        futures.discard(future)
        permits.release()

    print(
        json.dumps(
            {
                "status": "listening",
                "listen_url": config.listen_url,
                "transport": "windows_af_unix_to_tcp",
                "max_connections": config.max_connections,
                "sample_executed": False,
                "arbitrary_ghidra_scripts_enabled": False,
            },
            ensure_ascii=False,
            sort_keys=True,
        ),
        flush=True,
    )
    try:
        with ThreadPoolExecutor(
            max_workers=config.max_connections,
            thread_name_prefix="ghidra-mcp-uds-relay",
        ) as executor:
            while True:
                try:
                    client, peer = listener.accept()
                except socket.timeout:
                    continue
                try:
                    peer_address = ipaddress.ip_address(peer[0])
                except ValueError:
                    client.close()
                    continue
                if not peer_address.is_loopback or not permits.acquire(blocking=False):
                    client.close()
                    continue
                future = executor.submit(relay_connection, client, config)
                futures.add(future)
                future.add_done_callback(completed)
    except KeyboardInterrupt:
        return
    finally:
        listener.close()


class JapaneseArgumentParser(argparse.ArgumentParser):
    """標準help見出しを日本語化する。"""

    def format_help(self) -> str:
        return (
            super()
            .format_help()
            .replace("usage:", "使用法:")
            .replace("positional arguments:", "位置引数:")
            .replace("options:", "オプション:")
            .replace("show this help message and exit", "このhelpを表示して終了します")
        )


def build_parser() -> argparse.ArgumentParser:
    parser = JapaneseArgumentParser(description=__doc__)
    parser.add_argument("--uds-path", required=True, help="Ghidra MCPのWindows AF_UNIX socket名")
    parser.add_argument("--listen-host", default=DEFAULT_LISTEN_HOST, help="127.0.0.1固定")
    parser.add_argument("--listen-port", type=int, default=DEFAULT_LISTEN_PORT)
    parser.add_argument("--connect-timeout", type=float, default=DEFAULT_CONNECT_TIMEOUT)
    parser.add_argument("--idle-timeout", type=float, default=DEFAULT_IDLE_TIMEOUT)
    parser.add_argument("--max-connections", type=int, default=DEFAULT_MAX_CONNECTIONS)
    parser.add_argument("--max-request-bytes", type=int, default=DEFAULT_MAX_REQUEST_BYTES)
    parser.add_argument("--max-response-bytes", type=int, default=DEFAULT_MAX_RESPONSE_BYTES)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        config = validate_configuration(parser.parse_args(argv))
        serve(config)
        return 0
    except RelayConfigurationError as exc:
        print(
            json.dumps(
                {"ok": False, "error": {"code": "relay_configuration_invalid", "message": str(exc)}},
                ensure_ascii=False,
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2
    except OSError as exc:
        print(
            json.dumps(
                {"ok": False, "error": {"code": "relay_transport_failed", "message": type(exc).__name__}},
                ensure_ascii=False,
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
