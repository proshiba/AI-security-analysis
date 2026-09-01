#!/usr/bin/env python3
"""PureRATのapplication frameを長時間待ち受けるloopback限定observer。"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import socket
import stat
import struct
import time
import zlib
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from emulators.common import require_loopback


EMPTY_GCLASS4_PROTOBUF = b"\x0a\x00"
DEFAULT_DURATION_SECONDS = 3600.0
MAXIMUM_DURATION_SECONDS = 24 * 60 * 60
DEFAULT_MAXIMUM_FRAMES = 1024
ABSOLUTE_MAXIMUM_FRAMES = 4096
DEFAULT_MAXIMUM_FRAME_BYTES = 64 * 1024
ABSOLUTE_MAXIMUM_FRAME_BYTES = 1024 * 1024
DEFAULT_MAXIMUM_TOTAL_BYTES = 16 * 1024 * 1024
ABSOLUTE_MAXIMUM_TOTAL_BYTES = 64 * 1024 * 1024
DEFAULT_POLL_SECONDS = 1.0
MAXIMUM_READ_CALLS = 1_000_000


class ObserverError(RuntimeError):
    """observerが契約外frameまたは安全上限で停止したことを表す。"""


class ObserverStream(Protocol):
    """socketとtest fixtureが実装する最小stream契約。"""

    def recv(self, maximum_bytes: int) -> bytes: ...

    def sendall(self, data: bytes) -> None: ...

    def settimeout(self, timeout_seconds: float) -> None: ...


@dataclass(frozen=True)
class ObservationPolicy:
    """長時間観測を無限稼働にしないための固定上限。"""

    duration_seconds: float = DEFAULT_DURATION_SECONDS
    maximum_frames: int = DEFAULT_MAXIMUM_FRAMES
    maximum_frame_bytes: int = DEFAULT_MAXIMUM_FRAME_BYTES
    maximum_total_bytes: int = DEFAULT_MAXIMUM_TOTAL_BYTES
    poll_seconds: float = DEFAULT_POLL_SECONDS

    def __post_init__(self) -> None:
        if isinstance(self.duration_seconds, bool) or not isinstance(
            self.duration_seconds, (int, float)
        ):
            raise TypeError("duration_secondsは数値で指定してください")
        if not 1.0 <= float(self.duration_seconds) <= MAXIMUM_DURATION_SECONDS:
            raise ValueError("duration_secondsは1秒から24時間に限定します")
        if isinstance(self.poll_seconds, bool) or not isinstance(
            self.poll_seconds, (int, float)
        ):
            raise TypeError("poll_secondsは数値で指定してください")
        if not 0.1 <= float(self.poll_seconds) <= 30.0:
            raise ValueError("poll_secondsは0.1秒から30秒に限定します")
        for name, maximum in (
            ("maximum_frames", ABSOLUTE_MAXIMUM_FRAMES),
            ("maximum_frame_bytes", ABSOLUTE_MAXIMUM_FRAME_BYTES),
            ("maximum_total_bytes", ABSOLUTE_MAXIMUM_TOTAL_BYTES),
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{name}は整数で指定してください")
            if not 1 <= value <= maximum:
                raise ValueError(f"{name}は1から{maximum}に限定します")
        if self.maximum_total_bytes < self.maximum_frame_bytes:
            raise ValueError("maximum_total_bytesはmaximum_frame_bytes以上が必要です")


@dataclass(frozen=True)
class FrameObservation:
    """raw command本文を保持しない1 frameの観測結果。"""

    discriminator: int
    message_type: str
    classification: str
    action: str
    frame_size: int
    frame_sha256: str
    decoded_size: int
    decoded_sha256: str
    terminate_session: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "discriminator": self.discriminator,
            "message_type": self.message_type,
            "classification": self.classification,
            "action": self.action,
            "frame_size": self.frame_size,
            "frame_sha256": self.frame_sha256,
            "decoded_size": self.decoded_size,
            "decoded_sha256": self.decoded_sha256,
            "terminate_session": self.terminate_session,
            "raw_payload_retained": False,
            "operation_executed": False,
            "reply_sent": False,
        }


@dataclass(frozen=True)
class ObservationResult:
    """長時間loopback sessionの公開可能な要約。"""

    status: str
    started_monotonic: float
    ended_monotonic: float
    registration_frame: bytes
    observations: tuple[FrameObservation, ...]
    total_inbound_bytes: int
    read_calls: int
    idle_polls: int

    def to_dict(self) -> dict[str, Any]:
        command_count = sum(
            item.classification == "command_observed_and_refused"
            for item in self.observations
        )
        return {
            "schema_version": 1,
            "family": "purehvnc",
            "variant": "purerat_4_4_1",
            "mode": "long_observation_loopback_only",
            "status": self.status,
            "duration_seconds": max(0.0, self.ended_monotonic - self.started_monotonic),
            "registration": {
                "sent": True,
                "real_identity_sent": False,
                "packet_size": len(self.registration_frame),
                "packet_sha256": hashlib.sha256(self.registration_frame).hexdigest(),
            },
            "collection": {
                "frame_count": len(self.observations),
                "command_count": command_count,
                "total_inbound_bytes": self.total_inbound_bytes,
                "read_calls": self.read_calls,
                "idle_polls": self.idle_polls,
            },
            "observations": [item.to_dict() for item in self.observations],
            "safety": {
                "loopback_only": True,
                "single_connection": True,
                "reconnect_allowed": False,
                "sample_executed": False,
                "operation_executed": False,
                "command_reply_sent": False,
                "plugin_or_file_retained": False,
                "configuration_applied": False,
                "raw_payload_retained": False,
                "application_send_count": 1,
            },
        }


def build_empty_registration_frame() -> bytes:
    """匿名の空GClass4をLE32／GZip frameへ変換する。"""

    compressed = gzip.compress(EMPTY_GCLASS4_PROTOBUF, mtime=0)
    return struct.pack("<I", len(compressed)) + compressed


def build_fixture_frame(payload: bytes) -> bytes:
    """offline／loopback test専用のLE32／GZip frameを構築する。"""

    if not isinstance(payload, bytes):
        raise TypeError("payloadはbytesで指定してください")
    compressed = gzip.compress(payload, mtime=0)
    return struct.pack("<I", len(compressed)) + compressed


def _read_varint(data: bytes, offset: int = 0) -> tuple[int, int]:
    value = 0
    shift = 0
    for index in range(offset, min(len(data), offset + 10)):
        current = data[index]
        value |= (current & 0x7F) << shift
        if current < 0x80:
            return value, index + 1
        shift += 7
    raise ObserverError("protobuf discriminator varintが不正です")


def _bounded_gzip_decompress(data: bytes, maximum_size: int) -> bytes:
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        clear = decoder.decompress(data, maximum_size + 1)
        if len(clear) > maximum_size or decoder.unconsumed_tail:
            raise ObserverError("展開後payloadが上限を超えました")
        clear += decoder.flush(maximum_size + 1 - len(clear))
    except zlib.error as exc:
        raise ObserverError("GZip payloadが不正です") from exc
    if len(clear) > maximum_size:
        raise ObserverError("展開後payloadが上限を超えました")
    if not decoder.eof or decoder.unused_data:
        raise ObserverError("GZip payloadがtruncateまたは連結されています")
    return clear


def classify_frame(raw_frame: bytes, *, maximum_frame_bytes: int) -> FrameObservation:
    """frame本文を返さず、最初のprotobuf fieldだけを分類する。"""

    if not isinstance(raw_frame, bytes) or len(raw_frame) < 5:
        raise ObserverError("frameが短すぎます")
    if len(raw_frame) > maximum_frame_bytes:
        raise ObserverError("frameが上限を超えました")
    declared = struct.unpack("<I", raw_frame[:4])[0]
    if declared != len(raw_frame) - 4:
        raise ObserverError("LE32 frame長が実長と一致しません")
    decoded = _bounded_gzip_decompress(raw_frame[4:], maximum_frame_bytes)
    if not decoded:
        raise ObserverError("protobuf payloadが空です")
    key, _offset = _read_varint(decoded)
    discriminator = key >> 3
    wire_type = key & 7
    if discriminator <= 0 or wire_type != 2:
        raise ObserverError("ProtoInclude discriminatorが不正です")

    mapping = {
        1: ("registration", "unexpected_client_message", "record_and_stop", True),
        2: ("heartbeat", "heartbeat_observed", "record_and_continue", False),
        3: ("status_or_error", "status_observed", "record_and_continue", False),
        4: ("plugin_result", "unexpected_client_message", "record_and_stop", True),
        5: ("plugin_request", "plugin_request_observed_and_refused", "record_and_stop", True),
        35: ("auxiliary", "auxiliary_message_observed", "record_and_continue", False),
        38: ("configuration_update", "configuration_update_observed_and_refused", "record_and_stop", True),
        86: ("command", "command_observed_and_refused", "record_and_stop", True),
    }
    message_type, classification, action, terminate = mapping.get(
        discriminator,
        ("unknown", "unknown_discriminator_rejected", "record_and_stop", True),
    )
    return FrameObservation(
        discriminator=discriminator,
        message_type=message_type,
        classification=classification,
        action=action,
        frame_size=len(raw_frame),
        frame_sha256=hashlib.sha256(raw_frame).hexdigest(),
        decoded_size=len(decoded),
        decoded_sha256=hashlib.sha256(decoded).hexdigest(),
        terminate_session=terminate,
    )


class _FrameReader:
    """timeoutをまたいで部分frameを保持する有界reader。"""

    def __init__(self) -> None:
        self.buffer = bytearray()
        self.total_bytes = 0
        self.read_calls = 0
        self.peer_closed = False

    def receive(
        self,
        stream: ObserverStream,
        *,
        policy: ObservationPolicy,
    ) -> bytes | None:
        while True:
            expected = 4
            if len(self.buffer) >= 4:
                declared = struct.unpack("<I", self.buffer[:4])[0]
                if declared < 1 or declared + 4 > policy.maximum_frame_bytes:
                    raise ObserverError("宣言frame長が上限外です")
                expected = declared + 4
                if len(self.buffer) >= expected:
                    frame = bytes(self.buffer[:expected])
                    del self.buffer[:expected]
                    return frame
            if self.read_calls >= MAXIMUM_READ_CALLS:
                raise ObserverError("read call上限へ到達しました")
            remaining_total = policy.maximum_total_bytes - self.total_bytes
            if remaining_total <= 0:
                raise ObserverError("総受信byte上限へ到達しました")
            request = min(max(1, expected - len(self.buffer)), 65_536, remaining_total)
            try:
                chunk = stream.recv(request)
            except (TimeoutError, socket.timeout):
                return None
            self.read_calls += 1
            if not isinstance(chunk, bytes) or len(chunk) > request:
                raise ObserverError("stream.recvが契約外の値を返しました")
            if not chunk:
                self.peer_closed = True
                if self.buffer:
                    raise ObserverError("peerがframe途中で切断しました")
                return b""
            self.buffer.extend(chunk)
            self.total_bytes += len(chunk)


def observe_connected_stream(
    stream: ObserverStream,
    *,
    policy: ObservationPolicy | None = None,
    stop_requested: Callable[[], bool] | None = None,
    event_callback: Callable[[dict[str, Any]], None] | None = None,
    monotonic: Callable[[], float] = time.monotonic,
) -> ObservationResult:
    """既にloopbackへ接続済みのstreamを単一sessionだけ観測する。"""

    active = policy or ObservationPolicy()
    should_stop = stop_requested or (lambda: False)
    started = monotonic()
    deadline = started + float(active.duration_seconds)
    stream.settimeout(float(active.poll_seconds))
    registration = build_empty_registration_frame()
    stream.sendall(registration)
    if event_callback is not None:
        event_callback(
            {
                "event": "registration_sent",
                "packet_size": len(registration),
                "packet_sha256": hashlib.sha256(registration).hexdigest(),
                "real_identity_sent": False,
            }
        )

    reader = _FrameReader()
    observations: list[FrameObservation] = []
    idle_polls = 0
    status = "duration_limit_reached"
    while monotonic() < deadline:
        if should_stop():
            status = "kill_switch_released"
            break
        if len(observations) >= active.maximum_frames:
            status = "frame_limit_reached"
            break
        frame = reader.receive(stream, policy=active)
        if frame is None:
            idle_polls += 1
            continue
        if not frame:
            status = "peer_closed"
            break
        observation = classify_frame(
            frame,
            maximum_frame_bytes=active.maximum_frame_bytes,
        )
        observations.append(observation)
        if event_callback is not None:
            event_callback({"event": "frame_observed", **observation.to_dict()})
        if observation.terminate_session:
            status = "sensitive_frame_observed"
            break

    ended = monotonic()
    result = ObservationResult(
        status=status,
        started_monotonic=started,
        ended_monotonic=ended,
        registration_frame=registration,
        observations=tuple(observations),
        total_inbound_bytes=reader.total_bytes,
        read_calls=reader.read_calls,
        idle_polls=idle_polls,
    )
    if event_callback is not None:
        event_callback({"event": "session_stopped", **result.to_dict()})
    return result


class KillSwitch:
    """同一の通常fileが存在する間だけ観測を継続する。"""

    def __init__(self, path: Path) -> None:
        if not path.is_absolute():
            raise ValueError("kill-switch fileは絶対pathで指定してください")
        self.path = path
        self.identity = self._identity()

    def _identity(self) -> tuple[int, int, int, int]:
        metadata = self.path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or self.path.is_symlink():
            raise ValueError("kill-switch fileは通常fileである必要があります")
        return (
            int(metadata.st_dev),
            int(metadata.st_ino),
            int(metadata.st_size),
            int(metadata.st_mtime_ns),
        )

    def released(self) -> bool:
        try:
            return self._identity() != self.identity
        except OSError:
            return True


class RotatingJsonlLogger:
    """raw payloadを受け取らない小容量JSONL logger。"""

    def __init__(self, path: Path, *, maximum_bytes: int, backups: int = 3) -> None:
        if not path.is_absolute():
            raise ValueError("log pathは絶対pathで指定してください")
        if path.exists() or path.is_symlink():
            raise FileExistsError(f"既存logを上書きしません: {path}")
        if not path.parent.is_dir():
            raise ValueError("log parent directoryがありません")
        if not 4096 <= maximum_bytes <= 64 * 1024 * 1024:
            raise ValueError("log上限は4 KiBから64 MiBに限定します")
        if not 1 <= backups <= 10:
            raise ValueError("backup数は1から10に限定します")
        self.path = path
        self.maximum_bytes = maximum_bytes
        self.backups = backups

    @staticmethod
    def _regular_size(path: Path) -> int:
        if not path.exists() and not path.is_symlink():
            return 0
        metadata = path.lstat()
        if (
            path.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
        ):
            raise ObserverError(f"logまたはbackupが通常fileではありません: {path}")
        return int(metadata.st_size)

    def _rotate(self) -> None:
        oldest = self.path.with_name(f"{self.path.name}.{self.backups}")
        if self._regular_size(oldest):
            oldest.unlink()
        for index in range(self.backups - 1, 0, -1):
            source = self.path.with_name(f"{self.path.name}.{index}")
            if self._regular_size(source):
                source.replace(self.path.with_name(f"{self.path.name}.{index + 1}"))
        if self._regular_size(self.path):
            self.path.replace(self.path.with_name(f"{self.path.name}.1"))

    def __call__(self, event: dict[str, Any]) -> None:
        record = {"recorded_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), **event}
        encoded = (json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
        if len(encoded) > self.maximum_bytes:
            raise ObserverError("単一log eventがrotation上限を超えました")
        if self._regular_size(self.path) + len(encoded) > self.maximum_bytes:
            self._rotate()
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(self.path, flags, 0o600)
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise ObserverError("open後のlogが単一の通常fileではありません")
            os.write(descriptor, encoded)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def connect_loopback(host: str, port: int, *, timeout: float) -> socket.socket:
    """DNSを使わずnumeric loopbackへ1回だけ接続する。"""

    canonical = require_loopback(host, "PureRAT observer")
    if not 1 <= port <= 65_535:
        raise ValueError("portは1から65535に限定します")
    return socket.create_connection((canonical, port), timeout=timeout)


def main() -> int:
    """loopback observer CLIを起動し、終了時に公開要約を表示する。"""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--duration-seconds", type=float, default=DEFAULT_DURATION_SECONDS)
    parser.add_argument("--maximum-frames", type=int, default=DEFAULT_MAXIMUM_FRAMES)
    parser.add_argument("--maximum-frame-bytes", type=int, default=DEFAULT_MAXIMUM_FRAME_BYTES)
    parser.add_argument("--maximum-total-bytes", type=int, default=DEFAULT_MAXIMUM_TOTAL_BYTES)
    parser.add_argument("--poll-seconds", type=float, default=DEFAULT_POLL_SECONDS)
    parser.add_argument("--kill-switch-file", type=Path, required=True)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--log-maximum-bytes", type=int, default=4 * 1024 * 1024)
    args = parser.parse_args()

    policy = ObservationPolicy(
        duration_seconds=args.duration_seconds,
        maximum_frames=args.maximum_frames,
        maximum_frame_bytes=args.maximum_frame_bytes,
        maximum_total_bytes=args.maximum_total_bytes,
        poll_seconds=args.poll_seconds,
    )
    kill_switch = KillSwitch(args.kill_switch_file)
    logger = RotatingJsonlLogger(args.log, maximum_bytes=args.log_maximum_bytes)
    with connect_loopback(args.host, args.port, timeout=args.poll_seconds) as stream:
        result = observe_connected_stream(
            stream,
            policy=policy,
            stop_requested=kill_switch.released,
            event_callback=logger,
        )
    print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
