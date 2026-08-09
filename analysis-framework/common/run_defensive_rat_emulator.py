#!/usr/bin/env python3
"""レビュー済みprofileだけで防御用RAT host sessionを有界実行する。"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import ipaddress
import json
import os
import socket
import ssl
import stat
import struct
import sys
import time
import uuid
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from immutable_snapshot import ensure_new_output, read_bounded_snapshot, write_new_json
from rat_emulator_live_leases import (
    LiveLease,
    LiveLeaseRegistrySnapshot,
    RatEmulatorLiveLeaseError,
    resolve_active_live_lease,
)
from rat_emulator_profiles import (
    RatEmulatorProfileError,
    RegistrySnapshot,
    load_registry,
    resolve_profile,
)
from rat_emulator_transcript import (
    RatEmulatorTranscriptError,
    SessionTranscriptWriter,
    build_public_summary,
)
from safe_private_output import reject_existing_reparse_components

MAXMIND_MAXIMUM_BUILD_AGE_HOURS = 24.0
KILL_SWITCH_MAXIMUM_BYTES = 256
FILE_ATTRIBUTE_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
ADAPTER_PATHS = {
    "tls_messagepack_rat_host": (
        "analysis-framework",
        "common",
        "tls_messagepack_rat_host_emulator.py",
    ),
    "valleyrat_n520_v1": (
        "analysis-framework",
        "malware",
        "valleyrat",
        "n520_host_emulator.py",
    ),
}
HOST_ADAPTER_CONTRACT_VERSION = 1


class RatHostAdapter(Protocol):
    """将来のClientInfo登録adapterも従う共通callable契約。"""

    def run_host_session(
        self,
        stream: Any,
        profile: Mapping[str, Any] | None = None,
        *,
        session_limits: Mapping[str, int | float],
        allow_registration: bool,
        allow_heartbeat_request: bool = False,
        transcript_callback: Callable[[dict[str, Any]], None] | None = None,
    ) -> dict[str, Any]: ...


class RatEmulatorRunError(RuntimeError):
    """live sessionの明示承認、安全上限、証拠pinの不一致を表す。"""


class TlsCertificatePinMismatch(RatEmulatorRunError):
    """TLS stopped before registration because the reviewed leaf pin changed."""

    def __init__(self, expected_sha256: str, observed_sha256: str) -> None:
        super().__init__("TLS leaf certificate SHA-256 pin mismatch")
        self.expected_sha256 = expected_sha256
        self.observed_sha256 = observed_sha256


def repository_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _absolute(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _is_within(path: Path, root: Path) -> bool:
    try:
        return os.path.commonpath(
            [os.path.normcase(str(_absolute(path))), os.path.normcase(str(_absolute(root)))]
        ) == os.path.normcase(str(_absolute(root)))
    except ValueError:
        return False


def validate_private_locations(
    private_output_directory: Path,
    maxmind_cache_directory: Path,
) -> None:
    """network前にprivate出力とMaxMind cacheがrepository外かを検証する。"""

    root = repository_root()
    for path, label in (
        (private_output_directory, "private transcript"),
        (maxmind_cache_directory, "MaxMind cache"),
    ):
        if not path.is_absolute():
            raise RatEmulatorRunError(f"{label}は絶対pathで指定してください")
        if _is_within(path, root):
            raise RatEmulatorRunError(f"{label}をrepository配下へ保存できません")
    output = _absolute(private_output_directory)
    if output.exists() or output.is_symlink():
        raise FileExistsError(f"既存の通信記録directoryは上書きしません: {output}")
    reject_existing_reparse_components(output.parent)
    if not output.parent.is_dir():
        raise RatEmulatorRunError("private transcriptのparent directoryがありません")


def _checked_regular_file(path: Path, maximum_bytes: int) -> tuple[int, int, int, int]:
    reject_existing_reparse_components(path)
    read_bounded_snapshot(path, maximum_bytes)
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or path.is_symlink()
        or int(getattr(metadata, "st_file_attributes", 0)) & FILE_ATTRIBUTE_REPARSE_POINT
        or metadata.st_nlink != 1
    ):
        raise RatEmulatorRunError("kill-switchは単一の通常fileである必要があります")
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_size),
        int(metadata.st_mtime_ns),
    )


class KillSwitch:
    """存在とidentityを維持している間だけsessionを許可する停止用file。"""

    def __init__(self, path: Path) -> None:
        if not path.is_absolute():
            raise RatEmulatorRunError("kill-switchは絶対pathで指定してください")
        self.path = _absolute(path)
        try:
            self.identity = _checked_regular_file(self.path, KILL_SWITCH_MAXIMUM_BYTES)
        except (OSError, ValueError) as exc:
            raise RatEmulatorRunError(f"有効なkill-switch fileが必要です: {exc}") from exc

    def require_armed(self) -> None:
        try:
            current = _checked_regular_file(self.path, KILL_SWITCH_MAXIMUM_BYTES)
        except (OSError, ValueError) as exc:
            raise RatEmulatorRunError("kill-switchが解除されたためsessionを停止します") from exc
        if current != self.identity:
            raise RatEmulatorRunError("kill-switchのidentityが変化したためsessionを停止します")


def require_live_gates(
    profile: Mapping[str, Any],
    *,
    allow_network: bool,
    allow_live_c2_emulation: bool,
    acknowledged_profile: str | None,
    kill_switch_path: Path | None,
) -> KillSwitch:
    """live接続前に三段階承認と継続監視可能なkill-switchを検証する。"""

    if not allow_network:
        raise RatEmulatorRunError("--allow-networkが必要です")
    if not allow_live_c2_emulation:
        raise RatEmulatorRunError("--allow-live-c2-emulationが必要です")
    if acknowledged_profile != profile["profile_id"]:
        raise RatEmulatorRunError("--acknowledge-profileは完全一致profile IDで指定してください")
    if kill_switch_path is None:
        raise RatEmulatorRunError("--kill-switch-fileが必要です")
    if profile.get("allow_live_fake_results") is not False:
        raise RatEmulatorRunError("初期live profileは偽実行結果の送信を許可できません")
    return KillSwitch(kill_switch_path)


def resolve_single_pinned_ip(
    profile: Mapping[str, Any],
    *,
    resolver: Callable[..., list[tuple[Any, ...]]] = socket.getaddrinfo,
) -> tuple[str, list[str]]:
    """DNS結果を記録するが、接続先はprofileの単一pinだけに固定する。"""

    pinned = profile.get("pinned_ips")
    if not isinstance(pinned, list) or len(pinned) != 1:
        raise RatEmulatorRunError("profileには単一pinned IPが必要です")
    pinned_ip = str(ipaddress.ip_address(pinned[0]))
    host = str(profile["host"])
    try:
        endpoint_ip = str(ipaddress.ip_address(host))
    except ValueError:
        try:
            answers = resolver(host, int(profile["port"]), type=socket.SOCK_STREAM)
        except OSError as exc:
            raise RatEmulatorRunError("profile hostのDNS解決に失敗しました") from exc
        resolved: set[str] = set()
        for answer in answers:
            try:
                address = ipaddress.ip_address(str(answer[4][0]))
            except (IndexError, TypeError, ValueError):
                continue
            if address.is_global:
                resolved.add(address.compressed)
        if pinned_ip not in resolved:
            raise RatEmulatorRunError("DNS結果にprofileのpinned IPが含まれません")
        return pinned_ip, sorted(resolved)
    if endpoint_ip != pinned_ip:
        raise RatEmulatorRunError("IP endpointとpinned IPが一致しません")
    return pinned_ip, [pinned_ip]


def prepare_maxmind(cache_directory: Path, pinned_ip: str) -> dict[str, Any]:
    """接続前にCity/ASN DBを24時間基準で確認・更新し、対象IPを照合する。"""

    if not cache_directory.is_absolute():
        raise RatEmulatorRunError("MaxMind cache directoryは絶対pathで指定してください")
    try:
        from run_c2_monitoring_pipeline import (
            acquire_private_databases,
            enrich_with_acquired_databases,
        )

        acquired, freshness = acquire_private_databases(
            _absolute(cache_directory),
            max_build_age_hours=MAXMIND_MAXIMUM_BUILD_AGE_HOURS,
        )
        if not freshness.get("checked_before_live_check"):
            raise RatEmulatorRunError("MaxMind DB鮮度を接続前に確認できませんでした")
        for _path, acquisition in acquired.values():
            if acquisition.get("official_checksum_verified") is not True:
                raise RatEmulatorRunError("MaxMind DBの公式checksum検証を確認できません")
        monitoring = {"results": [{"observation": {"resolved_ips": [pinned_ip]}}]}
        enriched, summary = enrich_with_acquired_databases(monitoring, acquired, freshness)
        records = enriched["results"][0]["maxmind"]["records"]
    except RatEmulatorRunError:
        raise
    except (ImportError, OSError, RuntimeError, ValueError) as exc:
        raise RatEmulatorRunError(f"MaxMind鮮度確認に失敗しました: {exc}") from exc
    return {
        "freshness_policy": summary["freshness_policy"],
        "city_build_time_utc": summary["city_build_time_utc"],
        "asn_build_time_utc": summary["asn_build_time_utc"],
        "ip_record": records[0] if records else {"ip": pinned_ip, "geo": None, "as": None},
        "attribution": (
            "This product includes GeoLite2 Data created by MaxMind, "
            "available from https://www.maxmind.com."
        ),
    }


def open_pinned_tls_stream(
    profile: Mapping[str, Any],
    pinned_ip: str,
    *,
    connector: Callable[..., socket.socket] = socket.create_connection,
) -> tuple[Any, str]:
    """単一pinへTLS 1.2で1回だけ接続し、leaf certificate hashを固定する。"""

    timeout = min(float(profile["limits"]["duration_seconds"]), 30.0)
    raw = connector((pinned_ip, int(profile["port"])), timeout=timeout)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    try:
        stream = context.wrap_socket(raw, server_hostname=str(profile["sni"]))
        certificate = stream.getpeercert(binary_form=True)
        digest = hashlib.sha256(certificate or b"").hexdigest()
        if digest != profile["expected_certificate_sha256"]:
            stream.close()
            raise TlsCertificatePinMismatch(
                str(profile["expected_certificate_sha256"]), digest
            )
        return stream, digest
    except BaseException:
        try:
            raw.close()
        except OSError:
            pass
        raise


class GuardedStream:
    """adapterの全send/recvへduration、kill-switch、byte/frame上限を強制する。"""

    def __init__(
        self,
        stream: Any,
        *,
        limits: Mapping[str, int | float],
        kill_switch: KillSwitch,
        transcript: SessionTranscriptWriter,
        monotonic: Callable[[], float] = time.monotonic,
        lease_deadline_monotonic: float | None = None,
    ) -> None:
        self.stream = stream
        self.limits = dict(limits)
        self.kill_switch = kill_switch
        self.transcript = transcript
        self.monotonic = monotonic
        self.started = monotonic()
        session_deadline = self.started + float(self.limits["duration_seconds"])
        self.deadline = (
            session_deadline
            if lease_deadline_monotonic is None
            else min(session_deadline, float(lease_deadline_monotonic))
        )
        self.inbound_frames = 0
        self.inbound_read_calls = 0
        self.inbound_bytes = 0
        self.outbound_frames = 0
        self.outbound_bytes = 0
        self.last_send: float | None = None
        self.requested_timeout_seconds: float | None = None

    def _check(self) -> None:
        self.kill_switch.require_armed()
        if self.monotonic() >= self.deadline:
            raise RatEmulatorRunError("sessionまたは短期live leaseの期限へ到達しました")

    def _refresh_timeout(self) -> None:
        """次のI/O直前に残時間以下へtransport timeoutを再設定する。"""

        self._check()
        if self.requested_timeout_seconds is None:
            return
        remaining = self.deadline - self.monotonic()
        effective = min(self.requested_timeout_seconds, remaining)
        if effective <= 0:
            raise RatEmulatorRunError("短期live lease期限後のI/Oを拒否しました")
        self.stream.settimeout(effective)

    def settimeout(self, timeout_seconds: float) -> None:
        requested = float(timeout_seconds)
        if requested <= 0:
            raise RatEmulatorRunError("stream timeoutは正の秒数で指定してください")
        self.requested_timeout_seconds = requested
        self._refresh_timeout()

    def recv(self, maximum_bytes: int) -> bytes:
        self._refresh_timeout()
        if self.inbound_read_calls >= int(self.limits["maximum_inbound_read_calls"]):
            raise RatEmulatorRunError("inbound read-call limit reached")
        if self.inbound_frames >= int(self.limits["maximum_inbound_frames"]):
            raise RatEmulatorRunError("inbound frame上限へ到達しました")
        remaining = int(self.limits["maximum_inbound_bytes"]) - self.inbound_bytes
        request = min(int(maximum_bytes), int(self.limits["maximum_frame_bytes"]), remaining + 1)
        if request <= 0:
            raise RatEmulatorRunError("inbound byte上限へ到達しました")
        chunk = self.stream.recv(request)
        self.inbound_read_calls += 1
        if not isinstance(chunk, bytes):
            raise RatEmulatorRunError("stream.recvがbytes以外を返しました")
        if not chunk:
            return b""
        self.inbound_frames += 1
        self.inbound_bytes += len(chunk)
        if self.inbound_bytes > int(self.limits["maximum_inbound_bytes"]):
            raise RatEmulatorRunError("inbound byte上限を超えました")
        digest = hashlib.sha256(chunk).hexdigest()
        if self.outbound_frames == 0:
            self.transcript.append_event(
                "inbound",
                "transport_pre_registration_frame",
                raw_frame=chunk,
                public_fields={"size": len(chunk), "sha256": digest},
            )
        else:
            # command-16/18等のfile-transferを保持しないため、登録後はhashだけを残す。
            self.transcript.append_event(
                "inbound",
                "transport_post_registration_chunk",
                public_fields={"size": len(chunk), "sha256": digest, "raw_retained": False},
            )
        return chunk

    def recv_application_frame(self, maximum_frame_bytes: int) -> bytes:
        """Read one length-prefixed frame with separately bounded transport reads."""

        self._refresh_timeout()
        if self.inbound_frames >= int(self.limits["maximum_inbound_frames"]):
            raise RatEmulatorRunError("inbound application-frame limit reached")
        remaining = int(self.limits["maximum_inbound_bytes"]) - self.inbound_bytes
        frame_limit = min(
            int(maximum_frame_bytes),
            int(self.limits["maximum_frame_bytes"]),
            remaining,
        )
        if frame_limit < 5:
            raise RatEmulatorRunError("inbound application-frame byte limit reached")

        frame = bytearray()

        def read_exact(size: int) -> bool:
            while len(frame) < size:
                self._refresh_timeout()
                if self.inbound_read_calls >= int(
                    self.limits["maximum_inbound_read_calls"]
                ):
                    raise RatEmulatorRunError("inbound read-call limit reached")
                request = size - len(frame)
                chunk = self.stream.recv(request)
                self.inbound_read_calls += 1
                if not isinstance(chunk, bytes):
                    raise RatEmulatorRunError("stream.recv must return bytes")
                if len(chunk) > request:
                    raise RatEmulatorRunError("stream.recv returned more bytes than requested")
                if not chunk:
                    return False
                frame.extend(chunk)
                self.inbound_bytes += len(chunk)
                if self.inbound_bytes > int(self.limits["maximum_inbound_bytes"]):
                    raise RatEmulatorRunError("inbound byte limit reached")
            return True

        if not read_exact(4):
            if frame:
                raise RatEmulatorRunError("stream closed during application-frame header")
            return b""
        declared = struct.unpack("<I", frame[:4])[0]
        total_size = 4 + declared
        if declared < 1 or total_size > frame_limit:
            raise RatEmulatorRunError("declared application frame exceeds its reviewed limit")
        if not read_exact(total_size):
            raise RatEmulatorRunError("stream closed during application frame")

        self.inbound_frames += 1
        wire = bytes(frame)
        public_fields = {
            "size": len(wire),
            "sha256": hashlib.sha256(wire).hexdigest(),
        }
        if self.outbound_frames == 0:
            self.transcript.append_event(
                "inbound",
                "transport_pre_registration_frame",
                raw_frame=wire,
                public_fields=public_fields,
            )
        else:
            self.transcript.append_event(
                "inbound",
                "transport_post_registration_frame",
                public_fields={**public_fields, "raw_retained": False},
            )
        return wire

    def sendall(self, data: bytes) -> None:
        self._refresh_timeout()
        if not isinstance(data, bytes):
            raise RatEmulatorRunError("stream.sendallはbytesだけを許可します")
        if self.outbound_frames >= int(self.limits["maximum_outbound_frames"]):
            raise RatEmulatorRunError("outbound frame上限へ到達しました")
        if len(data) > int(self.limits["maximum_frame_bytes"]):
            raise RatEmulatorRunError("outbound frame上限を超えました")
        if self.outbound_bytes + len(data) > int(self.limits["maximum_outbound_bytes"]):
            raise RatEmulatorRunError("outbound byte上限を超えました")
        now = self.monotonic()
        if self.last_send is not None and now - self.last_send < float(
            self.limits["minimum_send_interval_seconds"]
        ):
            raise RatEmulatorRunError("送信間隔下限を満たしません")
        self.stream.sendall(data)
        self.outbound_frames += 1
        self.outbound_bytes += len(data)
        self.last_send = now
        event_type = (
            "reviewed_registration_frame"
            if self.outbound_frames == 1
            else "reviewed_fixed_heartbeat_request_frame"
        )
        self.transcript.append_event(
            "outbound",
            event_type,
            raw_frame=data,
            public_fields={
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "real_identity_sent": False,
                "synthetic": True,
                "synthetic_request_sent": self.outbound_frames == 2,
            },
        )

    def close(self) -> None:
        self.stream.close()


def _load_adapter(adapter_id: str) -> Any:
    parts = ADAPTER_PATHS.get(adapter_id)
    if parts is None:
        raise RatEmulatorRunError(f"未レビューのadapter IDです: {adapter_id}")
    path = repository_root().joinpath(*parts)
    module_name = f"_defensive_rat_adapter_{adapter_id}"
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RatEmulatorRunError("adapterを読み込めません")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except (ImportError, OSError, ValueError) as exc:
        raise RatEmulatorRunError(f"adapterを検証できません: {exc}") from exc
    if not callable(getattr(module, "run_host_session", None)):
        raise RatEmulatorRunError("adapterにrun_host_sessionがありません")
    return module


def _adapter_event_callback(
    transcript: SessionTranscriptWriter,
) -> Callable[[dict[str, Any]], None]:
    public_keys = {
        "command",
        "sequence",
        "payload_size",
        "packet_size",
        "packet_sha256",
        "real_identity_sent",
        "response_size",
        "response_sha256",
        "frame_count",
        "remainder_size",
        "classification",
        "direction",
        "action",
        "reason",
        "should_respond",
        "terminate_session",
        "transfer_refused",
        "status",
        "fake_result_sent",
        "header_matches",
        "handshake_size",
        "opcode",
        "packet_kind",
        "frame_size",
        "frame_sha256",
        "decoded_size",
        "decoded_sha256",
        "sent",
        "synthetic",
        "synthetic_request_sent",
    }

    def callback(event: dict[str, Any]) -> None:
        name = str(event.get("event") or "adapter_event")
        public = {key: value for key, value in event.items() if key in public_keys}
        fingerprint = event.get("fingerprint")
        if isinstance(fingerprint, dict):
            for key in ("frame_size", "frame_sha256", "decoded_size", "decoded_sha256"):
                if key in fingerprint:
                    public[key] = fingerprint[key]
            private = {"fingerprint": fingerprint}
        else:
            private = {}
        transcript.append_event(
            "internal",
            name,
            public_fields=public,
            private_fields=private,
        )

    return callback


def _run_adapter(
    profile: Mapping[str, Any],
    stream: GuardedStream,
    callback: Callable[[dict[str, Any]], None],
) -> dict[str, Any]:
    adapter = _load_adapter(str(profile["adapter_id"]))
    limits = profile["limits"]
    if profile["adapter_id"] == "tls_messagepack_rat_host":
        return adapter.run_host_session(
            stream,
            profile,
            session_limits={
                "timeout_seconds": min(5.0, float(limits["duration_seconds"])),
                "maximum_frame_bytes": int(limits["maximum_frame_bytes"]),
                "maximum_decoded_bytes": int(limits["maximum_inbound_bytes"]),
                "maximum_binary_bytes": int(limits["maximum_inbound_bytes"]),
                "maximum_read_calls": int(limits["maximum_inbound_read_calls"]),
                "maximum_send_bytes": int(limits["maximum_outbound_bytes"]),
                "maximum_frames": int(limits["maximum_inbound_frames"]),
                "maximum_commands": int(limits["maximum_commands"]),
            },
            allow_registration=True,
            allow_heartbeat_request=True,
            transcript_callback=callback,
        )
    return adapter.run_host_session(
        stream,
        session_limits={
            "timeout_seconds": min(5.0, float(limits["duration_seconds"])),
            "maximum_response_bytes": int(limits["maximum_inbound_bytes"]),
            "maximum_frames": int(limits["maximum_commands"]),
            "maximum_read_calls": int(limits["maximum_inbound_read_calls"]),
            "read_chunk_bytes": int(limits["maximum_frame_bytes"]),
        },
        allow_registration=True,
        transcript_callback=callback,
    )


def _public_adapter_result(
    result: Mapping[str, Any], profile: Mapping[str, Any] | None = None
) -> dict[str, Any]:
    registration = result.get("registration") if isinstance(result.get("registration"), dict) else {}
    collection = result.get("collection") if isinstance(result.get("collection"), dict) else {}
    safety = result.get("safety") if isinstance(result.get("safety"), dict) else {}
    decisions = result.get("decisions") if isinstance(result.get("decisions"), list) else []
    command = result.get("command") if isinstance(result.get("command"), dict) else None
    certificate_policy = (
        profile.get("certificate_mismatch_is_negative_evidence")
        if isinstance(profile, Mapping)
        else None
    )
    if command is not None:
        fingerprint = command.get("fingerprint")
        fingerprint = fingerprint if isinstance(fingerprint, dict) else {}
        public_command = {
            "command": command.get("opcode"),
            "opcode": command.get("opcode"),
            "classification": command.get("packet_kind"),
            "packet_kind": command.get("packet_kind"),
            "action": command.get("action"),
            "should_respond": command.get("should_respond"),
            "terminate_session": command.get("terminate_session"),
            "frame_size": fingerprint.get("frame_size"),
            "frame_sha256": fingerprint.get("frame_sha256"),
            "decoded_size": fingerprint.get("decoded_size"),
            "decoded_sha256": fingerprint.get("decoded_sha256"),
        }
        heartbeat = (
            result.get("heartbeat_request")
            if isinstance(result.get("heartbeat_request"), dict)
            else {}
        )
        return {
            "schema_version": 1,
            "family": result.get("family"),
            "protocol": result.get("protocol"),
            "status": result.get("status"),
            "certificate_mismatch_is_negative_evidence": certificate_policy,
            "registration": {
                key: registration.get(key)
                for key in (
                    "packet_kind",
                    "opcode",
                    "frame_size",
                    "frame_sha256",
                    "decoded_size",
                    "decoded_sha256",
                    "synthetic",
                )
            },
            "collection": dict(collection),
            "command": public_command,
            "decisions": [public_command],
            "heartbeat_request": {
                key: heartbeat.get(key)
                for key in (
                    "packet_kind",
                    "opcode",
                    "sent",
                    "synthetic",
                    "frame_size",
                    "frame_sha256",
                    "decoded_size",
                    "decoded_sha256",
                )
            },
            "safety": dict(safety),
        }
    return {
        "schema_version": 1,
        "family": result.get("family"),
        "protocol": result.get("protocol"),
        "status": result.get("status"),
        "certificate_mismatch_is_negative_evidence": certificate_policy,
        "registration": {
            key: registration.get(key)
            for key in (
                "sent",
                "command",
                "sequence",
                "payload_size",
                "real_identity_sent",
                "packet_size",
                "packet_sha256",
            )
        },
        "collection": dict(collection),
        "decisions": [
            {
                **{
                    key: decision.get(key)
                    for key in (
                        "command",
                        "classification",
                        "direction",
                        "action",
                        "reason",
                        "should_respond",
                        "terminate_session",
                        "transfer_refused",
                    )
                },
                "frame_sha256": (
                    decision.get("fingerprint", {}).get("frame_sha256")
                    if isinstance(decision.get("fingerprint"), dict)
                    else None
                ),
                "frame_size": (
                    decision.get("fingerprint", {}).get("frame_size")
                    if isinstance(decision.get("fingerprint"), dict)
                    else None
                ),
            }
            for decision in decisions
            if isinstance(decision, dict)
        ],
        "safety": dict(safety),
    }


def _write_public_output(path: Path | None, document: dict[str, Any]) -> None:
    if path is None:
        return
    target = ensure_new_output(path, ())
    write_new_json(target, document)


def _effective_lease_time(value: datetime | None) -> datetime:
    """1回の検証で使うUTC時刻を固定する。"""

    return datetime.now(UTC) if value is None else value


def _require_live_lease_deadline(
    deadline_monotonic: float,
    monotonic: Callable[[], float],
) -> float:
    """lease期限までの正の秒数を返し、期限到達時は停止する。"""

    remaining = float(deadline_monotonic) - monotonic()
    if remaining <= 0:
        raise RatEmulatorRunError("短期live leaseがsession開始前に期限切れになりました")
    return remaining


def _public_live_lease(
    registry: LiveLeaseRegistrySnapshot,
    lease: LiveLease,
) -> dict[str, str]:
    """公開可能なlease registry pinとreview情報を返す。"""

    return {
        "source": registry.source,
        "sha256": registry.sha256,
        "reviewed_at_utc": lease.reviewed_at_utc,
        "expires_at_utc": lease.expires_at_utc,
        "review_owner": lease.review_owner,
    }


def preflight(
    profile_id: str,
    *,
    lease_now_utc: datetime | None = None,
) -> dict[str, Any]:
    """networkを使わずprofile証拠と現在有効な短期leaseを検証する。"""

    registry = load_registry()
    profile = registry.profiles.get(profile_id)
    if profile is None:
        raise RatEmulatorRunError(f"未レビューのprofile IDです: {profile_id}")
    effective_lease_time = _effective_lease_time(lease_now_utc)
    try:
        lease_registry, lease = resolve_active_live_lease(
            profile_id,
            now_utc=effective_lease_time,
            profile_registry=registry,
        )
    except RatEmulatorLiveLeaseError as exc:
        raise RatEmulatorRunError(str(exc)) from exc
    return {
        "schema_version": 1,
        "mode": "preflight",
        "network_used": False,
        "profile_id": profile["profile_id"],
        "family": profile["family"],
        "adapter_id": profile["adapter_id"],
        "adapter_contract_version": HOST_ADAPTER_CONTRACT_VERSION,
        "endpoint": {"host": profile["host"], "port": profile["port"]},
        "pinned_ips": list(profile["pinned_ips"]),
        "protocol_profile_id": profile["protocol_profile_id"],
        "registry_sha256": registry.sha256,
        "evidence_sha256": profile["evidence_sha256"],
        "live_lease": _public_live_lease(lease_registry, lease),
        "certificate_mismatch_is_negative_evidence": profile[
            "certificate_mismatch_is_negative_evidence"
        ],
        "live_fake_result_allowed": False,
    }


def _open_stream_with_certificate_record(
    profile: Mapping[str, Any],
    resolved_ip: str,
    transcript: SessionTranscriptWriter,
    stream_opener: Callable[[Mapping[str, Any], str], tuple[Any, str]],
) -> tuple[Any, str]:
    try:
        return stream_opener(profile, resolved_ip)
    except TlsCertificatePinMismatch as exc:
        transcript.append_event(
            "internal",
            "tls_certificate_mismatch",
            public_fields={
                "expected_certificate_sha256": exc.expected_sha256,
                "observed_certificate_sha256": exc.observed_sha256,
                "application_frame_sent": False,
                "certificate_mismatch_is_negative_evidence": profile[
                    "certificate_mismatch_is_negative_evidence"
                ],
                "c2_exclusion_supported": False,
            },
        )
        raise


def run_live_session(
    profile_id: str,
    *,
    allow_network: bool,
    allow_live_c2_emulation: bool,
    acknowledged_profile: str | None,
    kill_switch_path: Path | None,
    private_output_directory: Path,
    maxmind_cache_directory: Path,
    public_output: Path | None = None,
    resolver: Callable[..., list[tuple[Any, ...]]] = socket.getaddrinfo,
    maxmind_preparer: Callable[[Path, str], dict[str, Any]] = prepare_maxmind,
    stream_opener: Callable[[Mapping[str, Any], str], tuple[Any, str]] = (
        open_pinned_tls_stream
    ),
    adapter_runner: Callable[
        [Mapping[str, Any], GuardedStream, Callable[[dict[str, Any]], None]],
        dict[str, Any],
    ] = _run_adapter,
    lease_now_utc: datetime | None = None,
    monotonic: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    """全gate通過後だけ単一のreview済みsessionを実行する。"""

    registry: RegistrySnapshot = load_registry()
    try:
        profile = resolve_profile(
            profile_id,
            expected_registry_sha256=registry.sha256,
        )
    except RatEmulatorProfileError as exc:
        raise RatEmulatorRunError(str(exc)) from exc
    effective_lease_time = _effective_lease_time(lease_now_utc)
    try:
        lease_registry, lease = resolve_active_live_lease(
            profile_id,
            now_utc=effective_lease_time,
            profile_registry=registry,
        )
    except RatEmulatorLiveLeaseError as exc:
        raise RatEmulatorRunError(str(exc)) from exc
    lease_remaining = (lease.expires_at - effective_lease_time.astimezone(UTC)).total_seconds()
    lease_deadline_monotonic = monotonic() + lease_remaining
    live_lease = _public_live_lease(lease_registry, lease)
    kill_switch = require_live_gates(
        profile,
        allow_network=allow_network,
        allow_live_c2_emulation=allow_live_c2_emulation,
        acknowledged_profile=acknowledged_profile,
        kill_switch_path=kill_switch_path,
    )
    validate_private_locations(
        private_output_directory,
        maxmind_cache_directory,
    )
    if public_output is not None:
        ensure_new_output(public_output, ())
    pinned_ip = str(profile["pinned_ips"][0])
    maxmind = maxmind_preparer(maxmind_cache_directory, pinned_ip)
    kill_switch.require_armed()
    _require_live_lease_deadline(lease_deadline_monotonic, monotonic)
    resolved_ip, dns_answers = resolve_single_pinned_ip(profile, resolver=resolver)
    kill_switch.require_armed()
    _require_live_lease_deadline(lease_deadline_monotonic, monotonic)
    transcript = SessionTranscriptWriter(
        private_output_directory,
        session_id=f"{profile_id}-{uuid.uuid4().hex}",
        metadata={
            "profile_id": profile_id,
            "family": profile["family"],
            "protocol_profile_id": profile["protocol_profile_id"],
            "registry_sha256": registry.sha256,
            "protocol_profile_object_sha256": profile["protocol_profile_object_sha256"],
            "evidence_sha256": profile["evidence_sha256"],
            "live_lease": live_lease,
            "certificate_mismatch_is_negative_evidence": profile[
                "certificate_mismatch_is_negative_evidence"
            ],
            "pinned_ip": resolved_ip,
            "dns_answers": dns_answers,
            "maxmind": maxmind,
            "sample_executed": False,
        },
        repository_root=repository_root(),
    )
    stream: Any | None = None
    finalized = False
    try:
        transcript.append_event(
            "internal",
            "preconnect_policy_validated",
            public_fields={
                "single_connection": True,
                "single_pinned_ip": True,
                "live_fake_result_allowed": False,
                "certificate_mismatch_is_negative_evidence": profile[
                    "certificate_mismatch_is_negative_evidence"
                ],
                "live_lease_sha256": lease_registry.sha256,
                "live_lease_expires_at_utc": lease.expires_at_utc,
                "kill_switch_armed": True,
            },
        )
        connection_remaining = _require_live_lease_deadline(
            lease_deadline_monotonic, monotonic
        )
        connection_profile = dict(profile)
        connection_profile["limits"] = {
            **profile["limits"],
            "duration_seconds": min(
                float(profile["limits"]["duration_seconds"]),
                connection_remaining,
            ),
        }
        stream, certificate_sha256 = _open_stream_with_certificate_record(
            connection_profile, resolved_ip, transcript, stream_opener
        )
        _require_live_lease_deadline(lease_deadline_monotonic, monotonic)
        if certificate_sha256 != profile["expected_certificate_sha256"]:
            mismatch = TlsCertificatePinMismatch(
                str(profile["expected_certificate_sha256"]), certificate_sha256
            )
            transcript.append_event(
                "internal",
                "tls_certificate_mismatch",
                public_fields={
                    "expected_certificate_sha256": mismatch.expected_sha256,
                    "observed_certificate_sha256": mismatch.observed_sha256,
                    "application_frame_sent": False,
                    "certificate_mismatch_is_negative_evidence": profile[
                        "certificate_mismatch_is_negative_evidence"
                    ],
                    "c2_exclusion_supported": False,
                },
            )
            raise mismatch
        transcript.append_event(
            "internal",
            "tls_certificate_pinned",
            public_fields={
                "tls_version": profile["tls_version"],
                "certificate_sha256": certificate_sha256,
            },
        )
        guarded = GuardedStream(
            stream,
            limits=profile["limits"],
            kill_switch=kill_switch,
            transcript=transcript,
            monotonic=monotonic,
            lease_deadline_monotonic=lease_deadline_monotonic,
        )
        result = adapter_runner(profile, guarded, _adapter_event_callback(transcript))
        public_adapter = _public_adapter_result(result, profile)
        transcript.finalize(
            status="completed",
            stop_reason=str(result.get("status") or "completed"),
        )
        finalized = True
        public = build_public_summary(private_output_directory)
        public["adapter_result"] = public_adapter
        _write_public_output(public_output, public)
        return public
    except BaseException as exc:
        if not finalized:
            transcript.append_event(
                "internal",
                "session_failed",
                public_fields={"error_type": type(exc).__name__, "task_executed": False},
            )
            transcript.finalize(status="failed", stop_reason=type(exc).__name__)
        if public_output is not None and not public_output.exists():
            _write_public_output(
                public_output,
                build_public_summary(private_output_directory),
            )
        raise
    finally:
        if stream is not None:
            try:
                stream.close()
            except OSError:
                pass


def replay_transcript(
    private_transcript_directory: Path,
    *,
    public_output: Path | None = None,
) -> dict[str, Any]:
    """通信せず、既存の非公開記録を検証して公開要約だけを再生成する。"""

    result = build_public_summary(private_transcript_directory)
    result["mode"] = "offline_replay"
    result["network_used"] = False
    _write_public_output(public_output, result)
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    profile_parser = subparsers.add_parser(
        "preflight",
        help="通信せずprofile証拠を検証します",
    )
    profile_parser.add_argument("--profile-id", required=True)
    live = subparsers.add_parser(
        "live",
        help="明示承認された有界live sessionを1回実行します",
    )
    live.add_argument("--profile-id", required=True)
    live.add_argument("--allow-network", action="store_true")
    live.add_argument("--allow-live-c2-emulation", action="store_true")
    live.add_argument("--acknowledge-profile")
    live.add_argument("--kill-switch-file", type=Path)
    live.add_argument("--private-output-directory", type=Path, required=True)
    live.add_argument(
        "--maxmind-cache-directory",
        type=Path,
        default=Path.home() / ".cache" / "ai-security-analysis" / "maxmind",
    )
    live.add_argument("--public-output", type=Path)
    replay = subparsers.add_parser(
        "replay",
        help="通信せずprivate transcriptを検証します",
    )
    replay.add_argument("--private-transcript-directory", type=Path, required=True)
    replay.add_argument("--public-output", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "preflight":
            result = preflight(args.profile_id)
        elif args.command == "replay":
            result = replay_transcript(
                args.private_transcript_directory,
                public_output=args.public_output,
            )
        else:
            result = run_live_session(
                args.profile_id,
                allow_network=args.allow_network,
                allow_live_c2_emulation=args.allow_live_c2_emulation,
                acknowledged_profile=args.acknowledge_profile,
                kill_switch_path=args.kill_switch_file,
                private_output_directory=args.private_output_directory,
                maxmind_cache_directory=args.maxmind_cache_directory,
                public_output=args.public_output,
            )
    except (
        FileExistsError,
        OSError,
        RatEmulatorProfileError,
        RatEmulatorLiveLeaseError,
        RatEmulatorRunError,
        RatEmulatorTranscriptError,
        ValueError,
    ) as exc:
        parser.error(str(exc))
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
