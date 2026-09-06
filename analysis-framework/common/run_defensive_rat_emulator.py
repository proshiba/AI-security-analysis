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

from immutable_snapshot import (
    decode_strict_json,
    ensure_new_output,
    read_bounded_snapshot,
    write_new_json,
)
from purerat_public_result import (
    PureRatPublicResultError,
    build_public_purerat_result,
)
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
MAXMIND_MAXIMUM_DATABASE_BYTES = 256 * 1024 * 1024
MAXMIND_MAXIMUM_ACQUISITION_JSON_BYTES = 64 * 1024
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
    "valleyrat_winos_v1": (
        "analysis-framework",
        "malware",
        "valleyrat",
        "winos_host_emulator.py",
    ),
    "valleyrat_winos_external_v1": (
        "analysis-framework",
        "malware",
        "valleyrat",
        "winos_host_emulator.py",
    ),
    "purerat_direct_tls_v1": (
        "analysis-framework",
        "malware",
        "purehvnc",
        "purerat_host_emulator.py",
    ),
}
HOST_ADAPTER_CONTRACT_VERSION = 1
OFFLINE_ONLY_LIVE_SCOPE = "offline_or_loopback_only"


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


class ObserverStopRequested(RatEmulatorRunError):
    """supervisorの停止要求を次のI/Oより前に反映する。"""


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


def _load_pre_refreshed_maxmind(
    cache_directory: Path,
) -> dict[str, tuple[Path, dict[str, Any]]]:
    """license keyやnetworkなしで取得済みCity／ASN cacheを完全性検証する。"""

    editions = ("GeoLite2-City", "GeoLite2-ASN")
    acquired: dict[str, tuple[Path, dict[str, Any]]] = {}
    for edition in editions:
        database_path = cache_directory / f"{edition}.mmdb"
        metadata_path = cache_directory / f"{edition}.acquisition.json"
        for path, maximum_bytes in (
            (database_path, MAXMIND_MAXIMUM_DATABASE_BYTES),
            (metadata_path, MAXMIND_MAXIMUM_ACQUISITION_JSON_BYTES),
        ):
            reject_existing_reparse_components(path)
            metadata = path.lstat()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or path.is_symlink()
                or metadata.st_nlink != 1
                or not 0 < metadata.st_size <= maximum_bytes
            ):
                raise RatEmulatorRunError(
                    f"MaxMind cacheは上限内の単一通常fileにしてください: {edition}"
                )
        try:
            acquisition = decode_strict_json(
                read_bounded_snapshot(
                    metadata_path,
                    MAXMIND_MAXIMUM_ACQUISITION_JSON_BYTES,
                ).data
            )
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise RatEmulatorRunError(
                f"MaxMind cache metadataを検証できません: {edition}"
            ) from exc
        if not isinstance(acquisition, dict):
            raise RatEmulatorRunError("MaxMind cache metadataはobjectにしてください")
        digest = hashlib.sha256()
        with database_path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        if (
            acquisition.get("edition") != edition
            or acquisition.get("mmdb_bytes") != database_path.stat().st_size
            or acquisition.get("mmdb_sha256") != digest.hexdigest()
        ):
            raise RatEmulatorRunError("MaxMind cacheのsize／SHA-256 pinが一致しません")
        acquired[edition] = (database_path, acquisition)
    return acquired


def prepare_maxmind(cache_directory: Path, pinned_ip: str) -> dict[str, Any]:
    """直前に公式更新したCity／ASN cacheをread-only検証して対象IPを照合する。"""

    if not cache_directory.is_absolute():
        raise RatEmulatorRunError("MaxMind cache directoryは絶対pathで指定してください")
    try:
        from run_c2_monitoring_pipeline import (
            enrich_with_acquired_databases,
        )

        acquired = _load_pre_refreshed_maxmind(_absolute(cache_directory))
        checked_at = datetime.now(UTC)
        acquired_at: dict[str, str] = {}
        for edition, (_path, acquisition) in acquired.items():
            if acquisition.get("official_checksum_verified") is not True:
                raise RatEmulatorRunError("MaxMind DBの公式checksum検証を確認できません")
            if (
                acquisition.get("license_key_stored") is not False
                or acquisition.get("download_url_stored") is not False
            ):
                raise RatEmulatorRunError("MaxMind cache metadataへ秘密情報が保存されています")
            acquired_text = acquisition.get("acquired_at_utc")
            if not isinstance(acquired_text, str):
                raise RatEmulatorRunError("MaxMind DBの取得時刻がありません")
            try:
                acquired_time = datetime.fromisoformat(acquired_text)
            except ValueError as exc:
                raise RatEmulatorRunError("MaxMind DBの取得時刻が不正です") from exc
            if acquired_time.tzinfo is None or acquired_time.utcoffset() is None:
                raise RatEmulatorRunError("MaxMind DBの取得時刻にtimezoneがありません")
            age_seconds = (
                checked_at - acquired_time.astimezone(UTC)
            ).total_seconds()
            if not 0.0 <= age_seconds < MAXMIND_MAXIMUM_BUILD_AGE_HOURS * 3600:
                raise RatEmulatorRunError("MaxMind DBの公式再取得から24時間以上経過しています")
            acquired_at[edition] = acquired_text
        freshness = {
            "schema_version": 1,
            "checked_at_utc": checked_at.isoformat(),
            "checked_before_live_check": True,
            "maximum_acquisition_age_hours": MAXMIND_MAXIMUM_BUILD_AGE_HOURS,
            "official_refresh_acquired_at_utc": acquired_at,
            "cache_mode": "pre_refreshed_read_only",
        }
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


def _enable_tcp_keepalive(stream: Any) -> dict[str, Any]:
    """Linuxではidle 60秒からTCP keepaliveを使い、設定結果を返す。"""

    setter = getattr(stream, "setsockopt", None)
    if not callable(setter):
        return {"tcp_keepalive_enabled": False}
    setter(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    configured: dict[str, Any] = {"tcp_keepalive_enabled": True}
    for name, value in (("TCP_KEEPIDLE", 60), ("TCP_KEEPINTVL", 20), ("TCP_KEEPCNT", 3)):
        option = getattr(socket, name, None)
        if option is not None:
            setter(socket.IPPROTO_TCP, option, value)
            configured[name.lower()] = value
    return configured


def open_pinned_tls_stream(
    profile: Mapping[str, Any],
    pinned_ip: str,
    *,
    connector: Callable[..., socket.socket] = socket.create_connection,
    event_callback: Callable[[str, dict[str, Any]], None] | None = None,
) -> tuple[Any, str]:
    """単一pinへprofile固定TLSで1回だけ接続し、leaf certificate hashを固定する。"""

    timeout = min(float(profile["limits"]["duration_seconds"]), 30.0)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    tls_version = profile.get("tls_version")
    if tls_version == "TLSv1.0":
        context.minimum_version = ssl.TLSVersion.TLSv1
        context.maximum_version = ssl.TLSVersion.TLSv1
        context.set_ciphers("DEFAULT:@SECLEVEL=0")
    elif tls_version == "TLSv1.2":
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.maximum_version = ssl.TLSVersion.TLSv1_2
    else:
        raise RatEmulatorRunError("未レビューのTLS versionです")
    emit = event_callback or (lambda _name, _fields: None)
    emit("tcp_connect_started", {"application_frame_sent": False})
    raw = connector((pinned_ip, int(profile["port"])), timeout=timeout)
    sni = profile.get("sni")
    server_hostname = str(sni) if isinstance(sni, str) and sni else None
    stream: Any | None = None
    try:
        emit("tcp_connected", _enable_tcp_keepalive(raw))
        emit("tls_handshake_started", {"requested_tls_version": tls_version})
        stream = context.wrap_socket(raw, server_hostname=server_hostname)
        negotiated = stream.version()
        expected_version = {"TLSv1.0": "TLSv1", "TLSv1.2": "TLSv1.2"}[tls_version]
        if negotiated != expected_version:
            stream.close()
            raise RatEmulatorRunError("negotiated TLS versionがreview済み値と一致しません")
        emit("tls_handshake_completed", {"negotiated_tls_version": negotiated})
        certificate = stream.getpeercert(binary_form=True)
        digest = hashlib.sha256(certificate or b"").hexdigest()
        if digest != profile["expected_certificate_sha256"]:
            stream.close()
            raise TlsCertificatePinMismatch(
                str(profile["expected_certificate_sha256"]), digest
            )
        return stream, digest
    except BaseException:
        if stream is not None:
            try:
                stream.close()
            except OSError:
                pass
        try:
            raw.close()
        except OSError:
            pass
        raise


def open_reviewed_stream(
    profile: Mapping[str, Any],
    pinned_ip: str,
    *,
    connector: Callable[..., socket.socket] = socket.create_connection,
    event_callback: Callable[[str, dict[str, Any]], None] | None = None,
) -> tuple[Any, str | None]:
    """TLSまたは唯一のreview済みWinos raw TCPへ単1接続する。"""

    if profile.get("transport") == "tls":
        return open_pinned_tls_stream(
            profile, pinned_ip, connector=connector, event_callback=event_callback
        )
    if (
        profile.get("transport") != "raw_tcp"
        or profile.get("adapter_id") != "valleyrat_winos_external_v1"
        or profile.get("profile_id")
        != "valleyrat-winos-heartbeat-20260810-64-81-30-192-6666"
        or profile.get("host") != "64.81.30.192"
        or profile.get("port") != 6666
        or profile.get("pinned_ips") != ["64.81.30.192"]
        or pinned_ip != "64.81.30.192"
        or profile.get("tls_version") is not None
        or profile.get("sni") is not None
        or profile.get("expected_certificate_sha256") is not None
        or profile.get("certificate_mismatch_is_negative_evidence") is not False
    ):
        raise RatEmulatorRunError("未reviewのraw TCP transportです")
    timeout = min(float(profile["limits"]["duration_seconds"]), 3.0)
    emit = event_callback or (lambda _name, _fields: None)
    emit("tcp_connect_started", {"application_frame_sent": False})
    raw = connector((pinned_ip, int(profile["port"])), timeout=timeout)
    try:
        emit("tcp_connected", _enable_tcp_keepalive(raw))
    except BaseException:
        raw.close()
        raise
    return raw, None


class GuardedStream:
    """adapterの全send/recvへduration、kill-switch、byte/frame上限を強制する。"""

    def __init__(
        self,
        stream: Any,
        *,
        limits: Mapping[str, int | float],
        kill_switch: KillSwitch,
        transcript: SessionTranscriptWriter,
        retain_private_inbound_frames: bool = False,
        monotonic: Callable[[], float] = time.monotonic,
        lease_deadline_monotonic: float | None = None,
        stop_requested: Callable[[], bool] | None = None,
        progress_callback: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        self.stream = stream
        self.limits = dict(limits)
        self.kill_switch = kill_switch
        self.transcript = transcript
        self.retain_private_inbound_frames = retain_private_inbound_frames
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
        self.first_outbound_event_type = "reviewed_registration_frame"
        self.stop_requested = stop_requested or (lambda: False)
        self.progress_callback = progress_callback

    def set_first_outbound_event_type(self, event_type: str) -> None:
        """初回送信frameのreview済み意味をadapter dispatch時に固定する。"""

        allowed = {
            "reviewed_registration_frame",
            "reviewed_fixed_heartbeat_request_frame",
        }
        if self.outbound_frames != 0 or event_type not in allowed:
            raise RatEmulatorRunError("初回outbound event typeを設定できません")
        self.first_outbound_event_type = event_type

    def _check(self) -> None:
        if self.stop_requested():
            raise ObserverStopRequested("supervisorから停止要求を受信しました")
        self.kill_switch.require_armed()
        if self.monotonic() >= self.deadline:
            raise RatEmulatorRunError("sessionまたは短期live leaseの期限へ到達しました")
        if self.progress_callback is not None:
            self.progress_callback({
                "state": "observing",
                "connected": True,
                "inbound_frames": self.inbound_frames,
                "inbound_bytes": self.inbound_bytes,
                "outbound_frames": self.outbound_frames,
                "outbound_bytes": self.outbound_bytes,
            })

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

    def remaining_seconds(self) -> float:
        """kill-switchを再確認し、session期限までの残秒を返す。"""

        if self.stop_requested():
            raise ObserverStopRequested("supervisorから停止要求を受信しました")
        self.kill_switch.require_armed()
        return max(0.0, self.deadline - self.monotonic())

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
            self.transcript.append_event(
                "inbound",
                "transport_post_registration_chunk",
                raw_frame=(chunk if self.retain_private_inbound_frames else None),
                public_fields={
                    "size": len(chunk),
                    "sha256": digest,
                    "raw_retained_private": self.retain_private_inbound_frames,
                },
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
                raw_frame=(wire if self.retain_private_inbound_frames else None),
                public_fields={
                    **public_fields,
                    "raw_retained_private": self.retain_private_inbound_frames,
                },
            )
        return wire

    def recv_total_length_application_frame(
        self,
        maximum_frame_bytes: int,
        *,
        minimum_total_bytes: int = 14,
    ) -> bytes:
        """LE32 total-length frameをread callとframe countを分離して1件読む。"""

        self._refresh_timeout()
        if self.inbound_frames >= int(self.limits["maximum_inbound_frames"]):
            raise RatEmulatorRunError("inbound application-frame limit reached")
        remaining = int(self.limits["maximum_inbound_bytes"]) - self.inbound_bytes
        frame_limit = min(
            int(maximum_frame_bytes),
            int(self.limits["maximum_frame_bytes"]),
            remaining,
        )
        if not 5 <= minimum_total_bytes <= frame_limit:
            raise RatEmulatorRunError("total-length frame limitが不正です")

        frame = bytearray()

        def read_exact(total_size: int) -> bool:
            while len(frame) < total_size:
                self._refresh_timeout()
                if self.inbound_read_calls >= int(
                    self.limits["maximum_inbound_read_calls"]
                ):
                    raise RatEmulatorRunError("inbound read-call limit reached")
                request = total_size - len(frame)
                self.inbound_read_calls += 1
                try:
                    chunk = self.stream.recv(request)
                except TimeoutError as exc:
                    if frame:
                        raise RatEmulatorRunError(
                            "partial_frame_timeout: 途中のtotal-length frameは再同期せず終了します"
                        ) from exc
                    raise
                if not isinstance(chunk, bytes):
                    raise RatEmulatorRunError("stream.recv must return bytes")
                if len(chunk) > request:
                    raise RatEmulatorRunError(
                        "stream.recv returned more bytes than requested"
                    )
                if not chunk:
                    return False
                frame.extend(chunk)
                self.inbound_bytes += len(chunk)
                if self.inbound_bytes > int(self.limits["maximum_inbound_bytes"]):
                    raise RatEmulatorRunError("inbound byte limit reached")
            return True

        if not read_exact(4):
            if frame:
                raise RatEmulatorRunError("stream closed during total-length header")
            return b""
        declared_total = struct.unpack("<I", frame[:4])[0]
        if not minimum_total_bytes <= declared_total <= frame_limit:
            raise RatEmulatorRunError(
                "declared total-length frame exceeds its reviewed limit"
            )
        if not read_exact(declared_total):
            raise RatEmulatorRunError("stream closed during total-length frame")

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
                raw_frame=(wire if self.retain_private_inbound_frames else None),
                public_fields={
                    **public_fields,
                    "raw_retained_private": self.retain_private_inbound_frames,
                },
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
            self.first_outbound_event_type
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
                "synthetic_request_sent": event_type
                == "reviewed_fixed_heartbeat_request_frame",
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
    *,
    adapter_id: str | None = None,
    maximum_elapsed_ms: int = 28_800_000,
) -> Callable[[dict[str, Any]], None]:
    if type(maximum_elapsed_ms) is not int or not 1 <= maximum_elapsed_ms <= 28_800_000:
        raise RatEmulatorRunError("event時刻の上限は1 ms〜8時間の整数が必要です")
    last_winos_elapsed_ms = 0
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
        "role",
        "frame_size",
        "frame_sha256",
        "declared_length",
        "complete",
        "integrity_authenticated",
        "decoded_size",
        "decoded_sha256",
        "sent",
        "synthetic",
        "synthetic_request_sent",
        "stage_requested",
        "registration_sent",
        "registration_requested",
        "unknown_command_reply_sent",
    }

    def callback(event: dict[str, Any]) -> None:
        nonlocal last_winos_elapsed_ms
        accepted_winos_elapsed_ms: int | None = None
        name = str(event.get("event") or "adapter_event")
        active_public_keys = public_keys
        if adapter_id == "purerat_direct_tls_v1":
            active_public_keys = {
                "classification",
                "discriminator",
                "message_type",
                "action",
                "should_respond",
                "terminate_session",
                "packet_size",
                "packet_sha256",
                "response_size",
                "response_sha256",
                "frame_count",
                "real_identity_sent",
                "status",
                "synthetic",
            }
        public = {
            key: value for key, value in event.items() if key in active_public_keys
        }
        if adapter_id in {"valleyrat_winos_v1", "valleyrat_winos_external_v1"} and (
            "elapsed_ms" in event or "timing_basis" in event
        ):
            elapsed_ms = event.get("elapsed_ms")
            timing_basis = event.get("timing_basis")
            if (
                type(elapsed_ms) is not int
                or not last_winos_elapsed_ms <= elapsed_ms <= maximum_elapsed_ms
                or type(timing_basis) is not str
                or timing_basis != "session_monotonic"
            ):
                raise RatEmulatorRunError("Winos eventの単調経過時刻または固定basisが不正です")
            public.update(elapsed_ms=elapsed_ms, timing_basis=timing_basis)
            accepted_winos_elapsed_ms = elapsed_ms
        fingerprint = event.get("fingerprint")
        if isinstance(fingerprint, dict):
            for key in ("frame_size", "frame_sha256", "decoded_size", "decoded_sha256"):
                if key in fingerprint:
                    public[key] = fingerprint[key]
            private = (
                {}
                if adapter_id == "purerat_direct_tls_v1"
                else {"fingerprint": fingerprint}
            )
        else:
            private = {}
        transcript.append_event(
            "internal",
            name,
            public_fields=public,
            private_fields=private,
        )
        if accepted_winos_elapsed_ms is not None:
            last_winos_elapsed_ms = accepted_winos_elapsed_ms

    return callback


def _run_adapter(
    profile: Mapping[str, Any],
    stream: GuardedStream,
    callback: Callable[[dict[str, Any]], None],
) -> dict[str, Any]:
    adapter = _load_adapter(str(profile["adapter_id"]))
    limits = profile["limits"]
    adapter_id = profile["adapter_id"]
    if adapter_id == "tls_messagepack_rat_host":
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
    if adapter_id == "purerat_direct_tls_v1":
        return adapter.run_host_session(
            stream,
            profile,
            session_limits={
                "timeout_seconds": min(3.0, float(limits["duration_seconds"])),
                "maximum_response_bytes": int(limits["maximum_inbound_bytes"]),
                "maximum_frames": int(limits["maximum_inbound_frames"]),
                "maximum_read_calls": int(
                    limits["maximum_inbound_read_calls"]
                ),
                "read_chunk_bytes": int(limits["maximum_frame_bytes"]),
            },
            allow_registration=True,
            allow_heartbeat_request=False,
            transcript_callback=callback,
        )
    if adapter_id in {"valleyrat_winos_external_v1", "valleyrat_winos_v1"}:
        # total-length readerがtransport readとapplication frameを分離する。
        stream.set_first_outbound_event_type(
            "reviewed_fixed_heartbeat_request_frame"
        )
        if adapter_id == "valleyrat_winos_external_v1":
            return adapter.run_passive_observation_session(
                stream,
                policy=adapter.PassiveObservationPolicy.from_mapping(
                    {
                        "duration_seconds": float(limits["duration_seconds"]),
                        "timeout_seconds": min(
                            3.0,
                            float(limits["duration_seconds"]),
                        ),
                        "maximum_response_bytes": int(
                            limits["maximum_frame_bytes"]
                        ),
                        "maximum_frames": int(limits["maximum_inbound_frames"]),
                        "maximum_read_calls": min(
                            64,
                            int(limits["maximum_inbound_read_calls"]),
                        ),
                        "read_chunk_bytes": int(limits["maximum_frame_bytes"]),
                    }
                ),
                allow_c9_heartbeat=True,
                transcript_callback=callback,
            ).to_dict()
        return adapter.run_host_session(
            stream,
            session_limits={
                "timeout_seconds": min(3.0, float(limits["duration_seconds"])),
                "maximum_response_bytes": int(limits["maximum_inbound_bytes"]),
                "maximum_frames": int(limits["maximum_inbound_frames"]),
                "maximum_read_calls": int(limits["maximum_inbound_read_calls"]),
                "read_chunk_bytes": int(limits["maximum_frame_bytes"]),
            },
            allow_c9_heartbeat=True,
            transcript_callback=callback,
        )
    if adapter_id == "valleyrat_n520_v1":
        return adapter.run_host_session(
            stream,
            session_limits={
                "timeout_seconds": min(30.0, float(limits["duration_seconds"])),
                "maximum_response_bytes": int(limits["maximum_inbound_bytes"]),
                "maximum_frames": int(limits["maximum_commands"]),
                "maximum_read_calls": int(limits["maximum_inbound_read_calls"]),
                "read_chunk_bytes": int(limits["maximum_frame_bytes"]),
            },
            allow_registration=True,
            transcript_callback=callback,
        )
    raise RatEmulatorRunError(f"adapter dispatchがありません: {adapter_id}")


def _public_winos_adapter_result(
    result: Mapping[str, Any],
    profile: Mapping[str, Any],
) -> dict[str, Any]:
    """Winos resultからraw payloadを含まないallowlist要約だけを返す。"""

    heartbeat = result.get("heartbeat")
    registration = result.get("registration")
    collection = result.get("collection")
    safety = result.get("safety")
    decisions = result.get("decisions")
    if not all(
        isinstance(value, dict)
        for value in (heartbeat, registration, collection, safety)
    ) or not isinstance(decisions, list):
        raise RatEmulatorRunError("Winos adapter resultの構造が不正です")
    public_decisions: list[dict[str, Any]] = []
    for decision in decisions:
        if not isinstance(decision, dict):
            raise RatEmulatorRunError("Winos decisionがobjectではありません")
        fingerprint = decision.get("fingerprint")
        if not isinstance(fingerprint, dict):
            raise RatEmulatorRunError("Winos decision fingerprintがありません")
        public_decisions.append(
            {
                key: decision.get(key)
                for key in (
                    "command",
                    "role",
                    "classification",
                    "action",
                    "should_respond",
                    "terminate_session",
                    "registration_requested",
                )
            }
            | {
                "frame_size": fingerprint.get("frame_size"),
                "frame_sha256": fingerprint.get("frame_sha256"),
                "declared_length": fingerprint.get("declared_length"),
                "complete": fingerprint.get("complete"),
                "integrity_authenticated": fingerprint.get(
                    "integrity_authenticated"
                ),
            }
        )
    return {
        "schema_version": 1,
        "family": result.get("family"),
        "protocol": result.get("protocol"),
        "status": result.get("status"),
        "required_endpoint_role": result.get("required_endpoint_role"),
        "certificate_mismatch_is_negative_evidence": profile[
            "certificate_mismatch_is_negative_evidence"
        ],
        "heartbeat": {
            key: heartbeat.get(key)
            for key in (
                "sent",
                "command",
                "payload_size",
                "packet_size",
                "packet_sha256",
                "synthetic_header",
                "real_identity_sent",
            )
        },
        "registration": {
            key: registration.get(key)
            for key in (
                "sent",
                "supported",
                "requested",
                "offline_reference_available",
                "reference_layout_id",
                "sample_bound",
                "external_send_allowed",
                "login_token_status",
            )
        },
        "collection": {
            key: collection.get(key)
            for key in (
                "response_size",
                "response_sha256",
                "frame_count",
                "total_inbound_bytes",
                "idle_timeouts",
                "timed_out",
                "peer_closed",
            )
        },
        "decisions": public_decisions,
        "safety": {
            key: safety.get(key)
            for key in (
                "sample_executed",
                "host_operation_executed",
                "victim_metadata_sent",
                "registration_sent",
                "unknown_command_reply_sent",
                "stage_requested",
                "stage_retained",
                "response_integrity_authenticated",
                "fake_result_sent",
                "application_send_count",
                "session_continues",
                "received_frame_executed",
                "received_frame_reply_sent",
                "received_frame_discarded_count",
            )
        },
    }


def _public_purerat_adapter_result(
    result: Mapping[str, Any],
    profile: Mapping[str, Any],
) -> dict[str, Any]:
    """PureRAT resultを専用のscalar allowlistへ写像する。"""

    try:
        return build_public_purerat_result(result, profile)
    except PureRatPublicResultError as exc:
        raise RatEmulatorRunError(str(exc)) from exc


def _public_adapter_result(
    result: Mapping[str, Any], profile: Mapping[str, Any] | None = None
) -> dict[str, Any]:
    if (
        isinstance(profile, Mapping)
        and profile.get("adapter_id") == "purerat_direct_tls_v1"
    ):
        return _public_purerat_adapter_result(result, profile)
    if (
        isinstance(profile, Mapping)
        and profile.get("adapter_id")
        in {"valleyrat_winos_external_v1", "valleyrat_winos_v1"}
    ):
        return _public_winos_adapter_result(result, profile)
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
    """networkを使わずprofile証拠とlive適格性を検証する。"""

    registry = load_registry()
    profile = registry.profiles.get(profile_id)
    if profile is None:
        raise RatEmulatorRunError(f"未レビューのprofile IDです: {profile_id}")
    result = {
        "schema_version": 1,
        "mode": "preflight",
        "network_used": False,
        "profile_id": profile["profile_id"],
        "family": profile["family"],
        "adapter_id": profile["adapter_id"],
        "adapter_contract_version": HOST_ADAPTER_CONTRACT_VERSION,
        "endpoint": {"host": profile["host"], "port": profile["port"]},
        "pinned_ips": list(profile["pinned_ips"]),
        "transport": profile["transport"],
        "protocol_profile_id": profile["protocol_profile_id"],
        "registry_sha256": registry.sha256,
        "evidence_sha256": profile["evidence_sha256"],
        "certificate_mismatch_is_negative_evidence": profile[
            "certificate_mismatch_is_negative_evidence"
        ],
        "live_scope": profile["live_scope"],
        "live_fake_result_allowed": False,
    }
    if profile["live_scope"] == OFFLINE_ONLY_LIVE_SCOPE:
        return {**result, "live_enabled": False, "live_lease": None}
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
        **result,
        "live_enabled": True,
        "live_lease": _public_live_lease(lease_registry, lease),
    }

def _open_stream_with_certificate_record(
    profile: Mapping[str, Any],
    resolved_ip: str,
    transcript: SessionTranscriptWriter,
    stream_opener: Callable[[Mapping[str, Any], str], tuple[Any, str | None]],
    event_callback: Callable[[str, dict[str, Any]], None] | None = None,
) -> tuple[Any, str | None]:
    try:
        if stream_opener is open_reviewed_stream:
            return stream_opener(profile, resolved_ip, event_callback=event_callback)
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
    stream_opener: Callable[[Mapping[str, Any], str], tuple[Any, str | None]] = (
        open_reviewed_stream
    ),
    adapter_runner: Callable[
        [Mapping[str, Any], GuardedStream, Callable[[dict[str, Any]], None]],
        dict[str, Any],
    ] = _run_adapter,
    lease_now_utc: datetime | None = None,
    monotonic: Callable[[], float] = time.monotonic,
    session_duration_seconds: float | None = None,
    stop_requested: Callable[[], bool] | None = None,
    progress_callback: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """全gate通過後だけ単一のreview済みsessionを実行する。"""

    stop_requested = stop_requested or (lambda: False)

    def progress(state: str, **fields: Any) -> None:
        if stop_requested():
            raise ObserverStopRequested("supervisorから停止要求を受信しました")
        if progress_callback is not None:
            progress_callback({"state": state, "connected": False, **fields})

    progress("validating")
    registry: RegistrySnapshot = load_registry()
    try:
        profile = resolve_profile(
            profile_id,
            expected_registry_sha256=registry.sha256,
        )
    except RatEmulatorProfileError as exc:
        raise RatEmulatorRunError(str(exc)) from exc
    if profile["live_scope"] == OFFLINE_ONLY_LIVE_SCOPE:
        raise RatEmulatorRunError(
            "offline／loopback専用profileは外部live sessionを開始できません"
        )
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
    profile_duration = float(profile["limits"]["duration_seconds"])
    if session_duration_seconds is None:
        active_duration = min(profile_duration, lease_remaining)
    else:
        if (
            type(session_duration_seconds) is not float
            or not 1.0 <= session_duration_seconds <= profile_duration
            or session_duration_seconds > lease_remaining
        ):
            raise RatEmulatorRunError(
                "session durationはprofile上限と短期live lease内に限定します"
            )
        active_duration = session_duration_seconds
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
    progress("waiting_maxmind")
    maxmind = maxmind_preparer(maxmind_cache_directory, pinned_ip)
    kill_switch.require_armed()
    _require_live_lease_deadline(lease_deadline_monotonic, monotonic)
    progress("resolving")
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
            "private_inbound_frame_retention": (
                profile["adapter_id"]
                in {"purerat_direct_tls_v1", "valleyrat_winos_external_v1"}
                and profile["live_scope"] == "leased_external"
            ),
        },
        repository_root=repository_root(),
    )
    stream: Any | None = None
    finalized = False
    transport_phase = "tcp_connect_started"

    def transport_event(name: str, fields: dict[str, Any]) -> None:
        nonlocal transport_phase
        transport_phase = name
        transcript.append_event("internal", name, public_fields=fields)
        progress("connecting", transport_phase=name)

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
        active_limits = {
            **profile["limits"],
            "duration_seconds": min(active_duration, connection_remaining),
        }
        connection_profile["limits"] = active_limits
        stream, certificate_sha256 = _open_stream_with_certificate_record(
            connection_profile, resolved_ip, transcript, stream_opener, transport_event
        )
        transport_phase = "application_session"
        _require_live_lease_deadline(lease_deadline_monotonic, monotonic)
        if profile["transport"] == "tls":
            if certificate_sha256 != profile["expected_certificate_sha256"]:
                mismatch = TlsCertificatePinMismatch(
                    str(profile["expected_certificate_sha256"]),
                    str(certificate_sha256),
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
        elif (
            profile["transport"] == "raw_tcp"
            and profile["adapter_id"] == "valleyrat_winos_external_v1"
            and certificate_sha256 is None
            and profile["expected_certificate_sha256"] is None
        ):
            transcript.append_event(
                "internal",
                "reviewed_raw_tcp_transport_established",
                public_fields={
                    "single_pinned_ip": True,
                    "tls_used": False,
                    "certificate_expected": False,
                },
            )
        else:
            raise RatEmulatorRunError("接続transport契約がprofileと一致しません")
        guarded = GuardedStream(
            stream,
            limits=active_limits,
            kill_switch=kill_switch,
            transcript=transcript,
            retain_private_inbound_frames=(
                profile["adapter_id"]
                in {"purerat_direct_tls_v1", "valleyrat_winos_external_v1"}
                and profile["live_scope"] == "leased_external"
            ),
            monotonic=monotonic,
            lease_deadline_monotonic=lease_deadline_monotonic,
            stop_requested=stop_requested,
            progress_callback=progress_callback,
        )
        active_profile = dict(profile)
        active_profile["limits"] = active_limits
        result = adapter_runner(
            active_profile,
            guarded,
            _adapter_event_callback(
                transcript,
                adapter_id=str(profile["adapter_id"]),
                maximum_elapsed_ms=int(float(active_limits["duration_seconds"]) * 1000),
            ),
        )
        public_adapter = _public_adapter_result(result, active_profile)
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
            if isinstance(exc, ConnectionResetError):
                transcript.append_event(
                    "inbound",
                    "transport_peer_reset_received",
                    public_fields={
                        "error_type": type(exc).__name__,
                        "error_number": exc.errno,
                        "reset_direction": "peer_to_observer",
                        "task_executed": False,
                        "operation_executed": False,
                    },
                )
            transcript.append_event(
                "internal",
                "session_failed",
                public_fields={
                    "error_type": type(exc).__name__,
                    "task_executed": False,
                    "transport_phase": transport_phase,
                },
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
