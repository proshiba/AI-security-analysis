#!/usr/bin/env python3
"""Bounded exact-sample TLS MessagePack RAT host adapter."""

from __future__ import annotations

import gzip
import hashlib
import struct
import zlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol, TypeAlias

ADAPTER_ID = "tls_messagepack_rat_host"
ASYNC_PROFILE_ID = "asyncrat-058-20f21565-191-96-78-221-7788"
VENOM_PROFILE_ID = "venomrat-603-6a24ba25-localto-6377"
LIVE_ARBITRARY_RESULT_ALLOWED = False

Scalar: TypeAlias = str | int | bytes


class TlsMessagePackHostError(ValueError):
    """The frame, profile, or session exceeded a reviewed boundary."""


class RatStream(Protocol):
    def recv(self, maximum_bytes: int) -> bytes: ...

    def sendall(self, data: bytes) -> None: ...

    def settimeout(self, timeout_seconds: float) -> None: ...


@dataclass(frozen=True)
class SessionLimits:
    timeout_seconds: float = 5.0
    maximum_frame_bytes: int = 1024 * 1024
    maximum_decoded_bytes: int = 1024 * 1024
    maximum_map_entries: int = 64
    maximum_string_bytes: int = 8192
    maximum_binary_bytes: int = 512 * 1024
    maximum_opcode_bytes: int = 64
    maximum_read_calls: int = 256
    maximum_send_bytes: int = 16 * 1024
    maximum_frames: int = 1
    maximum_commands: int = 1

    def __post_init__(self) -> None:
        if isinstance(self.timeout_seconds, bool) or not isinstance(self.timeout_seconds, (int, float)):
            raise TypeError("timeout_seconds must be numeric")
        if not 0.1 <= float(self.timeout_seconds) <= 30.0:
            raise TlsMessagePackHostError("timeout_seconds is outside the reviewed range")
        integer_limits = {
            "maximum_frame_bytes": (64, 16 * 1024 * 1024),
            "maximum_decoded_bytes": (64, 16 * 1024 * 1024),
            "maximum_map_entries": (1, 256),
            "maximum_string_bytes": (1, 1024 * 1024),
            "maximum_binary_bytes": (1, 16 * 1024 * 1024),
            "maximum_opcode_bytes": (1, 256),
            "maximum_read_calls": (2, 4096),
            "maximum_send_bytes": (64, 1024 * 1024),
        }
        for name, (minimum, maximum) in integer_limits.items():
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{name} must be an integer")
            if not minimum <= value <= maximum:
                raise TlsMessagePackHostError(f"{name} is outside the reviewed range")
        if self.maximum_frames != 1 or self.maximum_commands != 1:
            raise TlsMessagePackHostError("the initial adapter is limited to one frame and one command")

    @classmethod
    def from_mapping(cls, values: Mapping[str, int | float] | None) -> SessionLimits:
        if values is None:
            return cls()
        aliases = {
            "timeout_seconds": "timeout_seconds",
            "idle_timeout_seconds": "timeout_seconds",
            "maximum_frame_bytes": "maximum_frame_bytes",
            "maximum_response_bytes": "maximum_frame_bytes",
            "max_bytes": "maximum_frame_bytes",
            "maximum_decoded_bytes": "maximum_decoded_bytes",
            "maximum_map_entries": "maximum_map_entries",
            "maximum_string_bytes": "maximum_string_bytes",
            "maximum_binary_bytes": "maximum_binary_bytes",
            "maximum_opcode_bytes": "maximum_opcode_bytes",
            "maximum_read_calls": "maximum_read_calls",
            "max_read_calls": "maximum_read_calls",
            "maximum_send_bytes": "maximum_send_bytes",
            "maximum_frames": "maximum_frames",
            "max_frames": "maximum_frames",
            "maximum_commands": "maximum_commands",
            "max_commands": "maximum_commands",
        }
        unknown = sorted(set(values) - set(aliases))
        if unknown:
            raise TlsMessagePackHostError(f"unsupported session limits: {', '.join(unknown)}")
        normalized: dict[str, int | float] = {}
        for source, value in values.items():
            destination = aliases[source]
            if destination in normalized and normalized[destination] != value:
                raise TlsMessagePackHostError(f"conflicting session limit: {destination}")
            normalized[destination] = value
        return cls(**normalized)


@dataclass(frozen=True)
class ExactProfile:
    profile_id: str
    family: str
    sample_sha256: str
    evidence_sha256: str
    packet_key: str
    registration_fields: tuple[tuple[str, str], ...]
    heartbeat_request_opcode: str
    heartbeat_response_opcode: str
    file_opcodes: frozenset[str]
    operation_opcodes: frozenset[str]
    handler: str
    registration_enabled: bool = True
    heartbeat_request_reviewed: bool = True


@dataclass(frozen=True)
class DecodedFrame:
    values: dict[str, Scalar]
    frame_size: int
    frame_sha256: str
    compressed_payload_size: int
    compressed_payload_sha256: str
    decoded_size: int
    decoded_sha256: str


@dataclass(frozen=True)
class CommandDecision:
    packet_kind: str
    opcode: str
    action: str
    should_respond: bool
    terminate_session: bool
    file_or_plugin_retained: bool
    operation_executed: bool
    fingerprint: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "packet_kind": self.packet_kind,
            "opcode": self.opcode,
            "action": self.action,
            "should_respond": self.should_respond,
            "terminate_session": self.terminate_session,
            "file_or_plugin_retained": self.file_or_plugin_retained,
            "operation_executed": self.operation_executed,
            "fingerprint": dict(self.fingerprint),
        }


@dataclass(frozen=True)
class SyntheticResultDecision:
    opcode: str
    outcome: str
    send_allowed: bool = False
    fixture_only: bool = True
    wire_schema_status: str = "unreviewed"
    wire_bytes: None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "packet_kind": "abstract_synthetic_result",
            "opcode": self.opcode,
            "outcome": self.outcome,
            "send_allowed": self.send_allowed,
            "fixture_only": self.fixture_only,
            "wire_schema_status": self.wire_schema_status,
            "wire_bytes": self.wire_bytes,
        }


@dataclass(frozen=True)
class HostSessionResult:
    profile: ExactProfile
    status: str
    registration: dict[str, Any]
    decision: CommandDecision
    heartbeat_request: dict[str, Any]
    received_bytes: int
    read_calls: int
    application_send_count: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "adapter_id": ADAPTER_ID,
            "profile_id": self.profile.profile_id,
            "family": self.profile.family,
            "protocol": self.profile.family,
            "sample_sha256": self.profile.sample_sha256,
            "evidence_sha256": self.profile.evidence_sha256,
            "status": self.status,
            "registration": dict(self.registration),
            "command": self.decision.to_dict(),
            "heartbeat_request": dict(self.heartbeat_request),
            "collection": {
                "received_bytes": self.received_bytes,
                "read_calls": self.read_calls,
                "frame_count": 1,
                "command_count": 1,
            },
            "safety": {
                "sample_executed": False,
                "real_host_information_read": False,
                "real_effect_performed": False,
                "file_or_plugin_retained": False,
                "file_or_plugin_executed": False,
                "operation_executed": False,
                "secondary_network_performed": False,
                "arbitrary_fake_result_sent": False,
                "live_arbitrary_result_allowed": LIVE_ARBITRARY_RESULT_ALLOWED,
                "application_send_count": self.application_send_count,
                "session_continues": False,
            },
        }


_ASYNC_REGISTRATION = (
    ("Packet", "ClientInfo"),
    ("HWID", "6288BA49683DDB92689F03079156A2435DAD54B3432AE37C63745E69C8B50E85"),
    ("User", "sandbox-user"),
    ("OS", "Windows 10 Pro 64bit"),
    ("Path", r"C:\ProgramData\SystemCache\client.exe"),
    ("Admin", "User"),
    ("Performance", ""),
    ("Pastebin", ""),
    ("Antivirus", "Windows Defender"),
    ("Installed", "1970-01-01T00:00:00Z"),
    ("Pong", ""),
    ("Group", "Default"),
)

_VENOM_REGISTRATION = (
    ("Pac_ket", "ClientInfo"),
    ("ClientType", "Normal"),
    ("HWID", "42598CF28F9526EC96DBA8DA094C2DD84D2F221CDFA2CD02401175A49C30D279"),
    ("DesktopName", "sandbox-host"),
    ("User", "sandbox-user"),
    ("OS", "Windows 10 Pro 64bit"),
    ("Camera", "False"),
    ("Path", r"C:\ProgramData\SystemCache\client.exe"),
    ("Version", "Venom RAT + HVNC + Stealer + Grabber  v6.0.3"),
    ("Admin", "User"),
    ("Perfor_mance", ""),
    ("Paste_bin", ""),
    ("Anti_virus", "Windows Defender"),
    ("Install_ed", "1970-01-01T00:00:00Z"),
    ("Po_ng", ""),
    ("Group", "start"),
    ("CPU", "Synthetic CPU"),
    ("GPU", "Synthetic GPU"),
    ("RAM", "4 GB"),
    ("apps", ""),
    ("running", ""),
    ("keylogsetting", "{}"),
)

_PROFILES = {
    ASYNC_PROFILE_ID: ExactProfile(
        profile_id=ASYNC_PROFILE_ID,
        family="asyncrat",
        sample_sha256="20f21565d7e77f3b3b7247099af91da43dcde0078c173f8e6efc74a6d40b44c3",
        evidence_sha256="4c4f598aa861c1da660f513d419184b7b195994d322ed236684c7042ede31f81",
        packet_key="Packet",
        registration_fields=_ASYNC_REGISTRATION,
        heartbeat_request_opcode="Ping",
        heartbeat_response_opcode="pong",
        file_opcodes=frozenset({"plugin", "savePlugin", "winUpdate"}),
        operation_opcodes=frozenset(),
        handler="asyncrat_tls_messagepack",
    ),
    VENOM_PROFILE_ID: ExactProfile(
        profile_id=VENOM_PROFILE_ID,
        family="venomrat",
        sample_sha256="6a24ba25482c73d193fcc208d8ae267236b870b9ab30c44cabe2dc8bfb7a1073",
        evidence_sha256="2db755d8ed49d1488d558da77171be8a7ff95a175f1322e65b359a368a8219b9",
        packet_key="Pac_ket",
        registration_fields=_VENOM_REGISTRATION,
        heartbeat_request_opcode="Ping",
        heartbeat_response_opcode="Po_ng",
        file_opcodes=frozenset({"plu_gin", "save_Plugin", "loadofflinelog"}),
        operation_opcodes=frozenset(
            {"init_reg", "HVNCStop", "keylogsetting", "runningapp", "filterinfo"}
        ),
        handler="venomrat_tls_messagepack",
    ),
}


def resolve_profile(profile: str | Mapping[str, Any]) -> ExactProfile:
    if isinstance(profile, str):
        profile_id = profile
        binding: Mapping[str, Any] | None = None
    elif isinstance(profile, Mapping):
        profile_id = str(profile.get("profile_id") or "")
        binding = profile
    else:
        raise TypeError("profile must be an exact profile ID or a registry mapping")
    selected = _PROFILES.get(profile_id)
    if selected is None:
        raise TlsMessagePackHostError("unknown or unreviewed TLS MessagePack RAT profile")
    if binding is None:
        return selected
    expected_bindings = {
        "family": selected.family,
        "packet_key": selected.packet_key,
        "handler": selected.handler,
        "method": selected.handler,
    }
    for name, expected in expected_bindings.items():
        if name in binding and str(binding[name]) != expected:
            raise TlsMessagePackHostError(f"profile binding mismatch: {name}")
    if "sample_sha256s" in binding:
        supplied = {str(value).casefold() for value in binding["sample_sha256s"]}
        if supplied != {selected.sample_sha256}:
            raise TlsMessagePackHostError("profile sample binding mismatch")
    return selected


def build_synthetic_client_info(profile: str | Mapping[str, Any]) -> dict[str, str]:
    selected = resolve_profile(profile)
    if not selected.registration_enabled:
        raise TlsMessagePackHostError("registration is disabled because its static schema is incomplete")
    result = dict(selected.registration_fields)
    if len(result) != len(selected.registration_fields):
        raise TlsMessagePackHostError("the reviewed registration contains a duplicate key")
    if result.get(selected.packet_key) != "ClientInfo":
        raise TlsMessagePackHostError("the reviewed registration opcode is invalid")
    return result


def _encode_string(value: str, limits: SessionLimits) -> bytes:
    raw = value.encode("utf-8")
    size = len(raw)
    if size > limits.maximum_string_bytes:
        raise TlsMessagePackHostError("MessagePack string exceeds the reviewed limit")
    if size <= 31:
        return bytes([0xA0 | size]) + raw
    if size <= 0xFF:
        return b"\xD9" + bytes([size]) + raw
    if size <= 0xFFFF:
        return b"\xDA" + struct.pack(">H", size) + raw
    return b"\xDB" + struct.pack(">I", size) + raw


def _encode_integer(value: int) -> bytes:
    if isinstance(value, bool):
        raise TlsMessagePackHostError("boolean values are not part of the reviewed schema")
    if 0 <= value <= 0x7F:
        return bytes([value])
    if -32 <= value < 0:
        return bytes([value & 0xFF])
    if 0 <= value <= 0xFF:
        return b"\xCC" + struct.pack(">B", value)
    if 0 <= value <= 0xFFFF:
        return b"\xCD" + struct.pack(">H", value)
    if 0 <= value <= 0xFFFFFFFF:
        return b"\xCE" + struct.pack(">I", value)
    if 0 <= value <= 0x7FFFFFFFFFFFFFFF:
        return b"\xD3" + struct.pack(">q", value)
    if -0x80 <= value < -32:
        return b"\xD0" + struct.pack(">b", value)
    if -0x8000 <= value < -0x80:
        return b"\xD1" + struct.pack(">h", value)
    if -0x80000000 <= value < -0x8000:
        return b"\xD2" + struct.pack(">i", value)
    if -0x8000000000000000 <= value < -0x80000000:
        return b"\xD3" + struct.pack(">q", value)
    raise TlsMessagePackHostError("MessagePack integer is outside signed 64-bit range")


def _encode_binary(value: bytes, limits: SessionLimits) -> bytes:
    size = len(value)
    if size > limits.maximum_binary_bytes:
        raise TlsMessagePackHostError("MessagePack binary exceeds the reviewed limit")
    if size <= 0xFF:
        return b"\xC4" + bytes([size]) + value
    if size <= 0xFFFF:
        return b"\xC5" + struct.pack(">H", size) + value
    return b"\xC6" + struct.pack(">I", size) + value


def _encode_scalar(value: Scalar, limits: SessionLimits) -> bytes:
    if isinstance(value, str):
        return _encode_string(value, limits)
    if isinstance(value, bytes):
        return _encode_binary(value, limits)
    if isinstance(value, int) and not isinstance(value, bool):
        return _encode_integer(value)
    raise TlsMessagePackHostError("unsupported MessagePack scalar type")


def encode_messagepack_map(values: Mapping[str, Scalar], limits: SessionLimits | None = None) -> bytes:
    active = limits or SessionLimits()
    items = list(values.items())
    if not 1 <= len(items) <= active.maximum_map_entries:
        raise TlsMessagePackHostError("MessagePack map size is outside the reviewed limit")
    seen: set[str] = set()
    encoded = bytearray()
    for key, value in items:
        if not isinstance(key, str):
            raise TlsMessagePackHostError("MessagePack map keys must be strings")
        if key in seen:
            raise TlsMessagePackHostError("duplicate MessagePack map key")
        seen.add(key)
        encoded.extend(_encode_string(key, active))
        encoded.extend(_encode_scalar(value, active))
    count = len(items)
    header = bytes([0x80 | count]) if count <= 15 else b"\xDE" + struct.pack(">H", count)
    return header + bytes(encoded)


class _Reader:
    def __init__(self, data: bytes, limits: SessionLimits) -> None:
        self.data = data
        self.limits = limits
        self.offset = 0

    def take(self, size: int) -> bytes:
        if size < 0 or self.offset + size > len(self.data):
            raise TlsMessagePackHostError("truncated MessagePack value")
        value = self.data[self.offset : self.offset + size]
        self.offset += size
        return value

    def byte(self) -> int:
        return self.take(1)[0]

    def string(self, prefix: int) -> str:
        if 0xA0 <= prefix <= 0xBF:
            size = prefix & 0x1F
        elif prefix == 0xD9:
            size = self.byte()
            if size <= 31:
                raise TlsMessagePackHostError("noncanonical overlong str8 value")
        elif prefix == 0xDA:
            size = struct.unpack(">H", self.take(2))[0]
            if size <= 0xFF:
                raise TlsMessagePackHostError("noncanonical overlong str16 value")
        elif prefix == 0xDB:
            size = struct.unpack(">I", self.take(4))[0]
            if size <= 0xFFFF:
                raise TlsMessagePackHostError("noncanonical overlong str32 value")
        else:
            raise TlsMessagePackHostError("MessagePack map key or opcode is not a string")
        if size > self.limits.maximum_string_bytes:
            raise TlsMessagePackHostError("MessagePack string exceeds the reviewed limit")
        try:
            return self.take(size).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise TlsMessagePackHostError("MessagePack string is not valid UTF-8") from exc

    def integer(self, prefix: int) -> int:
        if prefix <= 0x7F:
            return prefix
        if prefix >= 0xE0:
            return prefix - 256
        formats = {
            0xCC: (">B", 1, lambda value: value > 0x7F),
            0xCD: (">H", 2, lambda value: value > 0xFF),
            0xCE: (">I", 4, lambda value: value > 0xFFFF),
            0xCF: (">Q", 8, lambda value: value > 0xFFFFFFFF),
            0xD0: (">b", 1, lambda value: value < -32),
            0xD1: (">h", 2, lambda value: value < -0x80),
            0xD2: (">i", 4, lambda value: value < -0x8000),
            0xD3: (">q", 8, lambda value: value < -0x80000000 or value > 0xFFFFFFFF),
        }
        item = formats.get(prefix)
        if item is None:
            raise TlsMessagePackHostError("unsupported MessagePack scalar type")
        format_string, size, canonical = item
        value = struct.unpack(format_string, self.take(size))[0]
        if not canonical(value):
            raise TlsMessagePackHostError("noncanonical overlong MessagePack integer")
        return int(value)

    def binary(self, prefix: int) -> bytes:
        if prefix == 0xC4:
            size = self.byte()
        elif prefix == 0xC5:
            size = struct.unpack(">H", self.take(2))[0]
            if size <= 0xFF:
                raise TlsMessagePackHostError("noncanonical overlong bin16 value")
        elif prefix == 0xC6:
            size = struct.unpack(">I", self.take(4))[0]
            if size <= 0xFFFF:
                raise TlsMessagePackHostError("noncanonical overlong bin32 value")
        else:
            raise TlsMessagePackHostError("unsupported MessagePack binary type")
        if size > self.limits.maximum_binary_bytes:
            raise TlsMessagePackHostError("MessagePack binary exceeds the reviewed limit")
        return self.take(size)

    def scalar(self) -> Scalar:
        prefix = self.byte()
        if 0xA0 <= prefix <= 0xBF or prefix in {0xD9, 0xDA, 0xDB}:
            return self.string(prefix)
        if prefix <= 0x7F or prefix >= 0xE0 or prefix in {0xCC, 0xCD, 0xCE, 0xCF, 0xD0, 0xD1, 0xD2, 0xD3}:
            return self.integer(prefix)
        if prefix in {0xC4, 0xC5, 0xC6}:
            return self.binary(prefix)
        raise TlsMessagePackHostError("unsupported MessagePack value type")


def _decode_messagepack_map(data: bytes, limits: SessionLimits) -> dict[str, Scalar]:
    if not data:
        raise TlsMessagePackHostError("empty MessagePack payload")
    reader = _Reader(data, limits)
    prefix = reader.byte()
    if 0x81 <= prefix <= 0x8F:
        count = prefix & 0x0F
    elif prefix == 0xDE:
        count = struct.unpack(">H", reader.take(2))[0]
        if count <= 15:
            raise TlsMessagePackHostError("noncanonical overlong map16 value")
    else:
        raise TlsMessagePackHostError("only fixmap and map16 are accepted")
    if not 1 <= count <= limits.maximum_map_entries:
        raise TlsMessagePackHostError("MessagePack map size is outside the reviewed limit")
    result: dict[str, Scalar] = {}
    for _ in range(count):
        key_prefix = reader.byte()
        key = reader.string(key_prefix)
        if key in result:
            raise TlsMessagePackHostError("duplicate MessagePack map key")
        result[key] = reader.scalar()
    if reader.offset != len(data):
        raise TlsMessagePackHostError("unparsed bytes follow the MessagePack map")
    return result


def _bounded_gzip_decompress(data: bytes, declared: int, limits: SessionLimits) -> bytes:
    if not 1 <= declared <= limits.maximum_decoded_bytes:
        raise TlsMessagePackHostError("declared decoded size is outside the reviewed limit")
    decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        raw = decompressor.decompress(data, declared + 1)
        raw += decompressor.flush(max(1, declared + 1 - len(raw)))
    except zlib.error as exc:
        raise TlsMessagePackHostError("invalid gzip payload") from exc
    if len(raw) > declared or len(raw) > limits.maximum_decoded_bytes:
        raise TlsMessagePackHostError("gzip decompression bomb or declared-size mismatch")
    if not decompressor.eof or decompressor.unconsumed_tail or decompressor.unused_data:
        raise TlsMessagePackHostError("truncated, concatenated, or trailing gzip data")
    if len(raw) != declared:
        raise TlsMessagePackHostError("decoded size does not match its declaration")
    return raw


def encode_frame(values: Mapping[str, Scalar], limits: SessionLimits | None = None) -> bytes:
    active = limits or SessionLimits()
    raw = encode_messagepack_map(values, active)
    if len(raw) > active.maximum_decoded_bytes:
        raise TlsMessagePackHostError("encoded MessagePack exceeds the reviewed decoded limit")
    payload = struct.pack("<I", len(raw)) + gzip.compress(raw, compresslevel=9, mtime=0)
    if len(payload) > active.maximum_frame_bytes:
        raise TlsMessagePackHostError("compressed frame exceeds the reviewed wire limit")
    return struct.pack("<I", len(payload)) + payload


def _decode_frame(frame: bytes, limits: SessionLimits) -> DecodedFrame:
    if len(frame) < 9:
        raise TlsMessagePackHostError("TLS MessagePack frame is too short")
    declared_frame = struct.unpack("<I", frame[:4])[0]
    if not 1 <= declared_frame <= limits.maximum_frame_bytes:
        raise TlsMessagePackHostError("declared frame size is outside the reviewed limit")
    if declared_frame != len(frame) - 4:
        raise TlsMessagePackHostError("wire frame size does not match its declaration")
    payload = frame[4:]
    declared_raw = struct.unpack("<I", payload[:4])[0]
    raw = _bounded_gzip_decompress(payload[4:], declared_raw, limits)
    values = _decode_messagepack_map(raw, limits)
    return DecodedFrame(
        values=values,
        frame_size=len(frame),
        frame_sha256=hashlib.sha256(frame).hexdigest(),
        compressed_payload_size=len(payload),
        compressed_payload_sha256=hashlib.sha256(payload).hexdigest(),
        decoded_size=len(raw),
        decoded_sha256=hashlib.sha256(raw).hexdigest(),
    )


def _binary_fingerprint(values: Mapping[str, Scalar]) -> dict[str, int | str | None]:
    """Summarize binary values without retaining their bytes or field names."""

    digest = hashlib.sha256()
    count = 0
    total_size = 0
    for value in values.values():
        if not isinstance(value, bytes):
            continue
        count += 1
        total_size += len(value)
        digest.update(struct.pack(">Q", len(value)))
        digest.update(value)
    return {
        "binary_payload_count": count,
        "binary_payload_size": total_size,
        "binary_payload_sha256": digest.hexdigest() if count else None,
    }


def classify_frame(
    frame: DecodedFrame,
    profile: str | Mapping[str, Any] | ExactProfile,
    limits: SessionLimits | None = None,
) -> CommandDecision:
    """Classify one decoded command without exposing command arguments."""

    active = limits or SessionLimits()
    selected = profile if isinstance(profile, ExactProfile) else resolve_profile(profile)
    opcode = frame.values.get(selected.packet_key)
    if not isinstance(opcode, str):
        raise TlsMessagePackHostError("command packet does not contain a string opcode")
    if len(opcode.encode("utf-8")) > active.maximum_opcode_bytes:
        raise TlsMessagePackHostError("command opcode exceeds the reviewed limit")
    fingerprint: dict[str, Any] = {
        "frame_size": frame.frame_size,
        "frame_sha256": frame.frame_sha256,
        "compressed_payload_size": frame.compressed_payload_size,
        "compressed_payload_sha256": frame.compressed_payload_sha256,
        "decoded_size": frame.decoded_size,
        "decoded_sha256": frame.decoded_sha256,
        **_binary_fingerprint(frame.values),
    }
    if opcode == selected.heartbeat_response_opcode:
        return CommandDecision(
            packet_kind="heartbeat",
            opcode=opcode,
            action="record_heartbeat_response_and_terminate",
            should_respond=False,
            terminate_session=True,
            file_or_plugin_retained=False,
            operation_executed=False,
            fingerprint=fingerprint,
        )
    if opcode in selected.file_opcodes:
        return CommandDecision(
            packet_kind="file_or_plugin",
            opcode=opcode,
            action="refuse_file_or_plugin_and_terminate",
            should_respond=False,
            terminate_session=True,
            file_or_plugin_retained=False,
            operation_executed=False,
            fingerprint=fingerprint,
        )
    if opcode in selected.operation_opcodes:
        return CommandDecision(
            packet_kind="operation",
            opcode=opcode,
            action="refuse_operation_and_terminate",
            should_respond=False,
            terminate_session=True,
            file_or_plugin_retained=False,
            operation_executed=False,
            fingerprint=fingerprint,
        )
    return CommandDecision(
        packet_kind="unknown",
        opcode=opcode,
        action="terminate_unknown_command",
        should_respond=False,
        terminate_session=True,
        file_or_plugin_retained=False,
        operation_executed=False,
        fingerprint=fingerprint,
    )


def synthetic_result_decision(
    profile: str | Mapping[str, Any], opcode: str, outcome: str
) -> dict[str, Any]:
    """Return a fixture-only decision; no arbitrary result has a live wire form."""

    selected = resolve_profile(profile)
    if not isinstance(opcode, str) or not opcode:
        raise TlsMessagePackHostError("synthetic-result opcode must be a non-empty string")
    if len(opcode.encode("utf-8")) > SessionLimits().maximum_opcode_bytes:
        raise TlsMessagePackHostError("synthetic-result opcode exceeds the reviewed limit")
    allowed_outcomes = {"success", "failure", "unsupported", "not_executed"}
    if outcome not in allowed_outcomes:
        raise TlsMessagePackHostError("unsupported abstract synthetic-result outcome")
    decision = SyntheticResultDecision(opcode=opcode, outcome=outcome)
    result = decision.to_dict()
    result["profile_id"] = selected.profile_id
    return result


@dataclass
class _ReadBudget:
    calls: int = 0
    received_bytes: int = 0


def _recv_exact(stream: RatStream, size: int, limits: SessionLimits, budget: _ReadBudget) -> bytes:
    output = bytearray()
    while len(output) < size:
        if budget.calls >= limits.maximum_read_calls:
            raise TlsMessagePackHostError("stream exceeded the reviewed read-call limit")
        requested = size - len(output)
        budget.calls += 1
        try:
            chunk = stream.recv(requested)
        except TimeoutError as exc:
            raise TlsMessagePackHostError("stream timed out while reading one frame") from exc
        if not isinstance(chunk, (bytes, bytearray, memoryview)):
            raise TlsMessagePackHostError("stream returned a non-bytes value")
        raw_chunk = bytes(chunk)
        if len(raw_chunk) > requested:
            raise TlsMessagePackHostError("stream returned more bytes than requested")
        if not raw_chunk:
            raise TlsMessagePackHostError("stream closed before one frame was complete")
        output.extend(raw_chunk)
        budget.received_bytes += len(raw_chunk)
    return bytes(output)


def _read_one_frame(stream: RatStream, limits: SessionLimits, budget: _ReadBudget) -> DecodedFrame:
    application_reader = getattr(stream, "recv_application_frame", None)
    if callable(application_reader):
        before = getattr(stream, "inbound_read_calls", None)
        frame = application_reader(limits.maximum_frame_bytes)
        if not isinstance(frame, bytes) or not frame:
            raise TlsMessagePackHostError("stream closed before one frame was complete")
        after = getattr(stream, "inbound_read_calls", None)
        if isinstance(before, int) and isinstance(after, int) and after >= before:
            budget.calls = after - before
        else:
            budget.calls = 1
        budget.received_bytes = len(frame)
        return _decode_frame(frame, limits)
    header = _recv_exact(stream, 4, limits, budget)
    declared = struct.unpack("<I", header)[0]
    if not 1 <= declared <= limits.maximum_frame_bytes:
        raise TlsMessagePackHostError("declared frame size is outside the reviewed limit")
    body = _recv_exact(stream, declared, limits, budget)
    return _decode_frame(header + body, limits)


def _wire_metadata(packet_kind: str, opcode: str, frame: bytes, limits: SessionLimits) -> dict[str, Any]:
    decoded = _decode_frame(frame, limits)
    return {
        "packet_kind": packet_kind,
        "opcode": opcode,
        "frame_size": decoded.frame_size,
        "frame_sha256": decoded.frame_sha256,
        "decoded_size": decoded.decoded_size,
        "decoded_sha256": decoded.decoded_sha256,
    }


def _emit(callback: Callable[[dict[str, Any]], None] | None, event: dict[str, Any]) -> None:
    if callback is not None:
        callback(dict(event))


def run_host_session(
    stream: RatStream,
    profile: str | Mapping[str, Any],
    *,
    session_limits: Mapping[str, int | float] | SessionLimits | None = None,
    allow_registration: bool = False,
    allow_heartbeat_request: bool = False,
    transcript_callback: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Run one bounded application session over a caller-owned TLS-like stream."""

    selected = resolve_profile(profile)
    limits = (
        session_limits
        if isinstance(session_limits, SessionLimits)
        else SessionLimits.from_mapping(session_limits)
    )
    if not allow_registration:
        raise TlsMessagePackHostError("synthetic ClientInfo transmission requires explicit approval")
    if not selected.registration_enabled:
        raise TlsMessagePackHostError("registration is disabled because its schema is incomplete")

    stream.settimeout(float(limits.timeout_seconds))
    registration_frame = encode_frame(build_synthetic_client_info(selected.profile_id), limits)
    if len(registration_frame) > limits.maximum_send_bytes:
        raise TlsMessagePackHostError("synthetic registration exceeds the send-byte limit")
    stream.sendall(registration_frame)
    send_count = 1
    sent_bytes = len(registration_frame)
    registration = _wire_metadata("registration", "ClientInfo", registration_frame, limits)
    registration["synthetic"] = True
    _emit(transcript_callback, {"event": "registration_sent", **registration})

    heartbeat_request: dict[str, Any] = {
        "packet_kind": "heartbeat_request",
        "opcode": selected.heartbeat_request_opcode,
        "sent": False,
        "synthetic": True,
    }
    if allow_heartbeat_request:
        if not selected.heartbeat_request_reviewed:
            raise TlsMessagePackHostError("heartbeat request schema is not reviewed")
        request_values: dict[str, Scalar] = {
            selected.packet_key: selected.heartbeat_request_opcode,
            "Message": "",
        }
        heartbeat_frame = encode_frame(request_values, limits)
        if sent_bytes + len(heartbeat_frame) > limits.maximum_send_bytes:
            raise TlsMessagePackHostError("heartbeat request exceeds the session send-byte limit")
        stream.sendall(heartbeat_frame)
        send_count += 1
        heartbeat_request = _wire_metadata(
            "heartbeat_request",
            selected.heartbeat_request_opcode,
            heartbeat_frame,
            limits,
        )
        heartbeat_request["sent"] = True
        heartbeat_request["synthetic"] = True
        _emit(
            transcript_callback,
            {"event": "heartbeat_request_sent", **heartbeat_request},
        )

    budget = _ReadBudget()
    decoded = _read_one_frame(stream, limits, budget)
    decision = classify_frame(decoded, selected, limits)
    _emit(transcript_callback, {"event": "command_classified", **decision.to_dict()})

    status = {
        "heartbeat": (
            "heartbeat_response_observed"
            if heartbeat_request["sent"]
            else "unsolicited_heartbeat_response_observed"
        ),
        "file_or_plugin": "file_or_plugin_refused",
        "operation": "operation_refused",
        "unknown": "unknown_command_terminated",
    }[decision.packet_kind]

    _emit(
        transcript_callback,
        {"event": "session_terminated", "packet_kind": decision.packet_kind, "opcode": decision.opcode},
    )
    return HostSessionResult(
        profile=selected,
        status=status,
        registration=registration,
        decision=decision,
        heartbeat_request=heartbeat_request,
        received_bytes=budget.received_bytes,
        read_calls=budget.calls,
        application_send_count=send_count,
    ).to_dict()
