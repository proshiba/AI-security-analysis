"""Extract native PureHVNC and managed PureRAT configuration without execution."""

from __future__ import annotations

import base64
import gzip
import ipaddress
import re
from collections import defaultdict
from typing import Any, Iterator

import dnfile

from extractors.common import build_result, extract_strings, sha256_bytes


def read_varint(data: bytes, offset: int) -> tuple[int, int]:
    """Read one protobuf varint and return its value and next offset."""
    value = 0
    for shift in range(0, 70, 7):
        if offset >= len(data):
            raise ValueError("truncated protobuf varint")
        current = data[offset]
        offset += 1
        value |= (current & 0x7F) << shift
        if not current & 0x80:
            return value, offset
    raise ValueError("protobuf varint exceeds 64 bits")


def parse_protobuf(data: bytes) -> dict[int, list[Any]]:
    """Parse protobuf wire types used by the reviewed PureRAT configuration."""
    fields: dict[int, list[Any]] = defaultdict(list)
    offset = 0
    while offset < len(data):
        key, offset = read_varint(data, offset)
        number, wire = key >> 3, key & 7
        if number == 0:
            raise ValueError("invalid protobuf field zero")
        if wire == 0:
            value, offset = read_varint(data, offset)
        elif wire == 1:
            if offset + 8 > len(data):
                raise ValueError("truncated protobuf fixed64")
            value, offset = data[offset : offset + 8], offset + 8
        elif wire == 2:
            length, offset = read_varint(data, offset)
            if offset + length > len(data):
                raise ValueError("truncated protobuf field")
            value, offset = data[offset : offset + length], offset + length
        elif wire == 5:
            if offset + 4 > len(data):
                raise ValueError("truncated protobuf fixed32")
            value, offset = data[offset : offset + 4], offset + 4
        else:
            raise ValueError(f"unsupported protobuf wire type: {wire}")
        fields[number].append(value)
    return dict(fields)


def iter_dotnet_user_strings(data: bytes) -> Iterator[str]:
    """Yield managed #US values when *data* is a valid .NET PE image."""
    try:
        pe = dnfile.dnPE(data=data)
    except Exception:
        return
    if not pe.net:
        return
    heap = pe.net.user_strings
    offset = 1
    while offset < heap.sizeof():
        item = heap.get(offset, errors="replace")
        if item is None or item.raw_size <= 0:
            offset += 1
            continue
        if isinstance(item.value, str):
            yield item.value
        offset += item.raw_size


def decode_config_blob(strings: list[str]) -> tuple[bytes, dict[int, list[Any]]]:
    """Locate Base64/GZip protobuf data and return its nested PureRAT message."""
    candidates: list[bytes] = []
    for value in strings:
        try:
            candidates.append(gzip.decompress(base64.b64decode(value, validate=True)))
        except (ValueError, OSError):
            continue
    for clear in sorted(candidates, key=len, reverse=True):
        try:
            outer = parse_protobuf(clear)
        except ValueError:
            continue
        for nested in outer.get(38, []):
            if isinstance(nested, bytes):
                try:
                    fields = parse_protobuf(nested)
                except ValueError:
                    continue
                if 1 in fields and 2 in fields:
                    return nested, fields
        if 1 in outer and 2 in outer:
            return clear, outer
    raise ValueError("managed PureRAT Base64/GZip protobuf config was not found")


def _text(value: Any) -> str:
    """Decode one protobuf byte string for a publish-safe value."""
    return value.decode("utf-8", errors="replace") if isinstance(value, bytes) else str(value)


def certificate_metadata(value: str) -> dict[str, Any]:
    """Return public PKCS#12 certificate metadata without exposing its private key."""
    try:
        from cryptography.hazmat.primitives.serialization import Encoding, pkcs12

        raw = base64.b64decode(value, validate=True)
        _key, cert, _chain = pkcs12.load_key_and_certificates(raw, None)
        if cert is None:
            raise ValueError("PKCS#12 has no leaf certificate")
        return {
            "pfx_sha256": sha256_bytes(raw),
            "certificate_sha256": sha256_bytes(cert.public_bytes(Encoding.DER)),
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "serial_number": cert.serial_number,
            "not_before": cert.not_valid_before_utc.isoformat(),
            "not_after": cert.not_valid_after_utc.isoformat(),
        }
    except Exception as error:
        return {"parse_error": type(error).__name__}


def extract_managed_config(data: bytes) -> dict[str, Any]:
    """Extract the managed PureRAT protobuf config and certificate fingerprints."""
    strings = list(iter_dotnet_user_strings(data))
    _blob, fields = decode_config_blob(strings)
    host = _text(fields[1][0]).lower().rstrip(".")
    ports = [int(item) for item in fields[2] if isinstance(item, int)]
    config: dict[str, Any] = {
        "variant": "managed_purerat",
        "c2_host": host,
        "c2_ports": ports,
        "campaign_id": _text(fields.get(4, [b""])[0]),
        "persistence": bool(fields.get(5, [0])[0]),
        "prevent_sleep": bool(fields.get(6, [0])[0]),
        "scheduled_task": _text(fields.get(7, [b""])[0]),
        "install_environment": _text(fields.get(8, [b""])[0]),
        "mutex": _text(fields.get(9, [b""])[0]),
        "endpoints": [f"{host}:{port}" for port in ports],
    }
    if 3 in fields:
        config["certificate"] = certificate_metadata(_text(fields[3][0]))
    versions = sorted({item for item in strings if re.fullmatch(r"\d+\.\d+\.\d+", item)})
    if versions:
        config["version_candidates"] = versions
    return config


def extract_native_config(data: bytes) -> dict[str, Any]:
    """Extract a conservative native 10FX-framed PureHVNC endpoint profile."""
    strings = extract_strings(data, minimum=3)
    ips = []
    for value in strings:
        for candidate in re.findall(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])", value):
            try:
                address = ipaddress.ip_address(candidate)
            except ValueError:
                continue
            if not address.is_unspecified and not address.is_multicast:
                ips.append(candidate)
    ips = list(dict.fromkeys(ips))
    if b"10FX" not in data and b"XF01" not in data and not any("START_SCREEN" in item for item in strings):
        raise ValueError("native PureHVNC protocol markers were not found")
    ports = sorted({int(item) for value in strings for item in re.findall(r"(?<!\d)(?:8080|[1-9]\d{3,4})(?!\d)", value) if int(item) <= 65535})
    endpoints = [f"{host}:{port}" for host in ips for port in ports]
    return {"variant": "native_10fx", "c2_hosts": ips, "c2_ports": ports, "endpoints": endpoints, "frame_magic": "0x58463031", "frame_magic_ascii": "10FX"}


def extract(data: bytes, name: str = "sample") -> dict:
    """Extract PureRAT/PureHVNC config, preferring the managed protobuf profile."""
    limitations = ["Static extraction only; no payload execution or C2 contact was performed."]
    try:
        config, confidence = extract_managed_config(data), "confirmed"
    except ValueError:
        try:
            config, confidence = extract_native_config(data), "high"
        except ValueError:
            config, confidence = {"variant": "unrecognized", "endpoints": []}, "unverified"
            limitations.append("No supported managed protobuf or native 10FX profile was found.")
    config["source_name"] = name
    findings = [{"kind": "network.endpoint", "value": endpoint, "role": "configured_c2", "confidence": confidence, "source": "static_config"} for endpoint in config.get("endpoints", [])]
    return build_result("purehvnc", data, config, findings, limitations)
