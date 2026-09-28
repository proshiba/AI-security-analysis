"""検体を実行せずnative PureHVNCとmanaged PureRATの設定を抽出する。"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import re
import zlib
from collections import defaultdict
from collections.abc import Iterator
from typing import Any

import dnfile
import pefile

from extractors.common import build_result, extract_strings, sha256_bytes
from extractors.managed_pe import has_clr_metadata


HANDLER_CONTRACT = {
    "input_formats": ["pe"],
    "minimum_evidence_score": 1,
}


class _ManagedMetadataError(ValueError):
    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


MAX_CONFIG_BASE64_CHARS = 8 * 1024 * 1024
MAX_CONFIG_COMPRESSED_BYTES = 6 * 1024 * 1024
MAX_CONFIG_CLEAR_BYTES = 4 * 1024 * 1024
MAX_CONFIG_PROTOBUF_FIELDS = 4_096
MAX_CONFIG_NESTING = 3
MAX_CONFIG_MESSAGE_CANDIDATES = 128
MAX_CONFIG_DECODE_CANDIDATES = 64
MAX_MANAGED_TERMINAL_BYTES = 16 * 1024 * 1024
MAX_MANAGED_USER_STRINGS = 16_384
MAX_FALLBACK_STRINGS = 16_384


def read_varint(data: bytes, offset: int) -> tuple[int, int]:
    """protobuf varintを1個読み、値と次のoffsetを返す。"""
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
    """確認済みPureRAT設定で使うprotobuf wire typeを境界付きで解析する。"""
    if not isinstance(data, bytes) or len(data) > MAX_CONFIG_CLEAR_BYTES:
        raise ValueError("protobuf input exceeds the static-analysis limit")
    fields: dict[int, list[Any]] = defaultdict(list)
    offset = 0
    field_count = 0
    while offset < len(data):
        field_count += 1
        if field_count > MAX_CONFIG_PROTOBUF_FIELDS:
            raise ValueError("protobuf field count exceeds the static-analysis limit")
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


def _bounded_gzip_decompress(data: bytes) -> bytes:
    """単一GZip memberだけを固定上限内で展開する。"""

    if not data or len(data) > MAX_CONFIG_COMPRESSED_BYTES:
        raise ValueError("managed PureRAT compressed config exceeds the input limit")
    inflater = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        clear = inflater.decompress(data, MAX_CONFIG_CLEAR_BYTES + 1)
    except zlib.error as error:
        raise ValueError("managed PureRAT config is not valid GZip") from error
    if (
        len(clear) > MAX_CONFIG_CLEAR_BYTES
        or not inflater.eof
        or inflater.unused_data
        or inflater.unconsumed_tail
    ):
        raise ValueError("managed PureRAT GZip config violates output boundaries")
    return clear


def _decode_base64_gzip(value: str) -> bytes:
    """Convert.FromBase64String互換の空白を除去し、GZipを有界展開する。"""

    if not isinstance(value, str) or len(value) > MAX_CONFIG_BASE64_CHARS:
        raise ValueError("managed PureRAT Base64 config exceeds the input limit")
    compact = "".join(value.split())
    if not compact or len(compact) > MAX_CONFIG_BASE64_CHARS:
        raise ValueError("managed PureRAT Base64 config is empty or oversized")
    try:
        compressed = base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError) as error:
        raise ValueError("managed PureRAT config is not canonical Base64") from error
    return _bounded_gzip_decompress(compressed)


def _looks_like_base64_gzip(value: str) -> bool:
    """GZip magicをBase64化したprefixを安価に確認する。"""

    if not isinstance(value, str) or not 4 <= len(value) <= MAX_CONFIG_BASE64_CHARS:
        return False
    prefix: list[str] = []
    for character in value:
        if character.isspace():
            continue
        prefix.append(character)
        if len(prefix) == 4:
            break
    return "".join(prefix) == "H4sI"


def _packed_varints(value: bytes) -> list[int]:
    """protobuf-netのpacked repeated integerを終端まで厳格に読む。"""

    values: list[int] = []
    offset = 0
    while offset < len(value):
        item, offset = read_varint(value, offset)
        values.append(item)
        if len(values) > 32:
            raise ValueError("packed port list exceeds the static-analysis limit")
    return values


def _normalise_config_fields(fields: dict[int, list[Any]]) -> dict[int, list[Any]]:
    """field 2のpacked／unpacked表現を同じport列へ正規化する。"""

    if 2 not in fields:
        return fields
    ports: list[int] = []
    for item in fields[2]:
        if isinstance(item, int) and not isinstance(item, bool):
            ports.append(item)
        elif isinstance(item, bytes):
            ports.extend(_packed_varints(item))
        else:
            raise ValueError("managed PureRAT port field has an unsupported type")
    normalized = dict(fields)
    normalized[2] = ports
    return normalized


def _valid_config_fields(fields: dict[int, list[Any]]) -> bool:
    """hostとportの構文を満たすmessageだけを設定候補にする。"""

    if not fields.get(1) or len(fields[1]) != 1 or not fields.get(2):
        return False
    host_value = fields[1][0]
    if not isinstance(host_value, bytes):
        return False
    try:
        host = host_value.decode("utf-8").casefold().rstrip(".")
    except UnicodeDecodeError:
        return False
    if not host or len(host) > 253:
        return False
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        labels = host.split(".")
        if len(labels) < 2 or any(
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
            for label in labels
        ):
            return False
    else:
        if address.is_unspecified or address.is_multicast:
            return False
    ports = fields[2]
    return (
        1 <= len(ports) <= 8
        and len(set(ports)) == len(ports)
        and all(isinstance(port, int) and not isinstance(port, bool) and 1 <= port <= 65535 for port in ports)
    )


def _iter_nested_messages(data: bytes) -> Iterator[tuple[bytes, dict[int, list[Any]]]]:
    """外包みfield番号に依存せず、境界付きで入れ子messageを探索する。"""

    pending: list[tuple[bytes, int]] = [(data, 0)]
    seen: set[str] = set()
    count = 0
    while pending:
        raw, depth = pending.pop(0)
        digest = sha256_bytes(raw)
        if digest in seen:
            continue
        seen.add(digest)
        # 成功・失敗ともuniqueな構造解析を既存の128件枠へ一度だけ計上する。
        count += 1
        if count > MAX_CONFIG_MESSAGE_CANDIDATES:
            raise ValueError("managed PureRAT nested message candidate limit exceeded")
        try:
            parsed = parse_protobuf(raw)
        except ValueError:
            continue
        # 深さ上限の先は構造確認だけ。未評価messageを設定候補へ昇格しない。
        if depth > MAX_CONFIG_NESTING:
            raise ValueError("managed PureRAT nested message depth limit exceeded")
        try:
            fields = _normalise_config_fields(parsed)
        except ValueError:
            fields = parsed
        yield raw, fields
        for values in parsed.values():
            for value in values:
                if isinstance(value, bytes) and 2 <= len(value) <= MAX_CONFIG_CLEAR_BYTES:
                    pending.append((value, depth + 1))


def _config_identity(fields: dict[int, list[Any]]) -> tuple[Any, ...]:
    """field順序に依存せず、同じ設定messageを一意に比較する。"""

    normalized: list[tuple[int, tuple[tuple[str, Any], ...]]] = []
    for number in sorted(fields):
        values: list[tuple[str, Any]] = []
        for value in fields[number]:
            if isinstance(value, bytes):
                # 単一hostだけを既存出力と同じ表記へ正規化する。
                # port順、証明書、未知field、複数hostのbyte同一性は変えない。
                identity_value = (
                    value.decode("utf-8").lower().rstrip(".").encode("utf-8")
                    if number == 1 and len(fields[number]) == 1
                    and not value.endswith(b"..") and all(octet < 128 for octet in value)
                    else value
                )
                values.append(("bytes_sha256", sha256_bytes(identity_value)))
            elif isinstance(value, int) and not isinstance(value, bool):
                values.append(("integer", value))
            else:
                raise ValueError("managed PureRAT config identity has an invalid value")
        normalized.append((number, tuple(values)))
    return tuple(normalized)


def iter_dotnet_user_strings(data: bytes) -> Iterator[str]:
    """有効な#US heapがある.NET PEだけから範囲内の文字列を返す。"""
    if not has_clr_metadata(data):
        return
    try:
        pe = dnfile.dnPE(data=data)
    except Exception:  # noqa: BLE001 - 任意の壊れたmanaged metadataを検出器境界で拒否する
        return
    try:
        heap = pe.net.user_strings
    except AttributeError:
        return
    if heap is None:
        return
    heap_size = heap.sizeof()
    if not isinstance(heap_size, int) or not 0 <= heap_size <= len(data):
        raise _ManagedMetadataError("user_string_heap_size_invalid")
    offset = 1
    while offset < heap_size:
        item = heap.get(offset, errors="replace")
        if item is None or item.raw_size <= 0:
            offset += 1
            continue
        if item.raw_size > heap_size - offset:
            raise _ManagedMetadataError("user_string_item_out_of_bounds")
        if isinstance(item.value, str):
            yield item.value
        offset += item.raw_size


def _iter_bounded_embedded_strings(data: bytes) -> Iterator[str]:
    """raw resource候補のASCII／UTF-16LE文字列を件数上限付きで列挙する。"""

    patterns = (
        (re.compile(rb"[\x20-\x7e]{24,}"), "ascii"),
        (re.compile(rb"(?:[\x20-\x7e]\x00){24,}"), "utf-16le"),
    )
    seen: set[str] = set()
    observed = 0
    for pattern, encoding in patterns:
        for match in pattern.finditer(data):
            observed += 1
            if observed > MAX_FALLBACK_STRINGS:
                raise _ManagedMetadataError("managed_embedded_string_count_exceeded")
            value = match.group().decode(encoding, errors="ignore")
            if value and value not in seen:
                seen.add(value)
                yield value


def decode_config_blob(strings: list[str]) -> tuple[bytes, dict[int, list[Any]]]:
    """Base64／GZip／protobuf候補を検証し、一意なPureRAT設定messageを返す。"""
    configurations: dict[
        tuple[Any, ...],
        tuple[bytes, dict[int, list[Any]]],
    ] = {}
    decoded_candidate_count = 0
    for value in strings:
        if not _looks_like_base64_gzip(value):
            continue
        decoded_candidate_count += 1
        if decoded_candidate_count > MAX_CONFIG_DECODE_CANDIDATES:
            raise ValueError("managed PureRAT Base64/GZip candidate limit exceeded")
        try:
            clear = _decode_base64_gzip(value)
        except ValueError:
            continue
        for raw, fields in _iter_nested_messages(clear):
            if len(fields.get(1, [])) > 1:
                # 旧host/port条件で受理されるmessageだけを単一host契約の違反にする。
                # 任意wrapperを設定と推測せず、他candidateからも相反を隠さない。
                first_host_fields = dict(fields)
                first_host_fields[1] = fields[1][:1]
                if _valid_config_fields(first_host_fields):
                    raise ValueError("managed PureRAT host field multiplicity is unsupported")
            if _valid_config_fields(fields):
                identity = _config_identity(fields)
                if identity not in configurations:
                    configurations[identity] = (raw, fields)
    if len(configurations) > 1:
        raise ValueError("conflicting managed PureRAT configurations were found")
    if configurations:
        return next(iter(configurations.values()))
    raise ValueError("managed PureRAT Base64/GZip protobuf config was not found")


def _text(value: Any) -> str:
    """protobufのbyte列を公開用文字列へ変換する。"""
    return value.decode("utf-8", errors="replace") if isinstance(value, bytes) else str(value)


def certificate_metadata(value: str) -> dict[str, Any]:
    """秘密鍵を公開せずPKCS#12証明書の公開metadataだけを返す。"""
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
    except Exception as error:  # noqa: BLE001 - 証明書parser境界をfail-closedにする
        return {"parse_error": type(error).__name__}


def extract_managed_config(data: bytes) -> dict[str, Any]:
    """managed PureRATの厳密protobuf設定と公開証明書fingerprintを抽出する。"""
    if len(data) > MAX_MANAGED_TERMINAL_BYTES:
        raise _ManagedMetadataError("managed_input_size_exceeded")
    metadata_error: _ManagedMetadataError | None = None
    try:
        strings = []
        for value in iter_dotnet_user_strings(data):
            strings.append(value)
            if len(strings) > MAX_MANAGED_USER_STRINGS:
                raise _ManagedMetadataError("managed_user_string_count_exceeded")
    except _ManagedMetadataError as error:
        metadata_error = error
        strings = []
    # 一部のprotectorは設定文字列を#USではなくmanifest resourceへ移す。
    # CLR構造が妥当な場合だけ、raw resource内の連続ASCII／UTF-16文字列を
    # 同じ厳格なBase64/GZip/protobuf検証へ渡す。
    if has_clr_metadata(data):
        fallback = list(_iter_bounded_embedded_strings(data))
        strings = list(dict.fromkeys([*strings, *fallback]))
    if not strings:
        raise metadata_error or _ManagedMetadataError("managed_user_strings_unavailable")
    try:
        _blob, fields = decode_config_blob(strings)
    except ValueError:
        if metadata_error is not None:
            raise metadata_error
        raise
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


def _valid_ipv4(value: str) -> bool:
    """未指定・multicastではない妥当なIPv4 literalかを返す。"""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return address.version == 4 and not address.is_unspecified and not address.is_multicast


def native_endpoint_candidates(strings: list[str], adjacency: int = 2) -> list[str]:
    """隣接native IP／portを相関し、無関係なport風文字列を除外する。"""
    if adjacency < 0:
        raise ValueError("adjacency must be non-negative")
    endpoints: set[str] = set()
    for value in strings:
        for host, raw_port in re.findall(r"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})\s*:\s*(\d{1,5})(?!\d)", value):
            port = int(raw_port)
            if _valid_ipv4(host) and 0 < port <= 65535:
                endpoints.add(f"{host}:{port}")
    for index, value in enumerate(strings):
        host = value.strip()
        if not re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host) or not _valid_ipv4(host):
            continue
        start, stop = max(0, index - adjacency), min(len(strings), index + adjacency + 1)
        for neighbor in strings[start:stop]:
            raw_port = neighbor.strip()
            if re.fullmatch(r"\d{1,5}", raw_port) and 0 < int(raw_port) <= 65535:
                endpoints.add(f"{host}:{int(raw_port)}")
    return sorted(endpoints)


def extract_native_config(data: bytes) -> dict[str, Any]:
    """native 10FX PureHVNCの確認済みmarkerとendpoint候補を保守的に抽出する。"""
    strings = extract_strings(data, minimum=3)
    upper = data.upper()
    upper_strings = [value.upper() for value in strings]
    frame_marker = (
        b"10FX" in upper
        or b"XF01" in upper
        or any(marker in value for value in upper_strings for marker in ("10FX", "XF01"))
    )
    command_marker = (
        b"START_SCREEN" in upper
        or b"SCREENSHOT_PREVIEW" in upper
        or any(
            marker in value
            for value in upper_strings
            for marker in ("START_SCREEN", "SCREENSHOT_PREVIEW")
        )
    )
    if not frame_marker or not command_marker:
        raise ValueError("corroborated native PureHVNC protocol markers were not found")
    endpoints = native_endpoint_candidates(strings)
    if not endpoints:
        raise ValueError("native PureHVNC endpoint tuple was not found")
    hosts = sorted({value.rsplit(":", 1)[0] for value in endpoints})
    ports = sorted({int(value.rsplit(":", 1)[1]) for value in endpoints})
    return {
        "variant": "native_10fx",
        "c2_hosts": hosts,
        "c2_ports": ports,
        "endpoints": endpoints,
        "frame_magic": "0x58463031",
        "frame_magic_ascii": "10FX",
    }


def extract_direct_config(data: bytes) -> tuple[dict[str, Any], str]:
    """回収済み終端payloadからmanaged設定またはnative候補を抽出する。"""
    try:
        return extract_managed_config(data), "confirmed"
    except ValueError:
        return extract_native_config(data), "high"


def extract_chrd_carrier(data: bytes) -> tuple[dict[str, Any], dict[str, Any]]:
    """CHRD／Donut carrierを静的復元し、managed終端のPureRAT設定を抽出する。"""
    from unpackers.chrd_donut_unpacker import unpack_chrd_donut

    chain = unpack_chrd_donut(data)
    config = extract_managed_config(chain.terminal_payload)
    config.update(
        {
            "delivery_profile": "chrd_wave_donut",
            "terminal_sha256": sha256_bytes(chain.terminal_payload),
            "chain": chain.metadata,
        }
    )
    return config, chain.metadata


def extract(data: bytes, name: str = "sample") -> dict:
    """直接またはCHRD経由の設定を復元し、managed成功だけを標準契約へ反映する。"""
    limitations = ["静的抽出だけを実施し、payload実行やC2への接続は行っていない。"]
    try:
        config, confidence = extract_direct_config(data)
    except ValueError:
        if data.startswith(b"MZ") and b"CHRD" in data:
            try:
                config, _metadata = extract_chrd_carrier(data)
                confidence = "confirmed"
            except (ValueError, RuntimeError, OSError, pefile.PEFormatError) as error:
                config, confidence = {"variant": "unrecognized", "endpoints": []}, "unverified"
                limitations.append(f"CHRD carrierの復元検証に失敗した: {type(error).__name__}。")
        else:
            config, confidence = {"variant": "unrecognized", "endpoints": []}, "unverified"
            limitations.append("対応するmanaged protobuf、native 10FX、CHRD carrier profileを確認できなかった。")
    # native候補や未復元結果を標準config復元へ広げない。family確証は別detectorで相関する。
    managed_recovered = config.get("variant") == "managed_purerat" and confidence == "confirmed"
    config["static_config_recovered"] = managed_recovered
    config["decoded_config_recovered"] = managed_recovered
    config["source_name"] = name
    findings = [
        {
            "kind": "network.endpoint",
            "value": endpoint,
            "role": "configured_c2",
            "confidence": confidence,
            "source": "static_config",
        }
        for endpoint in config.get("endpoints", [])
    ]
    result = build_result("purehvnc", data, config, findings, limitations)
    result["c2"] = [
        {
            "host": config["c2_host"],
            "port": port,
            "role": "c2",
            "confidence": "confirmed_static_configuration",
            "evidence": {
                "kind": "managed_base64_gzip_protobuf_config",
                "variant": "managed_purerat",
                "host_and_ports_validated": True,
                "endpoint_correlated": True,
            },
        }
        for port in config["c2_ports"]
    ] if managed_recovered else []
    return result
