"""PureLogsの静的文字列または復号済み通信メタデータから設定候補を抽出する。"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import json
import re
from collections.abc import Iterator
from typing import Any
from urllib.parse import urlsplit

from extractors.common import build_result, sha256_bytes
from extractors.purehvnc.extractor import parse_protobuf
from extractors.purelogs.managed_resource import (
    PureLogsManagedResource,
    public_recovery_evidence,
    recover_purelogs_managed_strings,
)
from extractors.purelogs.yqty_resource import PureLogsYqtyResource

MAX_SCAN_BYTES = 128 * 1024 * 1024
MAX_TEXT_CHARS = 16 * 1024 * 1024
MAX_TEXT_STRINGS = 16_384
MAX_STRUCTURED_METADATA_BYTES = 1 * 1024 * 1024
MAX_STRUCTURED_CHANNELS = 4_096
MAX_ENDPOINT_CANDIDATES = 16_384
PROTOCOL_PATHS = (
    "/ping",
    "/plugin",
    "/userinfo",
    "/browser",
    "/application",
    "/crypto",
    "/discord",
    "/filesearch/req",
    "/filesearch/res",
    "/finish",
)
PRODUCT_MARKERS = ("purelogs", "protobuf-net")
DELIVERY_MARKERS = (
    "KpTpQWPnqL",
    "FPuXKfGtMg",
    "MicrosoftEdgeUpdateTaskMachineCore__",
    "UserInitMprLogonScript",
)
HOST_PORT_RE = re.compile(
    r"(?<![A-Za-z0-9.-])"
    r"((?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}"
    r"|(?:\d{1,3}\.){3}\d{1,3})"
    r":(\d{1,5})(?!\d)",
    re.IGNORECASE,
)
URL_RE = re.compile(r"https?://[^\s\"'<>\\]+", re.IGNORECASE)
BASE64_RUN_RE = re.compile(
    r"(?<![A-Za-z0-9+/])(?:[A-Za-z0-9+/]{4}){4,}"
    r"(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?"
    r"(?![A-Za-z0-9+/=])"
)
MAX_CONFIG_BASE64_CHARS = 8 * 1024 * 1024
MAX_CONFIG_CLEAR_BYTES = 4 * 1024 * 1024
MAX_CONFIG_CANDIDATES = 64
MAX_CONFIG_MESSAGES = 128
MAX_CONFIG_NESTING = 3
MAX_CONFIG_TOTAL_FIELDS = 32_768
MAX_CONFIG_STRING_VALUES = 16_384
MAX_CONFIG_INTEGER_VALUES = 4_096
MAX_CONFIG_KEY_HASHES = 64
_BOUNDED_STRING_PATTERNS = (
    (re.compile(rb"[\x20-\x7e]{4,}"), "ascii", 1),
    (re.compile(rb"(?:[\x20-\x7e]\x00){4,}"), "utf-16le", 2),
)


def _managed_resource_public_evidence(
    recovered: PureLogsManagedResource | PureLogsYqtyResource,
) -> dict[str, object]:
    """復元型ごとの固定helperから公開可能な証拠だけを返す。"""

    if isinstance(recovered, PureLogsManagedResource):
        return public_recovery_evidence(recovered)
    if isinstance(recovered, PureLogsYqtyResource):
        return PureLogsYqtyResource.public_evidence(recovered)
    raise TypeError("PureLogs managed resource結果型が不正です")


def _structured_channel_endpoints(data: bytes) -> list[str] | None:
    """構造化された通信観測からPureLogs担当チャネルの接続先を返す。"""
    if len(data) > MAX_STRUCTURED_METADATA_BYTES:
        # 通常のPEやmemory dumpはJSON専用上限を超え得る。構造化入力として
        # decodeしないだけで、独立したtext走査まで候補超過扱いにしない。
        return None
    try:
        payload = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        return None
    if not isinstance(payload, dict):
        return None
    channels = payload.get("channels")
    if not isinstance(channels, list):
        return None
    if len(channels) > MAX_STRUCTURED_CHANNELS:
        raise ValueError("PureLogs structured channel count exceeded")

    endpoints: set[str] = set()
    role_aware = False
    for channel in channels:
        if not isinstance(channel, dict):
            continue
        role = str(channel.get("role", "")).lower()
        if any(label in role for label in ("purelogs", "purerat", "purehvnc")):
            role_aware = True
        if "purelogs" not in role or "purerat" in role or "purehvnc" in role:
            continue
        endpoint = channel.get("endpoint")
        if isinstance(endpoint, str):
            endpoints.update(endpoint_candidates(endpoint))
            if len(endpoints) > MAX_ENDPOINT_CANDIDATES:
                raise ValueError("PureLogs endpoint candidate limit exceeded")
    return sorted(endpoints) if role_aware else None


def _bounded_text(data: bytes) -> tuple[str, bool]:
    """入力を上限付きで文字列化し、切り詰めの有無を返す。"""

    scanned = memoryview(data)[:MAX_SCAN_BYTES]
    chunks: list[str] = []
    seen: set[str] = set()
    total = 0
    observed = 0
    truncated = len(data) > len(scanned)
    exhausted = False
    for pattern, encoding, width in _BOUNDED_STRING_PATTERNS:
        for match in pattern.finditer(scanned):
            observed += 1
            if observed > MAX_TEXT_STRINGS:
                truncated = True
                exhausted = True
                break
            separator = 1 if chunks else 0
            remaining = MAX_TEXT_CHARS - total - separator
            if remaining <= 0:
                truncated = True
                exhausted = True
                break
            character_count = (match.end() - match.start()) // width
            retained_count = min(character_count, remaining)
            raw = scanned[
                match.start() : match.start() + retained_count * width
            ].tobytes()
            value = raw.decode(encoding, errors="ignore")
            if value and value not in seen:
                seen.add(value)
                chunks.append(value)
                total += separator + len(value)
            if retained_count < character_count:
                truncated = True
                exhausted = True
                break
        if exhausted:
            break
    return "\n".join(chunks), truncated


def _valid_host(host: str) -> bool:
    """公開IOCとして扱えるdomainまたはIPv4かを判定する。"""
    candidate = host.casefold().rstrip(".")
    if not candidate or len(candidate) > 253:
        return False
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        labels = candidate.split(".")
        return len(labels) >= 2 and all(
            bool(
                re.fullmatch(
                    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?",
                    label,
                )
            )
            for label in labels
        )
    return (
        address.version == 4
        and not address.is_unspecified
        and not address.is_multicast
        and not address.is_loopback
    )


def endpoint_candidates(text: str) -> list[str]:
    """URLとhost:port表記から重複のないendpoint候補を返す。"""
    endpoints: set[str] = set()
    observed = 0
    for match in HOST_PORT_RE.finditer(text):
        observed += 1
        if observed > MAX_ENDPOINT_CANDIDATES:
            raise ValueError("PureLogs endpoint candidate limit exceeded")
        host, raw_port = match.groups()
        port = int(raw_port)
        host = host.lower().rstrip(".")
        if 0 < port <= 65535 and _valid_host(host):
            endpoints.add(f"{host}:{port}")
    for match in URL_RE.finditer(text):
        observed += 1
        if observed > MAX_ENDPOINT_CANDIDATES:
            raise ValueError("PureLogs endpoint candidate limit exceeded")
        value = match.group(0)
        parsed = urlsplit(value.rstrip(".,);]"))
        if not parsed.hostname or not _valid_host(parsed.hostname):
            continue
        try:
            port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
        except ValueError:
            continue
        endpoints.add(f"{parsed.hostname.lower().rstrip('.')}:{port}")
    return sorted(endpoints)


def _path_bound_endpoints(text: str) -> list[str]:
    """既知PureLogs pathを持つURLだけからendpointを返す。"""

    endpoints: set[str] = set()
    observed = 0
    for match in URL_RE.finditer(text):
        observed += 1
        if observed > MAX_ENDPOINT_CANDIDATES:
            raise ValueError("PureLogs URL candidate limit exceeded")
        value = match.group(0)
        parsed = urlsplit(value.rstrip(".,);]"))
        path = parsed.path.lower().rstrip("/") or "/"
        if not any(
            path == item or path.startswith(f"{item}/") for item in PROTOCOL_PATHS
        ):
            continue
        endpoints.update(endpoint_candidates(value))
    return sorted(endpoints)


def _bare_endpoint_candidates(text: str) -> list[str]:
    """URLを除外し、独立したhost:port表記だけを返す。"""

    return endpoint_candidates(URL_RE.sub("", text))


def _standalone_host(value: str) -> bool:
    """schemeやpathを含まないdomain／IPv4だけを許可する。"""

    return _valid_host(value)


def _iter_base64_candidates(text: str) -> Iterator[str]:
    """長さと件数を制限してcanonical Base64候補を列挙する。"""

    observed = 0
    seen: set[str] = set()
    for match in BASE64_RUN_RE.finditer(text):
        value = match.group(0)
        if value in seen or len(value) > MAX_CONFIG_BASE64_CHARS:
            continue
        seen.add(value)
        observed += 1
        if observed > MAX_CONFIG_CANDIDATES:
            raise ValueError("PureLogs protobuf Base64 candidate limit exceeded")
        yield value


def _iter_protobuf_messages(data: bytes) -> Iterator[dict[int, list[Any]]]:
    """field番号を仮定せず、入れ子protobufを有界探索する。"""

    pending: list[tuple[bytes, int]] = [(data, 0)]
    queued = {sha256_bytes(data)}
    seen: set[str] = set()
    observed = 0
    candidate_limit_exceeded = False
    while pending:
        raw, depth = pending.pop(0)
        digest = sha256_bytes(raw)
        if digest in seen:
            continue
        seen.add(digest)
        observed += 1
        if observed > MAX_CONFIG_MESSAGES:
            raise ValueError("PureLogs protobuf message candidate limit exceeded")
        try:
            fields = parse_protobuf(raw)
        except ValueError:
            continue
        yield fields
        if depth >= MAX_CONFIG_NESTING:
            continue
        for values in fields.values():
            for value in values:
                if (
                    isinstance(value, bytes)
                    and 2 <= len(value) <= MAX_CONFIG_CLEAR_BYTES
                ):
                    value_digest = sha256_bytes(value)
                    if value_digest in seen or value_digest in queued:
                        continue
                    if observed + len(pending) >= MAX_CONFIG_MESSAGES:
                        candidate_limit_exceeded = True
                        continue
                    if candidate_limit_exceeded:
                        continue
                    pending.append((value, depth + 1))
                    queued.add(value_digest)
    if candidate_limit_exceeded:
        raise ValueError("PureLogs protobuf message candidate limit exceeded")


def _decode_key_candidate(value: bytes) -> bytes | None:
    """AES-256鍵らしいfieldを復号するが、raw値は結果へ含めない。"""

    if len(value) == 32:
        return value
    try:
        text = value.decode("ascii").strip()
    except UnicodeDecodeError:
        return None
    if re.fullmatch(r"[0-9a-fA-F]{64}", text):
        return bytes.fromhex(text)
    try:
        decoded = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        return None
    return decoded if len(decoded) == 32 else None


def _protobuf_config_candidate(clear: bytes) -> dict[str, Any] | None:
    """PureLogs設定候補からendpointと公開可能な鍵fingerprintを返す。"""

    if not clear or len(clear) > MAX_CONFIG_CLEAR_BYTES:
        return None
    strings: set[str] = set()
    integers: set[int] = set()
    key_hashes: set[str] = set()
    field_count = 0
    message_count = 0
    try:
        messages = _iter_protobuf_messages(clear)
    except ValueError:
        return None
    try:
        for fields in messages:
            message_count += 1
            field_count += sum(len(values) for values in fields.values())
            if field_count > MAX_CONFIG_TOTAL_FIELDS:
                return None
            for values in fields.values():
                for value in values:
                    if isinstance(value, int) and not isinstance(value, bool):
                        if 1 <= value <= 65535:
                            integers.add(value)
                            if len(integers) > MAX_CONFIG_INTEGER_VALUES:
                                return None
                        continue
                    if not isinstance(value, bytes):
                        continue
                    key = _decode_key_candidate(value)
                    if key is not None:
                        key_hashes.add(sha256_bytes(key))
                        if len(key_hashes) > MAX_CONFIG_KEY_HASHES:
                            return None
                    try:
                        text = value.decode("utf-8")
                    except UnicodeDecodeError:
                        continue
                    if text and all(
                        character.isprintable() or character in "\r\n\t"
                        for character in text
                    ):
                        strings.add(text)
                        if len(strings) > MAX_CONFIG_STRING_VALUES:
                            return None
    except ValueError:
        return None
    endpoints: set[str] = set()
    hosts: set[str] = set()
    implicit_url_hosts: dict[str, int] = {}
    for value in strings:
        endpoints.update(endpoint_candidates(value))
        if len(endpoints) > MAX_ENDPOINT_CANDIDATES:
            return None
        for match in URL_RE.finditer(value):
            parsed = urlsplit(match.group(0).rstrip(".,);]"))
            if not parsed.hostname or not _valid_host(parsed.hostname):
                continue
            try:
                explicit_port = parsed.port
            except ValueError:
                continue
            if explicit_port is None:
                host = parsed.hostname.lower().rstrip(".")
                implicit_url_hosts[host] = (
                    443 if parsed.scheme.lower() == "https" else 80
                )
        candidate = value.lower().rstrip(".")
        if _standalone_host(candidate):
            hosts.add(candidate)
    # 一部の版はorigin URLではなくhostとportを別fieldへ格納する。
    # 値1はbool／feature flagとして除外し、暗黙portのURLは候補portが
    # 一意な場合だけ既定portから置換する。
    candidate_ports = {value for value in integers if value > 1}
    port_binding_required = bool(implicit_url_hosts or hosts)
    if port_binding_required and len(candidate_ports) > 1:
        # field番号を仮定しない探索では、複数整数のどれが通信portかを
        # 一意に証明できない。cross productや既定portへのfallbackで
        # configured C2へ昇格させず、schema証拠が追加されるまで拒否する。
        return None
    if implicit_url_hosts and len(candidate_ports) == 1:
        port = next(iter(candidate_ports))
        for host, default_port in implicit_url_hosts.items():
            default_endpoint = f"{host}:{default_port}"
            endpoints = {
                endpoint for endpoint in endpoints if endpoint != default_endpoint
            }
            endpoints.add(f"{host}:{port}")
    if hosts and 1 <= len(candidate_ports) <= 8:
        if len(hosts) * len(candidate_ports) > MAX_ENDPOINT_CANDIDATES - len(endpoints):
            return None
        endpoints.update(f"{host}:{port}" for host in hosts for port in candidate_ports)
    # 32-byte値が複数ある場合、どれがwire暗号鍵かをfield番号だけで
    # 決め打ちできない。曖昧なfingerprint集合を「設定回収済み」へ
    # 昇格させず、独立したschema根拠が追加されるまでfail-closedとする。
    if not endpoints or len(key_hashes) != 1 or field_count < 4:
        return None
    return {
        "endpoints": sorted(endpoints),
        "aes_key_sha256": sorted(key_hashes),
        "aes_key_length_bytes": 32,
        "protobuf_field_count": field_count,
        "protobuf_message_count": message_count,
    }


def decode_config_blob(text: str) -> dict[str, Any]:
    """Base64／protobuf設定を全候補比較し、一意な設定だけ返す。"""

    configurations: dict[tuple[tuple[str, ...], tuple[str, ...]], dict[str, Any]] = {}
    for encoded in _iter_base64_candidates(text):
        try:
            clear = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError):
            continue
        candidate = _protobuf_config_candidate(clear)
        if candidate is None:
            continue
        identity = (
            tuple(candidate["endpoints"]),
            tuple(candidate["aes_key_sha256"]),
        )
        if identity not in configurations:
            configurations[identity] = candidate
    if len(configurations) > 1:
        raise ValueError("conflicting PureLogs protobuf configurations were found")
    if configurations:
        return next(iter(configurations.values()))
    raise ValueError("PureLogs Base64/protobuf configuration was not found")


def extract(data: bytes, name: str = "sample") -> dict:
    """検体、メモリ文字列、復号済みPCAPメタデータを実行せず解析する。"""
    text, truncated = _bounded_text(data)
    managed_resource = recover_purelogs_managed_strings(data)
    if managed_resource is not None:
        recovered_text = managed_resource.text
        separator = 1 if text and recovered_text else 0
        retained_original = MAX_TEXT_CHARS - len(recovered_text) - separator
        if retained_original < 0:
            # managed_resource側の独立上限が変わっても部分的な設定を
            # 公開せず、既存textだけで解析を継続する。
            managed_resource = None
        else:
            if len(text) > retained_original:
                text = text[:retained_original]
                truncated = True
            text = f"{text}\n{recovered_text}" if text else recovered_text
    config_search_text = managed_resource.text if managed_resource is not None else text
    lowered = text.lower()
    paths = sorted(path for path in PROTOCOL_PATHS if path in lowered)
    product_markers = sorted(marker for marker in PRODUCT_MARKERS if marker in lowered)
    delivery_markers = sorted(
        marker for marker in DELIVERY_MARKERS if marker.lower() in lowered
    )
    endpoint_limit_exceeded = False
    try:
        structured_endpoints = _structured_channel_endpoints(data)
    except ValueError:
        structured_endpoints = None
        endpoint_limit_exceeded = True
    decoded_config: dict[str, Any] | None = None
    config_status = "configuration_not_found_or_incompatible"
    try:
        decoded_config = decode_config_blob(config_search_text)
    except ValueError as error:
        if "conflicting" in str(error):
            config_status = "conflicting_configuration_candidates"

    try:
        if endpoint_limit_exceeded:
            endpoints = []
        elif structured_endpoints is not None:
            endpoints = structured_endpoints
        else:
            endpoints = _path_bound_endpoints(text)
            # 復号済み観測ではpathと単一endpointが別fieldになる場合がある。
            loose_endpoints = _bare_endpoint_candidates(text)
            if not endpoints and len(loose_endpoints) == 1:
                endpoints = loose_endpoints
    except ValueError:
        endpoints = []
        endpoint_limit_exceeded = True
    protocol_endpoints = endpoints
    if decoded_config is not None:
        combined_endpoints = set(protocol_endpoints)
        combined_endpoints.update(decoded_config["endpoints"])
        if len(combined_endpoints) > MAX_ENDPOINT_CANDIDATES:
            # 観測URLの部分集合は公開せず、独立に検証済みの
            # protobuf設定だけを後段のfamily相関へ残す。
            protocol_endpoints = []
            endpoint_limit_exceeded = True

    strong_paths = {"/plugin", "/userinfo", "/filesearch/req", "/finish"}
    strong_count = len(strong_paths.intersection(paths))
    family_anchor = bool(
        strong_count >= 3 or ("purelogs" in product_markers and strong_count >= 1)
    )
    decoded_family_evidence = family_anchor
    family_correlated_config = bool(
        decoded_config is not None and decoded_family_evidence
    )
    if decoded_config is not None:
        config_status = (
            "purelogs_protobuf_config_recovered"
            if family_correlated_config
            else "protobuf_config_candidate_requires_family_evidence"
        )
    if decoded_config is not None and decoded_family_evidence:
        confidence = "confirmed"
        variant = "purelogs_protobuf_config"
    elif family_anchor:
        confidence = "confirmed"
        variant = "purelogs_http_api"
    elif product_markers and (strong_count >= 1 or len(paths) >= 3):
        confidence = "high"
        variant = "purelogs_static_markers"
    elif delivery_markers and len(paths) >= 2:
        confidence = "medium"
        variant = "pure_suite_delivery_cluster"
    else:
        confidence = "unverified"
        # 共通のhandler証拠評価でrouteそのものを構造証拠にしないため、
        # 設定・family根拠がない結果は既知の負sentinelで表す。
        variant = "unresolved_variant"

    configured_endpoints = (
        sorted(decoded_config["endpoints"]) if family_correlated_config else []
    )
    observed_endpoints = (
        sorted(protocol_endpoints) if confidence != "unverified" else []
    )
    accepted_endpoint_set = set(configured_endpoints)
    accepted_endpoint_set.update(observed_endpoints)
    accepted_endpoints = sorted(accepted_endpoint_set)
    hosts = sorted({item.rsplit(":", 1)[0] for item in accepted_endpoints})
    ports = sorted({int(item.rsplit(":", 1)[1]) for item in accepted_endpoints})
    config = {
        "variant": variant,
        "confidence": confidence,
        "source_name": name,
        "protocol_endpoint_paths": paths,
        "product_markers": product_markers,
        "delivery_markers": delivery_markers,
        "c2_hosts": hosts,
        "c2_ports": ports,
        "endpoints": accepted_endpoints,
        "configured_endpoints": configured_endpoints,
        "observed_protocol_endpoints": observed_endpoints,
        "status": config_status,
        "static_config_recovered": family_correlated_config,
        "decoded_config_recovered": decoded_config is not None,
        "family_attribution_confirmed": confidence == "confirmed",
        "supports_family_attribution": confidence == "confirmed",
        "terminal_family_confirmed": confidence == "confirmed",
        "family_attribution_requires_correlated_markers": True,
        "managed_resource_recovery": (
            _managed_resource_public_evidence(managed_resource)
            if managed_resource is not None
            else {"status": "not_recovered"}
        ),
    }
    if decoded_config is not None:
        config["protobuf"] = {
            **decoded_config,
            "aes_key_material_published": False,
            "source_encoding": "base64_protobuf",
        }
    configured_endpoint_set = set(configured_endpoints)
    findings = []
    for endpoint in accepted_endpoints:
        configured = endpoint in configured_endpoint_set
        family_attributed = confidence == "confirmed"
        findings.append(
            {
                "kind": "network.endpoint",
                "value": endpoint,
                "role": (
                    "configured_c2"
                    if configured
                    else "observed_c2"
                    if family_attributed
                    else "family_unresolved_endpoint_candidate"
                ),
                "confidence": (
                    "confirmed"
                    if configured
                    else confidence
                    if family_attributed
                    else "unverified"
                ),
                "source": (
                    "base64_protobuf_config"
                    if configured
                    else "static_or_decrypted_protocol_evidence"
                ),
                "family_attribution_confirmed": family_attributed,
                "c2_confirmation_allowed": configured,
            }
        )
    limitations = [
        "静的抽出のみであり、payload実行やC2接続は行っていません。",
        "TLS暗号化PCAPは復号済みHTTPメタデータへ変換してから入力する必要があります。",
    ]
    if truncated:
        limitations.append("安全上限により入力の一部を走査対象外としました。")
    if managed_resource is not None:
        limitations.append(
            "managed resourceは実行せず、検証済みAES/Deflate経路だけを静的復元しました。"
        )
    if endpoint_limit_exceeded:
        limitations.append(
            "endpoint候補数が安全上限を超えたため公開対象から除外しました。"
        )
    if confidence == "unverified":
        limitations.append(
            "PureLogs固有の複数endpointまたは製品マーカーが不足しています。"
        )
    result = build_result("purelogs", data, config, findings, limitations)
    result["supports_family_attribution"] = confidence == "confirmed"
    result["terminal_family_confirmed"] = confidence == "confirmed"
    result["c2"] = (
        [
            {
                "host": endpoint.rsplit(":", 1)[0],
                "port": int(endpoint.rsplit(":", 1)[1]),
                "role": "c2",
                "confidence": "confirmed_static_configuration",
                "evidence": {
                    "kind": "base64_protobuf_config",
                    "aes_key_length_validated": True,
                    "family_markers_correlated": True,
                },
            }
            for endpoint in configured_endpoints
        ]
        if family_correlated_config
        else []
    )
    return result
