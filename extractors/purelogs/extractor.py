"""PureLogsの静的文字列または復号済み通信メタデータから設定候補を抽出する。"""

from __future__ import annotations

import ipaddress
import json
import re
from urllib.parse import urlsplit

from extractors.common import build_result, extract_strings

MAX_SCAN_BYTES = 128 * 1024 * 1024
MAX_TEXT_CHARS = 16 * 1024 * 1024
PROTOCOL_PATHS = (
    "/ping",
    "/plugin",
    "/userinfo",
    "/browser",
    "/discord",
    "/filesearch/req",
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


def _structured_channel_endpoints(data: bytes) -> list[str] | None:
    """?????????????PureLogs????????????"""
    try:
        payload = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    channels = payload.get("channels")
    if not isinstance(channels, list):
        return None

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
    return sorted(endpoints) if role_aware else None


def _bounded_text(data: bytes) -> tuple[str, bool]:
    """入力を上限付きで文字列化し、切り詰めの有無を返す。"""
    scanned = data[:MAX_SCAN_BYTES]
    values = extract_strings(scanned, minimum=4)
    chunks: list[str] = []
    total = 0
    truncated = len(data) > len(scanned)
    for value in values:
        remaining = MAX_TEXT_CHARS - total
        if remaining <= 0:
            truncated = True
            break
        chunks.append(value[:remaining])
        total += min(len(value), remaining) + 1
    return "\n".join(chunks), truncated


def _valid_host(host: str) -> bool:
    """公開IOCとして扱えるdomainまたはIPv4かを判定する。"""
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return "." in host and len(host) <= 253
    return (
        address.version == 4
        and not address.is_unspecified
        and not address.is_multicast
        and not address.is_loopback
    )


def endpoint_candidates(text: str) -> list[str]:
    """URLとhost:port表記から重複のないendpoint候補を返す。"""
    endpoints: set[str] = set()
    for host, raw_port in HOST_PORT_RE.findall(text):
        port = int(raw_port)
        host = host.lower().rstrip(".")
        if 0 < port <= 65535 and _valid_host(host):
            endpoints.add(f"{host}:{port}")
    for value in URL_RE.findall(text):
        parsed = urlsplit(value.rstrip(".,);]"))
        if not parsed.hostname or not _valid_host(parsed.hostname):
            continue
        try:
            port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
        except ValueError:
            continue
        endpoints.add(f"{parsed.hostname.lower().rstrip('.')}:{port}")
    return sorted(endpoints)


def extract(data: bytes, name: str = "sample") -> dict:
    """検体、メモリ文字列、復号済みPCAPメタデータを実行せず解析する。"""
    text, truncated = _bounded_text(data)
    lowered = text.lower()
    paths = sorted(path for path in PROTOCOL_PATHS if path in lowered)
    product_markers = sorted(marker for marker in PRODUCT_MARKERS if marker in lowered)
    delivery_markers = sorted(
        marker for marker in DELIVERY_MARKERS if marker.lower() in lowered
    )
    structured_endpoints = _structured_channel_endpoints(data)
    endpoints = (
        endpoint_candidates(text)
        if structured_endpoints is None
        else structured_endpoints
    )

    strong_paths = {"/plugin", "/userinfo", "/filesearch/req", "/finish"}
    strong_count = len(strong_paths.intersection(paths))
    if strong_count >= 3:
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
        variant = "unrecognized"

    accepted_endpoints = endpoints if confidence != "unverified" else []
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
    }
    findings = [
        {
            "kind": "network.endpoint",
            "value": endpoint,
            "role": "configured_or_observed_c2",
            "confidence": confidence,
            "source": "static_or_decrypted_evidence",
        }
        for endpoint in accepted_endpoints
    ]
    limitations = [
        "静的抽出のみであり、payload実行やC2接続は行っていません。",
        "TLS暗号化PCAPは復号済みHTTPメタデータへ変換してから入力する必要があります。",
    ]
    if truncated:
        limitations.append("安全上限により入力の一部を走査対象外としました。")
    if confidence == "unverified":
        limitations.append(
            "PureLogs固有の複数endpointまたは製品マーカーが不足しています。"
        )
    return build_result("purelogs", data, config, findings, limitations)
