#!/usr/bin/env python3
"""C2/config所見をオフラインで評価し、安全な受動検索クエリを生成する。"""

from __future__ import annotations

import argparse
import ipaddress
import json
from pathlib import Path
import re
import sys
from urllib.parse import SplitResult, urlsplit

REPO = Path(__file__).parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from extractors.profiled_family import profile_for  # noqa: E402
from network_target import (  # noqa: E402
    NetworkTargetError,
    parse_network_target,
    shodan_target_query,
)

NON_C2_ROLES = {
    "certificate_service",
    "documentation_reference",
    "host_discovery_service",
    "stage_url_candidate",
}

MAX_TARGET_LENGTH = 4096
DOCUMENTATION_NETWORKS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
    ipaddress.ip_network("3fff::/20"),
)
NON_PUBLIC_HOST_SUFFIXES = {
    "alt",
    "arpa",
    "corp",
    "example",
    "home",
    "home.arpa",
    "internal",
    "invalid",
    "lan",
    "local",
    "localdomain",
    "localhost",
    "onion",
    "test",
}
DOCUMENTATION_HOSTS = {"example.com", "example.net", "example.org"}
DNS_LABEL = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)\Z")


def protocol_profile(family: str | None) -> dict | None:
    """登録済みファミリーのオフライン確認条件とエミュレータ案内を返す。"""
    if not family:
        return None
    try:
        profile = profile_for(family)
    except ValueError:
        return None
    return {
        "category": profile["category"],
        "transport": profile["transport"],
        "endpoint_role": profile["endpoint_role"],
        "confirmation_requirements": profile["confirmation"],
        "active_confirmation_default": "disabled",
        "emulator": "emulators/families/lab.py (loopback限定)",
    }


def _normalized_port(value: object) -> int | None:
    """ポートを1～65535の10進整数へ正規化する。"""
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        raise ValueError("boolean is not a port")
    text = str(value)
    if not text.isascii() or not text.isdecimal() or len(text) > 5:
        raise ValueError("invalid port")
    port = int(text)
    if not 1 <= port <= 65535:
        raise ValueError("port out of range")
    return port


def _normalized_host(value: str) -> str | None:
    """IPまたはDNSホスト名を注入不能なASCII表現へ正規化する。"""
    host = value
    if (
        not host
        or host != host.strip()
        or len(host) > 253
        or any(ord(character) < 32 or ord(character) == 127 for character in host)
    ):
        return None
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if "%" in host:
        return None
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    if host.endswith(".."):
        return None
    host = host.removesuffix(".")
    try:
        ascii_host = host.encode("idna").decode("ascii").lower()
        ascii_host.encode("ascii").decode("idna")
    except UnicodeError:
        return None
    if len(ascii_host) > 253:
        return None
    labels = ascii_host.split(".")
    if not labels or any(not DNS_LABEL.fullmatch(label) for label in labels):
        return None
    return ascii_host


def _parsed_port(parsed: SplitResult) -> int | None:
    """URL authorityのポートを検証し、空のポート指定も拒否する。"""
    authority = parsed.netloc.rsplit("@", 1)[-1]
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("invalid URL port") from exc
    if authority.endswith(":") and port is None:
        raise ValueError("empty URL port")
    return _normalized_port(port)


def _target_from_text(value: str, port: object = None) -> tuple[str, int | None] | None:
    """URL、host:port、IPを正規化し、外部通信なしで検索対象へ変換する。"""
    source = str(value)
    if (
        not source
        or len(source) > MAX_TARGET_LENGTH
        or any(ord(character) < 32 or ord(character) == 127 for character in source)
    ):
        return None
    raw = source.strip()
    if not raw:
        return None
    try:
        explicit_port = _normalized_port(port)
    except ValueError:
        return None

    bare_ip = raw[1:-1] if raw.startswith("[") and raw.endswith("]") else raw
    try:
        normalized_ip = str(ipaddress.ip_address(bare_ip))
    except ValueError:
        normalized_ip = None
    if normalized_ip is not None:
        return normalized_ip, explicit_port

    try:
        if "://" in raw:
            parsed = urlsplit(raw)
            if not parsed.scheme or not parsed.netloc:
                return None
        else:
            parsed = urlsplit(f"//{raw}")
            if not parsed.netloc:
                return None
        embedded_port = _parsed_port(parsed)
    except ValueError:
        return None
    if explicit_port is not None and embedded_port is not None and explicit_port != embedded_port:
        return None
    normalized_host = _normalized_host(parsed.hostname or "")
    if normalized_host is None:
        return None
    return normalized_host, explicit_port if explicit_port is not None else embedded_port


def _public_ip(value: str) -> bool:
    """Shodanのインターネット検索対象になり得る公開IPだけを許可する。"""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    if (
        not address.is_global
        or address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
        or address.is_multicast
        or address.is_unspecified
        or getattr(address, "is_site_local", False)
    ):
        return False
    return not any(address in network for network in DOCUMENTATION_NETWORKS if address.version == network.version)


def _public_hostname(value: str) -> bool:
    """特殊用途名・文書用名・単一ラベル名を除く通常の公開DNS名だけを許可する。"""
    labels = value.split(".")
    if len(labels) < 2 or labels[-1].isdigit():
        return False
    if any(value == suffix or value.endswith(f".{suffix}") for suffix in NON_PUBLIC_HOST_SUFFIXES):
        return False
    return not any(value == host or value.endswith(f".{host}") for host in DOCUMENTATION_HOSTS)


def target_from_finding(finding: dict) -> tuple[str, int | None] | None:
    """ネットワーク所見を正規化したホストと任意ポートへ変換する。"""
    if not isinstance(finding, dict):
        return None
    value = str(finding.get("value", ""))
    kind = finding.get("kind")
    if kind not in {"network.url", "network.endpoint", "exfiltration.endpoint"}:
        return None
    try:
        target = parse_network_target(
            value,
            require_port=kind in {"network.endpoint", "exfiltration.endpoint"},
        )
    except NetworkTargetError:
        return None
    return target.host, target.port


def shodan_queries(host: str, port: int | None = None) -> list[str]:
    """対象へ接続せず、公開ホストだけの受動Shodan検索式を生成する。"""
    try:
        target = parse_network_target(host, port)
    except NetworkTargetError:
        return []
    query = shodan_target_query(target)
    return [query] if query else []


def _sanitized_finding(finding: dict, host: str, port: int | None) -> dict:
    """成果物用所見からURL資格情報、query、fragmentを除去する。"""
    sanitized = dict(finding)
    formatted_host = f"[{host}]" if ":" in host else host
    if finding.get("kind") == "network.url":
        try:
            target = parse_network_target(str(finding.get("value", "")))
        except NetworkTargetError:
            sanitized["value"] = formatted_host + (f":{port}" if port is not None else "")
        else:
            sanitized["value"] = target.sanitized_value()
    else:
        sanitized["value"] = formatted_host + (f":{port}" if port is not None else "")
    return sanitized


def assess(result: object) -> dict:
    """抽出所見を保守的に評価し、無害化した来歴を保持する。"""
    if not isinstance(result, dict):
        result = {}
    raw_findings = result.get("findings", [])
    if not isinstance(raw_findings, list):
        raw_findings = []
    rows = []
    ignored_findings = 0
    for finding in raw_findings:
        if not isinstance(finding, dict):
            ignored_findings += 1
            continue
        if finding.get("role") in NON_C2_ROLES:
            continue
        target = target_from_finding(finding)
        if not target:
            continue
        host, port = target
        rows.append(
            {
                "finding": _sanitized_finding(finding, host, port),
                "host": host,
                "port": port,
                "passive_queries": shodan_queries(host, port),
                "active_probe_performed": False,
            }
        )
    confidence = "none"
    values = {row["finding"].get("confidence") for row in rows}
    if "confirmed" in values:
        confidence = "confirmed"
    elif "probable" in values:
        confidence = "probable"
    elif rows:
        confidence = "candidate"
    family = result.get("family")
    return {
        "schema_version": 1,
        "family": family,
        "assessment": confidence,
        "protocol_profile": protocol_profile(family),
        "ignored_finding_count": ignored_findings,
        "targets": rows,
        "network_contacted": False,
        "sample_executed": False,
        "warning": "受動検索式と埋め込み文字列だけでは、稼働中のC2サービスと確定できない。",
    }


def build_parser() -> argparse.ArgumentParser:
    """オフライン検出器のコマンドラインパーサーを構築する。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--extractor-result", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    """抽出結果1件を評価し、決定的なJSONを書き出す。"""
    args = build_parser().parse_args(argv)
    result = assess(json.loads(args.extractor_result.read_text(encoding="utf-8")))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output), "targets": len(result["targets"])}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
