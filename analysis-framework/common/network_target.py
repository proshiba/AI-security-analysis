#!/usr/bin/env python3
"""C2監視対象のhost・port・URLを安全かつ一貫して正規化する。"""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import re
from typing import Collection
from urllib.parse import SplitResult, urlsplit, urlunsplit


MAX_TARGET_LENGTH = 4096
DNS_LABEL = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)\Z")
SCHEME = re.compile(r"[a-z][a-z0-9+.-]{0,31}\Z")
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


class NetworkTargetError(ValueError):
    """ネットワーク監視対象の入力が安全契約に違反したことを示す。"""


@dataclass(frozen=True)
class NetworkTarget:
    """正規化済みのネットワーク監視対象。"""

    host: str
    port: int | None = None
    scheme: str | None = None
    path: str = ""
    userinfo_present: bool = False

    @property
    def authority(self) -> str:
        """IPv6を括弧で囲み、任意portを付けたauthorityを返す。"""

        rendered_host = f"[{self.host}]" if ":" in self.host else self.host
        return rendered_host + (f":{self.port}" if self.port is not None else "")

    @property
    def is_ip(self) -> bool:
        """hostがIPv4またはIPv6アドレスかを返す。"""

        try:
            ipaddress.ip_address(self.host)
        except ValueError:
            return False
        return True

    def sanitized_value(self, *, default_path: str = "/") -> str:
        """userinfo・query・fragmentを除去したURLまたはendpointを返す。"""

        if self.scheme:
            return urlunsplit(
                (self.scheme, self.authority, self.path or default_path, "", "")
            )
        return self.authority


def normalize_port(value: object) -> int | None:
    """portを1から65535のASCII十進整数へ正規化する。"""

    if value is None or value == "":
        return None
    if isinstance(value, bool):
        raise NetworkTargetError("bool値をportとして扱えません")
    text = str(value)
    if not text.isascii() or not text.isdecimal() or len(text) > 5:
        raise NetworkTargetError("portはASCII十進整数で指定してください")
    port = int(text)
    if not 1 <= port <= 65535:
        raise NetworkTargetError("portは1から65535で指定してください")
    return port


def normalize_host(value: object) -> str:
    """IPまたはDNS名を検証し、ASCII表現へ正規化する。"""

    if not isinstance(value, str):
        raise NetworkTargetError("hostは文字列で指定してください")
    host = value
    if (
        not host
        or host != host.strip()
        or len(host) > 253
        or any(ord(character) < 32 or ord(character) == 127 for character in host)
    ):
        raise NetworkTargetError("hostが空、過長、または制御文字を含みます")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if "%" in host:
        raise NetworkTargetError("IPv6 zone IDは監視対象として扱えません")
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    if host.endswith(".."):
        raise NetworkTargetError("DNS名の末尾dotが不正です")
    host = host.removesuffix(".")
    try:
        ascii_host = host.encode("idna").decode("ascii").lower()
        ascii_host.encode("ascii").decode("idna")
    except UnicodeError as exc:
        raise NetworkTargetError("hostをIDNAへ変換できません") from exc
    if len(ascii_host) > 253:
        raise NetworkTargetError("IDNA変換後のhostが長すぎます")
    labels = ascii_host.split(".")
    if not labels or any(not DNS_LABEL.fullmatch(label) for label in labels):
        raise NetworkTargetError("DNS labelが不正です")
    return ascii_host


def _parsed_port(parsed: SplitResult) -> int | None:
    authority = parsed.netloc.rsplit("@", 1)[-1]
    try:
        port = parsed.port
    except ValueError as exc:
        raise NetworkTargetError("URLのportが不正です") from exc
    if authority.endswith(":") and port is None:
        raise NetworkTargetError("空のURL port指定は許可されません")
    return normalize_port(port)


def parse_network_target(
    value: object,
    port: object = None,
    *,
    require_port: bool = False,
    allowed_schemes: Collection[str] | None = None,
) -> NetworkTarget:
    """URL・host:port・IPを単一の監視対象へ正規化する。"""

    source = str(value) if value is not None else ""
    if (
        not source
        or len(source) > MAX_TARGET_LENGTH
        or source != source.strip()
        or any(ord(character) < 32 or ord(character) == 127 for character in source)
    ):
        raise NetworkTargetError("対象が空、過長、または制御文字を含みます")
    explicit_port = normalize_port(port)
    bare_ip = source[1:-1] if source.startswith("[") and source.endswith("]") else source
    if "%" in bare_ip:
        raise NetworkTargetError("IPv6 zone IDは監視対象として扱えません")
    try:
        normalized_ip = str(ipaddress.ip_address(bare_ip))
    except ValueError:
        normalized_ip = None
    if normalized_ip is not None:
        if require_port and explicit_port is None:
            raise NetworkTargetError("endpointにはportが必要です")
        return NetworkTarget(host=normalized_ip, port=explicit_port)

    try:
        parsed = urlsplit(source if "://" in source else f"//{source}")
    except ValueError as exc:
        raise NetworkTargetError("URL authorityが不正です") from exc
    if not parsed.netloc:
        raise NetworkTargetError("URL authorityにhostがありません")
    scheme = parsed.scheme.casefold() or None
    if scheme and not SCHEME.fullmatch(scheme):
        raise NetworkTargetError("URL schemeが不正です")
    if allowed_schemes is not None and scheme not in {
        item.casefold() for item in allowed_schemes
    }:
        raise NetworkTargetError("許可されていないURL schemeです")
    embedded_port = _parsed_port(parsed)
    if (
        explicit_port is not None
        and embedded_port is not None
        and explicit_port != embedded_port
    ):
        raise NetworkTargetError("明示portとURL内portが競合しています")
    effective_port = explicit_port if explicit_port is not None else embedded_port
    if require_port and effective_port is None:
        raise NetworkTargetError("endpointにはportが必要です")
    host = normalize_host(parsed.hostname or "")
    if "." in host and all(label.isdecimal() for label in host.split(".")):
        try:
            ipaddress.ip_address(host)
        except ValueError as exc:
            raise NetworkTargetError("不正なIPv4形式です") from exc
    return NetworkTarget(
        host=host,
        port=effective_port,
        scheme=scheme,
        path=parsed.path,
        userinfo_present=parsed.username is not None or parsed.password is not None,
    )


def is_public_ip(value: str) -> bool:
    """インターネット公開Shodan検索に適したIPかを返す。"""

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
    return not any(
        address in network
        for network in DOCUMENTATION_NETWORKS
        if address.version == network.version
    )


def is_public_hostname(value: str) -> bool:
    """公開DNSとして妥当な複数labelのhost名かを返す。"""

    try:
        normalized = normalize_host(value)
    except NetworkTargetError:
        return False
    try:
        ipaddress.ip_address(normalized)
    except ValueError:
        pass
    else:
        return False
    labels = normalized.split(".")
    if len(labels) < 2 or labels[-1].isdigit():
        return False
    if any(
        normalized == suffix or normalized.endswith(f".{suffix}")
        for suffix in NON_PUBLIC_HOST_SUFFIXES
    ):
        return False
    return not any(
        normalized == host or normalized.endswith(f".{host}")
        for host in DOCUMENTATION_HOSTS
    )


def shodan_target_query(target: NetworkTarget) -> str | None:
    """公開対象だけをShodan検索式へ変換し、非公開対象は除外する。"""

    if target.is_ip:
        if not is_public_ip(target.host):
            return None
        prefix = f"ip:{target.host}"
    else:
        if not is_public_hostname(target.host):
            return None
        prefix = f"hostname:{target.host}"
    return f"{prefix} port:{target.port}" if target.port is not None else prefix
