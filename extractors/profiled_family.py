"""profile定義済みWindows malware family向けの共有・上限付き静的抽出器。

保守的なliteral復元とfamily固有の暗号decoderを分離し、完全なfamily固有設定構造を
復元できない限りfindingを候補として扱う。外部endpointへは接続しない。
"""

from __future__ import annotations

import ipaddress
import json
from functools import lru_cache
from pathlib import Path
import re
from typing import Callable
from urllib.parse import urlsplit, urlunsplit

from extractors.common import build_result, endpoint_candidates, url_candidates

PROFILE_PATH = Path(__file__).with_name("profiles") / "windows_family_profiles.json"
ASCII = re.compile(rb"[\x20-\x7e]{4,}")
WIDE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")
FULL_SCAN_LIMIT = 8 * 1024 * 1024
SAMPLE_WINDOW = 2 * 1024 * 1024
MAX_STRINGS = 50_000
MAX_FINDINGS = 64
BENIGN_HOSTS = {
    "ns.adobe.com",
    "oneocsp.microsoft.com",
    "api.ipify.org",
    "freegeoip.net",
    "ip-api.com",
    "schemas.microsoft.com",
    "nsis.sf.net",
    "www.google.com",
    "www.microsoft.com",
    "support.microsoft.com",
    "aka.ms",
    "www.w3.org",
    "schemas.xmlsoap.org",
    "www.flexerasoftware.com",
    "logo.verisign.com",
    "docs.microsoft.com",
    "learn.microsoft.com",
    "go.microsoft.com",
    "www.youtube.com",
    "youtube.com",
    "google.com",
    "www.jrsoftware.org",
    "www.gendigital.com",
}
BENIGN_HOST_PARTS = (
    "cacerts.digicert.com",
    "crl.digicert.com",
    "crl3.digicert.com",
    "crl4.digicert.com",
    "ocsp.digicert.com",
    "crl.microsoft.com",
    "ocsp.sectigo.com",
    "crl.sectigo.com",
    "ocsp.usertrust.com",
    "comodoca.com",
    "usertrust.com",
    "sectigo.com",
    "digicert.com",
    "symcb.com",
    "verisign.com",
    "globalsign.com",
    "symauth.com",
    "contoso.com",
)
DISCOVERY_HOSTS = {"api.my-ip.io", "geolocation-db.com", "ipinfo.io", "ipwhois.app"}
DELIVERY_HOSTS = {
    "onedrive.live.com",
    "github.com",
    "raw.githubusercontent.com",
    "bitbucket.org",
    "dropbox.com",
    "www.dropbox.com",
}
COMMON_PUBLIC_TLDS = {
    "app",
    "at",
    "biz",
    "cc",
    "cfd",
    "ch",
    "cloud",
    "club",
    "co",
    "com",
    "de",
    "dev",
    "eu",
    "fr",
    "fun",
    "info",
    "io",
    "jp",
    "live",
    "me",
    "net",
    "nl",
    "online",
    "org",
    "pro",
    "ru",
    "site",
    "store",
    "tech",
    "top",
    "tv",
    "uk",
    "us",
    "website",
    "win",
    "xyz",
}
STAGE_SUFFIXES = (
    ".bat",
    ".cab",
    ".dll",
    ".exe",
    ".hta",
    ".img",
    ".iso",
    ".js",
    ".msi",
    ".png",
    ".ps1",
    ".rar",
    ".vbs",
    ".zip",
)


@lru_cache(maxsize=16)
def _load_profiles_cached(path: Path, mtime_ns: int, size: int) -> dict[str, dict]:
    """file identity付きcacheからprofile mapを読み込み検証する。"""
    value = json.loads(path.read_text(encoding="utf-8"))
    profiles = value.get("profiles")
    if value.get("schema_version") != 1 or not isinstance(profiles, dict):
        raise ValueError("family profile文書が不正です")
    for family, profile in profiles.items():
        markers = profile.get("markers") if isinstance(profile, dict) else None
        minimum = profile.get("minimum_markers") if isinstance(profile, dict) else None
        normalized = (
            [marker.lower() for marker in markers if isinstance(marker, str) and marker]
            if isinstance(markers, list)
            else []
        )
        required = profile.get("required_markers") or []
        normalized_required = (
            [marker.lower() for marker in required if isinstance(marker, str) and marker]
            if isinstance(required, list)
            else []
        )
        if (
            not isinstance(markers, list)
            or len(normalized) != len(markers)
            or len(set(normalized)) != len(normalized)
            or len(markers) < 2
            or not isinstance(minimum, int)
            or minimum < 2
            or minimum > len(markers)
            or not isinstance(required, list)
            or len(normalized_required) != len(required)
            or len(set(normalized_required)) != len(normalized_required)
            or any(item not in normalized for item in normalized_required)
        ):
            raise ValueError(f"family profileのmarker閾値が不正です: {family}")
    return profiles


def load_profiles(path: Path = PROFILE_PATH) -> dict[str, dict]:
    """変更済みprofileを同一processでも再読込できる形で返す。"""

    resolved = path.resolve(strict=True)
    stat = resolved.stat()
    return _load_profiles_cached(resolved, stat.st_mtime_ns, stat.st_size)


def clear_profile_cache() -> None:
    """profile file cacheを明示的に破棄する。"""

    _load_profiles_cached.cache_clear()


def normalize_family(value: str, profiles: dict[str, dict] | None = None) -> str:
    """family IDまたは宣言済みaliasを単一のprofile keyへ正規化する。"""
    profiles = profiles or load_profiles()
    normalized = re.sub(r"[^a-z0-9]", "", value.lower())
    for family, profile in profiles.items():
        names = [
            family,
            profile.get("display_name", ""),
            *(profile.get("aliases") or []),
        ]
        if any(re.sub(r"[^a-z0-9]", "", name.lower()) == normalized for name in names):
            return family
    raise ValueError(f"未対応のprofile familyです: {value}")


def profile_for(family: str) -> dict:
    """慣例上immutableな正規化済みprofileのcopyを返す。"""
    profiles = load_profiles()
    normalized = normalize_family(family, profiles)
    return {"family": normalized, **profiles[normalized]}


def bounded_strings(data: bytes, limit: int = MAX_STRINGS) -> list[str]:
    """決定的なwindowから順序付きで重複しないASCII/UTF-16LE文字列を抽出する。"""
    if limit <= 0:
        return []
    if len(data) <= FULL_SCAN_LIMIT:
        windows = [(0, data)]
    else:
        middle = max(0, (len(data) - SAMPLE_WINDOW) // 2)
        windows = [
            (0, data[:SAMPLE_WINDOW]),
            (middle, data[middle : middle + SAMPLE_WINDOW]),
            (len(data) - SAMPLE_WINDOW, data[-SAMPLE_WINDOW:]),
        ]

    candidates: dict[str, list[tuple[int, str]]] = {"ascii": [], "utf-16le": []}
    for pattern, encoding in ((ASCII, "ascii"), (WIDE, "utf-16le")):
        seen: set[str] = set()
        for base_offset, sample in windows:
            for match in pattern.finditer(sample):
                value = match.group().decode(encoding, errors="ignore")
                if value and value not in seen:
                    seen.add(value)
                    candidates[encoding].append((base_offset + match.start(), value))
                    if len(candidates[encoding]) >= limit:
                        break
            if len(candidates[encoding]) >= limit:
                break

    ascii_quota = (limit + 1) // 2
    wide_quota = limit // 2
    selected = candidates["ascii"][:ascii_quota] + candidates["utf-16le"][:wide_quota]
    selected_keys = {(offset, value) for offset, value in selected}
    remaining = sorted(
        (
            item
            for encoding_candidates in candidates.values()
            for item in encoding_candidates
            if item not in selected_keys
        ),
        key=lambda item: (item[0], item[1]),
    )
    selected.extend(remaining[: max(0, limit - len(selected))])
    selected.sort(key=lambda item: (item[0], item[1]))
    return [value for _offset, value in selected[:limit]]


def _marker_identity(value: str) -> str:
    """空白・句読点・大文字小文字だけが異なるmarkerを同一視する。"""

    lowered = value.casefold()
    return re.sub(r"[^a-z0-9]+", "", lowered) or lowered


def _independent_marker_hits(markers: list[str], text: str) -> list[str]:
    """substring aliasと同義表記を二重計上せず、一致literalを返す。

    例えばAsyncRAT Serverをasyncratとasyncrat serverの両方として数えず、
    HwidGenなど2つ目の独立したliteralを必須とする。空白・句読点だけが
    異なるHijackLoader／Hijack Loaderも1件として扱う。
    """

    lowered = text.casefold()
    matched: list[str] = []
    seen: set[str] = set()
    for marker in markers:
        literal = marker.casefold()
        identity = _marker_identity(marker)
        if identity in seen or literal not in lowered:
            continue
        seen.add(identity)
        matched.append(marker)
    return [
        marker
        for marker in matched
        if not any(
            _marker_identity(marker) != _marker_identity(other)
            and _marker_identity(marker) in _marker_identity(other)
            for other in matched
        )
    ]


def sanitize_network_url(value: str) -> str | None:
    """URLのsecretを除去し、local、不正、証明書、文書用hostを除外する。"""
    try:
        parsed = urlsplit(value.rstrip(".,;)]}"))
        host = (parsed.hostname or "").lower().rstrip(".")
        if parsed.scheme.lower() not in {"http", "https", "ftp"} or not host:
            return None
        if host in {"localhost", "example.com", "www.example.com"} or host.endswith(
            (".local", ".invalid", ".example", ".test")
        ):
            return None
        if host in BENIGN_HOSTS or any(
            host == item or host.endswith("." + item) for item in BENIGN_HOST_PARTS
        ):
            return None
        try:
            address = ipaddress.ip_address(host)
            if not address.is_global:
                return None
        except ValueError:
            labels = host.split(".")
            label = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", re.I)
            if len(labels) < 2 or not re.fullmatch(r"[a-z]{2,63}", labels[-1], re.I):
                return None
            if not all(label.fullmatch(part) for part in labels) or (
                len(labels) == 2 and labels[0] == "www"
            ):
                return None
        netloc = f"[{host}]" if ":" in host else host
        if parsed.port:
            netloc += f":{parsed.port}"
        path = parsed.path or "/"
        lowered = path.lower()
        parts = path.split("/")
        if host in {"discord.com", "discordapp.com"} and "/api/webhooks/" in lowered:
            index = next(
                (i for i, part in enumerate(parts) if part.lower() == "webhooks"), None
            )
            if index is not None and len(parts) > index + 2:
                path = "/".join(parts[: index + 2])
        elif (
            host == "hooks.slack.com"
            and lowered.startswith("/services/")
            and len(parts) > 4
        ):
            path = "/".join(parts[:4])
        elif host == "api.telegram.org":
            path = re.sub(r"/bot[^/]{8,}", "/bot-REDACTED", path, flags=re.I)
        elif host == "t.me" and path.lower().rstrip("/") in {"/example", "/test"}:
            return None
        return urlunsplit((parsed.scheme.lower(), netloc, path, "", ""))
    except ValueError:
        return None


def url_role(default_role: str, value: str) -> str:
    """無害化済みURLを探索、配布stage、profile既定roleへ分類する。"""
    parsed = urlsplit(value)
    host = (parsed.hostname or "").lower()
    if host in DISCOVERY_HOSTS:
        return "host_discovery_service"
    if host in DELIVERY_HOSTS or parsed.path.lower().endswith(STAGE_SUFFIXES):
        return "stage_url_candidate"
    return default_role


def _publishable_endpoint(value: str) -> bool:
    host = value.rsplit(":", 1)[0].strip("[]").lower()
    if host in {"localhost", "example.com"} or host.endswith(
        (".local", ".invalid", ".example", ".test")
    ):
        return False
    try:
        return ipaddress.ip_address(host).is_global
    except ValueError:
        labels = host.split(".")
        label = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", re.I)
        return (
            len(labels) >= 2
            and labels[-1] in COMMON_PUBLIC_TLDS
            and all(label.fullmatch(part) for part in labels)
        )


def extract_family(family: str, data: bytes, source_name: str = "sample.bin") -> dict:
    """1プロファイルの設定候補とnetwork指標を上限付きで抽出する。"""
    profile = profile_for(family)
    strings = bounded_strings(data)
    lowered = [value.lower() for value in strings]
    joined = "\n".join(lowered)
    marker_hits = _independent_marker_hits(profile["markers"], joined)
    required_marker_hits = _independent_marker_hits(
        profile.get("required_markers") or [], joined
    )
    required_marker_satisfied = bool(
        not profile.get("required_markers") or required_marker_hits
    )
    key_hits = [key for key in profile["config_keys"] if key.lower() in joined]
    enough_markers = bool(
        len(marker_hits) >= max(2, int(profile["minimum_markers"]))
        and required_marker_satisfied
    )
    urls = []
    for raw in url_candidates(strings):
        value = sanitize_network_url(raw)
        if value and value not in urls:
            urls.append(value)
    endpoints = [
        value for value in endpoint_candidates(strings) if _publishable_endpoint(value)
    ]
    role = profile["endpoint_role"]
    confidence = "candidate"
    findings = [
        {
            "kind": "network.url",
            "value": value,
            "role": url_role(role, value),
            "confidence": confidence,
            "source": "bounded_static_strings",
        }
        for value in urls[:MAX_FINDINGS]
    ]
    remaining = max(0, MAX_FINDINGS - len(findings))
    findings.extend(
        {
            "kind": "network.endpoint",
            "value": value,
            "role": role,
            "confidence": confidence,
            "source": "bounded_static_strings",
        }
        for value in endpoints[:remaining]
    )
    profile_literal_correlation = bool(enough_markers and key_hits and findings)
    config = {
        "source_name": source_name,
        "profile": profile["family"],
        "display_name": profile["display_name"],
        "category": profile["category"],
        "transport": profile["transport"],
        "marker_hits": marker_hits,
        "required_marker_hits": required_marker_hits,
        "required_marker_satisfied": required_marker_satisfied,
        "minimum_markers": profile["minimum_markers"],
        "observed_config_keys": key_hits,
        "network_candidates": [item["value"] for item in findings],
        "profile_literal_correlation": profile_literal_correlation,
        "correlation_requirements": {
            "independent_markers": enough_markers,
            "config_key": bool(key_hits),
            "network_candidate": bool(findings),
        },
        "decoded_config_recovered": False,
        "static_config_recovered": False,
        "scan_scope": "complete_input"
        if len(data) <= FULL_SCAN_LIMIT
        else "deterministic_three_window_sample",
    }
    return build_result(
        profile["family"],
        data,
        config,
        findings,
        [
            "プロファイル文字列、設定key、無害化済みnetwork候補の相関は、復号済み設定そのものではありません。",
            "暗号化またはpack済み設定fieldには、family固有decoderまたは復元済みinner payloadが必要です。",
            profile["confirmation"],
            "候補インフラへ接続せず、稼働状態も推定していません。",
            "資格情報、token、URL query、fragmentは公開しません。",
        ],
    )


def extractor_for(family: str) -> Callable[[bytes, str], dict]:
    """1つのprofileへbindした2引数の抽出関数を返す。"""
    normalized = profile_for(family)["family"]

    def extract(data: bytes, source_name: str = "sample.bin") -> dict:
        """検体を実行せず、bind済みfamily profileを適用する。"""
        return extract_family(normalized, data, source_name)

    extract.__name__ = f"extract_{normalized}"
    return extract
