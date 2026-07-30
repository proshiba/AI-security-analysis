#!/usr/bin/env python3
"""ClickFix情報源を収集し、限定ライブ観測と公開用ケースを生成する。"""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import hashlib
import html
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import yaml


CARSON_BASE = "https://clickfix.carsonww.com"
CARSON_DOMAIN = "tbhadvisors.com"
CLICKFIX_PRO_EXPORT = "https://clickfix.pro/export.csv"
THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"
DEFAULT_LIMIT = 50
DEFAULT_TIMEOUT = 8.0
BASE_BODY_LIMIT = 262_144
STAGE_BODY_LIMIT = 1_048_576
MAX_REDIRECTS = 2
MAX_STAGE_URLS = 3
USER_AGENT = "AI-security-analysis ClickFix research/1.0"
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
    re.IGNORECASE,
)
REVERSED_URL_RE = re.compile(
    r"(?P<quote>['\"])(?P<value>[A-Za-z0-9+_./:=?&%-]{12,})"
    r"(?P=quote)\s*\[\s*-1\s*\.\.\s*-\d+\s*\]",
    re.IGNORECASE,
)
NO_SCHEME_FETCH_RE = re.compile(
    r"(?:irm|iwr|invoke-restmethod|invoke-webrequest|downloadstring)"
    r"\s*\(?\s*['\"](?P<value>(?:[a-z0-9-]+\.)+[a-z]{2,63}/[^'\"]*)",
    re.IGNORECASE,
)
UNC_SSL_RE = re.compile(
    r"\\\\(?P<host>[a-z0-9.-]+)@SSL\\(?P<path>[^\"'\s&]+)",
    re.IGNORECASE,
)
NET_USE_RE = re.compile(
    r"net\s+use\s+\S+\s+(?P<url>https?://[^\s\"']+)",
    re.IGNORECASE,
)
COMMAND_MARKERS = (
    "powershell",
    "pwsh",
    "cmd.exe",
    "cmd /",
    "rundll32",
    "mshta",
    "wscript",
    "cscript",
    "conhost",
    "regsvr32",
    "net use",
    "pushd ",
)
CLIPBOARD_MARKERS = (
    "navigator.clipboard",
    "clipboard.write",
    "writetext(",
    "execcommand('copy",
    'execcommand("copy',
    "clipboarditem",
)
LURE_MARKERS = (
    "verify you are human",
    "verification",
    "captcha",
    "cloudflare",
    "press win",
    "windows key",
    "run dialog",
    "ctrl+v",
)
TEXT_CONTENT_MARKERS = (
    "text/",
    "javascript",
    "json",
    "xml",
    "html",
    "powershell",
)
DUAL_USE_HOSTS = {
    "t.me",
    "telegram.me",
    "telegram.org",
    "web.telegram.org",
}
SOURCE_URLS = {
    "clickfix_hunter": f"{CARSON_BASE}/domains/{CARSON_DOMAIN}",
    "clickfix_pro": "https://clickfix.pro/",
    "threatfox_clickfix": "https://threatfox.abuse.ch/browse/tag/clickfix/",
    "threatfox_clearfake": "https://threatfox.abuse.ch/browse/tag/clearfake/",
}
BACKGROUND_SOURCES = {
    "microsoft": (
        "Microsoft: ClickFixの攻撃チェーンと検知",
        "https://www.microsoft.com/en-us/security/blog/2025/08/21/"
        "think-before-you-clickfix-analyzing-the-clickfix-social-engineering-technique/",
    ),
    "proofpoint": (
        "Proofpoint: ClickFixの普及と配布マルウェア",
        "https://www.proofpoint.com/us/blog/threat-insight/"
        "security-brief-clickfix-social-engineering-technique-floods-threat-landscape",
    ),
    "unit42": (
        "Unit 42: ClickFixの防御・ハンティング",
        "https://unit42.paloaltonetworks.com/preventing-clickfix-attack-vector/",
    ),
}


def utc_now() -> str:
    """現在時刻をUTC ISO 8601で返す。"""

    return datetime.now(timezone.utc).isoformat()


def atomic_json(path: Path, value: Any) -> None:
    """JSONを一時ファイル経由で決定的に保存する。"""

    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    os.replace(temporary, path)


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content.rstrip() + "\n", encoding="utf-8", newline="\n")


def sanitize_domain(value: str) -> str:
    """IOCまたはURLから小文字のドメインを返す。"""

    candidate = value.strip()
    if "://" in candidate:
        candidate = urllib.parse.urlsplit(candidate).hostname or ""
    return candidate.rstrip(".").lower()


def sanitize_url(value: str) -> dict[str, Any]:
    """URLから資格情報・query・fragmentを除き、証跡用hashを残す。"""

    parsed = urllib.parse.urlsplit(value)
    host = (parsed.hostname or "").lower()
    port = f":{parsed.port}" if parsed.port else ""
    original_path = parsed.path or "/"
    redact_path = host in DUAL_USE_HOSTS and original_path != "/"
    safe_path = "/<redacted>" if redact_path else original_path
    safe = urllib.parse.urlunsplit((parsed.scheme.lower(), host + port, safe_path, "", ""))
    return {
        "sanitized": safe,
        "host": host,
        "path": safe_path,
        "path_redacted": redact_path,
        "path_sha256": (hashlib.sha256(original_path.encode("utf-8")).hexdigest() if redact_path else None),
        "query_present": bool(parsed.query),
        "query_names": sorted(
            {
                name
                for name, _ in urllib.parse.parse_qsl(
                    parsed.query,
                    keep_blank_values=True,
                )
            }
        ),
        "query_sha256": (hashlib.sha256(parsed.query.encode("utf-8")).hexdigest() if parsed.query else None),
        "fragment_present": bool(parsed.fragment),
        "userinfo_present": parsed.username is not None or parsed.password is not None,
    }


def redact_urls_in_text(value: str) -> str:
    """文中のURLから秘密になり得る要素を除去する。"""

    def replace(match: re.Match[str]) -> str:
        candidate = match.group(0).rstrip(").,;")
        suffix = match.group(0)[len(candidate) :]
        return sanitize_url(candidate)["sanitized"] + suffix

    return URL_RE.sub(replace, value)


def classify_bytes(data: bytes, content_type: str = "") -> str:
    """取得したbytesを実行せずに大まかな形式へ分類する。"""

    if data.startswith(b"MZ"):
        return "pe"
    if data.startswith(b"PK\x03\x04"):
        return "zip"
    if data.startswith(b"Rar!\x1a\x07"):
        return "rar"
    if data.startswith(b"\x7fELF"):
        return "elf"
    if data[:4] in {
        bytes.fromhex("feedface"),
        bytes.fromhex("feedfacf"),
        bytes.fromhex("cefaedfe"),
        bytes.fromhex("cffaedfe"),
    }:
        return "mach-o"
    lowered = data[:1_024].lower()
    if b"<!doctype html" in lowered or b"<html" in lowered:
        return "html"
    if b"powershell" in lowered or b"invoke-expression" in lowered:
        return "powershell"
    if b"function " in lowered or b"=>{" in lowered:
        return "javascript"
    lowered_type = content_type.lower()
    if "html" in lowered_type:
        return "html"
    if "javascript" in lowered_type:
        return "javascript"
    if "text/" in lowered_type:
        return "text"
    return "other"


def command_profile(command: str) -> dict[str, Any]:
    """ClickFixのコピーコマンドをプロセス・段階・検知系列へ要約する。"""

    lowered = command.lower()
    processes = []
    for marker, process in (
        ("conhost", "conhost.exe"),
        ("cmd", "cmd.exe"),
        ("powershell", "powershell.exe"),
        ("pwsh", "pwsh.exe"),
        ("rundll32", "rundll32.exe"),
        ("mshta", "mshta.exe"),
        ("wscript", "wscript.exe"),
        ("cscript", "cscript.exe"),
        ("regsvr32", "regsvr32.exe"),
        ("net use", "net.exe"),
    ):
        if marker in lowered and process not in processes:
            processes.append(process)
    if "conhost" in lowered and "--headless" in lowered and "@ssl" in lowered:
        pattern = "webdav_rundll32"
        summary = "conhostをheadlessで起動し、cmdからWebDAVのUNCパスへ移動後、取得DLLのexport #1をrundll32で呼び出す。"
    elif "net use" in lowered and "webdav" in lowered:
        pattern = "mapped_webdav_command"
        summary = "net useでWebDAVをドライブへ割り当て、共有上のcommand scriptを実行してマッピングを解除する。"
    elif "t.me" in command[::-1].lower() or ("[-1.." in lowered and "_description" in lowered and "/l.dat" in lowered):
        pattern = "telegram_dead_drop_powershell"
        summary = (
            "PowerShellが逆順文字列からTelegram URLを復元し、ページdescriptionの"
            "2トークンから次段hostを取得して `/l.dat` をメモリ内実行する。"
        )
    elif "powershell" in lowered and any(marker in lowered for marker in ("irm", "iwr", "downloadstring")):
        pattern = "powershell_download_execute"
        summary = "PowerShellがHTTP(S)からscriptまたはpayloadを取得し、Invoke-Expression相当でメモリ内実行する。"
    elif any(marker in lowered for marker in COMMAND_MARKERS):
        pattern = "shell_execution"
        summary = "WindowsのshellまたはLOLBINを使って後続処理を起動する。"
    elif command.strip().lower().startswith(("http://", "https://")):
        pattern = "url_only_clipboard"
        summary = "clipboardにはURLだけが入り、後続commandはこの証跡では確認できない。"
    else:
        pattern = "unknown_clipboard_content"
        summary = "clipboard内容は取得したが、実行可能なcommandとして確定できない。"
    return {
        "pattern": pattern,
        "summary": summary,
        "processes": processes,
        "command_sha256": hashlib.sha256(command.encode("utf-8")).hexdigest(),
    }


def extract_stage_urls(command: str) -> list[str]:
    """コピーコマンドから実際に参照されるHTTP(S) URLを復元する。"""

    output: list[str] = []

    def add(candidate: str) -> None:
        value = candidate.strip().rstrip(").,;")
        try:
            parsed = urllib.parse.urlsplit(value)
        except ValueError:
            return
        if parsed.scheme.lower() in {"http", "https"} and parsed.hostname and value not in output:
            output.append(value)

    for match in URL_RE.finditer(command):
        add(match.group(0))
    for match in REVERSED_URL_RE.finditer(command):
        reversed_value = match.group("value")[::-1]
        if reversed_value.lower().startswith(("http://", "https://")):
            add(reversed_value)
    for match in NO_SCHEME_FETCH_RE.finditer(command):
        add("https://" + match.group("value"))
    for match in UNC_SSL_RE.finditer(command):
        path = match.group("path").replace("\\", "/")
        add(f"https://{match.group('host')}/{path}")
    for match in NET_USE_RE.finditer(command):
        base = match.group("url").rstrip("/")
        add(base)
        if "update.cmd" in command.lower():
            add(base + "/update.cmd")
    return output


def _is_textual(content_type: str, kind: str) -> bool:
    return kind in {"html", "javascript", "powershell", "text"} or any(
        marker in content_type.lower() for marker in TEXT_CONTENT_MARKERS
    )


def _decode_text(data: bytes, content_type: str) -> str:
    charset = "utf-8"
    match = re.search(r"charset=([A-Za-z0-9._-]+)", content_type, re.IGNORECASE)
    if match:
        charset = match.group(1)
    try:
        return data.decode(charset, errors="replace")
    except LookupError:
        return data.decode("utf-8", errors="replace")


def analyze_text_body(text: str) -> dict[str, Any]:
    """HTML/script本文からclipboard、lure、command、通信候補を抽出する。"""

    lowered = text.lower()
    title_match = re.search(
        r"<title[^>]*>(?P<title>.*?)</title>",
        text,
        re.IGNORECASE | re.DOTALL,
    )
    title = None
    if title_match:
        title = re.sub(r"\s+", " ", html.unescape(title_match.group("title"))).strip()
    urls = []
    for match in URL_RE.finditer(html.unescape(text)):
        value = match.group(0).rstrip(").,;")
        safe = sanitize_url(value)
        if safe["sanitized"] not in [item["sanitized"] for item in urls]:
            urls.append(safe)
        if len(urls) >= 50:
            break
    commands = []
    plain = re.sub(r"<[^>]+>", "\n", html.unescape(text))
    for line in plain.splitlines():
        compact = re.sub(r"\s+", " ", line).strip()
        if not compact or len(compact) < 8:
            continue
        if any(marker in compact.lower() for marker in COMMAND_MARKERS):
            profile = command_profile(compact[:4_096])
            if profile["command_sha256"] not in {item["command_sha256"] for item in commands}:
                commands.append({**profile, "private_command": compact[:4_096]})
        if len(commands) >= 20:
            break
    telegram_match = re.search(
        r"_description[^>]*>(?P<host>\S+)\s+(?P<code>\S+)<",
        text,
        re.IGNORECASE,
    )
    telegram_next_stage = None
    if telegram_match and DOMAIN_RE.fullmatch(telegram_match.group("host")):
        telegram_next_stage = f"https://{telegram_match.group('host')}/l.dat"
    return {
        "title": title,
        "clipboard_api_observed": any(marker in lowered for marker in CLIPBOARD_MARKERS),
        "lure_markers": sorted(marker for marker in LURE_MARKERS if marker in lowered),
        "candidate_commands": commands,
        "referenced_urls": urls,
        "telegram_next_stage": telegram_next_stage,
    }


def resolve_public(host: str) -> dict[str, Any]:
    """hostを解決し、global addressだけを接続許可候補として返す。"""

    addresses: list[str] = []
    try:
        for _, _, _, _, sockaddr in socket.getaddrinfo(
            host,
            None,
            type=socket.SOCK_STREAM,
        ):
            address = str(sockaddr[0])
            if address not in addresses:
                addresses.append(address)
    except OSError as error:
        return {
            "status": "error",
            "error": type(error).__name__,
            "addresses": [],
            "public_addresses": [],
        }
    public = []
    for address in addresses:
        try:
            if ipaddress.ip_address(address).is_global:
                public.append(address)
        except ValueError:
            continue
    return {
        "status": "ok",
        "addresses": addresses,
        "public_addresses": public,
        "all_addresses_public": bool(addresses) and len(addresses) == len(public),
    }


def _tls_certificate_summary(
    connection: http.client.HTTPConnection,
) -> dict[str, Any] | None:
    """既存HTTPS接続のleaf証明書を、秘密値を含めずピボット用に要約する。"""

    sock = getattr(connection, "sock", None)
    if sock is None or not hasattr(sock, "getpeercert"):
        return None
    try:
        certificate = sock.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError, ValueError):
        return None
    if not certificate:
        return None
    result: dict[str, Any] = {
        "sha256": hashlib.sha256(certificate).hexdigest(),
        "der_size": len(certificate),
    }
    try:
        from cryptography import x509
        from cryptography.x509.oid import ExtensionOID

        parsed = x509.load_der_x509_certificate(certificate)
        result.update(
            {
                "subject": parsed.subject.rfc4514_string(),
                "issuer": parsed.issuer.rfc4514_string(),
                "serial_number_hex": format(parsed.serial_number, "x"),
                "not_valid_before_utc": parsed.not_valid_before_utc.isoformat(),
                "not_valid_after_utc": parsed.not_valid_after_utc.isoformat(),
            }
        )
        try:
            extension = parsed.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            result["dns_names"] = sorted(set(extension.value.get_values_for_type(x509.DNSName)))[:100]
        except x509.ExtensionNotFound:
            result["dns_names"] = []
    except (ImportError, ValueError):
        result["parsed"] = False
    return result


def _http_once(url: str, timeout: float, limit: int) -> tuple[dict[str, Any], bytes]:
    parsed = urllib.parse.urlsplit(url)
    safe = sanitize_url(url)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return {
            "status": "blocked",
            "reason": "http_https以外、またはhostなし",
            "url": safe,
        }, b""
    dns = resolve_public(parsed.hostname)
    if not dns["public_addresses"]:
        return {
            "status": "blocked",
            "reason": "public addressを確認できない",
            "url": safe,
            "dns": dns,
        }, b""
    connection: http.client.HTTPConnection | None = None
    started = time.monotonic()
    try:
        if parsed.scheme.lower() == "https":
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            connection = http.client.HTTPSConnection(
                parsed.hostname,
                parsed.port or 443,
                timeout=timeout,
                context=context,
            )
        else:
            connection = http.client.HTTPConnection(
                parsed.hostname,
                parsed.port or 80,
                timeout=timeout,
            )
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        connection.request(
            "GET",
            path,
            headers={
                "User-Agent": USER_AGENT,
                "Accept": "text/html,application/javascript,text/plain,application/octet-stream;q=0.5",
                "Accept-Encoding": "identity",
                "Range": f"bytes=0-{limit}",
                "Connection": "close",
            },
        )
        response = connection.getresponse()
        tls_certificate = _tls_certificate_summary(connection) if parsed.scheme.lower() == "https" else None
        data = response.read(limit + 1)
        truncated = len(data) > limit
        if truncated:
            data = data[:limit]
        content_type = response.getheader("Content-Type") or ""
        kind = classify_bytes(data, content_type)
        result: dict[str, Any] = {
            "status": "ok",
            "url": safe,
            "http_status": response.status,
            "reason": response.reason,
            "content_type": content_type,
            "content_length_header": response.getheader("Content-Length"),
            "location": (
                sanitize_url(urllib.parse.urljoin(url, response.getheader("Location")))
                if response.getheader("Location")
                else None
            ),
            "bytes_read": len(data),
            "body_truncated": truncated,
            "body_sha256": hashlib.sha256(data).hexdigest(),
            "body_type": kind,
            "dns": dns,
            "latency_ms": round((time.monotonic() - started) * 1_000, 1),
            "tls_certificate_validation": "disabled_for_malicious_site_observation"
            if parsed.scheme.lower() == "https"
            else "not_applicable",
            "tls_certificate": tls_certificate,
        }
        if _is_textual(content_type, kind):
            result["text_analysis"] = analyze_text_body(_decode_text(data, content_type))
        return result, data
    except (OSError, http.client.HTTPException, ssl.SSLError) as error:
        return {
            "status": "error",
            "url": safe,
            "error": type(error).__name__,
            "dns": dns,
            "latency_ms": round((time.monotonic() - started) * 1_000, 1),
        }, b""
    finally:
        if connection:
            connection.close()


def probe_url(
    url: str,
    *,
    timeout: float,
    limit: int,
    private_directory: Path,
    label: str,
    max_redirects: int = MAX_REDIRECTS,
) -> dict[str, Any]:
    """URLを上限付きGETし、redirect chainと静的本文特徴を返す。"""

    hops = []
    current = url
    for index in range(max_redirects + 1):
        result, data = _http_once(current, timeout, limit)
        result["hop"] = index
        retained = False
        if data and result.get("body_type") in {
            "html",
            "javascript",
            "powershell",
            "text",
        }:
            private_directory.mkdir(parents=True, exist_ok=True)
            path = private_directory / f"{label}-hop-{index}.txt"
            path.write_bytes(data)
            retained = True
        result["body_retained_private"] = retained
        hops.append(result)
        location = result.get("location")
        if (
            result.get("status") != "ok"
            or not isinstance(location, dict)
            or not location.get("sanitized")
            or index >= max_redirects
        ):
            break
        raw_location = urllib.parse.urljoin(
            current,
            str(result.get("location", {}).get("sanitized")),
        )
        current = raw_location
    return {
        "requested": sanitize_url(url),
        "hops": hops,
        "redirects_followed": max(0, len(hops) - 1),
        "javascript_executed": False,
        "credentials_sent": False,
        "malware_protocol_sent": False,
    }


def _stage_candidates_from_probe(probe: dict[str, Any]) -> list[str]:
    candidates: list[str] = []
    for hop in probe.get("hops", []):
        text_analysis = hop.get("text_analysis") or {}
        telegram = text_analysis.get("telegram_next_stage")
        if telegram and telegram not in candidates:
            candidates.append(telegram)
        for command in text_analysis.get("candidate_commands", []):
            for url in extract_stage_urls(str(command.get("private_command") or "")):
                if url not in candidates:
                    candidates.append(url)
    return candidates


@dataclass(frozen=True)
class SelectedCase:
    case_id: str
    domain: str
    observed_at: str
    source: str
    source_id: str
    source_url: str
    tags: tuple[str, ...]
    reported_malware: str
    confidence: int | None
    raw_command: str | None = None
    urlscan_url: str | None = None
    note: str | None = None


def _case_id(analysis_date: str, source: str, source_id: str) -> str:
    compact = analysis_date.replace("-", "")
    safe_source = re.sub(r"[^a-z0-9]+", "-", source.lower()).strip("-")
    safe_id = re.sub(r"[^a-zA-Z0-9._-]+", "-", source_id).strip("-")
    return f"{compact}-{safe_source}-{safe_id.lower()}"


def parse_threatfox(path: Path, tag: str, analysis_date: str) -> list[SelectedCase]:
    """ThreatFox taginfo応答から指定日付のcaseを抽出する。"""

    document = json.loads(path.read_text(encoding="utf-8-sig"))
    if document.get("query_status") != "ok":
        raise ValueError(f"ThreatFox query failed: {tag}")
    output = []
    for row in document.get("data", []):
        observed = str(row.get("first_seen") or "")
        if not observed.startswith(analysis_date):
            continue
        domain = sanitize_domain(str(row.get("ioc") or ""))
        if not DOMAIN_RE.fullmatch(domain):
            continue
        source_id = str(row.get("id") or hashlib.sha256(domain.encode()).hexdigest()[:12])
        row_tags = tuple(sorted({str(item) for item in (row.get("tags") or [])} | {tag}))
        output.append(
            SelectedCase(
                case_id=_case_id(analysis_date, "threatfox", source_id),
                domain=domain,
                observed_at=observed,
                source="ThreatFox",
                source_id=source_id,
                source_url=SOURCE_URLS[f"threatfox_{tag}"],
                tags=row_tags,
                reported_malware=str(row.get("malware_printable") or "Unknown malware"),
                confidence=int(row["confidence_level"]) if row.get("confidence_level") is not None else None,
                note="payload_deliveryとして報告。終端payloadのfamilyとは区別する。",
            )
        )
    return sorted(output, key=lambda item: (item.observed_at, item.source_id), reverse=True)


def parse_clickfix_pro(path: Path, analysis_date: str) -> list[SelectedCase]:
    """clickfix.pro公開CSVからClickFix/ClearFake行を抽出する。"""

    output = []
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        for row in csv.DictReader(stream, delimiter=";"):
            tag = str(row.get("Tag") or "")
            if not re.search(r"clickfix|clearfake", tag, re.IGNORECASE):
                continue
            domain = sanitize_domain(str(row.get("Domain") or ""))
            if not DOMAIN_RE.fullmatch(domain):
                continue
            observed = str(row.get("Scan Date") or "")
            source_id = hashlib.sha256(f"{observed}|{domain}|{tag}".encode("utf-8")).hexdigest()[:12]
            output.append(
                SelectedCase(
                    case_id=_case_id(analysis_date, "clickfix-pro", source_id),
                    domain=domain,
                    observed_at=observed,
                    source="ClickFix Campaign Monitor",
                    source_id=source_id,
                    source_url=SOURCE_URLS["clickfix_pro"],
                    tags=(tag,),
                    reported_malware=("ClearFake" if "clearfake" in tag.lower() else "未確認"),
                    confidence=None,
                    note="公開monitorのtag。終端payloadは別証跡が得られるまで未確認。",
                )
            )
    return sorted(output, key=lambda item: (item.observed_at, item.domain), reverse=True)


def parse_carson(path: Path, analysis_date: str) -> SelectedCase:
    """ClickFix Hunterのdomain API応答から明示対象caseを生成する。"""

    document = json.loads(path.read_text(encoding="utf-8-sig"))
    row = document.get("data") or {}
    domain = sanitize_domain(str(row.get("domain") or CARSON_DOMAIN))
    observed = str(row.get("timestamp") or "")
    source_id = hashlib.sha256(f"{observed}|{domain}".encode()).hexdigest()[:12]
    metadata = row.get("metadata") or {}
    return SelectedCase(
        case_id=_case_id(analysis_date, "clickfix-hunter", source_id),
        domain=domain,
        observed_at=observed,
        source="ClickFix Hunter",
        source_id=source_id,
        source_url=SOURCE_URLS["clickfix_hunter"],
        tags=("ClickFix", "clipboard-hijack", "fake-captcha"),
        reported_malware="未確認",
        confidence=100 if row.get("malicious") else None,
        raw_command=str(row.get("clipboardContent") or "") or None,
        urlscan_url=str(metadata.get("urlscanLink") or "") or None,
        note="ClickFix Hunterのsandbox観測。terminal payloadは静的追跡結果で別評価する。",
    )


def select_cases(
    *,
    analysis_date: str,
    threatfox_clickfix: Iterable[SelectedCase],
    threatfox_clearfake: Iterable[SelectedCase],
    clickfix_pro: Iterable[SelectedCase],
    carson: SelectedCase,
    limit: int,
) -> list[SelectedCase]:
    """明示対象と本日ThreatFoxを優先し、最大limit件へ重複排除する。"""

    if not 1 <= limit <= DEFAULT_LIMIT:
        raise ValueError(f"limitは1から{DEFAULT_LIMIT}の範囲で指定してください")
    selected: list[SelectedCase] = []
    domains: set[str] = set()

    def add(item: SelectedCase) -> None:
        if len(selected) >= limit or item.domain in domains:
            return
        selected.append(item)
        domains.add(item.domain)

    add(carson)
    threatfox = sorted(
        [*threatfox_clickfix, *threatfox_clearfake],
        key=lambda item: (item.observed_at, item.source_id),
        reverse=True,
    )
    for item in threatfox:
        add(item)
    for item in clickfix_pro:
        add(item)
    return selected


def _download(
    request: urllib.request.Request,
    *,
    timeout: float,
    limit: int,
) -> bytes:
    with urllib.request.urlopen(request, timeout=timeout) as response:
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"response exceeded {limit} bytes")
    return data


def collect_sources(
    private_root: Path,
    *,
    auth_key: str,
    timeout: float,
) -> dict[str, Path]:
    """3情報源の生応答をprivate領域へ取得する。"""

    private_root.mkdir(parents=True, exist_ok=True)
    outputs = {
        "carson": private_root / "carson-tbhadvisors.json",
        "clickfix_pro": private_root / "clickfixpro-export.csv",
        "threatfox_clickfix": private_root / "threatfox-clickfix.json",
        "threatfox_clearfake": private_root / "threatfox-clearfake.json",
    }
    carson = _download(
        urllib.request.Request(
            f"{CARSON_BASE}/api/domain/{CARSON_DOMAIN}/latest",
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
        ),
        timeout=timeout,
        limit=20_000_000,
    )
    outputs["carson"].write_bytes(carson)
    clickfix_pro = _download(
        urllib.request.Request(
            CLICKFIX_PRO_EXPORT,
            headers={"User-Agent": USER_AGENT, "Accept": "text/csv"},
        ),
        timeout=timeout,
        limit=5_000_000,
    )
    outputs["clickfix_pro"].write_bytes(clickfix_pro)
    for tag, key in (
        ("clickfix", "threatfox_clickfix"),
        ("clearfake", "threatfox_clearfake"),
    ):
        body = json.dumps({"query": "taginfo", "tag": tag, "limit": 50}).encode("utf-8")
        request = urllib.request.Request(
            THREATFOX_API,
            method="POST",
            data=body,
            headers={
                "User-Agent": USER_AGENT,
                "Content-Type": "application/json",
                "Auth-Key": auth_key,
            },
        )
        outputs[key].write_bytes(_download(request, timeout=timeout, limit=5_000_000))
    return outputs


def _source_paths(source_root: Path) -> dict[str, Path]:
    paths = {
        "carson": source_root / "carson-tbhadvisors.json",
        "clickfix_pro": source_root / "clickfixpro-export.csv",
        "threatfox_clickfix": source_root / "threatfox-clickfix.json",
        "threatfox_clearfake": source_root / "threatfox-clearfake.json",
    }
    missing = [str(path) for path in paths.values() if not path.is_file()]
    if missing:
        raise FileNotFoundError("missing source files: " + ", ".join(missing))
    return paths


def probe_case(
    item: SelectedCase,
    *,
    timeout: float,
    private_root: Path,
) -> dict[str, Any]:
    """1 caseのlanding pageと静的に復元した次段URLを限定GETする。"""

    case_private = private_root / "cases" / item.case_id
    base_probe = probe_url(
        f"https://{item.domain}/",
        timeout=timeout,
        limit=BASE_BODY_LIMIT,
        private_directory=case_private / "http",
        label="landing-https",
    )
    if not any(hop.get("status") == "ok" for hop in base_probe["hops"]):
        fallback = probe_url(
            f"http://{item.domain}/",
            timeout=timeout,
            limit=BASE_BODY_LIMIT,
            private_directory=case_private / "http",
            label="landing-http",
        )
        landing_probes = [base_probe, fallback]
    else:
        landing_probes = [base_probe]
    stage_urls = extract_stage_urls(item.raw_command or "")
    for landing in landing_probes:
        for candidate in _stage_candidates_from_probe(landing):
            if candidate not in stage_urls:
                stage_urls.append(candidate)
    stage_probes = []
    seen_sanitized: set[str] = set()
    index = 0
    while index < len(stage_urls) and len(stage_probes) < MAX_STAGE_URLS:
        candidate = stage_urls[index]
        index += 1
        safe = sanitize_url(candidate)["sanitized"]
        if safe in seen_sanitized:
            continue
        seen_sanitized.add(safe)
        stage = probe_url(
            candidate,
            timeout=timeout,
            limit=STAGE_BODY_LIMIT,
            private_directory=case_private / "stages",
            label=f"stage-{len(stage_probes) + 1}",
            max_redirects=1,
        )
        stage_probes.append(stage)
        for nested in _stage_candidates_from_probe(stage):
            if nested not in stage_urls:
                stage_urls.append(nested)
    result = {
        "schema_version": 1,
        "case_id": item.case_id,
        "domain": item.domain,
        "probed_at_utc": utc_now(),
        "policy": {
            "method": "GET",
            "redirect_limit": MAX_REDIRECTS,
            "landing_body_limit": BASE_BODY_LIMIT,
            "stage_body_limit": STAGE_BODY_LIMIT,
            "javascript_executed": False,
            "malware_executed": False,
            "credentials_sent": False,
            "malware_protocol_sent": False,
            "non_text_binary_retained": False,
        },
        "landing": landing_probes,
        "stages": stage_probes,
    }
    atomic_json(case_private / "private-observation.json", result)
    return result


def _iter_hops(observation: dict[str, Any]) -> Iterable[dict[str, Any]]:
    for probe in [*observation.get("landing", []), *observation.get("stages", [])]:
        yield from probe.get("hops", [])


def public_observation(observation: dict[str, Any]) -> dict[str, Any]:
    """private情報と通常サイト資産の列挙を除いたライブ観測を返す。"""

    value = json.loads(json.dumps(observation))
    for hop in _iter_hops(value):
        hop.pop("body_retained_private", None)
        text_analysis = hop.get("text_analysis") or {}
        for command in text_analysis.get("candidate_commands", []):
            command.pop("private_command", None)
        referenced = text_analysis.pop("referenced_urls", [])
        text_analysis["referenced_url_count"] = len(referenced)
    return value


def observation_summary(observation: dict[str, Any]) -> dict[str, Any]:
    """case文書向けにライブ観測を短く集約する。"""

    hops = list(_iter_hops(observation))
    ok = [hop for hop in hops if hop.get("status") == "ok"]
    http_statuses = sorted({int(hop["http_status"]) for hop in ok if hop.get("http_status") is not None})
    addresses = sorted({address for hop in hops for address in (hop.get("dns") or {}).get("public_addresses", [])})
    redirects = sorted(
        {
            str((hop.get("location") or {}).get("sanitized"))
            for hop in hops
            if (hop.get("location") or {}).get("sanitized")
        }
    )
    types = Counter(str(hop.get("body_type") or "unknown") for hop in ok)
    commands = []
    clipboard = False
    lure_markers: set[str] = set()

    telegram_requested = False
    telegram_reachable = False
    telegram_next_stage_recovered = False
    for probe in observation.get("stages", []):
        requested_host = str((probe.get("requested") or {}).get("host") or "")
        if requested_host not in {"t.me", "telegram.me"}:
            continue
        telegram_requested = True
        for hop in probe.get("hops", []):
            telegram_reachable = telegram_reachable or hop.get("status") == "ok"
            analysis = hop.get("text_analysis") or {}
            telegram_next_stage_recovered = telegram_next_stage_recovered or bool(analysis.get("telegram_next_stage"))
    for hop in ok:
        analysis = hop.get("text_analysis") or {}
        clipboard = clipboard or bool(analysis.get("clipboard_api_observed"))
        lure_markers.update(analysis.get("lure_markers") or [])
        for command in analysis.get("candidate_commands") or []:
            public = {key: value for key, value in command.items() if key != "private_command"}
            if public.get("command_sha256") not in {item.get("command_sha256") for item in commands}:
                commands.append(public)

    payloads = []
    for hop in ok:
        if hop.get("body_type") in {"pe", "zip", "rar", "elf", "mach-o"}:
            payloads.append(
                {
                    "sha256": hop.get("body_sha256"),
                    "type": hop.get("body_type"),
                    "bytes_observed": hop.get("bytes_read"),
                    "truncated": hop.get("body_truncated"),
                    "source_url": (hop.get("url") or {}).get("sanitized"),
                    "retained": False,
                }
            )
    certificates: dict[str, dict[str, Any]] = {}
    for hop in ok:
        certificate = hop.get("tls_certificate") or {}
        fingerprint = str(certificate.get("sha256") or "")
        if re.fullmatch(r"[0-9a-f]{64}", fingerprint):
            certificates[fingerprint] = certificate
    if telegram_next_stage_recovered:
        telegram_state = "next_stage_recovered"
    elif telegram_reachable:
        telegram_state = "reachable_but_tokens_absent"
    elif telegram_requested:
        telegram_state = "unreachable"
    else:
        telegram_state = "not_applicable"
    return {
        "reachable": bool(ok),
        "successful_http_hops": len(ok),
        "http_statuses": http_statuses,
        "webdav_multistatus_observed": 207 in http_statuses,
        "public_addresses": addresses,
        "redirects": redirects,
        "body_types": dict(sorted(types.items())),
        "clipboard_api_observed_live": clipboard,
        "lure_markers_live": sorted(lure_markers),
        "candidate_commands_live": commands,
        "telegram_resolver_state": telegram_state,
        "binary_payloads_observed": payloads,
        "tls_certificates": list(certificates.values()),
    }


def _indicator(
    kind: str,
    value: str,
    role: str,
    confidence: str,
    source: str,
) -> dict[str, str]:
    return {
        "type": kind,
        "value": value,
        "role": role,
        "confidence": confidence,
        "source": source,
    }


def build_iocs(
    item: SelectedCase,
    summary: dict[str, Any],
    command: dict[str, Any] | None,
) -> dict[str, Any]:
    """case根拠に紐づく公開可能IOCを構築する。"""

    indicators = [
        _indicator(
            "domain",
            item.domain,
            "clickfix_landing_or_payload_delivery",
            "confirmed_provider_report",
            item.source,
        )
    ]
    for address in summary["public_addresses"]:
        indicators.append(
            _indicator(
                "ip",
                address,
                "context_only_live_dns_resolution",
                "observed_at_analysis_time",
                "限定ライブ観測",
            )
        )
    stage_urls = extract_stage_urls(item.raw_command or "")
    for stage_url in stage_urls:
        safe = sanitize_url(stage_url)
        role = "context_only_dead_drop_resolver" if safe["host"] in DUAL_USE_HOSTS else "stage_delivery"
        indicators.append(
            _indicator(
                "url",
                safe["sanitized"],
                role,
                "confirmed_in_clipboard_command",
                item.source,
            )
        )
    for redirect in summary["redirects"]:
        indicators.append(
            _indicator(
                "url",
                redirect,
                "context_only_live_redirect",
                "observed_at_analysis_time",
                "限定ライブ観測",
            )
        )
    for payload in summary["binary_payloads_observed"]:
        if payload.get("sha256") and not payload.get("truncated"):
            indicators.append(
                _indicator(
                    "sha256",
                    str(payload["sha256"]),
                    "retrieved_payload",
                    "confirmed_in_memory_download",
                    "限定ライブ観測",
                )
            )
    deduplicated = {}
    for indicator in indicators:
        key = (
            indicator["type"],
            indicator["value"].lower(),
            indicator["role"],
        )
        deduplicated[key] = indicator
    return {
        "schema_version": 1,
        "case_id": item.case_id,
        "source": {
            "provider": item.source,
            "observed_at": item.observed_at,
        },
        "command_pattern": command["pattern"] if command else None,
        "indicators": list(deduplicated.values()),
    }


def _is_public_ioc(indicator: dict[str, str]) -> bool:
    lowered = f"{indicator.get('role')} {indicator.get('confidence')}".lower()
    return not any(marker in lowered for marker in ("context_only", "not_ioc", "not_c2", "dual-use"))


def render_ioc_list(iocs: dict[str, Any]) -> str:
    """共通generatorと同じ標準5列表のIOC-LIST.mdを生成する。"""

    lines = [
        "# IOC 一覧",
        "",
        "| 種別 (Type) | 値 (Value) | 役割 (Role) | 確度 (Confidence) | 根拠 (Source) |",
        "|---|---|---|---|---|",
    ]
    for item in iocs["indicators"]:
        if not _is_public_ioc(item):
            continue
        kind = {
            "domain": "ドメイン",
            "endpoint": "接続先",
            "ethereum_address": "Ethereumアドレス",
        }.get(item["type"], item["type"])
        lines.append(f"| {kind} | {item['value']} | {item['role']} | {item['confidence']} | {item['source']} |")
    return "\n".join(lines)


def _sigma_uuid(case_id: str, suffix: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"ai-security-analysis:{case_id}:{suffix}"))


def _case_date(case_id: str) -> str:
    return f"{case_id[:4]}-{case_id[4:6]}-{case_id[6:8]}"


def sigma_documents(item: SelectedCase, command: dict[str, Any] | None) -> list[dict[str, Any]]:
    """case証跡に合わせたSigma候補を返す。"""

    documents: list[dict[str, Any]] = [
        {
            "title": f"ClickFix疑いのRunMRU登録 ({item.case_id})",
            "id": _sigma_uuid(item.case_id, "runmru"),
            "status": "experimental",
            "description": (
                "Run dialogへ貼り付けられたLOLBINとdownload/execute表現の組合せを検知する。"
                "ドメイン単独ではなくユーザー実行証跡を対象とする。"
            ),
            "author": "AI-security-analysis",
            "date": _case_date(item.case_id),
            "logsource": {"category": "registry_set", "product": "windows"},
            "detection": {
                "selection_key": {
                    "TargetObject|contains": ("\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU\\")
                },
                "selection_lolbin": {
                    "Details|contains": [
                        "powershell",
                        "pwsh",
                        "mshta",
                        "rundll32",
                        "conhost",
                        "net use",
                    ]
                },
                "selection_suspicious": {
                    "Details|contains": [
                        "iex",
                        "Invoke-Expression",
                        "irm ",
                        "iwr ",
                        "Invoke-RestMethod",
                        "Invoke-WebRequest",
                        "-w h",
                        "--headless",
                        "@SSL",
                        "/webdav",
                    ]
                },
                "condition": "selection_key and selection_lolbin and selection_suspicious",
            },
            "falsepositives": [
                "管理者がRun dialogから正規の保守scriptを実行した場合",
            ],
            "level": "high",
            "tags": [
                "attack.execution",
                "attack.t1059.001",
                "attack.t1204.004",
            ],
        }
    ]
    if command and command["pattern"] == "telegram_dead_drop_powershell":
        documents.append(
            {
                "title": f"Telegram dead-drop resolver経由のClickFix PowerShell ({item.case_id})",
                "id": _sigma_uuid(item.case_id, "telegram-ddr"),
                "status": "experimental",
                "description": (
                    "Telegram HTMLのdescriptionからhostを抽出し、/l.datを取得して実行するClickFix系列を検知する。"
                ),
                "author": "AI-security-analysis",
                "date": _case_date(item.case_id),
                "logsource": {"category": "process_creation", "product": "windows"},
                "detection": {
                    "selection_image": {"Image|endswith": ["\\powershell.exe", "\\pwsh.exe"]},
                    "selection_all": {
                        "CommandLine|contains|all": [
                            "_description",
                            "/l.dat",
                            "irm",
                        ]
                    },
                    "selection_execute": {
                        "CommandLine|contains": [
                            "iex",
                            "Invoke-Expression",
                            "voke-E",
                            "ke-Ex",
                        ]
                    },
                    "condition": "selection_image and selection_all and selection_execute",
                },
                "falsepositives": [
                    "Telegram HTMLを同じ抽出式で処理する管理script",
                ],
                "level": "high",
                "tags": [
                    "attack.execution",
                    "attack.t1059.001",
                    "attack.t1105",
                ],
            }
        )
    elif command and command["pattern"] == "webdav_rundll32":
        documents.append(
            {
                "title": f"headless conhostからWebDAV DLLをrundll32実行 ({item.case_id})",
                "id": _sigma_uuid(item.case_id, "webdav-rundll32"),
                "status": "experimental",
                "description": (
                    "ClickFixで観測されたconhost --headless、WebDAV UNC、rundll32 export呼出しの組合せを検知する。"
                ),
                "author": "AI-security-analysis",
                "date": _case_date(item.case_id),
                "logsource": {"category": "process_creation", "product": "windows"},
                "detection": {
                    "selection_image": {"Image|endswith": "\\conhost.exe"},
                    "selection_all": {
                        "CommandLine|contains|all": [
                            "--headless",
                            "@SSL",
                            "rundll32",
                            "pushd",
                        ]
                    },
                    "condition": "selection_image and selection_all",
                },
                "falsepositives": [
                    "WebDAV上の正規DLLを同一command構造で保守実行する場合",
                ],
                "level": "high",
                "tags": [
                    "attack.execution",
                    "attack.t1218.011",
                    "attack.t1105",
                ],
            }
        )
    elif command and command["pattern"] == "mapped_webdav_command":
        documents.append(
            {
                "title": f"ClickFix由来のWebDAVドライブ割当とcommand実行 ({item.case_id})",
                "id": _sigma_uuid(item.case_id, "mapped-webdav"),
                "status": "experimental",
                "description": (
                    "net useによるWebDAV割当、共有上のcommand script実行、"
                    "割当解除を同じcommand lineで行う系列を検知する。"
                ),
                "author": "AI-security-analysis",
                "date": _case_date(item.case_id),
                "logsource": {"category": "process_creation", "product": "windows"},
                "detection": {
                    "selection_image": {"Image|endswith": ["\\cmd.exe", "\\net.exe"]},
                    "selection_all": {
                        "CommandLine|contains|all": [
                            "net use",
                            "/webdav",
                            "update.cmd",
                            "/delete",
                        ]
                    },
                    "condition": "selection_image and selection_all",
                },
                "falsepositives": [
                    "同一形式でWebDAV上の正規更新scriptを実行する場合",
                ],
                "level": "high",
                "tags": [
                    "attack.execution",
                    "attack.t1059.003",
                    "attack.t1105",
                ],
            }
        )
    elif command and command["pattern"] == "powershell_download_execute":
        documents.append(
            {
                "title": f"ClickFix PowerShell download-and-execute ({item.case_id})",
                "id": _sigma_uuid(item.case_id, "powershell-download-execute"),
                "status": "experimental",
                "description": (
                    "非表示またはpolicy bypassのPowerShellがHTTP(S)取得と"
                    "メモリ内実行を同じcommand lineで行う系列を検知する。"
                ),
                "author": "AI-security-analysis",
                "date": _case_date(item.case_id),
                "logsource": {"category": "process_creation", "product": "windows"},
                "detection": {
                    "selection_image": {"Image|endswith": ["\\powershell.exe", "\\pwsh.exe"]},
                    "selection_fetch": {
                        "CommandLine|contains": [
                            "irm ",
                            "iwr ",
                            "Invoke-RestMethod",
                            "Invoke-WebRequest",
                            "DownloadString",
                        ]
                    },
                    "selection_execute": {
                        "CommandLine|contains": [
                            "iex",
                            "Invoke-Expression",
                        ]
                    },
                    "condition": "selection_image and selection_fetch and selection_execute",
                },
                "falsepositives": [
                    "管理者が署名・hash検証なしで実行する正規保守script",
                ],
                "level": "high",
                "tags": [
                    "attack.execution",
                    "attack.t1059.001",
                    "attack.t1105",
                ],
            }
        )
    return documents


def render_sigma(documents: list[dict[str, Any]]) -> str:
    return "---\n".join(
        yaml.safe_dump(
            document,
            allow_unicode=True,
            sort_keys=False,
            width=120,
        ).rstrip()
        + "\n"
        for document in documents
    )


def _mermaid_label(value: str) -> str:
    return value.replace('"', "'").replace("\n", " ")[:100]


def render_overall_logic(
    item: SelectedCase,
    summary: dict[str, Any],
    command: dict[str, Any] | None,
) -> str:
    command_label = command["summary"] if command else "実行commandは未取得"
    live_label = (
        f"HTTP応答を観測: {', '.join(map(str, summary['http_statuses']))}"
        if summary["reachable"]
        else "ライブHTTP応答は未確認"
    )
    clipboard_edge = "-->" if summary["clipboard_api_observed_live"] or item.raw_command else "-.未観測.->"
    command_edge = "-->" if command else "-.未観測.->"
    return f"""# 全体ロジック

## 実行フロー

```mermaid
flowchart LR
  E0["利用者がlanding pageへ到達"] --> E1["ClickFix / fake CAPTCHA lure"]
  E1 {clipboard_edge} E2["clipboardへcommandまたはURLを設定"]
  E2 {command_edge} E3["利用者がRun dialog / terminalで実行"]
  E3 {command_edge} E4["{_mermaid_label(command_label)}"]
  E4 -.未解決.-> E5["終端payload / malware"]
```

実線は情報源またはライブHTMLで確認した関係、点線はこのcaseで未観測の関係です。

## 感染チェーン

```mermaid
flowchart LR
  I0["配布・侵害domain: {item.domain}"] --> I1["landing page"]
  I1 {clipboard_edge} I2["clipboard操作"]
  I2 {command_edge} I3["Windows shell / LOLBIN"]
  I3 {command_edge} I4["追加stage取得先"]
  I4 -.未解決.-> I5["終端マルウェア"]
```

## モジュール関係

```mermaid
flowchart TD
  M0["Web landing / inject"] --> M1["lure UI"]
  M1 {clipboard_edge} M2["clipboard処理"]
  M2 {command_edge} M3["shell command"]
  M3 {command_edge} M4["downloader / resolver"]
  M4 -.未解決.-> M5["payload module"]
```

## 比較プロファイル

| 軸 | 本case |
|---|---|
| 配布文脈 | `{item.source}`で`{item.domain}`を観測 |
| lure | `{", ".join(item.tags)}` |
| clipboard | `{"observed" if summary["clipboard_api_observed_live"] or item.raw_command else "unverified"}` |
| command系列 | `{command["pattern"] if command else "unverified"}` |
| 終端payload | `{"取得あり" if summary["binary_payloads_observed"] else "未取得"}` |
| ライブ状態 | `{live_label}` |

## 他caseとの比較

同一domain、単一tag、単一IPだけではcampaign同一性を判定しません。command系列とstage構造の
2軸以上が一致した場合に限り、同一cluster候補として上位索引で扱います。
"""


def _format_processes(command: dict[str, Any] | None) -> str:
    if not command or not command["processes"]:
        return "未確認"
    return " → ".join(f"`{item}`" for item in command["processes"])


def render_case_readme(
    item: SelectedCase,
    summary: dict[str, Any],
    command: dict[str, Any] | None,
    iocs: dict[str, Any],
) -> str:
    live_status = (
        f"HTTP {', '.join(map(str, summary['http_statuses']))}を観測"
        if summary["reachable"]
        else "HTTP応答を確認できず"
    )
    command_summary = command["summary"] if command else "実行commandは未取得"
    stage_urls = [sanitize_url(value)["sanitized"] for value in extract_stage_urls(item.raw_command or "")]
    stage_lines = (
        "\n".join(f"- `{value}`" for value in stage_urls)
        if stage_urls
        else "- このcaseでは追加stage URLを復元できませんでした。"
    )
    address_lines = (
        "\n".join(
            f"- `{value}`（解析時DNS解決。共有基盤を含むためIOCから除外）" for value in summary["public_addresses"]
        )
        if summary["public_addresses"]
        else "- 解析時にpublic IPを解決できませんでした。"
    )
    payloads = summary["binary_payloads_observed"]
    payload_lines = (
        "\n".join(
            f"- `{payload['type']}` / SHA-256 `{payload['sha256']}` / {payload['bytes_observed']} bytes観測"
            for payload in payloads
        )
        if payloads
        else "- 終端binary payloadは取得できませんでした。"
    )
    source_command = (
        f"- pattern: `{command['pattern']}`\n"
        f"- コマンドSHA-256: `{command['command_sha256']}`\n"
        f"- 正規化説明: {command_summary}"
        if command
        else "- providerまたはライブ本文から実行commandを取得できませんでした。"
    )
    live_chain_notes = []
    if summary["webdav_multistatus_observed"]:
        live_chain_notes.append(
            "- GETに対してHTTP 207 Multi-Statusを観測しました。WebDAV互換endpointの"
            "可能性を支持しますが、ファイル一覧取得や変更系methodは送信していません。"
        )
    telegram_state = summary["telegram_resolver_state"]
    if telegram_state == "reachable_but_tokens_absent":
        live_chain_notes.append(
            "- Telegram dead-drop URLはHTTP 200でしたが、現在のdescriptionは一般的な"
            "group招待文で、元commandが要求する2トークンを返しませんでした。"
            "このため `/l.dat` のhostを現在は復元できず、感染チェーンはresolverで停止します。"
        )
    elif telegram_state == "next_stage_recovered":
        live_chain_notes.append("- Telegram descriptionから次段hostを復元できました。")
    elif telegram_state == "unreachable":
        live_chain_notes.append("- Telegram dead-drop URLへ接続を試みましたが、応答を取得できませんでした。")
    if not live_chain_notes:
        live_chain_notes.append("- ライブ本文から新たなclipboard commandまたは終端payloadは確認できませんでした。")
    live_chain_text = "\n".join(live_chain_notes)
    confidence = item.confidence if item.confidence is not None else "未提示"
    return f"""# ClickFixケース: {item.domain}

## 概要

- ケースID: `{item.case_id}`
- 観測日時: `{item.observed_at}`
- 解析日: `{item.case_id[:4]}-{item.case_id[4:6]}-{item.case_id[6:8]}`
- 情報源: [{item.source}]({item.source_url})
- 情報源タグ: `{", ".join(item.tags)}`
- 情報源の確度: `{confidence}`
- 情報源上のマルウェア表記: `{item.reported_malware}`
- ライブ確認: {live_status}

`ClearFake`または`ClickFix`は配布cluster／手法を示し、終端マルウェアのfamily名とは限りません。
本caseでは配布先、stage取得先、終端C2を役割別に分けています。

## 配布マルウェア

{payload_lines}

providerが`ClearFake`と記載している場合も、これはWeb inject／配布frameworkの識別です。
LummaStealer、NetSupport RAT等の終端familyを、このcaseの個別証跡なしに補完していません。

## 感染チェーン

1. 利用者が`{item.domain}`のlanding pageまたは侵害ページへ到達する。
2. fake CAPTCHA／verification等のClickFix lureが、clipboardへのcommand設定と手動実行を促す。
3. {command_summary}
4. 後続stageまたは終端payloadは、取得できた静的証跡だけを採用する。

### ライブ後段評価

{live_chain_text}

図は[全体ロジック](OVERALL-LOGIC.md)を参照してください。

## 実行されるプロセスとcommand

想定されるprocess chain: {_format_processes(command)}

{source_command}

生commandはquery、invite token等を含み得るため公開せず、hashと処理ロジックを残しました。

## 追加通信先

### commandから確認

{stage_lines}

### ライブ観測

{address_lines}

redirect、本文hash、HTTP statusは[live-observation.json](live-observation.json)に記録しています。
DNS・RDAP・証明書・ASN／netblock・portの調査は[インフラ調査](INFRASTRUCTURE.md)、
既存sandbox実行の照合は[Hatching Triage照合](TRIAGE.md)を参照してください。
TCP open、通常HTTP応答、DNS解決だけではC2と判定していません。

## Sigma

[case別Sigma候補](rules/sigma.yml)を参照してください。RunMRUとLOLBINの複合条件を使い、
domain単独の検知は行いません。

## IOC

[IOC一覧](IOC-LIST.md)と[構造化IOC](iocs.json)を参照してください。
公開IOC数は{sum(_is_public_ioc(indicator) for indicator in iocs["indicators"])}件です。

## 確度と制約

- provider報告とcommandは`confirmed_provider_report`、解析時のHTTP/DNSは`observed_at_analysis_time`です。
- JavaScriptを実行せず、GET本文を上限付きで取得して静的に確認しました。
- 検体、script、DLL、PEをローカル実行していません。
- geo-fence、bot対策、時限配信、1回限りのtokenにより、provider観測とライブ結果が異なる可能性があります。
- {item.note or "追加注記なし"}
"""


def render_features(
    item: SelectedCase,
    summary: dict[str, Any],
    command: dict[str, Any] | None,
) -> str:
    clipboard = "確認" if item.raw_command or summary["clipboard_api_observed_live"] else "未確認"
    webdav = "観測" if summary["webdav_multistatus_observed"] else "未観測"
    telegram = {
        "not_applicable": "対象外",
        "reachable_but_tokens_absent": "到達・次段token未復元",
        "next_stage_recovered": "次段復元",
        "unreachable": "到達せず",
    }.get(summary["telegram_resolver_state"], "未確認")
    return f"""# 挙動・検体特徴

| 種別 | 特徴 | 確度 |
|---|---|---|
| 配布手法 | ClickFix / fake verification | provider報告 |
| domain | `{item.domain}` | provider報告 |
| clipboard | `{clipboard}` | providerまたはライブHTML |
| command系列 | `{command["pattern"] if command else "未確認"}` | 静的command解析 |
| HTTP応答 | `{summary["http_statuses"]}` | 解析時ライブ観測 |
| WebDAV Multi-Status | `{webdav}` | GET応答 |
| Telegram resolver | `{telegram}` | 限定ライブ観測 |
| body形式 | `{summary["body_types"]}` | 解析時ライブ観測 |
| 終端binary | `{len(summary["binary_payloads_observed"])}`件 | 上限付きGET |

本ファイルは挙動と特徴だけを扱い、IOC値や検知条件の詳細は別成果物へ分離しています。
"""


def render_collection_readme(
    analysis_date: str,
    rendered: list[dict[str, Any]],
    manifest: dict[str, Any],
) -> str:
    by_source = Counter(item["source"] for item in rendered)
    patterns = Counter(item["command_pattern"] or "unverified" for item in rendered)
    reachable = sum(item["live"]["reachable"] for item in rendered)
    payloads = sum(len(item["live"]["binary_payloads_observed"]) for item in rendered)
    webdav = sum(item["live"]["webdav_multistatus_observed"] for item in rendered)
    telegram_stopped = sum(
        item["live"]["telegram_resolver_state"] == "reachable_but_tokens_absent" for item in rendered
    )
    source_rows = "\n".join(f"| {source}（情報源） | {count} |" for source, count in sorted(by_source.items()))
    pattern_rows = "\n".join(
        f"| `{pattern}` | {count} |"
        for pattern, count in sorted(patterns.items(), key=lambda pair: (-pair[1], pair[0]))
    )
    case_rows = "\n".join(
        f"| `{item['domain']}` | `{item['source']}` | "
        f"`{item['command_pattern'] or 'unverified'}` | "
        f"{'応答あり' if item['live']['reachable'] else '応答なし'} | "
        f"[case](../../{item['relative_path']}/README.md) |"
        for item in rendered
    )
    return f"""# ClickFix日次調査: {analysis_date}

## 結論

2026年7月30日時点の最新情報を最大50件へ正規化しました。ThreatFoxの本日観測を優先し、
明示指定の`tbhadvisors.com`とclickfix.proの最新行で補完しています。

- 解析対象: {len(rendered)}件
- ライブHTTP応答あり: {reachable}件
- 終端binaryを上限内で観測: {payloads}件
- HTTP 207 WebDAV Multi-Status観測: {webdav}件
- Telegram resolverで次段token未復元: {telegram_stopped}件
- JavaScript実行: 0件
- マルウェア実行: 0件

情報源の最新時刻と「本日観測」は別です。ClickFix Hunterとclickfix.proは取得時点で
7月29日以前が最新でしたが、ThreatFoxには{analysis_date}の新規IOCがありました。

## 情報源別

| 情報源 | 件数 |
|---|---:|
{source_rows}

## 観測した感染チェーン

```mermaid
flowchart LR
  A["侵害サイト / 配布domain"] --> B["fake CAPTCHA / verification lure"]
  B --> C["clipboardへcommand設定"]
  C --> D["利用者がRun dialog / terminalへ貼付"]
  D --> E["PowerShell / cmd / conhost"]
  E --> F["HTTP(S) / WebDAV / dead-drop resolver"]
  F -.case別に未解決.-> G["loader / stealer / RAT等の終端payload"]
```

ClickFixは手法であり、ClearFakeはWeb inject／配布clusterです。同じtagを持つだけで
終端malwareやactorを同一としません。

## command系列

| 系列 | 件数 |
|---|---:|
{pattern_rows}

## 検知の要点

- RunMRUへの`powershell`、`mshta`、`rundll32`、`conhost`等と、`irm`／`iwr`／`iex`、
  `--headless`、`@SSL`、`/webdav`等を相関する。
- `powershell.exe`単独、domain単独、IP単独では検知しない。
- WebDAV系列は`conhost --headless`、`pushd`、UNC `@SSL`、`rundll32` export呼出しを組み合わせる。
- Telegram等の正規サービスはdead-drop resolverとして文脈に残すが、サービス全体をIOCにしない。

各caseの`rules/sigma.yml`に、case証跡へ対応するSigma候補を保存しています。

## 対象一覧

| domain | 情報源 | command系列 | ライブ | 結果 |
|---|---|---|---|---|
{case_rows}

## OSINTによる背景

- [Microsoft: ClickFixの攻撃チェーンと検知]({BACKGROUND_SOURCES["microsoft"][1]})
- [Proofpoint: ClickFixの普及と配布マルウェア]({BACKGROUND_SOURCES["proofpoint"][1]})
- [Unit 42: ClickFixの防御・ハンティング]({BACKGROUND_SOURCES["unit42"][1]})
- [ClickFix Hunter]({SOURCE_URLS["clickfix_hunter"]})
- [ClickFix Campaign Monitor]({SOURCE_URLS["clickfix_pro"]})
- [ThreatFox clickfix]({SOURCE_URLS["threatfox_clickfix"]})
- [ThreatFox clearfake]({SOURCE_URLS["threatfox_clearfake"]})

## 制約

- ライブ確認はGET、最大{MAX_REDIRECTS}リダイレクト、landing {BASE_BODY_LIMIT} bytes、
  stage {STAGE_BODY_LIMIT} bytesに制限しました。
- JavaScript、clipboard操作、Windows command、取得物は実行していません。
- provider生応答と取得本文はGit管理外へ保存し、公開側には正規化結果だけを残しました。
- TLS証明書検証を無効にした限定観測を含むため、本文hashと時刻を証跡として併記しています。
- 収集ID: `{manifest["collection_id"]}`
"""


def render_root_readme(analysis_date: str, collection_id: str) -> str:
    return f"""# ClickFix調査

ClickFix、ClearFake、fake CAPTCHA、WebDAV型ClickFixのdomain／case別調査を保存します。
各caseは`<domain>/cases/<case-id>/`へ置き、配布マルウェア、感染チェーン、process／command、
追加通信先、Sigma、ライブ観測を分離します。

## 最新調査

- [{analysis_date} 日次調査](collections/{collection_id}/README.md)

## 運用原則

- 1回の解析対象は最大{DEFAULT_LIMIT}件です。
- 配布domain、stage取得先、dead-drop resolver、終端C2を区別します。
- ClearFake／ClickFix tagだけで終端malware、campaign、actorを確定しません。
- 実サイト確認は上限付きGETと静的本文解析を基本とし、取得したcommandやmalwareを実行しません。
- 配布マルウェアのhashまたはbinaryを取得した場合は、既存のcanonical malware caseへ別途登録します。
- ペイロード未取得でも、DNS・RDAP・CT・netblock・ASN・Shodan InternetDBによるインフラ調査を継続します。
- Triageの公開済み解析をdomain／取得済み完全URL／hashで照合し、process、command hash、通信、dump／memory／PCAP候補を確認します。
"""


def publish(
    repository: Path,
    analysis_date: str,
    cases: list[SelectedCase],
    observations: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """domain/case別成果物と日次collectionを生成する。"""

    root = repository / "analysis-results" / "clickfix"
    collection_id = f"clickfix-daily-{analysis_date.replace('-', '')}"
    rendered = []
    for item in cases:
        summary = observation_summary(observations[item.case_id])
        if item.raw_command:
            command = command_profile(item.raw_command)
        elif summary["candidate_commands_live"]:
            command = dict(summary["candidate_commands_live"][0])
        else:
            command = None
        iocs = build_iocs(item, summary, command)
        relative = Path("analysis-results") / "clickfix" / item.domain / "cases" / item.case_id
        case_root = repository / relative
        public_live = public_observation(observations[item.case_id])
        analysis = {
            "schema_version": 1,
            "case_id": item.case_id,
            "domain": item.domain,
            "observed_at": item.observed_at,
            "analysis_date": analysis_date,
            "source": {
                "name": item.source,
                "id": item.source_id,
                "url": item.source_url,
                "tags": list(item.tags),
                "reported_malware": item.reported_malware,
                "confidence": item.confidence,
            },
            "command": command,
            "live_summary": summary,
            "terminal_payload": {
                "status": ("binary_observed" if summary["binary_payloads_observed"] else "not_retrieved"),
                "family": None,
                "artifacts": summary["binary_payloads_observed"],
            },
            "attribution": {
                "clickfix_is_technique": True,
                "clearfake_is_distribution_cluster": (item.reported_malware.lower() == "clearfake"),
                "terminal_malware_inferred_from_tag": False,
                "actor": "unattributed",
            },
        }
        atomic_json(case_root / "analysis.json", analysis)
        atomic_json(case_root / "iocs.json", iocs)
        atomic_json(case_root / "live-observation.json", public_live)
        _write_text(
            case_root / "README.md",
            render_case_readme(item, summary, command, iocs),
        )
        _write_text(
            case_root / "FEATURES.md",
            render_features(item, summary, command),
        )
        _write_text(
            case_root / "OVERALL-LOGIC.md",
            render_overall_logic(item, summary, command),
        )
        _write_text(case_root / "IOC-LIST.md", render_ioc_list(iocs))
        _write_text(
            case_root / "rules" / "sigma.yml",
            render_sigma(sigma_documents(item, command)),
        )
        rendered.append(
            {
                "case_id": item.case_id,
                "domain": item.domain,
                "observed_at": item.observed_at,
                "source": item.source,
                "source_id": item.source_id,
                "relative_path": relative.relative_to(Path("analysis-results") / "clickfix").as_posix(),
                "command_pattern": command["pattern"] if command else None,
                "candidate_urls": [
                    sanitize_url(url)["sanitized"]
                    for url in extract_stage_urls(item.raw_command or "")
                    if sanitize_url(url)["host"] not in DUAL_USE_HOSTS
                ],
                "sha256_candidates": [
                    artifact["sha256"] for artifact in summary["binary_payloads_observed"] if artifact.get("sha256")
                ],
                "live": summary,
            }
        )
    manifest = {
        "schema_version": 1,
        "collection_id": collection_id,
        "analysis_date": analysis_date,
        "generated_at_utc": utc_now(),
        "selection": {
            "limit": len(cases),
            "maximum": DEFAULT_LIMIT,
            "policy": (
                "明示指定tbhadvisors.com、本日ThreatFox clickfix/clearfake、clickfix.pro最新行の順でdomain重複を除外"
            ),
        },
        "source_counts": dict(Counter(item.source for item in cases)),
        "case_count": len(cases),
        "cases": rendered,
    }
    collection_root = root / "collections" / collection_id
    atomic_json(collection_root / "manifest.json", manifest)
    _write_text(
        collection_root / "README.md",
        render_collection_readme(analysis_date, rendered, manifest),
    )
    _write_text(root / "README.md", render_root_readme(analysis_date, collection_id))
    return manifest


def build_parser() -> argparse.ArgumentParser:
    """CLI parserを構築する。"""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    parser.add_argument(
        "--analysis-date",
        default=datetime.now(timezone.utc).date().isoformat(),
    )
    parser.add_argument("--private-output", type=Path, required=True)
    parser.add_argument("--source-dir", type=Path)
    parser.add_argument("--collect-sources", action="store_true")
    parser.add_argument("--allow-live-probes", action="store_true")
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT)
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    return parser


def parse_arguments(argv: list[str] | None = None) -> argparse.Namespace:
    return build_parser().parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    arguments = parse_arguments(argv)
    analysis_date = (
        datetime.strptime(
            arguments.analysis_date,
            "%Y-%m-%d",
        )
        .date()
        .isoformat()
    )
    repository = arguments.repository.resolve()
    private_root = arguments.private_output.resolve() / analysis_date
    source_root = arguments.source_dir.resolve() if arguments.source_dir else private_root / "sources"
    if arguments.collect_sources:
        auth_key = os.environ.get("MALWAREBAZAAR_AUTH_KEY")
        if not auth_key:
            raise SystemExit("MALWAREBAZAAR_AUTH_KEYが必要です")
        collect_sources(
            source_root,
            auth_key=auth_key,
            timeout=max(arguments.timeout, 30.0),
        )
    paths = _source_paths(source_root)
    carson = parse_carson(paths["carson"], analysis_date)
    selected = select_cases(
        analysis_date=analysis_date,
        threatfox_clickfix=parse_threatfox(
            paths["threatfox_clickfix"],
            "clickfix",
            analysis_date,
        ),
        threatfox_clearfake=parse_threatfox(
            paths["threatfox_clearfake"],
            "clearfake",
            analysis_date,
        ),
        clickfix_pro=parse_clickfix_pro(paths["clickfix_pro"], analysis_date),
        carson=carson,
        limit=arguments.limit,
    )
    if len(selected) != arguments.limit:
        raise SystemExit(f"選定件数が不足しています: selected={len(selected)} requested={arguments.limit}")
    atomic_json(
        private_root / "selection.json",
        {
            "schema_version": 1,
            "analysis_date": analysis_date,
            "selected": [
                {
                    **item.__dict__,
                    "tags": list(item.tags),
                    "raw_command": item.raw_command,
                }
                for item in selected
            ],
        },
    )
    observations: dict[str, dict[str, Any]] = {}
    if arguments.allow_live_probes:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, arguments.workers)) as executor:
            futures = {
                executor.submit(
                    probe_case,
                    item,
                    timeout=arguments.timeout,
                    private_root=private_root,
                ): item
                for item in selected
            }
            for future in concurrent.futures.as_completed(futures):
                item = futures[future]
                observations[item.case_id] = future.result()
    else:
        for item in selected:
            path = private_root / "cases" / item.case_id / "private-observation.json"
            if not path.is_file():
                raise SystemExit("ライブ観測を省略する場合は既存private-observation.jsonが必要です: " + str(path))
            observations[item.case_id] = json.loads(path.read_text(encoding="utf-8"))
    manifest = None
    if arguments.write:
        manifest = publish(repository, analysis_date, selected, observations)
    summary = {
        "analysis_date": analysis_date,
        "selected": len(selected),
        "source_counts": dict(Counter(item.source for item in selected)),
        "live_reachable": sum(observation_summary(observations[item.case_id])["reachable"] for item in selected),
        "binary_payloads_observed": sum(
            len(observation_summary(observations[item.case_id])["binary_payloads_observed"]) for item in selected
        ),
        "write_performed": bool(arguments.write),
        "collection_id": manifest["collection_id"] if manifest else None,
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
