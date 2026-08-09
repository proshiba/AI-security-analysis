#!/usr/bin/env python3
"""検体取得とIOC補強に使う外部APIの小さな共通クライアント。

資格情報は各操作の実行時に環境変数からだけ読み込む。moduleのimportやclientの
生成だけでは資格情報を要求せず、外部通信も行わない。

セキュリティ注意: 取得対象はLIVE MALWAREである。検体archiveを自動展開・実行
せず、orchestrator上でdetonateしないこと。検体とmemory artifactはrepository外の
隔離領域で扱うこと。
"""

from __future__ import annotations

import base64
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import date
import hashlib
from io import BytesIO
import ipaddress
import json
import os
from pathlib import Path
import re
import threading
import time
from typing import Any
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile

__all__ = [
    "CredentialError",
    "ExternalServiceError",
    "HttpClient",
    "HttpResponse",
    "MalwareBazaarClient",
    "MaxMindClient",
    "RateLimitError",
    "RateLimiter",
    "TriageClient",
    "VirusTotalClient",
]

USER_AGENT = "AI-security-analysis/external-api-helpers/1"
MALWAREBAZAAR_API = "https://mb-api.abuse.ch/api/v1/"
VIRUSTOTAL_API = "https://www.virustotal.com/api/v3"
TRIAGE_API = "https://tria.ge/api/v0"
MAXMIND_WEB_API = "https://geoip.maxmind.com/geoip/v2.1"

DEFAULT_TIMEOUT_SECONDS = 30.0
DEFAULT_MAX_JSON_BYTES = 25 * 1024 * 1024
DEFAULT_MAX_SAMPLE_BYTES = 512 * 1024 * 1024
DEFAULT_MAX_ARTIFACT_BYTES = 64 * 1024 * 1024

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
FILE_HASH_RE = re.compile(r"^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$")
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}\.?$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?\.?$",
    re.IGNORECASE,
)
SAMPLE_ID_RE = re.compile(r"^\d{6}-[a-z0-9]{10}$")
TASK_ID_RE = re.compile(r"^behavioral\d+$")


class CredentialError(RuntimeError):
    """操作時に必要な環境変数がないことを、秘密値なしで示す。"""


class ExternalServiceError(RuntimeError):
    """秘密値や応答本文を含めない外部service error。"""

    def __init__(self, message: str, *, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class RateLimitError(ExternalServiceError):
    """設定した日次request上限へ達したことを示す。"""


@dataclass(frozen=True)
class HttpResponse:
    """上限内で取得したHTTP応答。"""

    status: int
    headers: Mapping[str, str]
    body: bytes

    def json(self) -> Any:
        """UTF-8 JSONをdecodeし、不正な応答を秘密値なしで拒否する。"""

        try:
            return json.loads(self.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ExternalServiceError("外部APIが有効なUTF-8 JSONを返しませんでした") from error


class RateLimiter:
    """request間隔と日次件数をprocess内で制限する簡易limiter。"""

    def __init__(
        self,
        requests_per_minute: int = 4,
        requests_per_day: int = 500,
        *,
        clock: Callable[[], float] = time.monotonic,
        day_provider: Callable[[], date] = date.today,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        if requests_per_minute <= 0 or requests_per_day <= 0:
            raise ValueError("rate limitは正の値が必要です")
        self.requests_per_minute = requests_per_minute
        self.requests_per_day = requests_per_day
        self._clock = clock
        self._day_provider = day_provider
        self._sleeper = sleeper
        self._day = day_provider()
        self._daily_count = 0
        self._next_allowed = 0.0
        self._lock = threading.Lock()

    def acquire(self) -> None:
        """必要なら待機し、1 request分の日次枠を確保する。"""

        with self._lock:
            current_day = self._day_provider()
            if current_day != self._day:
                self._day = current_day
                self._daily_count = 0
                self._next_allowed = 0.0
            if self._daily_count >= self.requests_per_day:
                raise RateLimitError("設定した外部APIの日次request上限へ達しました")
            now = self._clock()
            delay = max(0.0, self._next_allowed - now)
            if delay:
                self._sleeper(delay)
                now = self._clock()
            self._next_allowed = max(now, self._next_allowed) + 60.0 / self.requests_per_minute
            self._daily_count += 1


class HttpClient:
    """stdlibだけでtimeout、再試行、応答上限を適用するHTTP client。

    header、URL、応答本文をlogや例外へ出さないため、Authorization tokenなどの
    secretがdebug出力へ混入しない。
    """

    def __init__(
        self,
        *,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        attempts: int = 3,
        user_agent: str = USER_AGENT,
        opener: Any | None = None,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        if timeout <= 0 or not 1 <= attempts <= 8:
            raise ValueError("timeoutは正、attemptsは1から8の範囲が必要です")
        self.timeout = timeout
        self.attempts = attempts
        self.user_agent = user_agent
        self._opener = opener or urllib.request.build_opener()
        self._sleeper = sleeper

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        data: bytes | None = None,
        max_bytes: int = DEFAULT_MAX_JSON_BYTES,
        limiter: RateLimiter | None = None,
    ) -> HttpResponse:
        """HTTP要求を上限付きで実行し、429と一時的5xxだけを再試行する。"""

        if method.upper() not in {"GET", "POST"}:
            raise ValueError("HTTP methodはGETまたはPOSTだけを許可します")
        if max_bytes <= 0:
            raise ValueError("max_bytesは正の値が必要です")
        request_headers = {str(key): str(value) for key, value in (headers or {}).items()}
        if not any(key.casefold() == "user-agent" for key in request_headers):
            request_headers["User-Agent"] = self.user_agent
        retry_statuses = {429, 500, 502, 503, 504}
        for attempt in range(1, self.attempts + 1):
            if limiter is not None:
                limiter.acquire()
            request = urllib.request.Request(
                url,
                data=data,
                headers=request_headers,
                method=method.upper(),
            )
            try:
                with self._opener.open(request, timeout=self.timeout) as response:
                    body = response.read(max_bytes + 1)
                    if len(body) > max_bytes:
                        raise ExternalServiceError("外部API応答が設定したbyte上限を超えました")
                    raw_status = getattr(response, "status", None)
                    status = int(raw_status if raw_status is not None else response.getcode())
                    response_headers = {
                        str(key): str(value) for key, value in response.headers.items()
                    }
                    return HttpResponse(status=status, headers=response_headers, body=body)
            except urllib.error.HTTPError as error:
                if error.code not in retry_statuses or attempt == self.attempts:
                    raise ExternalServiceError(
                        f"外部APIがHTTP {error.code}を返しました", status=error.code
                    ) from None
                retry_after = error.headers.get("Retry-After") if error.headers else None
                delay = _retry_delay(attempt, retry_after)
                self._sleeper(delay)
            except urllib.error.URLError:
                if attempt == self.attempts:
                    raise ExternalServiceError("外部APIへのnetwork接続に失敗しました") from None
                self._sleeper(min(30.0, float(2 ** (attempt - 1))))
        raise ExternalServiceError("外部API要求の再試行回数を使い切りました")


class MalwareBazaarClient:
    """MalwareBazaarのmetadata照会と暗号化ZIP取得helper。

    セキュリティ注意: 取得物はLIVE MALWAREである。password ``infected`` の暗号化
    ZIPを自動展開・実行せず、orchestrator上でdetonateしないこと。
    ``MALWAREBAZAAR_AUTH_KEY``は操作時に環境変数からだけ読む。
    """

    def __init__(self, *, http: HttpClient | None = None) -> None:
        self.http = http or HttpClient(timeout=60.0, attempts=5)

    def query_by_hash(self, sha256: str) -> dict[str, Any] | None:
        """完全SHA-256に一致するmetadataを返し、該当なしは``None``にする。"""

        digest = _normalize_sha256(sha256)
        rows = self._query({"query": "get_info", "hash": digest}, "hash", digest)
        return rows[0] if rows else None

    def query_by_tag(self, tag: str, *, limit: int = 100) -> list[dict[str, Any]]:
        """tagに一致するmetadataを最大``limit``件返す。"""

        value = _bounded_text(tag, "tag")
        return self._query(
            {"query": "get_taginfo", "tag": value, "limit": str(_query_limit(limit))},
            "tag",
            value,
        )

    def query_by_signature(
        self, signature: str, *, limit: int = 100
    ) -> list[dict[str, Any]]:
        """MalwareBazaar signatureに一致するmetadataを返す。"""

        value = _bounded_text(signature, "signature")
        return self._query(
            {
                "query": "get_siginfo",
                "signature": value,
                "limit": str(_query_limit(limit)),
            },
            "signature",
            value,
        )

    def query_by_family(self, family: str, *, limit: int = 100) -> list[dict[str, Any]]:
        """family名をMalwareBazaar signatureとして照会し、照会種別を保持する。"""

        value = _bounded_text(family, "family")
        rows = self._query(
            {
                "query": "get_siginfo",
                "signature": value,
                "limit": str(_query_limit(limit)),
            },
            "family",
            value,
        )
        return rows

    def download_sample(
        self,
        sha256: str,
        output_path: Path | None = None,
        *,
        downloads_dir: Path | None = None,
    ) -> dict[str, Any]:
        """検体をpassword保護済みZIPのまま保存し、展開せず転送情報を返す。"""

        digest = _normalize_sha256(sha256)
        auth_key = _require_environment("MALWAREBAZAAR_AUTH_KEY")
        response = self.http.request(
            "POST",
            MALWAREBAZAAR_API,
            headers={
                "Auth-Key": auth_key,
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/zip, application/json",
            },
            data=urllib.parse.urlencode(
                {"query": "get_file", "sha256_hash": digest}
            ).encode("ascii"),
            max_bytes=DEFAULT_MAX_SAMPLE_BYTES,
        )
        if response.body.startswith(b"{"):
            payload = _json_mapping(response)
            raise ExternalServiceError(
                "MalwareBazaar検体取得に失敗しました: "
                + str(payload.get("query_status") or "unknown_status")
            )
        _require_encrypted_zip(response.body, "MalwareBazaar")
        destination = _download_destination(
            output_path,
            downloads_dir,
            default_subdirectory="malwarebazaar",
            filename=f"{digest}.zip",
        )
        _write_new_file(destination, response.body)
        return {
            "source": "malwarebazaar",
            "sample_sha256": digest,
            "archive_path": str(destination),
            "archive_sha256": hashlib.sha256(response.body).hexdigest(),
            "archive_size": len(response.body),
            "archive_password": "infected",
            "archive_encrypted": True,
            "archive_extracted": False,
            "sample_executed": False,
        }

    def _query(
        self, fields: Mapping[str, str], query_kind: str, query_value: str
    ) -> list[dict[str, Any]]:
        auth_key = _require_environment("MALWAREBAZAAR_AUTH_KEY")
        response = self.http.request(
            "POST",
            MALWAREBAZAAR_API,
            headers={
                "Auth-Key": auth_key,
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            },
            data=urllib.parse.urlencode(fields).encode("utf-8"),
        )
        payload = _json_mapping(response)
        status = str(payload.get("query_status") or "")
        if status in {"hash_not_found", "no_results"}:
            return []
        if status != "ok":
            raise ExternalServiceError(f"MalwareBazaar照会に失敗しました: {status or 'unknown'}")
        data = payload.get("data")
        if not isinstance(data, list):
            return []
        return [
            _normalize_malwarebazaar(row, query_kind, query_value)
            for row in data
            if isinstance(row, dict)
        ]


class MaxMindClient:
    """local GeoLite2 MMDB優先のIP Geo/ASN補強helper。

    セキュリティ注意: IOCは検体由来でも対象hostへ接続しない。取得済みLIVE
    MALWAREを展開・実行せず、orchestrator上でdetonateしないこと。web serviceを
    明示した場合だけ``MAXMIND_LICENSE_KEY``を環境変数から読む。
    """

    def __init__(
        self,
        city_db_path: Path | None = None,
        asn_db_path: Path | None = None,
        *,
        http: HttpClient | None = None,
    ) -> None:
        self.city_db_path = Path(city_db_path) if city_db_path is not None else None
        self.asn_db_path = Path(asn_db_path) if asn_db_path is not None else None
        self.http = http or HttpClient()

    def enrich_ip(self, ip_address: str, *, use_web_service: bool = False) -> dict[str, Any]:
        """IPをcountry、city、ASN、organizationの共通dictへ正規化する。"""

        normalized_ip = str(ipaddress.ip_address(ip_address.strip()))
        if not use_web_service and self.city_db_path and self.asn_db_path:
            return self._offline_lookup(normalized_ip)
        if not use_web_service:
            raise ValueError(
                "offline照合にはGeoLite2-City.mmdbとGeoLite2-ASN.mmdbの両pathが必要です"
            )
        return self._web_lookup(normalized_ip)

    def _offline_lookup(self, ip_address: str) -> dict[str, Any]:
        assert self.city_db_path is not None and self.asn_db_path is not None
        if not self.city_db_path.is_file() or not self.asn_db_path.is_file():
            raise FileNotFoundError("指定したGeoLite2 MMDBが見つかりません")
        try:
            import maxminddb
        except ImportError as error:
            raise RuntimeError(
                "offline MaxMind照合にはrequirements-maxmind.txtのmaxminddbが必要です"
            ) from error
        with maxminddb.open_database(str(self.city_db_path)) as city_reader:
            city_record = city_reader.get(ip_address) or {}
        with maxminddb.open_database(str(self.asn_db_path)) as asn_reader:
            asn_record = asn_reader.get(ip_address) or {}
        return _normalize_maxmind(ip_address, city_record, asn_record, "GeoLite2 local MMDB")

    def _web_lookup(self, ip_address: str) -> dict[str, Any]:
        account_id = _require_environment("MAXMIND_ACCOUNT_ID")
        license_key = _require_environment("MAXMIND_LICENSE_KEY")
        token = base64.b64encode(f"{account_id}:{license_key}".encode("utf-8")).decode("ascii")
        response = self.http.request(
            "GET",
            f"{MAXMIND_WEB_API}/city/{urllib.parse.quote(ip_address, safe=':.')}",
            headers={"Authorization": f"Basic {token}", "Accept": "application/json"},
        )
        payload = _json_mapping(response)
        return _normalize_maxmind(ip_address, payload, payload.get("traits") or {}, "GeoIP2 web service")


class VirusTotalClient:
    """VirusTotal v3のfile hash、IP、domain、behavior補強helper。

    セキュリティ注意: APIは既存情報だけを参照し、LIVE MALWAREをupload・実行せず、
    orchestrator上でdetonateしないこと。``VT_API_KEY``は各操作時に環境変数から
    だけ読む。既定limiterはpublic APIの4 request/分、500 request/日である。
    """

    def __init__(
        self,
        *,
        http: HttpClient | None = None,
        limiter: RateLimiter | None = None,
    ) -> None:
        self.http = http or HttpClient(attempts=4)
        self.limiter = limiter or RateLimiter(4, 500)

    def enrich_file_hash(self, file_hash: str) -> dict[str, Any]:
        """MD5、SHA-1、SHA-256のいずれかをVirusTotal file情報で補強する。"""

        digest = _normalize_file_hash(file_hash)
        item = self._get_object(f"files/{digest}")
        attributes = item.get("attributes") if isinstance(item.get("attributes"), dict) else {}
        return {
            "source": "virustotal",
            "type": "file",
            "id": item.get("id") or digest,
            "hashes": {
                key: attributes.get(key)
                for key in ("md5", "sha1", "sha256")
                if attributes.get(key)
            },
            "meaningful_name": attributes.get("meaningful_name"),
            "names": sorted({str(value) for value in attributes.get("names") or []})[:50],
            "size": attributes.get("size"),
            "file_type": attributes.get("type_description"),
            "tags": sorted({str(value) for value in attributes.get("tags") or []}),
            "reputation": attributes.get("reputation"),
            "last_analysis_stats": _analysis_stats(attributes),
            "first_submission_date": attributes.get("first_submission_date"),
            "last_analysis_date": attributes.get("last_analysis_date"),
        }

    def enrich_ip(self, ip_address: str) -> dict[str, Any]:
        """IP addressのVirusTotal reputationと帰属情報を正規化する。"""

        value = str(ipaddress.ip_address(ip_address.strip()))
        item = self._get_object(f"ip_addresses/{value}")
        attributes = item.get("attributes") if isinstance(item.get("attributes"), dict) else {}
        return {
            "source": "virustotal",
            "type": "ip_address",
            "id": item.get("id") or value,
            "country": attributes.get("country"),
            "asn": attributes.get("asn"),
            "organization": attributes.get("as_owner"),
            "network": attributes.get("network"),
            "reputation": attributes.get("reputation"),
            "tags": sorted({str(tag) for tag in attributes.get("tags") or []}),
            "last_analysis_stats": _analysis_stats(attributes),
        }

    def enrich_domain(self, domain: str) -> dict[str, Any]:
        """domainのVirusTotal reputation、登録情報、直近解決先を正規化する。"""

        value = _normalize_domain(domain)
        item = self._get_object(f"domains/{value}")
        attributes = item.get("attributes") if isinstance(item.get("attributes"), dict) else {}
        resolutions = []
        for row in attributes.get("last_dns_records") or []:
            if isinstance(row, dict):
                resolutions.append(
                    {"type": row.get("type"), "value": row.get("value"), "ttl": row.get("ttl")}
                )
        return {
            "source": "virustotal",
            "type": "domain",
            "id": item.get("id") or value,
            "registrar": attributes.get("registrar"),
            "creation_date": attributes.get("creation_date"),
            "last_update_date": attributes.get("last_update_date"),
            "reputation": attributes.get("reputation"),
            "categories": dict(attributes.get("categories") or {}),
            "tags": sorted({str(tag) for tag in attributes.get("tags") or []}),
            "last_analysis_stats": _analysis_stats(attributes),
            "last_dns_records": resolutions[:50],
        }

    def fetch_behavior_reports(self, file_hash: str) -> dict[str, Any]:
        """hashに紐づくsandbox behaviorをprocess名と通信contextへ要約する。"""

        digest = _normalize_file_hash(file_hash)
        payload = self._get(f"files/{digest}/behaviours")
        reports = payload.get("data") if isinstance(payload.get("data"), list) else []
        sandboxes: list[dict[str, Any]] = []
        domains: set[str] = set()
        ips: set[str] = set()
        processes: set[str] = set()
        verdicts: set[str] = set()
        for report in reports:
            if not isinstance(report, dict):
                continue
            attributes = report.get("attributes") if isinstance(report.get("attributes"), dict) else {}
            verdict = attributes.get("verdict") or attributes.get("malware_classification")
            if verdict:
                verdicts.add(str(verdict))
            for key in ("contacted_domains", "dns_lookups"):
                for entry in attributes.get(key) or []:
                    value = entry.get("hostname") if isinstance(entry, dict) else entry
                    if value:
                        domains.add(str(value).lower())
            for key in ("contacted_ips", "ip_traffic"):
                for entry in attributes.get(key) or []:
                    value = entry.get("destination_ip") if isinstance(entry, dict) else entry
                    if value:
                        ips.add(str(value))
            for process in attributes.get("processes_tree") or []:
                if isinstance(process, dict) and process.get("name"):
                    processes.add(str(process["name"]))
            sandboxes.append(
                {
                    "id": report.get("id"),
                    "sandbox_name": attributes.get("sandbox_name"),
                    "verdict": verdict,
                }
            )
        return {
            "source": "virustotal",
            "type": "file_behaviors",
            "file_hash": digest,
            "report_count": len(sandboxes),
            "sandboxes": sandboxes,
            "verdicts": sorted(verdicts),
            "process_names": sorted(processes),
            "contacted_domains": sorted(domains),
            "contacted_ips": sorted(ips),
            "network_context_only": True,
        }

    def _get_object(self, path: str) -> dict[str, Any]:
        payload = self._get(path)
        item = payload.get("data")
        if not isinstance(item, dict):
            raise ExternalServiceError("VirusTotal応答にdata objectがありません")
        return item

    def _get(self, path: str) -> dict[str, Any]:
        api_key = _require_environment("VT_API_KEY")
        response = self.http.request(
            "GET",
            f"{VIRUSTOTAL_API}/{path.lstrip('/')}",
            headers={"x-apikey": api_key, "Accept": "application/json"},
            limiter=self.limiter,
        )
        return _json_mapping(response)


class TriageClient:
    """Hatching Triageの検体、analysis、report、memory artifact helper。

    セキュリティ注意: 検体とmemory dumpはLIVE MALWARE相当として扱う。downloadを
    自動展開・実行せず、orchestrator上でdetonateしないこと。新規submitは承認済み
    sandbox workflowだけで使う。``TRIAGE_API_KEY``は操作時に環境変数からだけ読む。
    """

    def __init__(
        self,
        *,
        http: HttpClient | None = None,
        sleeper: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.http = http or HttpClient(timeout=60.0, attempts=4)
        self._sleeper = sleeper
        self._clock = clock

    def fetch_sample(
        self,
        sample_id: str,
        output_path: Path | None = None,
        *,
        downloads_dir: Path | None = None,
    ) -> dict[str, Any]:
        """Triage検体をserver提供の暗号化ZIPのまま保存し、自動展開しない。"""

        identifier = _normalize_sample_id(sample_id)
        response = self._request(
            "GET",
            f"/samples/{identifier}/sample",
            accept="application/zip, application/octet-stream",
            max_bytes=DEFAULT_MAX_SAMPLE_BYTES,
        )
        _require_encrypted_zip(response.body, "Hatching Triage")
        destination = _download_destination(
            output_path,
            downloads_dir,
            default_subdirectory="triage",
            filename=f"{identifier}.zip",
        )
        _write_new_file(destination, response.body)
        return {
            "source": "hatching_triage",
            "sample_id": identifier,
            "archive_path": str(destination),
            "archive_sha256": hashlib.sha256(response.body).hexdigest(),
            "archive_size": len(response.body),
            "archive_encrypted": True,
            "archive_extracted": False,
            "sample_executed_locally": False,
        }

    def submit_sample(
        self,
        sample_path: Path,
        *,
        profiles: Sequence[str] = (),
        tags: Sequence[str] = (),
        timeout_seconds: int | None = None,
    ) -> dict[str, Any]:
        """明示した検体をTriageへsubmitし、orchestratorでは実行しない。"""

        path = Path(sample_path)
        if not path.is_file() or path.is_symlink():
            raise ValueError("submit対象はsymlinkでない通常fileが必要です")
        size = path.stat().st_size
        if not 1 <= size <= DEFAULT_MAX_SAMPLE_BYTES:
            raise ValueError("submit対象sizeは1 byteから512 MiBの範囲が必要です")
        profile_values = [_bounded_text(value, "profile") for value in profiles]
        tag_values = [_bounded_text(value, "tag") for value in tags]
        if timeout_seconds is not None and not 1 <= timeout_seconds <= 3600:
            raise ValueError("Triage timeoutは1から3600秒の範囲が必要です")
        sample = path.read_bytes()
        fields: list[tuple[str, str]] = []
        fields.extend(("profiles[]", value) for value in profile_values)
        fields.extend(("tags[]", value) for value in tag_values)
        if timeout_seconds is not None:
            fields.append(("timeout", str(timeout_seconds)))
        body, content_type = _multipart_body(fields, path.name, sample)
        response = self._request(
            "POST",
            "/samples",
            accept="application/json",
            content_type=content_type,
            data=body,
        )
        payload = _json_mapping(response)
        sample_record = payload.get("sample") if isinstance(payload.get("sample"), dict) else {}
        identifier = str(payload.get("id") or sample_record.get("id") or "")
        if not SAMPLE_ID_RE.fullmatch(identifier):
            raise ExternalServiceError("Triage submit応答に有効なsample IDがありません")
        return {
            "source": "hatching_triage",
            "sample_id": identifier,
            "status": payload.get("status") or "submitted",
            "submitted_sha256": hashlib.sha256(sample).hexdigest(),
            "submitted_size": size,
            "sample_executed_locally": False,
        }

    def get_analysis_status(self, sample_id: str) -> dict[str, Any]:
        """Triage sample metadataからanalysis statusを返す。"""

        identifier = _normalize_sample_id(sample_id)
        payload = _json_mapping(self._request("GET", f"/samples/{identifier}"))
        task_states: dict[str, str] = {}
        tasks = payload.get("tasks")
        if isinstance(tasks, dict):
            for task_id, task in tasks.items():
                if isinstance(task, dict) and task.get("status"):
                    task_states[str(task_id)] = str(task["status"])
        return {
            "source": "hatching_triage",
            "sample_id": identifier,
            "status": payload.get("status") or payload.get("state") or "unknown",
            "task_states": task_states,
        }

    def poll_analysis_status(
        self,
        sample_id: str,
        *,
        interval_seconds: float = 15.0,
        timeout_seconds: float = 900.0,
    ) -> dict[str, Any]:
        """analysisがterminal statusになるまで上限時間内でpollする。"""

        if interval_seconds <= 0 or timeout_seconds <= 0:
            raise ValueError("poll intervalとtimeoutは正の値が必要です")
        deadline = self._clock() + timeout_seconds
        terminal = {"completed", "reported", "failed", "error", "canceled", "cancelled"}
        while True:
            status = self.get_analysis_status(sample_id)
            if str(status["status"]).casefold() in terminal:
                return status
            if self._clock() >= deadline:
                raise TimeoutError("Triage analysis statusのpollがtimeoutしました")
            self._sleeper(min(interval_seconds, max(0.0, deadline - self._clock())))

    def retrieve_behavioral_report(
        self, sample_id: str, task_id: str | None = None
    ) -> dict[str, Any]:
        """Triage behavioral reportをraw commandを除いた共通形式へ要約する。"""

        identifier = _normalize_sample_id(sample_id)
        selected_task = _normalize_task_id(task_id) if task_id else None
        if selected_task is None:
            overview = _json_mapping(
                self._request("GET", f"/samples/{identifier}/overview.json")
            )
            selected_task = _first_reported_task(overview, identifier)
            if selected_task is None:
                raise ExternalServiceError("reported状態のTriage behavioral taskがありません")
        report = _json_mapping(
            self._request(
                "GET", f"/samples/{identifier}/{selected_task}/report_triage.json"
            )
        )
        return _normalize_triage_report(identifier, selected_task, report)

    def list_memory_dump_artifacts(self, sample_id: str) -> list[dict[str, Any]]:
        """overviewから取得可能なmemory artifact候補だけを列挙する。"""

        identifier = _normalize_sample_id(sample_id)
        overview = _json_mapping(
            self._request("GET", f"/samples/{identifier}/overview.json")
        )
        artifacts: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        for extracted in overview.get("extracted") or []:
            if not isinstance(extracted, dict):
                continue
            resource = str(extracted.get("resource") or "").replace("\\", "/")
            match = re.fullmatch(r"(behavioral\d+)/memory/([^/]+)", resource)
            if match:
                task, name = match.groups()
                safe_name = _safe_filename(name)
                marker = (task, safe_name)
                if marker not in seen:
                    seen.add(marker)
                    artifacts.append(
                        {"task_id": task, "name": safe_name, "kind": "memory_dump"}
                    )
            dumped = str(extracted.get("dumped_file") or "").replace("\\", "/")
            tasks = [
                _task_from_overview(str(value), identifier)
                for value in extracted.get("tasks") or []
            ]
            tasks = [value for value in tasks if value]
            if dumped.lower().startswith("memory/") and tasks:
                safe_name = _safe_filename(dumped.rsplit("/", 1)[-1])
                marker = (tasks[0], safe_name)
                if marker not in seen:
                    seen.add(marker)
                    artifacts.append(
                        {"task_id": tasks[0], "name": safe_name, "kind": "memory_dump"}
                    )
        return artifacts

    def retrieve_memory_dump(
        self,
        sample_id: str,
        task_id: str,
        artifact_name: str,
        output_path: Path,
        *,
        max_bytes: int = DEFAULT_MAX_ARTIFACT_BYTES,
    ) -> dict[str, Any]:
        """指定memory dumpを不透明なartifactとして保存し、解析・実行しない。"""

        identifier = _normalize_sample_id(sample_id)
        task = _normalize_task_id(task_id)
        name = _safe_filename(artifact_name)
        if not 1 <= max_bytes <= DEFAULT_MAX_ARTIFACT_BYTES:
            raise ValueError("memory dump上限は1 byteから64 MiBの範囲が必要です")
        response = self._request(
            "GET",
            f"/samples/{identifier}/{task}/memory/{urllib.parse.quote(name, safe='')}",
            accept="application/octet-stream",
            max_bytes=max_bytes,
        )
        destination = Path(output_path)
        _write_new_file(destination, response.body)
        return {
            "source": "hatching_triage",
            "sample_id": identifier,
            "task_id": task,
            "artifact_name": name,
            "artifact_path": str(destination),
            "artifact_sha256": hashlib.sha256(response.body).hexdigest(),
            "artifact_size": len(response.body),
            "artifact_extracted": False,
            "artifact_executed": False,
        }

    def _request(
        self,
        method: str,
        path: str,
        *,
        accept: str = "application/json",
        content_type: str | None = None,
        data: bytes | None = None,
        max_bytes: int = DEFAULT_MAX_JSON_BYTES,
    ) -> HttpResponse:
        api_key = _require_environment("TRIAGE_API_KEY")
        if not path.startswith("/") or ".." in path:
            raise ValueError("許可されていないTriage API pathです")
        headers = {"Authorization": f"Bearer {api_key}", "Accept": accept}
        if content_type:
            headers["Content-Type"] = content_type
        return self.http.request(
            method,
            TRIAGE_API + path,
            headers=headers,
            data=data,
            max_bytes=max_bytes,
        )


def _retry_delay(attempt: int, retry_after: str | None) -> float:
    if retry_after:
        try:
            return min(120.0, max(0.0, float(retry_after)))
        except ValueError:
            pass
    return min(30.0, float(2 ** (attempt - 1)))


def _require_environment(name: str) -> str:
    value = os.environ.get(name, "")
    if not value.strip():
        raise CredentialError(f"{name}環境変数が必要です")
    return value.strip()


def _normalize_sha256(value: str) -> str:
    normalized = str(value).strip().lower()
    if not SHA256_RE.fullmatch(normalized):
        raise ValueError("有効なSHA-256が必要です")
    return normalized


def _normalize_file_hash(value: str) -> str:
    normalized = str(value).strip().lower()
    if not FILE_HASH_RE.fullmatch(normalized):
        raise ValueError("有効なMD5、SHA-1、SHA-256のいずれかが必要です")
    return normalized


def _normalize_domain(value: str) -> str:
    normalized = str(value).strip().lower().rstrip(".")
    if not DOMAIN_RE.fullmatch(normalized):
        raise ValueError("有効なdomainが必要です")
    return normalized


def _normalize_sample_id(value: str) -> str:
    normalized = str(value).strip().lower()
    if not SAMPLE_ID_RE.fullmatch(normalized):
        raise ValueError("有効なTriage sample IDが必要です")
    return normalized


def _normalize_task_id(value: str) -> str:
    normalized = str(value).strip().lower()
    if not TASK_ID_RE.fullmatch(normalized):
        raise ValueError("有効なTriage behavioral task IDが必要です")
    return normalized


def _bounded_text(value: str, label: str) -> str:
    normalized = str(value).strip()
    if not normalized or len(normalized) > 200 or any(ord(character) < 32 for character in normalized):
        raise ValueError(f"{label}は1から200文字の安全な値が必要です")
    return normalized


def _query_limit(limit: int) -> int:
    if not 1 <= limit <= 100:
        raise ValueError("query limitは1から100の範囲が必要です")
    return limit


def _json_mapping(response: HttpResponse) -> dict[str, Any]:
    value = response.json()
    if not isinstance(value, dict):
        raise ExternalServiceError("外部API JSONのrootがobjectではありません")
    return value


def _normalize_malwarebazaar(
    row: Mapping[str, Any], query_kind: str, query_value: str
) -> dict[str, Any]:
    tags = row.get("tags") if isinstance(row.get("tags"), list) else []
    return {
        "source": "malwarebazaar",
        "query_kind": query_kind,
        "query_value": query_value,
        "sha256": row.get("sha256_hash"),
        "sha1": row.get("sha1_hash"),
        "md5": row.get("md5_hash"),
        "first_seen": row.get("first_seen"),
        "last_seen": row.get("last_seen"),
        "file_name": row.get("file_name"),
        "file_size": row.get("file_size"),
        "file_type": row.get("file_type"),
        "mime_type": row.get("file_type_mime"),
        "signature": row.get("signature"),
        "tags": sorted({str(tag) for tag in tags}),
    }


def _download_destination(
    output_path: Path | None,
    downloads_dir: Path | None,
    *,
    default_subdirectory: str,
    filename: str,
) -> Path:
    if output_path is not None:
        return Path(output_path)
    if downloads_dir is not None:
        root = Path(downloads_dir)
    else:
        configured = os.environ.get("MALWARE_LAB_DOWNLOADS_DIR", "").strip()
        root = Path(configured) if configured else Path.cwd() / "downloads"
    return root / default_subdirectory / filename


def _write_new_file(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() or path.is_symlink():
        raise FileExistsError(f"既存のdownload先は上書きしません: {path}")
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.part")
    try:
        with temporary.open("xb") as handle:
            handle.write(data)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def _require_encrypted_zip(data: bytes, source: str) -> None:
    try:
        with zipfile.ZipFile(BytesIO(data)) as archive:
            files = [item for item in archive.infolist() if not item.is_dir()]
            if not files or any(not (item.flag_bits & 0x1) for item in files):
                raise ExternalServiceError(f"{source}応答は暗号化ZIPではありません")
    except (zipfile.BadZipFile, OSError) as error:
        raise ExternalServiceError(f"{source}応答は有効なZIPではありません") from error


def _localized_name(record: Any) -> str | None:
    if not isinstance(record, dict) or not isinstance(record.get("names"), dict):
        return None
    return record["names"].get("ja") or record["names"].get("en")


def _normalize_maxmind(
    ip_address: str,
    city_record: Mapping[str, Any],
    asn_record: Mapping[str, Any],
    source: str,
) -> dict[str, Any]:
    country = city_record.get("country") if isinstance(city_record.get("country"), dict) else {}
    city = city_record.get("city") if isinstance(city_record.get("city"), dict) else {}
    location = city_record.get("location") if isinstance(city_record.get("location"), dict) else {}
    subdivisions = city_record.get("subdivisions") if isinstance(city_record.get("subdivisions"), list) else []
    subdivision = subdivisions[0] if subdivisions and isinstance(subdivisions[0], dict) else {}
    traits = city_record.get("traits") if isinstance(city_record.get("traits"), dict) else {}
    return {
        "source": source,
        "ip": ip_address,
        "country_code": country.get("iso_code"),
        "country": _localized_name(country),
        "subdivision": _localized_name(subdivision),
        "city": _localized_name(city),
        "latitude": location.get("latitude"),
        "longitude": location.get("longitude"),
        "accuracy_radius_km": location.get("accuracy_radius"),
        "asn": asn_record.get("autonomous_system_number") or traits.get("autonomous_system_number"),
        "organization": asn_record.get("autonomous_system_organization")
        or traits.get("autonomous_system_organization")
        or traits.get("organization"),
        "matched": bool(city_record or asn_record),
    }


def _analysis_stats(attributes: Mapping[str, Any]) -> dict[str, int]:
    stats = attributes.get("last_analysis_stats")
    if not isinstance(stats, dict):
        return {}
    return {str(key): int(value) for key, value in stats.items() if isinstance(value, int)}


def _safe_filename(value: str) -> str:
    normalized = str(value).replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
    if (
        not normalized
        or normalized in {".", ".."}
        or len(normalized) > 240
        or any(ord(character) < 32 for character in normalized)
    ):
        raise ValueError("安全なartifact名が必要です")
    return normalized


def _multipart_body(
    fields: Sequence[tuple[str, str]], filename: str, sample: bytes
) -> tuple[bytes, str]:
    boundary = f"asa-{uuid.uuid4().hex}"
    chunks: list[bytes] = []
    for name, value in fields:
        chunks.extend(
            [
                f"--{boundary}\r\n".encode("ascii"),
                f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode("ascii"),
                value.encode("utf-8"),
                b"\r\n",
            ]
        )
    safe_name = _safe_filename(filename).replace('"', "_")
    chunks.extend(
        [
            f"--{boundary}\r\n".encode("ascii"),
            f'Content-Disposition: form-data; name="file"; filename="{safe_name}"\r\n'.encode(
                "utf-8"
            ),
            b"Content-Type: application/octet-stream\r\n\r\n",
            sample,
            b"\r\n",
            f"--{boundary}--\r\n".encode("ascii"),
        ]
    )
    return b"".join(chunks), f"multipart/form-data; boundary={boundary}"


def _task_from_overview(value: str, sample_id: str) -> str | None:
    normalized = value
    if normalized.startswith(sample_id + "-"):
        normalized = normalized[len(sample_id) + 1 :]
    return normalized if TASK_ID_RE.fullmatch(normalized) else None


def _first_reported_task(overview: Mapping[str, Any], sample_id: str) -> str | None:
    tasks = overview.get("tasks")
    if not isinstance(tasks, dict):
        return None
    for task_id, task in tasks.items():
        normalized = _task_from_overview(str(task_id), sample_id)
        if (
            normalized
            and isinstance(task, dict)
            and task.get("kind") == "behavioral"
            and task.get("status") == "reported"
        ):
            return normalized
    return None


def _normalize_triage_report(
    sample_id: str, task_id: str, report: Mapping[str, Any]
) -> dict[str, Any]:
    process_names: set[str] = set()
    command_hashes: set[str] = set()
    for process in report.get("processes") or []:
        if not isinstance(process, dict):
            continue
        image = process.get("image") or process.get("orig")
        if image:
            process_names.add(_safe_filename(str(image)))
        command = str(process.get("cmd") or "")
        if command:
            command_hashes.add(hashlib.sha256(command.encode("utf-8")).hexdigest())
    dumped_files = []
    for entry in report.get("dumped") or []:
        if not isinstance(entry, dict):
            continue
        digest = str(entry.get("sha256") or "").lower()
        dumped_files.append(
            {
                "name": _safe_filename(str(entry.get("path") or entry.get("name") or "unnamed")),
                "sha256": digest if SHA256_RE.fullmatch(digest) else None,
            }
        )
    network_context: set[str] = set()
    network = report.get("network")
    for key, value in _iter_key_values(network):
        if key.casefold() not in {
            "url",
            "host",
            "hostname",
            "domain",
            "ip",
            "dst",
            "destination",
        }:
            continue
        candidates = value if isinstance(value, list) else [value]
        for candidate in candidates:
            normalized = _safe_network_value(candidate)
            if normalized:
                network_context.add(normalized)
    return {
        "source": "hatching_triage",
        "type": "behavioral_report",
        "sample_id": sample_id,
        "task_id": task_id,
        "process_names": sorted(process_names),
        "command_sha256": sorted(command_hashes),
        "dumped_files": dumped_files[:100],
        "network_context": sorted(network_context)[:200],
        "raw_commands_included": False,
        "network_context_only": True,
    }


def _iter_key_values(value: Any):
    if isinstance(value, dict):
        for key, child in value.items():
            yield str(key), child
            yield from _iter_key_values(child)
    elif isinstance(value, list):
        for child in value:
            yield from _iter_key_values(child)


def _safe_network_value(value: Any) -> str | None:
    text = str(value or "").strip()
    if not text or len(text) > 2048:
        return None
    if text.casefold().startswith(("http://", "https://")):
        parsed = urllib.parse.urlsplit(text)
        if not parsed.hostname:
            return None
        try:
            port = parsed.port
        except ValueError:
            return None
        return f"{parsed.hostname.lower()}:{port}" if port else parsed.hostname.lower()
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        pass
    if DOMAIN_RE.fullmatch(text.rstrip(".")):
        return text.lower().rstrip(".")
    if re.fullmatch(r"[a-z0-9.-]+:\d{1,5}", text, re.IGNORECASE):
        host, port = text.rsplit(":", 1)
        if DOMAIN_RE.fullmatch(host) and 0 < int(port) <= 65535:
            return f"{host.lower()}:{port}"
    return None
