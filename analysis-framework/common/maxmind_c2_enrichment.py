#!/usr/bin/env python3
"""C2監視結果をprivate MaxMind GeoLite2 City/ASN DBでエンリッチする。

ライセンスキー、download URL、MMDB本体は公開結果へ保存しない。GeoLite2の
照合結果、DB build epoch、MMDB SHA-256、取得時刻だけを公開可能なJSONへ残す。
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import os
import re
import shutil
import tarfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen


EDITIONS = ("GeoLite2-City", "GeoLite2-ASN")
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_CHECKSUM_BYTES = 4096
SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
ATTRIBUTION = "This product includes GeoLite2 Data created by MaxMind, available from https://www.maxmind.com."


class MaxMindDownloadError(RuntimeError):
    """secretを含まないdownload error。"""


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON rootはobjectである必要があります: {path}")
    return value


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def user_environment(name: str) -> str | None:
    """process環境を優先し、Windowsでは新規HKCU環境変数も安全に読む。"""
    value = os.environ.get(name)
    if value:
        return value.strip()
    if os.name != "nt":
        return None
    try:
        import winreg

        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as key:
            value, _ = winreg.QueryValueEx(key, name)
    except (FileNotFoundError, OSError):
        return None
    return str(value).strip() or None


def download_request(
    edition: str,
    suffix: str,
    *,
    account_id: str | None,
    license_key: str,
) -> tuple[Request, str]:
    if edition not in EDITIONS:
        raise ValueError(f"許可していないMaxMind editionです: {edition}")
    if suffix not in {"tar.gz", "tar.gz.sha256"}:
        raise ValueError(f"許可していないsuffixです: {suffix}")
    headers = {"User-Agent": "AI-security-analysis/MaxMind-C2-enrichment"}
    if account_id:
        token = base64.b64encode(f"{account_id}:{license_key}".encode("utf-8")).decode("ascii")
        headers["Authorization"] = f"Basic {token}"
        url = f"https://download.maxmind.com/geoip/databases/{edition}/download?suffix={suffix}"
        mode = "basic_auth_current"
    else:
        url = (
            "https://download.maxmind.com/app/geoip_download"
            f"?edition_id={edition}&license_key={quote(license_key, safe='')}&suffix={suffix}"
        )
        mode = "license_key_permalink_legacy_fallback"
    return Request(url, headers=headers), mode


def _download_to_file(request: Request, destination: Path, edition: str) -> dict[str, Any]:
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".download")
    size = 0
    headers: dict[str, str | None] = {}
    try:
        with urlopen(request, timeout=120) as response, temporary.open("wb") as handle:
            headers = {
                "last_modified": response.headers.get("Last-Modified"),
                "content_type": response.headers.get("Content-Type"),
            }
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_ARCHIVE_BYTES:
                    raise MaxMindDownloadError(f"{edition} archiveが上限を超えました")
                handle.write(chunk)
    except HTTPError as exc:
        temporary.unlink(missing_ok=True)
        raise MaxMindDownloadError(f"{edition} downloadはHTTP {exc.code}で失敗しました") from None
    except URLError:
        temporary.unlink(missing_ok=True)
        raise MaxMindDownloadError(f"{edition} downloadはnetwork errorで失敗しました") from None
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    temporary.replace(destination)
    return {"bytes": size, **headers}


def _download_checksum(request: Request, edition: str) -> str:
    try:
        with urlopen(request, timeout=60) as response:
            raw = response.read(MAX_CHECKSUM_BYTES + 1)
    except HTTPError as exc:
        raise MaxMindDownloadError(f"{edition} checksumはHTTP {exc.code}で失敗しました") from None
    except URLError:
        raise MaxMindDownloadError(f"{edition} checksumはnetwork errorで失敗しました") from None
    if len(raw) > MAX_CHECKSUM_BYTES:
        raise MaxMindDownloadError(f"{edition} checksum responseが上限を超えました")
    token = raw.decode("ascii", errors="strict").strip().split()[0]
    if not SHA256_RE.fullmatch(token):
        raise MaxMindDownloadError(f"{edition} checksum形式が不正です")
    return token.casefold()


def _safe_mmdb_member(archive: tarfile.TarFile, edition: str) -> tarfile.TarInfo:
    candidates = [
        member
        for member in archive.getmembers()
        if member.isfile() and Path(member.name).name == f"{edition}.mmdb"
    ]
    if len(candidates) != 1:
        raise MaxMindDownloadError(f"{edition} archive内のMMDBを一意に決定できません")
    member = candidates[0]
    if member.size <= 0 or member.size > MAX_ARCHIVE_BYTES:
        raise MaxMindDownloadError(f"{edition} MMDB sizeが不正です")
    return member


def acquire_database(
    cache_dir: Path,
    edition: str,
    *,
    account_id: str | None,
    license_key: str,
    refresh: bool,
) -> tuple[Path, dict[str, Any]]:
    mmdb = cache_dir / f"{edition}.mmdb"
    metadata_path = cache_dir / f"{edition}.acquisition.json"
    if mmdb.is_file() and metadata_path.is_file() and not refresh:
        metadata = load_json(metadata_path)
        if metadata.get("mmdb_sha256") == sha256_file(mmdb):
            return mmdb, metadata
    archive_request, mode = download_request(
        edition, "tar.gz", account_id=account_id, license_key=license_key
    )
    checksum_request, _ = download_request(
        edition, "tar.gz.sha256", account_id=account_id, license_key=license_key
    )
    cache_dir.mkdir(parents=True, exist_ok=True)
    archive_path = cache_dir / f"{edition}.tar.gz"
    response_metadata = _download_to_file(archive_request, archive_path, edition)
    archive_sha256 = sha256_file(archive_path)
    expected_sha256 = _download_checksum(checksum_request, edition)
    if archive_sha256 != expected_sha256:
        archive_path.unlink(missing_ok=True)
        raise MaxMindDownloadError(f"{edition} archiveの公式SHA-256照合に失敗しました")
    temporary_mmdb = mmdb.with_suffix(".mmdb.extract")
    try:
        with tarfile.open(archive_path, mode="r:gz") as archive:
            member = _safe_mmdb_member(archive, edition)
            source = archive.extractfile(member)
            if source is None:
                raise MaxMindDownloadError(f"{edition} MMDBを展開できません")
            with source, temporary_mmdb.open("wb") as target:
                shutil.copyfileobj(source, target, length=1024 * 1024)
        temporary_mmdb.replace(mmdb)
    finally:
        archive_path.unlink(missing_ok=True)
        temporary_mmdb.unlink(missing_ok=True)
    metadata = {
        "schema_version": 1,
        "edition": edition,
        "acquired_at_utc": datetime.now(UTC).isoformat(),
        "authentication_mode": mode,
        "last_modified": response_metadata.get("last_modified"),
        "archive_bytes": response_metadata.get("bytes"),
        "archive_sha256": archive_sha256,
        "official_checksum_verified": True,
        "mmdb_bytes": mmdb.stat().st_size,
        "mmdb_sha256": sha256_file(mmdb),
        "license_key_stored": False,
        "download_url_stored": False,
        "archive_retained": False,
    }
    write_json(metadata_path, metadata)
    return mmdb, metadata


def _localized_name(value: Any) -> str | None:
    if not isinstance(value, dict):
        return None
    names = value.get("names")
    if not isinstance(names, dict):
        return None
    return names.get("ja") or names.get("en")


def project_city(record: dict[str, Any] | None) -> dict[str, Any] | None:
    if not record:
        return None
    subdivisions = record.get("subdivisions") if isinstance(record.get("subdivisions"), list) else []
    subdivision = subdivisions[0] if subdivisions and isinstance(subdivisions[0], dict) else {}
    location = record.get("location") if isinstance(record.get("location"), dict) else {}
    postal = record.get("postal") if isinstance(record.get("postal"), dict) else {}
    continent = record.get("continent") if isinstance(record.get("continent"), dict) else {}
    country = record.get("country") if isinstance(record.get("country"), dict) else {}
    registered = record.get("registered_country") if isinstance(record.get("registered_country"), dict) else {}
    represented = record.get("represented_country") if isinstance(record.get("represented_country"), dict) else {}
    traits = record.get("traits") if isinstance(record.get("traits"), dict) else {}
    return {
        "continent_code": continent.get("code"),
        "continent_name": _localized_name(continent),
        "country_iso_code": country.get("iso_code"),
        "country_name": _localized_name(country),
        "registered_country_iso_code": registered.get("iso_code"),
        "represented_country_iso_code": represented.get("iso_code"),
        "subdivision_iso_code": subdivision.get("iso_code"),
        "subdivision_name": _localized_name(subdivision),
        "city_name": _localized_name(record.get("city")),
        "postal_code": postal.get("code"),
        "latitude": location.get("latitude"),
        "longitude": location.get("longitude"),
        "accuracy_radius_km": location.get("accuracy_radius"),
        "time_zone": location.get("time_zone"),
        "is_anycast": traits.get("is_anycast"),
    }


def project_asn(record: dict[str, Any] | None) -> dict[str, Any] | None:
    if not record:
        return None
    return {
        "autonomous_system_number": record.get("autonomous_system_number"),
        "autonomous_system_organization": record.get("autonomous_system_organization"),
    }


def database_metadata(reader: Any, path: Path, acquisition: dict[str, Any]) -> dict[str, Any]:
    metadata = reader.metadata()
    epoch = getattr(metadata, "build_epoch", 0)
    return {
        "database_type": getattr(metadata, "database_type", None),
        "build_epoch": epoch,
        "build_time_utc": datetime.fromtimestamp(epoch, UTC).isoformat() if epoch else None,
        "ip_version": getattr(metadata, "ip_version", None),
        "languages": list(getattr(metadata, "languages", []) or []),
        "mmdb_sha256": sha256_file(path),
        "mmdb_bytes": path.stat().st_size,
        "acquired_at_utc": acquisition.get("acquired_at_utc"),
        "last_modified": acquisition.get("last_modified"),
        "official_checksum_verified": acquisition.get("official_checksum_verified") is True,
    }


def public_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return address.is_global


def enrich_monitoring(
    monitoring: dict[str, Any],
    city_reader: Any,
    asn_reader: Any,
    *,
    city_metadata: dict[str, Any],
    asn_metadata: dict[str, Any],
) -> dict[str, Any]:
    lookups = matched = 0
    for result in monitoring.get("results", []):
        if not isinstance(result, dict):
            continue
        observation = result.get("observation") if isinstance(result.get("observation"), dict) else {}
        values = observation.get("resolved_ips") if isinstance(observation.get("resolved_ips"), list) else []
        ips = sorted({str(value) for value in values if public_ip(str(value))})
        records = []
        for ip in ips:
            lookups += 1
            city = project_city(city_reader.get(ip))
            asn = project_asn(asn_reader.get(ip))
            if city or asn:
                matched += 1
            records.append({"ip": ip, "geo": city, "as": asn})
        result["maxmind"] = {
            "status": "matched" if any(item["geo"] or item["as"] for item in records) else ("not_applicable" if not ips else "not_found"),
            "records": records,
            "source": "GeoLite2 local MMDB",
        }
    monitoring["maxmind"] = {
        "schema_version": 1,
        "enriched_at_utc": datetime.now(UTC).isoformat(),
        "attribution": ATTRIBUTION,
        "privacy_note": "IP単位の概略Geo/AS情報であり、個人・世帯・住所の識別には使用しない。",
        "city_database": city_metadata,
        "asn_database": asn_metadata,
        "lookup_count": lookups,
        "matched_count": matched,
        "license_key_published": False,
        "download_url_published": False,
        "mmdb_published": False,
    }
    return monitoring


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--cache-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--refresh-databases", action="store_true")
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    try:
        import maxminddb
    except ImportError:
        parser.error("geoip2/maxminddbが必要です。requirements-maxmind.txtを導入してください")
    license_key = user_environment("MAXMIND_LICENSE_KEY")
    if not license_key:
        parser.error("MAXMIND_LICENSE_KEYが見つかりません")
    account_id = user_environment("MAXMIND_ACCOUNT_ID") or user_environment("MAXMIND_USER_ID")
    acquired: dict[str, tuple[Path, dict[str, Any]]] = {}
    for edition in EDITIONS:
        try:
            acquired[edition] = acquire_database(
                args.cache_dir.resolve(), edition, account_id=account_id,
                license_key=license_key, refresh=args.refresh_databases,
            )
        except MaxMindDownloadError as exc:
            parser.error(str(exc))
    monitoring = load_json(args.results)
    city_path, city_acquisition = acquired["GeoLite2-City"]
    asn_path, asn_acquisition = acquired["GeoLite2-ASN"]
    with maxminddb.open_database(str(city_path)) as city_reader, maxminddb.open_database(str(asn_path)) as asn_reader:
        enriched = enrich_monitoring(
            monitoring, city_reader, asn_reader,
            city_metadata=database_metadata(city_reader, city_path, city_acquisition),
            asn_metadata=database_metadata(asn_reader, asn_path, asn_acquisition),
        )
    output = args.output or args.results
    if args.write:
        write_json(output, enriched)
    summary = {
        "output": str(output),
        "written": args.write,
        "lookup_count": enriched["maxmind"]["lookup_count"],
        "matched_count": enriched["maxmind"]["matched_count"],
        "city_build_time_utc": enriched["maxmind"]["city_database"]["build_time_utc"],
        "asn_build_time_utc": enriched["maxmind"]["asn_database"]["build_time_utc"],
        "authentication_mode": city_acquisition.get("authentication_mode"),
        "license_key_published": False,
        "mmdb_published": False,
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
