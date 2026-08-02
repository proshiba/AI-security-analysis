#!/usr/bin/env python3
"""C2監視で解決されたIPへ、第三者geolocation照会の結果を付与する。

`monitor_recent_c2.py` の `monitoring-results.json` にある `resolved_ips` を
入力とし、国・都市・緯度経度・ASNを `ip-geo.json` として同じ日付ディレクトリへ
保存します。UIの世界地図プロットはこの成果物だけを読みます。

安全境界:

- 照会先は第三者のIP情報API(`ipwho.is`)だけです。**監視対象のC2へは接続しません**。
  接続を伴う観測は `monitor_recent_c2.py` の責務で、本スクリプトは行いません。
- `--allow-network` を明示した場合だけ外部へ出ます。既定は計画表示のみです。
- private / loopback / reserved アドレスと `.onion` は照会しません。
- geolocationは登録情報ベースの推定です。物理的な設置場所やC2所有者を
  確定するものではありません。judgement はUI側でも併記します。
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

SOURCE_NAME = "ipwho.is"
SOURCE_URL = "https://ipwho.is/"
RESULTS_NAME = "monitoring-results.json"
OUTPUT_NAME = "ip-geo.json"
SCHEMA_VERSION = 1


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def is_public_ip(value: str) -> bool:
    """照会してよいpublic addressか判定する。"""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (
        address.is_private
        or address.is_loopback
        or address.is_reserved
        or address.is_multicast
        or address.is_link_local
        or address.is_unspecified
    )


def resolved_ips(results: dict) -> dict[str, list[str]]:
    """monitoring-results.json から IP -> 参照host のマップを作る。"""
    hosts: dict[str, set[str]] = {}
    for entry in results.get("results") or []:
        observation = entry.get("observation") or {}
        host = entry.get("host") or observation.get("host")
        for address in observation.get("resolved_ips") or []:
            if not is_public_ip(str(address)):
                continue
            hosts.setdefault(str(address), set())
            if host:
                hosts[str(address)].add(str(host))
    return {ip: sorted(names) for ip, names in sorted(hosts.items())}


def summarize(raw: dict) -> dict | None:
    """APIの生応答から、保持する項目だけを取り出す。"""
    if raw.get("success") is not True:
        return None
    connection = raw.get("connection") or {}
    asn = connection.get("asn")
    timezone_info = raw.get("timezone") or {}
    latitude = raw.get("latitude")
    longitude = raw.get("longitude")
    return {
        "ip": raw.get("ip"),
        "continent": raw.get("continent"),
        "continent_code": raw.get("continent_code"),
        "country": raw.get("country"),
        "country_code": raw.get("country_code"),
        "region": raw.get("region"),
        "city": raw.get("city"),
        "latitude": round(float(latitude), 4) if isinstance(latitude, (int, float)) else None,
        "longitude": round(float(longitude), 4) if isinstance(longitude, (int, float)) else None,
        "timezone": timezone_info.get("id"),
        "asn": int(asn) if isinstance(asn, (int, float)) else None,
        "organization": connection.get("org"),
        "isp": connection.get("isp"),
        "domain": connection.get("domain"),
    }


def fetch(address: str, timeout: float) -> dict:
    request = urllib.request.Request(
        SOURCE_URL + urllib.parse.quote(address),
        headers={"User-Agent": "ai-security-analysis-c2-geo/1.0"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def build(results: dict, allow_network: bool, timeout: float, pause: float) -> dict:
    targets = resolved_ips(results)
    entries: list[dict] = []
    errors: list[dict] = []
    for index, (address, hosts) in enumerate(targets.items()):
        record = {"ip": address, "hosts": hosts}
        if allow_network:
            if index and pause:
                time.sleep(pause)
            try:
                summary = summarize(fetch(address, timeout))
            except (OSError, ValueError, json.JSONDecodeError, urllib.error.URLError) as error:
                errors.append(
                    {
                        "ip": address,
                        "error": type(error).__name__,
                        "http_status": getattr(error, "code", None),
                    }
                )
                summary = None
            if summary:
                record.update({k: v for k, v in summary.items() if k != "ip"})
                record["geo_resolved"] = True
            else:
                record["geo_resolved"] = False
        else:
            record["geo_resolved"] = False
        entries.append(record)
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": utc_now(),
        "source": SOURCE_NAME,
        "source_url": SOURCE_URL,
        "network_enabled": bool(allow_network),
        "target_c2_contacted": False,
        "interpretation": {
            "registry_based_estimate": True,
            "physical_location_confirmed": False,
            "c2_ownership_confirmed": False,
            "note": "geolocationは登録情報ベースの推定であり、設置場所やC2所有者を確定しない。",
        },
        "ip_count": len(entries),
        "resolved_count": sum(1 for e in entries if e.get("geo_resolved")),
        "errors": errors,
        "ips": entries,
    }


def render(payload: dict) -> str:
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def coverage_gap(results: dict, existing: dict) -> list[str]:
    """既存 ip-geo.json が未カバーのIPを返す。"""
    known = {
        str(entry.get("ip"))
        for entry in existing.get("ips") or []
        if entry.get("geo_resolved")
    }
    return [ip for ip in resolved_ips(results) if ip not in known]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--results",
        type=Path,
        required=True,
        help=f"{RESULTS_NAME} のパス、またはそれを含むディレクトリ",
    )
    parser.add_argument("--allow-network", action="store_true", help="外部IP情報APIへ照会する")
    parser.add_argument("--check", action="store_true", help="既存ip-geo.jsonの網羅を検証する(通信なし)")
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--pause", type=float, default=0.4, help="照会間隔(秒)")
    args = parser.parse_args(argv)

    path = args.results
    if path.is_dir():
        path = path / RESULTS_NAME
    if not path.is_file():
        print(f"{path} が見つかりません", file=sys.stderr)
        return 2
    results = json.loads(path.read_text(encoding="utf-8"))
    output = path.parent / OUTPUT_NAME

    if args.check:
        if not output.is_file():
            print(f"{output} がありません", file=sys.stderr)
            return 1
        gap = coverage_gap(results, json.loads(output.read_text(encoding="utf-8")))
        if gap:
            print("geo未取得のIP: " + ", ".join(gap), file=sys.stderr)
            return 1
        print(f"{output} は全ての解決IPを網羅しています。")
        return 0

    payload = build(results, args.allow_network, args.timeout, args.pause)
    if not args.allow_network:
        print("計画のみ(通信なし)。--allow-network で照会します。")
        print(f"照会対象IP: {payload['ip_count']}件")
        for entry in payload["ips"]:
            print(f"  {entry['ip']}  <- {', '.join(entry['hosts'])}")
        return 0

    output.write_text(render(payload), encoding="utf-8")
    print(f"wrote {output}")
    print(f"geo取得: {payload['resolved_count']}/{payload['ip_count']} 件、エラー {len(payload['errors'])}件")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
