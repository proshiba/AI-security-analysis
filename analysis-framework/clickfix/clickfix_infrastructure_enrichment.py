#!/usr/bin/env python3
"""ClickFix caseをpassive DNS・RDAP・CT・InternetDBで補強する。"""

from __future__ import annotations

import argparse
import concurrent.futures
import ipaddress
import json
from pathlib import Path
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from clickfix_daily_intake import atomic_json, utc_now

USER_AGENT = "AI-security-analysis ClickFix infrastructure enrichment/1.0"
MAX_CASES = 50
MAX_BYTES = 8 * 1024 * 1024
DNS_TYPES = ("A", "AAAA", "CNAME", "NS", "MX")


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content.rstrip() + "\n", encoding="utf-8", newline="\n")


def _get_json(url: str, timeout: float) -> Any:
    for attempt in range(3):
        request = urllib.request.Request(
            url,
            headers={"Accept": "application/json", "User-Agent": USER_AGENT},
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                data = response.read(MAX_BYTES + 1)
                if len(data) > MAX_BYTES:
                    raise ValueError("応答が上限を超えました")
                return json.loads(data.decode("utf-8"))
        except urllib.error.HTTPError as error:
            if error.code not in {429, 502, 503, 504} or attempt == 2:
                raise
            retry_after = error.headers.get("Retry-After")
            try:
                delay = float(retry_after) if retry_after else float(2 ** (attempt + 1))
            except ValueError:
                delay = float(2 ** (attempt + 1))
            time.sleep(min(max(delay, 1.0), 15.0))
    raise RuntimeError("到達不能なretry状態")


def _events(value: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for event in value.get("events") or []:
        action = str(event.get("eventAction") or "")
        date = str(event.get("eventDate") or "")
        if action and date:
            rows.append({"action": action, "date": date})
    return rows


def _registrars(value: dict[str, Any]) -> list[str]:
    handles = set()
    for entity in value.get("entities") or []:
        roles = {str(role).lower() for role in entity.get("roles") or []}
        if "registrar" in roles and entity.get("handle"):
            handles.add(str(entity["handle"])[:200])
    return sorted(handles)


def _public_domain_rdap(value: dict[str, Any]) -> dict[str, Any]:
    return {
        "ldh_name": value.get("ldhName"),
        "unicode_name": value.get("unicodeName"),
        "handle": value.get("handle"),
        "status": sorted(str(item) for item in value.get("status") or []),
        "events": _events(value),
        "nameservers": sorted(
            {str(item.get("ldhName") or "").lower() for item in value.get("nameservers") or [] if item.get("ldhName")}
        ),
        "registrar_handles": _registrars(value),
        "port43": value.get("port43"),
    }


def _public_ip_rdap(value: dict[str, Any]) -> dict[str, Any]:
    return {
        "handle": value.get("handle"),
        "name": value.get("name"),
        "type": value.get("type"),
        "country": value.get("country"),
        "start_address": value.get("startAddress"),
        "end_address": value.get("endAddress"),
        "parent_handle": value.get("parentHandle"),
        "status": sorted(str(item) for item in value.get("status") or []),
        "events": _events(value),
    }


def _dns_records(value: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for answer in value.get("Answer") or []:
        data = str(answer.get("data") or "").rstrip(".")
        if not data:
            continue
        rows.append(
            {
                "name": str(answer.get("name") or "").rstrip(".").lower(),
                "type": answer.get("type"),
                "ttl": answer.get("TTL"),
                "data": data,
            }
        )
    return rows


def _ct_summary(value: Any, domain: str) -> dict[str, Any]:
    rows = value if isinstance(value, list) else []
    names = set()
    issuers = set()
    certificates = []
    for row in rows:
        for name in str(row.get("name_value") or "").splitlines():
            name = name.strip().lower()
            if name and (name == domain or name.endswith("." + domain) or name == "*." + domain):
                names.add(name)
        issuer = str(row.get("issuer_name") or "")
        if issuer:
            issuers.add(issuer[:500])
        certificates.append(
            {
                "common_name": str(row.get("common_name") or "")[:300],
                "not_before": row.get("not_before"),
                "not_after": row.get("not_after"),
                "serial_number": str(row.get("serial_number") or "")[:100],
            }
        )
    certificates.sort(key=lambda item: str(item.get("not_before") or ""), reverse=True)
    return {
        "certificate_rows": len(rows),
        "names": sorted(names)[:100],
        "issuers": sorted(issuers)[:20],
        "recent_certificates": certificates[:20],
    }


def _internetdb_summary(value: dict[str, Any]) -> dict[str, Any]:
    return {
        "ip": value.get("ip"),
        "ports": sorted(int(port) for port in value.get("ports") or []),
        "hostnames": sorted(str(item).lower() for item in value.get("hostnames") or [])[:100],
        "cpes": sorted(str(item) for item in value.get("cpes") or [])[:100],
        "vulns": sorted(str(item) for item in value.get("vulns") or [])[:100],
        "tags": sorted(str(item) for item in value.get("tags") or [])[:100],
    }


def _ipwhois_summary(value: dict[str, Any]) -> dict[str, Any] | None:
    if value.get("success") is not True:
        return None
    connection = value.get("connection") or {}
    asn = connection.get("asn")
    return {
        "ip": value.get("ip"),
        "country_code": value.get("country_code"),
        "asn": int(asn) if isinstance(asn, (int, float)) else None,
        "organization": connection.get("org"),
        "isp": connection.get("isp"),
        "domain": connection.get("domain"),
    }


def _current_live(case_root: Path, manifest_case: dict[str, Any]) -> dict[str, Any]:
    path = case_root / "live-observation.json"
    if path.is_file():
        observation = json.loads(path.read_text(encoding="utf-8"))
    else:
        observation = {}
    certificates = {}
    addresses_by_role: dict[str, set[str]] = {"landing": set(), "stages": set()}
    for probe_name in ("landing", "stages"):
        for probe in observation.get(probe_name) or []:
            for hop in probe.get("hops") or []:
                addresses_by_role[probe_name].update(
                    str(address) for address in (hop.get("dns") or {}).get("public_addresses", [])
                )
                certificate = hop.get("tls_certificate") or {}
                fingerprint = str(certificate.get("sha256") or "")
                if re.fullmatch(r"[0-9a-f]{64}", fingerprint):
                    certificates[fingerprint] = certificate
    live = manifest_case.get("live") or {}
    return {
        "reachable": bool(live.get("reachable")),
        "http_statuses": live.get("http_statuses") or [],
        "webdav_multistatus_observed": bool(live.get("webdav_multistatus_observed")),
        "redirects": live.get("redirects") or [],
        "public_addresses": live.get("public_addresses") or [],
        "landing_public_addresses": sorted(addresses_by_role["landing"]),
        "stage_public_addresses": sorted(addresses_by_role["stages"]),
        "tls_certificates": list(certificates.values()),
    }


def _enrich_case(case: dict[str, Any], repository: Path, private_root: Path, timeout: float) -> dict[str, Any]:
    domain = str(case["domain"]).lower()
    case_id = str(case["case_id"])
    case_root = repository / "analysis-results" / "clickfix" / case["relative_path"]
    private_case = private_root / case_id
    existing_path = case_root / "infrastructure.json"
    existing = json.loads(existing_path.read_text(encoding="utf-8")) if existing_path.is_file() else {}
    existing_layers = existing.get("evidence_layers") or {}
    errors = []
    dns = dict(existing_layers.get("current_passive_dns") or {})
    for record_type in DNS_TYPES:
        url = "https://dns.google/resolve?" + urllib.parse.urlencode(
            {"name": domain, "type": record_type, "cd": "false", "do": "false"}
        )
        try:
            raw = _get_json(url, timeout)
            atomic_json(private_case / f"dns-{record_type.lower()}.json", raw)
            dns[record_type] = {
                "status": raw.get("Status"),
                "records": _dns_records(raw),
            }
        except (OSError, ValueError, json.JSONDecodeError, urllib.error.URLError) as error:
            errors.append(
                {
                    "source": f"dns:{record_type}",
                    "error": type(error).__name__,
                    "http_status": getattr(error, "code", None),
                }
            )
    domain_rdap = existing_layers.get("domain_rdap")
    if domain_rdap is None:
        try:
            raw = _get_json("https://rdap.org/domain/" + urllib.parse.quote(domain), timeout)
            atomic_json(private_case / "rdap-domain.json", raw)
            domain_rdap = _public_domain_rdap(raw)
        except (OSError, ValueError, json.JSONDecodeError, urllib.error.URLError) as error:
            errors.append(
                {
                    "source": "rdap:domain",
                    "error": type(error).__name__,
                    "http_status": getattr(error, "code", None),
                }
            )
    ct = existing_layers.get("certificate_transparency")
    try:
        raw = _get_json(
            "https://crt.sh/?" + urllib.parse.urlencode({"q": "%." + domain, "output": "json"}),
            timeout,
        )
        atomic_json(private_case / "certificate-transparency.json", raw)
        ct = _ct_summary(raw, domain)
    except (OSError, ValueError, json.JSONDecodeError, urllib.error.URLError) as error:
        errors.append(
            {
                "source": "certificate_transparency",
                "error": type(error).__name__,
                "http_status": getattr(error, "code", None),
            }
        )
    live = _current_live(case_root, case)
    pivot_ip = next(
        (
            address
            for address in [*live["landing_public_addresses"], *live["public_addresses"]]
            if _is_public_ip(str(address))
        ),
        None,
    )
    previous_pivot = existing_layers.get("ip_pivot") or {}
    same_pivot = previous_pivot.get("address") == pivot_ip
    ip_rdap = previous_pivot.get("rdap") if same_pivot else None
    internetdb = previous_pivot.get("shodan_internetdb") if same_pivot else None
    asn = previous_pivot.get("asn") if same_pivot else None
    if pivot_ip:
        try:
            raw = _get_json("https://rdap.org/ip/" + urllib.parse.quote(pivot_ip), timeout)
            atomic_json(private_case / "rdap-ip.json", raw)
            ip_rdap = _public_ip_rdap(raw)
        except (OSError, ValueError, json.JSONDecodeError, urllib.error.URLError) as error:
            errors.append(
                {"source": "rdap:ip", "error": type(error).__name__, "http_status": getattr(error, "code", None)}
            )
        try:
            raw = _get_json("https://internetdb.shodan.io/" + urllib.parse.quote(pivot_ip), timeout)
            atomic_json(private_case / "shodan-internetdb.json", raw)
            internetdb = _internetdb_summary(raw)
        except (OSError, ValueError, json.JSONDecodeError, urllib.error.URLError) as error:
            errors.append(
                {
                    "source": "shodan_internetdb",
                    "error": type(error).__name__,
                    "http_status": getattr(error, "code", None),
                }
            )
        try:
            raw = _get_json("https://ipwho.is/" + urllib.parse.quote(pivot_ip), timeout)
            atomic_json(private_case / "ipwhois.json", raw)
            asn = _ipwhois_summary(raw)
        except (OSError, ValueError, json.JSONDecodeError, urllib.error.URLError) as error:
            errors.append(
                {
                    "source": "ipwhois",
                    "error": type(error).__name__,
                    "http_status": getattr(error, "code", None),
                }
            )
    return {
        "schema_version": 1,
        "case_id": case_id,
        "domain": domain,
        "observed_at": case.get("observed_at"),
        "investigated_at_utc": utc_now(),
        "evidence_layers": {
            "provider_observation": {
                "source": case.get("source"),
                "source_id": case.get("source_id"),
            },
            "active_bounded_get": live,
            "current_passive_dns": dns,
            "domain_rdap": domain_rdap,
            "certificate_transparency": ct,
            "ip_pivot": {
                "address": pivot_ip,
                "rdap": ip_rdap,
                "asn": asn,
                "shodan_internetdb": internetdb,
            },
            "historical_passive_dns": {
                "status": "not_collected",
                "reason": "履歴DNS provider未設定。CT・source観測日時・現行DNSで時間軸を分離",
            },
        },
        "errors": errors,
        "interpretation": {
            "shared_hosting_and_cdn_possible": True,
            "dns_or_open_port_alone_is_c2": False,
            "campaign_attribution_requires_multi_axis_evidence": True,
        },
    }


def _is_public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def render_case(result: dict[str, Any]) -> str:
    layers = result["evidence_layers"]
    live = layers["active_bounded_get"]
    dns = layers["current_passive_dns"]
    rdap = layers["domain_rdap"] or {}
    ct = layers["certificate_transparency"] or {}
    pivot = layers["ip_pivot"]
    dns_rows = []
    for record_type in DNS_TYPES:
        records = dns.get(record_type, {}).get("records") or []
        values = ", ".join(str(row["data"]) for row in records[:20]) or "未取得"
        dns_rows.append(f"| `{record_type}` | {values}（DNS応答） |")
    internetdb = pivot.get("shodan_internetdb") or {}
    asn = pivot.get("asn") or {}
    return f"""# インフラ調査

## 時点と役割

- domain: `{result["domain"]}`
- 情報源観測日時: `{result.get("observed_at")}`
- インフラ調査日時: `{result["investigated_at_utc"]}`
- ライブ到達: `{"到達" if live["reachable"] else "未到達"}` / HTTP `{live["http_statuses"]}`
- WebDAV 207: `{"観測" if live["webdav_multistatus_observed"] else "未観測"}`

配布domain、stage取得先、resolver、終端C2を分離します。以下のDNS、RDAP、証明書、port情報は
pivot候補であり、単独では悪性またはC2の根拠にしません。

## 現行DNS

| DNS種別 | 解析時の応答 |
|---|---|
{chr(10).join(dns_rows)}

## 登録・ホスティング

- RDAP handle（登録識別子）: `{rdap.get("handle") or "未取得"}`
- registrar handle（レジストラ識別子）: `{", ".join(rdap.get("registrar_handles") or []) or "未取得"}`
- nameserver（権威DNS）: `{", ".join(rdap.get("nameservers") or []) or "未取得"}`
- 登録status: `{", ".join(rdap.get("status") or []) or "未取得"}`
- IP pivot（調査対象）: `{pivot.get("address") or "未設定"}`
- netblock（割当範囲）: `{(pivot.get("rdap") or {}).get("name") or "未取得"}` / `{(pivot.get("rdap") or {}).get("start_address") or "?"} - {(pivot.get("rdap") or {}).get("end_address") or "?"}`
- ASN: `AS{asn.get("asn") or "未取得"}` / `{asn.get("organization") or asn.get("isp") or "未取得"}` / 国コード `{asn.get("country_code") or "未取得"}`

## 証明書とCT

- ライブleaf証明書: `{len(live.get("tls_certificates") or [])}`件
- CT行数: `{ct.get("certificate_rows", 0)}`
- CT names（証明書名）: `{", ".join((ct.get("names") or [])[:30]) or "未取得"}`
- issuer（発行者）: `{", ".join((ct.get("issuers") or [])[:10]) or "未取得"}`

## Shodan InternetDBの公開サービス情報

- ports（公開port）: `{internetdb.get("ports") or []}`
- hostnames（観測名）: `{internetdb.get("hostnames") or []}`
- CPE（製品識別子）: `{internetdb.get("cpes") or []}`
- CVE（脆弱性識別子）: `{internetdb.get("vulns") or []}`

port openはサービス存在の観測にすぎません。malware protocol、URI、証明書再利用、process帰属の
いずれかを追加確認してからC2候補へ昇格します。

## 時系列上の制約

履歴passive DNS providerは未設定です。情報源の観測日時、今回のcurrent DNS、RDAP event、CTの
not-before／not-afterを混同せず、同一IP・証明書・nameserverの再利用はcampaign候補としてのみ扱います。
API errorは`{len(result["errors"])}`件でした。
"""


def render_summary(results: list[dict[str, Any]], analysis_date: str) -> str:
    reachable = sum(item["evidence_layers"]["active_bounded_get"]["reachable"] for item in results)
    rdap = sum(item["evidence_layers"]["domain_rdap"] is not None for item in results)
    ct = sum(item["evidence_layers"]["certificate_transparency"] is not None for item in results)
    internetdb = sum(item["evidence_layers"]["ip_pivot"]["shodan_internetdb"] is not None for item in results)
    asn = sum(item["evidence_layers"]["ip_pivot"].get("asn") is not None for item in results)
    errors = sum(len(item["errors"]) for item in results)
    return f"""# ClickFixインフラ調査サマリー: {analysis_date}

- case: `{len(results)}`件
- ライブHTTP到達: `{reachable}`件
- domain RDAP取得: `{rdap}`件
- CT取得: `{ct}`件
- Shodan InternetDB取得: `{internetdb}`件
- ASN取得: `{asn}`件
- provider別error: `{errors}`件

DNS・証明書・RDAP・netblock・InternetDBを同一caseへ束ねました。共有CDNや侵害された正規サイトを
含むため、IP／証明書／portの一致だけでcampaignやC2を確定しません。
"""


def enrich(
    repository: Path, analysis_date: str, private_root: Path, workers: int, timeout: float, write: bool
) -> list[dict[str, Any]]:
    collection_id = f"clickfix-daily-{analysis_date.replace('-', '')}"
    manifest_path = repository / "analysis-results" / "clickfix" / "collections" / collection_id / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    cases = list(manifest.get("cases") or [])
    if not cases or len(cases) > MAX_CASES:
        raise ValueError(f"case件数が範囲外です: {len(cases)}")
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, min(workers, 4))) as executor:
        futures = {executor.submit(_enrich_case, case, repository, private_root, timeout): case for case in cases}
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())
    order = {case["case_id"]: index for index, case in enumerate(cases)}
    results.sort(key=lambda item: order[item["case_id"]])
    if write:
        for case, result in zip(cases, results, strict=True):
            case_root = repository / "analysis-results" / "clickfix" / case["relative_path"]
            atomic_json(case_root / "infrastructure.json", result)
            _write_text(case_root / "INFRASTRUCTURE.md", render_case(result))
        _write_text(manifest_path.parent / "INFRASTRUCTURE-SUMMARY.md", render_summary(results, analysis_date))
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    parser.add_argument("--analysis-date", required=True)
    parser.add_argument("--private-output", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args(argv)
    results = enrich(
        args.repository.resolve(),
        args.analysis_date,
        args.private_output.resolve() / args.analysis_date,
        args.workers,
        args.timeout,
        args.write,
    )
    print(
        json.dumps(
            {
                "cases": len(results),
                "domain_rdap": sum(item["evidence_layers"]["domain_rdap"] is not None for item in results),
                "certificate_transparency": sum(
                    item["evidence_layers"]["certificate_transparency"] is not None for item in results
                ),
                "internetdb": sum(
                    item["evidence_layers"]["ip_pivot"]["shodan_internetdb"] is not None for item in results
                ),
                "asn": sum(item["evidence_layers"]["ip_pivot"].get("asn") is not None for item in results),
                "errors": sum(len(item["errors"]) for item in results),
                "write_performed": bool(args.write),
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
