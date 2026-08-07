#!/usr/bin/env python3
"""マルウェア解析ブラウザUI用のデータファイル(ui/data.js)を生成する。

analysis-results/catalog/cases.json を正本として全caseを列挙し、
各caseの metadata.json / features.json / iocs.json / IOC-LIST.md / README.md、
ファミリ単位の文書(README/OSINT/TECHNICAL-ANALYSIS/VERSIONS等)と
YARA/Sigmaルール、analysis_history.yaml の解析履歴を統合する。

検体本体には一切触れず、リポジトリ内の公開可能な成果物だけを読み取る。

使い方:
    python3 ui/generate_ui_data.py            # ui/data.js を再生成
    python3 ui/generate_ui_data.py --check    # 差分があれば終了コード1
"""

from __future__ import annotations

import argparse
import itertools
import json
import os
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
RESULTS = REPO_ROOT / "analysis-results"
UI_ROOT = Path(__file__).resolve().parent
OUTPUT = UI_ROOT / "data.js"

# ケース詳細の切り出し先。全ケース分をdata.jsへ入れると、一覧も検索も参照しない
# 本文で初回転送が埋まる(README全文と検体特徴だけで全体の約55%)。個別ケース
# ページを開いたときだけ取りに行けるよう、SHA-256の先頭2文字で分けて置く。
CASE_DETAIL_DIR = UI_ROOT / "cases"
CASE_DETAIL_FIELDS = ("docs", "characteristics")
CASE_DETAIL_SCHEMA = 1

FAMILY_DOC_FILES = [
    ("readme", "README.md", "概要"),
    ("osint", "OSINT.md", "OSINT"),
    ("technical", "TECHNICAL-ANALYSIS.md", "技術解析"),
    ("versions", "VERSIONS.md", "版情報"),
    ("campaigns", "CAMPAIGNS.md", "キャンペーン"),
    ("behavior_c2", "BEHAVIOR-C2.md", "挙動・C2"),
]

# 全文をUIへ埋め込むcase文書。FEATURES.md/STATIC-LOGIC.mdは構造化データと
# 重複またはサイズ過大のため、ファイル一覧からのリンク参照に留める。
CASE_DOC_FILES = [
    ("readme", "README.md"),
]


def read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def read_json(path: Path):
    text = read_text(path)
    if text is None:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


# IOC-LIST.md の種別・役割の表記はケースによって揺れる(`url`/`URL`、`ドメイン`/
# `Domain`/`Host`、役割は `c2` を含まない `beacon_or_tasking`、`file_exfiltration`、
# `credential_exfiltration` など)。ラベルの綴りに依存すると取りこぼすため、
# 値の形を主な判定材料にする。spec v1向けの厳密な型判定は
# `build_portal_index.py` の classify_value() 側に持つ。
HASH_OR_FILE_TYPES = {
    "sha256", "sha-256", "sha1", "sha-1", "md5", "imphash",
    "file_name", "filename", "ethereumアドレス",
}
NETWORK_TYPE_HINTS = {
    "接続先", "ドメイン", "domain", "url", "host", "hostname",
    "endpoint", "ip", "ipv4", "ipv6",
}
NETWORK_ROLE_HINTS = (
    "c2", "beacon", "tasking", "exfil", "distribution", "download",
    "stage", "host", "endpoint", "network", "config",
)
_URL_VALUE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://\S+$")
_IPV4_VALUE_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_HOSTPORT_VALUE_RE = re.compile(r"^[A-Za-z0-9_.-]+:\d{1,5}$")
_HOSTNAME_VALUE_RE = re.compile(r"^[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+$")


def is_network_indicator(entry: dict) -> bool:
    """IOC-LIST.mdの1行が、C2・通信欄へ出すネットワーク指標かを判定する。"""
    ioc_type = str(entry.get("type") or "").strip().lower()
    if ioc_type in HASH_OR_FILE_TYPES:
        return False
    value = str(entry.get("value") or "").strip()
    if not value:
        return False
    # 値の形だけで通信先と分かるものは、種別・役割の表記に関係なく採用する
    if (
        _URL_VALUE_RE.match(value)
        or _IPV4_VALUE_RE.match(value)
        or _HOSTPORT_VALUE_RE.match(value)
    ):
        return True
    # ホスト名の形は、ファイル名と紛れるため種別か役割の裏付けを要求する
    if not _HOSTNAME_VALUE_RE.match(value):
        return False
    role = str(entry.get("role") or "").strip().lower()
    return ioc_type in NETWORK_TYPE_HINTS or any(h in role for h in NETWORK_ROLE_HINTS)


def structured_network_values(iocs_json: dict) -> set[str]:
    """`iocs.json` の network 配列から通信先を組み立てる。

    IOC-LIST.mdは生成物で表記が揺れるが、この配列はhost/ip/domain/url/portを
    分けて持つ構造化データなので、取りこぼしを防ぐために併用する。
    """
    values: set[str] = set()
    for entry in iocs_json.get("network") or []:
        if not isinstance(entry, dict):
            continue
        url = str(entry.get("url") or "").strip()
        if url:
            values.add(url)
        host = str(entry.get("host") or entry.get("ip") or entry.get("domain") or "").strip()
        if not host:
            continue
        port = entry.get("port")
        values.add(f"{host}:{port}" if port else host)
    return values


def parse_ioc_list(md: str) -> list[dict]:
    """IOC-LIST.md の5列標準表(種別/値/役割/確度/根拠)を行ごとに読み取る。"""
    entries = []
    for line in md.splitlines():
        line = line.strip()
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if len(cells) != 5:
            continue
        if cells[0].startswith("種別") or set(cells[0]) <= {"-", ":", " "}:
            continue
        value = cells[1].strip("`")
        if not value:
            continue
        entries.append(
            {
                "type": cells[0],
                "value": value,
                "role": cells[2],
                "confidence": cells[3],
                "source": cells[4],
            }
        )
    return entries


def collect_rules(rules_dir: Path, rel_base: Path) -> list[dict]:
    rules = []
    if not rules_dir.is_dir():
        return rules
    for path in sorted(rules_dir.rglob("*")):
        if not path.is_file():
            continue
        if path.suffix.lower() in (".yar", ".yara"):
            kind = "yara"
        elif path.suffix.lower() in (".yml", ".yaml"):
            kind = "sigma"
        else:
            continue
        text = read_text(path)
        if text is None:
            continue
        rules.append(
            {
                "kind": kind,
                "name": path.name,
                # OS依存のセパレータを避ける。Windows生成とCI(Linux)生成で
                # 出力が変わり、--check が環境によって落ちるため。
                "path": path.relative_to(rel_base).as_posix(),
                "text": text,
            }
        )
    return rules


def family_labels_from_index() -> dict[str, str]:
    """analysis-results/README.md のファミリ一覧から表示名を得る。"""
    labels: dict[str, str] = {}
    text = read_text(RESULTS / "README.md") or ""
    for match in re.finditer(r"^- \[(.+?)\]\(malware/([^/)]+)/README\.md\)", text, re.M):
        labels[match.group(2)] = match.group(1)
    return labels


def family_title_alias(readme: str | None) -> tuple[str | None, str | None]:
    if not readme:
        return None, None
    title = None
    alias = None
    for line in readme.splitlines():
        if title is None and line.startswith("# "):
            title = line[2:].strip()
        if alias is None and line.startswith("別名"):
            alias = line.split("：", 1)[-1].split(":", 1)[-1].strip()
    return title, alias


def load_history() -> dict[str, list[dict]]:
    data = yaml.safe_load(read_text(REPO_ROOT / "analysis_history.yaml") or "") or {}
    by_sha: dict[str, list[dict]] = {}
    for entry in data.get("analyses", []):
        sha = str(entry.get("sample_sha256") or "").lower()
        if not sha:
            continue
        by_sha.setdefault(sha, []).append(
            {
                "analyzed_at": str(entry.get("analyzed_at") or ""),
                "malware_type": entry.get("malware_type"),
                "analysis_level": entry.get("analysis_level"),
                "campaign_type": entry.get("campaign_type"),
                "matched_patterns": entry.get("matched_patterns") or [],
                "c2": [str(c) for c in (entry.get("c2") or [])],
                "notes": entry.get("notes"),
                "result_path": entry.get("result_path"),
            }
        )
    for items in by_sha.values():
        items.sort(key=lambda e: e["analyzed_at"], reverse=True)
    return by_sha


# コード完全一致groupがこのcase数を超える場合、library/compiler由来の可能性が
# 高いためcase間リンクの生成対象から除外する。
CODE_GROUP_CASE_CAP = 20


C2_STATE_LABELS = {
    "c2_protocol_confirmed": ("C2プロトコル一致", "confirmed"),
    "application_endpoint_reachable_c2_not_confirmed": ("HTTP応答あり(C2未確認)", "app"),
    "server_first_response_reachable_c2_not_confirmed": ("banner応答あり(C2未確認)", "app"),
    "tls_endpoint_reachable_c2_not_confirmed": ("TLS成立(C2未確認)", "tls"),
    "transport_reachable_c2_not_confirmed": ("TCP到達(C2未確認)", "tcp"),
    "not_reachable_at_observation": ("観測時点で応答なし", "down"),
    "not_observed_proxy_unavailable": ("観測経路なし(未観測)", "unknown"),
    "not_observed_safety_gate": ("安全境界により未実施", "unknown"),
    "dns_resolved_c2_service_not_confirmed": ("DNS解決あり(C2 service未確認)", "dns"),
    "dns_not_resolved": ("DNS解決なし(C2 service未観測)", "unknown"),
}


def c2_geo_table(run_dirs: list[Path]) -> dict[str, dict]:
    """C2監視結果に含まれるMaxMind GeoLite2の詳細を、新しい観測優先で集める。

    geoの正本は監視パイプライン(`maxmind_c2_enrichment.py`)が
    `monitoring-results.json` へ埋め込むMaxMind GeoLite2 City/ASNだけとする。
    以前は第三者API由来の `ip-geo.json` も併用していたが、同一IPで国が
    食い違う(例: CN Beijing と SG)ため、出所を1本に絞る。
    """
    table: dict[str, dict] = {}
    for run_dir in run_dirs:
        monitoring = read_json(run_dir / "monitoring-results.json") or {}
        for result in monitoring.get("results") or []:
            dns_history = (result.get("dns_tracking") or {}).get("history") or []
            for point in reversed(dns_history):
                for detail in point.get("ip_details") or []:
                    address = detail.get("ip")
                    geo = detail.get("geo") or {}
                    as_record = detail.get("as") or {}
                    if not address or not geo or address in table:
                        continue
                    table[address] = {
                        "country": geo.get("country_name"),
                        "country_code": geo.get("country_iso_code"),
                        "continent": geo.get("continent_name"),
                        "region": geo.get("subdivision_name"),
                        "city": geo.get("city_name"),
                        "lat": geo.get("latitude"),
                        "lon": geo.get("longitude"),
                        "asn": as_record.get("asn"),
                        "org": as_record.get("organization"),
                        "isp": None,
                        "observed_on": point.get("date") or run_dir.name,
                        "source": "GeoLite2 City/ASN",
                    }
    return table
def clickfix_dns_timeline() -> list[dict]:
    """ClickFix基盤の日付別caseから、ドメインの解決IP推移を組み立てる。

    `analysis-results/clickfix/<domain>/cases/<YYYYMMDD-...>/infrastructure.json`
    はcase毎に観測時点のAレコードを持つ。同一ドメインの複数caseを日付順に
    並べ、解決結果が変わった時点だけを遷移として残す。
    """
    root = RESULTS / "clickfix"
    if not root.is_dir():
        return []
    timelines: list[dict] = []
    for domain_dir in sorted(p for p in root.iterdir() if p.is_dir()):
        points: list[dict] = []
        for case_dir in sorted((domain_dir / "cases").glob("*")):
            payload = read_json(case_dir / "infrastructure.json")
            if not payload:
                continue
            layers = payload.get("evidence_layers") or {}
            records = ((layers.get("current_passive_dns") or {}).get("A") or {})
            addresses = sorted(
                {
                    str(record.get("data"))
                    for record in records.get("records") or []
                    if record.get("type") == 1 and record.get("data")
                }
            )
            pivot = layers.get("ip_pivot") or {}
            asn = pivot.get("asn") or {}
            stamp = case_dir.name[:8]
            points.append(
                {
                    "date": f"{stamp[0:4]}-{stamp[4:6]}-{stamp[6:8]}" if len(stamp) == 8 else stamp,
                    "case": case_dir.name,
                    "ips": addresses,
                    "dns_status": records.get("status"),
                    "pivot": pivot.get("address"),
                    "country_code": asn.get("country_code"),
                    "asn": asn.get("asn"),
                    "org": asn.get("organization") or asn.get("isp"),
                }
            )
        if not points:
            continue
        points.sort(key=lambda item: item["date"])
        timelines.append(
            {
                "host": domain_dir.name,
                "source": "clickfix",
                "path": (domain_dir.relative_to(REPO_ROOT)).as_posix(),
                "points": points,
                "changes": sum(
                    1
                    for index in range(1, len(points))
                    if points[index]["ips"] != points[index - 1]["ips"]
                ),
            }
        )
    return timelines


def load_c2_monitoring(known_shas: set[str]) -> dict:
    """C2稼働監視の日付別ランを集約し、endpoint毎の観測履歴とgeoを返す。

    `analysis-results/research/c2-monitoring/<YYYY-MM-DD>/` を新しい順に読み、
    endpoint(host:port)ごとに最新観測と全ランの履歴を持たせる。到達性と
    C2稼働確度は生成側でも混ぜず、そのままUIへ渡す。
    """
    root = RESULTS / "research" / "c2-monitoring"
    run_dirs = sorted(
        (p for p in root.glob("*") if p.is_dir() and read_json(p / "monitoring-results.json")),
        reverse=True,
    ) if root.is_dir() else []

    runs: list[dict] = []
    endpoints: dict[str, dict] = {}
    host_points: dict[str, list[dict]] = {}

    for run_dir in run_dirs:
        payload = read_json(run_dir / "monitoring-results.json") or {}
        runs.append(
            {
                "date": run_dir.name,
                "path": run_dir.relative_to(REPO_ROOT).as_posix(),
                "generated_at": payload.get("generated_at_utc"),
                "window": payload.get("analysis_window"),
                "target_count": payload.get("target_count"),
                "state_counts": payload.get("state_counts"),
                "policy": payload.get("policy"),
                "environment": payload.get("observation_environment"),
                "monitoring_history": payload.get("monitoring_history_summary"),
                "continuity": payload.get("monitoring_continuity"),
            }
        )
        for entry in payload.get("results") or []:
            host = entry.get("host")
            port = entry.get("port")
            if not host:
                continue
            key = "|".join(
                (
                    str(host).casefold().rstrip("."),
                    str(port or 0),
                    str(entry.get("protocol") or "tcp").casefold(),
                    str(entry.get("transport") or "direct").casefold(),
                    str(entry.get("http_path") or ""),
                )
            )
            observation = entry.get("observation") or {}
            assessment = entry.get("assessment") or {}
            state = assessment.get("state")
            label, tone = C2_STATE_LABELS.get(state, (state, "unknown"))
            point = {
                "date": run_dir.name,
                "timestamp": observation.get("timestamp_utc"),
                "state": state,
                "state_label": label,
                "tone": tone,
                "alive": bool(observation.get("alive")),
                "availability": entry.get("availability_status"),
                "resolved_ips": observation.get("resolved_ips") or [],
                "tcp_status": observation.get("tcp_status"),
                "status": observation.get("status"),
                "elapsed_ms": observation.get("elapsed_ms"),
                "reachability": assessment.get("reachability_confidence"),
                "c2_operational": assessment.get("c2_operational_confidence"),
                "ceiling": assessment.get("method_confidence_ceiling"),
                "negative": assessment.get("negative_observation_confidence"),
                "reason": assessment.get("reason"),
            }
            record = endpoints.get(key)
            if record is None:
                record = {
                    "id": entry.get("target_id") or key,
                    "host": host,
                    "port": port,
                    "protocol": entry.get("protocol"),
                    "transport": entry.get("transport"),
                    "method": entry.get("method"),
                    "method_label": entry.get("method_description"),
                    "http_path": entry.get("http_path"),
                    "family": entry.get("family"),
                    "onion": str(host).endswith(".onion"),
                    "cases": [
                        sha for sha in entry.get("sample_sha256s") or [] if sha in known_shas
                    ],
                    "case_count": entry.get("associated_case_count"),
                    "analyzed_dates": entry.get("analyzed_dates") or [],
                    "sources": entry.get("sources") or [],
                    "shodan": observation.get("shodan"),
                    "active": (entry.get("monitoring_lifecycle") or {}).get("active", True),
                    "lifecycle": entry.get("monitoring_lifecycle") or {},
                    "dns_tracking": entry.get("dns_tracking") or {},
                    "history": [],
                }
                endpoints[key] = record
            record["history"].append(point)
            dns_tracking = entry.get("dns_tracking") if isinstance(entry.get("dns_tracking"), dict) else {}
            dns_history = dns_tracking.get("history") if isinstance(dns_tracking.get("history"), list) else []
            if record["history"] == [point] and dns_history:
                for dns_point in dns_history:
                    if not isinstance(dns_point, dict):
                        continue
                    host_points.setdefault(host, []).append(
                        {
                            "date": dns_point.get("date") or run_dir.name,
                            "case": None,
                            "ips": sorted(dns_point.get("ips") or []),
                            "raw_ip_changed": bool(dns_point.get("raw_ip_changed")),
                            "infrastructure_ip_change": bool(
                                dns_point.get("infrastructure_ip_change")
                            ),
                            "change_classification": dns_point.get("change_classification"),
                            "shared_cdn_provider": dns_point.get("shared_cdn_provider"),
                            "ip_details": dns_point.get("ip_details") or [],
                            "transition": dns_point.get("transition"),
                        }
                    )
            elif not record.get("dns_tracking") and point["resolved_ips"]:
                host_points.setdefault(host, []).append(
                    {
                        "date": run_dir.name,
                        "case": None,
                        "ips": sorted(point["resolved_ips"]),
                    }
                )

    ordered: list[dict] = []
    for record in endpoints.values():
        # run_dirs は新しい順に読んでいるので history の先頭が最新観測
        record["latest"] = record["history"][0] if record["history"] else None
        ordered.append(record)
    def c2_rank(item: dict) -> float:
        """C2稼働確度の降順キー。値が無い/nullでも並べ替えを止めない。

        `.get(key, 0)` はキーが存在して値がnullの場合に0を返さないため、
        単項マイナスがTypeErrorになる。評価が埋まらない観測状態
        (not_observed_proxy_unavailable 等)で起こり得る。
        """
        value = (item.get("latest") or {}).get("c2_operational")
        return -value if isinstance(value, (int, float)) else 0.0

    ordered.sort(
        key=lambda item: (
            c2_rank(item),
            str(item.get("family") or ""),
            str(item.get("host")),
            item.get("port") or 0,
        )
    )

    monitor_timelines = []
    for host, points in sorted(host_points.items()):
        merged: dict[str, dict] = {}
        for point in points:
            date = str(point["date"])
            bucket = merged.setdefault(
                date,
                {
                    "ips": set(),
                    "raw_ip_changed": False,
                    "infrastructure_ip_change": False,
                    "classifications": set(),
                    "shared_cdn_providers": set(),
                    "ip_details": {},
                    "transitions": [],
                },
            )
            bucket["ips"].update(point["ips"])
            bucket["raw_ip_changed"] = (
                bucket["raw_ip_changed"] or point.get("raw_ip_changed", False)
            )
            bucket["infrastructure_ip_change"] = (
                bucket["infrastructure_ip_change"]
                or point.get("infrastructure_ip_change", False)
            )
            if point.get("change_classification"):
                bucket["classifications"].add(point["change_classification"])
            if point.get("shared_cdn_provider"):
                bucket["shared_cdn_providers"].add(point["shared_cdn_provider"])
            for detail in point.get("ip_details", []):
                if isinstance(detail, dict) and detail.get("ip"):
                    bucket["ip_details"].setdefault(detail["ip"], detail)
            transition = point.get("transition")
            if isinstance(transition, dict) and transition not in bucket["transitions"]:
                bucket["transitions"].append(transition)
        series = []
        previous_ips: list[str] | None = None
        for date, values in sorted(merged.items()):
            ips = sorted(values["ips"])
            raw_changed = values["raw_ip_changed"] or (
                previous_ips is not None and ips != previous_ips
            )
            infrastructure_changed = values["infrastructure_ip_change"]
            classifications = values["classifications"]
            if infrastructure_changed:
                classification = "infrastructure_ip_change"
            elif "shared_cdn_rotation_ignored" in classifications:
                classification = "shared_cdn_rotation_ignored"
            elif "resolution_state_changed" in classifications:
                classification = "resolution_state_changed"
            elif raw_changed:
                classification = "raw_ip_change_unclassified"
            elif previous_ips is None:
                classification = "initial_observation"
            else:
                classification = "unchanged"
            series.append(
                {
                    "date": date,
                    "case": None,
                    "ips": ips,
                    "ip_details": [
                        values["ip_details"][address]
                        for address in ips
                        if address in values["ip_details"]
                    ],
                    "raw_ip_changed": raw_changed,
                    "infrastructure_ip_change": infrastructure_changed,
                    "change_classification": classification,
                    "shared_cdn_provider": ", ".join(
                        sorted(values["shared_cdn_providers"])
                    )
                    or None,
                    "transition": (
                        values["transitions"][0] if values["transitions"] else None
                    ),
                }
            )
            previous_ips = ips
        monitor_timelines.append(
            {
                "host": host,
                "source": "c2-monitor",
                "path": None,
                "points": series,
                "changes": sum(point["infrastructure_ip_change"] for point in series),
                "raw_changes": sum(point["raw_ip_changed"] for point in series),
                "ignored_cdn_rotations": sum(
                    point["change_classification"] == "shared_cdn_rotation_ignored"
                    for point in series
                ),
            }
        )
    geo = c2_geo_table(run_dirs)
    plotted = sorted(
        {
            address
            for record in ordered
            if record.get("active", True)
            for address in (record["latest"] or {}).get("resolved_ips", [])
            if address in geo
        }
    )
    return {
        "runs": runs,
        "endpoints": ordered,
        "geo": geo,
        "ip_history": monitor_timelines + clickfix_dns_timeline(),
        "state_labels": {k: {"label": v[0], "tone": v[1]} for k, v in C2_STATE_LABELS.items()},
        "plotted_ips": plotted,
    }


def load_intel(known_shas: set[str]) -> dict:
    """intelligence調査が参照するcampaign相関候補とコード類似索引を集約する。

    - campaign候補: analysis-results/research/campaigns/correlated-*/campaigns.json
      の最新版(ディレクトリ名の辞書順末尾)を使う。
    - コード類似: catalog/code-similarity.json のexact group(意味トークン列の
      SHA-256完全一致)だけをcase間リンクへ集約する。SimHash近似は含めない。
    """
    campaigns: list[dict] = []
    labels: dict[str, list] = {}
    source = None

    camp_root = RESULTS / "research" / "campaigns"
    candidates = sorted(p for p in camp_root.glob("correlated-*") if p.is_dir())
    if candidates:
        latest = candidates[-1]
        source = latest.name
        data = read_json(latest / "campaigns.json") or {}
        for c in data.get("campaigns", []):
            cid = c.get("campaign_id")
            if not cid:
                continue
            cdir = latest / cid
            campaigns.append(
                {
                    "id": cid,
                    "classification": c.get("classification"),
                    "confidence": c.get("confidence"),
                    "families": c.get("families") or [],
                    "members": [m for m in (c.get("members") or []) if m in known_shas],
                    "member_count": c.get("member_count"),
                    "shared_indicators": c.get("shared_indicators") or [],
                    "shared_feature_ids": c.get("shared_feature_ids") or [],
                    "edge_count": c.get("edge_count"),
                    "max_pair_score": c.get("maximum_pair_score"),
                    "limitations": c.get("limitations") or [],
                    "path": cdir.relative_to(REPO_ROOT).as_posix() if cdir.is_dir() else None,
                    "rules": collect_rules(cdir / "rules", REPO_ROOT),
                    "readme": read_text(cdir / "README.md"),
                }
            )
        for sha, entries in (data.get("labels") or {}).items():
            if sha in known_shas:
                labels[sha] = [e.get("campaign_id") for e in entries if e.get("campaign_id")]

    code_links: list[list] = []
    code_meta = {"exact_groups": 0, "skipped_wide_groups": 0}
    cs = read_json(RESULTS / "catalog" / "code-similarity.json")
    if cs:
        rec_case = {
            r["record_id"]: r["sha256"]
            for r in cs.get("function_records", [])
            if r.get("record_id") and r.get("sha256")
        }
        pair_counts: Counter = Counter()
        for g in cs.get("exact_groups", []):
            cases = sorted({rec_case[m] for m in g.get("members", []) if m in rec_case})
            cases = [s for s in cases if s in known_shas]
            if len(cases) < 2:
                continue
            code_meta["exact_groups"] += 1
            if len(cases) > CODE_GROUP_CASE_CAP:
                code_meta["skipped_wide_groups"] += 1
                continue
            for a, b in itertools.combinations(cases, 2):
                pair_counts[(a, b)] += 1
        code_links = [
            [a, b, n]
            for (a, b), n in sorted(pair_counts.items(), key=lambda kv: -kv[1])
        ]

    return {
        "source": source,
        "campaigns": campaigns,
        "labels": labels,
        "code_links": code_links,
        "code_meta": code_meta,
    }


def detect_repo() -> dict | None:
    """GitHubリポジトリのHTML baseとbranchを推定する。

    GitHub Pagesのような軽量配信では成果物ファイル本体を同梱しないため、
    ケースの結果ディレクトリや成果物へのリンクをGitHub上の該当ファイルへ
    向ける。ローカル配信時に検出できなければNoneを返し、UIは相対パスへ
    フォールバックする。
    """
    slug = os.environ.get("MALDB_REPO_SLUG")
    if not slug:
        try:
            url = subprocess.run(
                ["git", "-C", str(REPO_ROOT), "remote", "get-url", "origin"],
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip()
            match = re.search(r"[/:]([^/:]+/[^/:]+?)(?:\.git)?$", url)
            if match:
                slug = match.group(1)
        except (OSError, subprocess.SubprocessError):
            slug = None
    if not slug:
        return None
    branch = os.environ.get("MALDB_REPO_BRANCH") or "main"
    return {"html_base": "https://github.com/" + slug, "branch": branch}


def _filesystem_case_index() -> dict[str, dict]:
    """UI対象の固定レイアウトcaseを実体から厳格に列挙する。"""

    discovered: dict[str, dict] = {}
    specifications = [
        (
            "malware/*/versions/*/cases/*",
            lambda parts: {
                "canonical_path": None,
                "case_id": None,
                "case_kind": "unclassified" if parts[1] == "unclassified" else "malware",
                "family": parts[1],
                "version_key": parts[3],
            },
        ),
        (
            "research/supply-chain/npm/axios-plain-crypto-js-2026/cases/*",
            lambda _parts: {
                "canonical_path": None,
                "case_id": None,
                "case_kind": "supply_chain_payload",
                "family": "npm-supply-chain",
                "version_key": None,
            },
        ),
    ]
    for pattern, identity_builder in specifications:
        for path in sorted(RESULTS.glob(pattern)):
            if not path.is_dir() or path.is_symlink():
                continue
            digest = path.name
            if not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise ValueError(f"不正なcaseディレクトリ名です: {path}")
            if digest in discovered:
                raise ValueError(f"同一SHA-256のcaseが重複しています: {digest}")
            parts = path.relative_to(RESULTS).parts
            identity = identity_builder(parts)
            identity["canonical_path"] = path.relative_to(REPO_ROOT).as_posix()
            identity["case_id"] = f"sha256:{digest}"
            discovered[digest] = identity
    return discovered


def existing_added_dates() -> dict[str, str]:
    """既存の data.js から added_at を読み出す。

    浅いクローンではgit履歴から追加日を復元できない。そこで既存の生成物の
    値を引き継ぐことで、環境差で `--check` が落ちたり、追加日が一括で
    消えることを防ぐ。
    """
    payload = parse_payload(read_text(OUTPUT))
    if payload is None:
        return {}
    return {
        c["sha256"]: c["added_at"]
        for c in payload.get("cases", [])
        if c.get("sha256") and c.get("added_at")
    }


def parse_payload(text: str) -> dict | None:
    """`window.MALDB = {...};` 形式の生成物からJSON本体を取り出す。"""
    if not text:
        return None
    try:
        return json.loads(text[text.index("=") + 1:].rstrip().rstrip(";"))
    except (ValueError, json.JSONDecodeError):
        return None


def only_unresolved_added_at(current: str, fresh: dict) -> bool:
    """差分が「commit前で確定しなかった added_at」だけかどうかを判定する。

    added_at は `git log --diff-filter=A` 由来のため、case を追加する commit
    そのものの中ではまだ確定しない。case追加とdata.js再生成を1コミットに
    まとめると生成時点では null になり、commit後に日付が付くので、この
    null→日付 の一方向だけは「未確定だった値が確定した」ものとして許容する。
    これを差分扱いにすると、case を追加するPRが構造的に必ず `--check` で
    落ちてしまう。配信されるdata.jsはワークフローが毎回再生成するため、
    公開内容は常に確定後の日付になる。
    """
    old = parse_payload(current)
    if old is None:
        return False
    old_cases = old.get("cases")
    new_cases = fresh.get("cases")
    if not isinstance(old_cases, list) or not isinstance(new_cases, list):
        return False
    if len(old_cases) != len(new_cases):
        return False
    if {k: v for k, v in old.items() if k != "cases"} != {
        k: v for k, v in fresh.items() if k != "cases"
    }:
        return False

    tolerated = False
    for old_case, new_case in zip(old_cases, new_cases):
        if old_case == new_case:
            continue
        # caseの並びは sha256 昇順で added_at に依存しない
        if old_case.get("sha256") != new_case.get("sha256"):
            return False
        if old_case.get("added_at") is not None or new_case.get("added_at") is None:
            return False
        patched = dict(old_case)
        patched["added_at"] = new_case["added_at"]
        if patched != new_case:
            return False
        tolerated = True
    return tolerated


def is_shallow_clone() -> bool:
    """浅いクローンかどうかを判定する。"""
    try:
        out = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "rev-parse", "--is-shallow-repository"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return False
    return out == "true"


def git_added_dates() -> dict[str, str]:
    """caseディレクトリがリポジトリへ追加されたcommit日をSHA-256ごとに得る。

    `analysis_history.yaml` は解析の正本だが、一括解析では履歴レコードが
    付かないcaseもあり網羅率が3割程度になる。ダッシュボードの新着一覧が
    履歴の有無で欠落しないよう、全caseに使える追加日をgitから取る。

    浅いクローン(CIの `actions/checkout` は既定で depth=1)では履歴が無く
    追加日を復元できないため、空を返して呼び出し側に既存値の引き継ぎを
    任せる。ここで部分的な結果を返すと、生成環境によって出力が変わり
    `--check` が落ちる。
    """
    if is_shallow_clone():
        return {}
    try:
        out = subprocess.run(
            [
                "git", "-C", str(REPO_ROOT), "log", "--diff-filter=A",
                "--name-only", "--date=short", "--format=%cd",
                "--", "analysis-results",
            ],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return {}

    date_re = re.compile(r"^\d{4}-\d{2}-\d{2}$")
    case_re = re.compile(r"^analysis-results/.*/cases/([0-9a-f]{64})/")
    added: dict[str, str] = {}
    current = None
    for line in out.splitlines():
        if date_re.fullmatch(line):
            current = line
            continue
        match = case_re.match(line)
        # git log は新しい順に出るため、最初に見えた日付が追加日
        if match and current and match.group(1) not in added:
            added[match.group(1)] = current
    return added


def discover_cases() -> dict[str, dict]:
    """catalogと固定レイアウトの完全一致を検証し、正本の全case一覧を返す。"""

    catalog = read_json(RESULTS / "catalog" / "cases.json")
    if not isinstance(catalog, dict) or catalog.get("schema_version") != 1:
        raise ValueError("analysis-results/catalog/cases.json が不正です")
    catalog_cases = catalog.get("cases")
    if not isinstance(catalog_cases, dict):
        raise ValueError("catalog cases はmappingでなければなりません")
    filesystem_cases = _filesystem_case_index()
    catalog_ids = set(catalog_cases)
    filesystem_ids = set(filesystem_cases)
    missing = sorted(filesystem_ids - catalog_ids)
    extra = sorted(catalog_ids - filesystem_ids)
    if missing or extra:
        raise ValueError(
            "catalogとcase実体が一致しません: "
            f"未登録={len(missing)} {missing[:3]}, 実体なし={len(extra)} {extra[:3]}"
        )
    for digest, expected in filesystem_cases.items():
        entry = catalog_cases[digest]
        if not isinstance(entry, dict):
            raise ValueError(f"catalog entryがobjectではありません: {digest}")
        mismatched = [
            key for key, value in expected.items() if entry.get(key) != value
        ]
        if mismatched:
            raise ValueError(
                f"catalog identityがcase実体と一致しません: {digest}: {mismatched}"
            )
    return dict(catalog_cases)


def build() -> dict:
    cases_catalog = discover_cases()
    history = load_history()
    added_dates = git_added_dates()
    if not added_dates:
        # 浅いクローンやgit不在の環境では既存生成物の値を引き継ぐ
        added_dates = existing_added_dates()
    labels = family_labels_from_index()

    families: dict[str, dict] = {}
    cases: list[dict] = []

    for sha, cat in sorted(cases_catalog.items()):
        rel_path = cat.get("canonical_path") or ""
        case_dir = REPO_ROOT / rel_path
        family = cat.get("family") or "unclassified"
        metadata = read_json(case_dir / "metadata.json") or {}
        features = read_json(case_dir / "features.json") or {}
        iocs_json = read_json(case_dir / "iocs.json") or {}
        ioc_md = read_text(case_dir / "IOC-LIST.md")
        ioc_entries = parse_ioc_list(ioc_md) if ioc_md else []

        source = metadata.get("source")
        if not isinstance(source, dict):
            source = {"provider": source} if source else {}
        reported = source.get("reported_metadata") or {}
        attribution = metadata.get("attribution") or {}
        if not isinstance(attribution, dict):
            attribution = {}
        assessment = features.get("analysis_assessment") or {}

        behaviors = [
            {
                "id": b.get("id"),
                "category": b.get("category"),
                "label": b.get("label"),
                "confidence": b.get("confidence"),
                "evidence": b.get("evidence"),
            }
            for b in features.get("behaviors") or []
        ]
        characteristics = [
            {
                "id": c.get("id"),
                "category": c.get("category"),
                "label": c.get("label"),
                "confidence": c.get("confidence"),
                "evidence": c.get("evidence"),
                "value": c.get("value"),
            }
            for c in features.get("sample_characteristics") or []
        ]

        docs = {}
        for key, filename in CASE_DOC_FILES:
            text = read_text(case_dir / filename)
            if text:
                docs[key] = text
        artifacts = sorted(
            p.relative_to(case_dir).as_posix()
            for p in case_dir.rglob("*")
            if p.is_file()
        )

        case_history = history.get(sha, [])
        c2_values = sorted(
            {c for h in case_history for c in h["c2"]}
            | {e["value"] for e in ioc_entries if is_network_indicator(e)}
            | structured_network_values(iocs_json)
        )

        case = {
            "sha256": sha,
            "family": family,
            "version_key": cat.get("version_key") or "unknown",
            "case_kind": cat.get("case_kind"),
            "path": rel_path,
            "file_name": reported.get("file_name"),
            "file_type": reported.get("file_type"),
            "file_size": reported.get("file_size"),
            "first_seen": reported.get("first_seen"),
            "provider": source.get("provider"),
            "reported_signature": attribution.get("reported_signature"),
            "tags": attribution.get("reported_tags") or [],
            "collections": metadata.get("collections") or [],
            # "unknown" は情報を持たないため表示・グラフの対象から外す
            "campaign_type": features.get("campaign_type")
            if features.get("campaign_type") not in (None, "", "unknown")
            else None,
            "assessment": {
                "score": assessment.get("score"),
                "max": assessment.get("maximum_score"),
                "status": assessment.get("status"),
                "unresolved": assessment.get("unresolved") or [],
                "next_actions": assessment.get("next_actions") or [],
            },
            "behaviors": behaviors,
            "characteristics": characteristics,
            "iocs": ioc_entries,
            "ioc_assessment": iocs_json.get("assessment"),
            "c2": c2_values,
            "history": case_history,
            # 履歴レコードが無いcaseでも新着順に並べられるようにする
            "added_at": added_dates.get(sha),
            "rules": collect_rules(case_dir / "rules", REPO_ROOT),
            "docs": docs,
            "artifacts": artifacts,
        }
        cases.append(case)

        fam = families.setdefault(
            family,
            {
                "key": family,
                "label": labels.get(family),
                "title": None,
                "aliases": None,
                "docs": {},
                "doc_titles": {},
                "rules": [],
                "case_count": 0,
            },
        )
        fam["case_count"] += 1

    # ファミリ単位の文書とルール
    for key, fam in families.items():
        fam_dir = RESULTS / "malware" / key
        if not fam_dir.is_dir():
            continue
        for doc_key, filename, doc_title in FAMILY_DOC_FILES:
            text = read_text(fam_dir / filename)
            if text:
                fam["docs"][doc_key] = text
                fam["doc_titles"][doc_key] = doc_title
        title, aliases = family_title_alias(fam["docs"].get("readme"))
        fam["title"] = title
        fam["aliases"] = aliases
        if fam["label"] is None:
            # README見出しは「<名前> 解析概要」形式のため接尾辞を除いて表示名にする
            label = re.sub(r"[ 　]*(の)?解析概要$", "", title) if title else None
            fam["label"] = label or key
        fam["rules"] = collect_rules(fam_dir / "rules", REPO_ROOT)

    # 履歴のうちcatalogに載っていないもの(調査ページ等)は対象外とし、件数だけ持つ
    known_shas = set(cases_catalog)
    orphan_history = sum(1 for sha in history if sha not in known_shas)

    intel = load_intel(known_shas)
    c2monitor = load_c2_monitoring(known_shas)

    stats = {
        "case_total": len(cases),
        "family_total": len(families),
        "ioc_total": sum(len(c["iocs"]) for c in cases),
        "rule_total": sum(len(f["rules"]) for f in families.values())
        + sum(len(c["rules"]) for c in cases),
        "history_total": sum(len(v) for v in history.values()),
        "orphan_history": orphan_history,
        "campaign_candidates": len(intel["campaigns"]),
        "code_links": len(intel["code_links"]),
        "c2_endpoints": len(c2monitor["endpoints"]),
        "c2_runs": len(c2monitor["runs"]),
        "c2_geo_ips": len(c2monitor["geo"]),
    }

    return {
        "schema_version": 1,
        "repo": detect_repo(),
        "stats": stats,
        "families": families,
        "cases": cases,
        "intel": intel,
        "c2monitor": c2monitor,
    }


def case_detail_path(sha: str) -> Path:
    """ケース詳細の格納先。1ディレクトリに数千ファイルを置かないよう2文字で分ける。"""
    return CASE_DETAIL_DIR / sha[:2] / f"{sha}.json"


def render_case_detail(sha: str, detail: dict) -> str:
    payload = {"schema_version": CASE_DETAIL_SCHEMA, "sha256": sha}
    payload.update(detail)
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n"


def split_case_details(data: dict) -> dict[str, dict]:
    """data から個別ページ専用の重いフィールドを抜き、SHA-256ごとに返す。

    抜くのは `docs`(ケースREADME全文)と `characteristics`。一覧・検索・
    ダッシュボードはどちらも参照しないため、全ケース分を先に配ると初回転送の
    半分以上が使われないまま落ちてくることになる。
    """
    details: dict[str, dict] = {}
    for case in data.get("cases") or []:
        sha = case.get("sha256")
        if not sha:
            continue
        details[sha] = {field: case.pop(field) for field in CASE_DETAIL_FIELDS if field in case}
    return details


def write_case_details(details: dict[str, dict]) -> tuple[int, int]:
    """ケース詳細を書き出し、catalogから消えたケースの残骸を削除する。"""
    written = 0
    expected: set[Path] = set()
    for sha, detail in details.items():
        path = case_detail_path(sha)
        expected.add(path)
        payload = render_case_detail(sha, detail)
        if read_text(path) != payload:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(payload, encoding="utf-8")
            written += 1
    removed = 0
    if CASE_DETAIL_DIR.is_dir():
        for path in sorted(CASE_DETAIL_DIR.rglob("*.json")):
            if path not in expected:
                path.unlink()
                removed += 1
        # 空になったシャードディレクトリを残さない
        for directory in sorted(CASE_DETAIL_DIR.iterdir(), reverse=True):
            if directory.is_dir() and not any(directory.iterdir()):
                directory.rmdir()
    return written, removed


def case_details_out_of_date(details: dict[str, dict]) -> list[str]:
    """ケース詳細の差分・欠落・余剰を列挙する。"""
    problems: list[str] = []
    expected: set[Path] = set()
    for sha, detail in sorted(details.items()):
        path = case_detail_path(sha)
        expected.add(path)
        current = read_text(path)
        if current is None:
            problems.append(f"欠落: {path.relative_to(UI_ROOT)}")
        elif current != render_case_detail(sha, detail):
            problems.append(f"内容差分: {path.relative_to(UI_ROOT)}")
    if CASE_DETAIL_DIR.is_dir():
        for path in sorted(CASE_DETAIL_DIR.rglob("*.json")):
            if path not in expected:
                problems.append(f"余剰: {path.relative_to(UI_ROOT)}")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="既存data.jsとの差分を確認する")
    args = parser.parse_args()

    data = build()
    details = split_case_details(data)
    payload = "window.MALDB = " + json.dumps(
        data, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ) + ";\n"

    if args.check:
        current = read_text(OUTPUT)
        index_ok = current == payload
        tolerated = not index_ok and only_unresolved_added_at(current, data)
        if not index_ok and not tolerated:
            print("ui/data.js is out of date. Run: python3 ui/generate_ui_data.py", file=sys.stderr)
            return 1
        problems = case_details_out_of_date(details)
        if problems:
            print(
                f"ui/cases が最新ではありません ({len(problems)}件)。"
                " Run: python3 ui/generate_ui_data.py",
                file=sys.stderr,
            )
            for line in problems[:10]:
                print(f"  {line}", file=sys.stderr)
            if len(problems) > 10:
                print(f"  ... 他 {len(problems) - 10} 件", file=sys.stderr)
            return 1
        if tolerated:
            print(
                "ui/data.js is up to date. "
                "(commit前で未確定だった added_at のみ差分。次回の再生成で解消されます)"
            )
        else:
            print("ui/data.js is up to date.")
        print(f"ui/cases is up to date. ({len(details)} ケース)")
        return 0

    OUTPUT.write_text(payload, encoding="utf-8")
    written, removed = write_case_details(details)
    size_mb = OUTPUT.stat().st_size / (1024 * 1024)
    detail_bytes = sum(p.stat().st_size for p in CASE_DETAIL_DIR.rglob("*.json"))
    print(f"wrote {OUTPUT} ({size_mb:.1f} MiB)")
    print(
        f"wrote {CASE_DETAIL_DIR} ({len(details)} ケース / "
        f"{detail_bytes / (1024 * 1024):.1f} MiB、更新 {written}件、削除 {removed}件)"
    )
    print(json.dumps(data["stats"], ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
