#!/usr/bin/env python3
"""PCAPから値を公開せず、stealer系HTTP C2の構造証拠を判定する。

本文、query値、token、filename、victim metadata、User-Agent原文は保持しない。
同一socket endpointに属する要求の順序とfield名、および複数endpointに共通する
fan-outだけを照合し、単独のHTTP status、Host、port、domain、一般的なJSON POSTをC2確認へ昇格しない。
"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import re
import subprocess
from typing import Any, Callable
from urllib.parse import unquote, urlsplit

MAX_PCAP_SIZE = 512 * 1024 * 1024
MAX_REPORT_SIZE = 64 * 1024 * 1024
MAX_PROFILE_SIZE = 4 * 1024 * 1024
MAX_TSHARK_OUTPUT = 64 * 1024 * 1024
MULTIPART_NAME = re.compile(r'(?:^|;)\s*name="([^"\r\n]{1,128})"', re.IGNORECASE)
SAFE_FIELD = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
AMOS_LEDGER_PATH = re.compile(r"^/ledger/(?:(live)/)?([0-9a-f]{64})/?$", re.IGNORECASE)
FORMBOOK_ROUTE_PATH = re.compile(r"^/[A-Za-z0-9]{4}/$")
FORMBOOK_MIN_FANOUT_ENDPOINTS = 6

TSHARK_FIELDS = (
    "frame.number", "ip.dst", "tcp.dstport", "http.host",
    "http.request.method", "http.request.uri", "http.content_type",
    "http.content_length", "urlencoded-form.key",
    "mime_multipart.header.content-disposition", "http.user_agent",
)


@dataclass(frozen=True)
class HttpRequestEvidence:
    """値を除去した1件のHTTP要求証拠。"""

    frame: int
    destination_ip: str
    destination_port: int
    http_host: str
    method: str
    uri_path: str
    content_type: str
    content_length: int | None
    form_keys: tuple[str, ...]
    multipart_names: tuple[str, ...]
    query_keys: tuple[str, ...] = ()
    user_agent_sha256: str | None = None


def _bounded_bytes(path: Path, maximum: int) -> bytes:
    """上限を超えない通常fileだけを読み込む。"""

    if not path.is_file():
        raise ValueError(f"通常fileではありません: {path}")
    if path.stat().st_size > maximum:
        raise ValueError(f"{path.name}は{maximum} byte上限を超えています")
    return path.read_bytes()


def _safe_names(value: str) -> tuple[str, ...]:
    """区切られた名前から公開可能な識別子だけを返す。"""

    return tuple(dict.fromkeys(item for item in value.split(";") if SAFE_FIELD.fullmatch(item)))


def _split_uri(uri: str) -> tuple[str, tuple[str, ...]]:
    """URIから安全なpathとquery名だけを取り出す。"""

    if not uri:
        return "", ()
    try:
        parsed = urlsplit(uri)
    except ValueError:
        return "", ()
    path = parsed.path or "/"
    if not path.startswith("/") or any(ord(char) < 0x20 for char in path):
        return "", ()
    names: list[str] = []
    for pair in parsed.query.split("&"):
        name = pair.partition("=")[0]
        try:
            name = unquote(name, errors="strict")
        except UnicodeError:
            continue
        if SAFE_FIELD.fullmatch(name) and name not in names:
            names.append(name)
    return path[:2048], tuple(names)


def _user_agent_sha256(value: str) -> str | None:
    """公開せず照合できるよう、妥当なUser-Agentだけをhash化する。"""

    if not value or len(value) > 512 or any(ord(char) < 0x20 for char in value):
        return None
    return hashlib.sha256(value.encode()).hexdigest()


def parse_tshark_rows(text: str) -> list[HttpRequestEvidence]:
    """固定fieldのTSVを、値を保持しない要求一覧へ変換する。"""

    results: list[HttpRequestEvidence] = []
    for line in text.splitlines():
        columns = line.split("\t")
        columns.extend([""] * (len(TSHARK_FIELDS) - len(columns)))
        try:
            frame = int(columns[0])
            port = int(columns[2])
        except (IndexError, ValueError):
            continue
        try:
            length = int(columns[7]) if columns[7] else None
        except ValueError:
            length = None
        names = tuple(
            dict.fromkeys(
                name for name in MULTIPART_NAME.findall(columns[9]) if SAFE_FIELD.fullmatch(name)
            )
        )
        path, query_keys = _split_uri(columns[5])
        results.append(
            HttpRequestEvidence(
                frame, columns[1], port, columns[3].lower().rstrip("."),
                columns[4].upper(), path, columns[6].split(";", 1)[0].lower(),
                length, _safe_names(columns[8]), names, query_keys,
                _user_agent_sha256(columns[10]),
            )
        )
    return results


def run_tshark(pcap: Path, executable: Path) -> list[HttpRequestEvidence]:
    """PCAPを専用processで解析し、HTTP要求の構造だけを返す。"""

    _bounded_bytes(pcap, MAX_PCAP_SIZE)
    command = [
        str(executable), "-r", str(pcap), "-Y", "http.request", "-T", "fields",
        "-E", "occurrence=a", "-E", "aggregator=;",
    ]
    for field in TSHARK_FIELDS:
        command.extend(("-e", field))
    completed = subprocess.run(
        command, check=True, capture_output=True, text=True, encoding="utf-8",
        errors="replace", timeout=120,
    )
    if len(completed.stdout.encode()) > MAX_TSHARK_OUTPUT:
        raise ValueError("tshark出力が上限を超えています")
    return parse_tshark_rows(completed.stdout)


EndpointKey = tuple[str, int, str]
Predicate = Callable[[HttpRequestEvidence], bool]


def _endpoint_groups(requests: list[HttpRequestEvidence]) -> dict[EndpointKey, list[HttpRequestEvidence]]:
    groups: dict[EndpointKey, list[HttpRequestEvidence]] = defaultdict(list)
    for item in requests:
        groups[(item.destination_ip, item.destination_port, item.http_host)].append(item)
    for items in groups.values():
        items.sort(key=lambda item: item.frame)
    return groups


def _ordered_frames(items: list[HttpRequestEvidence], predicates: tuple[Predicate, ...]) -> tuple[int, ...] | None:
    frames: list[int] = []
    start = 0
    for predicate in predicates:
        for index in range(start, len(items)):
            if predicate(items[index]):
                frames.append(items[index].frame)
                start = index + 1
                break
        else:
            return None
    return tuple(frames)


def _sequence_match(
    requests: list[HttpRequestEvidence], predicates: tuple[Predicate, ...]
) -> tuple[EndpointKey, tuple[int, ...], list[HttpRequestEvidence]] | None:
    for endpoint, items in sorted(_endpoint_groups(requests).items()):
        if (frames := _ordered_frames(items, predicates)) is not None:
            return endpoint, frames, items
    return None


def _has_form(required: set[str]) -> Predicate:
    return lambda item: item.method == "POST" and required <= set(item.form_keys)


def _has_multipart(required: set[str]) -> Predicate:
    return lambda item: (
        item.method == "POST" and item.content_type == "multipart/form-data"
        and required <= set(item.multipart_names)
    )


def _classification(
    *, profile: str, confidence: str, evidence: dict[str, object],
    active_policy: str, reason: str,
) -> dict[str, object]:
    return {
        "profile": profile, "confidence": confidence, "evidence": evidence,
        "active_probe_policy": active_policy, "active_probe_reason": reason,
    }


def _classify_remus(requests: list[HttpRequestEvidence], family: str) -> dict[str, object] | None:
    match = _sequence_match(
        requests,
        (
            _has_form({"tag", "exp", "hwid"}), _has_form({"access_token", "debug"}),
            _has_form({"access_token", "step"}),
            _has_multipart({"access_token", "type", "file"}),
        ),
    )
    if match is None:
        return None
    _, frames, _ = match
    return _classification(
        profile="remus_http_token_task_file",
        confidence="high" if family in {"remus", "remusstealer"} else "medium",
        evidence={"same_endpoint": True, "ordered_frames": list(frames), "field_values_published": False},
        active_policy="guarded_active_reviewed_profile_only",
        reason="復号済み完全一致profileと二重の明示許可がある場合だけ、合成登録を1回送信します。",
    )


def _classify_lumma(requests: list[HttpRequestEvidence], family: str) -> dict[str, object] | None:
    match = _sequence_match(
        requests,
        (_has_form({"uid", "cid"}), _has_multipart({"uid", "pid", "hwid", "file"})),
    )
    if match is None:
        return None
    _, frames, items = match
    browser_agent = any(
        item.uri_path == "/api/set_agent" and frames[0] < item.frame < frames[1] for item in items
    )
    return _classification(
        profile="lumma_v6_compatible_uid_cid",
        confidence="high" if family in {"lumma", "lummastealer"} else "medium",
        evidence={
            "same_endpoint": True, "ordered_frames": list(frames),
            "browser_agent_path_between_steps": browser_agent, "field_values_published": False,
        },
        active_policy="guarded_active_reviewed_profile_only",
        reason="完全一致v6 profileと二重の明示許可がある場合だけ、合成uid/cidを1回送信します。",
    )


def _classify_stealc(requests: list[HttpRequestEvidence], family: str) -> dict[str, object] | None:
    if family not in {"stealc", "stealcv2"}:
        return None
    for items in _endpoint_groups(requests).values():
        by_path: dict[str, list[HttpRequestEvidence]] = defaultdict(list)
        for item in items:
            if item.method == "POST" and item.content_type == "application/json":
                by_path[item.uri_path].append(item)
        for path, posts in sorted(by_path.items()):
            if path and len(posts) >= 2 and posts[0].frame < posts[1].frame:
                return _classification(
                    profile="stealc_v2_json_transport_compatible", confidence="medium",
                    evidence={
                        "same_endpoint": True, "same_path": True,
                        "ordered_frames": [posts[0].frame, posts[1].frame],
                        "json_post_count": len(posts), "body_values_published": False,
                    },
                    active_policy="guarded_active_reviewed_profile_only",
                    reason="RC4鍵、build、endpointを固定したreview済みprofileだけが登録responseを確認できます。",
                )
    return None


def _valid_vidar_records(profile: dict[str, Any] | None) -> list[tuple[str, int, str, str]]:
    if not isinstance(profile, dict):
        return []
    family = str(profile.get("family", "vidar")).lower().replace("-", "")
    if family not in {"vidar", "vidarstealer"}:
        return []
    candidate = profile.get("config") if isinstance(profile.get("config"), dict) else profile
    if candidate.get("profile") != "vidar_repeated_xor_v1_5_plus":
        return []
    records = candidate.get("records")
    if not isinstance(records, list):
        return []
    valid: list[tuple[str, int, str, str]] = []
    for record in records[:32]:
        if not isinstance(record, dict):
            continue
        url, user_agent = record.get("url"), record.get("user_agent")
        if not isinstance(url, str) or not isinstance(user_agent, str):
            continue
        try:
            parsed = urlsplit(url)
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
        except ValueError:
            continue
        if (
            parsed.scheme not in {"http", "https"} or not parsed.hostname
            or parsed.username is not None or parsed.password is not None
            or not 1 <= port <= 65535
        ):
            continue
        if ua_hash := _user_agent_sha256(user_agent):
            valid.append((parsed.hostname.lower().rstrip("."), port, parsed.path or "/", ua_hash))
    return valid


def _classify_vidar(
    requests: list[HttpRequestEvidence], family: str, reviewed_profile: dict[str, Any] | None
) -> dict[str, object] | None:
    if family not in {"vidar", "vidarstealer"}:
        return None
    for record_index, (host, port, path, ua_hash) in enumerate(_valid_vidar_records(reviewed_profile)):
        for item in requests:
            host_match = item.http_host == host or (not item.http_host and item.destination_ip == host)
            if (
                host_match and item.destination_port == port and item.uri_path == path
                and item.user_agent_sha256 == ua_hash
            ):
                return _classification(
                    profile="vidar_static_profile_endpoint_match", confidence="high",
                    evidence={
                        "reviewed_profile": True, "record_index": record_index, "frame": item.frame,
                        "endpoint_value_published": False, "user_agent_value_published": False,
                    },
                    active_policy="passive_only",
                    reason="静的復元profileとの完全一致は受動確認にだけ使い、未知のVidar serverへ要求を送りません。",
                )
    return None


def _classify_amos(requests: list[HttpRequestEvidence], family: str) -> dict[str, object] | None:
    for items in _endpoint_groups(requests).values():
        first: dict[str, int] = {}
        for item in items:
            match = AMOS_LEDGER_PATH.fullmatch(item.uri_path)
            if item.method != "POST" or match is None:
                continue
            live, identifier = match.groups()
            identifier = identifier.lower()
            if not live:
                first.setdefault(identifier, item.frame)
                continue
            if (initial := first.get(identifier)) is not None and initial < item.frame:
                return _classification(
                    profile="amos_ledger_campaign_pair",
                    confidence="high" if family in {"amos", "amosstealer", "atomicmacosstealer"} else "medium",
                    evidence={
                        "same_endpoint": True, "same_campaign_identifier": True,
                        "ordered_frames": [initial, item.frame], "campaign_identifier_published": False,
                    },
                    active_policy="passive_only",
                    reason="被害端末由来データを送信し得るため、ledger経路は受動観測だけで照合します。",
                )
    return None


def _classify_formbook(
    requests: list[HttpRequestEvidence], family: str
) -> dict[str, object] | None:
    """FormBook/XLoaderの複数endpoint fan-outを値なしで照合する。"""

    RouteKey = tuple[EndpointKey, str, str]
    routes: dict[RouteKey, dict[str, object]] = {}
    for item in requests:
        if (
            FORMBOOK_ROUTE_PATH.fullmatch(item.uri_path) is None
            or item.user_agent_sha256 is None
        ):
            continue
        key = (
            (item.destination_ip, item.destination_port, item.http_host),
            item.uri_path,
            item.user_agent_sha256,
        )
        record = routes.setdefault(
            key,
            {"get_query_pairs": Counter(), "get_count": 0, "post_count": 0},
        )
        if item.method == "GET" and len(item.query_keys) == 2:
            record["get_count"] = int(record["get_count"]) + 1
            pairs = record["get_query_pairs"]
            assert isinstance(pairs, Counter)
            pairs[item.query_keys] += 1
        elif item.method == "POST" and not item.query_keys:
            record["post_count"] = int(record["post_count"]) + 1

    bindings: Counter[tuple[str, tuple[str, str]]] = Counter()
    for (*_, user_agent_hash), record in routes.items():
        pairs = record["get_query_pairs"]
        assert isinstance(pairs, Counter)
        if int(record["post_count"]) < 1:
            continue
        for pair in pairs:
            if len(pair) == 2:
                bindings[(user_agent_hash, pair)] += 1
    if not bindings:
        return None
    binding, _ = sorted(bindings.items(), key=lambda item: (-item[1], item[0]))[0]
    user_agent_hash, query_pair = binding
    matched = []
    for key, record in routes.items():
        pairs = record["get_query_pairs"]
        assert isinstance(pairs, Counter)
        if (
            key[2] == user_agent_hash
            and query_pair in pairs
            and int(record["post_count"]) >= 1
        ):
            matched.append((key, record))
    endpoint_count = len({key[0] for key, _ in matched})
    route_count = len({key[1] for key, _ in matched})
    if (
        endpoint_count < FORMBOOK_MIN_FANOUT_ENDPOINTS
        or route_count < FORMBOOK_MIN_FANOUT_ENDPOINTS
    ):
        return None
    get_count = sum(int(record["get_count"]) for _, record in matched)
    post_count = sum(int(record["post_count"]) for _, record in matched)
    return _classification(
        profile="formbook_xloader_http_route_fanout",
        confidence="high" if family in {"formbook", "xloader"} else "medium",
        evidence={
            "same_user_agent": True,
            "endpoint_count": endpoint_count,
            "unique_route_count": route_count,
            "query_get_count": get_count,
            "same_route_post_count": post_count,
            "query_parameter_count": 2,
            "route_values_published": False,
            "query_values_published": False,
            "user_agent_value_published": False,
        },
        active_policy="reviewed_route_head_only",
        reason=(
            "複数endpointへのfan-outは受動証拠として扱います。能動確認は完全一致profile、"
            "数値IP pin、同値acknowledgementを要求するbodyなしHEADと陰性対照だけです。"
        ),
    )


def classify_protocol(
    requests: list[HttpRequestEvidence], family_hint: str | None,
    reviewed_profile: dict[str, Any] | None = None,
) -> dict[str, object]:
    """要求順序を既知profileと照合し、能動確認の安全方針も返す。"""

    family = (family_hint or "").lower().replace("-", "")
    for classifier in (
        lambda: _classify_remus(requests, family),
        lambda: _classify_lumma(requests, family),
        lambda: _classify_stealc(requests, family),
        lambda: _classify_vidar(requests, family, reviewed_profile),
        lambda: _classify_amos(requests, family),
        lambda: _classify_formbook(requests, family),
    ):
        if (result := classifier()) is not None:
            return result
    if family in {"formbook", "xloader"}:
        return _classification(
            profile="formbook_xloader_terminal_protocol_not_observed", confidence="low",
            evidence={"http_request_count": len(requests), "terminal_wire_signature_matched": False},
            active_policy="passive_only",
            reason="terminal URI、鍵、復号可能なresponseが揃わないため、一般的なHTTP形状をC2確認に使いません。",
        )
    return _classification(
        profile="unclassified_http_sequence", confidence="low",
        evidence={"http_request_count": len(requests)}, active_policy="passive_only",
        reason="同一endpoint上の必須field集合と順序が一致しないため、能動probeを構成しません。",
    )


def _flow_domain_map(report_path: Path | None) -> tuple[dict[tuple[str, int], set[str]], dict[str, object]]:
    if report_path is None:
        return {}, {}
    report = json.loads(_bounded_bytes(report_path, MAX_REPORT_SIZE))
    network = report.get("network") if isinstance(report, dict) else None
    mapping: dict[tuple[str, int], set[str]] = defaultdict(set)
    if isinstance(network, dict):
        for flow in network.get("flows", []):
            if not isinstance(flow, dict):
                continue
            destination, domain = flow.get("dst"), flow.get("domain")
            if not isinstance(destination, str) or not isinstance(domain, str):
                continue
            host, separator, port_text = destination.rpartition(":")
            if not separator:
                continue
            try:
                port = int(port_text)
            except ValueError:
                continue
            mapping[(host, port)].add(domain.lower().rstrip("."))
    sample = report.get("sample", {}) if isinstance(report, dict) else {}
    analysis = report.get("analysis", {}) if isinstance(report, dict) else {}
    provenance = {
        "provider": "Hatching Triage",
        "sample_id": sample.get("id") if isinstance(sample, dict) else None,
        "sample_sha256": sample.get("sha256") if isinstance(sample, dict) else None,
        "submitted": sample.get("submitted") if isinstance(sample, dict) else None,
        "reported": analysis.get("reported") if isinstance(analysis, dict) else None,
    }
    return mapping, {key: value for key, value in provenance.items() if value is not None}


def build_report(
    pcap: Path, requests: list[HttpRequestEvidence], family_hint: str | None = None,
    triage_report: Path | None = None, reviewed_profile: dict[str, Any] | None = None,
) -> dict[str, object]:
    """公開可能なendpoint集約、要求列、判定、安全方針を構成する。"""

    domain_map, provenance = _flow_domain_map(triage_report)
    counts: Counter[EndpointKey] = Counter(
        (item.destination_ip, item.destination_port, item.http_host) for item in requests
    )
    endpoints = []
    for (destination_ip, destination_port, http_host), count in sorted(counts.items()):
        domains = sorted(domain_map.get((destination_ip, destination_port), set()))
        endpoints.append(
            {
                "destination_ip": destination_ip, "destination_port": destination_port,
                "resolved_domains": domains, "http_host": http_host,
                "host_misdirection": bool(domains and http_host and http_host not in domains),
                "request_count": count,
            }
        )
    return {
        "schema_version": 2, "family_hint": family_hint,
        "pcap_sha256": hashlib.sha256(_bounded_bytes(pcap, MAX_PCAP_SIZE)).hexdigest(),
        "provenance": provenance, "request_count": len(requests), "endpoints": endpoints,
        "requests": [asdict(item) for item in requests],
        "classification": classify_protocol(requests, family_hint, reviewed_profile),
        "privacy": {
            "body_values_retained": False, "query_values_retained": False,
            "tokens_retained": False, "filenames_retained": False,
            "user_agent_values_retained": False, "form_field_names_retained": True,
        },
        "execution": {"sample_executed_locally": False, "network_contacted": False},
    }


def _load_reviewed_profile(path: Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    value = json.loads(_bounded_bytes(path, MAX_PROFILE_SIZE))
    if not isinstance(value, dict):
        raise ValueError("reviewed profileはJSON objectである必要があります")
    return value


def main() -> int:
    """CLI入口。"""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pcap", type=Path, required=True)
    parser.add_argument("--tshark", type=Path, required=True)
    parser.add_argument("--family")
    parser.add_argument("--triage-report", type=Path)
    parser.add_argument("--reviewed-profile", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = build_report(
        args.pcap, run_tshark(args.pcap, args.tshark), args.family,
        args.triage_report, _load_reviewed_profile(args.reviewed_profile),
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
