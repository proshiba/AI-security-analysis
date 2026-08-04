#!/usr/bin/env python3
"""PCAPからスティーラー系HTTP通信の公開可能な構造証拠を生成する。

本文値、token、victim metadata、query文字列は保持しない。Wiresharkの
``tshark``を使って、socket接続先、HTTP Host、URI path、Content-Type、
フォームのkey名、multipartのnameだけを抽出する。検体や復元payloadは
実行せず、外部hostにも接続しない。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.parse import urlsplit

MAX_PCAP_SIZE = 512 * 1024 * 1024
MAX_REPORT_SIZE = 64 * 1024 * 1024
MAX_TSHARK_OUTPUT = 64 * 1024 * 1024
MULTIPART_NAME = re.compile(
    r'(?:^|;)\s*name="([^"\r\n]{1,128})"', re.IGNORECASE
)
SAFE_FIELD = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")

TSHARK_FIELDS = (
    "frame.number",
    "ip.dst",
    "tcp.dstport",
    "http.host",
    "http.request.method",
    "http.request.uri",
    "http.content_type",
    "http.content_length",
    "urlencoded-form.key",
    "mime_multipart.header.content-disposition",
)


@dataclass(frozen=True)
class HttpRequestEvidence:
    """値を除外した1件のHTTP要求証拠。"""

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


def _bounded_bytes(path: Path, maximum: int) -> bytes:
    """上限を超えないfileだけを読み込む。"""
    size = path.stat().st_size
    if size > maximum:
        raise ValueError(f"{path.name}が{maximum} byte上限を超えています")
    return path.read_bytes()


def _safe_names(value: str) -> tuple[str, ...]:
    """区切られたkey名から公開可能な識別子だけを返す。"""
    return tuple(
        dict.fromkeys(
            item
            for item in value.split(";")
            if SAFE_FIELD.fullmatch(item)
        )
    )


def _safe_path(uri: str) -> str:
    """queryとfragmentを除外し、pathだけを保持する。"""
    if not uri:
        return ""
    try:
        parsed = urlsplit(uri)
    except ValueError:
        return ""
    path = parsed.path or "/"
    if not path.startswith("/") or any(ord(char) < 0x20 for char in path):
        return ""
    return path[:2048]


def parse_tshark_rows(text: str) -> list[HttpRequestEvidence]:
    """固定fieldのTSVを解析し、本文値を保持しない要求一覧へ変換する。"""
    results: list[HttpRequestEvidence] = []
    for line in text.splitlines():
        columns = line.split("\t")
        columns.extend([""] * (len(TSHARK_FIELDS) - len(columns)))
        if len(columns) < len(TSHARK_FIELDS):
            continue
        try:
            frame = int(columns[0])
            port = int(columns[2])
        except ValueError:
            continue
        length: int | None
        try:
            length = int(columns[7]) if columns[7] else None
        except ValueError:
            length = None
        multipart_names = tuple(
            dict.fromkeys(
                name
                for name in MULTIPART_NAME.findall(columns[9])
                if SAFE_FIELD.fullmatch(name)
            )
        )
        results.append(
            HttpRequestEvidence(
                frame=frame,
                destination_ip=columns[1],
                destination_port=port,
                http_host=columns[3].lower().rstrip("."),
                method=columns[4].upper(),
                uri_path=_safe_path(columns[5]),
                content_type=columns[6].split(";", 1)[0].lower(),
                content_length=length,
                form_keys=_safe_names(columns[8]),
                multipart_names=multipart_names,
            )
        )
    return results


def run_tshark(pcap: Path, executable: Path) -> list[HttpRequestEvidence]:
    """PCAPを読み取り専用で解析し、HTTP要求の構造だけを返す。"""
    _bounded_bytes(pcap, MAX_PCAP_SIZE)
    command = [
        str(executable),
        "-r",
        str(pcap),
        "-Y",
        "http.request",
        "-T",
        "fields",
        "-E",
        "occurrence=a",
        "-E",
        "aggregator=;",
    ]
    for field in TSHARK_FIELDS:
        command.extend(("-e", field))
    completed = subprocess.run(
        command,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
    )
    if len(completed.stdout.encode("utf-8")) > MAX_TSHARK_OUTPUT:
        raise ValueError("tshark出力が上限を超えています")
    return parse_tshark_rows(completed.stdout)


def _flow_domain_map(report_path: Path | None) -> tuple[dict[tuple[str, int], set[str]], dict[str, object]]:
    """Triage報告からsocket endpointとDNS名の対応だけを取得する。"""
    if report_path is None:
        return {}, {}
    report = json.loads(_bounded_bytes(report_path, MAX_REPORT_SIZE))
    network = report.get("network") if isinstance(report, dict) else None
    mapping: dict[tuple[str, int], set[str]] = defaultdict(set)
    if isinstance(network, dict):
        for flow in network.get("flows", []):
            if not isinstance(flow, dict):
                continue
            destination = flow.get("dst")
            domain = flow.get("domain")
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


def classify_protocol(
    requests: list[HttpRequestEvidence], family_hint: str | None
) -> dict[str, object]:
    """要求順序を既知プロトコル形状と照合し、能動確認の安全方針も付ける。"""
    key_sets = [set(item.form_keys) for item in requests]
    multipart_sets = [set(item.multipart_names) for item in requests]
    family = (family_hint or "").lower().replace("-", "")

    remus_evidence = {
        "registration": any({"tag", "exp", "hwid"} <= keys for keys in key_sets),
        "token_debug": any({"access_token", "debug"} <= keys for keys in key_sets),
        "token_step": any({"access_token", "step"} <= keys for keys in key_sets),
        "file_upload": any(
            {"access_token", "type", "file"} <= names for names in multipart_sets
        ),
    }
    if all(remus_evidence.values()):
        return {
            "profile": "remus_http_token_task_file",
            "confidence": "high" if family in {"remus", "remusstealer"} else "medium",
            "evidence": remus_evidence,
            "active_probe_policy": "guarded_active_reviewed_profile_only",
            "active_probe_reason": "完全一致profileと二重許可時だけ合成登録し、token非公開でstep=1を1回取得します。",
        }

    lumma_evidence = {
        "uid_cid_registration": any({"uid", "cid"} <= keys for keys in key_sets),
        "multipart_exfil": any(
            {"uid", "pid", "hwid", "file"} <= names for names in multipart_sets
        ),
        "browser_agent_path": any(item.uri_path == "/api/set_agent" for item in requests),
    }
    if lumma_evidence["uid_cid_registration"] and lumma_evidence["multipart_exfil"]:
        return {
            "profile": "lumma_v6_compatible_uid_cid",
            "confidence": "high" if family in {"lumma", "lummastealer"} else "medium",
            "evidence": lumma_evidence,
            "active_probe_policy": "guarded_active_reviewed_profile_only",
            "active_probe_reason": "完全一致v6 profileと二重許可時だけuid/cidと合成hwidを各1回送信します。",
        }

    json_posts = [
        item
        for item in requests
        if item.method == "POST" and item.content_type == "application/json"
    ]
    if json_posts and family in {"stealc"}:
        return {
            "profile": "stealc_v2_json_transport_compatible",
            "confidence": "medium",
            "evidence": {
                "json_post_count": len(json_posts),
                "paths": sorted({item.uri_path for item in json_posts}),
            },
            "active_probe_policy": "guarded_active_reviewed_profile_only",
            "active_probe_reason": "完全一致profileと二重許可時だけ合成hwidでcreateし、loader taskを1回取得します。",
        }

    if family in {"formbook", "xloader"}:
        return {
            "profile": "formbook_xloader_terminal_protocol_not_observed",
            "confidence": "low",
            "evidence": {"http_request_count": len(requests)},
            "active_probe_policy": "passive_only",
            "active_probe_reason": "decoy domainと404偽装のため、復号済みmain URIと鍵なしのHTTP応答はC2確認になりません。",
        }

    return {
        "profile": "unclassified_http_sequence",
        "confidence": "low",
        "evidence": {"http_request_count": len(requests)},
        "active_probe_policy": "passive_only",
        "active_probe_reason": "既知プロトコルの必要条件を満たさないため、能動probeを構成しません。",
    }


def build_report(
    pcap: Path,
    requests: list[HttpRequestEvidence],
    family_hint: str | None = None,
    triage_report: Path | None = None,
) -> dict[str, object]:
    """公開可能なendpoint集約、要求列、分類、安全方針を構成する。"""
    domain_map, provenance = _flow_domain_map(triage_report)
    endpoint_counts: Counter[tuple[str, int, str]] = Counter(
        (item.destination_ip, item.destination_port, item.http_host)
        for item in requests
    )
    endpoints = []
    for (destination_ip, destination_port, http_host), count in sorted(endpoint_counts.items()):
        resolved_domains = sorted(domain_map.get((destination_ip, destination_port), set()))
        endpoints.append(
            {
                "destination_ip": destination_ip,
                "destination_port": destination_port,
                "resolved_domains": resolved_domains,
                "http_host": http_host,
                "host_misdirection": bool(
                    resolved_domains and http_host and http_host not in resolved_domains
                ),
                "request_count": count,
            }
        )
    return {
        "schema_version": 1,
        "family_hint": family_hint,
        "pcap_sha256": hashlib.sha256(_bounded_bytes(pcap, MAX_PCAP_SIZE)).hexdigest(),
        "provenance": provenance,
        "request_count": len(requests),
        "endpoints": endpoints,
        "requests": [asdict(item) for item in requests],
        "classification": classify_protocol(requests, family_hint),
        "privacy": {
            "body_values_retained": False,
            "query_values_retained": False,
            "tokens_retained": False,
            "form_field_names_retained": True,
        },
        "execution": {"sample_executed_locally": False, "network_contacted": False},
    }


def main() -> int:
    """CLI入口。"""
    parser = argparse.ArgumentParser(
        description="スティーラー系PCAPから値を除いたHTTPプロトコル証拠を生成します"
    )
    parser.add_argument("--pcap", type=Path, required=True)
    parser.add_argument("--tshark", type=Path, required=True)
    parser.add_argument("--family")
    parser.add_argument("--triage-report", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    requests = run_tshark(args.pcap, args.tshark)
    report = build_report(
        args.pcap,
        requests,
        family_hint=args.family,
        triage_report=args.triage_report,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
