#!/usr/bin/env python3
"""レビュー済みC2候補を限定観測し、JSONと日本語Markdownを生成する。"""
from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from c2_detector import probe


HOST_RE = re.compile(r"(?=.{1,253}$)[A-Za-z0-9.-]+")
SHA256_RE = re.compile(r"[0-9a-f]{64}")
ALLOWED_PROTOCOLS = {"tcp", "http", "https", "tls"}
ALLOWED_METHODS = {"tcp_connect", "passive_banner", "tls_handshake", "http_get"}
ALLOWED_TRANSPORTS = {"direct", "tor-socks5"}
METHOD_CEILINGS = {
    "tcp_connect": 0.25,
    "passive_banner": 0.55,
    "tls_handshake": 0.45,
    "http_get": 0.60,
}
METHOD_LABELS = {
    "tcp_connect": "DNS解決＋単一TCP接続（送受信なし）",
    "passive_banner": "DNS解決＋単一TCP接続＋server-first banner限定受信",
    "tls_handshake": "DNS解決＋単一TLS handshake（application dataなし）",
    "http_get": "DNS解決＋TLS/HTTP GET 1回（redirectなし）",
}
SAFE_HTTP_HEADERS = {"server", "content-type", "content-length", "date", "connection"}


class PlanError(ValueError):
    """監視計画が安全制約を満たさない場合のエラー。"""


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def validate_plan(plan: dict) -> dict:
    """完全一致ターゲット、上限、根拠、probe種別を検証する。"""
    if not isinstance(plan, dict) or plan.get("schema_version") != 1:
        raise PlanError("schema_version=1 のobjectが必要です")
    window = plan.get("analysis_window")
    if not isinstance(window, dict) or not window.get("start") or not window.get("end"):
        raise PlanError("analysis_window.start/end が必要です")
    targets = plan.get("targets")
    if not isinstance(targets, list) or not targets:
        raise PlanError("targets は1件以上のlistである必要があります")
    if len(targets) > 256:
        raise PlanError("1回の監視対象は256 endpoint以下です")

    seen: set[tuple] = set()
    for target in targets:
        if not isinstance(target, dict):
            raise PlanError("targetはobjectである必要があります")
        host = str(target.get("host", "")).lower()
        if not HOST_RE.fullmatch(host) or "*" in host or "/" in host:
            raise PlanError(f"完全一致hostではありません: {host}")
        if not _is_ip(host) and "." not in host:
            raise PlanError(f"FQDNまたはIPではありません: {host}")
        port = target.get("port")
        if not isinstance(port, int) or not 1 <= port <= 65535:
            raise PlanError(f"portが不正です: {port}")
        protocol = target.get("protocol", "tcp")
        method = target.get("method", "tcp_connect")
        transport = target.get("transport", "direct")
        if protocol not in ALLOWED_PROTOCOLS:
            raise PlanError(f"protocolが許可されていません: {protocol}")
        if method not in ALLOWED_METHODS:
            raise PlanError(f"methodが許可されていません: {method}")
        if transport not in ALLOWED_TRANSPORTS:
            raise PlanError(f"transportが許可されていません: {transport}")
        if host.endswith(".onion") and transport != "tor-socks5":
            raise PlanError(".onionはloopback SOCKS5経由に限定します")
        if not host.endswith(".onion") and transport != "direct":
            raise PlanError("Tor経由は.onion完全一致ターゲットに限定します")
        expected_protocol = {
            "tcp_connect": "tcp",
            "passive_banner": "tcp",
            "tls_handshake": "tls",
        }.get(method)
        if expected_protocol and protocol != expected_protocol:
            raise PlanError(f"{method}にはprotocol={expected_protocol}が必要です")
        if method == "http_get" and protocol not in {"http", "https"}:
            raise PlanError("http_getにはhttpまたはhttpsが必要です")
        timeout = float(target.get("timeout_seconds", 3.0))
        maximum = int(target.get("maximum_response_bytes", 256))
        if not 0.1 <= timeout <= 5.0 or not 1 <= maximum <= 256:
            raise PlanError("timeout<=5秒、response<=256 byteを超えています")
        path = str(target.get("http_path", "/"))
        if "\r" in path or "\n" in path or not path.startswith("/") or len(path) > 512:
            raise PlanError("HTTP pathが不正です")
        if any(key in target for key in ("send_hex", "payload", "cidr", "ports", "checkin")):
            raise PlanError("payload、check-in、range scanは監視計画へ指定できません")
        samples = target.get("sample_sha256s", [])
        if not isinstance(samples, list) or any(not SHA256_RE.fullmatch(str(x)) for x in samples):
            raise PlanError("sample_sha256sが不正です")
        sources = target.get("sources")
        if not isinstance(sources, list) or not sources or any(not str(x).strip() for x in sources):
            raise PlanError("各targetに1件以上の根拠sourcesが必要です")
        key = (host, port, protocol, path, transport)
        if key in seen:
            raise PlanError(f"重複targetです: {key}")
        seen.add(key)
        target["host"] = host
    return plan


def _probe_args(target: dict, allow_network: bool) -> SimpleNamespace:
    method = target.get("method", "tcp_connect")
    return SimpleNamespace(
        host=target["host"],
        port=target["port"],
        protocol=target.get("protocol", "tcp"),
        timeout=float(target.get("timeout_seconds", 3.0)),
        max_bytes=int(target.get("maximum_response_bytes", 256)),
        send_hex=None,
        expected_stage_size=0,
        expected_header_size=0,
        http_path=target.get("http_path", "/"),
        http_host=target.get("http_host"),
        sni=target.get("sni"),
        mxgo_mode="preview",
        mxgo_client_id="LAB-MXGO-000000000000",
        mxgo_recipient_path="/fixture.txt",
        n520_checkin=False,
        n520_wait=1.0,
        n520_max_bytes=256,
        n520_max_frames=1,
        artifact_zip=None,
        archive_password="infected",
        proxy_host="127.0.0.1" if target.get("transport") == "tor-socks5" else None,
        proxy_port=int(target.get("proxy_port", 9050)),
        collect_jarm=False,
        jarm_script=None,
        allow_network=allow_network,
        target_role="c2",
        sample_sha256=target.get("sample_sha256s", []),
        connect_only=method == "tcp_connect",
    )


def _sanitize_observation(observation: dict) -> dict:
    """banner本文やcookie等を公開結果へ残さずfingerprintだけ保持する。"""
    value = dict(observation)
    banner = value.get("banner")
    if isinstance(banner, dict):
        banner = dict(banner)
        prefix = banner.pop("prefix_base64", None)
        if prefix:
            try:
                decoded = base64.b64decode(prefix, validate=True)
            except (ValueError, TypeError):
                decoded = b""
            banner["ftp_220_marker"] = decoded.startswith(b"220")
        value["banner"] = banner
    http = value.get("http")
    if isinstance(http, dict):
        http = dict(http)
        headers = http.get("headers")
        if isinstance(headers, dict):
            http["headers"] = {
                str(key).lower(): val
                for key, val in headers.items()
                if str(key).lower() in SAFE_HTTP_HEADERS
            }
        value["http"] = http
    value.pop("sent_hex", None)
    return value


def assess_observation(target: dict, observation: dict) -> dict:
    """到達性とC2稼働確度を分離して評価する。"""
    method = target.get("method", "tcp_connect")
    ceiling = METHOD_CEILINGS[method]
    status = observation.get("status", "unknown")
    tcp_open = observation.get("tcp_status") == "open" or bool(
        observation.get("target_connection_established")
    )
    http_status = (observation.get("http") or {}).get("status")
    banner = observation.get("banner") or {}
    tls = observation.get("tls") or {}

    if observation.get("c2_confirmed"):
        return {
            "state": "c2_protocol_confirmed",
            "reachability_confidence": 1.0,
            "c2_operational_confidence": 0.95,
            "method_confidence_ceiling": max(0.95, ceiling),
            "negative_observation_confidence": 0.0,
            "reason": "review済みmalware固有protocol応答が一致",
        }
    if http_status is not None:
        return {
            "state": "application_endpoint_reachable_c2_not_confirmed",
            "reachability_confidence": 0.95,
            "c2_operational_confidence": min(0.60, ceiling),
            "method_confidence_ceiling": ceiling,
            "negative_observation_confidence": 0.0,
            "reason": "限定HTTP応答を確認したが所有者・C2 protocolは未確認",
        }
    if banner.get("length"):
        app_score = 0.50 if banner.get("ftp_220_marker") else 0.45
        return {
            "state": "server_first_response_reachable_c2_not_confirmed",
            "reachability_confidence": 0.95,
            "c2_operational_confidence": min(app_score, ceiling),
            "method_confidence_ceiling": ceiling,
            "negative_observation_confidence": 0.0,
            "reason": "server-first応答を確認したがmalware固有fingerprintではない",
        }
    if tls:
        return {
            "state": "tls_endpoint_reachable_c2_not_confirmed",
            "reachability_confidence": 0.95,
            "c2_operational_confidence": min(0.40, ceiling),
            "method_confidence_ceiling": ceiling,
            "negative_observation_confidence": 0.0,
            "reason": "TLS handshake成立のみでC2は未確認",
        }
    if tcp_open or observation.get("alive"):
        return {
            "state": "transport_reachable_c2_not_confirmed",
            "reachability_confidence": 0.90,
            "c2_operational_confidence": min(0.25, ceiling),
            "method_confidence_ceiling": ceiling,
            "negative_observation_confidence": 0.0,
            "reason": "TCP到達性のみでC2 applicationは未確認",
        }
    proxy_unavailable = (
        target.get("transport") == "tor-socks5"
        and not observation.get("target_contact_attempted")
    )
    if proxy_unavailable:
        return {
            "state": "not_observed_proxy_unavailable",
            "reachability_confidence": 0.0,
            "c2_operational_confidence": 0.0,
            "method_confidence_ceiling": ceiling,
            "negative_observation_confidence": 0.0,
            "reason": "loopback Tor SOCKS5へ接続できず対象へ到達していない",
        }
    negative = 0.85 if status == "closed" else (0.70 if observation.get("resolution_error") else 0.40)
    return {
        "state": "not_reachable_at_observation",
        "reachability_confidence": 0.0,
        "c2_operational_confidence": 0.0,
        "method_confidence_ceiling": ceiling,
        "negative_observation_confidence": negative,
        "reason": "この観測時点では到達応答なし。停止の恒久判定ではない",
    }


def monitor(plan: dict, *, allow_network: bool = False) -> dict:
    """レビュー済み対象を各1回だけ観測する。"""
    plan = validate_plan(plan)
    results = []
    for target in plan["targets"]:
        raw = probe(_probe_args(target, allow_network))
        observation = _sanitize_observation(raw)
        results.append({
            "target_id": target.get("target_id"),
            "family": target.get("family", "unknown"),
            "host": target["host"],
            "port": target["port"],
            "protocol": target.get("protocol", "tcp"),
            "transport": target.get("transport", "direct"),
            "method": target.get("method", "tcp_connect"),
            "method_description": METHOD_LABELS[target.get("method", "tcp_connect")],
            "http_path": target.get("http_path") if target.get("method") == "http_get" else None,
            "sample_sha256s": target.get("sample_sha256s", []),
            "associated_case_count": int(target.get("associated_case_count", len(target.get("sample_sha256s", [])))),
            "analyzed_dates": target.get("analyzed_dates", []),
            "sources": target["sources"],
            "observation": observation,
            "assessment": assess_observation(target, observation),
        })
    counts = Counter(item["assessment"]["state"] for item in results)
    return {
        "schema_version": 1,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "analysis_window": plan["analysis_window"],
        "policy": {
            "exact_targets_only": True,
            "one_bounded_probe_per_target": True,
            "maximum_timeout_seconds": 5,
            "maximum_response_bytes": 256,
            "redirect_followed": False,
            "malware_checkin_sent": False,
            "victim_metadata_sent": False,
            "command_polling_performed": False,
            "range_scan_performed": False,
            "tcp_open_confirms_c2": False,
            "network_enabled": allow_network,
        },
        "target_count": len(results),
        "state_counts": dict(sorted(counts.items())),
        "results": results,
    }


def _defang_host(host: str) -> str:
    return host.replace(".", "[.]")


def _score(value: float) -> str:
    label = "高" if value >= 0.80 else ("中" if value >= 0.40 else "低")
    return f"{value:.2f}（{label}）"


def render_markdown(result: dict) -> str:
    """監視結果を人がレビューしやすい日本語一覧表へ変換する。"""
    rows = []
    for item in result["results"]:
        assessment = item["assessment"]
        observation = item["observation"]
        endpoint = f"`{_defang_host(item['host'])}:{item['port']}`"
        if item.get("http_path"):
            endpoint += f" `{item['http_path']}`"
        checked = observation.get("timestamp_utc", "-")
        methods = item["method_description"]
        if item["transport"] == "tor-socks5":
            methods += "（localhost Tor SOCKS5経由）"
        result_text = f"{assessment['state']} / {assessment['reason']}"
        confidence = (
            f"到達 {_score(assessment['reachability_confidence'])}<br>"
            f"C2稼働 {_score(assessment['c2_operational_confidence'])}<br>"
            f"手法上限 {_score(assessment['method_confidence_ceiling'])}"
        )
        source = "<br>".join(item["sources"][:3])
        rows.append(
            f"| {item['family']} | {endpoint} | {item['associated_case_count']} | {checked} | "
            f"{methods} | {result_text} | {confidence} | {source} |"
        )
    counts = result.get("state_counts", {})
    summary = "、".join(f"{key}: {value}" for key, value in sorted(counts.items())) or "なし"
    return "\n".join([
        "# 過去1週間解析分のC2稼働状況",
        "",
        f"対象期間は `{result['analysis_window']['start']}` から `{result['analysis_window']['end']}`、監視対象は {result['target_count']} endpointです。状態内訳は {summary} です。",
        "",
        "この結果は観測時点のスナップショットです。TCP open、TLS証明書、一般HTTP/FTP応答だけではC2を確定しません。到達性とC2稼働確度を分離し、停止側の判定も恒久停止とは扱いません。",
        "",
        "## 一覧",
        "",
        "| ファミリー | endpoint | 関連case数 | 確認時刻（UTC） | 確認方法 | 観測結果 | confidence | 根拠 |",
        "|---|---|---:|---|---|---|---|---|",
        *rows,
        "",
        "## confidenceの読み方",
        "",
        "- `到達`: 今回のtransport／application到達観測の確からしさです。",
        "- `C2稼働`: 観測結果が、解析済みmalwareのC2 application稼働を示す確度です。TCP接続だけなら最大0.25です。",
        "- `手法上限`: その確認方法が、成功時でも単独で到達できるC2確度の上限です。malware固有protocolとの一致がない限り0.60以下です。",
        "- `negative_observation_confidence` はJSONに保持し、拒否は比較的強い停止側観測、timeoutは弱い停止側観測として区別します。",
        "",
        "## 安全境界",
        "",
        "完全一致host・単一portへ各1回、timeout最大5秒、応答最大256 byteで確認しました。malware check-in、victim metadata、stage要求、command polling、認証情報、port range、redirect追跡は使用していません。`.onion`はlocalhostのTor SOCKS5を通じて対象へ接続できた場合だけ観測成立とします。",
        "",
        "機械可読の完全な根拠、DNS解決先、証明書／banner hash、個別timeoutは [monitoring-results.json](monitoring-results.json)、再実行対象は [targets.json](targets.json) を参照してください。",
        "",
    ])


def main() -> int:
    parser = argparse.ArgumentParser(description="レビュー済みC2の限定監視と日本語結果生成")
    parser.add_argument("--targets", type=Path, required=True)
    parser.add_argument("--output-directory", type=Path, required=True)
    parser.add_argument("--allow-network", action="store_true")
    args = parser.parse_args()
    try:
        plan = json.loads(args.targets.read_text(encoding="utf-8"))
        result = monitor(plan, allow_network=args.allow_network)
    except (OSError, json.JSONDecodeError, PlanError, ValueError) as exc:
        parser.error(str(exc))
    args.output_directory.mkdir(parents=True, exist_ok=True)
    (args.output_directory / "monitoring-results.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8",
    )
    (args.output_directory / "README.md").write_text(render_markdown(result), encoding="utf-8")
    print(json.dumps({
        "target_count": result["target_count"],
        "state_counts": result["state_counts"],
        "output_directory": str(args.output_directory),
        "network_enabled": args.allow_network,
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
