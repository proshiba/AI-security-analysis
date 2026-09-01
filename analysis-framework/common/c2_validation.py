#!/usr/bin/env python3
"""検体別のC2候補を安全な上限内で一括probeする。"""
from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from types import SimpleNamespace

from nmap_c2_detector import probe_target_with_nmap


SHA256_RE = re.compile(r"[0-9a-f]{64}")
HOST_RE = re.compile(r"(?=.{1,253}$)[A-Za-z0-9.-]+")
ALLOWED_PROTOCOLS = {"tcp", "udp", "http", "https", "tls"}
ALLOWED_TRANSPORTS = {"direct", "tor-socks5"}
ALLOWED_ROLES = {
    "c2", "distribution", "kill_switch", "local_proxy", "local_controller", "unknown",
}


class ManifestError(ValueError):
    """安全でないmanifestを拒否する検証エラー。"""


def _candidate_key(candidate: dict) -> tuple:
    return (
        candidate["host"].lower(),
        candidate["port"],
        candidate.get("protocol", "tcp"),
        candidate.get("http_path", "/"),
        candidate.get("http_host"),
        candidate.get("sni"),
        candidate.get("role", "c2"),
        candidate.get("transport", "direct"),
        candidate.get("proxy_port", 9050),
    )


def validate_manifest(value: dict) -> dict:
    """対象を完全一致の単一ホスト・ポートへ制限する。"""
    if not isinstance(value, dict) or not isinstance(value.get("samples"), list):
        raise ManifestError("manifest.samples must be a list")
    if not value.get("batch_id") or len(str(value["batch_id"])) > 128:
        raise ManifestError("batch_id is required")
    seen: set[str] = set()
    for sample in value["samples"]:
        if not isinstance(sample, dict):
            raise ManifestError("each sample must be an object")
        digest = str(sample.get("sha256", "")).lower()
        if not SHA256_RE.fullmatch(digest):
            raise ManifestError("sample sha256 is invalid")
        if digest in seen:
            raise ManifestError(f"duplicate sample: {digest}")
        seen.add(digest)
        sample["sha256"] = digest
        resolution = sample.get("c2_resolution_status", "not_recovered")
        if resolution not in {"recovered", "not_recovered", "not_applicable"}:
            raise ManifestError(f"invalid c2_resolution_status: {resolution}")
        candidates = sample.get("candidates", [])
        if not isinstance(candidates, list) or len(candidates) > 8:
            raise ManifestError("candidates must be a list with at most 8 entries")
        if resolution == "recovered" and not candidates:
            raise ManifestError("recovered status requires at least one candidate")
        for candidate in candidates:
            if not isinstance(candidate, dict):
                raise ManifestError("candidate must be an object")
            host = str(candidate.get("host", ""))
            if not HOST_RE.fullmatch(host) or "*" in host:
                raise ManifestError(f"candidate host is invalid: {host}")
            port = candidate.get("port")
            if not isinstance(port, int) or not 1 <= port <= 65535:
                raise ManifestError("candidate port is invalid")
            protocol = candidate.get("protocol", "tcp")
            if protocol not in ALLOWED_PROTOCOLS:
                raise ManifestError(f"protocol is not server-first safe: {protocol}")
            role = candidate.get("role", "c2")
            if role not in ALLOWED_ROLES:
                raise ManifestError(f"invalid target role: {role}")
            proxy_port = candidate.get("proxy_port", 9050)
            if not isinstance(proxy_port, int) or not 1 <= proxy_port <= 65535:
                raise ManifestError("proxy_port is invalid")
            transport = candidate.get("transport", "direct")
            if transport not in ALLOWED_TRANSPORTS:
                raise ManifestError(f"invalid transport: {transport}")
            if protocol == "udp" and transport != "direct":
                raise ManifestError("UDP candidates require direct transport")
            if host.lower().endswith(".onion") and transport != "tor-socks5":
                raise ManifestError(".onion candidates require tor-socks5 transport")
            timeout = float(candidate.get("timeout", 3.0))
            maximum = int(candidate.get("max_bytes", 64))
            if not 0.1 <= timeout <= 5.0 or not 1 <= maximum <= 256:
                raise ManifestError("probe bounds exceed timeout=5s or max_bytes=256")
            path = str(candidate.get("http_path", "/"))
            if "\r" in path or "\n" in path or not path.startswith("/") or len(path) > 512:
                raise ManifestError("HTTP path is invalid")
            if any(key in candidate for key in ("send_hex", "payload", "cidr", "ports")):
                raise ManifestError("active payloads and scan ranges are forbidden")
            if not candidate.get("source"):
                raise ManifestError("candidate source evidence is required")
    return value


def _nmap_target(candidate: dict, sample_sha256s: list[str]) -> dict:
    protocol = candidate.get("protocol", "tcp")
    method = {
        "http": "tcp_connect",
        "https": "tls_handshake",
        "tcp": "tcp_connect",
        "tls": "tls_handshake",
    }.get(protocol)
    if method is None:
        raise ManifestError(f"Nmap transport NSEへ未対応のprotocolです: {protocol}")
    return {
        "target_id": "batch-c2-validation",
        "family": "unknown",
        "host": candidate["host"],
        "port": candidate["port"],
        "protocol": protocol,
        "method": method,
        "transport": "direct",
        "timeout_seconds": float(candidate.get("timeout", 3.0)),
        "maximum_request_bytes": 0,
        "maximum_response_bytes": 0,
        "sample_sha256s": sample_sha256s,
        "associated_case_count": len(sample_sha256s),
        "roles": [candidate.get("role", "c2")],
        "sources": [candidate["source"]],
        "selection_basis": "Nmap NSEによるtransport到達性観測のみ",
    }


def _probe_args(
    candidate: dict, sample_sha256s: list[str], allow_network: bool
) -> SimpleNamespace:
    """旧probe呼出し用の安全なconnect-only引数を返す。

    実probeはNmap NSEへ移行済みだが、既存利用側が安全policyを検査できるよう、
    送信payloadを持たない互換objectだけを残す。
    """

    return SimpleNamespace(
        host=candidate["host"],
        port=candidate["port"],
        protocol=candidate.get("protocol", "tcp"),
        timeout=float(candidate.get("timeout", 3.0)),
        max_bytes=int(candidate.get("max_bytes", 64)),
        send_hex=None,
        expected_stage_size=0,
        expected_header_size=0,
        http_path=candidate.get("http_path", "/"),
        http_host=candidate.get("http_host"),
        sni=candidate.get("sni"),
        mxgo_mode="preview",
        mxgo_client_id="LAB-MXGO-000000000000",
        mxgo_recipient_path="/fixture.txt",
        n520_checkin=False,
        n520_wait=1.0,
        n520_max_bytes=64,
        n520_max_frames=1,
        artifact_zip=None,
        archive_password="infected",
        proxy_host=(
            "127.0.0.1" if candidate.get("transport") == "tor-socks5" else None
        ),
        proxy_port=candidate.get("proxy_port", 9050),
        collect_jarm=False,
        jarm_script=None,
        allow_network=allow_network,
        target_role=candidate.get("role", "c2"),
        sample_sha256=sample_sha256s,
        connect_only=True,
    )


def _connection_status(results: list[dict], allow_network: bool, empty_status: str) -> str:
    if not results:
        return empty_status
    if any(item.get("target_contact_attempted") for item in results):
        return "performed"
    if any(
        "target_contact_attempted" not in item and item.get("network_contacted")
        for item in results
    ):
        return "performed"
    if allow_network:
        if any(
            item.get("network_contacted") and item.get("transport") == "tor-socks5"
            for item in results
        ):
            return "not_performed_proxy_unavailable"
        if any(item.get("network_contacted") for item in results):
            return "performed"
        return "not_performed_by_policy"
    return "dry_run"


C2_ROLES = {"c2", "local_controller"}


def validate_candidates(
    manifest: dict,
    *,
    allow_network: bool = False,
    include_non_c2: bool = False,
    nmap_executable: str | Path | None = None,
) -> dict:
    """候補を1回だけprobeし、関連するSHA-256へ結果を割り当てる。"""
    manifest = validate_manifest(manifest)
    grouped: dict[tuple, dict] = {}
    associations: dict[tuple, list[str]] = defaultdict(list)
    sample_results: dict[str, dict] = {}
    for sample in manifest["samples"]:
        digest = sample["sha256"]
        sample_results[digest] = {
            "sha256": digest,
            "family": sample.get("family", "unknown"),
            "c2_resolution_status": sample.get("c2_resolution_status", "not_recovered"),
            "candidate_results": [],
        }
        for candidate in sample.get("candidates", []):
            key = _candidate_key(candidate)
            grouped.setdefault(key, candidate)
            associations[key].append(digest)

    probe_results: dict[tuple, dict] = {}
    for key, candidate in grouped.items():
        role = candidate.get("role", "c2")
        transport = candidate.get("transport", "direct")
        linked = sorted(set(associations[key]))
        if role != "c2" and not include_non_c2:
            result = {
                "status": "not_performed_non_c2_role",
                "alive": False,
                "c2_confirmed": False,
                "network_contacted": False,
                "application_data_sent": False,
                "target_role": role,
                "transport": transport,
                "sample_sha256s": linked,
            }
        elif transport != "direct":
            result = {
                "status": "nmap_transport_unsupported",
                "alive": False,
                "c2_confirmed": False,
                "network_contacted": False,
                "target_contact_attempted": False,
                "application_data_sent": False,
                "target_role": role,
                "transport": transport,
                "sample_sha256s": linked,
            }
        elif candidate.get("protocol") == "udp":
            result = {
                "status": "nmap_udp_transport_unsupported",
                "alive": False,
                "c2_confirmed": False,
                "network_contacted": False,
                "target_contact_attempted": False,
                "application_data_sent": False,
                "target_role": role,
                "transport": transport,
                "sample_sha256s": linked,
            }
        else:
            result = probe_target_with_nmap(
                _nmap_target(candidate, linked),
                allow_network=allow_network,
                nmap_executable=nmap_executable,
            )
            result["target_role"] = role
            result["sample_sha256s"] = linked
            result["transport"] = transport
        result["candidate_source"] = candidate["source"]
        result["review_note"] = candidate.get("review_note")
        probe_results[key] = result

    for sample in manifest["samples"]:
        digest = sample["sha256"]
        for candidate in sample.get("candidates", []):
            result = dict(probe_results[_candidate_key(candidate)])
            result["deduplicated_probe"] = len(result.get("sample_sha256s", [])) > 1
            sample_results[digest]["candidate_results"].append(result)
        results = sample_results[digest]["candidate_results"]
        c2_results = [item for item in results if item.get("target_role") in C2_ROLES]
        non_c2_results = [item for item in results if item.get("target_role") not in C2_ROLES]
        resolution = sample_results[digest]["c2_resolution_status"]
        empty_c2_status = (
            "not_applicable"
            if resolution == "not_applicable"
            else "not_performed_no_exact_target"
        )
        sample_results[digest]["c2_connection_validation_status"] = _connection_status(
            c2_results, allow_network, empty_c2_status,
        )
        sample_results[digest]["non_c2_connection_validation_status"] = (
            _connection_status(non_c2_results, allow_network, "not_applicable")
        )
        sample_results[digest]["connection_validation_status"] = _connection_status(
            results, allow_network, empty_c2_status,
        )

    counts = Counter(item["connection_validation_status"] for item in sample_results.values())
    return {
        "schema_version": 1,
        "batch_id": manifest["batch_id"],
        "policy": {
            "exact_targets_only": True,
            "port_ranges_scanned": False,
            "application_payloads_allowed": False,
            "server_data_read": False,
            "maximum_timeout_seconds": 5,
            "maximum_response_bytes": 0,
            "network_enabled": allow_network,
            "network_execution_backend": "nmap_nse_only",
            "python_direct_probe_used": False,
            "non_c2_roles_included": include_non_c2,
            "tcp_reachability_confirms_c2": False,
            "c2_roles": sorted(C2_ROLES),
            "non_c2_reachability_never_substitutes_for_c2_validation": True,
        },
        "unique_probe_count": len(grouped),
        "sample_count": len(sample_results),
        "validation_status_counts": dict(sorted(counts.items())),
        "samples": list(sample_results.values()),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="検体別C2候補の限定接続検証を実行する")
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--allow-network", action="store_true")
    parser.add_argument("--include-non-c2", action="store_true")
    parser.add_argument("--nmap")
    args = parser.parse_args()
    try:
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
        result = validate_candidates(
            manifest,
            allow_network=args.allow_network,
            include_non_c2=args.include_non_c2,
            nmap_executable=args.nmap,
        )
    except (OSError, json.JSONDecodeError, ManifestError) as exc:
        parser.error(str(exc))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
