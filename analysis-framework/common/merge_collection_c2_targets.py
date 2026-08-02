#!/usr/bin/env python3
"""MalwareBazaar collectionの確認済み静的C2を監視targetへ統合する。"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import date
from pathlib import Path
from urllib.parse import urlsplit


SHA256_RE = re.compile(r"[0-9a-f]{64}")
CONFIRMED_CONFIDENCE = "confirmed_static_configuration"


def load_json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON rootはobjectである必要があります: {path}")
    return value


def endpoint_from_network(item: dict) -> tuple[str, int, str] | None:
    """確認済みnetwork itemから完全一致host・port・transportを返す。"""
    if item.get("confidence") != CONFIRMED_CONFIDENCE:
        return None
    raw_url = item.get("url")
    if isinstance(raw_url, str) and raw_url:
        parsed = urlsplit(raw_url)
        host = (parsed.hostname or "").lower().rstrip(".")
        try:
            port = parsed.port
        except ValueError:
            return None
        if port is None:
            port = 443 if parsed.scheme.casefold() == "https" else 80
    else:
        raw_host = item.get("host")
        host = raw_host.lower().rstrip(".") if isinstance(raw_host, str) else ""
        port = item.get("port")
        if (
            isinstance(port, bool)
            or not isinstance(port, int)
            or not 1 <= port <= 65535
        ):
            return None
    if not host or host in {"localhost", "127.0.0.1", "::1"}:
        return None
    if not 1 <= port <= 65535:
        return None
    transport = "tor-socks5" if host.endswith(".onion") else "direct"
    configured_transport = item.get("transport")
    if configured_transport in {"direct", "tor-socks5"}:
        transport = configured_transport
    if host.endswith(".onion") != (transport == "tor-socks5"):
        return None
    return host, port, transport


def collect_confirmed_endpoints(collection: Path) -> list[dict]:
    """collection membershipから静的設定で確認済みのC2だけを収集する。"""
    publication = load_json(collection / "publication-summary.json")
    observations: dict[tuple[str, int, str, str], dict] = {}
    for case in publication.get("cases", []):
        if not isinstance(case, dict) or not case.get("confirmed_static_c2_observations"):
            continue
        digest = str(case.get("sha256", "")).casefold()
        if not SHA256_RE.fullmatch(digest):
            continue
        case_path = Path(str(case.get("case_path", "")))
        ioc_path = case_path / "iocs.json"
        if not ioc_path.is_file():
            continue
        iocs = load_json(ioc_path)
        for index, network in enumerate(iocs.get("network", [])):
            if not isinstance(network, dict):
                continue
            endpoint = endpoint_from_network(network)
            if endpoint is None:
                continue
            host, port, transport = endpoint
            key = (host, port, transport, digest)
            observations[key] = {
                "host": host,
                "port": port,
                "transport": transport,
                "family": str(case.get("family") or "unknown"),
                "sha256": digest,
                "role": str(network.get("role") or "c2"),
                "source": f"{ioc_path.as_posix()}:network[{index}]",
            }
    return list(observations.values())


def merge_targets(plan: dict, observations: list[dict], analysis_date: str) -> dict:
    """既存件数を保持しながら、新規caseと新規endpointを決定的に統合する。"""
    targets = plan.get("targets")
    if not isinstance(targets, list):
        raise ValueError("targetsはlistである必要があります")
    by_endpoint = {
        (str(item.get("host", "")).casefold(), int(item.get("port", 0)), item.get("transport", "direct")): item
        for item in targets
        if isinstance(item, dict)
    }
    added_endpoints = 0
    added_case_links = 0
    for observation in observations:
        key = (observation["host"], observation["port"], observation["transport"])
        target = by_endpoint.get(key)
        if target is None:
            suffix = hashlib.sha256("|".join(map(str, key)).encode()).hexdigest()[:12]
            family_id = re.sub(r"[^a-z0-9]+", "-", observation["family"].casefold()).strip("-") or "unknown"
            target = {
                "target_id": f"{family_id}-{suffix}",
                "family": observation["family"],
                "host": observation["host"],
                "port": observation["port"],
                "protocol": "tcp",
                "method": "tcp_connect",
                "transport": observation["transport"],
                "sample_sha256s": [],
                "associated_case_count": 0,
                "analyzed_dates": [],
                "sources": [],
            }
            targets.append(target)
            by_endpoint[key] = target
            added_endpoints += 1
        samples = target.setdefault("sample_sha256s", [])
        if observation["sha256"] not in samples:
            samples.append(observation["sha256"])
            target["associated_case_count"] = int(target.get("associated_case_count", 0)) + 1
            added_case_links += 1
        dates = target.setdefault("analyzed_dates", [])
        if analysis_date not in dates:
            dates.append(analysis_date)
        sources = target.setdefault("sources", [])
        if observation["source"] not in sources:
            sources.append(observation["source"])
        roles = target.setdefault("roles", [])
        if observation["role"] not in roles:
            roles.append(observation["role"])
    plan["reviewed_at"] = analysis_date
    return {
        "plan": plan,
        "added_endpoints": added_endpoints,
        "added_case_links": added_case_links,
        "confirmed_observations": len(observations),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--targets", type=Path, required=True)
    parser.add_argument("--collection", type=Path, required=True)
    parser.add_argument("--analysis-date", default=date.today().isoformat())
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    plan = load_json(args.targets)
    observations = collect_confirmed_endpoints(args.collection)
    result = merge_targets(plan, observations, args.analysis_date)
    if args.write:
        args.targets.write_text(
            json.dumps(result["plan"], ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    print(json.dumps({key: value for key, value in result.items() if key != "plan"}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
