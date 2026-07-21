#!/usr/bin/env python3
"""レビュー済みプロファイルと受動通信観測を照合するC2候補検出器。"""

from __future__ import annotations

import argparse
import ipaddress
import json
from pathlib import Path


def _host_matches(endpoint: dict, observation: dict) -> bool:
    expected = str(endpoint.get("host", "")).lower().rstrip(".")
    observed = {
        str(observation.get(key, "")).lower().rstrip(".")
        for key in ("destination_host", "requested_host", "http_host", "sni")
    }
    return bool(expected and expected in observed)


def _indicator_matches(indicator: dict, observation: dict) -> bool:
    value: object = observation
    for part in str(indicator.get("field", "")).split("."):
        if not isinstance(value, dict) or part not in value:
            return False
        value = value[part]
    if "equals" in indicator:
        return str(value).lower() == str(indicator["equals"]).lower()
    if "contains" in indicator:
        return str(indicator["contains"]).lower() in str(value).lower()
    return False


def _shodan_queries(endpoint: dict) -> list[str]:
    if endpoint.get("role", "c2") != "c2":
        return []
    host = str(endpoint.get("host", ""))
    port = int(endpoint.get("port", 0) or 0)
    if not host or not port or host.lower().endswith(".onion"):
        return []
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return [f"hostname:{host} port:{port}"]
    return [f"ip:{host} port:{port}"] if address.is_global else []


def detect(profile: dict, observations: list[dict]) -> dict[str, object]:
    """完全一致エンドポイントと追加プロトコル所見を分離して判定する。"""
    matches: list[dict[str, object]] = []
    queries: set[str] = set()
    indicators = list(profile.get("protocol_indicators", []))
    required = int(profile.get("minimum_protocol_matches", 1))
    for endpoint in profile.get("endpoints", []):
        queries.update(_shodan_queries(endpoint))
        for index, observation in enumerate(observations):
            if not _host_matches(endpoint, observation):
                continue
            if int(observation.get("destination_port", 0)) != int(endpoint.get("port", 0)):
                continue
            protocol_matches = [
                indicator.get("id", indicator.get("field"))
                for indicator in indicators
                if _indicator_matches(indicator, observation)
            ]
            role = endpoint.get("role", "c2")
            confirmed = role == "c2" and bool(indicators) and len(protocol_matches) >= required
            matches.append(
                {
                    "observation_index": index,
                    "endpoint": endpoint,
                    "role": role,
                    "endpoint_match": True,
                    "protocol_indicator_matches": protocol_matches,
                    "c2_confirmed": confirmed,
                    "verdict": "confirmed_c2" if confirmed else ("possible_c2" if role == "c2" else "non_c2_role"),
                }
            )
    return {
        "schema_version": 1,
        "family": profile.get("family", "unknown"),
        "matches": matches,
        "shodan": {
            "queries": sorted(queries),
            "warning": "検索結果は候補であり、プロトコル所見なしにC2確定として扱わない",
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="受動C2候補検出器")
    parser.add_argument("--profile", required=True, type=Path)
    parser.add_argument("--observations", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    profile = json.loads(args.profile.read_text(encoding="utf-8"))
    observations_document = json.loads(args.observations.read_text(encoding="utf-8"))
    observations = observations_document.get("observations", observations_document)
    rendered = json.dumps(detect(profile, observations), ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
