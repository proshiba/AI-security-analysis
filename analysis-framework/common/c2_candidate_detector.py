#!/usr/bin/env python3
"""Offline C2/config finding assessment with passive-search query generation."""

from __future__ import annotations

import argparse
import ipaddress
import json
from pathlib import Path
import sys
from urllib.parse import urlsplit

REPO = Path(__file__).parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from extractors.profiled_family import profile_for  # noqa: E402

NON_C2_ROLES = {
    "certificate_service",
    "documentation_reference",
    "host_discovery_service",
    "stage_url_candidate",
}

def protocol_profile(family: str | None) -> dict | None:
    """Return offline confirmation and emulator guidance for a profiled family."""
    if not family:
        return None
    try:
        profile = profile_for(family)
    except ValueError:
        return None
    return {
        "category": profile["category"],
        "transport": profile["transport"],
        "endpoint_role": profile["endpoint_role"],
        "confirmation_requirements": profile["confirmation"],
        "active_confirmation_default": "disabled",
        "emulator": "emulators/families/lab.py (loopback only)",
    }

def target_from_finding(finding: dict) -> tuple[str, int | None] | None:
    """Normalize one network finding into a host and optional port."""
    value = str(finding.get("value", ""))
    if finding.get("kind") == "network.url":
        try:
            parsed = urlsplit(value)
            return (parsed.hostname or "", parsed.port)
        except ValueError:
            return None
    if finding.get("kind") in {"network.endpoint", "exfiltration.endpoint"} and ":" in value:
        host, raw_port = value.rsplit(":", 1)
        try:
            return host.strip("[]"), int(raw_port)
        except ValueError:
            return None
    return None


def shodan_queries(host: str, port: int | None = None) -> list[str]:
    """Create passive Shodan pivots without contacting the target or Shodan."""
    if not host:
        return []
    try:
        ipaddress.ip_address(host)
        base = f"ip:{host}"
    except ValueError:
        base = f"hostname:{host.lower()}"
    return [f"{base} port:{port}" if port else base]


def assess(result: dict) -> dict:
    """Assess extractor findings conservatively and preserve provenance."""
    rows = []
    for finding in result.get("findings", []):
        if finding.get("role") in NON_C2_ROLES:
            continue
        target = target_from_finding(finding)
        if not target:
            continue
        host, port = target
        rows.append(
            {
                "finding": finding,
                "host": host,
                "port": port,
                "passive_queries": shodan_queries(host, port),
                "active_probe_performed": False,
            }
        )
    confidence = "none"
    values = {row["finding"].get("confidence") for row in rows}
    if "confirmed" in values:
        confidence = "confirmed"
    elif "probable" in values:
        confidence = "probable"
    elif rows:
        confidence = "candidate"
    family = result.get("family")
    return {
        "schema_version": 1,
        "family": family,
        "assessment": confidence,
        "protocol_profile": protocol_profile(family),
        "targets": rows,
        "network_contacted": False,
        "sample_executed": False,
        "warning": "Passive pivots and embedded literals do not by themselves confirm a live C2 service.",
    }


def build_parser() -> argparse.ArgumentParser:
    """Build the offline detector command-line parser."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--extractor-result", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Assess one extractor result and write deterministic JSON."""
    args = build_parser().parse_args(argv)
    result = assess(json.loads(args.extractor_result.read_text(encoding="utf-8")))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output), "targets": len(result["targets"])}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
