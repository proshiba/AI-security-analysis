#!/usr/bin/env python3
"""Fetch and normalize VirusTotal sandbox behavior summaries for static triage.

This module only contacts the VirusTotal API endpoint requested by the analyst;
it never executes samples and never probes malware infrastructure.
"""
from __future__ import annotations

import argparse
import json
import os
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

VT_API_ROOT = "https://www.virustotal.com/api/v3"


def vt_get(path: str, api_key: str, api_root: str = VT_API_ROOT, timeout: float = 30.0) -> dict[str, Any]:
    """Return decoded JSON from a VirusTotal API path using the supplied API key."""
    request = urllib.request.Request(
        f"{api_root.rstrip('/')}/{path.lstrip('/')}",
        headers={"x-apikey": api_key, "accept": "application/json", "user-agent": "ai-security-analysis/1"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")[:1000]
        raise RuntimeError(f"VirusTotal API error {exc.code}: {body}") from exc


def extract_relationship_items(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract relationship item dictionaries from a VirusTotal relationship response."""
    data = payload.get("data", [])
    return [item for item in data if isinstance(item, dict)]


def summarize_behaviour_reports(reports: list[dict[str, Any]]) -> dict[str, Any]:
    """Summarize sandbox relationships into classification-friendly evidence."""
    sandboxes: list[dict[str, Any]] = []
    contacted_domains: set[str] = set()
    contacted_ips: set[str] = set()
    processes: set[str] = set()
    verdicts: list[str] = []
    for report in reports:
        attrs = report.get("attributes", {}) if isinstance(report.get("attributes"), dict) else {}
        sandbox_name = attrs.get("sandbox_name") or attrs.get("analysis_date") or report.get("id")
        verdict = attrs.get("verdict") or attrs.get("malware_classification")
        if verdict:
            verdicts.append(str(verdict))
        for key in ("contacted_domains", "dns_lookups"):
            for item in attrs.get(key, []) or []:
                value = item.get("hostname") if isinstance(item, dict) else item
                if value:
                    contacted_domains.add(str(value).lower())
        for key in ("contacted_ips", "ip_traffic"):
            for item in attrs.get(key, []) or []:
                value = item.get("destination_ip") if isinstance(item, dict) else item
                if value:
                    contacted_ips.add(str(value))
        for proc in attrs.get("processes_tree", []) or []:
            if isinstance(proc, dict) and proc.get("name"):
                processes.add(str(proc["name"]))
        sandboxes.append({"id": report.get("id"), "sandbox_name": sandbox_name, "verdict": verdict})
    return {
        "sandbox_count": len(reports),
        "sandboxes": sandboxes,
        "verdicts": sorted(set(verdicts)),
        "contacted_domains": sorted(contacted_domains),
        "contacted_ips": sorted(contacted_ips),
        "process_names": sorted(processes),
        "classification_uses": [
            "correlate process-attributed network activity with decoded config or loader chain",
            "do not promote IP/domain-only sandbox observations to confirmed C2 without static/process correlation",
        ],
    }


def fetch_file_behaviours(sha256: str, api_key: str, api_root: str = VT_API_ROOT, timeout: float = 30.0) -> dict[str, Any]:
    """Fetch VirusTotal file behaviour summaries for a SHA-256 sample hash."""
    payload = vt_get(f"files/{sha256}/behaviours", api_key, api_root, timeout)
    reports = extract_relationship_items(payload)
    return {"sample_sha256": sha256, "source": "virustotal", "raw_relationship_count": len(reports), "summary": summarize_behaviour_reports(reports), "raw": payload}


def main() -> int:
    """Run the VirusTotal sandbox fetcher from the command line."""
    parser = argparse.ArgumentParser(description="Fetch VirusTotal sandbox behaviour relationship data for a sample hash.")
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--api-key", default=os.environ.get("VT_API_KEY"))
    parser.add_argument("--api-root", default=VT_API_ROOT)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if not args.api_key:
        parser.error("--api-key or VT_API_KEY is required")
    result = fetch_file_behaviours(args.sha256.lower(), args.api_key, args.api_root, args.timeout)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"output": str(args.output), "sandbox_count": result["summary"]["sandbox_count"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
