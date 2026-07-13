from __future__ import annotations

import argparse
import json
from pathlib import Path


def shodan_lines(case: dict) -> list[str]:
    lines: list[str] = []
    for endpoint in case.get("c2", []):
        host, port = endpoint.rsplit(":", 1)
        host_filter = f'hostname:"{host}"' if not all(p.isdigit() for p in host.split(".")) else f'ip:"{host}"'
        lines.append(f"- `{host_filter} port:{port}` — infrastructure pivot; not a protocol fingerprint")
    if not lines:
        lines.append("- Confirmed host/port was not recovered, so no defensible Shodan query is emitted.")
    lines.append("- Banner hash, HTTP title, certificate hash and JARM: not available from static/sandbox evidence. Do not invent these values; collect only under an approved live-network procedure.")
    return lines


def case_report(family: str, case: dict) -> str:
    c2 = case.get("c2", [])
    urls = case.get("stage_urls", [])
    version = case.get("version")
    rows = [
        f"# {family} case {case['sha256'][:12]}", "",
        "## Overview", "",
        f"- SHA-256: `{case['sha256']}`",
        f"- Artifact: {case['artifact']}",
        f"- Delivery/campaign pattern: `{case['campaign']}`",
        "- Analysis mode: static analysis plus public sandbox evidence; the sample was not executed locally",
    ]
    if version:
        rows.append(f"- Recovered family version: {version}")
    rows += ["", "## Delivery and behavior", ""]
    rows += [f"- {n}" for n in case.get("notes", [])]
    rows += ["", "## Network observables", ""]
    rows += [f"- Confirmed configuration/sandbox endpoint: `{v}`" for v in c2] or ["- No independently confirmed final C2 endpoint was recovered."]
    rows += [f"- Loader/stage URL: `{v}`" for v in urls]
    rows += [
        "- Confidence: endpoints labeled confirmed were extracted from malware configuration or process-attributed sandbox evidence. Exact-byte duplicate containers inherit the inner payload result explicitly.",
        "- No live C2 check was performed. Current availability and server identity are therefore unknown.",
        "", "## Shodan pivots", "",
        *shodan_lines(case),
        "", "## Detection guidance", "",
        "- High confidence / low false-positive risk: exact SHA-256, a reviewed YARA match combining loader structure with family-specific strings, or an endpoint plus matching process ancestry.",
        "- Medium confidence / medium false-positive risk: script host spawning hidden PowerShell together with remote image retrieval, in-memory .NET loading, or a double-extension executable from an ISO.",
        "- Low confidence / high false-positive risk: a single domain/IP, FTP/SMTP use, PowerShell, WScript, HTA, or image-named download alone. These are common administrative or application behaviors.",
        "- Credential material extracted from configurations is intentionally not published. Preserve it only in access-controlled evidence and rotate/notify an owner when appropriate.",
        "", "## Rule-building fields", "",
        f"- Family: `{family}`",
        f"- Campaign pattern: `{case['campaign']}`",
        f"- Artifact type: `{case['artifact']}`",
        f"- SHA-256: `{case['sha256']}`",
        f"- C2 values: {', '.join(f'`{x}`' for x in c2) if c2 else 'none confirmed'}",
        f"- Stage URLs: {', '.join(f'`{x}`' for x in urls) if urls else 'none recovered'}",
        "- Correlate parent/child process, command line, file origin, signer/prevalence and network destination before blocking.",
        "", "## Reproduction", "",
        "Run the family batch workflow against the original password-protected MalwareBazaar ZIP. Outputs must retain `executed=false` and `network_contacted=false` unless a separately approved dynamic-analysis workflow was used.", "",
    ]
    return "\n".join(rows)


def family_index(data: dict) -> str:
    family = data["family"]
    rows = [f"# {family} analysis results", "", "Ten MalwareBazaar submissions were triaged without local sample execution. Delivery patterns are kept separate from payload/config clusters because builders and infrastructure may be reused by different operators.", "", "| SHA-256 | Artifact | Pattern | Confirmed C2/config endpoint |", "|---|---|---|---|"]
    for case in data["cases"]:
        c2 = "<br>".join(f"`{x}`" for x in case.get("c2", [])) or "not recovered"
        rows.append(f"| [`{case['sha256'][:12]}…`](cases/{case['sha256']}/README.md) | {case['artifact']} | `{case['campaign']}` | {c2} |")
    rows += ["", "See `rules/` for family-oriented YARA and Sigma starting points. Rules are hypotheses that require validation against local benign software and telemetry.", ""]
    return "\n".join(rows)


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate redacted, reproducible family/case reports from reviewed case metadata.")
    ap.add_argument("--cases", required=True, type=Path)
    ap.add_argument("--output", required=True, type=Path)
    args = ap.parse_args()
    data = json.loads(args.cases.read_text(encoding="utf-8"))
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "README.md").write_text(family_index(data), encoding="utf-8")
    for case in data["cases"]:
        dst = args.output / "cases" / case["sha256"]
        dst.mkdir(parents=True, exist_ok=True)
        (dst / "README.md").write_text(case_report(data["family"], case), encoding="utf-8")
        safe = {**case, "executed_locally": False, "network_contacted": False, "credentials_published": False}
        (dst / "indicators.json").write_text(json.dumps(safe, indent=2, ensure_ascii=False), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
