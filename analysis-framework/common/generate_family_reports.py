from __future__ import annotations

import argparse
import json
from pathlib import Path


def shodan_lines(case: dict) -> list[str]:
    lines: list[str] = []
    for endpoint in case.get("c2", []):
        host, port = endpoint.rsplit(":", 1)
        host_filter = (
            f'hostname:"{host}"'
            if not all(p.isdigit() for p in host.split("."))
            else f'ip:"{host}"'
        )
        lines.append(
            f"- `{host_filter} port:{port}` — infrastructure pivot; not a protocol fingerprint"
        )
    if not lines:
        lines.append(
            "- Confirmed host/port was not recovered, so no defensible Shodan query is emitted."
        )
    lines.append(
        "- Banner hash, HTTP title, certificate hash and JARM: not available from static/sandbox evidence. Do not invent these values; collect only under an approved live-network procedure."
    )
    return lines


def behavior_c2_assessment(family: str, case: dict) -> list[str]:
    c2 = case.get("c2", [])
    urls = case.get("stage_urls", [])
    duplicate = case.get("campaign") in {"rar_wrapped_javascript", "iso_double_extension_pe"}
    if duplicate:
        provenance = "inherited from a byte-identical inner payload; no independent endpoint extraction was claimed for the wrapper"
    elif c2:
        provenance = "external sandbox configuration or process-attributed evidence; the submitted loader alone did not establish the final endpoint"
    else:
        provenance = "not recovered; family tags or infrastructure pivots were not promoted to confirmed C2"
    if family.lower() == "agenttesla":
        protocol = case.get("protocol", "unknown")
        role = (
            f"{protocol} exfiltration/configuration endpoint used to upload stolen information; it is not assumed to be an interactive tasking server"
            if c2 else "no final exfiltration endpoint was independently recovered"
        )
        expected = "After the .NET payload is loaded, AgentTesla is expected to collect credentials and host/application data and exfiltrate them through its configured channel. This is family/config-derived capability unless process-attributed evidence says otherwise."
    else:
        role = (
            "long-lived outbound Remcos command-and-control channel; multiple host/port entries in one recovered configuration are treated as ordered fallback candidates, not separate malware families"
            if c2 else "interactive C2 is expected for Remcos, but no defensible host/port was recovered for this case"
        )
        expected = "After the payload is loaded, Remcos is expected to provide interactive remote administration such as command execution, file/process control, surveillance and persistence. These are family capabilities; the case report lists only behavior actually observed in its delivery/sandbox evidence."
    rows = [
        "## Behavior and C2 assessment",
        "",
        f"- Observed in this case: {'; '.join(case.get('notes', [])) or 'no additional behavior beyond the container structure was confirmed'}.",
        f"- Expected payload behavior: {expected}",
        f"- C2 role assumption: {role}.",
        f"- Endpoint provenance: {provenance}.",
    ]
    if urls:
        rows.append("- Distribution separation: " + ", ".join(f"`{url}`" for url in urls) + " are loader/stage locations and are not final C2 unless separately correlated.")
    rows += [
        "- Liveness: no live C2 check was performed for this case; current availability and server ownership remain unknown.",
        "- Confidence labels: delivery behavior is `confirmed` from static code/container structure; payload capability is `inferred` from family/config; listed final endpoints are `confirmed` only to the provenance stated above.",
    ]
    return rows


def case_report(family: str, case: dict) -> str:
    c2 = case.get("c2", [])
    urls = case.get("stage_urls", [])
    version = case.get("version")
    rows = [
        f"# {family} case {case['sha256'][:12]}",
        "",
        "## Overview",
        "",
        f"- SHA-256: `{case['sha256']}`",
        f"- Artifact: {case['artifact']}",
        f"- Delivery/campaign pattern: `{case['campaign']}`",
        "- Analysis mode: static analysis plus public sandbox evidence; the sample was not executed locally",
    ]
    if version:
        rows.append(f"- Recovered family version: {version}")
    rows += ["", "## Delivery and behavior", ""]
    rows += [f"- {n}" for n in case.get("notes", [])]
    rows += ["", *behavior_c2_assessment(family, case), "", "## Network observables", ""]
    rows += [f"- Confirmed configuration/sandbox endpoint: `{v}`" for v in c2] or [
        "- No independently confirmed final C2 endpoint was recovered."
    ]
    rows += [f"- Loader/stage URL: `{v}`" for v in urls]
    rows += [
        "- Confidence: endpoints labeled confirmed were extracted from malware configuration or process-attributed sandbox evidence. Exact-byte duplicate containers inherit the inner payload result explicitly.",
        "- No live C2 check was performed. Current availability and server identity are therefore unknown.",
        "",
        "## Shodan pivots",
        "",
        *shodan_lines(case),
        "",
        "## Detection guidance",
        "",
        "- High confidence / low false-positive risk: exact SHA-256, a reviewed YARA match combining loader structure with family-specific strings, or an endpoint plus matching process ancestry.",
        "- Medium confidence / medium false-positive risk: script host spawning hidden PowerShell together with remote image retrieval, in-memory .NET loading, or a double-extension executable from an ISO.",
        "- Low confidence / high false-positive risk: a single domain/IP, FTP/SMTP use, PowerShell, WScript, HTA, or image-named download alone. These are common administrative or application behaviors.",
        "- Credential material extracted from configurations is intentionally not published. Preserve it only in access-controlled evidence and rotate/notify an owner when appropriate.",
        "",
        "## Rule-building fields",
        "",
        f"- Family: `{family}`",
        f"- Campaign pattern: `{case['campaign']}`",
        f"- Artifact type: `{case['artifact']}`",
        f"- SHA-256: `{case['sha256']}`",
        f"- C2 values: {', '.join(f'`{x}`' for x in c2) if c2 else 'none confirmed'}",
        f"- Stage URLs: {', '.join(f'`{x}`' for x in urls) if urls else 'none recovered'}",
        "- Correlate parent/child process, command line, file origin, signer/prevalence and network destination before blocking.",
        "",
        "## Reproduction",
        "",
        "Run the family batch workflow against the original password-protected MalwareBazaar ZIP. Outputs must retain `executed=false` and `network_contacted=false` unless a separately approved dynamic-analysis workflow was used.",
        "",
    ]
    return "\n".join(rows)


def family_index(data: dict) -> str:
    family = data["family"]
    rows = [
        f"# {family} analysis results",
        "",
        "Ten MalwareBazaar submissions were triaged without local sample execution. Delivery patterns are kept separate from payload/config clusters because builders and infrastructure may be reused by different operators.",
        "",
        "## Family behavior and C2 model",
        "",
        (
            "AgentTesla is primarily an information stealer. In these cases the submitted scripts/HTA/RAR files are delivery layers; after the .NET payload is loaded, recovered FTP or SMTP settings are best understood as stolen-data exfiltration channels rather than interactive operator consoles."
            if family.lower() == "agenttesla" else
            "RemcosRAT is an interactive remote-administration implant. Its configured host/port values are expected to carry outbound tasking and result traffic; multiple ports in one configuration are treated as fallback candidates. Delivery URLs remain separate from final C2."
        ),
        "",
        "Case reports separate observed delivery behavior, inferred family capability, endpoint provenance, and current liveness. No current case was executed locally or live-probed.",
        "",
        "| SHA-256 | Artifact | Pattern | Confirmed C2/config endpoint |",
        "|---|---|---|---|",
    ]
    if family.lower() == "agenttesla":
        rows[4:4] = [
            "## Evidence provenance",
            "",
            "The FTP/SMTP endpoints in the current ten-case table came from external sandbox configuration output or, for the RAR wrapper, inheritance from its byte-identical inner sample. They were not recovered from the submitted scripts alone. Offline analysis recovered stage URLs in four cases, but no final .NET payload in the ten original containers because those stages must be separately acquired.",
            "",
            "`agenttesla_recover.py` records loader-derived stage URLs, recovers bounded encoded .NET candidates, and extracts redacted CLR configuration. `agenttesla_payload_fetch.py` provides explicit, bounded stage retrieval. New results must label endpoint provenance as `static_recovered_dotnet_payload`, `external_sandbox`, or `inherited_external_sandbox`.",
            "",
        ]
    for case in data["cases"]:
        c2 = "<br>".join(f"`{x}`" for x in case.get("c2", [])) or "not recovered"
        rows.append(
            f"| [`{case['sha256'][:12]}…`](cases/{case['sha256']}/README.md) | {case['artifact']} | `{case['campaign']}` | {c2} |"
        )
    rows += [
        "",
        "See `rules/` for family-oriented YARA and Sigma starting points. Rules are hypotheses that require validation against local benign software and telemetry.",
        "",
    ]
    return "\n".join(rows)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Generate redacted, reproducible family/case reports from reviewed case metadata."
    )
    ap.add_argument("--cases", required=True, type=Path)
    ap.add_argument("--output", required=True, type=Path)
    args = ap.parse_args()
    data = json.loads(args.cases.read_text(encoding="utf-8"))
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "README.md").write_text(family_index(data), encoding="utf-8")
    for case in data["cases"]:
        dst = args.output / "cases" / case["sha256"]
        dst.mkdir(parents=True, exist_ok=True)
        (dst / "README.md").write_text(
            case_report(data["family"], case), encoding="utf-8"
        )
        safe = {
            **case,
            "executed_locally": False,
            "network_contacted": False,
            "credentials_published": False,
        }
        (dst / "indicators.json").write_text(
            json.dumps(safe, indent=2, ensure_ascii=False), encoding="utf-8"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
