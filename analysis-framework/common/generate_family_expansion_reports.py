#!/usr/bin/env python3
"""Generate publish-safe per-case reports for a reviewed multi-family batch."""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import re
import sys

REPO = Path(__file__).parents[2]
COMMON = Path(__file__).parent
for location in (REPO, COMMON):
    if str(location) not in sys.path:
        sys.path.insert(0, str(location))

from c2_candidate_detector import assess  # noqa: E402
from extractors.profiled_family import extract_family, load_profiles, normalize_family, sanitize_network_url, url_role  # noqa: E402
from malware_io import read_single_aes_zip_member  # noqa: E402

RUN_ID = "malwarebazaar-20260717"


def public_source(item: dict) -> dict:
    """Return source metadata without reporter identity or local archive paths."""
    metadata = item.get("metadata") or {}
    return {
        "sha256": item["sha256"],
        "requested_signature": item["requested_signature"],
        "first_seen": metadata.get("first_seen"),
        "file_name": metadata.get("file_name"),
        "file_size": metadata.get("file_size"),
        "file_type": metadata.get("file_type"),
        "file_format": metadata.get("file_format"),
        "file_arch": metadata.get("file_arch"),
        "tags": metadata.get("tags") or [],
        "imphash": metadata.get("imphash"),
        "tlsh": metadata.get("tlsh"),
        "ssdeep": metadata.get("ssdeep"),
    }


def normalize_finding(item: dict) -> dict | None:
    """Retain only publish-safe network finding fields with calibrated confidence."""
    value = str(item.get("value") or "")
    if not value or len(value) > 1024:
        return None
    return {
        "kind": str(item.get("kind") or "network.candidate"),
        "value": value,
        "role": str(item.get("role") or "candidate_infrastructure"),
        "confidence": str(item.get("confidence") or "candidate"),
        "source": str(item.get("source") or "static_analysis"),
    }


def merge_findings(extractor_result: dict, static_case: dict) -> list[dict]:
    """Merge extractor and recursive-layer literals without upgrading confidence."""
    output: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for raw in extractor_result.get("findings") or []:
        item = normalize_finding(raw)
        if item and (item["kind"], item["value"]) not in seen:
            seen.add((item["kind"], item["value"]))
            output.append(item)
    for raw_value in (static_case.get("iocs") or {}).get("urls") or []:
        value = sanitize_network_url(raw_value)
        if not value:
            continue
        key = ("network.url", value)
        if key not in seen:
            seen.add(key)
            output.append({"kind": "network.url", "value": value, "role": url_role("recursive_layer_literal", value), "confidence": "candidate", "source": "bounded_recursive_static_analysis"})
    for value in (static_case.get("iocs") or {}).get("ips") or []:
        if ":" not in value:
            continue
        key = ("network.endpoint", value)
        if key not in seen:
            seen.add(key)
            output.append({"kind": "network.endpoint", "value": value, "role": "recursive_layer_literal", "confidence": "candidate", "source": "bounded_recursive_static_analysis"})
    return output[:256]


def build_case(item: dict, static_case: dict, extractor_result: dict, c2_plan: dict, profile: dict) -> dict:
    """Build one public case document with explicit evidence and limitations."""
    findings = merge_findings(extractor_result, static_case)
    return {
        "schema_version": 1,
        "family": profile["family"],
        "display_name": profile["display_name"],
        "source": public_source(item),
        "attribution": {
            "family": profile["family"],
            "confidence": "high",
            "basis": ["exact MalwareBazaar signature query", "downloaded member SHA-256 verified", "reviewed batch campaign registry"],
            "campaign_or_operator": "not attributed",
        },
        "static_analysis": {
            "root_unpack": static_case.get("root_unpack") or {},
            "layers": static_case.get("layers") or [],
            "repository_yara_matches": static_case.get("repository_yara_matches") or [],
            "profile_config": extractor_result.get("config") or {},
            "findings": findings,
        },
        "c2_assessment": c2_plan,
        "detection_inputs": {
            "sha256": item["sha256"],
            "imphash": (item.get("metadata") or {}).get("imphash"),
            "tags": (item.get("metadata") or {}).get("tags") or [],
            "profile_markers": (extractor_result.get("config") or {}).get("marker_hits") or [],
            "observed_config_keys": (extractor_result.get("config") or {}).get("observed_config_keys") or [],
            "packer_markers": (static_case.get("root_unpack") or {}).get("packer_markers") or [],
            "network_candidates": [entry["value"] for entry in findings],
        },
        "sample_executed": False,
        "network_contacted": False,
        "limitations": [
            "Static-only analysis; encrypted runtime-only values can remain unresolved.",
            "A literal endpoint, open port, or passive-search hit does not independently confirm a C2 service.",
            "Family source signature does not identify an operator or campaign.",
        ],
    }


def markdown_table(rows: list[list[str]]) -> str:
    """Render a small escaped Markdown table."""
    if not rows:
        return ""
    escaped = [[str(value).replace("|", "\\|").replace("\n", " ") for value in row] for row in rows]
    header = "| " + " | ".join(escaped[0]) + " |"
    separator = "| " + " | ".join("---" for _ in escaped[0]) + " |"
    body = ["| " + " | ".join(row) + " |" for row in escaped[1:]]
    return "\n".join([header, separator, *body])


def case_markdown(case: dict) -> str:
    """Render one detailed per-sample analysis README."""
    source = case["source"]
    static = case["static_analysis"]
    config = static["profile_config"]
    findings = static["findings"]
    finding_rows = [["Value", "Role", "Confidence", "Source"]] + [
        [f"`{item['value']}`", item["role"], item["confidence"], item["source"]] for item in findings
    ]
    layer_rows = [["Depth", "Kind", "Format", "Size", "SHA-256"]] + [
        [str(item.get("depth", "")), str(item.get("kind", "")), str(item.get("format", "")), str(item.get("size", "")), f"`{item.get('sha256', '')}`"]
        for item in static["layers"][:32]
    ]
    return f'''# {case["display_name"]} case {source["sha256"]}

## Overview

- Family: `{case["family"]}` (high confidence from exact MalwareBazaar signature selection and verified SHA-256)
- First seen: `{source.get("first_seen")}`
- Submitted name/type/size: `{source.get("file_name")}` / `{source.get("file_type")}` / `{source.get("file_size")}` bytes
- SHA-256: `{source["sha256"]}`
- Operator/campaign: not attributed
- Execution/network: sample not executed; infrastructure not contacted

## Static behavior and config

- Category/transport: `{config.get("category")}` / `{config.get("transport")}`
- Unpack status: `{static["root_unpack"].get("unpack_status")}`
- Packing classification: `{static["root_unpack"].get("packing_classification")}`
- Marker hits: `{", ".join(config.get("marker_hits") or []) or "none"}`
- Config keys observed: `{", ".join(config.get("observed_config_keys") or []) or "none"}`
- Static config candidate recovered: `{config.get("static_config_recovered", False)}`

### Candidate infrastructure

{markdown_table(finding_rows) if findings else "No publishable network candidate was recovered statically."}

Candidates are not labelled as live or confirmed C2. See `c2-observation-plan.json` for passive Shodan pivots and family-specific confirmation requirements.

### Recovered layers

{markdown_table(layer_rows) if static["layers"] else "No bounded inner layer was recovered."}

## Detection inputs

- Exact hash: high precision and low false-positive risk, but no variant coverage.
- Profile marker cluster plus endpoint: medium confidence; forks, leaked builders, and legitimate software strings can overlap.
- Standalone URL/IP literal: low confidence and high false-positive risk; shared hosting, update services, and benign embedded documentation are common causes.
- YARA input: profile markers, file size bound, and reviewed family context.
- Sigma input: only observed script-delivery behavior should be used; no dynamic process behavior was invented for direct PE cases.

## Limitations

This is bounded static analysis. Packed or runtime-decrypted configuration may remain unresolved, and source-family attribution does not establish a common operator or campaign.
'''


def ioc_markdown(hashes: list[str], findings: list[dict]) -> str:
    """Render hashes and network candidates as a copyable IOC-only list."""
    non_ioc_roles = {"certificate_service", "documentation_reference", "host_discovery_service"}
    unique: dict[tuple[str, str], dict] = {}
    for item in findings:
        if item.get("role") in non_ioc_roles:
            continue
        unique[(item["kind"], item["value"])] = item
    lines = ["# IOC List", "", "## SHA-256", *[f"- `{value}`" for value in sorted(set(hashes))], "", "## Network candidates"]
    if unique:
        lines.extend(f"- `{item['value']}` — {item['role']}; {item['confidence']}" for item in sorted(unique.values(), key=lambda value: value["value"]))
    else:
        lines.append("- None recovered statically.")
    lines.extend(["", "Network values are candidates unless a case explicitly records a decoded config structure. No liveness claim is made.", ""])
    return "\n".join(lines)


def yara_rule(family: str, profile: dict) -> str:
    """Render a conservative profile-marker YARA rule with false-positive notes."""
    strings = []
    for index, marker in enumerate(profile["markers"]):
        escaped = marker.replace("\\", "\\\\").replace('"', '\\"')
        strings.append(f'        $m{index} = "{escaped}" ascii wide nocase')
    threshold = min(int(profile["minimum_markers"]), len(strings))
    name = re.sub(r"[^A-Za-z0-9_]", "_", f"ASA_{family}_Profile_20260717")
    return f'''rule {name}
{{
    meta:
        description = "Profile markers for {profile["display_name"]}; corroboration required"
        author = "AI-security-analysis"
        date = "2026-07-17"
        confidence = "medium"
        false_positive = "Forks, leaked builders, test tools, and unrelated software containing generic markers"
    strings:
{chr(10).join(strings)}
    condition:
        filesize < 100MB and {threshold} of ($m*)
}}
'''


def family_markdown(family: str, profile: dict, cases: list[dict]) -> str:
    """Render one aggregate family report with coverage and false-positive analysis."""
    types = Counter(str(case["source"].get("file_type") or "unknown") for case in cases)
    statuses = Counter(str(case["static_analysis"]["root_unpack"].get("unpack_status") or "unknown") for case in cases)
    recovered = sum(bool(case["static_analysis"]["profile_config"].get("static_config_recovered")) for case in cases)
    findings = [item for case in cases for item in case["static_analysis"]["findings"]]
    case_rows = [["SHA-256", "Type", "Unpack", "Config", "Network candidates"]] + [
        [f"[{case['source']['sha256']}](cases/{case['source']['sha256']}/README.md)", str(case["source"].get("file_type")), str(case["static_analysis"]["root_unpack"].get("unpack_status")), str(case["static_analysis"]["profile_config"].get("static_config_recovered", False)), str(len(case["static_analysis"]["findings"]))]
        for case in cases
    ]
    return f'''# {profile["display_name"]} — MalwareBazaar review 2026-07-17

## Scope and outcome

Ten newest samples selected by exact MalwareBazaar signature were downloaded and analyzed statically. Inner hashes were verified; no sample or recovered payload was executed and no candidate infrastructure was contacted.

- Category: `{profile["category"]}`
- Expected transport/role: `{profile["transport"]}` / `{profile["endpoint_role"]}`
- File-type distribution: `{dict(types)}`
- Unpack-status distribution: `{dict(statuses)}`
- Profile config candidates: `{recovered}/10`
- Publishable network candidates: `{len(findings)}`

Family attribution here does not imply one operator or campaign. Builder leakage, forks, repacking, and distinct delivery chains remain separate dimensions.

## Cases

{markdown_table(case_rows)}

## C2/config interpretation

{profile["confirmation"]} Until that condition is met, report values as candidate delivery/C2/exfiltration infrastructure only. Passive Shodan queries are stored per case; no banner, JARM, certificate, or HTTP title was invented when no live observation occurred.

## Detection and false-positive assessment

| Confidence | Recommended input | False-positive considerations |
| --- | --- | --- |
| High | Exact reviewed SHA-256 | Very low false positives; misses every rebuild or repack. |
| Medium | Multiple family markers plus decoded/corroborated endpoint structure | Forks, leaked builders, research tools, and shared libraries can match. |
| Low | One marker, one URL/IP, packer label, or generic script interpreter behavior | Shared hosting, legitimate automation, installers, and documentation strings can over-detect. |

The generated YARA rule is medium confidence and must be validated against a benign corpus. Sigma should be based on actual endpoint telemetry; this static batch does not fabricate process or registry events.
'''


def write_text(path: Path, value: str) -> None:
    """Write normalized UTF-8 text after creating parent directories."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(value.replace("\r\n", "\n"))


def generate(manifest_path: Path, cache: Path, output_root: Path) -> dict:
    """Generate all public reports directly from encrypted archives and static cache."""
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    profiles = load_profiles()
    grouped: dict[str, list[dict]] = defaultdict(list)
    for item in manifest.get("items") or []:
        grouped[normalize_family(item["requested_signature"], profiles)].append(item)
    total_cases = total_findings = 0
    family_counts = {}
    for family, items in sorted(grouped.items()):
        profile = {"family": family, **profiles[family]}
        family_dir = output_root / family / RUN_ID
        cases = []
        for item in sorted(items, key=lambda value: value["sha256"]):
            member = read_single_aes_zip_member(Path(item["zip_path"]))
            digest = hashlib.sha256(member.data).hexdigest()
            if digest != item["sha256"]:
                raise ValueError(f"inner SHA-256 mismatch: {item['sha256']}")
            static_path = cache / "cases" / digest / "case.json"
            static_case = json.loads(static_path.read_text(encoding="utf-8"))
            extractor_result = extract_family(family, member.data, member.name)
            c2_plan = assess(extractor_result)
            case = build_case(item, static_case, extractor_result, c2_plan, profile)
            cases.append(case)
            case_dir = family_dir / "cases" / digest
            write_text(case_dir / "README.md", case_markdown(case))
            write_text(case_dir / "indicators.json", json.dumps(case, ensure_ascii=False, indent=2) + "\n")
            write_text(case_dir / "config.json", json.dumps(extractor_result, ensure_ascii=False, indent=2) + "\n")
            write_text(case_dir / "c2-observation-plan.json", json.dumps(c2_plan, ensure_ascii=False, indent=2) + "\n")
            write_text(case_dir / "IOC-LIST.md", ioc_markdown([digest], case["static_analysis"]["findings"]))
        findings = [item for case in cases for item in case["static_analysis"]["findings"]]
        hashes = [case["source"]["sha256"] for case in cases]
        public_manifest = {"schema_version": 1, "source": "MalwareBazaar exact signature query", "run_id": RUN_ID, "family": family, "items": [case["source"] for case in cases], "sample_executed": False, "network_contacted": False}
        write_text(family_dir / "README.md", family_markdown(family, profile, cases))
        write_text(family_dir / "IOC-LIST.md", ioc_markdown(hashes, findings))
        write_text(family_dir / "manifest.json", json.dumps(public_manifest, ensure_ascii=False, indent=2) + "\n")
        write_text(family_dir / "rules" / "yara" / f"{family}_profile.yar", yara_rule(family, profile))
        write_text(output_root / family / "README.md", f'# {profile["display_name"]}\n\n- [{RUN_ID}]({RUN_ID}/README.md): 10 newest reviewed MalwareBazaar samples, static-only.\n')
        total_cases += len(cases)
        total_findings += len(findings)
        family_counts[family] = len(cases)
    return {"families": len(grouped), "cases": total_cases, "findings": total_findings, "family_counts": family_counts, "sample_executed": False, "network_contacted": False}


def build_parser() -> argparse.ArgumentParser:
    """Build the publish-safe report generation parser."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--cache", required=True, type=Path)
    parser.add_argument("--output-root", type=Path, default=REPO / "analysis-results")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Generate reports and print aggregate counts."""
    args = build_parser().parse_args(argv)
    print(json.dumps(generate(args.manifest, args.cache, args.output_root), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
