#!/usr/bin/env python3
"""Generate publish-safe family and case reports from offline stealer results."""

from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
from typing import Any

from malwarebazaar_batch import public_manifest

OMITTED_CONFIG_KEYS = {
    "decoded_strings",
    "recovered_layer_configs",
    "selected_layer_config",
    "source_name",
}
AGGREGATE_CONFIG_KEYS = {
    "build_id",
    "campaign_id",
    "c2_urls",
    "delivery_profile",
    "group_id",
    "group_name",
    "install_directory",
    "install_filename",
    "profile",
    "version",
}


def load_case(case_dir: Path) -> dict:
    """Load one normalized case without recovered sample bytes."""
    layers_path = case_dir / "layers.json"
    return {
        "config": json.loads((case_dir / "config.json").read_text(encoding="utf-8")),
        "c2": json.loads((case_dir / "c2-candidates.json").read_text(encoding="utf-8")),
        "unpack": json.loads((case_dir / "unpack.json").read_text(encoding="utf-8")),
        "layers": json.loads(layers_path.read_text(encoding="utf-8")) if layers_path.exists() else {"layers": []},
    }


def compact_config(config: dict[str, Any]) -> dict[str, Any]:
    """Return publish-useful config fields while omitting bulky decoded buffers."""
    output: dict[str, Any] = {}
    for key, value in config.items():
        if key in OMITTED_CONFIG_KEYS or value in (None, "", [], {}):
            continue
        output[key] = value
    selected = config.get("selected_layer_config")
    if isinstance(selected, dict) and isinstance(selected.get("config"), dict):
        output["selected_recovered_layer"] = {
            "sha256": selected.get("sha256"),
            "kind": selected.get("kind"),
            "depth": selected.get("depth"),
            "config": compact_config(selected["config"]),
        }
    return output


def _aggregate_config_values(
    config: dict[str, Any], values: dict[str, Counter]
) -> None:
    """Count stable scalar and list config values for the family overview."""
    selected = config.get("selected_layer_config")
    candidates = [config]
    if isinstance(selected, dict) and isinstance(selected.get("config"), dict):
        candidates.append(selected["config"])
    for candidate in candidates:
        for key in AGGREGATE_CONFIG_KEYS:
            value = candidate.get(key)
            items = value if isinstance(value, list) else [value]
            for item in items:
                if isinstance(item, (str, int)) and item not in ("", None):
                    values[key][str(item)] += 1


def summarize_family(summary: dict, pipeline_root: Path) -> dict:
    """Aggregate campaigns, formats, features, and findings across analyzed cases."""
    campaigns, formats, features, findings = Counter(), Counter(), Counter(), []
    config_values: dict[str, Counter] = {
        key: Counter() for key in sorted(AGGREGATE_CONFIG_KEYS)
    }
    cases = []
    for item in summary["cases"]:
        case = load_case(pipeline_root / item["sha256"])
        campaigns[item["campaign"]] += 1
        formats[item["format"]] += 1
        config = case["config"]["config"]
        for feature, present in config.get("features", {}).items():
            if present:
                features[feature] += 1
        _aggregate_config_values(config, config_values)
        findings.extend(case["config"].get("findings", []))
        cases.append(
            {
                **item,
                "limitations": case["config"].get("limitations", []),
                "layer_count": len(case["layers"].get("layers", [])),
            }
        )
    unique_findings = []
    seen = set()
    for finding in findings:
        key = (finding.get("kind"), finding.get("value"), finding.get("role"))
        if key not in seen:
            seen.add(key)
            unique_findings.append(finding)
    return {
        "schema_version": 1,
        "family": summary["family"],
        "signature": summary["signature"],
        "source": summary.get("source", "local-offline-intake"),
        "counts": summary.get("counts", {}),
        "case_count": len(cases),
        "campaigns": dict(sorted(campaigns.items())),
        "formats": dict(sorted(formats.items())),
        "features": dict(sorted(features.items())),
        "config_values": {
            key: dict(sorted(counter.items()))
            for key, counter in config_values.items()
            if counter
        },
        "findings": unique_findings,
        "cases": cases,
        "sample_executed": False,
        "network_contacted": False,
    }


def render_case(item: dict, case: dict) -> str:
    """Render a compact, evidence-qualified case README."""
    findings = case["config"].get("findings", [])
    finding_rows = (
        "\n".join(f"| `{row['value']}` | {row['role']} | {row['confidence']} | {row['source']} |" for row in findings)
        or "| none recovered | - | - | static extraction incomplete |"
    )
    limitations = "\n".join(f"- {value}" for value in case["config"].get("limitations", []))
    layers = case["layers"].get("layers", [])
    layer_rows = (
        "\n".join(
            f"| {row.get('depth', '-')} | `{row.get('kind', 'unknown')}` | "
            f"`{row.get('sha256', 'unknown')}` | {row.get('size', 0)} | "
            f"`{row.get('format', 'unknown')}` |"
            for row in layers
        )
        or "| - | none recovered | - | - | - |"
    )
    config = compact_config(case["config"].get("config", {}))
    return f"""# {item["family"]} case {item["sha256"]}

## Overview

- Original name: `{item["name"]}`
- SHA-256: `{item["sha256"]}`
- Campaign shape: `{item["campaign"]}`
- Format: `{item["format"]}`
- Packing suspected: `{str(item["packing_suspected"]).lower()}`
- Packing classification: `{item.get("packing_classification", "unknown")}`
- Unpack status: `{item.get("unpack_status", "unknown")}`
- Recovered static layers: {item["recovered_artifacts"]}
- Sample executed: false
- Network contacted: false

## Config and C2 evidence

| Value | Role | Confidence | Source |
|---|---|---|---|
{finding_rows}

An embedded value is not proof that the server is live or exclusively controlled by this family.

## Static config snapshot

```json
{json.dumps(config, ensure_ascii=False, indent=2)}
```

The complete normalized extractor output, including bounded decoded-string evidence, is retained in `analysis.json`.

## Recovered layers

| Depth | Kind | SHA-256 | Size | Format |
|---:|---|---|---:|---|
{layer_rows}

Recovered bytes are deliberately not committed.

## Unpacking details

- Root entropy: {case["unpack"]["entropy"]}
- Root packing assessment: `{case["unpack"].get("pe", {}).get("packing_suspected", False)}`
- Recursive layers analyzed: {case["config"].get("layers_analyzed", 0)}
- 7z status: `{case["unpack"].get("sevenzip", {}).get("status", "not_applicable")}`
- UPX status: `{case["unpack"].get("upx", {}).get("status", "not_applicable")}`

## Limitations

{limitations}
"""


def render_family(value: dict) -> str:
    """Render a family README with detection trade-offs and all case outcomes."""
    campaigns = "\n".join(f"- `{key}`: {count}" for key, count in value["campaigns"].items())
    features = (
        "\n".join(f"- `{key}`: {count}/{value['case_count']}" for key, count in value["features"].items())
        or "- none statically visible"
    )
    findings = (
        "\n".join(
            f"| `{row['value']}` | {row['role']} | {row['confidence']} | {row['source']} |" for row in value["findings"]
        )
        or "| none recovered | - | - | packed/encrypted or no literal config |"
    )
    config_values = (
        "\n".join(
            f"- `{key}`: "
            + ", ".join(
                f"`{config_value}` ({count})"
                for config_value, count in values.items()
            )
            for key, values in value["config_values"].items()
        )
        or "- no validated family configuration values recovered"
    )
    cases = "\n".join(
        f"| [{item['sha256'][:12]}](cases/{item['sha256']}/README.md) | {item['format']} | "
        f"{item['campaign']} | {str(item['packing_suspected']).lower()} | {item['recovered_artifacts']} | "
        f"{item['config_findings']} |"
        for item in value["cases"]
    )
    return f"""# {value["signature"]} analysis

{value["case_count"]} `{value["source"]}` submissions were analyzed statically. Delivery shape is separated from malware family because loaders, packers, and operators can vary independently.

## Batch outcome

- Cases: {value["case_count"]}
- Errors: {value["counts"].get("errors", 0)}
- Packing suspected: {value["counts"].get("packing_suspected", 0)}
- Cases with recovered artifacts: {value["counts"].get("with_recovered_artifacts", 0)}
- Cases with validated static config: {value["counts"].get("with_static_config", 0)}
- Sample executed: false
- Network contacted: false

## Campaign/delivery shapes

{campaigns}

## Statically observed behavior features

{features}

## C2/config findings

| Value | Role | Confidence | Source |
|---|---|---|---|
{findings}

No active C2 check-in was performed. Use `analysis-framework/common/c2_candidate_detector.py` for offline assessment and passive-query generation.

## Validated config values

{config_values}

## Cases

| SHA-256 | Format | Campaign | Packed | Layers | Findings |
|---|---|---|---:|---:|---:|
{cases}

## Detection considerations

- **High false-positive risk:** generic access to browser databases, wallets, `osascript`, Go runtime strings, or high-entropy PE sections. Backup, migration, enterprise inventory, installers, and legitimate Go applications can match.
- **Medium false-positive risk:** script interpreter plus network download plus execution, or an unsigned process reading multiple browser/wallet stores. Administrative automation and software deployment can overlap.
- **Low false-positive risk:** combine family-specific strings, reviewed config path/host, credential-store collection, and unusual parent/child or network context. Builder/version changes can still cause false negatives.

Detection rules under `rules/` are starting points and require environment tuning. Literal C2s should be short-lived IOC matches rather than durable family signatures.

## Safety and limitations

- Samples were never executed and recovered layers are not committed.
- External infrastructure was not contacted.
- Unknown packers and password-protected nested archives remain unresolved.
- Source attribution is retained separately from validated static evidence.
"""


def generate(
    summary_path: Path,
    pipeline_root: Path,
    destination: Path,
    acquisition_manifest: Path | None = None,
) -> dict:
    """Write one family index plus normalized per-case reports and JSON."""
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    value = summarize_family(summary, pipeline_root)
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "README.md").write_text(render_family(value), encoding="utf-8")
    (destination / "summary.json").write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if acquisition_manifest:
        manifest = public_manifest(json.loads(acquisition_manifest.read_text(encoding="utf-8")))
        (destination / "malwarebazaar-manifest.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
    for item in value["cases"]:
        case = load_case(pipeline_root / item["sha256"])
        case_root = destination / "cases" / item["sha256"]
        case_root.mkdir(parents=True, exist_ok=True)
        (case_root / "README.md").write_text(render_case(item, case), encoding="utf-8")
        (case_root / "analysis.json").write_text(
            json.dumps({"case": item, **case}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
    return value


def build_parser() -> argparse.ArgumentParser:
    """Build the report-generation parser."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--summary", required=True, type=Path)
    parser.add_argument("--pipeline-root", required=True, type=Path)
    parser.add_argument("--destination", required=True, type=Path)
    parser.add_argument("--acquisition-manifest", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Generate one family report tree."""
    args = build_parser().parse_args(argv)
    value = generate(args.summary, args.pipeline_root, args.destination, args.acquisition_manifest)
    print(json.dumps({"family": value["family"], "cases": value["case_count"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
