#!/usr/bin/env python3
"""Generate publish-safe family and case reports from offline stealer results."""

from __future__ import annotations

import argparse
from collections import Counter
import json
import os
from pathlib import Path
from typing import Any

from malwarebazaar_batch import public_manifest
from result_publication import (
    PublicationError,
    detect_publication_context,
    publication_case_path,
    register_publication_cases,
)

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


def _aggregate_config_values(config: dict[str, Any], values: dict[str, Counter]) -> None:
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
    config_values: dict[str, Counter] = {key: Counter() for key in sorted(AGGREGATE_CONFIG_KEYS)}
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
        "config_values": {key: dict(sorted(counter.items())) for key, counter in config_values.items() if counter},
        "findings": unique_findings,
        "cases": cases,
        "sample_executed": False,
        "network_contacted": False,
    }


from report_templates_ja import render_case, render_family  # noqa: E402


def _sum_counts(left: dict, right: dict) -> dict:
    """数値カウンターをキー単位で加算する。"""
    keys = set(left) | set(right)
    return {
        key: int(left.get(key, 0)) + int(right.get(key, 0))
        for key in sorted(keys)
    }


def _merge_counter_maps(left: dict, right: dict) -> dict:
    """単層の名前別カウンターを加算する。"""
    return _sum_counts(left, right)


def _merge_config_values(left: dict, right: dict) -> dict:
    """設定キー別の値カウンターを加算する。"""
    return {
        key: _sum_counts(left.get(key, {}), right.get(key, {}))
        for key in sorted(set(left) | set(right))
    }


def merge_family_summaries(existing: dict, addition: dict) -> dict:
    """既存ファミリ集計へ重複しない追加ケースを安全に統合する。"""
    for key in ("schema_version", "family", "signature", "source"):
        if existing.get(key) != addition.get(key):
            raise ValueError(f"summary {key} mismatch")
    if any(existing.get(key) or addition.get(key) for key in ("sample_executed", "network_contacted")):
        raise ValueError("unsafe summary cannot be appended")
    old_hashes = {item["sha256"] for item in existing.get("cases", [])}
    new_hashes = {item["sha256"] for item in addition.get("cases", [])}
    overlap = sorted(old_hashes & new_hashes)
    if overlap:
        raise ValueError(f"duplicate cases cannot be appended: {overlap[0]}")
    findings = []
    seen_findings = set()
    for finding in [*existing.get("findings", []), *addition.get("findings", [])]:
        identity = (finding.get("kind"), finding.get("value"), finding.get("role"))
        if identity not in seen_findings:
            seen_findings.add(identity)
            findings.append(finding)
    cases = sorted(
        [*existing.get("cases", []), *addition.get("cases", [])],
        key=lambda item: item["sha256"],
    )
    return {
        "schema_version": 1,
        "family": existing["family"],
        "signature": existing["signature"],
        "source": existing["source"],
        "counts": _sum_counts(existing.get("counts", {}), addition.get("counts", {})),
        "case_count": len(cases),
        "campaigns": _merge_counter_maps(existing.get("campaigns", {}), addition.get("campaigns", {})),
        "formats": _merge_counter_maps(existing.get("formats", {}), addition.get("formats", {})),
        "features": _merge_counter_maps(existing.get("features", {}), addition.get("features", {})),
        "config_values": _merge_config_values(existing.get("config_values", {}), addition.get("config_values", {})),
        "findings": findings,
        "cases": cases,
        "sample_executed": False,
        "network_contacted": False,
    }


def merge_public_manifests(existing: dict, addition: dict) -> dict:
    """ローカルパスを含まない取得マニフェストをSHA-256単位で統合する。"""
    old_items = {item["sha256"]: item for item in existing.get("items", [])}
    new_items = {item["sha256"]: item for item in addition.get("items", [])}
    overlap = sorted(set(old_items) & set(new_items))
    if overlap:
        raise ValueError(f"duplicate acquisition item cannot be appended: {overlap[0]}")
    merged = {**existing, **addition}
    items = [*(old_items.values()), *(new_items.values())]
    items.sort(key=lambda item: item["sha256"])
    merged["items"] = items
    selected = {
        str(value).lower()
        for value in [
            *existing.get("selected_hashes", []),
            *addition.get("selected_hashes", []),
        ]
    }
    if selected:
        merged["selected_hashes"] = sorted(selected)
    merged["requested"] = len(items)
    merged["downloaded"] = len(items)
    merged["pending"] = int(existing.get("pending", 0)) + int(addition.get("pending", 0))
    merged["complete"] = bool(existing.get("complete", True) and addition.get("complete", True))
    merged["archives_remain_encrypted"] = bool(
        existing.get("archives_remain_encrypted", True)
        and addition.get("archives_remain_encrypted", True)
    )
    merged["samples_executed"] = False
    return merged


def generate(
    summary_path: Path,
    pipeline_root: Path,
    destination: Path,
    acquisition_manifest: Path | None = None,
    append: bool = False,
) -> dict:
    """Write one family index plus normalized per-case reports and JSON."""
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    addition = summarize_family(summary, pipeline_root)
    destination.mkdir(parents=True, exist_ok=True)
    summary_output = destination / "summary.json"
    if append and summary_output.is_file():
        existing = json.loads(summary_output.read_text(encoding="utf-8"))
        value = merge_family_summaries(existing, addition)
    else:
        value = addition
    summary_output.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if acquisition_manifest:
        manifest = public_manifest(json.loads(acquisition_manifest.read_text(encoding="utf-8")))
        manifest_output = destination / "malwarebazaar-manifest.json"
        if append and manifest_output.is_file():
            manifest = merge_public_manifests(
                json.loads(manifest_output.read_text(encoding="utf-8")), manifest
            )
        manifest_output.write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
    canonical_context = None
    try:
        canonical_context = detect_publication_context(destination, destination.name)
    except PublicationError:
        if any(
            parent.name == "analysis-results"
            for parent in destination.resolve().parents
        ):
            raise
    case_links: dict[str, str] = {}
    published_cases: list[Path] = []
    for item in addition["cases"]:
        case = load_case(pipeline_root / item["sha256"])
        if canonical_context is None:
            case_root = destination / "cases" / item["sha256"]
        else:
            case_root, resolved_context = publication_case_path(
                destination, canonical_context.family, item["sha256"]
            )
            if resolved_context != canonical_context:
                raise PublicationError(
                    "publication context changed during generation"
                )
        case_root.mkdir(parents=True, exist_ok=True)
        case_links[item["sha256"]] = Path(
            os.path.relpath(case_root / "README.md", destination)
        ).as_posix()
        (case_root / "README.md").write_text(render_case(item, case), encoding="utf-8")
        (case_root / "analysis.json").write_text(
            json.dumps(
                {"schema_version": 1, "case": item, **case},
                ensure_ascii=False,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        published_cases.append(case_root)
    for item in value["cases"]:
        if item["sha256"] in case_links:
            continue
        if canonical_context is None:
            case_root = destination / "cases" / item["sha256"]
            if not case_root.is_dir():
                raise PublicationError(f"existing case is missing: {item['sha256']}")
        else:
            case_root, resolved_context = publication_case_path(
                destination, canonical_context.family, item["sha256"]
            )
            if resolved_context != canonical_context or not case_root.is_dir():
                raise PublicationError(
                    f"existing canonical case is missing: {item['sha256']}"
                )
        case_links[item["sha256"]] = Path(
            os.path.relpath(case_root / "README.md", destination)
        ).as_posix()
    (destination / "README.md").write_text(
        render_family(value, case_links), encoding="utf-8"
    )
    if canonical_context is not None:
        register_publication_cases(canonical_context, published_cases)
    return value


def build_parser() -> argparse.ArgumentParser:
    """Build the report-generation parser."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--summary", required=True, type=Path)
    parser.add_argument("--pipeline-root", required=True, type=Path)
    parser.add_argument("--destination", required=True, type=Path)
    parser.add_argument("--acquisition-manifest", type=Path)
    parser.add_argument("--append", action="store_true", help="既存集計へ重複しないケースを追記する")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Generate one family report tree."""
    args = build_parser().parse_args(argv)
    value = generate(args.summary, args.pipeline_root, args.destination, args.acquisition_manifest, args.append)
    print(json.dumps({"family": value["family"], "cases": value["case_count"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
