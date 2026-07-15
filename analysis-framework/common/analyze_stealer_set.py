#!/usr/bin/env python3
"""Run the offline declarative/unpack/config/C2 pipeline for one supported family manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

from malware_io import read_single_aes_zip_member, write_json

REPO = Path(__file__).parents[2]
SRC = REPO / "analysis-framework" / "src"
for location in (REPO, SRC):
    if str(location) not in sys.path:
        sys.path.insert(0, str(location))

from asa.runner import run_analysis  # noqa: E402
from c2_candidate_detector import assess  # noqa: E402
from extractors.config_extractor import get_extractor  # noqa: E402
from extractors.stealer_common import campaign_shape  # noqa: E402
from unpackers.static_unpacker import unpack_bytes, write_artifacts  # noqa: E402

SIGNATURE_IDS = {
    "ValleyRAT": "valleyrat",
    "AgentTesla": "agenttesla",
    "RemcosRAT": "remcosrat",
    "VenomRAT": "venomrat",
    "Formbook": "formbook",
    "Vidar": "vidar",
    "LummaStealer": "lummastealer",
    "RemusStealer": "remusstealer",
    "AmosStealer": "amosstealer",
}


def family_id(signature: str) -> str:
    """Map exact MalwareBazaar signatures to declarative family IDs."""
    if signature not in SIGNATURE_IDS:
        raise ValueError(f"unsupported signature: {signature}")
    return SIGNATURE_IDS[signature]


def campaign_hint(family: str, name: str, data: bytes, unpack_report: dict) -> str:
    """Select a delivery/packing campaign shape without asserting operator identity."""
    shape = campaign_shape(name, data)
    if family in {"valleyrat", "agenttesla", "remcosrat", "venomrat"}:
        if unpack_report.get("format") == "ole":
            return "macro_office_delivery"
        if shape.endswith("_script_delivery"):
            return "script_delivery"
        if shape == "unknown_or_nested_delivery":
            return shape
        return "direct_pe_or_pe_loader"
    if family == "formbook":
        if shape.endswith("script_delivery"):
            return "script_delivery"
        if shape == "macro_office_delivery":
            return shape
    if family == "amosstealer":
        if shape.endswith("script_delivery"):
            return "script_delivery"
        if shape in {"macro_office_delivery", "direct_macho"}:
            return shape
    if family == "vidar" and shape == "unknown_or_nested_delivery":
        return "nested_zip_delivery"
    if family == "lummastealer":
        strings = data[: min(len(data), 16 * 1024 * 1024)].lower()
        return "go_pe_loader" if b"go build id" in strings or b"runtime.main" in strings else "packed_native_pe"
    if family == "remusstealer":
        if shape == "encrypted_7z_delivery":
            return shape
        strings = data[: min(len(data), 16 * 1024 * 1024)].lower()
        if b"go build id" in strings or b"runtime.main" in strings:
            return "go_pe_loader"
    return "direct_pe_or_pe_loader"


def analyze_layers(
    family: str,
    artifacts: list[tuple[str, bytes]],
    upx: Path | None = None,
    sevenzip: Path | None = None,
    diec: Path | None = None,
    max_depth: int = 2,
) -> tuple[list[dict], list[tuple[str, bytes]]]:
    """Recursively analyze bounded recovered layers and deduplicate artifacts."""
    queue = [(kind, blob, 1) for kind, blob in artifacts]
    retained = list(artifacts)
    layers = []
    seen = set()
    retained_hashes = {hashlib.sha256(value).hexdigest() for _, value in retained}
    while queue and len(layers) < 64:
        kind, blob, depth = queue.pop(0)
        digest = hashlib.sha256(blob).hexdigest()
        if digest in seen:
            continue
        seen.add(digest)
        unpack_report, children = unpack_bytes(blob, f"{kind}.bin", upx, sevenzip, diec)
        config = get_extractor(family)(blob, f"{kind}.bin")
        layers.append(
            {
                "depth": depth,
                "kind": kind,
                "sha256": digest,
                "size": len(blob),
                "format": unpack_report["format"],
                "unpack": unpack_report,
                "findings": config["findings"],
                "limitations": config["limitations"],
            }
        )
        for child_kind, child in children:
            child_digest = hashlib.sha256(child).hexdigest()
            if child_digest not in retained_hashes:
                retained.append((child_kind, child))
                retained_hashes.add(child_digest)
            if depth < max_depth:
                queue.append((child_kind, child, depth + 1))
    return layers, retained


def analyze_item(
    family: str,
    archive: Path,
    output: Path,
    definitions: Path,
    upx: Path | None = None,
    sevenzip: Path | None = None,
    diec: Path | None = None,
) -> dict:
    """Analyze one authenticated archive without executing or networking the sample."""
    member = read_single_aes_zip_member(archive)
    unpack_report, artifacts = unpack_bytes(member.data, member.name, upx, sevenzip, diec)
    campaign = campaign_hint(family, member.name, member.data, unpack_report)
    config = get_extractor(family)(member.data, member.name)
    layers, retained = analyze_layers(family, artifacts, upx, sevenzip, diec)
    findings = list(config["findings"])
    known = {(item.get("kind"), item.get("value"), item.get("role")) for item in findings}
    for layer in layers:
        for finding in layer["findings"]:
            key = (finding.get("kind"), finding.get("value"), finding.get("role"))
            if key not in known:
                known.add(key)
                findings.append(finding)
    combined = {**config, "findings": findings, "layers_analyzed": len(layers)}
    c2 = assess(combined)
    output.mkdir(parents=True, exist_ok=True)
    write_json(output / "unpack.json", unpack_report)
    write_json(output / "layers.json", {"layers": layers, "sample_executed": False, "network_contacted": False})
    write_json(output / "config.json", combined)
    write_json(output / "c2-candidates.json", c2)
    if retained:
        write_artifacts(output / "recovered-artifacts.zip", retained)
    declarative = run_analysis(
        archive,
        definitions,
        output / "declarative",
        family_hint=family,
        campaign_hint=campaign,
    )
    return {
        "sha256": member.sha256,
        "name": member.name,
        "family": family,
        "campaign": campaign,
        "format": unpack_report["format"],
        "packing_suspected": unpack_report.get("pe", {}).get("packing_suspected", False),
        "recovered_artifacts": len(retained),
        "config_findings": len(combined["findings"]),
        "c2_assessment": c2["assessment"],
        "declarative_status": declarative["plan_status"],
        "sample_executed": False,
        "network_contacted": False,
    }


def analyze_manifest(
    manifest_path: Path,
    output: Path,
    definitions: Path,
    upx: Path | None = None,
    sevenzip: Path | None = None,
    diec: Path | None = None,
) -> dict:
    """Analyze every item in one bounded MalwareBazaar family manifest."""
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    family = family_id(manifest["signature"])
    cases = []
    for item in manifest["items"]:
        cases.append(
            analyze_item(
                family,
                Path(item["zip_path"]),
                output / item["sha256"],
                definitions,
                upx,
                sevenzip,
                diec,
            )
        )
    summary = {
        "schema_version": 1,
        "signature": manifest["signature"],
        "family": family,
        "cases": cases,
        "counts": {
            "total": len(cases),
            "packing_suspected": sum(item["packing_suspected"] for item in cases),
            "with_recovered_artifacts": sum(item["recovered_artifacts"] > 0 for item in cases),
            "with_config_findings": sum(item["config_findings"] > 0 for item in cases),
        },
        "sample_executed": False,
        "network_contacted": False,
    }
    write_json(output / "summary.json", summary)
    return summary


def build_parser() -> argparse.ArgumentParser:
    """Build the family-manifest analysis parser."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--definitions", required=True, type=Path)
    parser.add_argument("--upx", type=Path)
    parser.add_argument("--sevenzip", type=Path)
    parser.add_argument("--diec", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run one manifest and print its aggregate counts."""
    args = build_parser().parse_args(argv)
    result = analyze_manifest(
        args.manifest, args.output, args.definitions, args.upx, args.sevenzip, args.diec
    )
    print(json.dumps({"family": result["family"], **result["counts"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
