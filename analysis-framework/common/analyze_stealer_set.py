#!/usr/bin/env python3
"""Run the offline declarative/unpack/config/C2 pipeline on archives or raw files."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

from malware_io import read_single_aes_zip_member, write_json

REPO = Path(__file__).parents[2]
SRC = REPO / "analysis-framework" / "src"
COMMON = REPO / "analysis-framework" / "common"
for location in (REPO, SRC, COMMON):
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
    "AMOS": "amosstealer",
    "Amadey": "amadey",
    "Latrodectus": "latrodectus",
    "DonutLoader": "donutloader",
}
DECLARATIVE_SIZE_LIMIT = 128 * 1024 * 1024


def family_id(signature: str) -> str:
    """Map exact source signatures to declarative family IDs."""
    if signature not in SIGNATURE_IDS:
        raise ValueError(f"unsupported signature: {signature}")
    return SIGNATURE_IDS[signature]


def campaign_hint(family: str, name: str, data: bytes, unpack_report: dict) -> str:
    """Select a delivery/packing shape without asserting operator identity."""
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
        if unpack_report.get("format") == "xz":
            return "xz_macho_delivery"
        if shape.endswith("script_delivery"):
            return "script_delivery"
        if shape in {"macro_office_delivery", "direct_macho"}:
            return shape
    if family == "vidar" and shape == "unknown_or_nested_delivery":
        return "nested_or_protected_delivery"
    if family == "lummastealer":
        strings = data[: min(len(data), 16 * 1024 * 1024)].lower()
        return "go_pe_loader" if b"go build id" in strings or b"runtime.main" in strings else "packed_native_pe"
    if family == "remusstealer":
        if shape == "encrypted_7z_delivery":
            return shape
        strings = data[: min(len(data), 16 * 1024 * 1024)].lower()
        if b"go build id" in strings or b"runtime.main" in strings:
            return "go_pe_loader"
    if family == "donutloader":
        return "direct_shellcode" if unpack_report.get("format") == "data" else "pe_wrapper_or_loader"
    if family == "amadey":
        return "protected_wrapper" if unpack_report.get("pe", {}).get("packing_suspected") else "direct_pe_or_container"
    if family == "latrodectus":
        if unpack_report.get("format") == "ole":
            return "office_delivery"
        return "direct_dll_or_loader"
    return "direct_pe_or_pe_loader"


def _finding_key(item: dict) -> tuple[object, object, object]:
    """Return the stable identity tuple used to merge findings."""
    return item.get("kind"), item.get("value"), item.get("role")


def merge_findings(results: list[dict]) -> list[dict]:
    """Deduplicate findings from root and recovered layers in stable order."""
    merged: list[dict] = []
    seen: set[tuple[object, object, object]] = set()
    for result in results:
        for finding in result.get("findings", []):
            key = _finding_key(finding)
            if key not in seen:
                seen.add(key)
                merged.append(finding)
    return merged


def analyze_layers(
    family: str,
    artifacts: list[tuple[str, bytes]],
    upx: Path | None = None,
    sevenzip: Path | None = None,
    diec: Path | None = None,
    max_depth: int = 3,
) -> tuple[list[dict], list[tuple[str, bytes]]]:
    """Recursively analyze bounded recovered layers and deduplicate artifacts."""
    queue = [(kind, blob, 1) for kind, blob in artifacts]
    retained = list(artifacts)
    layers: list[dict] = []
    seen: set[str] = set()
    retained_hashes = {hashlib.sha256(value).hexdigest() for _, value in retained}
    while queue and len(layers) < 128:
        kind, blob, depth = queue.pop(0)
        digest = hashlib.sha256(blob).hexdigest()
        if digest in seen:
            continue
        seen.add(digest)
        unpack_report, children = unpack_bytes(blob, f"{kind}.bin", upx, sevenzip, diec)
        extracted = get_extractor(family)(blob, f"{kind}.bin")
        layers.append(
            {
                "depth": depth,
                "kind": kind,
                "sha256": digest,
                "size": len(blob),
                "format": unpack_report["format"],
                "unpack": unpack_report,
                "config": extracted["config"],
                "findings": extracted["findings"],
                "limitations": extracted["limitations"],
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


def analyze_payload(
    family: str,
    data: bytes,
    name: str,
    source_path: Path,
    output: Path,
    definitions: Path,
    upx: Path | None = None,
    sevenzip: Path | None = None,
    diec: Path | None = None,
    max_depth: int = 3,
    archive_recovered: bool = False,
) -> dict:
    """Analyze one in-memory payload without execution or network access."""
    digest = hashlib.sha256(data).hexdigest()
    unpack_report, artifacts = unpack_bytes(data, name, upx, sevenzip, diec)
    campaign = campaign_hint(family, name, data, unpack_report)
    root_config = get_extractor(family)(data, name)
    layers, retained = analyze_layers(
        family, artifacts, upx, sevenzip, diec, max_depth=max_depth
    )
    layer_results = [
        {"findings": item["findings"], "config": item["config"]} for item in layers
    ]
    findings = merge_findings([root_config, *layer_results])
    recovered_configs = [
        {
            "sha256": item["sha256"],
            "kind": item["kind"],
            "depth": item["depth"],
            "config": item["config"],
        }
        for item in layers
        if item["config"].get("static_config_recovered")
    ]
    combined = {**root_config, "findings": findings, "layers_analyzed": len(layers)}
    combined["config"] = {
        **root_config["config"],
        "static_config_recovered": bool(
            root_config["config"].get("static_config_recovered") or recovered_configs
        ),
        "recovered_layer_configs": recovered_configs,
    }
    if recovered_configs:
        combined["config"]["selected_layer_config"] = recovered_configs[-1]
    c2 = assess(combined)
    output.mkdir(parents=True, exist_ok=True)
    write_json(output / "unpack.json", unpack_report)
    write_json(
        output / "layers.json",
        {"layers": layers, "sample_executed": False, "network_contacted": False},
    )
    write_json(output / "config.json", combined)
    write_json(output / "c2-candidates.json", c2)
    if archive_recovered and retained:
        write_artifacts(output / "recovered-artifacts.zip", retained)
    if len(data) <= DECLARATIVE_SIZE_LIMIT:
        declarative = run_analysis(
            source_path,
            definitions,
            output / "declarative",
            family_hint=family,
            campaign_hint=campaign,
            unwrap_archive=archive_recovered,
        )
        declarative_status = declarative["plan_status"]
    else:
        declarative_status = "skipped_size_limit"
    pe = unpack_report.get("pe", {})
    return {
        "sha256": digest,
        "name": name,
        "family": family,
        "campaign": campaign,
        "format": unpack_report["format"],
        "packing_suspected": pe.get("packing_suspected", False),
        "packing_classification": pe.get("classification", "not_applicable"),
        "unpack_status": unpack_report.get("unpack_status", "unknown"),
        "recovered_artifacts": len(retained),
        "recovered_configs": len(recovered_configs),
        "static_config_recovered": combined["config"]["static_config_recovered"],
        "config_findings": len(findings),
        "c2_assessment": c2["assessment"],
        "declarative_status": declarative_status,
        "sample_executed": False,
        "network_contacted": False,
    }


def analyze_item(
    family: str,
    archive: Path,
    output: Path,
    definitions: Path,
    upx: Path | None = None,
    sevenzip: Path | None = None,
    diec: Path | None = None,
) -> dict:
    """Analyze one authenticated archive without executing or networking it."""
    member = read_single_aes_zip_member(archive)
    return analyze_payload(
        family,
        member.data,
        member.name,
        archive,
        output,
        definitions,
        upx,
        sevenzip,
        diec,
        archive_recovered=True,
    )


def analyze_file(
    family: str,
    sample: Path,
    output_root: Path,
    definitions: Path,
    upx: Path | None = None,
    sevenzip: Path | None = None,
    diec: Path | None = None,
    max_depth: int = 3,
    data: bytes | None = None,
) -> dict:
    """Analyze one raw local sample, optionally reusing caller-supplied bytes."""
    payload = sample.read_bytes() if data is None else data
    digest = hashlib.sha256(payload).hexdigest()
    return analyze_payload(
        family,
        payload,
        sample.name,
        sample,
        output_root / digest,
        definitions,
        upx,
        sevenzip,
        diec,
        max_depth=max_depth,
        archive_recovered=False,
    )


def build_summary(signature: str, family: str, cases: list[dict], source: str) -> dict:
    """Build deterministic aggregate counts for one completed family batch."""
    return {
        "schema_version": 2,
        "signature": signature,
        "family": family,
        "source": source,
        "cases": cases,
        "counts": {
            "total": len(cases),
            "errors": sum("error" in item for item in cases),
            "packing_suspected": sum(bool(item.get("packing_suspected")) for item in cases),
            "with_recovered_artifacts": sum(item.get("recovered_artifacts", 0) > 0 for item in cases),
            "with_static_config": sum(bool(item.get("static_config_recovered")) for item in cases),
            "with_config_findings": sum(item.get("config_findings", 0) > 0 for item in cases),
        },
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
    cases = [
        analyze_item(
            family,
            Path(item["zip_path"]),
            output / item["sha256"],
            definitions,
            upx,
            sevenzip,
            diec,
        )
        for item in manifest["items"]
    ]
    summary = build_summary(manifest["signature"], family, cases, "malwarebazaar")
    write_json(output / "summary.json", summary)
    return summary


def analyze_directory(
    family: str,
    input_root: Path,
    output: Path,
    definitions: Path,
    signature: str | None = None,
    upx: Path | None = None,
    sevenzip: Path | None = None,
    diec: Path | None = None,
    max_depth: int = 3,
) -> dict:
    """Analyze all unique files below a directory as one offline family batch."""
    samples = sorted(path for path in input_root.rglob("*") if path.is_file())
    if not samples:
        raise ValueError(f"no files below: {input_root}")
    cases: list[dict] = []
    seen: set[str] = set()
    for sample in samples:
        data = sample.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        if digest in seen:
            continue
        seen.add(digest)
        try:
            cases.append(
                analyze_file(
                    family,
                    sample,
                    output,
                    definitions,
                    upx,
                    sevenzip,
                    diec,
                    max_depth,
                    data,
                )
            )
        except Exception as exc:
            cases.append(
                {
                    "sha256": digest,
                    "name": sample.name,
                    "family": family,
                    "error": type(exc).__name__,
                    "sample_executed": False,
                    "network_contacted": False,
                }
            )
    summary = build_summary(signature or family, family, cases, "vx-underground")
    write_json(output / "summary.json", summary)
    return summary


def build_parser() -> argparse.ArgumentParser:
    """Build the archive-or-directory batch analysis parser."""
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--manifest", type=Path)
    source.add_argument("--input-root", type=Path)
    parser.add_argument("--family")
    parser.add_argument("--signature")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--definitions", required=True, type=Path)
    parser.add_argument("--upx", type=Path)
    parser.add_argument("--sevenzip", type=Path)
    parser.add_argument("--diec", type=Path)
    parser.add_argument("--max-depth", type=int, default=3, choices=range(1, 6))
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run one manifest or raw directory and print aggregate counts."""
    args = build_parser().parse_args(argv)
    if args.manifest:
        result = analyze_manifest(
            args.manifest,
            args.output,
            args.definitions,
            args.upx,
            args.sevenzip,
            args.diec,
        )
    else:
        if not args.family:
            raise SystemExit("--family is required with --input-root")
        result = analyze_directory(
            args.family,
            args.input_root,
            args.output,
            args.definitions,
            args.signature,
            args.upx,
            args.sevenzip,
            args.diec,
            args.max_depth,
        )
    print(json.dumps({"family": result["family"], **result["counts"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
