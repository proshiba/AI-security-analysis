#!/usr/bin/env python3
"""Run the offline declarative/unpack/config/C2 pipeline on archives or raw files."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
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
    "ACRStealer": "acrstealer",
    "ValleyRAT": "valleyrat",
    "AsyncRAT": "asyncrat",
    "AgentTesla": "agenttesla",
    "RemcosRAT": "remcosrat",
    "VenomRAT": "venomrat",
    "Formbook": "formbook",
    "Vidar": "vidar",
    "Gh0stRAT": "gh0strat",
    "LummaStealer": "lummastealer",
    "RemusStealer": "remusstealer",
    "Stealc": "stealc",
    "AmosStealer": "amosstealer",
    "AMOS": "amosstealer",
    "Amadey": "amadey",
    "Latrodectus": "latrodectus",
    "DonutLoader": "donutloader",
}
DECLARATIVE_SIZE_LIMIT = 128 * 1024 * 1024
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def validate_claimed_sha256(value: object, field: str = "sha256") -> str:
    """Return one canonical SHA-256 identity or fail closed."""
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise ValueError(f"{field} must be exactly 64 lowercase hexadecimal characters")
    return value


def _contained_child(root: Path, child: Path, field: str) -> Path:
    """Resolve a child and require it to remain below its declared root."""
    resolved_root = root.resolve(strict=True)
    resolved_child = child.resolve(strict=True)
    try:
        resolved_child.relative_to(resolved_root)
    except ValueError as exc:
        raise ValueError(f"{field} escapes manifest storage root: {resolved_child}") from exc
    return resolved_child


def resolve_manifest_archive(manifest_path: Path, value: object) -> Path:
    """Resolve one manifest archive without allowing traversal or symlink escape.

    Existing manifests use either an absolute archive path or a repository-CWD
    relative path. A manifest-local relative path is also accepted, but an
    ambiguous relative path that resolves to two different files is rejected.
    In every case, the authenticated archive must remain below the manifest's
    own storage directory.
    """
    if not isinstance(value, str) or not value.strip():
        raise ValueError("zip_path must be a non-empty string")
    manifest_root = manifest_path.resolve(strict=True).parent
    raw = Path(value)
    candidates = [raw] if raw.is_absolute() else [Path.cwd() / raw, manifest_root / raw]
    resolved: list[Path] = []
    for candidate in candidates:
        try:
            item = candidate.resolve(strict=True)
        except (FileNotFoundError, OSError):
            continue
        if item not in resolved:
            resolved.append(item)
    if not resolved:
        raise FileNotFoundError(f"manifest archive does not exist: {value}")
    if len(resolved) != 1:
        raise ValueError(f"zip_path is ambiguous between working and manifest directories: {value}")
    archive = _contained_child(manifest_root, resolved[0], "zip_path")
    if not archive.is_file():
        raise ValueError(f"zip_path must resolve to a regular file: {archive}")
    return archive


def resolve_case_output(output: Path, claimed_sha256: str) -> Path:
    """Build a hash-keyed output directory and prove containment before writes."""
    claimed = validate_claimed_sha256(claimed_sha256)
    root = output.resolve(strict=False)
    child = (root / claimed).resolve(strict=False)
    try:
        child.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"case output escapes output root: {child}") from exc
    return child


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
    if family == "acrstealer":
        if unpack_report.get("format") == "zip":
            return "archive_or_file_pumped_delivery"
        if unpack_report.get("format") == "ole":
            return "msi_delivery"
        if unpack_report.get("pe", {}).get("containerized"):
            return "sfx_or_embedded_container"
        return "direct_pe_dll_or_related_payload"
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
    result = {
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
    write_json(output / "case-summary.json", result)
    return result


def analyze_item(
    family: str,
    archive: Path,
    output: Path,
    definitions: Path,
    upx: Path | None = None,
    sevenzip: Path | None = None,
    diec: Path | None = None,
    *,
    expected_sha256: str | None = None,
) -> dict:
    """Analyze one authenticated archive without executing or networking it."""
    member = read_single_aes_zip_member(archive)
    digest = hashlib.sha256(member.data).hexdigest()
    if expected_sha256 is not None:
        claimed = validate_claimed_sha256(expected_sha256)
        if digest != claimed:
            raise ValueError(
                f"authenticated inner SHA-256 mismatch: claimed {claimed}, observed {digest}"
            )
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


def load_resumable_analysis(
    output: Path,
    digest: str,
    family: str,
) -> dict | None:
    """安全フラグとSHA-256を検証した完了caseを専門バッチへ復元する。"""

    required_names = (
        "unpack.json",
        "layers.json",
        "config.json",
        "c2-candidates.json",
    )
    if any(not (output / name).is_file() for name in required_names):
        return None
    if output.is_symlink() or any((output / name).is_symlink() for name in required_names):
        raise ValueError(f"resumable case contains a symbolic link: {digest}")

    def read_object(path: Path) -> dict:
        """BOMなしUTF-8 JSON objectだけを再開根拠として読み込む。"""

        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"invalid resumable JSON: {path.name}") from exc
        if not isinstance(value, dict):
            raise ValueError(f"resumable JSON is not an object: {path.name}")
        return value

    unpack = read_object(output / "unpack.json")
    layers = read_object(output / "layers.json")
    config = read_object(output / "config.json")
    c2 = read_object(output / "c2-candidates.json")
    if unpack.get("sha256") != digest or config.get("sample_sha256") != digest:
        raise ValueError(f"resumable case SHA-256 mismatch: {digest}")
    if config.get("family") != family or c2.get("family") != family:
        raise ValueError(f"resumable case family mismatch: {digest}")
    safety_values = (
        unpack.get("executed"),
        unpack.get("network_contacted"),
        layers.get("sample_executed"),
        layers.get("network_contacted"),
        config.get("executed"),
        config.get("network_contacted"),
        c2.get("sample_executed"),
        c2.get("network_contacted"),
    )
    if any(value is not False for value in safety_values):
        raise ValueError(f"resumable case safety flag mismatch: {digest}")
    summary_path = output / "case-summary.json"
    if summary_path.is_file():
        if summary_path.is_symlink():
            raise ValueError(f"resumable summary is a symbolic link: {digest}")
        result = read_object(summary_path)
    else:
        config_body = config.get("config")
        findings = config.get("findings")
        layer_items = layers.get("layers")
        if not isinstance(config_body, dict) or not isinstance(findings, list):
            raise ValueError(f"resumable config structure mismatch: {digest}")
        if not isinstance(layer_items, list):
            raise ValueError(f"resumable layer structure mismatch: {digest}")
        recovered_configs = config_body.get("recovered_layer_configs")
        if not isinstance(recovered_configs, list):
            recovered_configs = []
        pe = unpack.get("pe") if isinstance(unpack.get("pe"), dict) else {}
        result = {
            "sha256": digest,
            "name": unpack.get("name", digest),
            "family": family,
            "campaign": "unknown",
            "format": unpack.get("format", "unknown"),
            "packing_suspected": bool(pe.get("packing_suspected")),
            "packing_classification": pe.get("classification", "not_applicable"),
            "unpack_status": unpack.get("unpack_status", "unknown"),
            "recovered_artifacts": max(len(unpack.get("recovered", [])), len(layer_items)),
            "recovered_configs": len(recovered_configs),
            "static_config_recovered": bool(config_body.get("static_config_recovered")),
            "config_findings": len(findings),
            "c2_assessment": c2.get("assessment", "none"),
            "declarative_status": "resumed_existing_output",
            "sample_executed": False,
            "network_contacted": False,
        }
    if (
        result.get("sha256") != digest
        or result.get("family") != family
        or result.get("sample_executed") is not False
        or result.get("network_contacted") is not False
    ):
        raise ValueError(f"resumable case summary mismatch: {digest}")
    return {**result, "resumed": True}


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
            "resumed": sum(bool(item.get("resumed")) for item in cases),
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
    resume: bool = False,
) -> dict:
    """Analyze every item in one bounded MalwareBazaar family manifest."""
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    family = family_id(manifest["signature"])
    items = manifest.get("items")
    if not isinstance(items, list):
        raise ValueError("manifest items must be a list")
    validated: list[tuple[str, Path, Path]] = []
    seen: set[str] = set()
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            raise ValueError(f"items[{index}] must be an object")
        claimed = validate_claimed_sha256(item.get("sha256"), f"items[{index}].sha256")
        if claimed in seen:
            raise ValueError(f"duplicate manifest SHA-256: {claimed}")
        seen.add(claimed)
        archive = resolve_manifest_archive(manifest_path, item.get("zip_path"))
        case_output = resolve_case_output(output, claimed)
        validated.append((claimed, archive, case_output))
    cases = []
    for claimed, archive, case_output in validated:
        resumed = load_resumable_analysis(case_output, claimed, family) if resume else None
        if resumed is not None:
            cases.append(resumed)
            continue
        cases.append(
            analyze_item(
                family,
                archive,
                case_output,
                definitions,
                upx,
                sevenzip,
                diec,
                expected_sha256=claimed,
            )
        )
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
    parser.add_argument(
        "--resume",
        action="store_true",
        help="検証済みの完了caseを再利用し、未完了caseだけを解析する",
    )
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
            args.resume,
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
