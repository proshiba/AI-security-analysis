#!/usr/bin/env python3
"""Validate a profile-family batch without executing samples or contacting infrastructure."""

from __future__ import annotations

import argparse
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import sys

REPO = Path(__file__).parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from extractors.config_extractor import get_extractor  # noqa: E402
from extractors.profiled_family import load_profiles, normalize_family  # noqa: E402
from generate_family_expansion_reports import ioc_indicators, ioc_markdown  # noqa: E402
from generate_ioc_lists import (  # noqa: E402
    IOC_CONFIDENCE_LABELS,
    IOC_HEADER,
    IOC_ROLE_LABELS,
    IOC_SEPARATOR,
    IOC_TYPE_LABELS,
    normalize_value,
)
from malware_io import read_single_aes_zip_member  # noqa: E402
from profiled_family_detector import detect_family  # noqa: E402
from result_layout import (  # noqa: E402
    canonical_collection_manifest_path,
    canonical_collection_source_path,
    canonical_malware_case_path,
)

FORBIDDEN_RESULT_SUFFIXES = {
    ".bat", ".cab", ".cmd", ".com", ".dll", ".dylib", ".exe", ".hta",
    ".iso", ".jar", ".js", ".jse", ".lnk", ".macho", ".msi", ".ps1",
    ".rar", ".scr", ".so", ".sys", ".vbe", ".vbs", ".zip",
}
REQUIRED_CASE_FILES = {
    "README.md", "IOC-LIST.md", "config.json", "c2-observation-plan.json",
    "indicators.json", "metadata.json",
}
IOC_TYPE_VALUES = {label: value for value, label in IOC_TYPE_LABELS.items()}
IOC_CONFIDENCE_VALUES = {label: value for value, label in IOC_CONFIDENCE_LABELS.items()}
IOC_ROLE_VALUES = {label: value for value, label in IOC_ROLE_LABELS.items()}


def _split_ioc_row(line: str) -> list[str] | None:
    """Split one rendered IOC row while preserving escaped Markdown pipes."""
    if not line.startswith("|") or not line.endswith("|"):
        return None
    cells: list[str] = []
    current: list[str] = []
    body = line[1:-1]
    index = 0
    while index < len(body):
        character = body[index]
        if character == "\\" and index + 1 < len(body) and body[index + 1] in {"|", "`"}:
            current.append(body[index + 1])
            index += 2
            continue
        if character == "|":
            cells.append("".join(current).strip())
            current = []
        else:
            current.append(character)
        index += 1
    cells.append("".join(current).strip())
    return cells


def validate_ioc_content(
    path: Path,
    hashes: list[str],
    findings: list[dict],
    label: str,
    *,
    exact: bool = False,
) -> list[str]:
    """Verify the five-column schema, safe normalization, and expected IOC rows."""
    if not path.is_file():
        return [f"{label}: missing IOC-LIST.md"]
    content = path.read_text(encoding="utf-8-sig")
    if exact and content != ioc_markdown(hashes, findings):
        return [f"{label}: stale aggregate IOC content"]
    lines = content.splitlines()
    if len(lines) < 4 or lines[:4] != ["# IOC 一覧", "", IOC_HEADER, IOC_SEPARATOR]:
        return [f"{label}: invalid IOC table contract"]
    rows = []
    errors: list[str] = []
    for index, line in enumerate(lines[4:], start=5):
        if not line:
            errors.append(f"{label}: unexpected blank IOC row at line {index}")
            continue
        cells = _split_ioc_row(line)
        if cells is None or len(cells) != 5:
            errors.append(f"{label}: malformed IOC row at line {index}")
            continue
        kind, value, role, confidence, source = cells
        normalized_kind = IOC_TYPE_VALUES.get(kind, kind)
        normalized_role = IOC_ROLE_VALUES.get(role, role)
        normalized_confidence = IOC_CONFIDENCE_VALUES.get(confidence, confidence)
        normalized = normalize_value(value)
        if normalized != (normalized_kind, value):
            errors.append(f"{label}: unsafe or non-normalized IOC value at line {index}")
            continue
        rows.append((normalized_kind, value, normalized_role, normalized_confidence, source))
    keys = [(kind, value.lower()) for kind, value, *_ in rows]
    if len(keys) != len(set(keys)):
        errors.append(f"{label}: duplicate IOC value")
    expected = {
        (item.type, item.value, item.role, item.confidence)
        for item in ioc_indicators(hashes, findings)
    }
    actual = {(kind, value, role, confidence) for kind, value, role, confidence, _ in rows}
    if expected - actual:
        errors.append(f"{label}: missing expected IOC content")
    return errors


def validate(manifest_path: Path, cache: Path, output_root: Path, run_id: str) -> dict:
    """Verify hashes, detector/extractor routing, public files, and offline safety flags."""
    output_root = output_root.resolve()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    profiles = load_profiles()
    errors: list[str] = []
    catalog_path = output_root / "catalog" / "cases.json"
    try:
        catalog = json.loads(catalog_path.read_text(encoding="utf-8-sig"))
        catalog_cases = catalog.get("cases") if isinstance(catalog, dict) else None
        if not isinstance(catalog_cases, dict):
            raise ValueError("cases is not an object")
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
        catalog_cases = {}
        errors.append("missing or invalid case catalog")
    families: dict[str, int] = {}
    family_hashes: dict[str, list[str]] = defaultdict(list)
    family_findings: dict[str, list[dict]] = defaultdict(list)
    findings = config_candidates = 0
    items = manifest.get("items") or []
    for item in items:
        family = normalize_family(str(item.get("requested_signature") or ""), profiles)
        families[family] = families.get(family, 0) + 1
        member = read_single_aes_zip_member(Path(item["zip_path"]))
        digest = hashlib.sha256(member.data).hexdigest()
        if digest != item.get("sha256"):
            errors.append(f"{digest}: manifest hash mismatch")
            continue
        detection = detect_family(family, member.data, Path(member.name))
        if not detection.get("matched") or detection.get("observations", {}).get("family") != family:
            errors.append(f"{digest}: detector routing failed")
        extraction = get_extractor(family)(member.data, member.name)
        if extraction.get("family") != family:
            errors.append(f"{digest}: extractor routing failed")
        if extraction.get("executed") or extraction.get("network_contacted"):
            errors.append(f"{digest}: unsafe extractor flag")
        findings += len(extraction.get("findings") or [])
        config_candidates += int(bool((extraction.get("config") or {}).get("static_config_recovered")))
        if not (cache / "cases" / digest / "case.json").is_file():
            errors.append(f"{digest}: missing static cache")
        case_dir = canonical_malware_case_path(
            output_root, family, digest, "unknown"
        )
        missing = sorted(name for name in REQUIRED_CASE_FILES if not (case_dir / name).is_file())
        if missing:
            errors.append(f"{digest}: missing public files {','.join(missing)}")
            continue
        catalog_entry = catalog_cases.get(digest)
        expected_catalog = {
            "case_id": f"sha256:{digest}",
            "family": family,
            "case_kind": "malware",
            "version_key": "unknown",
            "canonical_path": case_dir.relative_to(output_root.parent).as_posix(),
        }
        if not isinstance(catalog_entry, dict) or any(
            catalog_entry.get(key) != value for key, value in expected_catalog.items()
        ):
            errors.append(f"{digest}: missing or inconsistent catalog entry")
        for name in (
            "config.json",
            "c2-observation-plan.json",
            "indicators.json",
            "metadata.json",
        ):
            value = json.loads((case_dir / name).read_text(encoding="utf-8"))
            if value.get("sample_executed") or value.get("executed") or value.get("network_contacted"):
                errors.append(f"{digest}: unsafe public flag in {name}")
            if name == "indicators.json":
                source_hash = str((value.get("source") or {}).get("sha256") or "")
                if source_hash != digest:
                    errors.append(f"{digest}: public indicator source hash mismatch")
                case_findings = (value.get("static_analysis") or {}).get("findings") or []
                family_hashes[family].append(digest)
                family_findings[family].extend(case_findings)
                errors.extend(
                    validate_ioc_content(
                        case_dir / "IOC-LIST.md",
                        [digest],
                        case_findings,
                        digest,
                    )
                )
            if name == "metadata.json" and any(
                value.get(key) != expected
                for key, expected in {
                    "case_id": f"sha256:{digest}",
                    "family": family,
                    "case_kind": "malware",
                    "canonical_path": case_dir.relative_to(output_root.parent).as_posix(),
                }.items()
            ):
                errors.append(f"{digest}: inconsistent case metadata")
        for path in case_dir.rglob("*"):
            if path.is_file() and path.suffix.lower() in FORBIDDEN_RESULT_SUFFIXES:
                errors.append(f"forbidden result artifact: {path.relative_to(output_root)}")
    for family in families:
        run_root = canonical_collection_source_path(output_root, run_id, family)
        if run_root.is_dir():
            errors.extend(
                validate_ioc_content(
                    run_root / "IOC-LIST.md",
                    family_hashes[family],
                    family_findings[family],
                    f"{family}/{run_id}",
                    exact=True,
                )
            )
            for path in run_root.rglob("*"):
                if path.is_file() and path.suffix.lower() in FORBIDDEN_RESULT_SUFFIXES:
                    errors.append(f"forbidden result artifact: {path.relative_to(output_root)}")
        else:
            errors.append(f"{family}/{run_id}: missing collection source")
    collection_manifest_path = canonical_collection_manifest_path(output_root, run_id)
    if not collection_manifest_path.is_file():
        errors.append(f"{run_id}: missing collection manifest")
    else:
        collection_manifest = json.loads(
            collection_manifest_path.read_text(encoding="utf-8-sig")
        )
        expected_cases = [
            {"case_id": f"sha256:{str(item.get('sha256') or '').lower()}"}
            for item in sorted(items, key=lambda value: str(value.get("sha256") or ""))
        ]
        expected_sources = [
            {"family": family, "path": f"sources/{family}"}
            for family in sorted(families)
        ]
        if collection_manifest.get("collection_id") != run_id:
            errors.append(f"{run_id}: collection ID mismatch")
        if collection_manifest.get("cases") != expected_cases:
            errors.append(f"{run_id}: collection case references mismatch")
        if any(set(item) != {"case_id"} for item in collection_manifest.get("cases") or []):
            errors.append(f"{run_id}: collection cases must contain case_id only")
        if collection_manifest.get("family_sources") != expected_sources:
            errors.append(f"{run_id}: collection family source mapping mismatch")
    if errors:
        raise ValueError("batch validation failed:\n" + "\n".join(errors[:50]))
    return {
        "families": len(families),
        "family_counts": dict(sorted(families.items())),
        "cases": len(items),
        "extractor_findings": findings,
        "static_config_candidates": config_candidates,
        "retry_pending": sum(int(value.get("pending") or 0) for value in manifest.get("source_manifests") or []),
        "ioc_lists_validated": len(items) + len(families),
        "sample_executed": False,
        "infrastructure_contacted": False,
        "status": "valid",
    }


def build_parser() -> argparse.ArgumentParser:
    """Build the offline batch-validation command-line parser."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--cache", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--run-id", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Validate one batch and print its deterministic summary."""
    args = build_parser().parse_args(argv)
    print(json.dumps(validate(args.manifest, args.cache, args.output_root, args.run_id), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
