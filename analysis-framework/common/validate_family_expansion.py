#!/usr/bin/env python3
"""Validate a profile-family batch without executing samples or contacting infrastructure."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

REPO = Path(__file__).parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from extractors.config_extractor import get_extractor  # noqa: E402
from extractors.profiled_family import load_profiles, normalize_family  # noqa: E402
from malware_io import read_single_aes_zip_member  # noqa: E402
from profiled_family_detector import detect_family  # noqa: E402

FORBIDDEN_RESULT_SUFFIXES = {
    ".bat", ".cab", ".cmd", ".com", ".dll", ".dylib", ".exe", ".hta",
    ".iso", ".jar", ".js", ".jse", ".lnk", ".macho", ".msi", ".ps1",
    ".rar", ".scr", ".so", ".sys", ".vbe", ".vbs", ".zip",
}
REQUIRED_CASE_FILES = {
    "README.md", "IOC-LIST.md", "config.json", "c2-observation-plan.json", "indicators.json",
}

def validate(manifest_path: Path, cache: Path, output_root: Path, run_id: str) -> dict:
    """Verify hashes, detector/extractor routing, public files, and offline safety flags."""
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    profiles = load_profiles()
    errors: list[str] = []
    families: dict[str, int] = {}
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
        case_dir = output_root / family / run_id / "cases" / digest
        missing = sorted(name for name in REQUIRED_CASE_FILES if not (case_dir / name).is_file())
        if missing:
            errors.append(f"{digest}: missing public files {','.join(missing)}")
            continue
        for name in ("config.json", "c2-observation-plan.json", "indicators.json"):
            value = json.loads((case_dir / name).read_text(encoding="utf-8"))
            if value.get("sample_executed") or value.get("executed") or value.get("network_contacted"):
                errors.append(f"{digest}: unsafe public flag in {name}")
    for family in families:
        run_root = output_root / family / run_id
        if run_root.is_dir():
            for path in run_root.rglob("*"):
                if path.is_file() and path.suffix.lower() in FORBIDDEN_RESULT_SUFFIXES:
                    errors.append(f"forbidden result artifact: {path.relative_to(output_root)}")
    if errors:
        raise ValueError("batch validation failed:\n" + "\n".join(errors[:50]))
    return {
        "families": len(families),
        "family_counts": dict(sorted(families.items())),
        "cases": len(items),
        "extractor_findings": findings,
        "static_config_candidates": config_candidates,
        "retry_pending": sum(int(value.get("pending") or 0) for value in manifest.get("source_manifests") or []),
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
