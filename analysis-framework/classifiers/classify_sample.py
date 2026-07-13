from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
from typing import Any

CONFIDENCE_ORDER = {"high": 0, "medium": 1, "low": 2}


def load_detector(framework_root: Path, relative_path: str):
    """Load and return a registered malware detector function by relative path."""
    path = framework_root / relative_path
    spec = importlib.util.spec_from_file_location(f"malware_detector_{path.stem}", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load detector: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.detect


def _unknown_result(path: Path, digest: str, size: int, basis: str = "none") -> dict[str, Any]:
    """Build a normalized low-confidence unknown classification result."""
    return {
        "sample": str(path), "malware_type": "unknown", "malware_type_confidence": "low",
        "attribution_basis": basis, "campaign_type": "unknown", "campaign_confidence": "low",
        "candidates": [], "observations": {"sha256": digest, "size": size},
        "family_label_used_to_select_campaign": False,
    }


def classify(path: Path, registry: Path, malware_type: str | None = None) -> dict[str, Any]:
    """Classify a sample with all detectors or a user-selected malware type.

    When ``malware_type`` is supplied, only that type's registered detector is
    used.  The explicit type is recorded, but campaign selection still depends
    on structural detector evidence rather than a family label alone.
    """
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    registry_data = json.loads(registry.read_text(encoding="utf-8-sig"))["malware_types"]
    if malware_type and malware_type not in registry_data:
        raise ValueError(f"unknown malware type '{malware_type}'; registered: {', '.join(sorted(registry_data))}")
    framework_root = registry.parent.parent
    detections = []
    items = [(malware_type, registry_data[malware_type])] if malware_type else registry_data.items()
    for registered_type, metadata in items:
        detector = load_detector(framework_root, metadata["detector"])
        detection = detector(data, path)
        known_hash = digest in {value.lower() for value in metadata.get("known_sample_sha256", [])}
        if malware_type or known_hash or detection.get("matched"):
            confidence = "high" if known_hash else ("medium" if detection.get("matched") else "low")
            basis = "known_sha256" if known_hash else ("type_detector_structure" if detection.get("matched") else "explicit_user_type_unmatched")
            detections.append({
                "malware_type": registered_type,
                "malware_type_confidence": confidence,
                "attribution_basis": basis,
                "detection": detection,
            })
    if not detections:
        return _unknown_result(path, digest, len(data))
    detections.sort(key=lambda item: CONFIDENCE_ORDER[item["malware_type_confidence"]])
    selected = detections[0]
    campaigns = selected["detection"].get("campaigns", [])
    campaigns.sort(key=lambda item: CONFIDENCE_ORDER.get(item.get("confidence", "low"), 2))
    campaign = campaigns[0] if campaigns else {"campaign_type": "unknown", "confidence": "low"}
    return {
        "sample": str(path), "malware_type": selected["malware_type"],
        "malware_type_confidence": selected["malware_type_confidence"],
        "attribution_basis": selected["attribution_basis"],
        "campaign_type": campaign["campaign_type"], "campaign_confidence": campaign["confidence"],
        "candidates": campaigns,
        "observations": {"sha256": digest, "size": len(data), "type_detector": selected["detection"].get("observations", {})},
        "all_type_detections": detections,
        "family_label_used_to_select_campaign": False,
        "explicit_malware_type": malware_type,
    }


def main() -> int:
    """Parse CLI arguments, classify the sample, and write JSON output."""
    parser = argparse.ArgumentParser(description="Classify malware type via registered detectors, then select a campaign.")
    parser.add_argument("--sample", required=True, type=Path)
    parser.add_argument("--registry", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--malware-type", help="Optional registered malware type to force detector selection without using family label for campaign selection.")
    args = parser.parse_args()
    result = classify(args.sample, args.registry, args.malware_type)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
