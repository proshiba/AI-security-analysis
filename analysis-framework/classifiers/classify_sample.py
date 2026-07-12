from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

CONFIDENCE_ORDER = {"high": 0, "medium": 1, "low": 2}


def load_detector(framework_root: Path, relative_path: str):
    path = framework_root / relative_path
    spec = importlib.util.spec_from_file_location(f"malware_detector_{path.stem}", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load detector: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.detect


def classify(path: Path, registry: Path) -> dict:
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    registry_data = json.loads(registry.read_text(encoding="utf-8-sig"))["malware_types"]
    framework_root = registry.parent.parent
    detections = []
    for malware_type, metadata in registry_data.items():
        detector = load_detector(framework_root, metadata["detector"])
        detection = detector(data, path)
        known_hash = digest in {value.lower() for value in metadata.get("known_sample_sha256", [])}
        if known_hash or detection.get("matched"):
            detections.append({
                "malware_type": malware_type,
                "malware_type_confidence": "high" if known_hash else "medium",
                "attribution_basis": "known_sha256" if known_hash else "type_detector_structure",
                "detection": detection,
            })
    if not detections:
        return {
            "sample": str(path), "malware_type": "unknown", "malware_type_confidence": "low",
            "attribution_basis": "none", "campaign_type": "unknown", "campaign_confidence": "low",
            "candidates": [], "observations": {"sha256": digest, "size": len(data)},
            "family_label_used_to_select_campaign": False,
        }
    detections.sort(key=lambda item: CONFIDENCE_ORDER[item["malware_type_confidence"]])
    selected = detections[0]
    campaigns = selected["detection"].get("campaigns", [])
    campaigns.sort(key=lambda item: CONFIDENCE_ORDER[item["confidence"]])
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
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Classify malware type via registered detectors, then select a campaign.")
    parser.add_argument("--sample", required=True, type=Path)
    parser.add_argument("--registry", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    result = classify(args.sample, args.registry)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
