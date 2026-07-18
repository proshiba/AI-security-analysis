from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
from typing import Any

CONFIDENCE_ORDER = {"high": 0, "medium": 1, "low": 2}
FRAMEWORK_ROOT = Path(__file__).resolve().parents[1]
FAMILY_ID_RE = re.compile(r"^[a-z0-9_]+$")


class DetectorPathError(ValueError):
    """Raised when registry metadata points outside the detector allowlist."""


def _resolve_detector_path(
    framework_root: Path,
    family: str,
    relative_path: str,
) -> Path:
    """Resolve the exact malware/family/detect.py path below the trusted root."""
    trusted_root = FRAMEWORK_ROOT.resolve(strict=True)
    supplied_root = framework_root.resolve(strict=True)
    if supplied_root != trusted_root:
        raise DetectorPathError(f"untrusted framework root: {supplied_root}")
    if not isinstance(family, str) or FAMILY_ID_RE.fullmatch(family) is None:
        raise DetectorPathError(f"invalid detector family id: {family!r}")
    if not isinstance(relative_path, str):
        raise DetectorPathError("detector path must be a string")
    requested = Path(relative_path)
    expected = Path("malware") / family / "detect.py"
    if requested.is_absolute() or requested != expected:
        raise DetectorPathError(
            f"detector path must be exactly {expected.as_posix()}: {relative_path!r}"
        )
    malware_root = (trusted_root / "malware").resolve(strict=True)
    try:
        resolved = (trusted_root / requested).resolve(strict=True)
        relative = resolved.relative_to(malware_root)
    except (FileNotFoundError, OSError, ValueError) as exc:
        raise DetectorPathError(f"detector path escapes or does not exist: {relative_path!r}") from exc
    if relative.parts != (family, "detect.py") or not resolved.is_file():
        raise DetectorPathError(f"detector path is not allowlisted: {resolved}")
    return resolved


def load_detector(framework_root: Path, relative_path: str, family: str | None = None):
    """Load and return a registered malware detector function by relative path."""
    if family is None:
        parts = Path(relative_path).parts if isinstance(relative_path, str) else ()
        if len(parts) != 3:
            raise DetectorPathError(f"cannot infer detector family from: {relative_path!r}")
        family = parts[1]
    path = _resolve_detector_path(framework_root, family, relative_path)
    common = str(FRAMEWORK_ROOT / "common")
    if common not in sys.path:
        sys.path.insert(0, common)
    spec = importlib.util.spec_from_file_location(
        f"malware_detector_{path.parent.name}_{path.stem}", path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load detector: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    detector = getattr(module, "detect", None)
    if not callable(detector):
        raise RuntimeError(f"detector has no callable detect(): {path}")
    return detector


def detection_uses_known_inner(detection: dict) -> bool:
    """Return whether a detector matched a reviewed inner-object SHA-256."""
    return any(
        "known inner SHA-256" in candidate.get("reasons", [])
        for candidate in detection.get("campaigns", [])
    )


def _unknown_result(
    path: Path,
    digest: str,
    size: int,
    basis: str = "none",
    detector_errors: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Build a normalized low-confidence unknown classification result."""
    return {
        "sample": str(path),
        "malware_type": "unknown",
        "malware_type_confidence": "low",
        "attribution_basis": basis,
        "campaign_type": "unknown",
        "campaign_confidence": "low",
        "candidates": [],
        "observations": {
            "sha256": digest,
            "size": size,
            "detector_errors": detector_errors or {},
        },
        "family_label_used_to_select_campaign": False,
    }


def classify(path: Path, registry: Path, malware_type: str | None = None) -> dict[str, Any]:
    """Classify using all detectors or one explicitly selected type.

    An explicit type limits detector routing but does not independently select a
    campaign. Detector failures are isolated so one optional family handler
    cannot prevent the remaining registered detectors from running.
    """
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    registry_data = json.loads(registry.read_text(encoding="utf-8-sig"))["malware_types"]
    if malware_type and malware_type not in registry_data:
        registered = ", ".join(sorted(registry_data))
        raise ValueError(f"unknown malware type '{malware_type}'; registered: {registered}")

    framework_root = FRAMEWORK_ROOT
    detections = []
    detector_errors: dict[str, str] = {}
    items = [(malware_type, registry_data[malware_type])] if malware_type else registry_data.items()
    for registered_type, metadata in items:
        if not isinstance(metadata, dict):
            detector_errors[registered_type] = (
                "DetectorPathError: registry metadata must be an object"
            )
            continue
        try:
            detector = load_detector(
                framework_root, metadata.get("detector"), registered_type
            )
            detection = detector(data, path)
        except DetectorPathError as exc:
            detector_errors[registered_type] = f"{type(exc).__name__}: {exc}"
            continue
        except Exception as exc:
            detector_errors[registered_type] = f"{type(exc).__name__}: {exc}"
            detection = {"matched": False, "observations": {}, "campaigns": []}

        known_outer = digest in {value.lower() for value in metadata.get("known_sample_sha256", [])}
        known_inner = detection_uses_known_inner(detection)
        if malware_type or known_outer or detection.get("matched"):
            confidence = (
                "high"
                if known_outer or known_inner
                else ("medium" if detection.get("matched") else "low")
            )
            basis = (
                "known_outer_sha256"
                if known_outer
                else (
                    "known_inner_sha256"
                    if known_inner
                    else (
                        "type_detector_structure"
                        if detection.get("matched")
                        else "explicit_user_type_unmatched"
                    )
                )
            )
            detections.append(
                {
                    "malware_type": registered_type,
                    "malware_type_confidence": confidence,
                    "attribution_basis": basis,
                    "detection": detection,
                }
            )

    if not detections:
        return _unknown_result(path, digest, len(data), detector_errors=detector_errors)

    detections.sort(
        key=lambda item: (
            CONFIDENCE_ORDER[item["malware_type_confidence"]],
            item["malware_type"],
        )
    )
    top_rank = CONFIDENCE_ORDER[detections[0]["malware_type_confidence"]]
    top = [
        item
        for item in detections
        if CONFIDENCE_ORDER[item["malware_type_confidence"]] == top_rank
    ]
    if malware_type is None and len(top) > 1:
        return {
            "sample": str(path),
            "malware_type": "unknown",
            "malware_type_confidence": "low",
            "attribution_basis": "ambiguous_type_detection",
            "campaign_type": "unknown",
            "campaign_confidence": "low",
            "campaign_resolution": "ambiguous_type_detection",
            "candidates": [],
            "observations": {
                "sha256": digest,
                "size": len(data),
                "detector_errors": detector_errors,
            },
            "all_type_detections": detections,
            "ambiguous_type_candidates": [
                {
                    "malware_type": item["malware_type"],
                    "malware_type_confidence": item["malware_type_confidence"],
                    "attribution_basis": item["attribution_basis"],
                }
                for item in top
            ],
            "family_label_used_to_select_campaign": False,
            "explicit_malware_type": None,
        }
    selected = detections[0]
    campaigns = sorted(
        selected["detection"].get("campaigns", []),
        key=lambda item: (
            CONFIDENCE_ORDER.get(item.get("confidence", "low"), 2),
            str(item.get("campaign_type", "")),
        ),
    )
    campaign = campaigns[0] if campaigns else {"campaign_type": "unknown", "confidence": "low"}
    campaign_resolution = "selected"
    if campaigns:
        campaign_rank = CONFIDENCE_ORDER.get(campaign.get("confidence", "low"), 2)
        tied_names = {
            str(item.get("campaign_type", "unknown"))
            for item in campaigns
            if CONFIDENCE_ORDER.get(item.get("confidence", "low"), 2) == campaign_rank
        }
        if len(tied_names) > 1:
            campaign = {"campaign_type": "unknown", "confidence": "low"}
            campaign_resolution = "ambiguous_campaign_detection"
    return {
        "sample": str(path),
        "malware_type": selected["malware_type"],
        "malware_type_confidence": selected["malware_type_confidence"],
        "attribution_basis": selected["attribution_basis"],
        "campaign_type": campaign["campaign_type"],
        "campaign_confidence": campaign["confidence"],
        "campaign_resolution": campaign_resolution,
        "candidates": campaigns,
        "observations": {
            "sha256": digest,
            "size": len(data),
            "type_detector": selected["detection"].get("observations", {}),
            "detector_errors": detector_errors,
        },
        "all_type_detections": detections,
        "family_label_used_to_select_campaign": False,
        "explicit_malware_type": malware_type,
    }


def main() -> int:
    """Parse CLI arguments, classify the sample, and write JSON output."""
    parser = argparse.ArgumentParser(
        description="Classify malware type via registered detectors, then select a campaign."
    )
    parser.add_argument("--sample", required=True, type=Path)
    parser.add_argument("--registry", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--malware-type",
        help="Restrict detection to one registered type without using its label to select a campaign.",
    )
    args = parser.parse_args()
    result = classify(args.sample, args.registry, args.malware_type)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
