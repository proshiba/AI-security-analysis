from __future__ import annotations

import argparse
from functools import lru_cache
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
    """レジストリが許可外の検出器を指した場合に送出する。"""


def _resolve_detector_path(
    framework_root: Path,
    family: str,
    relative_path: str,
) -> Path:
    """信頼済みroot配下の正確なmalware/family/detect.pyだけを解決する。"""
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


@lru_cache(maxsize=None)
def load_detector(framework_root: Path, relative_path: str, family: str | None = None):
    """登録済み相対pathを検証し、マルウェア検出関数を返す。"""
    if family is None:
        parts = Path(relative_path).parts if isinstance(relative_path, str) else ()
        if len(parts) != 3:
            raise DetectorPathError(f"cannot infer detector family from: {relative_path!r}")
        family = parts[1]
    path = _resolve_detector_path(framework_root, family, relative_path)
    # 一部の既存検出器は ``extractors.*``、別の検出器は ``common`` 配下を
    # トップレベルモジュールとして参照する。いずれも検証済みの固定ルートだけを
    # 追加し、レジストリ値から任意の検索パスを注入しない。
    for trusted_import_root in (FRAMEWORK_ROOT, FRAMEWORK_ROOT / "common"):
        value = str(trusted_import_root)
        if value not in sys.path:
            sys.path.insert(0, value)
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
    """検出器がレビュー済み内包SHA-256へ一致したか返す。"""
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
    """低確度unknownの正規化済み分類結果を構築する。"""
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


def evaluate_detectors(
    data: bytes,
    source: Path,
    registry: Path,
    malware_type: str | None = None,
) -> dict[str, Any]:
    """全登録検出器の適用可否を、失敗を分離しながら評価する。"""

    digest = hashlib.sha256(data).hexdigest()
    registry_data = json.loads(registry.read_text(encoding="utf-8-sig"))["malware_types"]
    if malware_type and malware_type not in registry_data:
        registered = ", ".join(sorted(registry_data))
        raise ValueError(f"unknown malware type '{malware_type}'; registered: {registered}")

    framework_root = FRAMEWORK_ROOT
    evaluations: list[dict[str, Any]] = []
    detector_errors: dict[str, str] = {}
    items = [(malware_type, registry_data[malware_type])] if malware_type else registry_data.items()
    for registered_type, metadata in items:
        evaluation: dict[str, Any] = {
            "malware_type": registered_type,
            "detector": metadata.get("detector") if isinstance(metadata, dict) else None,
            "known_outer_sha256": False,
            "known_inner_sha256": False,
            "detector_matched": False,
            "applicable": False,
            "error": None,
            "detection": {"matched": False, "observations": {}, "campaigns": []},
        }
        if not isinstance(metadata, dict):
            error = "DetectorPathError: registry metadata must be an object"
            detector_errors[registered_type] = error
            evaluation["error"] = error
            evaluations.append(evaluation)
            continue
        known_outer = digest in {
            value.lower() for value in metadata.get("known_sample_sha256", [])
        }
        evaluation["known_outer_sha256"] = known_outer
        try:
            detector = load_detector(
                framework_root, metadata.get("detector"), registered_type
            )
            detection = detector(data, source)
            if not isinstance(detection, dict):
                raise TypeError("detector result must be an object")
        except DetectorPathError as exc:
            error = f"{type(exc).__name__}: {exc}"
            detector_errors[registered_type] = error
            evaluation["error"] = error
            detection = evaluation["detection"]
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
            detector_errors[registered_type] = error
            evaluation["error"] = error
            detection = {"matched": False, "observations": {}, "campaigns": []}
        known_inner = detection_uses_known_inner(detection)
        detector_matched = bool(detection.get("matched"))
        evaluation.update(
            known_inner_sha256=known_inner,
            detector_matched=detector_matched,
            applicable=bool(malware_type or known_outer or detector_matched),
            detection=detection,
        )
        evaluations.append(evaluation)
    return {
        "sha256": digest,
        "size": len(data),
        "source_name": source.name,
        "evaluations": evaluations,
        "detector_errors": detector_errors,
    }


def _classify_evaluations(
    source: Path,
    assessment: dict[str, Any],
    malware_type: str | None,
) -> dict[str, Any]:
    """正規化した検出器評価から曖昧性を保持した分類結果を構築する。"""

    digest = assessment["sha256"]
    size = assessment["size"]
    detector_errors = assessment["detector_errors"]
    detections = []
    for evaluation in assessment["evaluations"]:
        if evaluation["applicable"]:
            known_outer = evaluation["known_outer_sha256"]
            known_inner = evaluation["known_inner_sha256"]
            detector_matched = evaluation["detector_matched"]
            confidence = (
                "high"
                if known_outer or known_inner
                else ("medium" if detector_matched else "low")
            )
            basis = (
                "known_outer_sha256"
                if known_outer
                else (
                    "known_inner_sha256"
                    if known_inner
                    else (
                        "type_detector_structure"
                        if detector_matched
                        else "explicit_user_type_unmatched"
                    )
                )
            )
            detections.append(
                {
                    "malware_type": evaluation["malware_type"],
                    "malware_type_confidence": confidence,
                    "attribution_basis": basis,
                    "detection": evaluation["detection"],
                }
            )

    if not detections:
        result = _unknown_result(
            source,
            digest,
            size,
            detector_errors=detector_errors,
        )
        result["detector_evaluations"] = assessment["evaluations"]
        return result

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
            "sample": str(source),
            "malware_type": "unknown",
            "malware_type_confidence": "low",
            "attribution_basis": "ambiguous_type_detection",
            "campaign_type": "unknown",
            "campaign_confidence": "low",
            "campaign_resolution": "ambiguous_type_detection",
            "candidates": [],
            "observations": {
                "sha256": digest,
                "size": size,
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
            "detector_evaluations": assessment["evaluations"],
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
        "sample": str(source),
        "malware_type": selected["malware_type"],
        "malware_type_confidence": selected["malware_type_confidence"],
        "attribution_basis": selected["attribution_basis"],
        "campaign_type": campaign["campaign_type"],
        "campaign_confidence": campaign["confidence"],
        "campaign_resolution": campaign_resolution,
        "candidates": campaigns,
        "observations": {
            "sha256": digest,
            "size": size,
            "type_detector": selected["detection"].get("observations", {}),
            "detector_errors": detector_errors,
        },
        "all_type_detections": detections,
        "family_label_used_to_select_campaign": False,
        "explicit_malware_type": malware_type,
        "detector_evaluations": assessment["evaluations"],
    }


def classify_bytes(
    data: bytes,
    source: Path,
    registry: Path,
    malware_type: str | None = None,
) -> dict[str, Any]:
    """ディスクへ検体を再保存せず、バイト列を登録済み検出器で分類する。"""

    assessment = evaluate_detectors(data, source, registry, malware_type)
    return _classify_evaluations(source, assessment, malware_type)


def classify(path: Path, registry: Path, malware_type: str | None = None) -> dict[str, Any]:
    """ファイルを1度だけ読み、登録済み検出器で分類する。"""

    return classify_bytes(path.read_bytes(), path, registry, malware_type)


def main() -> int:
    """CLI引数を処理し、検体を分類してJSONへ保存する。"""
    parser = argparse.ArgumentParser(
        description="登録済み検出器でマルウェア種を分類し、キャンペーンを選択します。"
    )
    parser.add_argument("--sample", required=True, type=Path)
    parser.add_argument("--registry", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--malware-type",
        help="検出対象を登録済み1種へ限定します。ラベルだけでキャンペーンを選びません。",
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
