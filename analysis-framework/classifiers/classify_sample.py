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
SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
HINT_CONFIDENCE_VALUES = {"high", "medium", "low", "unknown", "unverified"}
MAX_FAMILY_HINT_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_FAMILY_HINT_SAMPLES = 10_000
MAX_FAMILY_HINTS_PER_SAMPLE = 16
MAX_ROUTING_LAYERS = 512
MAX_ROUTING_FAMILY_COVERAGE = 512
_EXTERNAL_PUBLICATION_BASES = {
    "malwarebazaar_direct_tag",
    "malwarebazaar_reported_signature",
}
_ATTRIBUTION_EVIDENCE_BASES = {
    "known_outer_sha256",
    "known_inner_sha256",
    "type_detector_structure",
}


class DetectorPathError(ValueError):
    """レジストリが許可外の検出器を指した場合に送出する。"""


class FamilyHintManifestError(ValueError):
    """外部family候補manifestが厳格schemaに適合しない場合に送出する。"""


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
        raise DetectorPathError(f"detector path must be exactly {expected.as_posix()}: {relative_path!r}")
    malware_root = (trusted_root / "malware").resolve(strict=True)
    try:
        resolved = (trusted_root / requested).resolve(strict=True)
        relative = resolved.relative_to(malware_root)
    except (FileNotFoundError, OSError, ValueError) as exc:
        raise DetectorPathError(f"detector path escapes or does not exist: {relative_path!r}") from exc
    if relative.parts != (family, "detect.py") or not resolved.is_file():
        raise DetectorPathError(f"detector path is not allowlisted: {resolved}")
    return resolved


@lru_cache(maxsize=32)
def _load_registry_cached(
    resolved_path: str,
    modified_ns: int,
    size: int,
) -> dict[str, dict[str, Any]]:
    """file identityをcache keyに含め、registry全体を一度だけ厳格検証する。"""

    del modified_ns, size
    registry = Path(resolved_path)
    document = json.loads(registry.read_text(encoding="utf-8-sig"))
    if not isinstance(document, dict):
        raise TypeError("registry root must be an object")
    values = document.get("malware_types")
    if not isinstance(values, dict):
        raise TypeError("registry malware_types must be an object")
    for family, metadata in values.items():
        if not isinstance(family, str) or FAMILY_ID_RE.fullmatch(family) is None:
            raise TypeError(f"invalid registry family id: {family!r}")
        if not isinstance(metadata, dict):
            raise TypeError(f"registry metadata must be an object: {family}")
        detector_path = metadata.get("detector")
        if not isinstance(detector_path, str):
            raise TypeError(f"registry detector must be a string: {family}")
        _resolve_detector_path(FRAMEWORK_ROOT, family, detector_path)
        known_hashes = metadata.get("known_sample_sha256", [])
        if not isinstance(known_hashes, list):
            raise TypeError(f"known_sample_sha256 must be a list: {family}")
        if any(not isinstance(value, str) or SHA256_RE.fullmatch(value) is None for value in known_hashes):
            raise TypeError(f"known_sample_sha256 contains an invalid digest: {family}")
    return values


def _validated_registry(registry: Path) -> dict[str, dict[str, Any]]:
    """更新を追跡するcache経由で検証済みregistryを返す。"""

    resolved = registry.resolve(strict=True)
    stat_result = resolved.stat()
    return _load_registry_cached(
        str(resolved),
        stat_result.st_mtime_ns,
        stat_result.st_size,
    )


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
    for trusted_import_root in (
        FRAMEWORK_ROOT.parent,
        FRAMEWORK_ROOT,
        FRAMEWORK_ROOT / "common",
    ):
        value = str(trusted_import_root)
        if value not in sys.path:
            sys.path.insert(0, value)
    spec = importlib.util.spec_from_file_location(f"malware_detector_{path.parent.name}_{path.stem}", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load detector: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    detector = getattr(module, "detect", None)
    if not callable(detector):
        raise RuntimeError(f"detector has no callable detect(): {path}")
    return detector


def normalize_detection_result(value: Any) -> dict[str, Any]:
    """検出器戻り値を厳格な共通shapeへ検証・正規化する。"""

    if not isinstance(value, dict):
        raise TypeError("detector result must be an object")
    matched = value.get("matched")
    if not isinstance(matched, bool):
        raise TypeError("detector matched must be a boolean")
    observations = value.get("observations", {})
    if not isinstance(observations, dict):
        raise TypeError("detector observations must be an object")
    campaigns = value.get("campaigns", [])
    if not isinstance(campaigns, list):
        raise TypeError("detector campaigns must be a list")
    normalized_campaigns = []
    for index, campaign in enumerate(campaigns):
        if not isinstance(campaign, dict):
            raise TypeError(f"detector campaign[{index}] must be an object")
        campaign_type = campaign.get("campaign_type")
        confidence = campaign.get("confidence")
        reasons = campaign.get("reasons", [])
        if not isinstance(campaign_type, str) or not campaign_type.strip():
            raise TypeError(f"detector campaign[{index}].campaign_type must be a string")
        if confidence not in CONFIDENCE_ORDER:
            raise TypeError(f"detector campaign[{index}].confidence is invalid")
        if not isinstance(reasons, list) or any(not isinstance(item, str) for item in reasons):
            raise TypeError(f"detector campaign[{index}].reasons must be a string list")
        normalized_campaigns.append(
            {
                **campaign,
                "campaign_type": campaign_type.strip(),
                "confidence": confidence,
                "reasons": reasons,
            }
        )
    return {
        **value,
        "matched": matched,
        "observations": observations,
        "campaigns": normalized_campaigns,
    }


def clear_classifier_caches() -> None:
    """batch境界でdetector moduleとregistry cacheを明示的に破棄する。"""

    load_detector.cache_clear()
    _load_registry_cached.cache_clear()


def detection_uses_known_inner(detection: dict) -> bool:
    """検出器がレビュー済み内包SHA-256へ一致したか返す。"""
    return any("known inner SHA-256" in candidate.get("reasons", []) for candidate in detection.get("campaigns", []))


def _bounded_hint_text(value: Any, field: str, maximum: int) -> str:
    """外部hintの文字列を制御文字なしの上限付き値として検証する。"""

    if not isinstance(value, str) or not value or len(value) > maximum:
        raise FamilyHintManifestError(f"{field} must be a non-empty string of at most {maximum} characters")
    if any(ord(character) < 0x20 for character in value):
        raise FamilyHintManifestError(f"{field} contains a control character")
    return value


def _normalize_family_hint(value: Any, location: str) -> dict[str, str]:
    """1件の外部family hintを正規化し、未知fieldを拒否する。"""

    if not isinstance(value, dict):
        raise FamilyHintManifestError(f"{location} must be an object")
    allowed = {"family", "source", "provenance", "confidence", "label", "observed_at"}
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise FamilyHintManifestError(f"{location} contains unknown fields: {', '.join(unknown)}")
    missing = sorted({"family", "source", "provenance", "confidence"} - set(value))
    if missing:
        raise FamilyHintManifestError(f"{location} is missing fields: {', '.join(missing)}")

    family = _bounded_hint_text(value["family"], f"{location}.family", 64).lower()
    if FAMILY_ID_RE.fullmatch(family) is None or family in {"unknown", "unclassified"}:
        raise FamilyHintManifestError(f"{location}.family is not a routable canonical family id")
    confidence = _bounded_hint_text(value["confidence"], f"{location}.confidence", 16).lower()
    if confidence not in HINT_CONFIDENCE_VALUES:
        allowed_values = ", ".join(sorted(HINT_CONFIDENCE_VALUES))
        raise FamilyHintManifestError(f"{location}.confidence must be one of: {allowed_values}")

    normalized = {
        "family": family,
        "source": _bounded_hint_text(value["source"], f"{location}.source", 128),
        "provenance": _bounded_hint_text(value["provenance"], f"{location}.provenance", 512),
        "confidence": confidence,
    }
    if "label" in value:
        normalized["label"] = _bounded_hint_text(value["label"], f"{location}.label", 128)
    if "observed_at" in value:
        normalized["observed_at"] = _bounded_hint_text(
            value["observed_at"], f"{location}.observed_at", 64
        )
    return normalized


def normalize_family_hint_manifest(document: Any) -> dict[str, Any]:
    """SHA-256 keyed外部family hint manifestを厳格schemaへ正規化する。

    外部providerのconfidenceはそのまま保持するが、分類confidenceへは昇格
    しない。family確定には別途detectorまたは既知hashの証拠が必要である。
    """

    if not isinstance(document, dict):
        raise FamilyHintManifestError("hint manifest root must be an object")
    unknown = sorted(set(document) - {"schema_version", "samples"})
    if unknown:
        raise FamilyHintManifestError(f"hint manifest contains unknown fields: {', '.join(unknown)}")
    if type(document.get("schema_version")) is not int or document["schema_version"] != 1:
        raise FamilyHintManifestError("hint manifest schema_version must be 1")
    samples = document.get("samples")
    if not isinstance(samples, dict):
        raise FamilyHintManifestError("hint manifest samples must be an object")
    if len(samples) > MAX_FAMILY_HINT_SAMPLES:
        raise FamilyHintManifestError("hint manifest exceeds the sample count limit")

    normalized_samples: dict[str, list[dict[str, str]]] = {}
    for raw_digest, raw_hints in samples.items():
        if not isinstance(raw_digest, str) or SHA256_RE.fullmatch(raw_digest) is None:
            raise FamilyHintManifestError(f"hint manifest contains an invalid SHA-256: {raw_digest!r}")
        digest = raw_digest.lower()
        if digest in normalized_samples:
            raise FamilyHintManifestError(f"hint manifest contains duplicate SHA-256 keys: {digest}")
        if not isinstance(raw_hints, list) or not raw_hints:
            raise FamilyHintManifestError(f"samples.{digest} must be a non-empty list")
        if len(raw_hints) > MAX_FAMILY_HINTS_PER_SAMPLE:
            raise FamilyHintManifestError(f"samples.{digest} exceeds the hint count limit")
        hints = [
            _normalize_family_hint(hint, f"samples.{digest}[{index}]")
            for index, hint in enumerate(raw_hints)
        ]
        fingerprints = {
            (
                hint["family"],
                hint["source"],
                hint["provenance"],
                hint["confidence"],
                hint.get("label"),
                hint.get("observed_at"),
            )
            for hint in hints
        }
        if len(fingerprints) != len(hints):
            raise FamilyHintManifestError(f"samples.{digest} contains duplicate hints")
        normalized_samples[digest] = sorted(
            hints,
            key=lambda item: (
                item["family"],
                item["source"],
                item["provenance"],
                item["confidence"],
                item.get("label", ""),
            ),
        )
    return {
        "schema_version": 1,
        "samples": dict(sorted(normalized_samples.items())),
    }


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """JSON object内の重複keyを黙って上書きせず拒否する。"""

    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise FamilyHintManifestError(f"hint manifest contains a duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_nonfinite_json(value: str) -> None:
    """NaNやInfinityをJSON値として受理しない。"""

    raise FamilyHintManifestError(f"hint manifest contains a non-finite number: {value}")


def load_family_hint_manifest(path: Path) -> dict[str, Any]:
    """上限付きで外部family hint manifestを読み、厳格検証済み値を返す。"""

    try:
        size = path.stat().st_size
    except OSError as exc:
        raise FamilyHintManifestError(f"cannot stat hint manifest: {exc}") from exc
    if size > MAX_FAMILY_HINT_MANIFEST_BYTES:
        raise FamilyHintManifestError("hint manifest exceeds the byte limit")
    try:
        text = path.read_text(encoding="utf-8-sig")
        document = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=_reject_nonfinite_json,
        )
    except FamilyHintManifestError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise FamilyHintManifestError(f"cannot read hint manifest: {exc}") from exc
    return normalize_family_hint_manifest(document)


def family_hints_for_sha256(manifest: dict[str, Any], digest: str) -> list[dict[str, str]]:
    """検証済みmanifestから完全一致SHA-256のhintだけをコピーして返す。"""

    if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
        raise FamilyHintManifestError("sample digest must be a SHA-256")
    normalized = normalize_family_hint_manifest(manifest)
    return [dict(item) for item in normalized["samples"].get(digest.lower(), [])]


def family_hint_manifest_from_publication_summary(
    document: Any,
    *,
    source: str = "malwarebazaar_publication_summary",
) -> dict[str, Any]:
    """MalwareBazaar publication-summaryを未検証hint manifestへ変換する。

    publication時のfamily名は確定証拠へ変換せず、外部tagまたはreported
    signature由来と明示されたcaseだけを候補として取り込む。
    """

    _bounded_hint_text(source, "source", 128)
    if not isinstance(document, dict) or not isinstance(document.get("cases"), list):
        raise FamilyHintManifestError("publication summary cases must be a list")
    samples: dict[str, list[dict[str, str]]] = {}
    for index, case in enumerate(document["cases"]):
        if not isinstance(case, dict):
            raise FamilyHintManifestError(f"publication summary cases[{index}] must be an object")
        basis = case.get("attribution_basis")
        if basis not in _EXTERNAL_PUBLICATION_BASES:
            continue
        digest = case.get("sha256")
        family = case.get("family")
        if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
            raise FamilyHintManifestError(f"publication summary cases[{index}].sha256 is invalid")
        if not isinstance(family, str):
            raise FamilyHintManifestError(f"publication summary cases[{index}].family is invalid")
        confidence = case.get("metadata_hint_confidence", "unverified")
        hint: dict[str, str] = {
            "family": family.lower(),
            "source": source,
            "provenance": f"publication-summary:{basis}",
            "confidence": confidence,
            "label": case.get("reported_signature") or family,
        }
        first_seen = case.get("first_seen")
        if isinstance(first_seen, str) and first_seen:
            hint["observed_at"] = first_seen
        samples.setdefault(digest.lower(), []).append(hint)
    return normalize_family_hint_manifest({"schema_version": 1, "samples": samples})


def _normalize_family_coverage(
    family_coverage: list[dict[str, Any]] | None,
) -> dict[str, dict[str, Any]]:
    """one-shot側のfamily coverageを候補routing用の最小shapeへ正規化する。"""

    if family_coverage is None:
        return {}
    if not isinstance(family_coverage, list):
        raise TypeError("family_coverage must be a list")
    if len(family_coverage) > MAX_ROUTING_FAMILY_COVERAGE:
        raise TypeError("family_coverage exceeds the family count limit")
    normalized: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(family_coverage):
        if not isinstance(item, dict):
            raise TypeError(f"family_coverage[{index}] must be an object")
        family = item.get("family")
        if not isinstance(family, str) or FAMILY_ID_RE.fullmatch(family) is None:
            raise TypeError(f"family_coverage[{index}].family is invalid")
        if family in normalized:
            raise TypeError(f"family_coverage contains duplicate family: {family}")
        detector_registered = item.get("detector_registered")
        if not isinstance(detector_registered, bool):
            raise TypeError(f"family_coverage[{index}].detector_registered must be a boolean")
        automatic = item.get("automatic_handlers", [])
        manual = item.get("manual_or_unsupported_handlers", [])
        if (
            not isinstance(automatic, list)
            or any(not isinstance(value, str) or not value for value in automatic)
            or not isinstance(manual, list)
            or any(not isinstance(value, str) or not value for value in manual)
        ):
            raise TypeError(f"family_coverage[{index}] handler ids must be string lists")
        normalized[family] = {
            "detector_registered": detector_registered,
            "automatic_handlers": sorted(set(automatic)),
            "manual_or_unsupported_handlers": sorted(set(manual)),
            "status": str(item.get("status", "unknown")),
        }
    return normalized


def _routing_layer_records(
    layer_classifications: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """公開layer classification列をrouting評価用の内部recordへ変換する。"""

    if not isinstance(layer_classifications, list):
        raise TypeError("layer_classifications must be a list")
    if len(layer_classifications) > MAX_ROUTING_LAYERS:
        raise TypeError("layer_classifications exceeds the layer count limit")
    records = []
    for index, item in enumerate(layer_classifications):
        if not isinstance(item, dict):
            raise TypeError(f"layer_classifications[{index}] must be an object")
        wrapped = isinstance(item.get("classification"), dict)
        classification = item["classification"] if wrapped else item
        layer = item.get("layer", {}) if wrapped else {}
        if not isinstance(layer, dict):
            raise TypeError(f"layer_classifications[{index}].layer must be an object")
        evaluations = classification.get("detector_evaluations", [])
        if not isinstance(evaluations, list):
            raise TypeError(
                f"layer_classifications[{index}].classification.detector_evaluations must be a list"
            )
        normalized_evaluations: dict[str, dict[str, Any]] = {}
        for evaluation_index, evaluation in enumerate(evaluations):
            if not isinstance(evaluation, dict):
                raise TypeError(
                    f"layer_classifications[{index}].detector_evaluations[{evaluation_index}] "
                    "must be an object"
                )
            family = evaluation.get("malware_type")
            if not isinstance(family, str) or FAMILY_ID_RE.fullmatch(family) is None:
                raise TypeError(
                    f"layer_classifications[{index}].detector_evaluations[{evaluation_index}] "
                    "has an invalid family"
                )
            if family in normalized_evaluations:
                raise TypeError(
                    f"layer_classifications[{index}] contains duplicate detector evaluation: {family}"
                )
            normalized_evaluations[family] = evaluation

        observations = classification.get("observations", {})
        if not isinstance(observations, dict):
            observations = {}
        digest = layer.get("sha256") or observations.get("sha256")
        if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
            digest = None
        selected_family = classification.get("malware_type")
        attribution_basis = classification.get("attribution_basis")
        confidence = classification.get("malware_type_confidence")
        selection_verified = bool(
            isinstance(selected_family, str)
            and FAMILY_ID_RE.fullmatch(selected_family) is not None
            and selected_family not in {"unknown", "unclassified"}
            and attribution_basis in _ATTRIBUTION_EVIDENCE_BASES
            and confidence in {"high", "medium"}
        )
        records.append(
            {
                "index": index,
                "sha256": digest.lower() if digest else None,
                "depth": layer.get("depth") if isinstance(layer.get("depth"), int) else None,
                "classification": classification,
                "evaluations": normalized_evaluations,
                "selected_family": selected_family if selection_verified else None,
                "attribution_basis": attribution_basis if selection_verified else None,
                "confidence": confidence if selection_verified else None,
            }
        )
    return records


def _positive_detector_evidence(
    evaluation: dict[str, Any],
    record: dict[str, Any],
) -> list[dict[str, Any]]:
    """1 detector評価の肯定証拠を、推測を加えずrouting根拠へ変換する。"""

    evidence = []
    values = (
        ("known_outer_sha256", "high", evaluation.get("known_outer_sha256") is True),
        ("known_inner_sha256", "high", evaluation.get("known_inner_sha256") is True),
        ("type_detector_structure", "medium", evaluation.get("detector_matched") is True),
    )
    for kind, confidence, matched in values:
        if matched:
            evidence.append(
                {
                    "kind": kind,
                    "confidence": confidence,
                    "layer_index": record["index"],
                    "layer_sha256": record["sha256"],
                    "supports_attribution": True,
                }
            )
    return evidence


def build_family_routing_candidates(
    layer_classifications: list[dict[str, Any]],
    *,
    metadata_hints: list[dict[str, Any]] | None = None,
    family_coverage: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """全layer証拠と外部hintからfail-closedなfamily routing候補を作る。

    既存分類器が各layerで一意選択したfamilyだけを通常の自動解析へ送る。
    外部metadataだけの候補や同順位で曖昧なdetector候補は、上限付きhandler
    がある場合でも候補検証routeに限定し、family attributionへ使わない。
    metadata_hintsはsubmitted rootの完全一致SHA-256で事前選択した値を渡す。
    """

    records = _routing_layer_records(layer_classifications)
    coverage = _normalize_family_coverage(family_coverage)
    if metadata_hints is not None and not isinstance(metadata_hints, list):
        raise TypeError("metadata_hints must be a list")
    if len(metadata_hints or []) > MAX_FAMILY_HINTS_PER_SAMPLE:
        raise TypeError("metadata_hints exceeds the hint count limit")
    normalized_hints = [
        _normalize_family_hint(item, f"metadata_hints[{index}]")
        for index, item in enumerate(metadata_hints or [])
    ]

    candidate_families: set[str] = {item["family"] for item in normalized_hints}
    selected_families: set[str] = set()
    for record in records:
        selected = record["selected_family"]
        if selected:
            candidate_families.add(selected)
            selected_families.add(selected)
        for family, evaluation in record["evaluations"].items():
            if (
                evaluation.get("known_outer_sha256") is True
                or evaluation.get("known_inner_sha256") is True
                or evaluation.get("detector_matched") is True
            ):
                candidate_families.add(family)

    candidates = []
    for family in sorted(candidate_families):
        family_hints = [dict(item) for item in normalized_hints if item["family"] == family]
        layer_support = []
        detector_evidence = []
        selected_layers = []
        for record in records:
            evaluation = record["evaluations"].get(family)
            is_selected = record["selected_family"] == family
            if is_selected:
                selected_layers.append(record["index"])
            if evaluation is None:
                if is_selected:
                    detector_evidence.append(
                        {
                            "kind": record["attribution_basis"],
                            "confidence": record["confidence"],
                            "layer_index": record["index"],
                            "layer_sha256": record["sha256"],
                            "supports_attribution": True,
                            "source": "legacy_classification_selection",
                        }
                    )
                continue
            positive = _positive_detector_evidence(evaluation, record)
            detector_evidence.extend(positive)
            layer_support.append(
                {
                    "layer_index": record["index"],
                    "layer_sha256": record["sha256"],
                    "depth": record["depth"],
                    "selected_by_existing_classifier": is_selected,
                    "known_outer_sha256": evaluation.get("known_outer_sha256") is True,
                    "known_inner_sha256": evaluation.get("known_inner_sha256") is True,
                    "detector_matched": evaluation.get("detector_matched") is True,
                    "detector_error": evaluation.get("error"),
                    "automatic_route_eligible": evaluation.get("automatic_route_eligible") is True,
                }
            )

        metadata_evidence = [
            {
                "kind": "external_metadata_hint",
                "confidence": "unverified",
                "provider_confidence": hint["confidence"],
                "source": hint["source"],
                "provenance": hint["provenance"],
                "label": hint.get("label"),
                "observed_at": hint.get("observed_at"),
                "layer_index": 0 if records else None,
                "layer_sha256": records[0]["sha256"] if records else None,
                "supports_attribution": False,
            }
            for hint in family_hints
        ]
        evidence = detector_evidence + metadata_evidence
        has_high = any(item["confidence"] == "high" for item in detector_evidence)
        has_medium = any(item["confidence"] == "medium" for item in detector_evidence)
        candidate_confidence = "high" if has_high else ("medium" if has_medium else "unverified")
        capability = coverage.get(family)
        observed_detector = any(family in record["evaluations"] for record in records)
        detector_registered = bool(
            observed_detector or (capability and capability["detector_registered"])
        )
        automatic_handlers = capability["automatic_handlers"] if capability else []
        manual_handlers = capability["manual_or_unsupported_handlers"] if capability else []
        selected_clean_route = any(
            item["selected_by_existing_classifier"]
            and item["automatic_route_eligible"]
            and not item["detector_error"]
            for item in layer_support
        )
        selected_family_analysis = bool(
            selected_layers
            and selected_clean_route
            and detector_registered
            and automatic_handlers
        )
        verification_only = bool(
            not selected_family_analysis
            and automatic_handlers
            and records
            and (detector_evidence or family_hints)
        )
        if selected_family_analysis:
            routing_mode = "selected_family_analysis"
        elif verification_only:
            routing_mode = "candidate_verification"
        else:
            routing_mode = "blocked"

        reason_codes = []
        if selected_layers:
            reason_codes.append("unambiguous_detector_selection")
        elif detector_evidence:
            reason_codes.append("ambiguous_or_nonwinning_detector_evidence")
        if family_hints:
            reason_codes.append("metadata_hint_unverified")
        if not detector_registered:
            reason_codes.append("detector_not_registered")
        elif not detector_evidence:
            reason_codes.append("detector_did_not_match")
        if automatic_handlers:
            reason_codes.append("automatic_handler_available")
        else:
            reason_codes.append("automatic_handler_unavailable")
        if verification_only:
            reason_codes.append("handler_evidence_required_before_attribution")

        confidence_score = {"high": 400, "medium": 300, "unverified": 100}[candidate_confidence]
        provider_score = max(
            (
                {"high": 4, "medium": 3, "low": 2, "unknown": 1, "unverified": 0}[
                    hint["confidence"]
                ]
                for hint in family_hints
            ),
            default=0,
        )
        score = (
            confidence_score
            + (40 if selected_layers else 0)
            + min(30, 5 * len(detector_evidence))
            + min(12, 2 * len(family_hints))
            + provider_score
            + (1 if automatic_handlers else 0)
        )
        if detector_evidence and family_hints:
            source_kind = "detector_and_external_metadata"
        elif detector_evidence:
            source_kind = "detector"
        else:
            source_kind = "external_metadata"
        supported_layer_sha256 = sorted(
            {
                item["layer_sha256"]
                for item in evidence
                if isinstance(item.get("layer_sha256"), str)
            }
        )
        candidates.append(
            {
                "family": family,
                "source": source_kind,
                "source_strength": candidate_confidence,
                "confidence": candidate_confidence,
                "rank_score": score,
                "routing_eligible": bool(selected_family_analysis or verification_only),
                "routing_mode": routing_mode,
                "layer_sha256": supported_layer_sha256,
                "evidence": evidence,
                "layer_support": layer_support,
                "metadata_hints": family_hints,
                "metadata_only": bool(family_hints and not detector_evidence),
                "capabilities": {
                    "coverage_known": capability is not None,
                    "coverage_status": capability["status"] if capability else "not_supplied",
                    "detector_registered": detector_registered,
                    "registry_detector_gap": bool(
                        capability is not None and not capability["detector_registered"]
                    ),
                    "automatic_handlers": automatic_handlers,
                    "manual_or_unsupported_handlers": manual_handlers,
                },
                "routing_eligibility": {
                    "mode": routing_mode,
                    "selected_family_analysis": selected_family_analysis,
                    "candidate_verification": verification_only,
                    "family_attribution": bool(selected_layers),
                    "reason_codes": sorted(set(reason_codes)),
                },
                "selected_layer_indexes": sorted(selected_layers),
            }
        )

    candidates.sort(key=lambda item: (-item["rank_score"], item["family"]))
    for rank, candidate in enumerate(candidates, start=1):
        candidate["rank"] = rank
    return {
        "schema_version": 1,
        "selection_policy": "fail_closed_existing_classifier_v1",
        "metadata_hints_used_for_attribution": False,
        "selected_families": sorted(selected_families),
        "automatic_analysis_families": [
            item["family"]
            for item in candidates
            if item["routing_eligibility"]["selected_family_analysis"]
        ],
        "verification_only_families": [
            item["family"]
            for item in candidates
            if item["routing_eligibility"]["candidate_verification"]
        ],
        "candidate_count": len(candidates),
        "metadata_hint_count": len(normalized_hints),
        "candidates": candidates,
    }


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
    registry_data = _validated_registry(registry)
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
        known_outer = digest in {value.lower() for value in metadata.get("known_sample_sha256", [])}
        evaluation["known_outer_sha256"] = known_outer
        try:
            detector = load_detector(framework_root, metadata.get("detector"), registered_type)
            detection = normalize_detection_result(detector(data, source))
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
        detector_matched = detection.get("matched") is True
        evaluation.update(
            known_inner_sha256=known_inner,
            detector_matched=detector_matched,
            applicable=bool(malware_type or known_outer or detector_matched),
            automatic_route_eligible=bool(not evaluation["error"] and (known_outer or known_inner or detector_matched)),
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
            confidence = "high" if known_outer or known_inner else ("medium" if detector_matched else "low")
            basis = (
                "known_outer_sha256"
                if known_outer
                else (
                    "known_inner_sha256"
                    if known_inner
                    else ("type_detector_structure" if detector_matched else "explicit_user_type_unmatched")
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
    top = [item for item in detections if CONFIDENCE_ORDER[item["malware_type_confidence"]] == top_rank]
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
    parser = argparse.ArgumentParser(description="登録済み検出器でマルウェア種を分類し、キャンペーンを選択します。")
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
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
