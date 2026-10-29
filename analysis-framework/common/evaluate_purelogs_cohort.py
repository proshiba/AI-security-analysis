#!/usr/bin/env python3
# ruff: noqa: E402
"""PureLogsコホートのfamily・config・C2静的復元率を厳格に測定する。"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import marshal
import math
import os
import re
import stat
import sys
import tempfile
import time
from collections import Counter
from collections.abc import Callable, Iterator, Mapping, MutableMapping, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import Any

COMMON_ROOT = Path(__file__).resolve().parent
FRAMEWORK_ROOT = COMMON_ROOT.parent
REPOSITORY_ROOT = FRAMEWORK_ROOT.parent
DETECTOR_PATH = FRAMEWORK_ROOT / "malware" / "purelogs" / "detect.py"
EXTRACTOR_PATH = REPOSITORY_ROOT / "extractors" / "purelogs" / "extractor.py"
PIPELINE_PATH = COMMON_ROOT / "static_layer_pipeline.py"
UNPACKER_PATH = REPOSITORY_ROOT / "unpackers" / "static_unpacker.py"
EVALUATOR_PATH = Path(__file__).resolve()
SHA256_RE = re.compile(r"[0-9a-f]{64}")
STATIC_REASON_RE = re.compile(r"[a-z][a-z0-9_]{0,127}")
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_SAMPLE_BYTES = 512 * 1024 * 1024
MAX_COHORT_CASES = 256
MAX_POLICY_LAYERS = 256
MAX_POLICY_DEPTH = 32
MAX_POLICY_LAYER_SIZE = 512 * 1024 * 1024
MAX_POLICY_TOTAL_SIZE = 1024 * 1024 * 1024
MAX_POLICY_COMPRESSION_RATIO = 1_000.0
MAX_POLICY_ARCHIVE_MEMBERS = 4_096
DEFAULT_CASE_DEADLINE_SECONDS = 30 * 60.0
DEFAULT_COHORT_DEADLINE_SECONDS = 16 * 60 * 60.0
MAX_CASE_DEADLINE_SECONDS = 2 * 60 * 60.0
MAX_COHORT_DEADLINE_SECONDS = 24 * 60 * 60.0
MAX_REASON_SCAN_NODES = 100_000
MAX_REASON_SCAN_DEPTH = 32
MAX_EXTERNAL_TOOL_BYTES = 128 * 1024 * 1024
OPAQUE_ID_KEY_BYTES = 32
MANAGED_OMLX_TERMINAL_TRANSFORM = "managed-omlx-tripledes-gzip-pe"
PURE_ROUTE_STAGE_TRANSFORMS = frozenset(
    {
        "managed-eaz-resource-pe",
        "managed-omlx-direct-tripledes-gzip-pe",
        "managed-omlx-tripledes-gzip-pe",
        "rotated-xor-donut-shellcode",
        "rzk-lece-encrypted-container",
    }
)

for trusted in (REPOSITORY_ROOT, FRAMEWORK_ROOT, COMMON_ROOT):
    value = str(trusted)
    if value not in sys.path:
        sys.path.insert(0, value)

from immutable_snapshot import (
    SnapshotIdentity,
    copy_bounded_snapshot,
    read_bounded_snapshot,
)
from malware_io import ArchiveValidationError, read_single_aes_zip_member
from malwarebazaar_batch import _signature_selection_commitment
from pure_cohort_profiles import (
    PURELOGS_PROFILE,
    PURERAT_PROFILE,
    ConfigIdentity,
    PureCohortProfile,
)
from safe_private_output import reject_existing_reparse_components
from static_layer_pipeline import (
    InputUnit,
    StaticLayer,
    StaticLayerPolicy,
    recover_static_layers,
)

__all__ = (
    "PURELOGS_PROFILE",
    "PURERAT_PROFILE",
    "evaluate_case",
    "evaluate_cohort",
    "evaluate_layers",
    "main",
)

PURELOGS_DETECT = PURELOGS_PROFILE.detector
extract_purelogs = PURELOGS_PROFILE.extractor
LayerCacheKey = tuple[str, str, str, str]
LayerCacheValue = tuple[
    bool,
    bool,
    bool,
    ConfigIdentity | None,
    int,
    tuple[str, ...],
    str | None,
]


class CohortEvaluationError(ValueError):
    """評価入力または証拠契約が不正な場合に送出する。"""


class EvaluationDeadlineExceeded(TimeoutError):
    """協調的な評価期限を超過した場合に送出する。"""

    def __init__(self, scope: str) -> None:
        super().__init__(f"{scope} evaluation deadline exceeded")
        self.scope = scope


class JapaneseArgumentParser(argparse.ArgumentParser):
    """argparseが固定で出すusage表記を日本語へ置換する。"""

    def format_help(self) -> str:
        return super().format_help().replace("usage:", "使用法:", 1)

    def format_usage(self) -> str:
        return super().format_usage().replace("usage:", "使用法:", 1)


def _validate_policy(policy: StaticLayerPolicy) -> None:
    """共有policyを評価器固有の絶対安全上限へ制限する。"""

    limits = (
        ("max_layers", policy.max_layers, MAX_POLICY_LAYERS),
        ("max_depth", policy.max_depth, MAX_POLICY_DEPTH),
        ("max_layer_size", policy.max_layer_size, MAX_POLICY_LAYER_SIZE),
        ("max_total_size", policy.max_total_size, MAX_POLICY_TOTAL_SIZE),
        (
            "max_compression_ratio",
            policy.max_compression_ratio,
            MAX_POLICY_COMPRESSION_RATIO,
        ),
        (
            "max_archive_members",
            policy.max_archive_members,
            MAX_POLICY_ARCHIVE_MEMBERS,
        ),
    )
    for name, value, maximum in limits:
        if value > maximum:
            raise CohortEvaluationError(f"policy {name}が安全上限{maximum:g}を超えています")
    if policy.max_layer_size > policy.max_total_size:
        raise CohortEvaluationError("policy max_layer_sizeはmax_total_size以下である必要があります")


def _validated_deadline_seconds(value: object, *, name: str, maximum: float) -> float:
    """deadline秒数を有限の正数かつ絶対上限以下へ制限する。"""

    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or not 0 < float(value) <= maximum
    ):
        raise CohortEvaluationError(f"{name}は0より大きく{maximum:g}以下の有限秒数で指定してください")
    return float(value)


def _check_deadline(
    deadline: float | None,
    *,
    clock: Callable[[], float],
    scope: str,
) -> None:
    """高コスト処理の境界で協調的な期限超過を通知する。"""

    if deadline is not None and clock() >= deadline:
        raise EvaluationDeadlineExceeded(scope)


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CohortEvaluationError(f"JSONに重複keyがあります: {key}")
        result[key] = value
    return result


def _read_regular_file(path: Path, *, maximum_size: int) -> bytes:
    """通常fileだけを上限付きで読み、読込前後の同一性を確認する。"""

    try:
        return read_bounded_snapshot(path, maximum_size).data
    except (OSError, ValueError) as exc:
        raise CohortEvaluationError(f"fileを参照できません: {path.name}") from exc


def _opaque_id(key: bytes, domain: str, value: str) -> str:
    """公開値から辞書逆引きできないrun-scoped相関IDを返す。"""

    if len(key) != OPAQUE_ID_KEY_BYTES:
        raise ValueError("opaque ID key長が不正です")
    payload = domain.encode("ascii") + b"\x00" + value.encode("utf-8")
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def _callable_code_sha256(value: Callable[..., object]) -> str:
    """実際に保持しているPython callableのcode objectをhashへ束縛する。"""

    code = getattr(value, "__code__", None)
    if code is None:
        raise CohortEvaluationError("profile callableをcode objectへ束縛できません")
    return hashlib.sha256(marshal.dumps(code)).hexdigest()


def _verify_profile_import_sources(profile: PureCohortProfile) -> dict[str, str]:
    """import時に固定した入口sourceと現在のrepo sourceが同一か検証する。"""

    verified: dict[str, str] = {}
    for relative_path, expected_sha256 in profile.import_source_sha256:
        path = REPOSITORY_ROOT / relative_path
        actual_sha256 = hashlib.sha256(
            _read_regular_file(path, maximum_size=16 * 1024 * 1024)
        ).hexdigest()
        if not hmac.compare_digest(actual_sha256, expected_sha256):
            raise CohortEvaluationError("profile sourceがimport後に変更されました")
        verified[relative_path] = expected_sha256
    return dict(sorted(verified.items()))


def _load_json_object(path: Path) -> tuple[bytes, dict[str, Any]]:
    raw = _read_regular_file(path, maximum_size=MAX_MANIFEST_BYTES)
    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=lambda item: (_ for _ in ()).throw(
                CohortEvaluationError(f"JSONの非有限値は許可されません: {item}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CohortEvaluationError("cohort manifestはstrict UTF-8 JSONではありません") from exc
    if not isinstance(value, dict):
        raise CohortEvaluationError("cohort manifestのrootはobjectである必要があります")
    return raw, value


def _validated_hashes(value: object, *, expected_count: object) -> list[str]:
    if not isinstance(value, list) or not value or len(value) > MAX_COHORT_CASES:
        raise CohortEvaluationError("root_sha256は有界な非空arrayである必要があります")
    hashes: list[str] = []
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, str) or SHA256_RE.fullmatch(item) is None:
            raise CohortEvaluationError("root_sha256に不正なSHA-256があります")
        if item in seen:
            raise CohortEvaluationError("root_sha256に重複があります")
        seen.add(item)
        hashes.append(item)
    if isinstance(expected_count, bool) or not isinstance(expected_count, int) or expected_count != len(hashes):
        raise CohortEvaluationError("root_case_countとroot_sha256件数が一致しません")
    return hashes


def load_cohort(path: Path, cohort_name: str) -> tuple[dict[str, Any], list[str], str]:
    """集計manifestからprovider labelを分母用途だけで読み込む。"""

    raw, manifest = _load_json_object(path)
    cohorts = manifest.get("cohorts")
    if cohorts is None:
        if (
            manifest.get("selection_mode") != "signature_newest"
            or manifest.get("signature") != cohort_name
            or manifest.get("samples_executed") is not False
            or manifest.get("archives_remain_encrypted") is not True
            or manifest.get("selection_only") is not False
            or manifest.get("complete") is not True
        ):
            raise CohortEvaluationError("取得manifestの固定signature cohort契約を確認できません")
        hashes = _validated_hashes(
            manifest.get("selected_hashes"),
            expected_count=manifest.get("requested"),
        )
        if manifest.get("downloaded") != len(hashes):
            raise CohortEvaluationError("取得manifestのdownload件数が固定cohortと一致しません")
        commitment = manifest.get("selection_commitment_sha256")
        recomputed = _signature_selection_commitment(manifest)
        if (
            not isinstance(commitment, str)
            or SHA256_RE.fullmatch(commitment) is None
            or not hmac.compare_digest(commitment, recomputed)
        ):
            raise CohortEvaluationError("取得manifestのselection commitmentが一致しません")
        return (
            {
                "root_case_count": len(hashes),
                "root_sha256": hashes,
                "provider_label_role": "route_cohort_only_not_family_confirmation",
                "selection_commitment_sha256": commitment,
            },
            hashes,
            hashlib.sha256(raw).hexdigest(),
        )
    if not isinstance(cohorts, dict):
        raise CohortEvaluationError("cohorts objectがありません")
    cohort = cohorts.get(cohort_name)
    if not isinstance(cohort, dict):
        raise CohortEvaluationError(f"cohortがありません: {cohort_name}")
    hashes = _validated_hashes(
        cohort.get("root_sha256"),
        expected_count=cohort.get("root_case_count"),
    )
    role = cohort.get("provider_label_role")
    if role != "route_cohort_only_not_family_confirmation":
        raise CohortEvaluationError("provider labelがfamily確認に利用されない契約を確認できません")
    return cohort, hashes, hashlib.sha256(raw).hexdigest()


def baseline_metrics(
    cohort: Mapping[str, Any],
    *,
    root_case_count: int,
) -> dict[str, Any]:
    """旧集計から厳格評価に利用できるbaselineだけを取り出す。"""

    family = cohort.get("family")
    config = cohort.get("config_c2_terminal")
    if not isinstance(family, Mapping) or not isinstance(config, Mapping):
        return {
            "available": False,
            "family_confirmed_case_count": None,
            "validated_config_recovered_case_count": None,
            "qualified_c2_recovered_case_count": None,
            "strict_joint_success_case_count": None,
            "strict_joint_derivation": "baseline_not_supplied_for_frozen_cohort",
        }

    def count(mapping: Mapping[str, Any], key: str) -> int:
        value = mapping.get(key)
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or not 0 <= value <= root_case_count
        ):
            raise CohortEvaluationError(f"baseline countが不正です: {key}")
        return value

    family_count = count(family, "confirmed_case_count")
    config_count = count(config, "validated_config_recovered_case_count")
    c2_count = count(config, "qualified_network_endpoint_recovered_case_count")
    # aggregateは3条件のcase単位共通部分を保持しない。ただし1条件でも0なら
    # 共通部分も必ず0であり、このコホートの旧baselineを厳密に確定できる。
    strict_joint = 0 if 0 in {family_count, config_count, c2_count} else None
    return {
        "available": True,
        "family_confirmed_case_count": family_count,
        "validated_config_recovered_case_count": config_count,
        "qualified_c2_recovered_case_count": c2_count,
        "strict_joint_success_case_count": strict_joint,
        "strict_joint_derivation": (
            "zero_dimension_proves_empty_intersection" if strict_joint == 0 else "not_derivable_from_aggregate_counts"
        ),
    }


def evaluate_layers(
    layers: Sequence[StaticLayer],
    *,
    profile: PureCohortProfile = PURELOGS_PROFILE,
    detector: Callable[[bytes, Path | None], Mapping[str, Any]] | None = None,
    extractor: Callable[[bytes, str], Mapping[str, Any]] | None = None,
    layer_cache: MutableMapping[LayerCacheKey, LayerCacheValue] | None = None,
    opaque_id_key: bytes | None = None,
    deadline: float | None = None,
    clock: Callable[[], float] = time.monotonic,
    deadline_scope: str = "case",
) -> dict[str, Any]:
    """全静的layerを評価し、同一layerで成立した厳格証拠だけを数える。"""

    detector = detector or profile.detector
    extractor = extractor or profile.extractor
    opaque_id_key = opaque_id_key or os.urandom(OPAQUE_ID_KEY_BYTES)
    if len(opaque_id_key) != OPAQUE_ID_KEY_BYTES:
        raise ValueError("opaque ID key長が不正です")
    root_family_layers: list[dict[str, Any]] = []
    loader_layers: list[dict[str, Any]] = []
    terminal_candidate_layers: list[dict[str, Any]] = []
    family_layers: list[dict[str, Any]] = []
    route_layers: list[dict[str, Any]] = []
    config_layers: list[dict[str, Any]] = []
    strict_layers: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    config_identities: set[ConfigIdentity] = set()
    for layer in layers:
        _check_deadline(deadline, clock=clock, scope=deadline_scope)
        actual_sha256 = hashlib.sha256(layer.data).hexdigest()
        _check_deadline(deadline, clock=clock, scope=deadline_scope)
        if actual_sha256 != layer.sha256:
            errors.append(
                {
                    "layer_sha256": layer.sha256,
                    "error_type": "LayerDigestMismatch",
                }
            )
            continue

        cache_key = (
            profile.profile_id,
            layer.sha256,
            layer.name,
            layer.transform,
        )
        cached = layer_cache.get(cache_key) if layer_cache is not None else None
        if cached is None:
            try:
                detection = detector(layer.data, Path(layer.name))
                _check_deadline(deadline, clock=clock, scope=deadline_scope)
                extraction = extractor(layer.data, layer.name)
                _check_deadline(deadline, clock=clock, scope=deadline_scope)
                assessment = profile.assess(
                    layer.sha256,
                    detection,
                    extraction,
                )
                cached = (
                    assessment.loader_family_confirmed,
                    assessment.terminal_candidate_verified,
                    assessment.terminal_family_confirmed,
                    assessment.config_identity,
                    assessment.endpoint_count,
                    assessment.endpoint_sha256,
                    None,
                )
            except EvaluationDeadlineExceeded:
                raise
            except Exception as exc:  # noqa: BLE001 - detector/extractor境界をcase内に閉じ込める
                cached = (False, False, False, None, 0, (), type(exc).__name__)
            if layer_cache is not None:
                layer_cache[cache_key] = cached

        (
            loader_family,
            terminal_candidate,
            terminal_family,
            identity,
            endpoint_count,
            endpoint_hashes,
            error_type,
        ) = cached
        if error_type is not None:
            errors.append(
                {
                    "layer_sha256": layer.sha256,
                    "error_type": error_type,
                }
            )
            continue
        layer_record = {
            "layer_sha256": layer.sha256,
            "depth": layer.depth,
            "transform": layer.transform,
        }
        if layer.transform in PURE_ROUTE_STAGE_TRANSFORMS:
            route_layers.append(layer_record)
        if loader_family:
            loader_layers.append(layer_record)
        if terminal_candidate:
            terminal_candidate_layers.append(layer_record)
        if terminal_family:
            family_layers.append(layer_record)
        if layer.depth == 0 and (loader_family or terminal_family):
            root_family_layers.append(layer_record)
        if identity is not None:
            serialized_identity = json.dumps(
                identity,
                ensure_ascii=False,
                separators=(",", ":"),
            )
            record = {
                "layer_sha256": layer.sha256,
                "depth": layer.depth,
                "transform": layer.transform,
                "configured_endpoint_count": endpoint_count,
                "configured_endpoint_opaque_id": [
                    _opaque_id(opaque_id_key, "configured-endpoint", item)
                    for item in endpoint_hashes
                ],
                "configuration_opaque_id": _opaque_id(
                    opaque_id_key,
                    "configuration-identity",
                    serialized_identity,
                ),
                "opaque_id_scope": "single_evaluation_run",
                "raw_endpoint_published": False,
                "raw_endpoint_hash_published": False,
                "raw_key_published": False,
            }
            config_layers.append(record)
            config_identities.add(identity)
            if terminal_family:
                strict_layers.append(record)
    _check_deadline(deadline, clock=clock, scope=deadline_scope)
    conflict = len(config_identities) > 1
    evaluation_complete = not errors
    strict_success = bool(strict_layers) and not conflict and evaluation_complete
    blockers: list[str] = []
    if not family_layers:
        blockers.append("corroborated_terminal_family_evidence_not_recovered")
    if not config_layers:
        blockers.append("family_bound_protobuf_config_not_recovered")
    if config_layers and not strict_layers:
        blockers.append("config_and_family_evidence_not_on_same_layer")
    if conflict:
        blockers.append("conflicting_configuration_candidates_across_layers")
    if errors:
        blockers.append("layer_evaluation_incomplete")
    route_only = bool(route_layers) and not terminal_candidate_layers
    if errors:
        primary_failure = "layer_evaluation_incomplete"
    elif loader_layers and not terminal_candidate_layers:
        primary_failure = "loader_only_terminal_not_recovered"
    elif route_only:
        primary_failure = "route_stage_only"
    elif terminal_candidate_layers and not family_layers:
        primary_failure = "terminal_reached_family_unconfirmed"
    elif family_layers and not config_layers:
        primary_failure = "terminal_family_config_not_recovered"
    elif conflict:
        primary_failure = "conflicting_configuration_candidates"
    elif config_layers and not strict_layers:
        primary_failure = "config_family_different_layer"
    elif config_layers and not strict_success:
        primary_failure = "qualified_c2_not_recovered"
    elif strict_success:
        primary_failure = "strict_success"
    else:
        primary_failure = "no_internal_family_evidence"
    return {
        "root_family_confirmed": bool(root_family_layers),
        "loader_family_confirmed": bool(loader_layers),
        "route_stage_recovered": bool(route_layers),
        "terminal_payload_reached": bool(terminal_candidate_layers),
        "terminal_family_confirmed": bool(family_layers),
        "family_confirmed": bool(family_layers),
        "validated_config_recovered": (
            bool(config_layers) and not conflict and evaluation_complete
        ),
        "qualified_c2_recovered": (
            bool(config_layers) and not conflict and evaluation_complete
        ),
        "strict_success": strict_success,
        "root_family_evidence_layers": root_family_layers,
        "loader_family_evidence_layers": loader_layers,
        "route_stage_layers": route_layers,
        "terminal_candidate_layers": terminal_candidate_layers,
        "family_evidence_layers": family_layers,
        "configuration_evidence_layers": config_layers,
        "strict_evidence_layers": strict_layers if not conflict else [],
        "configuration_conflict": conflict,
        "primary_failure_reason": primary_failure,
        "blockers": blockers,
        "evaluation_error_count": len(errors),
        "evaluation_errors": errors,
    }


def static_reason_counts(
    pipeline: Mapping[str, Any],
    *,
    deadline: float | None = None,
    clock: Callable[[], float] = time.monotonic,
    deadline_scope: str = "case",
) -> dict[str, int]:
    """unpacker reportから機微情報を含まない固定形式の失敗理由だけを数える。"""

    counts: Counter[str] = Counter()
    visited = 0

    def visit(value: object, depth: int) -> None:
        nonlocal visited
        if depth > MAX_REASON_SCAN_DEPTH or visited >= MAX_REASON_SCAN_NODES:
            return
        if visited % 256 == 0:
            _check_deadline(deadline, clock=clock, scope=deadline_scope)
        visited += 1
        if isinstance(value, Mapping):
            for key, item in value.items():
                if (
                    key in {"reason", "error"}
                    and isinstance(item, str)
                    and STATIC_REASON_RE.fullmatch(item) is not None
                ):
                    counts[item] += 1
                visit(item, depth + 1)
        elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            for item in value:
                visit(item, depth + 1)

    visit(pipeline, 0)
    _check_deadline(deadline, clock=clock, scope=deadline_scope)
    return dict(sorted(counts.items()))


def _sample_path(samples_root: Path, digest: str) -> Path:
    sample_dir = samples_root / digest
    try:
        reject_existing_reparse_components(samples_root)
        reject_existing_reparse_components(sample_dir)
        root_metadata = samples_root.lstat()
        directory_metadata = sample_dir.lstat()
        if (
            not stat.S_ISDIR(root_metadata.st_mode)
            or not stat.S_ISDIR(directory_metadata.st_mode)
            or samples_root.is_symlink()
            or sample_dir.is_symlink()
        ):
            raise ValueError("sample root／directoryが通常directoryではありません")
        entries = []
        for item in sample_dir.iterdir():
            reject_existing_reparse_components(item)
            metadata = item.lstat()
            if stat.S_ISREG(metadata.st_mode) and not item.is_symlink():
                entries.append(item)
    except (OSError, ValueError) as exc:
        raise CohortEvaluationError(f"sample directoryを読めません: {digest}") from exc
    if len(entries) != 1:
        raise CohortEvaluationError(f"sample directoryは通常fileを1件だけ含む必要があります: {digest}")
    return entries[0]


def evaluate_case(
    sample_path: Path,
    expected_sha256: str,
    *,
    policy: StaticLayerPolicy,
    profile: PureCohortProfile = PURELOGS_PROFILE,
    sevenzip: Path | None = None,
    layer_cache: MutableMapping[LayerCacheKey, LayerCacheValue] | None = None,
    opaque_id_key: bytes | None = None,
    deadline: float | None = None,
    clock: Callable[[], float] = time.monotonic,
    deadline_scope: str = "case",
) -> dict[str, Any]:
    """1 root検体を実行せずに再帰展開し、選択profileの証拠を評価する。"""

    _validate_policy(policy)
    _check_deadline(deadline, clock=clock, scope=deadline_scope)
    outer_data = _read_regular_file(sample_path, maximum_size=MAX_SAMPLE_BYTES)
    _check_deadline(deadline, clock=clock, scope=deadline_scope)
    outer_sha256 = hashlib.sha256(outer_data).hexdigest()
    data = outer_data
    input_kind = "raw"
    source_name = sample_path.name
    if outer_sha256 != expected_sha256:
        try:
            member = read_single_aes_zip_member(
                outer_data,
                password="infected",
                max_member_size=MAX_SAMPLE_BYTES,
                max_compression_ratio=policy.max_compression_ratio,
            )
        except ArchiveValidationError as exc:
            raise CohortEvaluationError(
                f"sample SHA-256が一致せず、認証済み単一member ZIPでもありません: {expected_sha256}"
            ) from exc
        data = member.data
        input_kind = "authenticated_single_member_zip"
        source_name = Path(member.name).name
    actual_sha256 = hashlib.sha256(data).hexdigest()
    _check_deadline(deadline, clock=clock, scope=deadline_scope)
    if actual_sha256 != expected_sha256:
        raise CohortEvaluationError(f"sample SHA-256が一致しません: {expected_sha256}")
    unit = InputUnit(
        source_name=source_name,
        data=data,
        input_kind=input_kind,
        outer_sha256=outer_sha256,
        outer_size=len(outer_data),
        member_name=member.name if input_kind == "authenticated_single_member_zip" else None,
    )
    layers, pipeline = recover_static_layers(
        unit,
        policy=policy,
        sevenzip=sevenzip,
        archive_password="infected",
    )
    _check_deadline(deadline, clock=clock, scope=deadline_scope)
    result = evaluate_layers(
        layers,
        profile=profile,
        layer_cache=layer_cache,
        opaque_id_key=opaque_id_key,
        deadline=deadline,
        clock=clock,
        deadline_scope=deadline_scope,
    )
    reason_counts = static_reason_counts(
        pipeline,
        deadline=deadline,
        clock=clock,
        deadline_scope=deadline_scope,
    )
    result.update(
        {
            "root_sha256": expected_sha256,
            "root_size": len(data),
            "input_kind": input_kind,
            "static_layer_count": len(layers),
            "static_layer_sha256": sorted({layer.sha256 for layer in layers}),
            "maximum_depth_reached": max(item.depth for item in layers),
            "static_limit_event_count": pipeline["counts"]["limit_events"],
            "static_pipeline_failed_step_count": sum(
                item.get("status") == "failed" for item in pipeline.get("steps", ())
            ),
            "static_unpacker_reason_counts": reason_counts,
            "managed_omlx_terminal_recovered": any(
                layer.transform == MANAGED_OMLX_TERMINAL_TRANSFORM for layer in layers
            ),
            "managed_omlx_terminal_layer_sha256": sorted(
                {layer.sha256 for layer in layers if layer.transform == MANAGED_OMLX_TERMINAL_TRANSFORM}
            ),
            "sample_executed": False,
            "network_contacted": False,
        }
    )
    if result["static_limit_event_count"]:
        result["blockers"].append("static_layer_limit_reached")
        result["strict_success"] = False
        result["validated_config_recovered"] = False
        result["qualified_c2_recovered"] = False
        result["strict_evidence_layers"] = []
        result["primary_failure_reason"] = "deadline_or_budget_exceeded"
    if result["static_pipeline_failed_step_count"]:
        result["blockers"].append("static_unpacker_step_failed")
        result["strict_success"] = False
        result["validated_config_recovered"] = False
        result["qualified_c2_recovered"] = False
        result["strict_evidence_layers"] = []
        if result["primary_failure_reason"] != "deadline_or_budget_exceeded":
            result["primary_failure_reason"] = "static_pipeline_error"
    _check_deadline(deadline, clock=clock, scope=deadline_scope)
    return result


def _source_identity_paths() -> tuple[Path, ...]:
    """評価結果へ影響するrepo内実装・profileを安定順で列挙する。"""

    runtime_paths = {
        EVALUATOR_PATH,
        COMMON_ROOT / "evaluate_pure_cohort.py",
        COMMON_ROOT / "evaluate_purerat_cohort.py",
        COMMON_ROOT / "pure_cohort_profiles.py",
        PIPELINE_PATH,
        COMMON_ROOT / "static_layer_lineage_adapter.py",
        COMMON_ROOT / "analysis_contract.py",
        COMMON_ROOT / "analyze_iso9660.py",
        COMMON_ROOT / "bounded_process.py",
        COMMON_ROOT / "extract_pyinstaller_archive.py",
        COMMON_ROOT / "immutable_snapshot.py",
        COMMON_ROOT / "lineage_child_selector.py",
        COMMON_ROOT / "malwarebazaar_batch.py",
        COMMON_ROOT / "malware_io.py",
        COMMON_ROOT / "pe_structural_profile.py",
        COMMON_ROOT / "safe_artifact_io.py",
        COMMON_ROOT / "safe_private_output.py",
        FRAMEWORK_ROOT / "registry" / "pe_structural_profiles.json",
        FRAMEWORK_ROOT / "malware" / "purehvnc" / "managed_resource_recovery.py",
        EXTRACTOR_PATH,
        REPOSITORY_ROOT / "extractors" / "__init__.py",
        REPOSITORY_ROOT / "extractors" / "common.py",
        REPOSITORY_ROOT / "extractors" / "managed_pe.py",
        REPOSITORY_ROOT / "extractors" / "purehvnc_schema.py",
        REPOSITORY_ROOT / "extractors" / "purehvnc" / "__init__.py",
        REPOSITORY_ROOT / "extractors" / "purehvnc" / "extractor.py",
        REPOSITORY_ROOT / "unpackers" / "profiles" / "byte_transforms.json",
    }
    for root in (
        REPOSITORY_ROOT / "unpackers",
        FRAMEWORK_ROOT / "malware" / "purelogs",
        FRAMEWORK_ROOT / "malware" / "purehvnc",
        REPOSITORY_ROOT / "extractors" / "purelogs",
    ):
        runtime_paths.update(path for path in root.rglob("*.py") if "tests" not in path.relative_to(root).parts)
    return tuple(
        sorted(
            runtime_paths,
            key=lambda path: path.relative_to(REPOSITORY_ROOT).as_posix(),
        )
    )


def _source_identity() -> dict[str, str]:
    """実依存の内容hashを重複なし・path順で返す。"""

    return {
        path.relative_to(REPOSITORY_ROOT).as_posix(): hashlib.sha256(
            _read_regular_file(path, maximum_size=16 * 1024 * 1024)
        ).hexdigest()
        for path in _source_identity_paths()
    }


@contextmanager
def _immutable_sevenzip_snapshot(
    executable: Path | None,
) -> Iterator[tuple[Path | None, dict[str, Any]]]:
    """review済み7-Zipをprivate snapshotへ固定してから下位処理へ渡す。"""

    if executable is None:
        yield None, {}
        return
    primary = read_bounded_snapshot(executable, MAX_EXTERNAL_TOOL_BYTES)
    component_sources = [(executable, primary.identity.sha256)]
    if os.name == "nt" and executable.name.casefold() == "7z.exe":
        companion = executable.with_name("7z.dll")
        try:
            companion.lstat()
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise CohortEvaluationError("7-Zip companionを確認できません") from exc
        else:
            companion_snapshot = read_bounded_snapshot(
                companion,
                MAX_EXTERNAL_TOOL_BYTES,
            )
            component_sources.append(
                (companion, companion_snapshot.identity.sha256)
            )

    with tempfile.TemporaryDirectory(prefix="asa-pure-cohort-tool-") as temporary:
        snapshot_root = Path(temporary)
        components: dict[str, str] = {}
        snapshot_components: dict[Path, SnapshotIdentity] = {}
        snapshot_executable: Path | None = None
        for source, expected_sha256 in component_sources:
            destination = snapshot_root / source.name
            copied = copy_bounded_snapshot(
                source,
                destination,
                MAX_EXTERNAL_TOOL_BYTES,
                expected_sha256=expected_sha256,
            )
            if os.name != "nt":
                source_mode = stat.S_IMODE(source.lstat().st_mode)
                destination.chmod(
                    (source_mode & 0o555) | stat.S_IRUSR | stat.S_IXUSR
                )
            verified = read_bounded_snapshot(
                destination,
                MAX_EXTERNAL_TOOL_BYTES,
            )
            if not hmac.compare_digest(
                copied.identity.sha256,
                verified.identity.sha256,
            ):
                raise CohortEvaluationError("7-Zip snapshotの内容が一致しません")
            components[source.name] = verified.identity.sha256
            snapshot_components[destination] = verified.identity
            if source == executable:
                snapshot_executable = destination
        if snapshot_executable is None:  # pragma: no cover - construction invariant
            raise CohortEvaluationError("7-Zip snapshotを作成できません")
        try:
            yield snapshot_executable, {
                "sevenzip_sha256": primary.identity.sha256,
                "sevenzip_component_sha256": dict(sorted(components.items())),
                "immutable_snapshot_used": True,
            }
        finally:
            for destination, expected_identity in snapshot_components.items():
                final = read_bounded_snapshot(
                    destination,
                    MAX_EXTERNAL_TOOL_BYTES,
                )
                if final.identity != expected_identity:
                    raise CohortEvaluationError(
                        "評価中に7-Zip snapshotが変更されました"
                    )


def _failed_case_result(
    digest: str,
    *,
    error_type: str,
    extra_blocker: str | None = None,
) -> dict[str, Any]:
    """例外内容を公開せず、分母を維持するcase失敗recordを返す。"""

    blockers = ["case_evaluation_failed"]
    if extra_blocker is not None:
        blockers.append(extra_blocker)
    return {
        "root_sha256": digest,
        "root_family_confirmed": False,
        "loader_family_confirmed": False,
        "route_stage_recovered": False,
        "terminal_payload_reached": False,
        "terminal_family_confirmed": False,
        "family_confirmed": False,
        "validated_config_recovered": False,
        "qualified_c2_recovered": False,
        "strict_success": False,
        "primary_failure_reason": (
            "deadline_or_budget_exceeded"
            if extra_blocker in {"case_deadline_exceeded", "cohort_deadline_exceeded"}
            else "static_pipeline_error"
        ),
        "blockers": blockers,
        "evaluation_error_count": 1,
        "evaluation_errors": [{"error_type": error_type}],
        "sample_executed": False,
        "network_contacted": False,
    }


def evaluate_cohort(
    *,
    cohort_manifest: Path,
    samples_root: Path,
    cohort_name: str,
    policy: StaticLayerPolicy,
    profile: PureCohortProfile = PURELOGS_PROFILE,
    sevenzip: Path | None = None,
    progress: Callable[[str], None] | None = None,
    case_deadline_seconds: float = DEFAULT_CASE_DEADLINE_SECONDS,
    cohort_deadline_seconds: float = DEFAULT_COHORT_DEADLINE_SECONDS,
    clock: Callable[[], float] = time.monotonic,
    _external_tools: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """provider cohortを分母として、現在実装の厳格な成功率を再測定する。"""

    _validate_policy(policy)
    case_deadline_seconds = _validated_deadline_seconds(
        case_deadline_seconds,
        name="case_deadline_seconds",
        maximum=MAX_CASE_DEADLINE_SECONDS,
    )
    cohort_deadline_seconds = _validated_deadline_seconds(
        cohort_deadline_seconds,
        name="cohort_deadline_seconds",
        maximum=MAX_COHORT_DEADLINE_SECONDS,
    )
    if cohort_name != profile.cohort_name:
        raise CohortEvaluationError(
            "cohort名が選択profileの固定cohortと一致しません"
        )
    if sevenzip is not None and _external_tools is None:
        with _immutable_sevenzip_snapshot(sevenzip) as (
            snapshot_sevenzip,
            external_tools,
        ):
            return evaluate_cohort(
                cohort_manifest=cohort_manifest,
                samples_root=samples_root,
                cohort_name=cohort_name,
                policy=policy,
                profile=profile,
                sevenzip=snapshot_sevenzip,
                progress=progress,
                case_deadline_seconds=case_deadline_seconds,
                cohort_deadline_seconds=cohort_deadline_seconds,
                clock=clock,
                _external_tools=external_tools,
            )
    cohort, hashes, manifest_sha256 = load_cohort(cohort_manifest, cohort_name)
    baseline = baseline_metrics(cohort, root_case_count=len(hashes))
    profile_import_sources = _verify_profile_import_sources(profile)
    implementation_before = _source_identity()
    runtime_callable_sha256 = {
        "assess": _callable_code_sha256(profile.assess),
        "detector": _callable_code_sha256(profile.detector),
        "extractor": _callable_code_sha256(profile.extractor),
    }
    external_tools = dict(_external_tools or {})
    opaque_id_key = os.urandom(OPAQUE_ID_KEY_BYTES)
    cases: list[dict[str, Any]] = []
    layer_cache: dict[LayerCacheKey, LayerCacheValue] = {}
    cohort_deadline = clock() + cohort_deadline_seconds
    for index, digest in enumerate(hashes, start=1):
        if progress is not None:
            progress(f"[{index}/{len(hashes)}] {digest}")
        case_started = clock()
        if case_started >= cohort_deadline:
            result = _failed_case_result(
                digest,
                error_type="EvaluationDeadlineExceeded",
                extra_blocker="cohort_deadline_exceeded",
            )
        else:
            case_deadline = min(
                case_started + case_deadline_seconds,
                cohort_deadline,
            )
            deadline_scope = "cohort" if cohort_deadline <= case_started + case_deadline_seconds else "case"
            try:
                result = evaluate_case(
                    _sample_path(samples_root, digest),
                    digest,
                    policy=policy,
                    profile=profile,
                    sevenzip=sevenzip,
                    layer_cache=layer_cache,
                    opaque_id_key=opaque_id_key,
                    deadline=case_deadline,
                    clock=clock,
                    deadline_scope=deadline_scope,
                )
                _check_deadline(
                    case_deadline,
                    clock=clock,
                    scope=deadline_scope,
                )
            except EvaluationDeadlineExceeded as exc:
                result = _failed_case_result(
                    digest,
                    error_type=type(exc).__name__,
                    extra_blocker=f"{exc.scope}_deadline_exceeded",
                )
            except Exception as exc:  # noqa: BLE001 - cohort継続のためcase単位に閉じ込める
                deadline_blocker = f"{deadline_scope}_deadline_exceeded" if clock() >= case_deadline else None
                result = _failed_case_result(
                    digest,
                    error_type=type(exc).__name__,
                    extra_blocker=deadline_blocker,
                )
        cases.append(result)
    total = len(cases)
    strict_count = sum(item["strict_success"] is True for item in cases)
    target_count = math.ceil(total * 0.5)
    implementation_after = _source_identity()
    implementation_stable = implementation_before == implementation_after
    case_deadline_count = sum("case_deadline_exceeded" in item.get("blockers", ()) for item in cases)
    cohort_deadline_count = sum("cohort_deadline_exceeded" in item.get("blockers", ()) for item in cases)
    deadline_free = case_deadline_count == 0 and cohort_deadline_count == 0
    reason_case_counts: Counter[str] = Counter()
    layer_roots: dict[str, set[str]] = {}
    for item in cases:
        reasons = item.get("static_unpacker_reason_counts")
        if isinstance(reasons, Mapping):
            reason_case_counts.update(
                reason
                for reason, count in reasons.items()
                if isinstance(reason, str) and isinstance(count, int) and not isinstance(count, bool) and count > 0
            )
        layer_hashes = item.get("static_layer_sha256")
        if isinstance(layer_hashes, list):
            for layer_sha256 in layer_hashes:
                if isinstance(layer_sha256, str) and SHA256_RE.fullmatch(layer_sha256) is not None:
                    layer_roots.setdefault(layer_sha256, set()).add(item["root_sha256"])
    shared_layer_sha256 = [
        {
            "layer_sha256": layer_sha256,
            "root_case_count": len(roots),
            "root_sha256": sorted(roots),
        }
        for layer_sha256, roots in sorted(layer_roots.items())
        if len(roots) > 1
    ]
    current = {
        "root_family_confirmed_case_count": sum(item.get("root_family_confirmed") is True for item in cases),
        "loader_family_confirmed_case_count": sum(item.get("loader_family_confirmed") is True for item in cases),
        "route_stage_recovered_case_count": sum(item.get("route_stage_recovered") is True for item in cases),
        "terminal_payload_reached_case_count": sum(item.get("terminal_payload_reached") is True for item in cases),
        "terminal_family_confirmed_case_count": sum(item.get("terminal_family_confirmed") is True for item in cases),
        "family_confirmed_case_count": sum(item["family_confirmed"] is True for item in cases),
        "validated_config_recovered_case_count": sum(item["validated_config_recovered"] is True for item in cases),
        "qualified_c2_recovered_case_count": sum(item["qualified_c2_recovered"] is True for item in cases),
        "strict_joint_success_case_count": strict_count,
        "strict_joint_success_rate": strict_count / total,
        "target_rate": 0.5,
        "target_case_count": target_count,
        "target_met": (strict_count >= target_count and implementation_stable and deadline_free),
        "case_evaluation_failure_count": sum("case_evaluation_failed" in item.get("blockers", ()) for item in cases),
        "managed_omlx_terminal_recovered_case_count": sum(
            item.get("managed_omlx_terminal_recovered") is True for item in cases
        ),
        "managed_omlx_terminal_recovered_root_sha256": [
            item["root_sha256"] for item in cases if item.get("managed_omlx_terminal_recovered") is True
        ],
        "shared_static_layer_sha256": shared_layer_sha256,
        "implementation_stable_during_evaluation": implementation_stable,
        "evaluation_completed_without_deadline": deadline_free,
        "case_deadline_exceeded_count": case_deadline_count,
        "cohort_deadline_exceeded_case_count": cohort_deadline_count,
        "static_unpacker_reason_case_counts": dict(sorted(reason_case_counts.items())),
        "primary_failure_reason_case_counts": dict(
            sorted(
                Counter(
                    str(item.get("primary_failure_reason", "no_internal_family_evidence")) for item in cases
                ).items()
            )
        ),
        "root_family_confirmed_root_sha256": [
            item["root_sha256"] for item in cases if item.get("root_family_confirmed") is True
        ],
        "loader_family_confirmed_root_sha256": [
            item["root_sha256"] for item in cases if item.get("loader_family_confirmed") is True
        ],
        "route_stage_recovered_root_sha256": [
            item["root_sha256"] for item in cases if item.get("route_stage_recovered") is True
        ],
        "terminal_payload_reached_root_sha256": [
            item["root_sha256"] for item in cases if item.get("terminal_payload_reached") is True
        ],
        "terminal_family_confirmed_root_sha256": [
            item["root_sha256"] for item in cases if item.get("terminal_family_confirmed") is True
        ],
        "family_confirmed_root_sha256": [item["root_sha256"] for item in cases if item["family_confirmed"] is True],
        "validated_config_recovered_root_sha256": [
            item["root_sha256"] for item in cases if item["validated_config_recovered"] is True
        ],
        "qualified_c2_recovered_root_sha256": [
            item["root_sha256"] for item in cases if item["qualified_c2_recovered"] is True
        ],
        "strict_joint_success_root_sha256": [item["root_sha256"] for item in cases if item["strict_success"] is True],
    }
    return {
        "schema_version": 2,
        "evaluation": "pure_family_config_c2_strict_static_cohort",
        "family_profile": {
            "profile_id": profile.profile_id,
            "family": profile.family,
        },
        "cohort": {
            "name": cohort_name,
            "root_case_count": total,
            "provider_label_role": "route_cohort_only_not_family_confirmation",
            "manifest_sha256": manifest_sha256,
        },
        "implementation_sha256": implementation_before,
        "profile_import_source_sha256": profile_import_sources,
        "runtime_callable_sha256": runtime_callable_sha256,
        "external_tools": external_tools,
        "policy": policy.public(),
        "deadlines": {
            "cooperative": True,
            "case_seconds": case_deadline_seconds,
            "cohort_seconds": cohort_deadline_seconds,
        },
        "strict_contract": {
            "same_layer_required": True,
            "detector_match_required": True,
            "detector_confidence": profile.detector_confidence,
            "detector_extractor_independence_claimed": (
                profile.detector_extractor_independence_claimed
            ),
            "detector_extractor_independence_required": False,
            "shared_decoding_primitives_allowed": True,
            "terminal_family_confirmation_required": True,
            "configuration_format": profile.configuration_format,
            "family_bound_configuration_required": True,
            "qualified_c2_record_required": True,
            "cross_layer_configuration_conflict_rejected": True,
            "provider_label_used_for_family_confirmation": False,
            "loose_url_used_as_configured_c2": False,
        },
        "metric_definitions": {
            "route_stage_recovered": (
                "review済みtransform名の静的layerを復元したことだけを示し、"
                "family帰属や終端payloadを意味しない"
            ),
            "terminal_payload_reached": (
                "profileが静的terminal候補として検証したlayerを示す。"
                "後続stageが存在しないことは証明しない"
            ),
            "terminal_family_confirmed": (
                "同一layer上のprofile証拠を照合したfamily判定。"
                "detectorとextractorの独立実装は主張しない"
            ),
            "validated_config_recovered": (
                "family-bound静的設定を復元したことを示し、endpointの稼働は確認しない"
            ),
            "qualified_c2_recovered": (
                "validated_config_recoveredと同じ静的predicate。"
                "live C2／protocol応答確認を意味しない"
            ),
            "strict_success": (
                "同一layerのterminal familyと設定が一致し、全静的走査が完走し、"
                "cross-layer設定競合がないことを示す"
            ),
        },
        "baseline": baseline,
        "current": current,
        "cases": cases,
        "safety": {
            "sample_executed": False,
            "network_contacted": False,
            "recovered_payload_written": False,
            "raw_endpoint_published": False,
            "raw_endpoint_hash_published": False,
            "configuration_fingerprint_published": False,
            "correlation_identifier": "run_scoped_hmac_sha256",
            "correlation_key_published": False,
        },
    }


def _positive_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("整数を指定してください") from exc
    if number <= 0:
        raise argparse.ArgumentTypeError("正の整数を指定してください")
    return number


def _bounded_positive_int(maximum: int, *, label: str) -> Callable[[str], int]:
    """argparse用の絶対上限付き正整数parserを返す。"""

    def parse(value: str) -> int:
        number = _positive_int(value)
        if number > maximum:
            raise argparse.ArgumentTypeError(f"{label}は安全上限{maximum}以下で指定してください")
        return number

    return parse


def _bounded_deadline_seconds(
    maximum: float,
    *,
    label: str,
) -> Callable[[str], float]:
    """argparse用の絶対上限付きdeadline秒数parserを返す。"""

    def parse(value: str) -> float:
        try:
            number = float(value)
            return _validated_deadline_seconds(
                number,
                name=label,
                maximum=maximum,
            )
        except (ValueError, CohortEvaluationError) as exc:
            raise argparse.ArgumentTypeError(str(exc)) from exc

    return parse


def build_parser(profile: PureCohortProfile = PURELOGS_PROFILE) -> argparse.ArgumentParser:
    """日本語helpを持つCLI parserを構築する。"""

    parser = JapaneseArgumentParser(
        description=(
            f"{profile.family}コホートを実行・通信なしで再解析し、provider labelやloose URLを"
            "除外したfamily・config・C2の同時成功率を測定します。"
        ),
        add_help=False,
    )
    parser._optionals.title = "オプション"
    parser.add_argument(
        "-h",
        "--help",
        action="help",
        help="このhelpを表示して終了します",
    )
    parser.add_argument(
        "--cohort-manifest",
        required=True,
        type=Path,
        help="cohorts objectを含む既存集計JSON",
    )
    parser.add_argument(
        "--samples-root",
        required=True,
        type=Path,
        help="<SHA-256>/<検体1件>で構成した入力root",
    )
    parser.add_argument(
        "--output",
        required=True,
        type=Path,
        help="raw endpointやpayloadを含まない評価JSONの出力先",
    )
    parser.add_argument(
        "--cohort",
        default=profile.cohort_name,
        help=f"評価するcohort名（既定: {profile.cohort_name}）",
    )
    parser.add_argument(
        "--sevenzip",
        type=Path,
        help="必要な7z carrierを静的展開するreview済み7-Zipの明示path",
    )
    parser.add_argument(
        "--max-layers",
        type=_bounded_positive_int(MAX_POLICY_LAYERS, label="max-layers"),
        default=64,
        help="1検体で保持する静的layer上限（既定: 64）",
    )
    parser.add_argument(
        "--max-depth",
        type=_bounded_positive_int(MAX_POLICY_DEPTH, label="max-depth"),
        default=6,
        help="静的layerの最大深さ（既定: 6）",
    )
    parser.add_argument(
        "--max-layer-size",
        type=_bounded_positive_int(
            MAX_POLICY_LAYER_SIZE,
            label="max-layer-size",
        ),
        default=128 * 1024 * 1024,
        help="1 layerの最大byte数（既定: 134217728）",
    )
    parser.add_argument(
        "--max-total-size",
        type=_bounded_positive_int(
            MAX_POLICY_TOTAL_SIZE,
            label="max-total-size",
        ),
        default=256 * 1024 * 1024,
        help="1検体で復元する総byte上限（既定: 268435456）",
    )
    parser.add_argument(
        "--case-deadline-seconds",
        "--case-timeout-seconds",
        dest="case_deadline_seconds",
        type=_bounded_deadline_seconds(
            MAX_CASE_DEADLINE_SECONDS,
            label="case-deadline-seconds",
        ),
        default=DEFAULT_CASE_DEADLINE_SECONDS,
        help="1検体の協調的deadline秒数（既定: 1800）",
    )
    parser.add_argument(
        "--cohort-deadline-seconds",
        "--cohort-timeout-seconds",
        dest="cohort_deadline_seconds",
        type=_bounded_deadline_seconds(
            MAX_COHORT_DEADLINE_SECONDS,
            label="cohort-deadline-seconds",
        ),
        default=DEFAULT_COHORT_DEADLINE_SECONDS,
        help="コホート全体の協調的deadline秒数（既定: 57600）",
    )
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    profile: PureCohortProfile = PURELOGS_PROFILE,
) -> int:
    args = build_parser(profile).parse_args(argv)
    policy = StaticLayerPolicy(
        max_layers=args.max_layers,
        max_depth=args.max_depth,
        max_layer_size=args.max_layer_size,
        max_total_size=args.max_total_size,
    )
    result = evaluate_cohort(
        cohort_manifest=args.cohort_manifest.resolve(),
        samples_root=args.samples_root.resolve(),
        cohort_name=args.cohort,
        policy=policy,
        profile=profile,
        sevenzip=args.sevenzip.resolve() if args.sevenzip else None,
        progress=lambda message: print(message, file=sys.stderr, flush=True),
        case_deadline_seconds=args.case_deadline_seconds,
        cohort_deadline_seconds=args.cohort_deadline_seconds,
    )
    encoded = (json.dumps(result, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f".{output.name}.{os.getpid()}.tmp")
    temporary.write_bytes(encoded)
    os.replace(temporary, output)
    print(json.dumps(result["current"], ensure_ascii=False, sort_keys=True))
    return 0 if result["current"]["target_met"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
