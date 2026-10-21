#!/usr/bin/env python3
"""ValleyRAT自動解析を20件単位、最大5回の未使用holdoutで評価する。

公式100件holdoutの契約は変更せず、同じ厳格なfamily確定・静的C2設定相関を
再利用する。解析前にMalwareBazaarの固定選定をprivate stateへ登録し、同じ20件の
再解析は開発用評価として分離する。公開評価には検体SHA-256、IOC、private pathを
含めない。検体、archive、復元payloadは開かず、外部通信やsubprocessも行わない。
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import hmac
import json
import math
import os
import sys
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

COMMON_ROOT = Path(__file__).resolve().parent
if str(COMMON_ROOT) not in sys.path:
    sys.path.insert(0, str(COMMON_ROOT))

import evaluate_valleyrat_holdout as strict_holdout
import malwarebazaar_batch
import summarize_one_shot_corpus as corpus

SCHEMA_VERSION = 1
STATE_SCHEMA_VERSION = 2
LEGACY_STATE_SCHEMA_VERSION = 1
CONTRACT_VERSION = "valleyrat-static-cycle-20x5-v1"
TARGET_FAMILY = "valleyrat"
PROVIDER_SIGNATURE = "ValleyRAT"
PROVIDER_ARCHIVE_ENCRYPTION_SCHEME = "winzip-aes-128"
PROVIDER_ARCHIVE_AES_STRENGTH_BITS = 128
COHORT_SIZE = 20
MAXIMUM_HOLDOUT_CYCLES = 5
MINIMUM_JOINT_SUCCESS_PERCENTAGE = 33.0
REQUIRED_JOINT_SUCCESSES = math.ceil(COHORT_SIZE * MINIMUM_JOINT_SUCCESS_PERCENTAGE / 100.0)
MAXIMUM_DEVELOPMENT_REANALYSES_PER_CYCLE = 32
MAXIMUM_STATE_BYTES = 4 * 1024 * 1024
REPOSITORY_ROOT = COMMON_ROOT.parent.parent.resolve()
DEVELOPMENT_CHAIN_COUNT_FIELD = "development_reanalyses_chain_count"

EVALUATION_KINDS = frozenset({"holdout", "development_reanalysis"})
GATE_STATUSES = frozenset({"passed", "failed", "not_applicable_development_reanalysis"})
NEXT_ACTIONS = frozenset(
    {
        "stop_target_met",
        "analyze_failures_then_register_unused_holdout",
        "maximum_cycles_exhausted",
        "continue_development_then_use_unused_holdout",
    }
)
TARGET = {
    "family": TARGET_FAMILY,
    "holdout_cases_per_cycle": COHORT_SIZE,
    "maximum_holdout_cycles": MAXIMUM_HOLDOUT_CYCLES,
    "minimum_joint_success_percentage": MINIMUM_JOINT_SUCCESS_PERCENTAGE,
    "required_joint_successes": REQUIRED_JOINT_SUCCESSES,
    "joint_success_condition": "family_confirmed_and_c2_config_confirmed",
}
VISIBILITY = {
    "classification": "private",
    "contains_sample_sha256": True,
    "contains_network_iocs": False,
    "contains_private_paths": False,
    "publishable": False,
}


class CycleEvaluationError(ValueError):
    """秘密値を含まない固定codeを持つcycle評価エラー。"""

    def __init__(self, code: str, message_ja: str) -> None:
        super().__init__(message_ja)
        self.code = code


class JapaneseArgumentParser(argparse.ArgumentParser):
    """argparseの固定見出しを日本語へ変換する。"""

    def format_help(self) -> str:
        return (
            super()
            .format_help()
            .replace("usage:", "使用法:")
            .replace("options:", "オプション:")
            .replace("positional arguments:", "操作:")
            .replace("show this help message and exit", "このヘルプを表示して終了します")
        )


def _canonical_sha256(value: object) -> str:
    """JSON値の決定的SHA-256を返す。"""

    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and corpus.SHA256_RE.fullmatch(value) is not None


def _require_sha256(value: object, *, code: str) -> str:
    if not _is_sha256(value):
        raise CycleEvaluationError(code, "SHA-256契約が不正です。")
    return str(value)


def _require_exact_keys(
    value: Mapping[str, Any],
    expected: set[str],
    *,
    code: str,
) -> None:
    if set(value) != expected:
        raise CycleEvaluationError(code, "JSON objectのfield契約が不正です。")


def _state_without_seal(value: Mapping[str, Any]) -> dict[str, Any]:
    return {key: copy.deepcopy(item) for key, item in value.items() if key != "state_semantic_sha256"}


def _seal_state(value: Mapping[str, Any]) -> dict[str, Any]:
    output = _state_without_seal(value)
    output["state_semantic_sha256"] = _canonical_sha256(output)
    return output


def _cycles_for_commitment(cycles: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """後続事前登録が観測した時点のcycle列を再構築する。"""

    projected: list[dict[str, Any]] = []
    for cycle in cycles:
        item = copy.deepcopy(dict(cycle))
        development = item.get("development_reanalyses")
        if DEVELOPMENT_CHAIN_COUNT_FIELD in item:
            chain_count = item.pop(DEVELOPMENT_CHAIN_COUNT_FIELD)
            if (
                type(chain_count) is not int
                or not isinstance(development, list)
                or not 0 <= chain_count <= len(development)
            ):
                raise CycleEvaluationError(
                    "state_development_chain_count_invalid",
                    "開発用再解析のcommitment境界が不正です。",
                )
            item["development_reanalyses"] = development[:chain_count]
        projected.append(item)
    return projected


def _has_downstream_development_commitment(
    *,
    cycle_number: int,
    cycles: Sequence[Mapping[str, Any]],
    extensions: Sequence[Mapping[str, Any]],
) -> bool:
    """開発用再解析の境界を必要とする後続の公式commitmentがあるか返す。"""

    # 後続cycleのregistration（およびそのrun登録）は、それ以前のcycle列を
    # commitmentへ含める。extensionも同じcycle境界以降なら同様に含める。
    if cycle_number < len(cycles):
        return True
    return any(
        isinstance(extension, Mapping)
        and type(extension.get("after_cycle_count")) is int
        and extension["after_cycle_count"] >= cycle_number
        for extension in extensions
    )


def _chain_prefix_state(
    *,
    baseline: Mapping[str, Any],
    extensions: Sequence[Mapping[str, Any]],
    cycles: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """公式登録chain用に、後追い開発記録を除いたstate sealを返す。"""

    return _seal_state(
        {
            "schema_version": STATE_SCHEMA_VERSION,
            "contract_version": CONTRACT_VERSION,
            "visibility": dict(VISIBILITY),
            "target": dict(TARGET),
            "baseline_exclusion": copy.deepcopy(dict(baseline)),
            "exclusion_extensions": copy.deepcopy(list(extensions)),
            "cycles": _cycles_for_commitment(cycles),
        }
    )


def _chain_state_semantic_sha256(state: Mapping[str, Any]) -> str:
    """現在stateから次の公式登録が参照するchain sealを返す。"""

    return str(
        _chain_prefix_state(
            baseline=state["baseline_exclusion"],
            extensions=state["exclusion_extensions"],
            cycles=state["cycles"],
        )["state_semantic_sha256"]
    )


def _exclusion_set_sha256(identities: Sequence[str]) -> str:
    """MalwareBazaar選定manifestと同じ除外集合commitmentを返す。"""

    return _canonical_sha256(sorted(identities))


def _baseline_record(identities: Sequence[str]) -> dict[str, Any]:
    normalized = sorted(set(identities))
    if len(normalized) != len(identities) or any(not _is_sha256(item) for item in normalized):
        raise CycleEvaluationError(
            "baseline_identity_set_invalid",
            "baseline除外集合は重複のないSHA-256集合である必要があります。",
        )
    return {
        "identity_type": "sha256",
        "identity_count": len(normalized),
        "identities": normalized,
        "excluded_hashes_sha256": _exclusion_set_sha256(normalized),
    }


def _empty_state(baseline_identities: Sequence[str]) -> dict[str, Any]:
    return _seal_state(
        {
            "schema_version": STATE_SCHEMA_VERSION,
            "contract_version": CONTRACT_VERSION,
            "visibility": dict(VISIBILITY),
            "target": dict(TARGET),
            "baseline_exclusion": _baseline_record(baseline_identities),
            "exclusion_extensions": [],
            "cycles": [],
        }
    )


def _identity_set_sha256(identities: Sequence[str]) -> str:
    return _canonical_sha256(
        {
            "domain": CONTRACT_VERSION,
            "identity_type": "sha256",
            "identities": sorted(identities),
        }
    )


def _registration_commitment(
    *,
    cycle_number: int,
    selection_commitment_sha256: str,
    identity_set_sha256: str,
    exclusion_extension_count: int,
    excluded_hashes: int,
    excluded_hashes_sha256: str,
    previous_state_semantic_sha256: str,
) -> str:
    return _canonical_sha256(
        {
            "domain": CONTRACT_VERSION,
            "kind": "new_unused_holdout",
            "cycle_number": cycle_number,
            "selection_commitment_sha256": selection_commitment_sha256,
            "identity_set_sha256": identity_set_sha256,
            "exclusion_extension_count": exclusion_extension_count,
            "excluded_hashes": excluded_hashes,
            "excluded_hashes_sha256": excluded_hashes_sha256,
            "previous_state_semantic_sha256": previous_state_semantic_sha256,
        }
    )


def _exclusion_extension_commitment(
    *,
    extension_number: int,
    after_cycle_count: int,
    added_identity_count: int,
    added_identities_sha256: str,
    effective_identity_count: int,
    effective_identities_sha256: str,
    previous_state_semantic_sha256: str,
) -> str:
    """既知集合を単調追加するextension epochのcommitmentを返す。"""

    return _canonical_sha256(
        {
            "domain": CONTRACT_VERSION,
            "kind": "monotonic_known_exclusion_extension",
            "extension_number": extension_number,
            "after_cycle_count": after_cycle_count,
            "added_identity_count": added_identity_count,
            "added_identities_sha256": added_identities_sha256,
            "effective_identity_count": effective_identity_count,
            "effective_identities_sha256": effective_identities_sha256,
            "previous_state_semantic_sha256": previous_state_semantic_sha256,
        }
    )


def _legacy_registration_commitment(
    *,
    cycle_number: int,
    selection_commitment_sha256: str,
    identity_set_sha256: str,
    previous_state_semantic_sha256: str,
) -> str:
    """state schema v1の登録commitmentをmigration時だけ再検証する。"""

    return _canonical_sha256(
        {
            "domain": CONTRACT_VERSION,
            "kind": "new_unused_holdout",
            "cycle_number": cycle_number,
            "selection_commitment_sha256": selection_commitment_sha256,
            "identity_set_sha256": identity_set_sha256,
            "previous_state_semantic_sha256": previous_state_semantic_sha256,
        }
    )


def _run_path_set_sha256(paths: Sequence[Path]) -> str:
    normalized = sorted(os.path.normcase(str(path.resolve(strict=False))) for path in paths)
    if len(normalized) != len(set(normalized)):
        raise CycleEvaluationError(
            "holdout_run_path_duplicate",
            "初回holdoutのrun pathを重複指定できません。",
        )
    return _canonical_sha256(
        {
            "domain": CONTRACT_VERSION,
            "kind": "first_holdout_run_paths",
            "paths": normalized,
        }
    )


def _analysis_code_tree_sha256() -> str:
    """初回holdoutに使う解析コードtreeをsubprocessなしで封印する。"""

    roots = (
        COMMON_ROOT,
        REPOSITORY_ROOT / "extractors",
        REPOSITORY_ROOT / "unpackers",
        COMMON_ROOT.parent / "classifiers",
        COMMON_ROOT.parent / "definitions",
        COMMON_ROOT.parent / "malware" / "valleyrat",
    )
    suffixes = frozenset({".py", ".json", ".toml", ".yaml", ".yml", ".yar", ".yara"})
    entries: list[dict[str, Any]] = []
    for root in roots:
        if not root.is_dir() or root.is_symlink():
            raise CycleEvaluationError(
                "analysis_code_root_invalid",
                "解析コードrootを安全なdirectoryとして読み取れません。",
            )
        for path in sorted(root.rglob("*")):
            if path.suffix.lower() not in suffixes or "__pycache__" in path.parts:
                continue
            if not path.is_file() or path.is_symlink():
                raise CycleEvaluationError(
                    "analysis_code_file_invalid",
                    "解析コードtreeに通常fileでない対象があります。",
                )
            try:
                payload = path.read_bytes()
            except OSError as exc:
                raise CycleEvaluationError(
                    "analysis_code_read_failed",
                    "解析コードtreeを固定commitmentへ読み取れません。",
                ) from exc
            entries.append(
                {
                    "path": path.relative_to(REPOSITORY_ROOT).as_posix(),
                    "size": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                }
            )
    if not entries:
        raise CycleEvaluationError(
            "analysis_code_tree_empty",
            "解析コードtreeが空です。",
        )
    return _canonical_sha256(
        {
            "domain": CONTRACT_VERSION,
            "kind": "valleyrat_analysis_code_tree",
            "entries": entries,
        }
    )


def _holdout_run_registration_commitment(
    *,
    cycle_number: int,
    run_path_count: int,
    run_path_set_sha256: str,
    analysis_code_tree_sha256: str,
    previous_state_semantic_sha256: str,
) -> str:
    return _canonical_sha256(
        {
            "domain": CONTRACT_VERSION,
            "kind": "first_holdout_run_precommitment",
            "cycle_number": cycle_number,
            "run_path_count": run_path_count,
            "run_path_set_sha256": run_path_set_sha256,
            "analysis_code_tree_sha256": analysis_code_tree_sha256,
            "previous_state_semantic_sha256": previous_state_semantic_sha256,
        }
    )


def _read_json_object(path: Path, *, error_prefix: str) -> tuple[dict[str, Any], bytes]:
    try:
        value, raw = corpus._read_json_snapshot(
            path,
            corpus._ReadBudget(),
            error_prefix=error_prefix,
        )
    except corpus.CorpusSummaryError as exc:
        raise CycleEvaluationError(
            f"{error_prefix}_unreadable",
            "JSONを安全な通常file snapshotとして読み取れません。",
        ) from exc
    if len(raw) > MAXIMUM_STATE_BYTES:
        raise CycleEvaluationError(
            f"{error_prefix}_size_limit",
            "JSONがcycle評価のsize上限を超えています。",
        )
    return value, raw


def _validate_private_state_path(path: Path) -> Path:
    resolved = path.resolve(strict=False)
    try:
        resolved.relative_to(REPOSITORY_ROOT)
    except ValueError:
        return resolved
    raise CycleEvaluationError(
        "private_state_inside_repository",
        "sample SHA-256を含むprivate stateはrepository外へ保存してください。",
    )


def _validate_private_artifact_path(path: Path, *, code: str) -> Path:
    """検体identityを含む入力artifactがrepository外にあることを確認する。"""

    resolved = path.resolve(strict=False)
    try:
        resolved.relative_to(REPOSITORY_ROOT)
    except ValueError:
        return resolved
    raise CycleEvaluationError(
        code,
        "検体identityを含むprivate入力はrepository外へ保存してください。",
    )


def _baseline_hashes_from_files(paths: Sequence[Path]) -> tuple[str, ...]:
    """private manifestまたはhash-listからbaseline検体SHA-256を厳格に集約する。"""

    if not paths:
        raise CycleEvaluationError(
            "baseline_manifest_required",
            "cycle 1登録またはstate migrationにはprivate baseline manifestが必要です。",
        )
    identities: set[str] = set()

    def add(value: object) -> None:
        if _is_sha256(value):
            identities.add(str(value).lower())

    def walk(node: object) -> None:
        if isinstance(node, Mapping):
            add(node.get("sha256"))
            add(node.get("sha256_hash"))
            case_id = node.get("case_id")
            if isinstance(case_id, str) and case_id.startswith("sha256:"):
                add(case_id.removeprefix("sha256:"))
            for field in ("selected_hashes", "identities"):
                values = node.get(field)
                if isinstance(values, list):
                    for value in values:
                        add(value)
            cases = node.get("cases")
            if isinstance(cases, Mapping):
                for value in cases:
                    add(value)
            for child in node.values():
                walk(child)
        elif isinstance(node, list):
            for child in node:
                if isinstance(child, str):
                    add(child)
                else:
                    walk(child)

    for path in paths:
        _validate_private_artifact_path(path, code="baseline_manifest_inside_repository")
        value, _raw = _read_json_object(path, error_prefix="baseline_manifest")
        walk(value)
    return tuple(sorted(identities))


def _exact_exclusion_hashes_from_files(paths: Sequence[Path]) -> tuple[str, ...]:
    """commitment付きprivate hash-listだけをextension入力として集約する。"""

    if not paths:
        raise CycleEvaluationError(
            "exclusion_manifest_required",
            "既知集合extensionにはprivate exact hash-listが必要です。",
        )
    identities: set[str] = set()
    for path in paths:
        _validate_private_artifact_path(path, code="exclusion_manifest_inside_repository")
        value, _raw = _read_json_object(path, error_prefix="exclusion_manifest")
        supplied = value.get("identities")
        if (
            value.get("identity_type") != "sha256"
            or type(value.get("identity_count")) is not int
            or not isinstance(supplied, list)
            or value["identity_count"] != len(supplied)
            or supplied != sorted(supplied)
            or len(set(supplied)) != len(supplied)
            or any(not _is_sha256(item) for item in supplied)
            or value.get("excluded_hashes_sha256") != _exclusion_set_sha256(supplied)
        ):
            raise CycleEvaluationError(
                "exclusion_manifest_contract_invalid",
                "既知集合extensionのhash-list、件数、digestが一致しません。",
            )
        identities.update(supplied)
    return tuple(sorted(identities))


def _signature_commitment(manifest: Mapping[str, Any]) -> str:
    helper = getattr(malwarebazaar_batch, "_signature_selection_commitment", None)
    if not callable(helper):
        raise CycleEvaluationError(
            "signature_commitment_helper_missing",
            "signature選定commitmentの検証helperがありません。",
        )
    try:
        value = helper(dict(manifest))
    except (KeyError, TypeError, ValueError) as exc:
        raise CycleEvaluationError(
            "selection_commitment_recalculation_failed",
            "signature選定commitmentを再計算できません。",
        ) from exc
    return _require_sha256(value, code="selection_commitment_invalid")


def _validated_selection_manifest(
    path: Path,
    *,
    phase: str,
) -> dict[str, Any]:
    """固定ValleyRAT選定を解析前登録または評価時の状態へ検証する。"""

    if phase not in {"registration", "evaluation", "migration"}:
        raise ValueError("unknown selection manifest phase")
    _validate_private_artifact_path(
        path,
        code="selection_manifest_inside_repository",
    )
    manifest, _raw = _read_json_object(path, error_prefix="selection_manifest")
    if (
        manifest.get("schema_version") != 1
        or manifest.get("source") != "MalwareBazaar Community API"
        or manifest.get("selection_mode") != "signature_newest"
        or manifest.get("signature") != PROVIDER_SIGNATURE
        or manifest.get("requested") != COHORT_SIZE
        or not isinstance(manifest.get("selected_at"), str)
        or not manifest["selected_at"]
        or manifest.get("archives_remain_encrypted") is not True
        or manifest.get("samples_executed") is not False
    ):
        raise CycleEvaluationError(
            "selection_manifest_contract_invalid",
            "ValleyRATの固定20件選定契約が不正です。",
        )
    query_limit = manifest.get("query_limit")
    if type(query_limit) is not int or not COHORT_SIZE <= query_limit <= malwarebazaar_batch.MAX_SIGNATURE_QUERY_LIMIT:
        raise CycleEvaluationError(
            "selection_manifest_query_limit_invalid",
            "signature照会件数の契約が不正です。",
        )
    excluded_count = manifest.get("excluded_hashes")
    if type(excluded_count) is not int or excluded_count < 0 or not _is_sha256(manifest.get("excluded_hashes_sha256")):
        raise CycleEvaluationError(
            "selection_manifest_exclusion_contract_invalid",
            "除外集合commitmentの契約が不正です。",
        )
    max_download_bytes = manifest.get("max_download_bytes")
    max_total_download_bytes = manifest.get("max_total_download_bytes")
    minimum_free_bytes = manifest.get("minimum_free_bytes")
    if (
        type(max_download_bytes) is not int
        or not 1 <= max_download_bytes <= malwarebazaar_batch.MAX_API_RESPONSE_BYTES
        or type(max_total_download_bytes) is not int
        or not 1 <= max_total_download_bytes <= COHORT_SIZE * max_download_bytes
        or type(minimum_free_bytes) is not int
        or minimum_free_bytes < 0
    ):
        raise CycleEvaluationError(
            "selection_manifest_quota_contract_invalid",
            "取得容量quotaの契約が不正です。",
        )
    selected = manifest.get("selected_hashes")
    if (
        not isinstance(selected, list)
        or len(selected) != COHORT_SIZE
        or any(not _is_sha256(item) for item in selected)
        or len(set(selected)) != COHORT_SIZE
    ):
        raise CycleEvaluationError(
            "selection_manifest_identity_set_invalid",
            "選定SHA-256は重複のない正確な20件である必要があります。",
        )
    metadata = manifest.get("selected_metadata")
    if not isinstance(metadata, list) or len(metadata) != COHORT_SIZE:
        raise CycleEvaluationError(
            "selection_manifest_metadata_count_invalid",
            "選定metadata件数が20件と一致しません。",
        )
    metadata_hashes = []
    for item in metadata:
        if not isinstance(item, Mapping):
            raise CycleEvaluationError(
                "selection_manifest_metadata_invalid",
                "選定metadataの構造が不正です。",
            )
        digest = item.get("sha256_hash")
        if not _is_sha256(digest):
            raise CycleEvaluationError(
                "selection_manifest_metadata_invalid",
                "選定metadataのSHA-256が不正です。",
            )
        metadata_hashes.append(str(digest))
    if metadata_hashes != selected:
        raise CycleEvaluationError(
            "selection_manifest_metadata_order_mismatch",
            "選定metadataとSHA-256集合の順序が一致しません。",
        )

    declared_commitment = _require_sha256(
        manifest.get("selection_commitment_sha256"),
        code="selection_commitment_invalid",
    )
    observed_commitment = _signature_commitment(manifest)
    if not hmac.compare_digest(declared_commitment, observed_commitment):
        raise CycleEvaluationError(
            "selection_commitment_mismatch",
            "signature選定commitmentがmanifest内容と一致しません。",
        )

    if phase == "registration":
        if (
            manifest.get("selection_only") is not True
            or manifest.get("downloaded") != 0
            or manifest.get("pending_count", manifest.get("pending")) != 0
            or manifest.get("complete") is not False
            or manifest.get("observed_download_bytes") != 0
            or manifest.get("items") != []
            or manifest.get("retry_queue") != []
        ):
            raise CycleEvaluationError(
                "selection_not_pre_analysis",
                "解析前登録にはselection-only manifestが必要です。",
            )
    elif phase == "evaluation":
        pending = manifest.get("pending_count", manifest.get("pending"))
        items = manifest.get("items")
        retry_queue = manifest.get("retry_queue")
        if (
            manifest.get("selection_only") is not False
            or manifest.get("downloaded") != COHORT_SIZE
            or pending != 0
            or manifest.get("complete") is not True
            or not isinstance(items, list)
            or len(items) != COHORT_SIZE
            or retry_queue != []
        ):
            raise CycleEvaluationError(
                "selection_download_incomplete",
                "評価前に固定20件の暗号化archive取得を完了してください。",
            )
        item_hashes = [item.get("sha256") if isinstance(item, Mapping) else None for item in items]
        if item_hashes != selected:
            raise CycleEvaluationError(
                "selection_download_item_mismatch",
                "取得済みitemと固定選定の順序または集合が一致しません。",
            )
        zip_sizes: list[int] = []
        for item in items:
            if (
                not isinstance(item, Mapping)
                or not _is_sha256(item.get("zip_sha256"))
                or type(item.get("zip_size")) is not int
                or not 1 <= item["zip_size"] <= max_download_bytes
                or item.get("member_sha256") != item.get("sha256")
                or type(item.get("member_size")) is not int
                or not 1 <= item["member_size"] <= malwarebazaar_batch.MAX_API_RESPONSE_BYTES
                or item.get("encrypted") is not True
                or item.get("encryption_verified") is not True
                or item.get("encryption_scheme") != PROVIDER_ARCHIVE_ENCRYPTION_SCHEME
                or item.get("aes_strength_bits") != PROVIDER_ARCHIVE_AES_STRENGTH_BITS
                or item.get("member_sha256_verified") is not True
            ):
                raise CycleEvaluationError(
                    "selection_download_item_integrity_invalid",
                    "取得済み暗号化archiveのintegrity契約が不正です。",
                )
            zip_sizes.append(item["zip_size"])
        observed_download_bytes = manifest.get("observed_download_bytes")
        if (
            type(observed_download_bytes) is not int
            or observed_download_bytes != sum(zip_sizes)
            or observed_download_bytes > max_total_download_bytes
        ):
            raise CycleEvaluationError(
                "selection_download_byte_accounting_invalid",
                "取得済み暗号化archiveのbyte集計がquotaと一致しません。",
            )

    elif manifest.get("selection_only") is True:
        if (
            manifest.get("downloaded") != 0
            or manifest.get("pending_count", manifest.get("pending")) != 0
            or manifest.get("complete") is not False
            or manifest.get("observed_download_bytes") != 0
            or manifest.get("items") != []
            or manifest.get("retry_queue") != []
        ):
            raise CycleEvaluationError(
                "selection_migration_manifest_invalid",
                "migration用selection-only manifestが不正です。",
            )
    else:
        pending = manifest.get("pending_count", manifest.get("pending"))
        items = manifest.get("items")
        if (
            manifest.get("downloaded") != COHORT_SIZE
            or pending != 0
            or manifest.get("complete") is not True
            or not isinstance(items, list)
            or len(items) != COHORT_SIZE
            or manifest.get("retry_queue") != []
        ):
            raise CycleEvaluationError(
                "selection_migration_manifest_invalid",
                "migration用manifestは固定選定または取得完了状態である必要があります。",
            )

    return {
        "identities": tuple(str(item) for item in selected),
        "selection_commitment_sha256": declared_commitment,
        "identity_set_sha256": _identity_set_sha256(selected),
        "excluded_hashes": excluded_count,
        "excluded_hashes_sha256": str(manifest["excluded_hashes_sha256"]),
        "download_contract_verified": phase == "evaluation",
        "archive_encryption_and_member_identity_verified": phase == "evaluation",
        "manifest_semantic_sha256": _canonical_sha256(manifest),
    }


def _validate_summary_record(
    record: Mapping[str, Any],
    *,
    cycle_number: int,
    kind: str,
    ordinal: int,
) -> None:
    _require_exact_keys(
        record,
        {
            "kind",
            "ordinal",
            "counts_for_target_gate",
            "input_commitment_sha256",
            "evaluation_summary_sha256",
            "observed_joint_successes",
            "input_integrity_clean",
            "target_gate_status",
        },
        code="state_evaluation_record_schema_invalid",
    )
    if (
        record.get("kind") != kind
        or record.get("ordinal") != ordinal
        or record.get("counts_for_target_gate") is not (kind == "holdout")
        or type(record.get("observed_joint_successes")) is not int
        or not 0 <= record["observed_joint_successes"] <= COHORT_SIZE
        or type(record.get("input_integrity_clean")) is not bool
        or record.get("target_gate_status") not in GATE_STATUSES
    ):
        raise CycleEvaluationError(
            "state_evaluation_record_invalid",
            "cycle評価recordが固定契約と一致しません。",
        )
    if kind == "holdout" and record["target_gate_status"] not in {"passed", "failed"}:
        raise CycleEvaluationError(
            "state_holdout_gate_invalid",
            "holdout評価のgate状態が不正です。",
        )
    if kind == "holdout" and (record["target_gate_status"] == "passed") is not (
        record["observed_joint_successes"] >= REQUIRED_JOINT_SUCCESSES and record["input_integrity_clean"]
    ):
        raise CycleEvaluationError(
            "state_holdout_gate_semantics_invalid",
            "holdout評価の成功件数、入力整合性、gate状態が一致しません。",
        )
    if kind == "development_reanalysis" and record["target_gate_status"] != "not_applicable_development_reanalysis":
        raise CycleEvaluationError(
            "state_development_gate_invalid",
            "開発用再解析をtarget gateへ使用できません。",
        )
    _require_sha256(
        record.get("input_commitment_sha256"),
        code="state_input_commitment_invalid",
    )
    _require_sha256(
        record.get("evaluation_summary_sha256"),
        code="state_evaluation_commitment_invalid",
    )
    del cycle_number


def _validated_state(value: Mapping[str, Any]) -> dict[str, Any]:
    """private stateのseal、cycle順序、未使用identityを再検証する。"""

    _require_exact_keys(
        value,
        {
            "schema_version",
            "contract_version",
            "visibility",
            "target",
            "baseline_exclusion",
            "exclusion_extensions",
            "cycles",
            "state_semantic_sha256",
        },
        code="state_schema_invalid",
    )
    if (
        value.get("schema_version") != STATE_SCHEMA_VERSION
        or value.get("contract_version") != CONTRACT_VERSION
        or value.get("visibility") != VISIBILITY
        or value.get("target") != TARGET
    ):
        raise CycleEvaluationError(
            "state_contract_invalid",
            "private stateの固定評価契約が一致しません。",
        )
    supplied_seal = _require_sha256(
        value.get("state_semantic_sha256"),
        code="state_seal_invalid",
    )
    expected_seal = _canonical_sha256(_state_without_seal(value))
    if not hmac.compare_digest(supplied_seal, expected_seal):
        raise CycleEvaluationError(
            "state_seal_mismatch",
            "private stateの意味sealが一致しません。",
        )
    cycles = value.get("cycles")
    if not isinstance(cycles, list) or len(cycles) > MAXIMUM_HOLDOUT_CYCLES:
        raise CycleEvaluationError(
            "state_cycle_count_invalid",
            "holdout cycle件数が上限を超えています。",
        )

    baseline = value.get("baseline_exclusion")
    if not isinstance(baseline, Mapping):
        raise CycleEvaluationError(
            "state_baseline_schema_invalid",
            "private stateのbaseline除外recordがありません。",
        )
    _require_exact_keys(
        baseline,
        {"identity_type", "identity_count", "identities", "excluded_hashes_sha256"},
        code="state_baseline_schema_invalid",
    )
    baseline_identities = baseline.get("identities")
    if (
        baseline.get("identity_type") != "sha256"
        or type(baseline.get("identity_count")) is not int
        or not isinstance(baseline_identities, list)
        or baseline["identity_count"] != len(baseline_identities)
        or baseline_identities != sorted(baseline_identities)
        or len(set(baseline_identities)) != len(baseline_identities)
        or any(not _is_sha256(item) for item in baseline_identities)
        or baseline.get("excluded_hashes_sha256") != _exclusion_set_sha256(baseline_identities)
    ):
        raise CycleEvaluationError(
            "state_baseline_identity_invalid",
            "private stateのbaseline除外集合またはcommitmentが不正です。",
        )

    extensions = value.get("exclusion_extensions")
    if not isinstance(extensions, list):
        raise CycleEvaluationError(
            "state_exclusion_extensions_invalid",
            "既知除外集合のextension一覧が不正です。",
        )

    seen: set[str] = set()
    effective_exclusion = {str(item) for item in baseline_identities}
    validated_extensions: list[dict[str, Any]] = []
    validated_cycles: list[dict[str, Any]] = []

    def consume_extensions(after_cycle_count: int) -> None:
        """指定cycle境界に登録された単調extensionを順に検証する。"""

        nonlocal effective_exclusion
        while len(validated_extensions) < len(extensions):
            supplied_extension = extensions[len(validated_extensions)]
            if not isinstance(supplied_extension, Mapping):
                raise CycleEvaluationError(
                    "state_exclusion_extension_schema_invalid",
                    "既知除外集合のextension recordはobjectである必要があります。",
                )
            supplied_after = supplied_extension.get("after_cycle_count")
            if type(supplied_after) is not int or supplied_after < after_cycle_count:
                raise CycleEvaluationError(
                    "state_exclusion_extension_order_invalid",
                    "既知除外集合のextension順序が不正です。",
                )
            if supplied_after != after_cycle_count:
                break
            if validated_cycles:
                latest_evaluation = validated_cycles[-1]["holdout_evaluation"]
                if latest_evaluation is None:
                    raise CycleEvaluationError(
                        "state_extension_after_unevaluated_cycle",
                        "未評価cycleの後に既知除外集合を拡張できません。",
                    )
                if latest_evaluation["target_gate_status"] == "passed":
                    raise CycleEvaluationError(
                        "state_extension_after_target_passed",
                        "目標達成後に既知除外集合を拡張できません。",
                    )
            _require_exact_keys(
                supplied_extension,
                {
                    "extension_number",
                    "kind",
                    "after_cycle_count",
                    "added_identity_count",
                    "added_identities",
                    "added_identities_sha256",
                    "effective_identity_count",
                    "effective_identities",
                    "effective_identities_sha256",
                    "previous_state_semantic_sha256",
                    "extension_commitment_sha256",
                },
                code="state_exclusion_extension_schema_invalid",
            )
            extension_number = len(validated_extensions) + 1
            added = supplied_extension.get("added_identities")
            effective = supplied_extension.get("effective_identities")
            if (
                supplied_extension.get("extension_number") != extension_number
                or supplied_extension.get("kind") != "monotonic_known_exclusion_extension"
                or not isinstance(added, list)
                or not added
                or added != sorted(added)
                or len(set(added)) != len(added)
                or any(not _is_sha256(item) for item in added)
                or type(supplied_extension.get("added_identity_count")) is not int
                or supplied_extension["added_identity_count"] != len(added)
                or not isinstance(effective, list)
                or effective != sorted(effective)
                or len(set(effective)) != len(effective)
                or any(not _is_sha256(item) for item in effective)
                or type(supplied_extension.get("effective_identity_count")) is not int
                or supplied_extension["effective_identity_count"] != len(effective)
                or effective_exclusion.intersection(added)
                or set(effective) != effective_exclusion.union(added)
            ):
                raise CycleEvaluationError(
                    "state_exclusion_extension_identity_invalid",
                    "既知除外集合のextensionは既存集合への非空な単調追加である必要があります。",
                )
            added_digest = _require_sha256(
                supplied_extension.get("added_identities_sha256"),
                code="state_exclusion_extension_added_commitment_invalid",
            )
            effective_digest = _require_sha256(
                supplied_extension.get("effective_identities_sha256"),
                code="state_exclusion_extension_effective_commitment_invalid",
            )
            if added_digest != _exclusion_set_sha256(added) or effective_digest != _exclusion_set_sha256(effective):
                raise CycleEvaluationError(
                    "state_exclusion_extension_identity_commitment_mismatch",
                    "既知除外集合のextension commitmentが一致しません。",
                )
            prefix = _chain_prefix_state(
                baseline=baseline,
                extensions=validated_extensions,
                cycles=validated_cycles,
            )
            previous_state = _require_sha256(
                supplied_extension.get("previous_state_semantic_sha256"),
                code="state_exclusion_extension_previous_commitment_invalid",
            )
            extension_commitment = _require_sha256(
                supplied_extension.get("extension_commitment_sha256"),
                code="state_exclusion_extension_commitment_invalid",
            )
            if previous_state != prefix[
                "state_semantic_sha256"
            ] or extension_commitment != _exclusion_extension_commitment(
                extension_number=extension_number,
                after_cycle_count=after_cycle_count,
                added_identity_count=len(added),
                added_identities_sha256=added_digest,
                effective_identity_count=len(effective),
                effective_identities_sha256=effective_digest,
                previous_state_semantic_sha256=previous_state,
            ):
                raise CycleEvaluationError(
                    "state_exclusion_extension_commitment_mismatch",
                    "既知除外集合のextension commitment chainが一致しません。",
                )
            validated_extensions.append(copy.deepcopy(dict(supplied_extension)))
            effective_exclusion = set(effective)

    for index, supplied_cycle in enumerate(cycles, start=1):
        consume_extensions(index - 1)
        if not isinstance(supplied_cycle, Mapping):
            raise CycleEvaluationError(
                "state_cycle_schema_invalid",
                "cycle recordはobjectである必要があります。",
            )
        cycle_keys = {
            "cycle_number",
            "selection",
            "registration",
            "holdout_run_registration",
            "holdout_evaluation",
            "development_reanalyses",
        }
        if set(supplied_cycle) not in {frozenset(cycle_keys), frozenset({*cycle_keys, DEVELOPMENT_CHAIN_COUNT_FIELD})}:
            raise CycleEvaluationError(
                "state_cycle_schema_invalid",
                "cycle recordのfield契約が不正です。",
            )
        if supplied_cycle.get("cycle_number") != index:
            raise CycleEvaluationError(
                "state_cycle_sequence_invalid",
                "cycle番号は1から連続している必要があります。",
            )
        selection = supplied_cycle.get("selection")
        registration = supplied_cycle.get("registration")
        if not isinstance(selection, Mapping) or not isinstance(registration, Mapping):
            raise CycleEvaluationError(
                "state_registration_schema_invalid",
                "selectionまたはregistration recordが不正です。",
            )
        _require_exact_keys(
            selection,
            {
                "identity_type",
                "identity_count",
                "identities",
                "identity_set_sha256",
                "selection_commitment_sha256",
                "exclusion_extension_count",
                "excluded_hashes",
                "excluded_hashes_sha256",
            },
            code="state_selection_schema_invalid",
        )
        identities = selection.get("identities")
        if (
            selection.get("identity_type") != "sha256"
            or selection.get("identity_count") != COHORT_SIZE
            or not isinstance(identities, list)
            or len(identities) != COHORT_SIZE
            or identities != sorted(identities)
            or len(set(identities)) != COHORT_SIZE
            or any(not _is_sha256(item) for item in identities)
        ):
            raise CycleEvaluationError(
                "state_selection_identity_invalid",
                "private stateの選定identity集合が不正です。",
            )
        if seen.intersection(identities):
            raise CycleEvaluationError(
                "state_cycle_identity_overlap",
                "異なるholdout cycleで同じ検体を再利用できません。",
            )
        seen.update(identities)
        identity_set_sha256 = _require_sha256(
            selection.get("identity_set_sha256"),
            code="state_identity_commitment_invalid",
        )
        if identity_set_sha256 != _identity_set_sha256(identities):
            raise CycleEvaluationError(
                "state_identity_commitment_mismatch",
                "private stateのidentity集合commitmentが一致しません。",
            )
        selection_commitment = _require_sha256(
            selection.get("selection_commitment_sha256"),
            code="state_selection_commitment_invalid",
        )
        excluded_hashes = selection.get("excluded_hashes")
        excluded_hashes_sha256 = _require_sha256(
            selection.get("excluded_hashes_sha256"),
            code="state_selection_exclusion_commitment_invalid",
        )
        exclusion_extension_count = selection.get("exclusion_extension_count")
        expected_exclusion = set(effective_exclusion)
        if (
            type(exclusion_extension_count) is not int
            or exclusion_extension_count != len(validated_extensions)
            or type(excluded_hashes) is not int
            or excluded_hashes != len(expected_exclusion)
            or excluded_hashes_sha256 != _exclusion_set_sha256(sorted(expected_exclusion))
            or expected_exclusion.intersection(identities)
        ):
            raise CycleEvaluationError(
                "state_selection_cumulative_exclusion_mismatch",
                "cycle選定の除外集合がbaselineと過去cycleの累積集合に一致しません。",
            )

        prefix = _chain_prefix_state(
            baseline=baseline,
            extensions=validated_extensions,
            cycles=validated_cycles,
        )
        _require_exact_keys(
            registration,
            {
                "kind",
                "counts_for_target_gate",
                "previous_state_semantic_sha256",
                "registration_commitment_sha256",
            },
            code="state_registration_schema_invalid",
        )
        previous_state = _require_sha256(
            registration.get("previous_state_semantic_sha256"),
            code="state_previous_commitment_invalid",
        )
        registration_commitment = _require_sha256(
            registration.get("registration_commitment_sha256"),
            code="state_registration_commitment_invalid",
        )
        if (
            registration.get("kind") != "new_unused_holdout"
            or registration.get("counts_for_target_gate") is not True
            or previous_state != prefix["state_semantic_sha256"]
            or registration_commitment
            != _registration_commitment(
                cycle_number=index,
                selection_commitment_sha256=selection_commitment,
                identity_set_sha256=identity_set_sha256,
                exclusion_extension_count=exclusion_extension_count,
                excluded_hashes=excluded_hashes,
                excluded_hashes_sha256=excluded_hashes_sha256,
                previous_state_semantic_sha256=previous_state,
            )
        ):
            raise CycleEvaluationError(
                "state_registration_commitment_mismatch",
                "cycle事前登録のcommitment chainが一致しません。",
            )

        holdout_run_registration = supplied_cycle.get("holdout_run_registration")
        if holdout_run_registration is not None:
            if not isinstance(holdout_run_registration, Mapping):
                raise CycleEvaluationError(
                    "state_holdout_run_registration_invalid",
                    "初回holdout runの事前登録recordが不正です。",
                )
            kind = holdout_run_registration.get("kind")
            if kind == "first_holdout_run_precommitment":
                _require_exact_keys(
                    holdout_run_registration,
                    {
                        "kind",
                        "run_path_count",
                        "run_path_set_sha256",
                        "analysis_code_tree_sha256",
                        "previous_state_semantic_sha256",
                        "registration_commitment_sha256",
                    },
                    code="state_holdout_run_registration_schema_invalid",
                )
                run_path_count = holdout_run_registration.get("run_path_count")
                run_path_set = _require_sha256(
                    holdout_run_registration.get("run_path_set_sha256"),
                    code="state_holdout_run_path_commitment_invalid",
                )
                code_tree = _require_sha256(
                    holdout_run_registration.get("analysis_code_tree_sha256"),
                    code="state_analysis_code_commitment_invalid",
                )
                pre_start_cycle = copy.deepcopy(dict(supplied_cycle))
                pre_start_cycle["holdout_run_registration"] = None
                pre_start_cycle["holdout_evaluation"] = None
                pre_start_cycle["development_reanalyses"] = []
                pre_start_cycle.pop(DEVELOPMENT_CHAIN_COUNT_FIELD, None)
                pre_start_state = _chain_prefix_state(
                    baseline=baseline,
                    extensions=validated_extensions,
                    cycles=[*copy.deepcopy(validated_cycles), pre_start_cycle],
                )
                previous_run_state = _require_sha256(
                    holdout_run_registration.get("previous_state_semantic_sha256"),
                    code="state_holdout_run_previous_commitment_invalid",
                )
                if (
                    type(run_path_count) is not int
                    or run_path_count < 1
                    or previous_run_state != pre_start_state["state_semantic_sha256"]
                    or holdout_run_registration.get("registration_commitment_sha256")
                    != _holdout_run_registration_commitment(
                        cycle_number=index,
                        run_path_count=run_path_count,
                        run_path_set_sha256=run_path_set,
                        analysis_code_tree_sha256=code_tree,
                        previous_state_semantic_sha256=previous_run_state,
                    )
                ):
                    raise CycleEvaluationError(
                        "state_holdout_run_registration_mismatch",
                        "初回holdout runの事前登録commitmentが一致しません。",
                    )
            elif kind == "legacy_evaluated_holdout":
                _require_exact_keys(
                    holdout_run_registration,
                    {
                        "kind",
                        "input_commitment_sha256",
                        "evaluation_summary_sha256",
                        "migration_commitment_sha256",
                    },
                    code="state_legacy_run_registration_schema_invalid",
                )
                legacy_input = _require_sha256(
                    holdout_run_registration.get("input_commitment_sha256"),
                    code="state_legacy_input_commitment_invalid",
                )
                legacy_summary = _require_sha256(
                    holdout_run_registration.get("evaluation_summary_sha256"),
                    code="state_legacy_summary_commitment_invalid",
                )
                if holdout_run_registration.get("migration_commitment_sha256") != _canonical_sha256(
                    {
                        "domain": CONTRACT_VERSION,
                        "kind": "legacy_evaluated_holdout",
                        "cycle_number": index,
                        "input_commitment_sha256": legacy_input,
                        "evaluation_summary_sha256": legacy_summary,
                    }
                ):
                    raise CycleEvaluationError(
                        "state_legacy_run_registration_mismatch",
                        "migration済み初回holdoutのcommitmentが一致しません。",
                    )
            else:
                raise CycleEvaluationError(
                    "state_holdout_run_registration_kind_invalid",
                    "初回holdout runの事前登録種別が不正です。",
                )

        holdout_evaluation = supplied_cycle.get("holdout_evaluation")
        if holdout_evaluation is not None:
            if not isinstance(holdout_evaluation, Mapping):
                raise CycleEvaluationError(
                    "state_holdout_evaluation_invalid",
                    "holdout評価recordが不正です。",
                )
            _validate_summary_record(
                holdout_evaluation,
                cycle_number=index,
                kind="holdout",
                ordinal=1,
            )
            if holdout_run_registration is None:
                raise CycleEvaluationError(
                    "state_holdout_evaluation_without_run_registration",
                    "初回holdout評価に解析前run登録がありません。",
                )
            if holdout_run_registration.get("kind") == "legacy_evaluated_holdout" and (
                holdout_run_registration["input_commitment_sha256"] != holdout_evaluation["input_commitment_sha256"]
                or holdout_run_registration["evaluation_summary_sha256"]
                != holdout_evaluation["evaluation_summary_sha256"]
            ):
                raise CycleEvaluationError(
                    "state_legacy_run_evaluation_mismatch",
                    "migration済み初回holdoutと評価recordが一致しません。",
                )
        development = supplied_cycle.get("development_reanalyses")
        if not isinstance(development, list) or len(development) > MAXIMUM_DEVELOPMENT_REANALYSES_PER_CYCLE:
            raise CycleEvaluationError(
                "state_development_count_invalid",
                "開発用再解析recordが上限を超えています。",
            )
        if development and holdout_evaluation is None:
            raise CycleEvaluationError(
                "state_development_before_holdout",
                "初回holdout評価前の開発用再解析recordは許可されません。",
            )
        if DEVELOPMENT_CHAIN_COUNT_FIELD in supplied_cycle:
            chain_count = supplied_cycle.get(DEVELOPMENT_CHAIN_COUNT_FIELD)
            has_downstream_commitment = _has_downstream_development_commitment(
                cycle_number=index,
                cycles=cycles,
                extensions=extensions,
            )
            if type(chain_count) is not int or not 0 <= chain_count < len(development) or not has_downstream_commitment:
                raise CycleEvaluationError(
                    "state_development_chain_count_invalid",
                    "後追い開発用再解析のcommitment境界が不正です。",
                )
        if (
            holdout_evaluation is None
            and isinstance(holdout_run_registration, Mapping)
            and holdout_run_registration.get("kind") == "legacy_evaluated_holdout"
        ):
            raise CycleEvaluationError(
                "state_legacy_run_without_evaluation",
                "legacy run登録には既存holdout評価recordが必要です。",
            )
        for ordinal, record in enumerate(development, start=1):
            if not isinstance(record, Mapping):
                raise CycleEvaluationError(
                    "state_development_record_invalid",
                    "開発用再解析recordが不正です。",
                )
            _validate_summary_record(
                record,
                cycle_number=index,
                kind="development_reanalysis",
                ordinal=ordinal,
            )
        if index < len(cycles):
            if holdout_evaluation is None:
                raise CycleEvaluationError(
                    "state_prior_cycle_unevaluated",
                    "前cycleの初回holdout評価がありません。",
                )
            if holdout_evaluation["target_gate_status"] == "passed":
                raise CycleEvaluationError(
                    "state_cycle_after_target_passed",
                    "目標達成後に新しいholdout cycleを追加できません。",
                )
        validated_cycles.append(copy.deepcopy(dict(supplied_cycle)))
        effective_exclusion.update(identities)
    consume_extensions(len(cycles))
    if len(validated_extensions) != len(extensions):
        raise CycleEvaluationError(
            "state_exclusion_extension_order_invalid",
            "既知除外集合のextensionが存在しないcycle境界を参照しています。",
        )
    return copy.deepcopy(dict(value))


def _validated_legacy_state(value: Mapping[str, Any]) -> dict[str, Any]:
    """schema v1 stateをmigrationまたは最新cycle取消のためだけに検証する。"""

    _require_exact_keys(
        value,
        {"schema_version", "contract_version", "visibility", "target", "cycles", "state_semantic_sha256"},
        code="legacy_state_schema_invalid",
    )
    if (
        value.get("schema_version") != LEGACY_STATE_SCHEMA_VERSION
        or value.get("contract_version") != CONTRACT_VERSION
        or value.get("visibility") != VISIBILITY
        or value.get("target") != TARGET
    ):
        raise CycleEvaluationError(
            "legacy_state_contract_invalid",
            "migration対象のschema v1 state契約が一致しません。",
        )
    supplied_seal = _require_sha256(value.get("state_semantic_sha256"), code="legacy_state_seal_invalid")
    if supplied_seal != _canonical_sha256(_state_without_seal(value)):
        raise CycleEvaluationError(
            "legacy_state_seal_mismatch",
            "schema v1 stateの意味sealが一致しません。",
        )
    supplied_cycles = value.get("cycles")
    if not isinstance(supplied_cycles, list) or len(supplied_cycles) > MAXIMUM_HOLDOUT_CYCLES:
        raise CycleEvaluationError(
            "legacy_state_cycle_count_invalid",
            "schema v1 stateのcycle件数が不正です。",
        )
    seen: set[str] = set()
    validated: list[dict[str, Any]] = []
    for index, cycle in enumerate(supplied_cycles, start=1):
        if not isinstance(cycle, Mapping):
            raise CycleEvaluationError("legacy_state_cycle_schema_invalid", "schema v1 cycleが不正です。")
        _require_exact_keys(
            cycle,
            {"cycle_number", "selection", "registration", "holdout_evaluation", "development_reanalyses"},
            code="legacy_state_cycle_schema_invalid",
        )
        if cycle.get("cycle_number") != index:
            raise CycleEvaluationError("legacy_state_cycle_sequence_invalid", "schema v1 cycle番号が不正です。")
        selection = cycle.get("selection")
        registration = cycle.get("registration")
        if not isinstance(selection, Mapping) or not isinstance(registration, Mapping):
            raise CycleEvaluationError("legacy_state_registration_schema_invalid", "schema v1登録が不正です。")
        _require_exact_keys(
            selection,
            {"identity_type", "identity_count", "identities", "identity_set_sha256", "selection_commitment_sha256"},
            code="legacy_state_selection_schema_invalid",
        )
        identities = selection.get("identities")
        if (
            selection.get("identity_type") != "sha256"
            or selection.get("identity_count") != COHORT_SIZE
            or not isinstance(identities, list)
            or len(identities) != COHORT_SIZE
            or identities != sorted(identities)
            or len(set(identities)) != COHORT_SIZE
            or any(not _is_sha256(item) for item in identities)
            or seen.intersection(identities)
        ):
            raise CycleEvaluationError("legacy_state_selection_identity_invalid", "schema v1選定集合が不正です。")
        seen.update(identities)
        identity_set = _require_sha256(
            selection.get("identity_set_sha256"), code="legacy_state_identity_commitment_invalid"
        )
        selection_commitment = _require_sha256(
            selection.get("selection_commitment_sha256"), code="legacy_state_selection_commitment_invalid"
        )
        if identity_set != _identity_set_sha256(identities):
            raise CycleEvaluationError(
                "legacy_state_identity_commitment_mismatch",
                "schema v1 identity集合commitmentが一致しません。",
            )
        prefix = _seal_state(
            {
                "schema_version": LEGACY_STATE_SCHEMA_VERSION,
                "contract_version": CONTRACT_VERSION,
                "visibility": dict(VISIBILITY),
                "target": dict(TARGET),
                "cycles": copy.deepcopy(validated),
            }
        )
        _require_exact_keys(
            registration,
            {"kind", "counts_for_target_gate", "previous_state_semantic_sha256", "registration_commitment_sha256"},
            code="legacy_state_registration_schema_invalid",
        )
        previous = _require_sha256(
            registration.get("previous_state_semantic_sha256"), code="legacy_state_previous_commitment_invalid"
        )
        if (
            registration.get("kind") != "new_unused_holdout"
            or registration.get("counts_for_target_gate") is not True
            or previous != prefix["state_semantic_sha256"]
            or registration.get("registration_commitment_sha256")
            != _legacy_registration_commitment(
                cycle_number=index,
                selection_commitment_sha256=selection_commitment,
                identity_set_sha256=identity_set,
                previous_state_semantic_sha256=previous,
            )
        ):
            raise CycleEvaluationError(
                "legacy_state_registration_commitment_mismatch",
                "schema v1登録commitment chainが一致しません。",
            )
        holdout = cycle.get("holdout_evaluation")
        if holdout is not None:
            if not isinstance(holdout, Mapping):
                raise CycleEvaluationError("legacy_state_holdout_invalid", "schema v1 holdout評価が不正です。")
            _validate_summary_record(holdout, cycle_number=index, kind="holdout", ordinal=1)
        development = cycle.get("development_reanalyses")
        if not isinstance(development, list) or len(development) > MAXIMUM_DEVELOPMENT_REANALYSES_PER_CYCLE:
            raise CycleEvaluationError("legacy_state_development_invalid", "schema v1開発用評価が不正です。")
        if development and holdout is None:
            raise CycleEvaluationError(
                "legacy_state_development_before_holdout",
                "schema v1で初回holdout前の開発用評価は許可されません。",
            )
        for ordinal, record in enumerate(development, start=1):
            if not isinstance(record, Mapping):
                raise CycleEvaluationError("legacy_state_development_invalid", "schema v1開発用評価が不正です。")
            _validate_summary_record(record, cycle_number=index, kind="development_reanalysis", ordinal=ordinal)
        if index < len(supplied_cycles):
            if holdout is None:
                raise CycleEvaluationError(
                    "legacy_state_prior_cycle_unevaluated",
                    "schema v1の前cycleに初回holdout評価がありません。",
                )
            if holdout["target_gate_status"] == "passed":
                raise CycleEvaluationError(
                    "legacy_state_cycle_after_target_passed",
                    "schema v1で目標達成後のcycleを受理できません。",
                )
        validated.append(copy.deepcopy(dict(cycle)))
    return copy.deepcopy(dict(value))


def migrate_legacy_state(
    legacy_state: Mapping[str, Any],
    selections: Sequence[Mapping[str, Any]],
    baseline_identities: Sequence[str],
) -> dict[str, Any]:
    """exact baselineと各manifestを使い、schema v1をschema v2へ安全に移行する。"""

    legacy = _validated_legacy_state(legacy_state)
    if len(selections) != len(legacy["cycles"]):
        raise CycleEvaluationError(
            "migration_selection_manifest_count_mismatch",
            "migrationには保持する各cycleのselection manifestが1件ずつ必要です。",
        )
    migrated: dict[str, Any] | None = None
    for index, (legacy_cycle, selection) in enumerate(zip(legacy["cycles"], selections, strict=True), start=1):
        legacy_selection = legacy_cycle["selection"]
        if (
            set(selection["identities"]) != set(legacy_selection["identities"])
            or selection["identity_set_sha256"] != legacy_selection["identity_set_sha256"]
            or selection["selection_commitment_sha256"] != legacy_selection["selection_commitment_sha256"]
        ):
            raise CycleEvaluationError(
                "migration_selection_manifest_mismatch",
                "migration用manifestがschema v1のcycle選定と一致しません。",
            )
        migrated, changed = register_next_holdout(
            migrated,
            selection,
            baseline_identities=baseline_identities if index == 1 else None,
        )
        if not changed:
            raise CycleEvaluationError("migration_registration_failed", "schema v2 cycleを再構築できません。")
        holdout = copy.deepcopy(legacy_cycle["holdout_evaluation"])
        development = copy.deepcopy(legacy_cycle["development_reanalyses"])
        if holdout is not None:
            migrated_cycle = migrated["cycles"][-1]
            migrated_cycle["holdout_run_registration"] = {
                "kind": "legacy_evaluated_holdout",
                "input_commitment_sha256": holdout["input_commitment_sha256"],
                "evaluation_summary_sha256": holdout["evaluation_summary_sha256"],
                "migration_commitment_sha256": _canonical_sha256(
                    {
                        "domain": CONTRACT_VERSION,
                        "kind": "legacy_evaluated_holdout",
                        "cycle_number": index,
                        "input_commitment_sha256": holdout["input_commitment_sha256"],
                        "evaluation_summary_sha256": holdout["evaluation_summary_sha256"],
                    }
                ),
            }
            migrated_cycle["holdout_evaluation"] = holdout
            migrated_cycle["development_reanalyses"] = development
            migrated = _validated_state(_seal_state(migrated))
    if migrated is None:
        return _validated_state(_empty_state(baseline_identities))
    return migrated


def revoke_latest_unevaluated(
    state: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """最新の未評価cycleだけを取消し、識別子を含まない監査recordを返す。"""

    schema_version = state.get("schema_version")
    current = _validated_state(state) if schema_version == STATE_SCHEMA_VERSION else _validated_legacy_state(state)
    if not current["cycles"]:
        raise CycleEvaluationError("cycle_not_registered", "取消対象のcycleがありません。")
    latest = current["cycles"][-1]
    if latest["holdout_evaluation"] is not None:
        raise CycleEvaluationError(
            "latest_cycle_already_evaluated",
            "初回holdout評価済みcycleを取消できません。",
        )
    before = current["state_semantic_sha256"]
    updated = copy.deepcopy(current)
    removed = updated["cycles"].pop()
    if schema_version == STATE_SCHEMA_VERSION:
        for cycle in updated["cycles"]:
            if DEVELOPMENT_CHAIN_COUNT_FIELD not in cycle:
                continue
            if not _has_downstream_development_commitment(
                cycle_number=cycle["cycle_number"],
                cycles=updated["cycles"],
                extensions=updated["exclusion_extensions"],
            ):
                cycle.pop(DEVELOPMENT_CHAIN_COUNT_FIELD)
    updated = _seal_state(updated)
    if schema_version == STATE_SCHEMA_VERSION:
        updated = _validated_state(updated)
    else:
        updated = _validated_legacy_state(updated)
    run_registration = removed.get("holdout_run_registration")
    audit = {
        "schema_version": 1,
        "contract_version": CONTRACT_VERSION,
        "kind": "latest_unevaluated_holdout_revocation",
        "cancelled_cycle_number": removed["cycle_number"],
        "selection_commitment_sha256": removed["selection"]["selection_commitment_sha256"],
        "identity_set_sha256": removed["selection"]["identity_set_sha256"],
        "registration_commitment_sha256": removed["registration"]["registration_commitment_sha256"],
        "holdout_run_was_pre_registered": run_registration is not None,
        "holdout_run_registration_commitment_sha256": (
            run_registration.get("registration_commitment_sha256") if isinstance(run_registration, Mapping) else None
        ),
        "before_state_semantic_sha256": before,
        "after_state_semantic_sha256": updated["state_semantic_sha256"],
        "sample_identifiers_included": False,
    }
    audit["revocation_semantic_sha256"] = _canonical_sha256(audit)
    return updated, audit


def _effective_exclusion_identities(state: Mapping[str, Any]) -> set[str]:
    """baseline、extension、公式cycleを合わせた現在の既知集合を返す。"""

    identities = set(state["baseline_exclusion"]["identities"])
    for extension in state["exclusion_extensions"]:
        identities.update(extension["added_identities"])
    for cycle in state["cycles"]:
        identities.update(cycle["selection"]["identities"])
    return identities


def extend_exclusions(
    state: Mapping[str, Any],
    effective_identities: Sequence[str],
) -> tuple[dict[str, Any], dict[str, Any], bool]:
    """次cycle前に既知集合をexact hash-listから単調拡張する。"""

    current = _validated_state(state)
    supplied = sorted(effective_identities)
    if len(supplied) != len(set(supplied)) or any(not _is_sha256(identity) for identity in supplied):
        raise CycleEvaluationError(
            "exclusion_extension_identity_set_invalid",
            "拡張用の既知集合は重複のないSHA-256集合である必要があります。",
        )
    if current["cycles"]:
        latest_evaluation = current["cycles"][-1]["holdout_evaluation"]
        if latest_evaluation is None:
            raise CycleEvaluationError(
                "exclusion_extension_pending_cycle",
                "未評価cycleを取消または評価するまで既知集合を拡張できません。",
            )
        if latest_evaluation["target_gate_status"] == "passed":
            raise CycleEvaluationError(
                "exclusion_extension_target_already_met",
                "目標達成後に次cycle用の既知集合を拡張できません。",
            )

    existing = _effective_exclusion_identities(current)
    supplied_set = set(supplied)
    if not existing.issubset(supplied_set):
        raise CycleEvaluationError(
            "exclusion_extension_not_monotonic",
            "拡張用の既知集合から既存baseline、extension、公式cycleを削除できません。",
        )
    added = sorted(supplied_set.difference(existing))
    before = current["state_semantic_sha256"]
    if not added:
        audit = {
            "schema_version": 1,
            "contract_version": CONTRACT_VERSION,
            "kind": "monotonic_known_exclusion_extension_audit",
            "status": "already_current",
            "extension_number": len(current["exclusion_extensions"]),
            "after_cycle_count": len(current["cycles"]),
            "added_identity_count": 0,
            "effective_identity_count": len(existing),
            "effective_identities_sha256": _exclusion_set_sha256(sorted(existing)),
            "extension_commitment_sha256": None,
            "before_state_semantic_sha256": before,
            "after_state_semantic_sha256": before,
            "sample_identifiers_included": False,
        }
        audit["audit_semantic_sha256"] = _canonical_sha256(audit)
        return current, audit, False

    extension_number = len(current["exclusion_extensions"]) + 1
    after_cycle_count = len(current["cycles"])
    effective_digest = _exclusion_set_sha256(supplied)
    added_digest = _exclusion_set_sha256(added)
    chain_previous_state = _chain_state_semantic_sha256(current)
    extension_commitment = _exclusion_extension_commitment(
        extension_number=extension_number,
        after_cycle_count=after_cycle_count,
        added_identity_count=len(added),
        added_identities_sha256=added_digest,
        effective_identity_count=len(supplied),
        effective_identities_sha256=effective_digest,
        previous_state_semantic_sha256=chain_previous_state,
    )
    updated = copy.deepcopy(current)
    updated["exclusion_extensions"].append(
        {
            "extension_number": extension_number,
            "kind": "monotonic_known_exclusion_extension",
            "after_cycle_count": after_cycle_count,
            "added_identity_count": len(added),
            "added_identities": added,
            "added_identities_sha256": added_digest,
            "effective_identity_count": len(supplied),
            "effective_identities": supplied,
            "effective_identities_sha256": effective_digest,
            "previous_state_semantic_sha256": chain_previous_state,
            "extension_commitment_sha256": extension_commitment,
        }
    )
    updated = _validated_state(_seal_state(updated))
    audit = {
        "schema_version": 1,
        "contract_version": CONTRACT_VERSION,
        "kind": "monotonic_known_exclusion_extension_audit",
        "status": "extended",
        "extension_number": extension_number,
        "after_cycle_count": after_cycle_count,
        "added_identity_count": len(added),
        "effective_identity_count": len(supplied),
        "effective_identities_sha256": effective_digest,
        "extension_commitment_sha256": extension_commitment,
        "before_state_semantic_sha256": before,
        "after_state_semantic_sha256": updated["state_semantic_sha256"],
        "sample_identifiers_included": False,
    }
    audit["audit_semantic_sha256"] = _canonical_sha256(audit)
    return updated, audit, True


def load_state(path: Path) -> dict[str, Any]:
    """repository外のprivate cycle stateを検証して返す。"""

    _validate_private_state_path(path)
    value, _raw = _read_json_object(path, error_prefix="cycle_state")
    return _validated_state(value)


def _write_state(path: Path, value: Mapping[str, Any]) -> None:
    resolved = _validate_private_state_path(path)
    validated = _validated_state(value)
    encoded = (
        json.dumps(
            validated,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
            allow_nan=False,
        )
        + "\n"
    )
    if len(encoded.encode("utf-8")) > MAXIMUM_STATE_BYTES:
        raise CycleEvaluationError(
            "state_size_limit",
            "private stateがsize上限を超えています。",
        )
    try:
        corpus._atomic_write_text(resolved, encoded)
    except corpus.CorpusSummaryError as exc:
        raise CycleEvaluationError(
            "state_write_failed",
            "private stateを安全に保存できません。",
        ) from exc


def register_next_holdout(
    state: Mapping[str, Any] | None,
    selection: Mapping[str, Any],
    *,
    baseline_identities: Sequence[str] | None = None,
) -> tuple[dict[str, Any], bool]:
    """未使用20件を次のholdout cycleへ事前登録する。"""

    if state is None:
        if baseline_identities is None:
            raise CycleEvaluationError(
                "baseline_manifest_required",
                "cycle 1登録にはexactなprivate baseline除外集合が必要です。",
            )
        current = _validated_state(_empty_state(baseline_identities))
    else:
        current = _validated_state(state)
        if baseline_identities is not None and _baseline_record(baseline_identities) != current["baseline_exclusion"]:
            raise CycleEvaluationError(
                "baseline_manifest_state_mismatch",
                "指定baselineがprivate stateへ封印済みの集合と一致しません。",
            )
    identities = tuple(selection["identities"])
    cycles = current["cycles"]
    if cycles:
        latest = cycles[-1]
        latest_selection = latest["selection"]
        if (
            latest_selection["identity_set_sha256"] == selection["identity_set_sha256"]
            and latest_selection["selection_commitment_sha256"] == selection["selection_commitment_sha256"]
        ):
            if (
                latest_selection["exclusion_extension_count"] != len(current["exclusion_extensions"])
                or latest_selection["excluded_hashes"] != selection.get("excluded_hashes")
                or latest_selection["excluded_hashes_sha256"] != selection.get("excluded_hashes_sha256")
            ):
                raise CycleEvaluationError(
                    "selection_registration_exclusion_mismatch",
                    "同じ選定commitmentの除外集合契約が登録済みstateと一致しません。",
                )
            if latest["holdout_evaluation"] is None:
                return current, False
            raise CycleEvaluationError(
                "selection_already_evaluated",
                "評価済み集合を新しいholdout cycleとして再登録できません。",
            )
        initial = latest["holdout_evaluation"]
        if initial is None:
            raise CycleEvaluationError(
                "previous_cycle_not_evaluated",
                "次cycleの前に現在cycleの初回holdout評価を完了してください。",
            )
        if initial["target_gate_status"] == "passed":
            raise CycleEvaluationError(
                "target_already_met",
                "目標達成後に追加cycleを開始できません。",
            )
    if len(cycles) >= MAXIMUM_HOLDOUT_CYCLES:
        raise CycleEvaluationError(
            "maximum_cycles_reached",
            "holdout cycleの上限5回に到達しています。",
        )
    expected_exclusion = _effective_exclusion_identities(current)
    if expected_exclusion.intersection(identities):
        raise CycleEvaluationError(
            "holdout_identity_in_required_exclusion",
            "次cycleにはbaselineと過去cycleの累積除外に含まれないSHA-256だけを指定してください。",
        )
    if selection.get("excluded_hashes") != len(expected_exclusion) or selection.get(
        "excluded_hashes_sha256"
    ) != _exclusion_set_sha256(sorted(expected_exclusion)):
        raise CycleEvaluationError(
            "selection_cumulative_exclusion_mismatch",
            "selection manifestの除外集合がbaselineと過去全cycleの累積集合に一致しません。",
        )

    updated = copy.deepcopy(current)
    cycle_number = len(cycles) + 1
    previous_state = _chain_state_semantic_sha256(current)
    identity_set = str(selection["identity_set_sha256"])
    selection_commitment = str(selection["selection_commitment_sha256"])
    updated["cycles"].append(
        {
            "cycle_number": cycle_number,
            "selection": {
                "identity_type": "sha256",
                "identity_count": COHORT_SIZE,
                "identities": sorted(identities),
                "identity_set_sha256": identity_set,
                "selection_commitment_sha256": selection_commitment,
                "exclusion_extension_count": len(current["exclusion_extensions"]),
                "excluded_hashes": int(selection["excluded_hashes"]),
                "excluded_hashes_sha256": str(selection["excluded_hashes_sha256"]),
            },
            "registration": {
                "kind": "new_unused_holdout",
                "counts_for_target_gate": True,
                "previous_state_semantic_sha256": previous_state,
                "registration_commitment_sha256": _registration_commitment(
                    cycle_number=cycle_number,
                    selection_commitment_sha256=selection_commitment,
                    identity_set_sha256=identity_set,
                    exclusion_extension_count=len(current["exclusion_extensions"]),
                    excluded_hashes=int(selection["excluded_hashes"]),
                    excluded_hashes_sha256=str(selection["excluded_hashes_sha256"]),
                    previous_state_semantic_sha256=previous_state,
                ),
            },
            "holdout_run_registration": None,
            "holdout_evaluation": None,
            "development_reanalyses": [],
        }
    )
    return _validated_state(_seal_state(updated)), True


def pre_register_holdout_run(
    state: Mapping[str, Any],
    run_paths: Sequence[Path],
) -> tuple[dict[str, Any], bool]:
    """初回holdout解析の出力rootと解析コードを実行前に封印する。"""

    current = _validated_state(state)
    if not current["cycles"]:
        raise CycleEvaluationError(
            "cycle_not_registered",
            "初回holdout runの前にcycleを登録してください。",
        )
    if not run_paths:
        raise CycleEvaluationError(
            "holdout_run_path_required",
            "初回holdoutの出力rootを1件以上指定してください。",
        )
    cycle = current["cycles"][-1]
    if cycle["holdout_evaluation"] is not None:
        raise CycleEvaluationError(
            "holdout_already_evaluated",
            "評価済みcycleへ初回holdout runを再登録できません。",
        )
    for path in run_paths:
        resolved = _validate_private_artifact_path(path, code="holdout_run_inside_repository")
        if cycle["holdout_run_registration"] is None and resolved.exists():
            raise CycleEvaluationError(
                "holdout_run_path_already_exists",
                "初回holdoutは未作成の新しい出力rootへ事前登録してください。",
            )
    path_set = _run_path_set_sha256(run_paths)
    code_tree = _analysis_code_tree_sha256()
    existing = cycle["holdout_run_registration"]
    if existing is not None:
        if (
            existing.get("kind") == "first_holdout_run_precommitment"
            and existing.get("run_path_count") == len(run_paths)
            and existing.get("run_path_set_sha256") == path_set
            and existing.get("analysis_code_tree_sha256") == code_tree
        ):
            return current, False
        raise CycleEvaluationError(
            "holdout_run_already_registered",
            "初回holdout runのpathまたは解析コードcommitmentを変更できません。",
        )
    previous = _chain_state_semantic_sha256(current)
    record = {
        "kind": "first_holdout_run_precommitment",
        "run_path_count": len(run_paths),
        "run_path_set_sha256": path_set,
        "analysis_code_tree_sha256": code_tree,
        "previous_state_semantic_sha256": previous,
        "registration_commitment_sha256": _holdout_run_registration_commitment(
            cycle_number=cycle["cycle_number"],
            run_path_count=len(run_paths),
            run_path_set_sha256=path_set,
            analysis_code_tree_sha256=code_tree,
            previous_state_semantic_sha256=previous,
        ),
    }
    updated = copy.deepcopy(current)
    updated["cycles"][-1]["holdout_run_registration"] = record
    return _validated_state(_seal_state(updated)), True


def _verify_holdout_run_precommitment(
    cycle: Mapping[str, Any],
    run_paths: Sequence[Path],
) -> None:
    registration = cycle.get("holdout_run_registration")
    if not isinstance(registration, Mapping):
        raise CycleEvaluationError(
            "holdout_run_not_pre_registered",
            "初回holdout評価には解析前のrun登録が必要です。",
        )
    if registration.get("kind") == "legacy_evaluated_holdout":
        if cycle.get("holdout_evaluation") is None:
            raise CycleEvaluationError(
                "legacy_holdout_not_evaluated",
                "legacy run登録を未評価holdoutへ使用できません。",
            )
        return
    if (
        registration.get("kind") != "first_holdout_run_precommitment"
        or registration.get("run_path_count") != len(run_paths)
        or registration.get("run_path_set_sha256") != _run_path_set_sha256(run_paths)
    ):
        raise CycleEvaluationError(
            "holdout_run_precommitment_mismatch",
            "評価対象run pathが解析前commitmentと一致しません。",
        )
    if registration.get("analysis_code_tree_sha256") != _analysis_code_tree_sha256():
        raise CycleEvaluationError(
            "holdout_analysis_code_changed",
            "初回holdout登録後に解析コードtreeが変更されています。",
        )


def _rate(numerator: int) -> dict[str, Any]:
    value = strict_holdout._rate(numerator, COHORT_SIZE)
    value["denominator_basis"] = "pre_registered_cycle_selection"
    return value


def _selection_matches_cycle(
    cycle: Mapping[str, Any],
    completed_selection: Mapping[str, Any],
) -> bool:
    """取得完了selectionが登録済みcycleと完全一致するかを返す。"""

    completed_identities = completed_selection.get("identities")
    if (
        not isinstance(completed_identities, (list, tuple))
        or len(completed_identities) != COHORT_SIZE
        or any(not _is_sha256(item) for item in completed_identities)
        or len(set(completed_identities)) != COHORT_SIZE
    ):
        return False
    selection = cycle["selection"]
    normalized_identities = sorted(str(item) for item in completed_identities)
    return (
        selection["identities"] == normalized_identities
        and selection["identity_set_sha256"] == completed_selection.get("identity_set_sha256")
        and completed_selection.get("identity_set_sha256") == _identity_set_sha256(normalized_identities)
        and selection["selection_commitment_sha256"] == completed_selection.get("selection_commitment_sha256")
        and selection["excluded_hashes"] == completed_selection.get("excluded_hashes")
        and selection["excluded_hashes_sha256"] == completed_selection.get("excluded_hashes_sha256")
    )


def _resolve_evaluation_cycle(
    state: Mapping[str, Any],
    *,
    evaluation_kind: str,
    completed_selection: Mapping[str, Any],
) -> tuple[int, Mapping[str, Any]]:
    """評価kindとselectionから対象cycleを一意かつfail-closedに解決する。"""

    cycles = state["cycles"]
    if evaluation_kind == "holdout":
        latest_index = len(cycles) - 1
        latest = cycles[latest_index]
        if not _selection_matches_cycle(latest, completed_selection):
            raise CycleEvaluationError(
                "selection_registration_mismatch",
                "holdout評価manifestが最新cycleの事前登録と一致しません。",
            )
        return latest_index, latest

    matches = [
        (index, cycle) for index, cycle in enumerate(cycles) if _selection_matches_cycle(cycle, completed_selection)
    ]
    if not matches:
        raise CycleEvaluationError(
            "selection_registration_mismatch",
            "開発用評価manifestが登録済みcycleの事前登録と一致しません。",
        )
    if len(matches) != 1:
        raise CycleEvaluationError(
            "selection_registration_ambiguous",
            "開発用評価manifestに一致するcycleを一意に解決できません。",
        )
    cycle_index, cycle = matches[0]
    if cycle["holdout_evaluation"] is None:
        raise CycleEvaluationError(
            "development_before_holdout",
            "未評価cycleまたは将来cycleを開発用再解析の対象にできません。",
        )
    return cycle_index, cycle


def _public_summary(
    *,
    cycle: Mapping[str, Any],
    evaluation_kind: str,
    selected_cases: Sequence[Any],
    corpus_summary: Mapping[str, Any],
    missing_count: int,
    out_of_scope_count: int,
    input_commitment_sha256: str,
    completed_manifest_semantic_sha256: str,
) -> dict[str, Any]:
    family_count = sum(item.family_confirmed for item in selected_cases)
    c2_count = sum(item.c2_config_confirmed for item in selected_cases)
    joint_count = sum(item.family_confirmed and item.c2_config_confirmed for item in selected_cases)
    categories = Counter(strict_holdout._case_failure_category_counts(selected_cases))
    categories["analysis_incomplete_or_limit"] += missing_count
    failure_count = sum(categories.values())
    if failure_count != COHORT_SIZE - joint_count:
        raise CycleEvaluationError(
            "failure_category_accounting_mismatch",
            "20件の成功・失敗分類が分母と一致しません。",
        )
    reasons = Counter(strict_holdout._case_failure_reason_counts(selected_cases))
    if missing_count:
        reasons["selected_case_missing_from_sealed_run"] += missing_count

    counts = corpus_summary.get("counts")
    if not isinstance(counts, Mapping):
        raise CycleEvaluationError(
            "sealed_corpus_counts_invalid",
            "封印済みコーパスの件数契約が不正です。",
        )
    required_count_fields = (
        "batch_errors",
        "invalid_unique_cases",
        "conflicting_case_sha256",
    )
    if any(type(counts.get(field)) is not int or counts[field] < 0 for field in required_count_fields):
        raise CycleEvaluationError(
            "sealed_corpus_counts_invalid",
            "封印済みコーパスの件数契約が不正です。",
        )
    input_integrity_clean = (
        missing_count == 0
        and counts["batch_errors"] == 0
        and counts["invalid_unique_cases"] == 0
        and counts["conflicting_case_sha256"] == 0
    )
    diagnostic_threshold_met = joint_count >= REQUIRED_JOINT_SUCCESSES and input_integrity_clean
    eligible = evaluation_kind == "holdout"
    if eligible:
        gate_status = "passed" if diagnostic_threshold_met else "failed"
        reason_codes = []
        if missing_count:
            reason_codes.append("selected_case_missing_from_sealed_run")
        if not input_integrity_clean:
            reason_codes.append("input_integrity_not_clean")
        if joint_count < REQUIRED_JOINT_SUCCESSES:
            reason_codes.append("joint_success_target_not_met")
        if gate_status == "passed":
            next_action = "stop_target_met"
        elif cycle["cycle_number"] >= MAXIMUM_HOLDOUT_CYCLES:
            next_action = "maximum_cycles_exhausted"
        else:
            next_action = "analyze_failures_then_register_unused_holdout"
    else:
        gate_status = "not_applicable_development_reanalysis"
        reason_codes = ["development_reanalysis_not_eligible_for_target_gate"]
        next_action = "continue_development_then_use_unused_holdout"

    summary: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "contract_version": CONTRACT_VERSION,
        "evaluation_mode": "offline_sealed_valleyrat_twenty_case_cycle",
        "evaluation_kind": evaluation_kind,
        "cycle": {
            "cycle_number": cycle["cycle_number"],
            "maximum_holdout_cycles": MAXIMUM_HOLDOUT_CYCLES,
            "cohort_size": COHORT_SIZE,
            "counts_for_target_gate": eligible,
            "registration_commitment_sha256": cycle["registration"]["registration_commitment_sha256"],
            "selection_commitment_verified": True,
            "completed_download_manifest_verified": True,
            "completed_download_manifest_semantic_sha256": completed_manifest_semantic_sha256,
            "identity_disjoint_from_prior_cycles": True,
            "exact_baseline_exclusion_sealed": True,
            "cumulative_exclusion_verified": True,
            "holdout_run_registration_kind": cycle["holdout_run_registration"]["kind"],
            "holdout_run_path_and_code_commitment_verified": (
                evaluation_kind == "holdout"
                and cycle["holdout_run_registration"]["kind"] == "first_holdout_run_precommitment"
            ),
        },
        "target": dict(TARGET),
        "input": {
            "pre_registered_cases": COHORT_SIZE,
            "matched_sealed_cases": len(selected_cases),
            "missing_selected_cases": missing_count,
            "out_of_scope_sealed_cases": out_of_scope_count,
            "batch_errors": counts["batch_errors"],
            "invalid_unique_cases": counts["invalid_unique_cases"],
            "conflicting_case_records": counts["conflicting_case_sha256"],
            "input_integrity_clean": input_integrity_clean,
            "input_commitment_sha256": input_commitment_sha256,
            "pins": strict_holdout._input_pin_summary(selected_cases),
        },
        "success_contract": {
            "joint_condition": "family_confirmed_and_c2_config_confirmed",
            "family": {
                "target": TARGET_FAMILY,
                "allowed_evidence_sources": sorted(strict_holdout.ALLOWED_FAMILY_SOURCES),
                "sample_identity_only_accepted": False,
                "external_family_hint_accepted": False,
                "known_hash_family_evidence_accepted": False,
                "unique_corroborated_candidate_required": True,
            },
            "c2_config": {
                "confirmed_config_required": True,
                "static_config_correlation_required": True,
                "control_role_required": True,
                "candidate_only_accepted": False,
            },
            "provider_archive": {
                "encryption_scheme_required": PROVIDER_ARCHIVE_ENCRYPTION_SCHEME,
                "aes_strength_bits_required": PROVIDER_ARCHIVE_AES_STRENGTH_BITS,
                "member_sha256_must_match_selection": True,
            },
            "development_reanalysis": {
                "same_cohort_allowed": True,
                "counts_for_target_gate": False,
                "next_holdout_requires_unused_identities": True,
            },
            "holdout_precommitment": {
                "run_paths_registered_before_output_exists": True,
                "analysis_code_tree_must_match_for_initial_evaluation": True,
                "legacy_evaluated_holdout_may_only_preserve_existing_record": True,
            },
        },
        "metrics": {
            "family_confirmed_without_disallowed_hints": _rate(family_count),
            "c2_config_confirmed": _rate(c2_count),
            "joint_success": _rate(joint_count),
        },
        "failure_reason_counts": dict(sorted(reasons.items())),
        "failure_category_counts": {
            category: categories.get(category, 0) for category in strict_holdout.FAILURE_CATEGORIES
        },
        "failure_category_contract": {
            "mutually_exclusive": True,
            "successful_cases_have_no_failure_category": True,
            "categories": list(strict_holdout.FAILURE_CATEGORIES),
            "all_pre_registered_cases_accounted": True,
        },
        "target_gate": {
            "status": gate_status,
            "eligible_evaluation": eligible,
            "diagnostic_threshold_met": diagnostic_threshold_met,
            "observed_joint_successes": joint_count,
            "required_joint_successes": REQUIRED_JOINT_SUCCESSES,
            "reason_codes": reason_codes,
        },
        "state_transition": {
            "next_action": next_action,
            "new_holdout_allowed": (
                eligible and gate_status == "failed" and cycle["cycle_number"] < MAXIMUM_HOLDOUT_CYCLES
            ),
            "maximum_cycles_reached": cycle["cycle_number"] >= MAXIMUM_HOLDOUT_CYCLES,
        },
        "safety": {
            "samples_opened_by_evaluator": False,
            "samples_executed": False,
            "network_contacted": False,
            "subprocess_started": False,
            "ai_used": False,
            "matched_sealed_report_safety_flags_verified": True,
            "sealed_report_safety_flags_verified": missing_count == 0,
            "archive_encryption_and_member_identity_verified": True,
            "provider_archive_encryption_scheme": PROVIDER_ARCHIVE_ENCRYPTION_SCHEME,
            "provider_archive_aes_strength_bits": PROVIDER_ARCHIVE_AES_STRENGTH_BITS,
            "provider_download_network_out_of_scope": True,
            "case_identifiers_included": False,
            "raw_config_included": False,
            "network_values_included": False,
            "source_names_included": False,
            "private_paths_included": False,
            "private_state_contains_sample_sha256": True,
            "private_state_publishable": False,
        },
    }
    summary["evaluation_summary_sha256"] = _canonical_sha256(summary)
    return summary


def evaluate_current_cycle(
    state: Mapping[str, Any],
    run_paths: Sequence[Path],
    *,
    evaluation_kind: str,
    completed_selection: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], bool]:
    """holdoutは最新、開発用再解析はselection一致cycleを評価する。"""

    if evaluation_kind not in EVALUATION_KINDS:
        raise CycleEvaluationError(
            "evaluation_kind_invalid",
            "評価種別はholdoutまたはdevelopment_reanalysisです。",
        )
    current = _validated_state(state)
    if not current["cycles"]:
        raise CycleEvaluationError(
            "cycle_not_registered",
            "評価前に20件のholdoutを事前登録してください。",
        )
    if (
        completed_selection.get("download_contract_verified") is not True
        or completed_selection.get("archive_encryption_and_member_identity_verified") is not True
        or not _is_sha256(completed_selection.get("manifest_semantic_sha256"))
    ):
        raise CycleEvaluationError(
            "completed_selection_not_verified",
            "取得完了manifestの暗号化archive契約が検証されていません。",
        )
    cycle_index, cycle = _resolve_evaluation_cycle(
        current,
        evaluation_kind=evaluation_kind,
        completed_selection=completed_selection,
    )
    if evaluation_kind == "holdout":
        _verify_holdout_run_precommitment(cycle, run_paths)
    try:
        all_cases, corpus_summary = strict_holdout._collect_case_evidence(run_paths)
    except strict_holdout.HoldoutEvaluationError as exc:
        raise CycleEvaluationError(
            f"sealed_holdout_{exc.code}",
            "封印済みone-shot成果物の厳格評価に失敗しました。",
        ) from exc
    input_commitment_document = corpus_summary.get("input_commitment")
    if not isinstance(input_commitment_document, Mapping) or not _is_sha256(
        input_commitment_document.get("aggregate_sha256")
    ):
        raise CycleEvaluationError(
            "sealed_corpus_commitment_invalid",
            "封印済みコーパスの入力commitmentが不正です。",
        )
    input_commitment = _canonical_sha256(input_commitment_document)
    selected_identities = set(cycle["selection"]["identities"])
    selected_cases = [item for item in all_cases if item.digest in selected_identities]
    observed = {item.digest for item in selected_cases}
    missing_count = len(selected_identities - observed)
    out_of_scope_count = len(all_cases) - len(selected_cases)
    summary = _public_summary(
        cycle=cycle,
        evaluation_kind=evaluation_kind,
        selected_cases=selected_cases,
        corpus_summary=corpus_summary,
        missing_count=missing_count,
        out_of_scope_count=out_of_scope_count,
        input_commitment_sha256=input_commitment,
        completed_manifest_semantic_sha256=str(completed_selection["manifest_semantic_sha256"]),
    )
    record = {
        "kind": evaluation_kind,
        "ordinal": (1 if evaluation_kind == "holdout" else len(cycle["development_reanalyses"]) + 1),
        "counts_for_target_gate": evaluation_kind == "holdout",
        "input_commitment_sha256": input_commitment,
        "evaluation_summary_sha256": summary["evaluation_summary_sha256"],
        "observed_joint_successes": summary["metrics"]["joint_success"]["numerator"],
        "input_integrity_clean": summary["input"]["input_integrity_clean"],
        "target_gate_status": summary["target_gate"]["status"],
    }

    if evaluation_kind == "holdout":
        previous = cycle["holdout_evaluation"]
        if previous is not None:
            if (
                previous["input_commitment_sha256"] == input_commitment
                and previous["evaluation_summary_sha256"] == summary["evaluation_summary_sha256"]
            ):
                return current, summary, False
            raise CycleEvaluationError(
                "holdout_already_evaluated",
                "初回holdout結果を別成果物で上書きできません。",
            )
    else:
        for previous in cycle["development_reanalyses"]:
            if previous["input_commitment_sha256"] != input_commitment:
                continue
            if previous["evaluation_summary_sha256"] == summary["evaluation_summary_sha256"]:
                return current, summary, False
            raise CycleEvaluationError(
                "development_result_commitment_changed",
                "同じ開発用成果物の評価結果commitmentが変化しました。",
            )
        if len(cycle["development_reanalyses"]) >= MAXIMUM_DEVELOPMENT_REANALYSES_PER_CYCLE:
            raise CycleEvaluationError(
                "development_reanalysis_limit_reached",
                "一cycleの開発用再解析record上限に到達しました。",
            )

    updated = copy.deepcopy(current)
    target = updated["cycles"][cycle_index]
    if evaluation_kind == "holdout":
        target["holdout_evaluation"] = record
    else:
        has_downstream_commitment = cycle_index < len(updated["cycles"]) - 1 or any(
            extension["after_cycle_count"] >= cycle["cycle_number"] for extension in updated["exclusion_extensions"]
        )
        if has_downstream_commitment and DEVELOPMENT_CHAIN_COUNT_FIELD not in target:
            target[DEVELOPMENT_CHAIN_COUNT_FIELD] = len(target["development_reanalyses"])
        target["development_reanalyses"].append(record)
    return _validated_state(_seal_state(updated)), summary, True


def render_markdown(summary: Mapping[str, Any]) -> str:
    """公開可能なcycle評価JSONを日本語Markdownへ変換する。"""

    if summary.get("schema_version") != SCHEMA_VERSION or summary.get("contract_version") != CONTRACT_VERSION:
        raise CycleEvaluationError(
            "render_schema_invalid",
            "cycle評価summaryのschemaを表示できません。",
        )
    metrics = summary["metrics"]

    def rate_text(value: Mapping[str, Any]) -> str:
        return f"{value['numerator']}/{value['denominator']} ({value['percentage']:.2f}%)"

    gate = summary["target_gate"]
    kind_ja = "未使用holdout" if summary["evaluation_kind"] == "holdout" else "開発用再解析"
    lines = [
        "# ValleyRAT 20件cycle自動解析評価",
        "",
        "## 結論",
        "",
        (f"cycle {summary['cycle']['cycle_number']}の{kind_ja}を、封印済みone-shot成果物だけで評価しました。"),
        (f"family確定と静的C2設定確定の同時成功は{rate_text(metrics['joint_success'])}です。"),
        (
            "この結果は目標判定に使用します。"
            if gate["eligible_evaluation"]
            else "同じ検体の再解析であるため、目標判定には使用しません。"
        ),
        "",
        "## 指標",
        "",
        "| 指標 | 結果 |",
        "|---|---:|",
        (f"| family確定 | {rate_text(metrics['family_confirmed_without_disallowed_hints'])} |"),
        f"| 静的C2設定確定 | {rate_text(metrics['c2_config_confirmed'])} |",
        f"| 同時成功 | {rate_text(metrics['joint_success'])} |",
        "",
        "## 目標gate",
        "",
        f"- 状態: `{gate['status']}`",
        f"- 必要件数: {gate['required_joint_successes']}/{COHORT_SIZE}",
        f"- 次の処理: `{summary['state_transition']['next_action']}`",
        "",
        "## 主失敗分類",
        "",
        "| 分類 | 件数 |",
        "|---|---:|",
    ]
    lines.extend(
        f"| `{category}` | {summary['failure_category_counts'][category]} |"
        for category in strict_holdout.FAILURE_CATEGORIES
    )
    lines.extend(
        [
            "",
            "## 安全境界",
            "",
            "- 評価器は検体、archive、復元payloadを開いていません。",
            "- 検体を実行せず、外部通信とsubprocess起動を行っていません。",
            "- 公開結果に検体SHA-256、C2値、source名、private pathを含めていません。",
            "- sample SHA-256を含むcycle stateはprivateであり、公開できません。",
            "",
        ]
    )
    return "\n".join(lines)


def _write_public_output(path: Path, content: str) -> None:
    try:
        corpus._atomic_write_text(path, content)
    except corpus.CorpusSummaryError as exc:
        raise CycleEvaluationError(
            "public_output_write_failed",
            "公開評価出力を安全に保存できません。",
        ) from exc


def build_parser() -> argparse.ArgumentParser:
    """20件cycleの事前登録・評価CLIを構築する。"""

    parser = JapaneseArgumentParser(description=__doc__, add_help=False)
    parser.add_argument("-h", "--help", action="help", help="このヘルプを表示して終了します")
    subparsers = parser.add_subparsers(dest="command", required=True)

    register = subparsers.add_parser(
        "register",
        help="解析前の未使用20件を次holdoutへ登録します。",
        add_help=False,
    )
    register.add_argument("-h", "--help", action="help", help="このヘルプを表示して終了します")
    register.add_argument("--state", required=True, type=Path, help="repository外のprivate cycle state JSON")
    register.add_argument(
        "--selection-manifest",
        required=True,
        type=Path,
        help="ValleyRATのselection-only取得manifest",
    )
    register.add_argument(
        "--baseline-manifest",
        action="append",
        default=[],
        type=Path,
        help="cycle 1以前に使用した検体を含むprivate manifestまたはhash-list。繰返し指定できます。",
    )

    start = subparsers.add_parser(
        "start-holdout",
        help="未作成の初回holdout出力rootと解析コードtreeを解析前に封印します。",
        add_help=False,
    )
    start.add_argument("-h", "--help", action="help", help="このヘルプを表示して終了します")
    start.add_argument("--state", required=True, type=Path, help="repository外のprivate cycle state JSON")
    start.add_argument(
        "--run",
        required=True,
        action="append",
        type=Path,
        help="未作成のanalyze_sample.py出力root。繰返し指定できます。",
    )

    migrate = subparsers.add_parser(
        "migrate-state",
        help="schema v1 stateをexact baseline付きschema v2へ移行します。",
        add_help=False,
    )
    migrate.add_argument("-h", "--help", action="help", help="このヘルプを表示して終了します")
    migrate.add_argument("--state", required=True, type=Path, help="repository外の既存private cycle state JSON")
    migrate.add_argument(
        "--selection-manifest",
        required=True,
        action="append",
        type=Path,
        help="保持する各cycleのselection manifest。cycle順に繰返し指定します。",
    )
    migrate.add_argument(
        "--baseline-manifest",
        required=True,
        action="append",
        type=Path,
        help="cycle 1以前に使用した検体を含むprivate manifestまたはhash-list。",
    )

    revoke = subparsers.add_parser(
        "revoke-latest",
        help="最新の未評価holdout登録だけを監査record付きで取消します。",
        add_help=False,
    )
    revoke.add_argument("-h", "--help", action="help", help="このヘルプを表示して終了します")
    revoke.add_argument("--state", required=True, type=Path, help="repository外のprivate cycle state JSON")
    revoke.add_argument(
        "--audit-output",
        required=True,
        type=Path,
        help="repository外へ保存する取消監査JSON",
    )

    extend = subparsers.add_parser(
        "extend-exclusions",
        help="次cycle前にprivate exact既知集合を単調追加し、監査recordを保存します。",
        add_help=False,
    )
    extend.add_argument("-h", "--help", action="help", help="このヘルプを表示して終了します")
    extend.add_argument("--state", required=True, type=Path, help="repository外のprivate cycle state JSON")
    extend.add_argument(
        "--exclusion-manifest",
        required=True,
        action="append",
        type=Path,
        help="現在の全既知検体を含むprivate manifestまたはhash-list。繰返し指定できます。",
    )
    extend.add_argument(
        "--audit-output",
        required=True,
        type=Path,
        help="repository外へ保存する識別子非包含の拡張監査JSON",
    )

    evaluate = subparsers.add_parser(
        "evaluate",
        help="封印済みone-shot成果物を登録済みcycleへ評価します。",
        add_help=False,
    )
    evaluate.add_argument("-h", "--help", action="help", help="このヘルプを表示して終了します")
    evaluate.add_argument("--state", required=True, type=Path, help="repository外のprivate cycle state JSON")
    evaluate.add_argument(
        "--selection-manifest",
        required=True,
        type=Path,
        help="取得完了済みの同一ValleyRAT選定manifest",
    )
    evaluate.add_argument(
        "--run",
        required=True,
        action="append",
        type=Path,
        help="analyze_sample.pyの封印済み出力root。繰返し指定できます。",
    )
    evaluate.add_argument(
        "--kind",
        required=True,
        choices=sorted(EVALUATION_KINDS),
        help="最新cycleの初回holdoutか、selection一致cycleの開発用再解析かを明示します。",
    )
    evaluate.add_argument("--output-json", required=True, type=Path, help="sample IOCを含まない公開評価JSON")
    evaluate.add_argument("--output-markdown", type=Path, help="日本語の公開評価Markdown")
    evaluate.add_argument(
        "--fail-below-target",
        action="store_true",
        help="初回holdoutが7/20未満またはintegrity不合格なら終了code 1を返します。",
    )
    return parser


def _paths_collide(first: Path, second: Path) -> bool:
    left = first.resolve(strict=False)
    right = second.resolve(strict=False)
    return left == right


def main(argv: Sequence[str] | None = None) -> int:
    """CLIを実行し、秘密値を含まない固定errorだけを返す。"""

    args = build_parser().parse_args(argv)
    try:
        state_path = _validate_private_state_path(args.state)
        if args.command == "register":
            manifest_path = args.selection_manifest.resolve(strict=False)
            if _paths_collide(state_path, manifest_path):
                raise CycleEvaluationError(
                    "state_manifest_collision",
                    "private stateと選定manifestを同じpathへ保存できません。",
                )
            selection = _validated_selection_manifest(
                args.selection_manifest,
                phase="registration",
            )
            state = load_state(state_path) if state_path.exists() else None
            baseline = _baseline_hashes_from_files(args.baseline_manifest) if args.baseline_manifest else None
            updated, changed = register_next_holdout(
                state,
                selection,
                baseline_identities=baseline,
            )
            if changed:
                _write_state(state_path, updated)
            print(
                json.dumps(
                    {
                        "schema_version": SCHEMA_VERSION,
                        "status": "registered" if changed else "already_registered",
                        "cycle_number": updated["cycles"][-1]["cycle_number"],
                        "holdout_cases": COHORT_SIZE,
                        "sample_identifiers_included": False,
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                )
            )
            return 0

        if args.command == "start-holdout":
            state = load_state(state_path)
            updated, changed = pre_register_holdout_run(state, args.run)
            if changed:
                _write_state(state_path, updated)
            print(
                json.dumps(
                    {
                        "schema_version": SCHEMA_VERSION,
                        "status": "holdout_run_registered" if changed else "holdout_run_already_registered",
                        "cycle_number": updated["cycles"][-1]["cycle_number"],
                        "run_paths_included": False,
                        "sample_identifiers_included": False,
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                )
            )
            return 0

        if args.command == "migrate-state":
            legacy, _raw = _read_json_object(state_path, error_prefix="cycle_state")
            selections = [_validated_selection_manifest(path, phase="migration") for path in args.selection_manifest]
            baseline = _baseline_hashes_from_files(args.baseline_manifest)
            migrated = migrate_legacy_state(legacy, selections, baseline)
            _write_state(state_path, migrated)
            print(
                json.dumps(
                    {
                        "schema_version": SCHEMA_VERSION,
                        "status": "migrated",
                        "cycle_count": len(migrated["cycles"]),
                        "sample_identifiers_included": False,
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                )
            )
            return 0

        if args.command == "revoke-latest":
            audit_path = _validate_private_artifact_path(
                args.audit_output,
                code="revocation_audit_inside_repository",
            )
            if _paths_collide(state_path, audit_path):
                raise CycleEvaluationError(
                    "state_audit_collision",
                    "private stateと取消監査JSONを同じpathへ保存できません。",
                )
            if audit_path.exists():
                raise CycleEvaluationError(
                    "revocation_audit_already_exists",
                    "既存の取消監査JSONを上書きできません。",
                )
            raw_state, _raw = _read_json_object(state_path, error_prefix="cycle_state")
            updated, audit = revoke_latest_unevaluated(raw_state)
            _write_public_output(
                audit_path,
                json.dumps(audit, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False) + "\n",
            )
            _write_state(state_path, updated) if updated[
                "schema_version"
            ] == STATE_SCHEMA_VERSION else corpus._atomic_write_text(
                state_path,
                json.dumps(updated, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False) + "\n",
            )
            print(
                json.dumps(
                    {
                        "schema_version": SCHEMA_VERSION,
                        "status": "latest_unevaluated_cycle_revoked",
                        "cancelled_cycle_number": audit["cancelled_cycle_number"],
                        "sample_identifiers_included": False,
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                )
            )
            return 0

        if args.command == "extend-exclusions":
            audit_path = _validate_private_artifact_path(
                args.audit_output,
                code="exclusion_extension_audit_inside_repository",
            )
            if _paths_collide(state_path, audit_path):
                raise CycleEvaluationError(
                    "state_audit_collision",
                    "private stateと拡張監査JSONを同じpathへ保存できません。",
                )
            if audit_path.exists():
                raise CycleEvaluationError(
                    "exclusion_extension_audit_already_exists",
                    "既存の拡張監査JSONを上書きできません。",
                )
            for manifest_path in args.exclusion_manifest:
                if _paths_collide(state_path, manifest_path) or _paths_collide(audit_path, manifest_path):
                    raise CycleEvaluationError(
                        "exclusion_extension_path_collision",
                        "state、拡張監査JSON、既知集合manifestは別pathにしてください。",
                    )
            state = load_state(state_path)
            effective = _exact_exclusion_hashes_from_files(args.exclusion_manifest)
            updated, audit, changed = extend_exclusions(state, effective)
            _write_public_output(
                audit_path,
                json.dumps(audit, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False) + "\n",
            )
            if changed:
                _write_state(state_path, updated)
            print(
                json.dumps(
                    {
                        "schema_version": SCHEMA_VERSION,
                        "status": "exclusions_extended" if changed else "exclusions_already_current",
                        "extension_number": audit["extension_number"],
                        "added_identity_count": audit["added_identity_count"],
                        "effective_identity_count": audit["effective_identity_count"],
                        "sample_identifiers_included": False,
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                )
            )
            return 0

        manifest_path = args.selection_manifest.resolve(strict=False)
        if _paths_collide(state_path, manifest_path):
            raise CycleEvaluationError(
                "state_manifest_collision",
                "private stateと選定manifestを同じpathへ保存できません。",
            )

        outputs = [args.output_json, args.output_markdown]
        if any(path is not None and _paths_collide(state_path, path) for path in outputs):
            raise CycleEvaluationError(
                "state_output_collision",
                "private stateを公開評価出力で上書きできません。",
            )
        corpus._validate_output_paths(
            outputs,
            args.run,
            additional_inputs=(state_path, manifest_path),
        )
        for run_path in args.run:
            _validate_private_artifact_path(
                run_path,
                code="sealed_run_inside_repository",
            )
        selection = _validated_selection_manifest(
            args.selection_manifest,
            phase="evaluation",
        )
        state = load_state(state_path)
        updated, summary, changed = evaluate_current_cycle(
            state,
            args.run,
            evaluation_kind=args.kind,
            completed_selection=selection,
        )
        if changed:
            _write_state(state_path, updated)
        _write_public_output(
            args.output_json,
            json.dumps(
                summary,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
                allow_nan=False,
            )
            + "\n",
        )
        if args.output_markdown is not None:
            _write_public_output(args.output_markdown, render_markdown(summary))
        print(
            json.dumps(
                {
                    "schema_version": SCHEMA_VERSION,
                    "status": summary["target_gate"]["status"],
                    "cycle_number": summary["cycle"]["cycle_number"],
                    "joint_successes": summary["target_gate"]["observed_joint_successes"],
                    "required_joint_successes": REQUIRED_JOINT_SUCCESSES,
                    "sample_identifiers_included": False,
                },
                ensure_ascii=False,
                sort_keys=True,
            )
        )
        if args.fail_below_target and args.kind == "holdout" and summary["target_gate"]["status"] != "passed":
            return 1
        return 0
    except CycleEvaluationError as exc:
        error_code = exc.code
    except (OSError, TypeError, ValueError, corpus.CorpusSummaryError):
        error_code = "cycle_evaluation_failed"
    print(
        json.dumps(
            {
                "schema_version": SCHEMA_VERSION,
                "status": "error",
                "error_code": error_code,
                "message_ja": "ValleyRAT cycle評価を安全に完了できませんでした。",
            },
            ensure_ascii=False,
            sort_keys=True,
        ),
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
