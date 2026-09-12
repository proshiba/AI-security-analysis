#!/usr/bin/env python3
"""検体の適用可否判定から静的解析までを1コマンドで実行する。"""

from __future__ import annotations

import argparse
import copy
import hashlib
import io
import json
import math
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import zipfile
from collections import Counter, deque
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pyzipper

COMMON_ROOT = Path(__file__).resolve().parent
FRAMEWORK_ROOT = COMMON_ROOT.parent
REPOSITORY_ROOT = FRAMEWORK_ROOT.parent
CLASSIFIERS_ROOT = FRAMEWORK_ROOT / "classifiers"
DEFAULT_REGISTRY = FRAMEWORK_ROOT / "registry" / "malware_types.json"
DEFAULT_MAX_FILE_SIZE = 512 * 1024 * 1024
DEFAULT_MAX_FILES = 1_000
MAX_FOLLOW_ON_ARTIFACTS = 64
MAX_FOLLOW_ON_EDGES = 128
MAX_FOLLOW_ON_OMITTED_METADATA = 4096
MAX_FOLLOW_ON_DEPTH = 4
MAX_FOLLOW_ON_TOTAL_BYTES = 256 * 1024 * 1024
MAX_FOLLOW_ON_PAYLOAD_SIZE = 128 * 1024 * 1024
MAX_FOLLOW_ON_WALL_SECONDS = 300.0
MAX_FOLLOW_ON_CHILD_SECONDS = 120.0
MAX_FOLLOW_ON_WORKER_REQUEST = 64 * 1024
MAX_FOLLOW_ON_WORKER_RESPONSE = 4 * 1024 * 1024
FOLLOW_ON_WORKER_FRAME_HEADER_BYTES = 8
MAX_DIRECT_CLI_SECONDS = 24 * 60 * 60
MAX_DIRECT_CLI_ACTIVE_PROCESSES = 32
MAX_DIRECT_CLI_MEMORY_BYTES = 4 * 1024 * 1024 * 1024
MAX_DIRECT_CLI_REQUEST = 64 * 1024
MAX_DIRECT_CLI_RESPONSE = 64 * 1024
MAX_DIRECT_CLI_ARGUMENTS = 256
MAX_DIRECT_CLI_ARGUMENT_CHARACTERS = 32 * 1024
MAX_CLI_CREDENTIAL_BYTES = 4096
MAX_FOLLOW_ON_WORKER_ACTIVE_PROCESSES = 8
MAX_FOLLOW_ON_WORKER_MEMORY_BYTES = 2 * 1024 * 1024 * 1024
MAX_HANDLER_ATTEMPTS_PER_CASE = 64
MAX_HANDLER_RESULT_BYTES_PER_CASE = 16 * 1024 * 1024
MAX_HANDLER_WALL_SECONDS_PER_CASE = 300.0
MAX_PE_FUNCTION_WORKER_WALL_SECONDS = 120.0
MAX_PE_FUNCTION_WORKER_REQUEST = 64 * 1024
MAX_PE_FUNCTION_WORKER_RESPONSE = 4 * 1024 * 1024
MAX_PE_FUNCTION_WORKER_LAYER_BYTES = 128 * 1024 * 1024
MAX_PE_FUNCTION_WORKER_TOTAL_BYTES = 256 * 1024 * 1024
MAX_PE_FUNCTION_WORKER_PROGRAMS = 8
MAX_PE_FUNCTION_WORKER_ACTIVE_PROCESSES = 1
MAX_PE_FUNCTION_WORKER_MEMORY_BYTES = 512 * 1024 * 1024
MAX_STATIC_TOOL_BINARY_BYTES = 128 * 1024 * 1024
CONFIDENCE = {"high": 3, "medium": 2, "low": 1}
FAMILY_ALIASES = {
    "mx_go": "mx-go",
    "amos": "amosstealer",
    "atomicstealer": "amosstealer",
    "remcos": "remcosrat",
    "remus": "remusstealer",
    "lumma": "lummastealer",
    "atlas": "atlascross",
}

for trusted in (REPOSITORY_ROOT, FRAMEWORK_ROOT, COMMON_ROOT, CLASSIFIERS_ROOT):
    value = str(trusted)
    if value not in sys.path:
        sys.path.insert(0, value)

import analyze_family_sample  # noqa: E402
import automated_case_analysis  # noqa: E402
import batch_error_contract  # noqa: E402
import classify_sample  # noqa: E402
import handler_evidence  # noqa: E402
import orchestration_outcome  # noqa: E402
import runtime_contract  # noqa: E402
import static_implementation_commitment  # noqa: E402
import static_layer_pipeline as static_layers  # noqa: E402
import structural_candidates as structural_candidate_aggregation  # noqa: E402
import terminal_payload_acquisition  # noqa: E402
from analysis_contract import (  # noqa: E402
    PIPELINE_CONTRACT_VERSION,
    artifact_hashes,
    case_integrity_errors,
    ensure_no_reparse_components,
    ensure_tree_without_reparse,
    format_compatible,
    handler_result_quality,
    load_json_object_strict,
    normalize_sha256_digest,
    resolve_case_artifact,
    runtime_dependency_versions,
    seal_report,
)
from campaign_correlation import (  # noqa: E402
    extract_campaign_evidence,
    load_rules,
    match_fingerprints,
)
from case_features import build_case_profile, render_features_markdown  # noqa: E402
from extractors.profiled_family import clear_profile_cache  # noqa: E402
from follow_on_commitment import (  # noqa: E402
    canonical_multiset_commitment,
    metadata_identity,
)
from handler_catalog import (  # noqa: E402
    DEFAULT_MAXIMUM_ASSESSMENT_LAYER_SIZE,
    DEFAULT_MAXIMUM_ASSESSMENT_TOTAL_SIZE,
    MAX_ASSESSMENT_ATTEMPTS,
    MAX_ASSESSMENT_LAYERS,
    HandlerSpec,
    _bounded_handler_environment,
    _read_verified_artifact,
    _sanitize_public_text,
    assess_candidate_handlers,
    assessment_format_compatible,
    catalog_summary,
    clear_handler_caches,
    collect_detector_evaluations,
    discover_handlers,
    execute_handler_bounded_for_assessment,
    sanitize_public_value,
)
from malware_io import (  # noqa: E402
    read_file_capped,
    read_single_aes_zip_member,
    safe_output_name,
    sha256_bytes,
    write_json,
)
from profiled_family_detector import clear_known_hash_cache  # noqa: E402
from static_logic import (  # noqa: E402
    build_static_logic_report,
    function_analysis_is_available,
    render_static_logic_markdown,
)
from unpackers.static_unpacker import (  # noqa: E402
    CAB_LZX_BLOCK_METADATA_RESERVE_BYTES,
    CAB_LZX_FOLDER_METADATA_RESERVE_BYTES,
    CAB_LZX_MAX_WINDOW_BITS,
    CAB_LZX_MEMBER_METADATA_RESERVE_BYTES,
    CAB_LZX_MIN_WINDOW_BITS,
    CAB_LZX_RUNTIME_MEMORY_RESERVE_BYTES,
    MAX_CAB_BLOCK_UNCOMPRESSED_SIZE,
    MAX_CAB_LZX_WORKER_MEMORY_BYTES,
    detect_format,
    unpack_bytes,
)

InputUnit = static_layers.InputUnit
StaticLayer = static_layers.StaticLayer
StaticLayerPolicy = static_layers.StaticLayerPolicy
MAX_STATIC_LAYERS = static_layers.MAX_STATIC_LAYERS
MAX_STATIC_DEPTH = static_layers.MAX_STATIC_DEPTH
MAX_RECOVERED_LAYER_SIZE = static_layers.MAX_RECOVERED_LAYER_SIZE
MAX_RECOVERED_TOTAL_SIZE = static_layers.MAX_RECOVERED_TOTAL_SIZE
MAX_STATIC_COMPRESSION_RATIO = static_layers.MAX_STATIC_COMPRESSION_RATIO
MAX_ARCHIVE_MEMBERS = static_layers.MAX_ARCHIVE_MEMBERS
recover_layer_pipeline = static_layers.recover_static_layers
DEFAULT_STRING_SCAN_LIMIT = analyze_family_sample.DEFAULT_STRING_SCAN_LIMIT
BINARY_FORMATS = frozenset({"pe", "elf", "macho"})
FAMILY_POLICY_CATEGORIES = frozenset(
    {
        "rat",
        "stealer",
        "loader",
        "downloader",
        "backdoor",
        "ransomware",
        "worm",
        "bot",
        "keylogger",
        "miner",
        "other",
    }
)
FAMILY_HINT_LINEAGE_FIELDS = (
    "root_sha256",
    "parent_sha256",
    "artifact_sha256",
    "artifact_kind",
    "source",
    "source_id",
    "depth",
    "inherited_family",
    "family_hint_source",
)


def _bounded_json_size(value: Any, *, maximum_bytes: int) -> int | None:
    """JSONを連結せず走査し、上限内ならUTF-8 byte数を返す。"""

    total = 0
    try:
        chunks = json.JSONEncoder(
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).iterencode(value)
        for chunk in chunks:
            total += len(chunk.encode("utf-8"))
            if total > maximum_bytes:
                return None
    except (RecursionError, TypeError, ValueError):
        return None
    return total


def _normalized_handler_result_digest(execution: dict[str, Any]) -> str | None:
    """明示的なlayer provenanceだけを除いたhandler結果digestを返す。"""

    payload = copy.deepcopy(execution.get("result"))
    if not isinstance(payload, dict):
        return None
    payload.pop("sample_sha256", None)
    payload.pop("source_name", None)
    config = payload.get("config")
    if isinstance(config, dict):
        config.pop("source_name", None)
    try:
        encoded = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (RecursionError, TypeError, ValueError):
        return None
    return hashlib.sha256(encoded).hexdigest()


def _equivalent_pe_padding_handler_layers(
    strongest: list[tuple[dict[str, Any], int, StaticLayer, dict[str, Any]]],
) -> list[str]:
    """PE末尾padding除去の直系親子で意味結果が同一の場合だけ両hashを返す。"""

    if len(strongest) != 2:
        return []
    first, second = strongest
    first_layer, second_layer = first[2], second[2]
    if first_layer.parent_sha256 == second_layer.sha256:
        child = first_layer
    elif second_layer.parent_sha256 == first_layer.sha256:
        child = second_layer
    else:
        return []
    if child.transform != "pe-overlay-padding-removed":
        return []
    digests = {
        _normalized_handler_result_digest(first[3]),
        _normalized_handler_result_digest(second[3]),
    }
    if None in digests or len(digests) != 1:
        return []
    return sorted({first_layer.sha256, second_layer.sha256})


CAMPAIGN_CORRELATION_RULES = FRAMEWORK_ROOT / "registry" / "campaign_correlation_rules.json"
CAMPAIGN_FINGERPRINTS = FRAMEWORK_ROOT / "registry" / "campaign_fingerprints.json"
FAMILY_ANALYSIS_REQUIREMENTS = FRAMEWORK_ROOT / "registry" / "family_analysis_requirements.json"


class JapaneseArgumentParser(argparse.ArgumentParser):
    """argparseの固定見出しを日本語へ置換する。"""

    def format_help(self) -> str:
        """使用法、オプション見出し、標準help説明を日本語で返す。"""

        return (
            super()
            .format_help()
            .replace("usage:", "使用法:")
            .replace("options:", "オプション:")
            .replace("show this help message and exit", "このヘルプを表示して終了します")
        )


def _positive_integer(value: str) -> int:
    """CLI引数を正の整数へ変換し、0以下と非整数を拒否する。"""

    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("正の整数で指定してください") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("正の整数で指定してください")
    return parsed


def normalize_family(value: str) -> str:
    """CLIの代表的な別名を内部ファミリーIDへ正規化する。"""

    lowered = value.strip().lower()
    return FAMILY_ALIASES.get(lowered, lowered)


def _inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except (OSError, ValueError):
        return False


def collect_inputs(inputs: list[Path], output: Path, max_files: int) -> list[Path]:
    """ファイルとディレクトリを決定的に展開し、symlinkと出力先を除外する。"""

    if isinstance(max_files, bool) or not isinstance(max_files, int) or max_files <= 0:
        raise ValueError("max_files must be positive")
    collected: dict[str, Path] = {}
    for supplied in inputs:
        if not supplied.exists():
            raise FileNotFoundError(f"入力が見つかりません: {supplied}")
        if supplied.is_symlink():
            continue
        candidates = [supplied] if supplied.is_file() else sorted(supplied.rglob("*"))
        for candidate in candidates:
            if not candidate.is_file() or candidate.is_symlink() or _inside(candidate, output):
                continue
            resolved = candidate.resolve()
            collected[str(resolved).casefold()] = resolved
            if len(collected) > max_files:
                raise ValueError(f"入力ファイル数が上限 {max_files} を超えました")
    return [collected[key] for key in sorted(collected)]


def _zip_envelope_shape(data: bytes) -> tuple[bool, int]:
    """ZIPが暗号化済み単一メンバーの受け入れ用外装か確認する。"""

    if not zipfile.is_zipfile(io.BytesIO(data)):
        return False, 0
    try:
        with pyzipper.AESZipFile(io.BytesIO(data)) as archive:
            infos = [item for item in archive.infolist() if not item.is_dir()]
            return bool(infos and all(item.flag_bits & 1 for item in infos)), len(infos)
    except (OSError, RuntimeError, zipfile.BadZipFile):
        return False, 0


def read_input_unit(
    path: Path,
    *,
    password: str,
    archive_mode: str,
    max_file_size: int,
) -> InputUnit:
    """生ファイルまたは認証済み単一メンバーZIPをメモリ内で読み込む。"""

    if archive_mode not in {"auto", "raw", "malwarebazaar"}:
        raise ValueError(f"unsupported archive_mode: {archive_mode!r}")
    if isinstance(max_file_size, bool) or not isinstance(max_file_size, int) or max_file_size <= 0:
        raise ValueError("max_file_size must be a positive integer")
    size = path.stat().st_size
    if size > max_file_size:
        raise ValueError(f"入力サイズが上限 {max_file_size} bytes を超えました")
    outer = read_file_capped(path, max_size=max_file_size)
    outer_digest = sha256_bytes(outer)
    encrypted, member_count = _zip_envelope_shape(outer)
    unwrap = archive_mode == "malwarebazaar" or (archive_mode == "auto" and encrypted and member_count == 1)
    if not unwrap:
        return InputUnit(
            source_name=path.name,
            data=outer,
            input_kind="raw",
            outer_sha256=outer_digest,
            outer_size=len(outer),
        )
    member = read_single_aes_zip_member(
        outer,
        password=password,
        max_member_size=max_file_size,
    )
    return InputUnit(
        source_name=Path(member.name).name,
        data=member.data,
        input_kind="authenticated_single_member_zip",
        outer_sha256=outer_digest,
        outer_size=len(outer),
        member_name=member.name,
    )


def _registered_families(registry: Path) -> set[str]:
    return set(classify_sample._validated_registry(registry))


def recover_static_layers(
    unit: InputUnit,
    *,
    upx: Path | None = None,
    sevenzip: Path | None = None,
    diec: Path | None = None,
    innounp: Path | None = None,
    force_container_probe: bool = False,
    max_static_layers: int = MAX_STATIC_LAYERS,
    archive_password: str = "infected",
    inno_password: str = "",
) -> tuple[list[StaticLayer], dict[str, Any]]:
    """共有パイプラインへ既存unpackerと公開値sanitizerを注入する互換入口。"""

    return recover_layer_pipeline(
        unit,
        unpacker=unpack_bytes,
        sanitizer=sanitize_public_value,
        policy=StaticLayerPolicy(max_layers=max_static_layers),
        upx=upx,
        sevenzip=sevenzip,
        diec=diec,
        innounp=innounp,
        force_container_probe=force_container_probe,
        archive_password=archive_password,
        inno_password=inno_password,
    )


def _layer_count_limit_reached(layer_report: dict[str, Any]) -> bool:
    """静的復元が層数上限へ達した場合だけ再試行対象とする。"""

    events = layer_report.get("limit_events")
    return isinstance(events, list) and any(
        isinstance(event, dict) and event.get("reason") == "layer_count_limit" for event in events
    )


def _handler_evidence_score(value: Any) -> int:
    """互換用に、共通証拠tierから決定的なscoreだけを返す。"""

    return int(handler_result_quality(value)["score"])


def _detector_error_for_family(classification: dict[str, Any], family: str) -> bool:
    """選択候補familyの検出器が例外終了したか返す。"""

    observations = classification.get("observations")
    if not isinstance(observations, dict):
        return False
    errors = observations.get("detector_errors")
    return isinstance(errors, dict) and family in errors


def _selected_family(
    classification: dict[str, Any],
    forced_family: str | None,
    minimum_confidence: str,
) -> tuple[str | None, str]:
    if forced_family:
        if classification.get("malware_type") != forced_family:
            return None, "explicit_family_not_selected"
        if classification.get("attribution_basis") == "explicit_user_type_unmatched":
            return None, "explicit_family_detector_unmatched"
        if _detector_error_for_family(classification, forced_family):
            return None, "explicit_family_detector_failed"
        return forced_family, "explicit_operator_selection"
    family = classification.get("malware_type")
    confidence = classification.get("malware_type_confidence", "low")
    if family == "unknown" or CONFIDENCE.get(confidence, 0) < CONFIDENCE[minimum_confidence]:
        return None, "no_unique_detection_above_threshold"
    if _detector_error_for_family(classification, str(family)):
        return None, "selected_family_detector_failed"
    return str(family), str(classification.get("attribution_basis", "detector"))


def assess_handlers(
    specs: list[HandlerSpec],
    layer_selections: list[dict[str, Any]],
    forced_family: str | None,
    registered_families: set[str] | None = None,
) -> list[dict[str, Any]]:
    """全既存解析器について、自動実行、非適用、手動確認を明示する。"""

    registered = registered_families or set()
    results = []
    for spec in specs:
        status = "not_applicable"
        reason = "different_family"
        family_layers = [item for item in layer_selections if item["selected_family"] == spec.family]
        eligible_layers = [
            item
            for item in family_layers
            if spec.campaign is None or item["classification"].get("campaign_type", "unknown") == spec.campaign
        ]
        if not spec.supported_interface:
            status, reason = "unsupported_interface", spec.reason
        elif family_layers:
            if spec.campaign and not eligible_layers:
                status, reason = "manual_review", "campaign_specific_handler_not_selected"
            elif spec.automatic:
                status = "applicable_forced" if forced_family else "applicable"
                reason = "explicit_family" if forced_family else "detector_selected_family"
            else:
                status, reason = "manual_review", spec.reason
        elif spec.family not in registered:
            status, reason = "manual_review", "family_has_no_registered_detector"
        results.append(
            {
                **spec.public(),
                "status": status,
                "applicability_reason": reason,
                "applicable_layers": [item["layer"].sha256 for item in eligible_layers],
            }
        )
    return results


def summarize_family_coverage(specs: list[HandlerSpec], registered_families: set[str]) -> list[dict[str, Any]]:
    """検出器と既存解析器の有無をファミリー単位で可視化する。"""

    families = sorted(registered_families | {item.family for item in specs})
    results = []
    for family in families:
        family_specs = [item for item in specs if item.family == family]
        automatic = [item.id for item in family_specs if item.automatic]
        manual = [item.id for item in family_specs if not item.automatic]
        if family not in registered_families:
            status = "handler_without_registered_detector"
        elif automatic:
            status = "automatic_handler_available"
        elif family_specs:
            status = "manual_or_unsupported_only"
        else:
            status = "no_handler_implemented"
        results.append(
            {
                "family": family,
                "status": status,
                "detector_registered": family in registered_families,
                "automatic_handlers": automatic,
                "manual_or_unsupported_handlers": manual,
            }
        )
    return results


def _load_family_hint_manifest(
    supplied: Path | None,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """外部ヒントを厳格に読み、内容識別子とともに返す。"""

    if supplied is None:
        return None, None
    path = supplied.expanduser()
    manifest = classify_sample.load_family_hint_manifest(path)
    canonical = json.dumps(
        manifest,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    identity = {
        "name": path.name,
        "canonical_size": len(canonical),
        "canonical_sha256": hashlib.sha256(canonical).hexdigest(),
    }
    return manifest, identity


def build_artifact_family_hint_manifest(
    *,
    artifact_sha256: str,
    parent_sha256: str,
    root_sha256: str,
    artifact_kind: str,
    source: str,
    source_id: str,
    depth: int,
    parent_hints: Sequence[Mapping[str, Any]],
) -> dict[str, Any] | None:
    """親の候補familyを、帰属には使わない子artifact検証hintへ変換する。"""

    artifact = normalize_sha256_digest(artifact_sha256)
    parent = normalize_sha256_digest(parent_sha256)
    root = normalize_sha256_digest(root_sha256)
    if artifact in {parent, root}:
        raise ValueError("artifact family hint lineage must reference an ancestor")
    if (
        isinstance(depth, bool)
        or not isinstance(depth, int)
        or not 1 <= depth <= classify_sample.MAX_FAMILY_HINT_LINEAGE_DEPTH
    ):
        raise ValueError("artifact family hint depth is outside the bounded lineage")
    normalized_kind = re.sub(r"[^a-z0-9_.-]+", "_", str(artifact_kind).casefold()).strip("._-")
    if not normalized_kind:
        normalized_kind = "recovered_payload"
    normalized_kind = normalized_kind[:64]
    inherited_by_fingerprint: dict[str, dict[str, Any]] = {}
    for supplied in parent_hints:
        if not isinstance(supplied, Mapping):
            raise TypeError("parent family hint must be a mapping")
        family = supplied.get("family")
        if not isinstance(family, str):
            raise ValueError("parent family hint is missing family")
        hint: dict[str, Any] = {
            "family": family,
            "source": source,
            "provenance": f"inherited-from-sha256:{parent}",
            "confidence": supplied.get("confidence", "unverified"),
            "artifact_sha256": artifact,
            "parent_sha256": parent,
            "root_sha256": root,
            "artifact_kind": normalized_kind,
            "source_id": source_id,
            "depth": depth,
            "inherited_family": family,
            "family_hint_source": "parent_metadata_candidate",
        }
        for optional in ("label", "observed_at"):
            if optional in supplied:
                hint[optional] = supplied[optional]
        # 親manifestではproviderごとに異なるsource/provenanceを持つ同一family hintを
        # 許可する。一方、子lineageではsource/provenanceを継承機構の固定値へ正規化
        # するため、同じfamily/confidenceのhintが同一objectへ収束し得る。ここで
        # canonical fingerprintにより決定的に集約し、正当な複数provider入力が
        # duplicate hintとしてfollow-on全体を失敗させないようにする。
        fingerprint = json.dumps(
            hint,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        inherited_by_fingerprint.setdefault(fingerprint, hint)
    inherited = [inherited_by_fingerprint[key] for key in sorted(inherited_by_fingerprint)]
    if not inherited:
        return None
    return classify_sample.normalize_family_hint_manifest({"schema_version": 1, "samples": {artifact: inherited}})


def _family_hint_lineage_records(hints: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """検証済みhintから、hashで結合可能なartifact lineageだけを公開する。"""

    records = []
    for hint in hints:
        if "artifact_sha256" not in hint:
            continue
        records.append({key: hint[key] for key in FAMILY_HINT_LINEAGE_FIELDS})
    return sorted(
        records,
        key=lambda item: (
            item["depth"],
            item["root_sha256"],
            item["parent_sha256"],
            item["artifact_sha256"],
            item["inherited_family"],
        ),
    )


def _family_hint_conflicts(
    hints: Sequence[Mapping[str, Any]],
    selected_families: Sequence[str],
) -> list[dict[str, Any]]:
    """親hintと子artifact自身の独立検出が異なる場合を上書きせず記録する。"""

    inherited = sorted(
        {str(hint["inherited_family"]) for hint in hints if isinstance(hint.get("inherited_family"), str)}
    )
    detected = sorted({family for family in selected_families if isinstance(family, str)})
    if not inherited or not detected or set(inherited) == set(detected):
        return []
    return [
        {
            "kind": "classification_conflict",
            "inherited_family_candidates": inherited,
            "independently_detected_families": detected,
            "resolution": "independent_detector_and_handler_evidence_take_precedence",
            "metadata_hint_used_for_attribution": False,
        }
    ]


def _verification_candidates(routing: dict[str, Any]) -> list[dict[str, Any]]:
    """通常の確定経路を除き、handlerで再検証できる候補だけを返す。"""

    values = routing.get("candidates")
    if not isinstance(values, list):
        return []
    return [
        item
        for item in values
        if isinstance(item, dict)
        and item.get("routing_eligible") is True
        and item.get("routing_mode") == "candidate_verification"
        and isinstance(item.get("routing_eligibility"), dict)
        and item["routing_eligibility"].get("candidate_verification") is True
    ]


def _candidate_assessment_inputs(candidates: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """候補sourceだけを個別に無害化し、strict assessment入力へ射影する。"""

    public = []
    for candidate in candidates:
        raw_sources = candidate.get("sources", candidate.get("source", []))
        sources = [raw_sources] if isinstance(raw_sources, str) else list(raw_sources or [])
        public.append(
            {
                "family": candidate.get("family"),
                "sources": [_sanitize_public_text(value) if isinstance(value, str) else value for value in sources],
                "routing_eligible": candidate.get("routing_eligible") is True,
                "routing_mode": candidate.get("routing_mode"),
                "routing_eligibility": candidate.get("routing_eligibility"),
                "rank": candidate.get("rank"),
                "rank_score": candidate.get("rank_score", 0),
            }
        )
    return public


def _public_candidate_layer(layer: StaticLayer) -> dict[str, Any]:
    """候補assessmentへ公開するlayer文字列を個別に無害化する。"""

    public = layer.public()
    public["name"] = _sanitize_public_text(layer.name)
    public["transform"] = _sanitize_public_text(layer.transform)
    return public


def _sanitize_candidate_assessment_layers(result: dict[str, Any]) -> None:
    """解析時のraw layer名を変えず、公開layer監査情報だけを個別に無害化する。"""

    def sanitize_layer(layer: Any) -> None:
        if not isinstance(layer, dict):
            return
        for field in ("name", "transform"):
            value = layer.get(field)
            if isinstance(value, str):
                layer[field] = _sanitize_public_text(value)

    pair_planning = result.get("pair_planning")
    lineage_layers = pair_planning.get("lineage_layers") if isinstance(pair_planning, Mapping) else None
    if isinstance(lineage_layers, list):
        for layer in lineage_layers:
            sanitize_layer(layer)

    families = result.get("families")
    if not isinstance(families, list):
        return
    for family in families:
        attempts = family.get("attempts") if isinstance(family, Mapping) else None
        if not isinstance(attempts, list):
            continue
        for attempt in attempts:
            layer = attempt.get("layer") if isinstance(attempt, Mapping) else None
            sanitize_layer(layer)


def _load_family_analysis_requirements(path: Path = FAMILY_ANALYSIS_REQUIREMENTS) -> dict[str, dict[str, Any]]:
    """family別の必須成果物policyを厳格schemaで読み込む。"""

    document = load_json_object_strict(path)
    if (
        set(document) != {"schema_version", "policies"}
        or type(document.get("schema_version")) is not int
        or document.get("schema_version") != 1
    ):
        raise ValueError("family analysis requirementsのroot schemaが不正です")
    supplied = document.get("policies")
    if not isinstance(supplied, dict) or len(supplied) > 512:
        raise ValueError("family analysis requirementsのpoliciesが不正です")
    expected = {"category", "config_required", "network_required", "terminal_payload_required"}
    policies: dict[str, dict[str, Any]] = {}
    for family, policy in supplied.items():
        if not isinstance(family, str) or classify_sample.FAMILY_ID_RE.fullmatch(family) is None:
            raise ValueError("family analysis requirementsに不正なfamilyがあります")
        if not isinstance(policy, dict) or set(policy) != expected:
            raise ValueError(f"family analysis requirementsのfieldが不正です: {family}")
        if policy.get("category") not in FAMILY_POLICY_CATEGORIES:
            raise ValueError(f"family analysis requirementsのcategoryが不正です: {family}")
        if any(type(policy.get(key)) is not bool for key in expected - {"category"}):
            raise ValueError(f"family analysis requirementsのbooleanが不正です: {family}")
        policies[family] = dict(policy)
    return dict(sorted(policies.items()))


def _requirements_policy_summary(policies: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """requirements policyのcoverageを機械可読に要約する。"""

    categories = {
        category: sum(policy.get("category") == category for policy in policies.values())
        for category in sorted(FAMILY_POLICY_CATEGORIES)
    }
    return {
        "source": "registry/family_analysis_requirements.json",
        "declared_family_count": len(policies),
        "categories": categories,
        "undeclared_family_policy": "block_complete_after_resolution",
    }


def _zero_attempt_candidate_assessment(
    *,
    base: Mapping[str, Any],
    status: str,
    excluded_layers: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    """候補検証の早期終了を、欠落のない0件accountingとして返す。"""

    return {
        **base,
        "status": status,
        "confirmed_families": [],
        "planned_attempt_count": 0,
        "actual_attempt_count": 0,
        "retained_attempt_detail_count": 0,
        "omitted_attempt_detail_count": 0,
        "unattempted_attempt_count": 0,
        "blockers": [],
        "budget": {"exhausted": False},
        "families": [],
        "excluded_layers": [dict(item) for item in excluded_layers],
    }


def _candidate_handler_assessment(
    *,
    routing: dict[str, Any],
    layers: list[StaticLayer],
    layer_classifications: list[dict[str, Any]],
    specs: list[HandlerSpec],
    assessment_only: bool,
    artifact_directory: Path | None,
) -> dict[str, Any]:
    """互換layerを容量・試行数の上限内で静的に候補検証する。"""

    candidates = _verification_candidates(routing)
    base = {
        "schema_version": 1,
        "candidate_count": len(candidates),
        "executed_sample": False,
        "network_contacted": False,
        "filesystem_written_by_handlers": False,
    }
    if assessment_only:
        return _zero_attempt_candidate_assessment(
            base=base,
            status="not_run_assessment_only",
        )
    if not candidates:
        return _zero_attempt_candidate_assessment(
            base=base,
            status="no_candidates",
        )
    candidate_families = {str(item["family"]) for item in candidates}
    candidate_specs = [spec for spec in specs if spec.automatic and spec.family in candidate_families]
    if not candidate_specs:
        return _zero_attempt_candidate_assessment(
            base=base,
            status="no_automatic_handler",
        )

    supported_hashes = {
        digest for item in candidates for digest in item.get("layer_sha256", []) if isinstance(digest, str)
    }
    compatible_layers: list[tuple[int, StaticLayer, str, int]] = []
    lineage_only_layers: list[tuple[int, StaticLayer, str, int]] = []
    excluded: list[dict[str, Any]] = []
    for index, layer in enumerate(layers):
        public_layer = _public_candidate_layer(layer)
        actual_format = detect_format(layer.data, layer.name)
        compatible_pair_count = sum(
            assessment_format_compatible(spec.input_formats, actual_format) for spec in candidate_specs
        )
        if len(layer.data) > DEFAULT_MAXIMUM_ASSESSMENT_LAYER_SIZE:
            excluded.append(
                {
                    "layer": public_layer,
                    "reason": "candidate_layer_size_limit",
                    "compatible_pair_count": compatible_pair_count,
                    "execution_quota_consumed": False,
                }
            )
        elif compatible_pair_count == 0:
            lineage_only_layers.append((index, layer, actual_format, 0))
        else:
            compatible_layers.append((index, layer, actual_format, compatible_pair_count))

    def order_key(item: tuple[int, StaticLayer, str, int]) -> tuple[int, int, int]:
        return (
            0 if item[1].sha256 in supported_hashes else 1,
            item[1].depth,
            item[0],
        )

    ordered = sorted(compatible_layers, key=order_key) + sorted(lineage_only_layers, key=order_key)
    selected: list[tuple[int, StaticLayer, str, int]] = []
    total_size = 0
    for item in ordered:
        if len(selected) >= MAX_ASSESSMENT_LAYERS:
            excluded.append(
                {
                    "layer": _public_candidate_layer(item[1]),
                    "reason": "candidate_layer_limit",
                    "compatible_pair_count": item[3],
                    "selection_role": (
                        "compatible_pair_candidate" if item[3] else "lineage_audit_only"
                    ),
                    "execution_quota_consumed": False,
                }
            )
            continue
        if total_size + len(item[1].data) > DEFAULT_MAXIMUM_ASSESSMENT_TOTAL_SIZE:
            excluded.append(
                {
                    "layer": _public_candidate_layer(item[1]),
                    "reason": "candidate_total_size_limit",
                    "compatible_pair_count": item[3],
                    "selection_role": (
                        "compatible_pair_candidate" if item[3] else "lineage_audit_only"
                    ),
                    "execution_quota_consumed": False,
                }
            )
            continue
        selected.append(item)
        total_size += len(item[1].data)
    if not selected:
        return _zero_attempt_candidate_assessment(
            base=base,
            status="no_eligible_layer_within_limits",
            excluded_layers=excluded,
        )

    selected_hashes = {item[1].sha256 for item in selected}
    assessment_layers = [
        {
            "name": layer.name,
            "data": layer.data,
            "sha256": layer.sha256,
            "parent_sha256": layer.parent_sha256 if layer.parent_sha256 in selected_hashes else None,
            "depth": layer.depth,
            "transform": layer.transform,
            "format": actual_format,
        }
        for _index, layer, actual_format, _compatible_pair_count in selected
    ]
    result = assess_candidate_handlers(
        _candidate_assessment_inputs(candidates),
        assessment_layers,
        detector_evaluations=collect_detector_evaluations(layer_classifications),
        specs=candidate_specs,
        maximum_attempts=MAX_ASSESSMENT_ATTEMPTS,
        artifact_directory=artifact_directory,
        artifact_path_prefix="p",
    )
    result["selected_layer_count"] = len(selected)
    result["selected_total_size"] = total_size
    result["selected_compatible_pair_count"] = sum(item[3] for item in selected)
    result["excluded_layers"] = excluded
    _sanitize_candidate_assessment_layers(result)
    return result


def _preflight_applicable(specs: list[HandlerSpec], applicability: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """親processではimportせず、layer単位の事前検査を隔離workerへ委譲する。"""

    known_ids = {item.id for item in specs}
    results = []
    for item in applicability:
        if item["status"] not in {"applicable", "applicable_forced"}:
            continue
        handler_id = item["id"]
        results.append(
            {
                "handler_id": handler_id,
                "available": handler_id in known_ids,
                "error": None if handler_id in known_ids else "handler_spec_not_found",
                "execution_boundary": "bounded_assessment_worker",
                "preflight": "deferred_to_per_layer_worker",
            }
        )
    return results


def plan_handler_layers(
    spec: HandlerSpec,
    applicability: dict[str, Any],
    layers: list[StaticLayer],
) -> list[dict[str, Any]]:
    """family一致層と安全に関連付けられる層を、形式契約付き実行順へ変換する。"""

    anchors = set(applicability.get("applicable_layers") or [])
    by_hash = {layer.sha256: layer for layer in layers}
    ancestors: set[str] = set()
    for anchor in anchors:
        current = by_hash.get(anchor)
        while current is not None and current.parent_sha256:
            ancestors.add(current.parent_sha256)
            current = by_hash.get(current.parent_sha256)

    # family共通shared extractorは、bundle外装でfamilyが確定した場合も、
    # その配下に復元された設定用DAT/PNG/DLL等を静的に確認する必要がある。
    # 他のhandlerへは入力契約外のmemberを広げず、従来どおりanchorと祖先だけを渡す。
    descendants: set[str] = set()
    companions: set[str] = set()
    if spec.source == "shared_extractor" and spec.campaign is None and anchors:
        children_by_parent: dict[str, list[str]] = {}
        for layer in layers:
            if layer.parent_sha256:
                children_by_parent.setdefault(layer.parent_sha256, []).append(layer.sha256)
        pending = list(anchors)
        visited = set(anchors)
        while pending:
            parent_sha256 = pending.pop()
            for child_sha256 in children_by_parent.get(parent_sha256, []):
                if child_sha256 in visited:
                    continue
                visited.add(child_sha256)
                descendants.add(child_sha256)
                pending.append(child_sha256)

        # family本体DLLと同じbundleに設定DAT等が並ぶ構成もあるため、anchorの
        # 直接の兄弟branchだけをcompanionとして追加する。別rootや祖先全体へは
        # 広げず、同一parentという明示的lineage境界を維持する。
        related = set(anchors) | descendants
        for anchor in anchors:
            current = by_hash.get(anchor)
            if current is None or not current.parent_sha256:
                continue
            pending = [
                sibling_sha256
                for sibling_sha256 in children_by_parent.get(current.parent_sha256, [])
                if sibling_sha256 not in related
            ]
            while pending:
                companion_sha256 = pending.pop()
                if companion_sha256 in related or companion_sha256 in companions:
                    continue
                companions.add(companion_sha256)
                pending.extend(children_by_parent.get(companion_sha256, []))

    plan = []
    for index, layer in enumerate(layers):
        if layer.sha256 in anchors:
            routing_role = "selected_family_layer"
            priority = 0
        elif layer.sha256 in descendants:
            routing_role = "descendant_candidate"
            priority = 1
        elif layer.sha256 in companions:
            routing_role = "companion_candidate"
            priority = 2
        elif layer.sha256 in ancestors:
            routing_role = "ancestor_fallback"
            priority = 3
        else:
            routing_role = "unrelated_layer"
            priority = 4
        actual_format = detect_format(layer.data, layer.name)
        plan.append(
            {
                "layer": layer,
                "layer_index": index,
                "routing_role": routing_role,
                "priority": priority,
                "actual_format": actual_format,
                "compatible": format_compatible(spec.input_formats, actual_format),
            }
        )
    return sorted(plan, key=lambda item: (item["priority"], item["layer_index"]))


def _next_round_robin_handler_plan(state: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]] | None:
    """skip監査を保持しつつ、handlerの次の実行可能pairを1件だけ返す。"""

    spec = state["spec"]
    while state["cursor"] < len(state["plan"]):
        planned = state["plan"][state["cursor"]]
        state["cursor"] += 1
        layer = planned["layer"]
        attempt = {
            "layer": layer.public(),
            "routing_role": planned["routing_role"],
            "actual_format": planned["actual_format"],
            "accepted_formats": list(spec.input_formats),
        }
        if planned["routing_role"] == "unrelated_layer":
            state["attempts"].append({**attempt, "status": "skipped_unrelated_layer"})
            continue
        if not planned["compatible"]:
            state["attempts"].append({**attempt, "status": "skipped_incompatible_format"})
            continue
        if planned["routing_role"] == "ancestor_fallback" and any(
            value[0]["sufficient"] and value[0]["tier"] >= 4 for value in state["completed"]
        ):
            state["attempts"].append({**attempt, "status": "skipped_fallback_not_needed"})
            continue
        return planned, attempt
    return None


def _run_handler_rounds(
    states: list[dict[str, Any]],
    *,
    recovered_payload_directory: Path | None,
) -> str | None:
    """各handlerを1pairずつ巡回し、case共通予算内で静的workerを実行する。"""

    attempts_used = 0
    result_bytes_used = 0
    deadline = time.monotonic() + MAX_HANDLER_WALL_SECONDS_PER_CASE
    budget_reason: str | None = None
    active = list(states)
    while active and budget_reason is None:
        next_active: list[dict[str, Any]] = []
        for state in active:
            selected = _next_round_robin_handler_plan(state)
            if selected is None:
                continue
            planned, attempt = selected
            if (
                attempts_used >= MAX_HANDLER_ATTEMPTS_PER_CASE
                or time.monotonic() >= deadline
                or result_bytes_used >= MAX_HANDLER_RESULT_BYTES_PER_CASE
            ):
                if attempts_used >= MAX_HANDLER_ATTEMPTS_PER_CASE:
                    budget_reason = "handler_attempt_limit"
                elif time.monotonic() >= deadline:
                    budget_reason = "handler_wall_clock_limit"
                else:
                    budget_reason = "handler_result_bytes_limit"
                state["attempts"].append({**attempt, "status": "failed", "error": budget_reason})
                state["truncated"] = True
                state["budget_reason"] = budget_reason
                break
            spec = state["spec"]
            layer = planned["layer"]
            attempts_used += 1
            try:
                bounded = execute_handler_bounded_for_assessment(
                    spec,
                    layer.data,
                    layer.name,
                    actual_format=planned["actual_format"],
                    maximum_input_size=DEFAULT_MAXIMUM_ASSESSMENT_LAYER_SIZE,
                    artifact_directory=recovered_payload_directory,
                    artifact_path_prefix="p",
                )
                worker_status = bounded.get("status")
                worker_attempt = {
                    **attempt,
                    "execution_boundary": "bounded_assessment_worker",
                    "worker_status": worker_status,
                    "preflight": sanitize_public_value(bounded.get("preflight")),
                }
                if worker_status != "completed":
                    state["attempts"].append(
                        {
                            **worker_attempt,
                            "status": "failed",
                            "error": sanitize_public_value(
                                bounded.get("error")
                                or (
                                    "handler_preflight_blocked"
                                    if worker_status == "preflight_blocked"
                                    else "handler_worker_incomplete"
                                )
                            ),
                        }
                    )
                else:
                    result = bounded.get("execution")
                    if not isinstance(result, dict):
                        state["attempts"].append(
                            {**worker_attempt, "status": "failed", "error": "handler_worker_invalid_execution"}
                        )
                    else:
                        remaining = MAX_HANDLER_RESULT_BYTES_PER_CASE - result_bytes_used
                        result_size = _bounded_json_size(result, maximum_bytes=remaining)
                        if result_size is None:
                            budget_reason = "handler_result_bytes_limit"
                            state["truncated"] = True
                            state["budget_reason"] = budget_reason
                            state["attempts"].append(
                                {**worker_attempt, "status": "failed", "error": budget_reason}
                            )
                        else:
                            result_bytes_used += result_size
                            quality = handler_result_quality(
                                result.get("result"),
                                minimum_score=spec.minimum_evidence_score,
                            )
                            state["attempts"].append(
                                {
                                    **worker_attempt,
                                    "status": "succeeded",
                                    "evidence_status": (
                                        "sufficient" if quality["sufficient"] else "insufficient"
                                    ),
                                    "evidence": quality,
                                }
                            )
                            state["completed"].append(
                                (quality, -planned["layer_index"], layer, result)
                            )
            except Exception as exc:
                state["attempts"].append(
                    {
                        **attempt,
                        "status": "failed",
                        "error": sanitize_public_value(f"{type(exc).__name__}: {exc}"),
                    }
                )
            if budget_reason is not None:
                break
            if budget_reason is None and state["cursor"] < len(state["plan"]):
                next_active.append(state)
        active = next_active
    if budget_reason is not None:
        for state in states:
            if state["cursor"] < len(state["plan"]):
                state["truncated"] = True
                state["budget_reason"] = budget_reason
    return budget_reason


def _materialize_handler_state(state: dict[str, Any], case_dir: Path) -> dict[str, Any]:
    """round-robin後のhandler状態から従来互換の実行記録と成果物を生成する。"""

    handler_id = state["handler_id"]
    if "preflight_error" in state:
        return {
            "handler_id": handler_id,
            "status": "preflight_failed",
            "error": state["preflight_error"],
        }
    attempts = state["attempts"]
    completed = state["completed"]
    truncated = bool(state["truncated"])
    budget_reason = state["budget_reason"]
    if not completed:
        attempted = any(value["status"] == "failed" for value in attempts)
        return {
            "handler_id": handler_id,
            "status": "failed" if attempted or truncated else "incompatible_input_format",
            "error": (
                budget_reason
                if truncated and isinstance(budget_reason, str)
                else "all_eligible_layers_failed"
                if attempted
                else "no_eligible_layer_satisfied_input_contract"
            ),
            "resource_budget_truncated": truncated,
            "resource_budget_reason": budget_reason if truncated else None,
            "attempts": attempts,
        }
    selected_quality, _, selected_layer, selected_result = max(
        completed,
        key=lambda value: (value[0]["score"], value[1]),
    )
    strongest = [
        value
        for value in completed
        if value[0]["score"] == selected_quality["score"] and value[0]["sufficient"]
    ]
    tied_layers = sorted({value[2].sha256 for value in strongest})
    equivalent_layers = _equivalent_pe_padding_handler_layers(strongest)
    ambiguous_layers = [] if equivalent_layers else tied_layers
    if not selected_quality["sufficient"]:
        execution_status = "no_evidence"
    elif len(ambiguous_layers) > 1 or truncated:
        execution_status = "ambiguous_evidence"
    else:
        execution_status = "succeeded"
    spec = state["spec"]
    filename = (
        safe_output_name(spec.family)
        + "-"
        + hashlib.sha256(handler_id.encode("utf-8")).hexdigest()[:16]
        + ".json"
    )
    write_json(
        case_dir / "handlers" / filename,
        {
            **selected_result,
            "handler": spec.public(),
            "selected_layer": selected_layer.public(),
            "selected_evidence": selected_quality,
            "selected_evidence_score": selected_quality["score"],
            "selection_strategy": "evidence_tier_then_score_then_root_order",
            "ambiguous_best_layer_sha256": ambiguous_layers,
            "equivalent_best_layer_sha256": equivalent_layers,
            "resource_budget_truncated": truncated,
            "resource_budget_reason": budget_reason if truncated else None,
            "attempts": attempts,
        },
    )
    return {
        "handler_id": handler_id,
        "status": execution_status,
        "selected_layer_sha256": selected_layer.sha256,
        "selected_evidence": selected_quality,
        "ambiguous_best_layer_sha256": ambiguous_layers,
        "equivalent_best_layer_sha256": equivalent_layers,
        "resource_budget_truncated": truncated,
        "resource_budget_reason": budget_reason if truncated else None,
        "result": f"handlers/{filename}",
        "attempts": attempts,
    }


def _triage_issues(value: Any, path: str = "root") -> list[str]:
    """汎用トリアージ内のparse失敗と明示的partialを再帰的に収集する。"""

    issues = []
    if isinstance(value, dict):
        coverage = value.get("analysis_coverage")
        if isinstance(coverage, dict) and coverage.get("status") not in {None, "complete"}:
            issues.append(f"{path}:coverage:{coverage.get('status')}")
        for key, item in value.items():
            lowered = str(key).casefold()
            child_path = f"{path}.{key}"
            if lowered == "parse_error" or lowered.endswith("_error"):
                issues.append(child_path)
            elif key != "analysis_coverage":
                issues.extend(_triage_issues(item, child_path))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            issues.extend(_triage_issues(item, f"{path}[{index}]"))
    return issues


def _run_generic_triage(
    layers: list[StaticLayer],
    case_dir: Path,
    *,
    string_scan_limit: int = DEFAULT_STRING_SCAN_LIMIT,
) -> tuple[dict[str, Any], str]:
    """全静的復元層を個別にトリアージし、部分失敗を隠さず集約する。"""

    entries = []
    for layer in layers:
        try:
            value = analyze_family_sample.analyze(
                layer.name,
                layer.data,
                case_dir / "scripts",
                persist_normalized_text=False,
                recurse_archives=False,
                string_scan_limit=string_scan_limit,
            )
            issues = _triage_issues(value)
            entries.append(
                {
                    "layer": layer.public(),
                    "status": "partial" if issues else "complete",
                    "issues": issues,
                    "result": sanitize_public_value(value),
                }
            )
        except Exception as exc:
            entries.append(
                {
                    "layer": layer.public(),
                    "status": "failed",
                    "issues": [f"{type(exc).__name__}: {exc}"],
                    "result": None,
                }
            )
    root = entries[0]
    document = dict(root["result"] or {})
    if root["result"] is None:
        document.update(status="failed", error=root["issues"][0])
    document["recovered_layer_triage"] = entries[1:]
    failed = sum(item["status"] == "failed" for item in entries)
    partial = sum(item["status"] == "partial" for item in entries)
    status = "failed" if failed == len(entries) else ("partial" if failed or partial else "complete")
    document["analysis_coverage"] = {
        "status": status,
        "layer_count": len(entries),
        "complete_layers": sum(item["status"] == "complete" for item in entries),
        "partial_layers": partial,
        "failed_layers": failed,
    }
    document["executed_sample"] = False
    document["network_contacted"] = False
    return document, status


INCOMPLETE_STATIC_STATUSES = frozenset(
    {
        "bounded_limit",
        "corrupt_or_truncated",
        "failed",
        "malformed_metadata",
        "member_limit_applied",
        "parse_failed",
        "partially_extracted",
        "ratio_blocked",
        "size_blocked",
        "size_mismatch",
        "total_size_blocked",
    }
)
INCOMPLETE_STATIC_STATUS_TOKENS = (
    "blocked",
    "corrupt",
    "encrypted",
    "error",
    "failed",
    "incomplete",
    "invalid",
    "limit",
    "malformed",
    "mismatch",
    "partial",
    "timeout",
    "truncated",
    "unavailable",
)


def _is_incomplete_static_status(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    normalized = value.strip().casefold()
    return normalized in INCOMPLETE_STATIC_STATUSES or any(
        token in normalized for token in INCOMPLETE_STATIC_STATUS_TOKENS
    )


def _completed_in_memory_lzx_cab(report: dict[str, Any]) -> bool:
    """全検証契約を満たすpure-Python LZX CAB成功だけを承認する。"""

    if report.get("format") != "cab":
        return False
    cab = report.get("cab")
    if not isinstance(cab, dict):
        return False
    contract = cab.get("in_memory_extraction")
    preflight = cab.get("preflight")
    inventory = cab.get("inventory")
    if not all(isinstance(item, dict) for item in (contract, preflight)):
        return False
    if not isinstance(inventory, list) or not inventory:
        return False
    if not all(isinstance(item, dict) for item in inventory):
        return False
    normalized_names = [str(item.get("name", "")).replace("\\", "/") for item in inventory]
    try:
        invalid_name = any(
            not name
            or len(name.encode("utf-8")) > 4096
            or name.startswith("/")
            or re.match(r"^[A-Za-z]:", name)
            or any(part in {"", ".", ".."} for part in name.split("/"))
            for name in normalized_names
        )
    except UnicodeEncodeError:
        return False
    if invalid_name:
        return False
    if len({name.casefold() for name in normalized_names}) != len(normalized_names):
        return False
    counts = (
        cab.get("member_count"),
        contract.get("member_count"),
        preflight.get("file_count"),
        contract.get("data_block_count"),
        contract.get("checksum_blocks_verified"),
        preflight.get("data_block_count"),
        preflight.get("checksum_blocks_required"),
        preflight.get("checksum_blocks_verified"),
    )
    if any(isinstance(value, bool) or not isinstance(value, int) for value in counts):
        return False
    member_count = counts[0]
    data_block_count = counts[3]
    if member_count <= 0 or data_block_count <= 0:
        return False
    if counts[:3] != (member_count, member_count, member_count):
        return False
    if counts[3:] != (data_block_count,) * 5:
        return False
    if len(inventory) != member_count:
        return False
    if any(
        item.get("status") != "extracted"
        or not isinstance(item.get("name"), str)
        or isinstance(item.get("size"), bool)
        or not isinstance(item.get("size"), int)
        or item.get("size") < 0
        or re.fullmatch(r"[0-9a-f]{64}", str(item.get("sha256"))) is None
        for item in inventory
    ):
        return False
    declared_total = preflight.get("declared_file_total_size")
    if (
        isinstance(declared_total, bool)
        or not isinstance(declared_total, int)
        or declared_total < 0
        or cab.get("extracted_total_size") != declared_total
        or sum(item["size"] for item in inventory) != declared_total
    ):
        return False
    peak_memory_budget = preflight.get("lzx_peak_memory_budget")
    contract_peak_memory_budget = contract.get("peak_memory_budget")
    if not isinstance(peak_memory_budget, dict) or contract_peak_memory_budget != peak_memory_budget:
        return False
    memory_fields = (
        "worker_limit_bytes",
        "runtime_reserve_bytes",
        "input_bytes",
        "folder_cache_bytes",
        "member_materialization_bytes",
        "decoder_window_bytes",
        "metadata_reserve_bytes",
        "estimated_peak_bytes",
        "headroom_bytes",
    )
    if any(
        isinstance(peak_memory_budget.get(field), bool) or not isinstance(peak_memory_budget.get(field), int)
        for field in memory_fields
    ):
        return False
    folder_count = preflight.get("folder_count")
    folder_output_total = preflight.get("declared_folder_output_total_size")
    cabinet_size = preflight.get("cabinet_size")
    window_bits = preflight.get("lzx_window_bits")
    if (
        isinstance(folder_count, bool)
        or not isinstance(folder_count, int)
        or folder_count <= 0
        or isinstance(folder_output_total, bool)
        or not isinstance(folder_output_total, int)
        or folder_output_total < declared_total
        or isinstance(cabinet_size, bool)
        or not isinstance(cabinet_size, int)
        or cabinet_size <= 0
        or not isinstance(window_bits, list)
        or not window_bits
        or any(
            isinstance(value, bool)
            or not isinstance(value, int)
            or not CAB_LZX_MIN_WINDOW_BITS <= value <= CAB_LZX_MAX_WINDOW_BITS
            for value in window_bits
        )
    ):
        return False
    expected_metadata_reserve = (
        member_count * CAB_LZX_MEMBER_METADATA_RESERVE_BYTES
        + folder_count * CAB_LZX_FOLDER_METADATA_RESERVE_BYTES
        + data_block_count * CAB_LZX_BLOCK_METADATA_RESERVE_BYTES
        + MAX_CAB_BLOCK_UNCOMPRESSED_SIZE
    )
    expected_estimated_peak = sum(
        peak_memory_budget[field]
        for field in (
            "runtime_reserve_bytes",
            "input_bytes",
            "folder_cache_bytes",
            "member_materialization_bytes",
            "decoder_window_bytes",
            "metadata_reserve_bytes",
        )
    )
    if (
        peak_memory_budget.get("status") != "passed"
        or peak_memory_budget["worker_limit_bytes"] != MAX_CAB_LZX_WORKER_MEMORY_BYTES
        or peak_memory_budget["runtime_reserve_bytes"] != CAB_LZX_RUNTIME_MEMORY_RESERVE_BYTES
        or peak_memory_budget["input_bytes"] != cabinet_size
        or peak_memory_budget["folder_cache_bytes"] != folder_output_total
        or peak_memory_budget["member_materialization_bytes"] != declared_total
        or peak_memory_budget["decoder_window_bytes"] != 1 << max(window_bits)
        or peak_memory_budget["metadata_reserve_bytes"] != expected_metadata_reserve
        or peak_memory_budget["estimated_peak_bytes"] != expected_estimated_peak
        or peak_memory_budget["headroom_bytes"] != peak_memory_budget["worker_limit_bytes"] - expected_estimated_peak
        or peak_memory_budget["headroom_bytes"] < 0
    ):
        return False
    required_values = {
        "cab_status": cab.get("status") in {"artifacts_recovered", "no_artifact_recovered"},
        "cab_parser": cab.get("parser") == "binary-refinery",
        "cab_backend": cab.get("backend") == "in_memory_python",
        "fallback_attempted": cab.get("lzx_fallback_attempted") is True,
        "fallback_completed": cab.get("lzx_fallback_completed") is True,
        "fallback_source": cab.get("fallback_from") == "cabarchive_lzx_unsupported",
        "preflight_status": preflight.get("status") == "passed",
        "preflight_compression": preflight.get("compression") == "lzx",
        "preflight_bounds": preflight.get("bounds_validation") == "passed",
        "preflight_paths": preflight.get("path_validation") == "passed",
        "preflight_single_volume": preflight.get("multi_volume") is False,
        "contract_version": contract.get("contract_version") == 2,
        "contract_status": contract.get("status") == "complete",
        "contract_parser": contract.get("parser") == "binary-refinery",
        "contract_backend": contract.get("backend") == "in_memory_python",
        "contract_compression": contract.get("compression") == "lzx",
        "contract_preflight": contract.get("preflight_status") == "passed",
        "contract_checksum": contract.get("checksum_status") == "verified",
        "contract_inventory": contract.get("complete_member_inventory") is True,
        "contract_paths": contract.get("path_validation") == "passed",
        "contract_declared_size": contract.get("declared_size_validation") == "passed",
        "contract_actual_size": contract.get("actual_size_validation") == "passed",
        "contract_order": contract.get("deterministic_member_order") is True,
        "contract_single_volume": contract.get("multi_volume") is False,
    }
    if not all(required_values.values()):
        return False
    for source in (cab, contract):
        if any(
            source.get(field) is not False
            for field in (
                "executed",
                "network_contacted",
                "external_process_started",
                "disk_written",
            )
        ):
            return False
    return True


def _completed_in_memory_cabarchive_cab(report: dict[str, Any]) -> bool:
    """全preflightとinventoryが一致する通常cabarchive CAB成功だけを承認する。"""

    if report.get("format") != "cab":
        return False
    report_size = report.get("size")
    report_sha256 = report.get("sha256")
    if (
        isinstance(report_size, bool)
        or not isinstance(report_size, int)
        or report_size <= 0
        or not isinstance(report_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", report_sha256) is None
        or report.get("executed") is not False
        or report.get("network_contacted") is not False
    ):
        return False

    cab = report.get("cab")
    if not isinstance(cab, dict):
        return False
    preflight = cab.get("preflight")
    inventory = cab.get("inventory")
    if not isinstance(preflight, dict) or not isinstance(inventory, list) or not inventory:
        return False
    if any(
        key in cab
        for key in (
            "error",
            "error_type",
            "failure_reason",
            "fallback_from",
            "in_memory_extraction",
        )
    ):
        return False

    numeric_values = (
        cab.get("member_count"),
        cab.get("extracted_total_size"),
        preflight.get("cabinet_size"),
        preflight.get("folder_count"),
        preflight.get("file_count"),
        preflight.get("data_block_count"),
        preflight.get("declared_file_total_size"),
        preflight.get("declared_folder_output_total_size"),
        preflight.get("checksum_blocks_required"),
        preflight.get("checksum_blocks_verified"),
    )
    if any(isinstance(value, bool) or not isinstance(value, int) for value in numeric_values):
        return False
    (
        member_count,
        extracted_total_size,
        cabinet_size,
        folder_count,
        file_count,
        data_block_count,
        declared_file_total_size,
        declared_folder_output_total_size,
        checksum_blocks_required,
        checksum_blocks_verified,
    ) = numeric_values
    if (
        member_count <= 0
        or folder_count <= 0
        or data_block_count <= 0
        or member_count != file_count
        or member_count != len(inventory)
        or cabinet_size != report_size
        or extracted_total_size < 0
        or declared_file_total_size < 0
        or extracted_total_size != declared_file_total_size
        or declared_folder_output_total_size < declared_file_total_size
        or checksum_blocks_required != 0
        or checksum_blocks_verified < 0
        or checksum_blocks_verified > data_block_count
    ):
        return False

    names: list[str] = []
    inventory_total_size = 0
    for item in inventory:
        if not isinstance(item, dict):
            return False
        name = item.get("name")
        size = item.get("size")
        digest = item.get("sha256")
        member_format = item.get("format")
        if (
            item.get("status") != "extracted"
            or not isinstance(name, str)
            or not name
            or isinstance(size, bool)
            or not isinstance(size, int)
            or size < 0
            or not isinstance(digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            or not isinstance(member_format, str)
            or not member_format
            or len(member_format) > 128
        ):
            return False
        normalized_name = name.replace("\\", "/")
        try:
            invalid_name = (
                normalized_name != name
                or len(name.encode("utf-8")) > 4096
                or name.startswith("/")
                or re.match(r"^[A-Za-z]:", name) is not None
                or any(part in {"", ".", ".."} for part in name.split("/"))
            )
        except UnicodeEncodeError:
            return False
        if invalid_name:
            return False
        names.append(name)
        inventory_total_size += size
    if (
        len({name.casefold() for name in names}) != len(names)
        or names != sorted(names, key=lambda name: (name.casefold(), name))
        or inventory_total_size != declared_file_total_size
    ):
        return False

    required_values = {
        "cab_status": cab.get("status") in {"artifacts_recovered", "no_artifact_recovered"},
        "cab_parser": cab.get("parser") == "cabarchive",
        "cab_backend": cab.get("backend") == "in_memory_python",
        "cab_order": cab.get("deterministic_member_order") is True,
        "fallback_attempted": cab.get("lzx_fallback_attempted") is False,
        "fallback_completed": cab.get("lzx_fallback_completed") is False,
        "preflight_status": preflight.get("status") == "passed",
        "preflight_compression": preflight.get("compression")
        in {"none", "mszip", "none_or_mszip"},
        "preflight_no_lzx_windows": preflight.get("lzx_window_bits") == [],
        "preflight_no_lzx_budget": "lzx_peak_memory_budget" not in preflight,
        "preflight_bounds": preflight.get("bounds_validation") == "passed",
        "preflight_paths": preflight.get("path_validation") == "passed",
        "preflight_single_volume": preflight.get("multi_volume") is False,
    }
    if not all(required_values.values()):
        return False
    return not any(
        cab.get(field) is not False
        for field in (
            "executed",
            "network_contacted",
            "external_process_started",
            "disk_written",
        )
    )


def _static_layer_issues(layer_report: dict[str, Any]) -> list[str]:
    """静的復元stepの失敗、深度上限、parser上限を決定的に列挙する。"""

    issues: list[str] = []
    steps = layer_report.get("steps")
    if not isinstance(steps, list):
        steps = []
    dotnet_recovered_layers = {
        str(step.get("input_layer", {}).get("sha256"))
        for step in steps
        if isinstance(step, dict)
        and isinstance(step.get("input_layer"), dict)
        and isinstance(step.get("report"), dict)
        and isinstance(step["report"].get("dotnet_bundle"), dict)
        and step["report"]["dotnet_bundle"].get("status") == "recovered"
    }

    def visit(value: Any, path: str) -> None:
        if isinstance(value, dict):
            for raw_key, item in value.items():
                key = str(raw_key).casefold()
                child = f"{path}.{raw_key}"
                fallback = value.get("sevenzip")
                authoritative = value.get("embedded_installer_archive")
                recovered = value.get("recovered")
                embedded_dotnet_recovered = isinstance(recovered, list) and any(
                    isinstance(candidate, dict)
                    and candidate.get("kind") == "embedded-pe"
                    and candidate.get("sha256") in dotnet_recovered_layers
                    for candidate in recovered
                )
                if (
                    key == "sevenzip"
                    and isinstance(item, dict)
                    and item.get("status") == "partially_extracted"
                    and isinstance(authoritative, dict)
                    and authoritative.get("status") == "artifacts_recovered"
                    and int(authoritative.get("record_count") or 0) > 0
                ):
                    continue
                if (
                    key in {"cab", "dotnet_bundle"}
                    and isinstance(item, dict)
                    and item.get("status") == "parse_failed"
                    and (
                        (
                            isinstance(fallback, dict)
                            and fallback.get("status") == "extracted"
                            and fallback.get("extract_exit_code") == 0
                        )
                        or (key == "dotnet_bundle" and embedded_dotnet_recovered)
                    )
                ):
                    # cabarchiveが未対応のLZXでも、境界付き7-Zip fallbackが
                    # 全memberを正常展開できた場合は未完了にしない。
                    continue
                if item == "validation_failed" and ".profiled_transforms.attempts[" in path:
                    continue
                if key == "unpack_status" and _is_incomplete_static_status(item):
                    issues.append(f"{child}:{item}")
                elif key == "status" and _is_incomplete_static_status(item):
                    issues.append(f"{child}:{item}")
                elif (key == "parse_error" or key.endswith("_error")) and (
                    item is not None and item is not False and item != ""
                ):
                    issues.append(child)
                visit(item, child)
        elif isinstance(value, list):
            for index, item in enumerate(value):
                visit(item, f"{path}[{index}]")

    for index, step in enumerate(steps):
        if not isinstance(step, dict):
            issues.append(f"steps[{index}]:invalid")
            continue
        step_status = step.get("status")
        if _is_incomplete_static_status(step_status):
            issues.append(f"steps[{index}]:{step_status}")
        visit(step.get("report"), f"steps[{index}].report")
        report = step.get("report")
        if isinstance(report, dict) and "sevenzip" not in report:
            in_memory_cab_complete = _completed_in_memory_lzx_cab(
                report
            ) or _completed_in_memory_cabarchive_cab(report)
            if report.get("format") in {"7z", "apple-disk-image", "cab", "rar"} and not (
                report.get("format") == "cab" and in_memory_cab_complete
            ):
                issues.append(f"steps[{index}].report:container_extractor_unavailable")
            pe_report = report.get("pe")
            if isinstance(pe_report, dict) and pe_report.get("containerized") is True:
                issues.append(f"steps[{index}].report:pe_container_extractor_unavailable")
    return sorted(set(issues))


def _handler_static_logic_records(
    case_dir: Path,
    executions: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """成功ハンドラーが公開した代表関数をcaseの標準ロジックへ集約する。"""

    records: list[dict[str, Any]] = []
    root = case_dir.resolve()
    for execution in executions:
        if execution.get("status") != "succeeded":
            continue
        relative = execution.get("result")
        if not isinstance(relative, str):
            continue
        candidate = (case_dir / relative).resolve()
        try:
            candidate.relative_to(root)
        except ValueError:
            continue
        if not candidate.is_file():
            continue
        artifact = load_json_object_strict(candidate)
        payload = artifact.get("result")
        functions = payload.get("representative_functions") if isinstance(payload, dict) else None
        if not isinstance(functions, list):
            continue
        records.extend(item for item in functions[:128] if isinstance(item, dict))
    return records[:512]


def _handler_static_logic_program_evidence(
    case_dir: Path,
    executions: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """成功handlerが公開したprogram inventoryを標準ロジックへ集約する。"""

    programs: list[dict[str, Any]] = []
    root = case_dir.resolve()
    for execution in executions:
        if execution.get("status") != "succeeded":
            continue
        relative = execution.get("result")
        if not isinstance(relative, str):
            continue
        candidate = (case_dir / relative).resolve()
        try:
            candidate.relative_to(root)
        except ValueError:
            continue
        if not candidate.is_file():
            continue
        artifact = load_json_object_strict(candidate)
        payload = artifact.get("result")
        supplied = payload.get("program_evidence") if isinstance(payload, dict) else None
        if isinstance(supplied, list):
            programs.extend(item for item in supplied[:16] if isinstance(item, dict))
    return programs[:64]


def _verified_outputs_from_wrapper(value: Any) -> list[dict[str, Any]]:
    """handler wrapperが生成した検証済みbinary metadataだけを返す。"""

    if not isinstance(value, dict):
        return []
    supplied = value.get("verified_binary_outputs")
    if not isinstance(supplied, list) or not supplied:
        supplied = value.get("observed_binary_outputs")
    if not isinstance(supplied, list):
        return []
    return [item for item in supplied if isinstance(item, dict)]


def _verified_output_audit_from_wrapper(value: Any) -> dict[str, Any] | None:
    """handler wrapperの保持・後続解析auditを改変せずoutcome境界へ渡す。"""

    if not isinstance(value, dict):
        return None
    supplied = value.get("verified_binary_output_audit")
    return supplied if isinstance(supplied, dict) else None


def _legacy_outcome_handler_records(
    case_dir: Path,
    executions: list[dict[str, Any]],
    specs: list[HandlerSpec],
    *,
    wrapper_overrides: Mapping[Path, dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """既存handler結果をfamily付きのoutcome証拠へ正規化する。"""

    by_id = {spec.id: spec for spec in specs}
    records = []
    for execution in executions:
        handler_id = execution.get("handler_id")
        spec = by_id.get(handler_id)
        if spec is None:
            continue
        record = {
            "source": "selected_family_analysis",
            "family": spec.family,
            "handler_id": handler_id,
            "status": execution.get("status"),
            "selected_evidence": execution.get("selected_evidence"),
            "selected_layer_sha256": execution.get("selected_layer_sha256"),
        }
        relative = execution.get("result")
        if isinstance(relative, str):
            wrapper_path = resolve_case_artifact(case_dir, relative)
            wrapper = wrapper_overrides.get(wrapper_path) if wrapper_overrides is not None else None
            if wrapper is None:
                wrapper = load_json_object_strict(wrapper_path)
            record["result"] = wrapper
            verified = _verified_outputs_from_wrapper(wrapper)
            if verified:
                record["verified_binary_outputs"] = verified
            audit = _verified_output_audit_from_wrapper(wrapper)
            if audit is not None:
                record["verified_binary_output_audit"] = audit
        records.append(record)
    return records


def _candidate_outcome_handler_records(assessment: dict[str, Any]) -> list[dict[str, Any]]:
    """候補handlerの全試行をfamily付きのoutcome証拠へ正規化する。"""

    records = []
    for family_result in assessment.get("families") or []:
        if not isinstance(family_result, dict):
            continue
        family = family_result.get("family")
        for attempt in family_result.get("attempts") or []:
            if not isinstance(attempt, dict):
                continue
            supplied_source = attempt.get("source")
            source = (
                supplied_source if isinstance(supplied_source, str) and supplied_source else "candidate_verification"
            )
            records.append(
                {
                    "source": source,
                    "family": family,
                    "handler_id": attempt.get("handler_id"),
                    "status": attempt.get("status"),
                    "handler_evidence": attempt.get("handler_evidence"),
                    "detector_corroboration": attempt.get("detector_corroboration"),
                    "selected_layer_sha256": (
                        attempt.get("selected_layer_sha256") or (attempt.get("layer") or {}).get("sha256")
                    ),
                    "verified_binary_outputs": _verified_outputs_from_wrapper(attempt.get("result")),
                    "verified_binary_output_audit": _verified_output_audit_from_wrapper(attempt.get("result")),
                    "result": attempt.get("result"),
                }
            )
    return records


def _candidate_automation_handler_results(
    assessment: Mapping[str, Any],
    *,
    resolved_family: str | None,
) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    """detectorで相関済みの候補handler結果だけを通信成果物へ射影する。

    candidate verificationは、既存分類器が一意選択できなかった場合だけ走る。
    その結果は従来family解決には使われていた一方、config／C2成果物へ渡されて
    いなかった。ここではfamily解決と同じく``corroborated``だけを受理し、
    handler wrapper、layer hash、十分性を再確認して既存の厳格な
    ``trusted_handler_result``入力へ変換する。metadata hint単独やhandlerの
    自己申告だけでは射影しない。
    """

    if not isinstance(resolved_family, str) or not resolved_family:
        return []
    projected: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for family_result in assessment.get("families") or []:
        if (
            not isinstance(family_result, Mapping)
            or family_result.get("family") != resolved_family
            or family_result.get("confirmed") is not True
            or family_result.get("status") != "confirmed"
        ):
            continue
        for attempt in family_result.get("attempts") or []:
            if not isinstance(attempt, Mapping) or attempt.get("status") != "corroborated":
                continue
            evidence = attempt.get("handler_evidence")
            corroboration = attempt.get("detector_corroboration")
            wrapper = attempt.get("result")
            layer = attempt.get("layer")
            handler_id = attempt.get("handler_id")
            if (
                not isinstance(evidence, Mapping)
                or evidence.get("sufficient") is not True
                or not isinstance(corroboration, Mapping)
                or corroboration.get("corroborated") is not True
                or not isinstance(wrapper, Mapping)
                or wrapper.get("executed_sample") is not False
                or wrapper.get("network_contacted") is not False
                or not isinstance(layer, Mapping)
                or not isinstance(layer.get("sha256"), str)
                or not isinstance(handler_id, str)
                or not handler_id
            ):
                continue
            handler = wrapper.get("handler")
            if (
                not isinstance(handler, Mapping)
                or handler.get("id") != handler_id
                or handler.get("family") != resolved_family
            ):
                continue
            public_evidence = dict(evidence)
            public_layer = {
                key: layer[key]
                for key in (
                    "name",
                    "sha256",
                    "parent_sha256",
                    "depth",
                    "transform",
                    "format",
                    "size",
                )
                if key in layer
            }
            execution = {
                "source": "candidate_verification",
                "handler_id": handler_id,
                "status": "succeeded",
                "selected_evidence": public_evidence,
                "selected_layer_sha256": layer["sha256"],
                "detector_corroboration": dict(corroboration),
            }
            artifact = {
                **dict(wrapper),
                "selected_evidence": public_evidence,
                "selected_layer": public_layer,
            }
            projected.append((execution, artifact))
    return projected


def _outcome_candidates(
    routing: dict[str, Any],
    layers: list[StaticLayer],
    logic_report: dict[str, Any],
    requirements_policy: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """binaryの未完了関数解析を候補familyの必須gateへ反映する。"""

    function_required = not function_analysis_is_available(logic_report) and any(
        detect_format(layer.data, layer.name) in BINARY_FORMATS for layer in layers
    )
    candidates = []
    for supplied in routing.get("candidates") or []:
        if not isinstance(supplied, dict):
            continue
        candidate = dict(supplied)
        family = candidate.get("family")
        policy = requirements_policy.get(family) if isinstance(family, str) else None
        requirements = {
            "policy_declared": policy is not None,
            "policy_category": policy.get("category") if policy is not None else None,
            "config_required": policy.get("config_required") if policy is not None else None,
            "network_required": policy.get("network_required") if policy is not None else None,
            "terminal_payload_required": (policy.get("terminal_payload_required") if policy is not None else None),
        }
        if function_required:
            requirements["function_analysis_required"] = True
        candidate["requirements"] = requirements
        candidates.append(candidate)
    return candidates


def _public_outcome_handler_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """秘密値やhandler本文を除いた証拠索引を返す。"""

    return [
        {
            key: record.get(key)
            for key in (
                "source",
                "family",
                "handler_id",
                "status",
                "selected_evidence",
                "handler_evidence",
                "detector_corroboration",
                "selected_layer_sha256",
                "verified_binary_outputs",
                "verified_binary_output_audit",
            )
        }
        for record in records
    ]


def _automation_summary_state(outcome: dict[str, Any]) -> str:
    """自動処理の結果をresolved・partial・unknownの排他的状態へ変換する。"""

    resolution = outcome.get("family_resolution")
    resolution_status = resolution.get("status") if isinstance(resolution, dict) else None
    blockers = set(outcome.get("blockers") or [])
    if outcome.get("status") == "complete" and resolution_status == "resolved":
        return "resolved"
    if resolution_status in {"unresolved", "ambiguous"} and blockers.issubset({"family_resolution"}):
        return "unknown"
    return "partial"


def _synchronize_completion_with_outcome(
    completion: dict[str, Any],
    outcome: Mapping[str, Any],
) -> None:
    """resolved familyでは厳格orchestration gateをcase stateへfail-closedで反映する。"""

    resolution = outcome.get("family_resolution")
    if not isinstance(resolution, Mapping) or resolution.get("status") != "resolved":
        return
    previous = [
        item
        for item in completion.get("blockers", [])
        if isinstance(item, str) and not item.startswith("orchestration:")
    ]
    orchestration_blockers = [
        f"orchestration:{item}" for item in outcome.get("blockers", []) if isinstance(item, str) and item
    ]
    blockers = sorted(set((*previous, *orchestration_blockers)))
    completion["blockers"] = blockers
    if blockers:
        if completion.get("status") != "failed":
            completion["status"] = "partial"
        completion["complete"] = False
        completion["resumable"] = False
    elif completion.get("status") != "failed":
        completion["status"] = "complete"
        completion["complete"] = True
        completion["resumable"] = True


def _apply_requirements_policy_gate(
    outcome: dict[str, Any],
    requirements_policy: dict[str, dict[str, Any]],
) -> None:
    """resolved familyにpolicy宣言がない場合、completeをfail-closedで拒否する。"""

    resolution = outcome.get("family_resolution")
    resolved = isinstance(resolution, dict) and resolution.get("status") == "resolved"
    resolved_family = resolution.get("family") if resolved else None
    declared = isinstance(resolved_family, str) and resolved_family in requirements_policy
    outcome["requirements_policy"] = {
        "schema_version": 1,
        "source": "registry/family_analysis_requirements.json",
        "declared_family_count": len(requirements_policy),
        "resolved_family": resolved_family,
    }
    outcome.setdefault("quality_gates", {})["requirements_policy"] = {
        "required": resolved,
        "satisfied": bool(not resolved or declared),
        "observed": declared if resolved else None,
        "status": "satisfied" if resolved and declared else ("required_missing" if resolved else "not_applicable"),
    }
    if resolved and not declared:
        blockers = set(outcome.get("blockers") or [])
        blockers.add("requirements_policy")
        outcome["blockers"] = sorted(blockers)
        outcome["status"] = "partial"
        actions = list(outcome.get("next_actions_ja") or [])
        action = "familyの必須config・通信先・最終payload policyをregistryへ宣言してください。"
        if action not in actions:
            actions.append(action)
        outcome["next_actions_ja"] = actions


def _completion_state(
    *,
    assessment_only: bool,
    generic_status: str,
    layer_report: dict[str, Any],
    layer_selections: list[dict[str, Any]],
    selected_families: list[str],
    applicability: list[dict[str, Any]],
    executions: list[dict[str, Any]],
    logic_report: dict[str, Any],
) -> dict[str, Any]:
    """再開・公開判断に使うcase完了状態とblockerを一箇所で算出する。"""

    blockers = []
    if generic_status == "failed":
        blockers.append("generic_triage_failed")
    elif generic_status == "partial":
        blockers.append("generic_triage_partial")
    limit_count = int((layer_report.get("counts") or {}).get("limit_events") or 0)
    if limit_count:
        blockers.append("static_layer_limit_reached")
    static_issues = _static_layer_issues(layer_report)
    if static_issues:
        blockers.append("static_layer_incomplete")

    detector_error_set: set[str] = set()
    for selection in layer_selections:
        if not isinstance(selection, dict):
            continue
        classification = selection.get("classification")
        if not isinstance(classification, dict):
            continue
        observations = classification.get("observations")
        if not isinstance(observations, dict):
            continue
        errors = observations.get("detector_errors")
        if isinstance(errors, dict):
            detector_error_set.update(str(family) for family in errors)
    detector_errors = sorted(detector_error_set)
    if detector_errors:
        blockers.append("detector_error_present")

    execution_values = [item for item in executions if isinstance(item, dict)]
    execution_statuses = [str(item.get("status")) for item in execution_values]
    incomplete_anchor_attempts = []
    if not assessment_only:
        for status in sorted(set(execution_statuses)):
            if status in {
                "failed",
                "preflight_failed",
                "no_evidence",
                "ambiguous_evidence",
                "incompatible_input_format",
            }:
                blockers.append(f"handler_{status}")

        applicable_handlers: dict[str, set[str]] = {family: set() for family in selected_families}
        for item in applicability:
            if not isinstance(item, dict):
                continue
            family = item.get("family")
            handler_id = item.get("id")
            if (
                family in applicable_handlers
                and isinstance(handler_id, str)
                and item.get("status") in {"applicable", "applicable_forced"}
            ):
                applicable_handlers[family].add(handler_id)
        successful_handlers = {
            str(item.get("handler_id")) for item in execution_values if item.get("status") == "succeeded"
        }
        for family, handler_ids in sorted(applicable_handlers.items()):
            if not handler_ids:
                blockers.append(f"selected_family_has_no_automatic_handler:{family}")
            elif not handler_ids.intersection(successful_handlers):
                blockers.append(f"selected_family_has_no_valid_handler_evidence:{family}")

        for execution in execution_values:
            for attempt in execution.get("attempts") or []:
                if not isinstance(attempt, dict) or attempt.get("routing_role") != "selected_family_layer":
                    continue
                attempt_status = attempt.get("status")
                if attempt_status in {"failed", "skipped_incompatible_format"} or (
                    attempt_status == "succeeded" and attempt.get("evidence_status") != "sufficient"
                ):
                    incomplete_anchor_attempts.append(
                        {
                            "handler_id": execution.get("handler_id"),
                            "layer_sha256": (attempt.get("layer") or {}).get("sha256"),
                            "status": attempt_status,
                        }
                    )
        if incomplete_anchor_attempts:
            blockers.append("selected_family_layer_incomplete")
        if not function_analysis_is_available(logic_report):
            blockers.append("representative_function_analysis_required")

    blockers = sorted(set(blockers))
    if assessment_only:
        status = "assessment_only_complete" if not blockers else "partial"
    elif not blockers and selected_families:
        status = "complete"
    elif not blockers:
        status = "triaged_unknown"
    elif generic_status == "failed" and "succeeded" not in execution_statuses:
        status = "failed"
    else:
        status = "partial"
    return {
        "status": status,
        "complete": status in {"complete", "assessment_only_complete"},
        "resumable": status in {"complete", "assessment_only_complete"},
        "blockers": blockers,
        "detector_error_families": detector_errors,
        "static_layer_issues": static_issues,
        "incomplete_selected_layer_attempts": incomplete_anchor_attempts,
    }


def _prepare_case_directory(output: Path, digest: str) -> Path:
    """再解析が確定したSHA-256 caseだけを検証後に空directoryへ初期化する。"""

    normalize_sha256_digest(digest)
    cases_root = output / "cases"
    cases_root.mkdir(parents=True, exist_ok=True)
    ensure_no_reparse_components(cases_root)
    resolved_root = cases_root.resolve(strict=True)
    case_dir = cases_root / digest
    ensure_no_reparse_components(case_dir)
    if case_dir.exists():
        ensure_tree_without_reparse(case_dir)
        resolved_case = case_dir.resolve(strict=True)
        if not resolved_case.is_dir() or resolved_case.parent != resolved_root or resolved_case.name != digest:
            raise ValueError(f"安全に初期化できないcase directoryです: {digest}")
        shutil.rmtree(case_dir)
    case_dir.mkdir()
    return case_dir


def _routing_classifications(layer_selections: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """公開quotaで省略する前の分類器評価を内部routing入力へ変換する。"""

    return [
        {
            "layer": selection["layer"].public(),
            "classification": selection["classification"],
        }
        for selection in layer_selections
    ]


def analyze_unit(
    unit: InputUnit,
    *,
    output: Path,
    registry: Path,
    specs: list[HandlerSpec],
    registered: set[str],
    forced_family: str | None,
    minimum_confidence: str,
    assessment_only: bool,
    analysis_contract: dict[str, Any],
    family_hint_manifest: dict[str, Any] | None = None,
    family_requirements_policy: dict[str, dict[str, Any]] | None = None,
    upx: Path | None = None,
    sevenzip: Path | None = None,
    diec: Path | None = None,
    innounp: Path | None = None,
    force_container_probe: bool = False,
    max_static_layers: int = MAX_STATIC_LAYERS,
    retry_max_static_layers: int | None = None,
    archive_password: str = "infected",
    string_scan_limit: int = DEFAULT_STRING_SCAN_LIMIT,
    follow_on_lineage: dict[str, Any] | None = None,
    inno_password: str = "",
) -> dict[str, Any]:
    """1検体を分類し、適用可能な既存静的解析器を一括実行する。"""

    digest = hashlib.sha256(unit.data).hexdigest()
    requirements_policy = (
        family_requirements_policy if family_requirements_policy is not None else _load_family_analysis_requirements()
    )
    case_dir = _prepare_case_directory(output, digest)
    classifier_family = forced_family if forced_family in registered else None
    if assessment_only:
        layers = [
            StaticLayer(
                name=unit.source_name,
                data=unit.data,
                sha256=digest,
                parent_sha256=None,
                depth=0,
                transform="submission",
            )
        ]
        layer_report = {
            "schema_version": 1,
            "status": "not_run_assessment_only",
            "layers": [layers[0].public()],
            "executed_sample": False,
            "network_contacted": False,
            "recovered_content_exported": False,
        }
    else:
        layers, layer_report = recover_static_layers(
            unit,
            upx=upx,
            sevenzip=sevenzip,
            diec=diec,
            innounp=innounp,
            force_container_probe=force_container_probe,
            max_static_layers=max_static_layers,
            archive_password=archive_password,
            inno_password=inno_password,
        )
        if retry_max_static_layers is not None and _layer_count_limit_reached(layer_report):
            initial_counts = layer_report.get("counts", {})
            initial_limit_events = layer_report.get("limit_events", [])
            layers, layer_report = recover_static_layers(
                unit,
                upx=upx,
                sevenzip=sevenzip,
                diec=diec,
                innounp=innounp,
                force_container_probe=force_container_probe,
                max_static_layers=retry_max_static_layers,
                archive_password=archive_password,
                inno_password=inno_password,
            )
            layer_report["adaptive_retry"] = {
                "trigger": "layer_count_limit",
                "initial_max_static_layers": max_static_layers,
                "retry_max_static_layers": retry_max_static_layers,
                "initial_counts": initial_counts,
                "initial_limit_event_count": (
                    len(initial_limit_events) if isinstance(initial_limit_events, list) else None
                ),
            }
    structural_candidate_report = structural_candidate_aggregation.build_structural_candidates(
        layer_report,
        assessment_only=assessment_only,
    )
    # 候補固有のstatusは復元stepとは別のtop-levelへ置き、
    # _static_layer_issuesの再帰走査へ混入させない。
    layer_report["structural_candidates"] = structural_candidate_report
    write_json(case_dir / "static-layers.json", layer_report)

    layer_selections: list[dict[str, Any]] = []
    public_classifications = []
    for layer in layers:
        classification = classify_sample.classify_bytes(
            layer.data,
            Path(layer.name),
            registry,
            classifier_family,
        )
        selected_family, selection_basis = _selected_family(
            classification,
            forced_family,
            minimum_confidence,
        )
        classification["one_shot_selection"] = {
            "family": selected_family,
            "basis": selection_basis,
            "forced_family_registered": (forced_family in registered if forced_family else None),
        }
        layer_selections.append(
            {
                "layer": layer,
                "classification": classification,
                "selected_family": selected_family,
                "selection_basis": selection_basis,
            }
        )
        public_classifications.append(
            {
                "layer": layer.public(),
                "classification": sanitize_public_value(classification),
            }
        )

    root_selection = layer_selections[0]
    root_classification = sanitize_public_value(root_selection["classification"])
    selected_families = sorted(
        {item["selected_family"] for item in layer_selections if item["selected_family"] is not None}
    )
    classification_document = {
        **root_classification,
        "root": root_classification,
        "layer_classifications": public_classifications,
        "selected_families": selected_families,
    }
    family_coverage = summarize_family_coverage(specs, registered)
    routing_family_coverage = [
        item
        for item in family_coverage
        if classify_sample.FAMILY_ID_RE.fullmatch(str(item.get("family", ""))) is not None
    ]
    metadata_hints = (
        classify_sample.family_hints_for_sha256(family_hint_manifest, digest)
        if family_hint_manifest is not None
        else []
    )
    family_hint_lineage = _family_hint_lineage_records(metadata_hints)
    family_hint_conflicts = _family_hint_conflicts(metadata_hints, selected_families)
    classification_document["family_hint_lineage"] = family_hint_lineage
    classification_document["classification_conflicts"] = family_hint_conflicts
    routing = classify_sample.build_family_routing_candidates(
        _routing_classifications(layer_selections),
        metadata_hints=metadata_hints,
        family_coverage=routing_family_coverage,
        operator_family=(forced_family if forced_family in registered else None),
    )
    write_json(case_dir / "family-routing.json", routing)
    applicability = assess_handlers(
        specs,
        layer_selections,
        forced_family,
        registered,
    )
    preflight = _preflight_applicable(specs, applicability)
    available = {item["handler_id"]: item for item in preflight}
    write_json(case_dir / "classification.json", classification_document)
    write_json(
        case_dir / "applicability.json",
        {
            "schema_version": 1,
            "selected_family": root_selection["selected_family"],
            "selected_families": selected_families,
            "selection_basis": root_selection["selection_basis"],
            "family_hint_lineage": family_hint_lineage,
            "classification_conflicts": family_hint_conflicts,
            "catalog": catalog_summary(specs),
            "family_coverage": summarize_family_coverage(specs, registered),
            "handlers": applicability,
            "preflight": preflight,
            "executed_sample": False,
            "network_contacted": False,
        },
    )

    generic_status = "not_run_assessment_only"
    if not assessment_only:
        generic, generic_status = _run_generic_triage(
            layers,
            case_dir,
            string_scan_limit=string_scan_limit,
        )
        write_json(case_dir / "generic-triage.json", generic)

    executions = []
    recovered_payload_directory: Path | None = None
    if not assessment_only:
        resolved_case = case_dir.resolve(strict=True)
        resolved_repository = REPOSITORY_ROOT.resolve(strict=True)
        if resolved_case != resolved_repository and resolved_repository not in resolved_case.parents:
            # WindowsのMAX_PATH余裕を確保するため、hash case配下は短い固定名にする。
            recovered_payload_directory = case_dir / "p"
            ensure_no_reparse_components(recovered_payload_directory)
            recovered_payload_directory.mkdir()
            ensure_no_reparse_components(recovered_payload_directory)
    specs_by_id = {item.id: item for item in specs}
    if not assessment_only:
        # 公開applicability順は保持し、実行対象だけを共有extractor優先で
        # handler round-robinへ渡す。各handlerの第1試行を第2試行より先に行う。
        execution_applicability = sorted(
            applicability,
            key=lambda item: (
                item.get("source") != "shared_extractor",
                item.get("campaign") is not None,
            ),
        )
        handler_states: list[dict[str, Any]] = []
        for item in execution_applicability:
            if item["status"] not in {"applicable", "applicable_forced"}:
                continue
            handler_id = item["id"]
            if not available.get(handler_id, {}).get("available"):
                handler_states.append(
                    {
                        "handler_id": handler_id,
                        "preflight_error": available.get(handler_id, {}).get("error"),
                    }
                )
                continue
            spec = specs_by_id[handler_id]
            handler_states.append(
                {
                    "handler_id": handler_id,
                    "spec": spec,
                    "plan": plan_handler_layers(spec, item, layers),
                    "cursor": 0,
                    "attempts": [],
                    "completed": [],
                    "truncated": False,
                    "budget_reason": None,
                }
            )
        _run_handler_rounds(
            [state for state in handler_states if "spec" in state],
            recovered_payload_directory=recovered_payload_directory,
        )
        executions = [
            _materialize_handler_state(state, case_dir)
            for state in handler_states
        ]

    candidate_assessment = _candidate_handler_assessment(
        routing=routing,
        layers=layers,
        layer_classifications=public_classifications,
        specs=specs,
        assessment_only=assessment_only,
        artifact_directory=recovered_payload_directory,
    )
    if recovered_payload_directory is not None:
        ensure_no_reparse_components(recovered_payload_directory)
        retained_directory_information = recovered_payload_directory.lstat()
        if not stat.S_ISDIR(retained_directory_information.st_mode) or int(
            getattr(retained_directory_information, "st_file_attributes", 0)
        ) & int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)):
            raise ValueError("保持payload directoryが通常directoryではありません")
        with os.scandir(recovered_payload_directory) as retained_entries:
            retained_entry = next(retained_entries, None)
        if retained_entry is None:
            recovered_payload_directory.rmdir()
            recovered_payload_directory = None
    write_json(case_dir / "candidate-handler-assessment.json", candidate_assessment)
    route_config_candidates = handler_evidence.build_route_config_candidate_document(
        sha256=digest,
        assessment=candidate_assessment,
    )
    write_json(case_dir / "route-config-candidates.json", route_config_candidates)

    report = {
        "schema_version": 1,
        "sample": {
            "sha256": digest,
            "size": len(unit.data),
            "source_name": unit.source_name,
            "input_kind": unit.input_kind,
            "outer_sha256": unit.outer_sha256,
            "outer_size": unit.outer_size,
            "member_name": unit.member_name,
        },
        "classification": {
            "family": root_classification.get("malware_type"),
            "confidence": root_classification.get("malware_type_confidence"),
            "campaign": root_classification.get("campaign_type"),
            "selected_family": root_selection["selected_family"],
            "selected_families": selected_families,
            "selection_basis": root_selection["selection_basis"],
            "family_hint_lineage": family_hint_lineage,
            "classification_conflicts": family_hint_conflicts,
        },
        "static_layers": "static-layers.json",
        "structural_candidates": structural_candidate_aggregation.structural_candidate_summary(
            structural_candidate_report
        ),
        "generic_triage": generic_status,
        "analysis_contract": analysis_contract,
        "handler_executions": executions,
        "assessment_only": assessment_only,
        "ai_used": False,
        "executed_sample": False,
        "network_contacted": False,
        "limitations": [
            "検体と復元層は実行していません。",
            "外部ホストへの接続、C2 probe、stage取得は行っていません。",
            "unknownまたは曖昧な判定ではファミリー固有解析器を自動流用しません。",
            "手動確認対象の特殊解析器はapplicability.jsonへ理由付きで残します。",
        ],
    }
    write_json(case_dir / "report.json", report)
    if follow_on_lineage is not None:
        report["follow_on_lineage"] = sanitize_public_value(follow_on_lineage)
    handler_logic_records = _handler_static_logic_records(case_dir, executions)
    handler_program_evidence = _handler_static_logic_program_evidence(case_dir, executions)
    automated_binary_analysis = _run_pe_function_analysis_isolated(
        layers,
        assessment_only=assessment_only,
    )
    logic_report = build_static_logic_report(
        sha256=digest,
        family=root_selection["selected_family"] or root_classification.get("malware_type"),
        source_name=unit.source_name,
        data=None if assessment_only or handler_logic_records else unit.data,
        records=handler_logic_records,
        program_evidence=handler_program_evidence,
        automated_binary_analysis=automated_binary_analysis,
        analysis_source=(
            "campaign_handler_representative_functions" if handler_logic_records else "one_shot_static_analysis"
        ),
    )
    write_json(case_dir / "static-logic.json", logic_report)
    (case_dir / "STATIC-LOGIC.md").write_text(render_static_logic_markdown(logic_report), encoding="utf-8")
    profile = build_case_profile(case_dir)
    write_json(case_dir / "features.json", profile)
    (case_dir / "FEATURES.md").write_text(render_features_markdown(profile), encoding="utf-8")
    rules = load_rules(CAMPAIGN_CORRELATION_RULES)
    evidence = extract_campaign_evidence(case_dir, profile, rules)
    if CAMPAIGN_FINGERPRINTS.is_file():
        fingerprints = load_json_object_strict(CAMPAIGN_FINGERPRINTS)
    else:
        fingerprints = {"schema_version": 1, "fingerprints": []}
    campaign_labels = match_fingerprints(evidence, fingerprints)
    write_json(
        case_dir / "campaign-labels.json",
        {
            "schema_version": 1,
            "sha256": digest,
            "labels": campaign_labels,
            "status": "matched" if campaign_labels else "no_strong_match",
            "rule_source": "registry/campaign_fingerprints.json",
            "executed_sample": False,
            "network_contacted": False,
            "safety": {
                "samples_opened": False,
                "samples_executed": False,
                "network_contacted": False,
            },
        },
    )
    legacy_outcome_records = _legacy_outcome_handler_records(case_dir, executions, specs)
    candidate_outcome_records = _candidate_outcome_handler_records(candidate_assessment)
    outcome_handler_records = legacy_outcome_records + candidate_outcome_records
    outcome_candidates = _outcome_candidates(
        routing,
        layers,
        logic_report,
        requirements_policy,
    )
    family_resolution = orchestration_outcome.resolve_family(
        outcome_candidates,
        outcome_handler_records,
    )

    handler_results: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for execution in executions:
        relative = execution.get("result")
        if not isinstance(relative, str):
            continue
        handler_results.append(
            (
                execution,
                load_json_object_strict(resolve_case_artifact(case_dir, relative)),
            )
        )
    automation_family = family_resolution.get("family")
    if not isinstance(automation_family, str) or not automation_family:
        automation_family = "unclassified"
    handler_results.extend(
        _candidate_automation_handler_results(
            candidate_assessment,
            resolved_family=(
                automation_family if automation_family != "unclassified" else None
            ),
        )
    )
    communication_patterns, c2_analysis = automated_case_analysis.build_case_automation_artifacts(
        sha256=digest,
        family=automation_family,
        layer_report=layer_report,
        handler_results=handler_results,
    )
    write_json(case_dir / "communication-patterns.json", communication_patterns)
    write_json(case_dir / "c2-analysis.json", c2_analysis)

    outcome = orchestration_outcome.build_outcome(
        sample_sha256=digest,
        generic_status=generic_status,
        layer_status=(
            "not_run_assessment_only"
            if assessment_only
            else ("complete" if not _static_layer_issues(layer_report) else "partial")
        ),
        candidates=outcome_candidates,
        handler_records=outcome_handler_records,
        function_analysis_available=function_analysis_is_available(logic_report),
    )
    outcome["family_resolution"] = family_resolution
    _apply_requirements_policy_gate(outcome, requirements_policy)
    outcome["handler_evidence"] = _public_outcome_handler_records(outcome_handler_records)
    outcome["artifacts"] = {
        "routing": "family-routing.json",
        "candidate_handler_assessment": "candidate-handler-assessment.json",
        "route_config_candidates": "route-config-candidates.json",
    }
    write_json(case_dir / "orchestration.json", outcome)

    completion = _completion_state(
        assessment_only=assessment_only,
        generic_status=generic_status,
        layer_report=layer_report,
        layer_selections=layer_selections,
        selected_families=selected_families,
        applicability=applicability,
        executions=executions,
        logic_report=logic_report,
    )
    if (
        completion["status"] == "triaged_unknown"
        and outcome.get("status") == "complete"
        and family_resolution.get("status") == "resolved"
        and not outcome.get("blockers")
    ):
        completion["status"] = "complete"
        completion["complete"] = True
        completion["resumable"] = True
        completion["automation_family"] = family_resolution.get("family")
        completion["automation_promotion"] = "strong_evidence_without_legacy_blockers"
    _synchronize_completion_with_outcome(completion, outcome)
    report["knowledge_artifacts"] = {
        "features": "features.json",
        "features_markdown": "FEATURES.md",
        "campaign_labels": "campaign-labels.json",
        "static_logic": "static-logic.json",
        "static_logic_markdown": "STATIC-LOGIC.md",
        "communication_patterns": "communication-patterns.json",
        "c2_analysis": "c2-analysis.json",
        "route_config_candidates": "route-config-candidates.json",
    }
    report["case_state"] = completion
    report["classification"]["automation_family"] = family_resolution.get("family")
    report["classification"]["automation_status"] = family_resolution.get("status")
    report["candidate_handler_assessment"] = {
        "status": candidate_assessment.get("status"),
        "planned_attempt_count": candidate_assessment.get("planned_attempt_count", 0),
    }
    report["route_config_candidates"] = {
        "status": route_config_candidates["status"],
        "status_scope": route_config_candidates["status_scope"],
        "projection_disposition": route_config_candidates["projection_disposition"],
        "projection_reason": route_config_candidates["projection_reason"],
        "overall_analysis_result_affected": route_config_candidates[
            "overall_analysis_result_affected"
        ],
        "candidate_count": route_config_candidates["candidate_count"],
        "candidate_set_complete": route_config_candidates["candidate_set_complete"],
        "family_attribution_confirmed": False,
        "used_for_c2_confirmation": False,
    }
    report["orchestration"] = "orchestration.json"
    report["knowledge_artifacts"].update(
        {
            "family_routing": "family-routing.json",
            "candidate_handler_assessment": "candidate-handler-assessment.json",
            "orchestration": "orchestration.json",
        }
    )
    artifact_paths = [
        "static-layers.json",
        "classification.json",
        "applicability.json",
        "features.json",
        "FEATURES.md",
        "campaign-labels.json",
        "static-logic.json",
        "STATIC-LOGIC.md",
        "communication-patterns.json",
        "c2-analysis.json",
        "route-config-candidates.json",
    ]
    if not assessment_only:
        artifact_paths.append("generic-triage.json")
    artifact_paths.extend(item["result"] for item in executions if isinstance(item.get("result"), str))
    report["artifact_sha256"] = artifact_hashes(case_dir, artifact_paths)
    artifact_paths.extend(["family-routing.json", "candidate-handler-assessment.json", "orchestration.json"])
    retained_outputs = (outcome.get("outputs") or {}).get("retained_binary_outputs")
    if isinstance(retained_outputs, list):
        retained_paths = sorted(
            {item["path"] for item in retained_outputs if isinstance(item, dict) and isinstance(item.get("path"), str)}
        )
        if retained_paths:
            report["retained_artifact_paths"] = retained_paths
            artifact_paths.extend(path for path in retained_paths if path not in artifact_paths)
    report["artifact_sha256"] = artifact_hashes(case_dir, artifact_paths)
    seal_report(report)
    write_json(case_dir / "report.json", report)
    return {
        "sha256": digest,
        "source_name": unit.source_name,
        "family": root_classification.get("malware_type"),
        "selected_family": root_selection["selected_family"],
        "selected_families": selected_families,
        "automation_family": family_resolution.get("family"),
        "automation_state": _automation_summary_state(outcome),
        "candidate_handler_attempts": int(candidate_assessment.get("planned_attempt_count", 0)),
        "ai_used": False,
        "campaign": root_classification.get("campaign_type"),
        "handler_succeeded": sum(item["status"] == "succeeded" for item in executions),
        "handler_failed": sum(item["status"] in {"failed", "preflight_failed"} for item in executions),
        "handler_no_evidence": sum(item["status"] == "no_evidence" for item in executions),
        "handler_ambiguous": sum(item["status"] == "ambiguous_evidence" for item in executions),
        "handler_incompatible": sum(item["status"] == "incompatible_input_format" for item in executions),
        "analysis_stage_failed": generic_status == "failed",
        "analysis_stage_partial": generic_status == "partial",
        "case_state": completion["status"],
        "report": f"cases/{digest}/report.json",
        "resumed": False,
    }


def _analysis_components(
    registry: Path,
    specs: list[HandlerSpec],
    *,
    implementation_sources: tuple[static_implementation_commitment.ImplementationSource, ...] | None = None,
) -> list[Path]:
    """case結果へ影響する解析コード、検出器、抽出器、規則を列挙する。"""

    if implementation_sources is None:
        try:
            implementation_sources = static_implementation_commitment.discover_implementation_sources(
                REPOSITORY_ROOT
            )
        except static_implementation_commitment.StaticImplementationError as exc:
            raise ValueError("静的解析実装treeを安全に固定できません") from exc
    components = {source.path for source in implementation_sources}
    components.update(
        {
            registry.resolve(),
            CAMPAIGN_CORRELATION_RULES.resolve(),
            CAMPAIGN_FINGERPRINTS.resolve(),
        }
    )
    for spec in specs:
        path = (REPOSITORY_ROOT / spec.relative_path).resolve()
        if path.is_file():
            components.add(path)
    registry_value = load_json_object_strict(registry)
    for metadata in (registry_value.get("malware_types") or {}).values():
        if not isinstance(metadata, dict) or not isinstance(metadata.get("detector"), str):
            continue
        path = (FRAMEWORK_ROOT / metadata["detector"]).resolve()
        if path.is_file():
            components.add(path)
    return sorted(components, key=lambda path: str(path).casefold())


@dataclass(frozen=True)
class _ExternalAnalysisComponent:
    """実装tree外に明示された解析componentの固定済みidentity。"""

    path: Path
    label: str
    size: int
    sha256: str
    device: int
    inode: int
    modified_ns: int
    changed_ns: int


def _capture_external_analysis_component(path: Path) -> _ExternalAnalysisComponent:
    """実装tree外componentを単一handleで読み、identityと内容を固定する。"""

    try:
        ensure_no_reparse_components(path)
        before = path.lstat()
    except (OSError, RuntimeError) as exc:
        raise ValueError("解析componentを安全に確認できません") from exc
    payload = _read_static_tool_binary_once(path)
    try:
        after = path.lstat()
    except OSError as exc:
        raise ValueError("解析componentを読取り後に確認できません") from exc
    if (
        not _same_file_identity(before, after)
        or before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
        or before.st_ctime_ns != after.st_ctime_ns
    ):
        raise ValueError("解析componentが読取り中に変更されました")
    try:
        label = path.relative_to(REPOSITORY_ROOT).as_posix()
    except ValueError:
        label = f"external:{path.name}"
    return _ExternalAnalysisComponent(
        path=path,
        label=label,
        size=len(payload),
        sha256=hashlib.sha256(payload).hexdigest(),
        device=after.st_dev,
        inode=after.st_ino,
        modified_ns=after.st_mtime_ns,
        changed_ns=after.st_ctime_ns,
    )


def _verify_external_analysis_component(component: _ExternalAnalysisComponent) -> None:
    """実装tree外componentのidentity、size、内容hashを再検証する。"""

    try:
        before = component.path.lstat()
    except OSError as exc:
        raise ValueError("解析componentを再確認できません") from exc
    if (
        before.st_dev != component.device
        or before.st_ino != component.inode
        or before.st_size != component.size
        or before.st_mtime_ns != component.modified_ns
        or before.st_ctime_ns != component.changed_ns
    ):
        raise ValueError("解析componentのidentityまたはsizeが変更されました")
    payload = _read_static_tool_binary_once(component.path)
    if len(payload) != component.size or hashlib.sha256(payload).hexdigest() != component.sha256:
        raise ValueError("解析componentの内容が変更されました")


@dataclass(frozen=True)
class _AnalysisComponentSnapshot:
    """pipeline fingerprintと実行前後検証で共有する実装snapshot。"""

    implementation_sources: tuple[static_implementation_commitment.ImplementationSource, ...]
    implementation_hashes: tuple[tuple[str, str], ...]
    records: tuple[tuple[str, str, int, str], ...]
    external_components: tuple[_ExternalAnalysisComponent, ...]

    @classmethod
    def capture(cls, registry: Path, specs: list[HandlerSpec]) -> _AnalysisComponentSnapshot:
        """安全列挙したidentityを内容hashとcomponent集合へ束縛する。"""

        hashes: dict[str, str] = {}

        def hash_source(source: static_implementation_commitment.ImplementationSource) -> str:
            payload = static_implementation_commitment.read_implementation_source(
                REPOSITORY_ROOT,
                source,
            )
            digest = hashlib.sha256(payload).hexdigest()
            hashes[source.relative_path] = digest
            return digest

        try:
            _commitment, sources = static_implementation_commitment.build_implementation_commitment(
                REPOSITORY_ROOT,
                hash_file=hash_source,
            )
        except static_implementation_commitment.StaticImplementationError as exc:
            raise ValueError("静的解析実装treeを安全に固定できません") from exc
        source_by_path = {str(source.path).casefold(): source for source in sources}
        records: list[tuple[str, str, int, str]] = [
            (str(source.path).casefold(), source.relative_path, source.size, hashes[source.relative_path])
            for source in sources
        ]
        external: list[_ExternalAnalysisComponent] = []
        for path in _analysis_components(registry, specs, implementation_sources=sources):
            key = str(path).casefold()
            if key in source_by_path:
                continue
            captured = _capture_external_analysis_component(path)
            external.append(captured)
            records.append((key, captured.label, captured.size, captured.sha256))
        snapshot = cls(
            implementation_sources=sources,
            implementation_hashes=tuple(sorted(hashes.items())),
            records=tuple(sorted(records, key=lambda item: item[0])),
            external_components=tuple(sorted(external, key=lambda item: str(item.path).casefold())),
        )
        return snapshot

    def verify(self) -> None:
        """membershipを再列挙し、全componentのidentity、size、hashを再確認する。"""

        try:
            static_implementation_commitment.verify_implementation_snapshot(
                REPOSITORY_ROOT,
                self.implementation_sources,
                dict(self.implementation_hashes),
            )
        except static_implementation_commitment.StaticImplementationError as exc:
            raise ValueError("静的解析実装treeがsnapshotから変更されました") from exc
        for component in self.external_components:
            _verify_external_analysis_component(component)

    def pipeline_fingerprint(self, settings: Mapping[str, Any]) -> dict[str, Any]:
        """安全に読んだrecordだけから既存形式のpipeline fingerprintを返す。"""

        component_records = [
            {"path": label, "size": size, "sha256": digest}
            for _sort_key, label, size, digest in self.records
        ]
        payload = {
            "pipeline_contract_version": PIPELINE_CONTRACT_VERSION,
            "settings": dict(sorted(settings.items())),
            "components": component_records,
        }
        encoded = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        return {
            "schema_version": 1,
            "pipeline_contract_version": PIPELINE_CONTRACT_VERSION,
            "sha256": hashlib.sha256(encoded).hexdigest(),
            "component_count": len(component_records),
            "settings": payload["settings"],
        }


def _static_tool_has_single_link(information: os.stat_result) -> bool:
    """link数を確認できない0も含め、単一link以外をfail-closedにする。"""

    return information.st_nlink == 1


def _normalize_tool_path(value: Path | None, label: str) -> Path | None:
    """明示指定された外部静的toolを通常fileへ限定する。"""

    if value is None:
        return None
    try:
        lexical = value.expanduser()
        if not lexical.is_absolute():
            lexical = Path.cwd() / lexical
        ensure_no_reparse_components(lexical)
        information = lexical.lstat()
        resolved = lexical.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ValueError(f"{label}が見つかりません: {value}") from exc
    if (
        not stat.S_ISREG(information.st_mode)
        or not _static_tool_has_single_link(information)
        or int(getattr(information, "st_file_attributes", 0))
        & int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
        or not 1 <= information.st_size <= MAX_STATIC_TOOL_BINARY_BYTES
    ):
        raise ValueError(f"{label}は単一link・非reparseの通常fileで指定してください: {value}")
    return resolved


def _read_static_tool_binary_once(path: Path) -> bytes:
    """tool binaryを単一handleから有界に読み、置換・hardlinkを拒否する。"""

    ensure_no_reparse_components(path)
    before_path = path.lstat()
    flags = os.O_RDONLY | int(getattr(os, "O_BINARY", 0))
    flags |= int(getattr(os, "O_CLOEXEC", 0))
    flags |= int(getattr(os, "O_NOINHERIT", 0))
    flags |= int(getattr(os, "O_NOFOLLOW", 0))
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or not _static_tool_has_single_link(opened)
            or not _static_tool_has_single_link(before_path)
            or not _same_file_identity(opened, before_path)
            or not 1 <= opened.st_size <= MAX_STATIC_TOOL_BINARY_BYTES
        ):
            raise ValueError("static tool binary metadataが不正です")
        remaining = opened.st_size + 1
        chunks: list[bytes] = []
        while remaining > 0:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after_handle = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    after_path = path.lstat()
    if (
        len(payload) != opened.st_size
        or not _static_tool_has_single_link(after_handle)
        or not _static_tool_has_single_link(after_path)
        or not _same_file_identity(opened, after_handle)
        or not _same_file_identity(opened, after_path)
        or after_handle.st_size != opened.st_size
        or getattr(after_handle, "st_mtime_ns", None) != getattr(opened, "st_mtime_ns", None)
        or getattr(after_handle, "st_ctime_ns", None) != getattr(opened, "st_ctime_ns", None)
    ):
        raise ValueError("static tool binaryが読取り中に変更されました")
    return payload


def _tool_identity(path: Path | None) -> dict[str, Any] | None:
    """外部toolの絶対pathを公開せず、名前・size・内容hashを契約化する。"""

    if path is None:
        return None
    data = _read_static_tool_binary_once(path)
    return {
        "name": path.name,
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def _static_tool_settings(
    upx: Path | None,
    sevenzip: Path | None,
    diec: Path | None,
    innounp: Path | None = None,
) -> dict[str, Any]:
    return {
        "upx": _tool_identity(upx),
        "sevenzip": _tool_identity(sevenzip),
        "diec": _tool_identity(diec),
        "innounp": _tool_identity(innounp),
    }


def _build_analysis_contract(
    *,
    registry: Path,
    specs: list[HandlerSpec],
    archive_mode: str,
    forced_family: str | None,
    minimum_confidence: str,
    upx: Path | None = None,
    sevenzip: Path | None = None,
    diec: Path | None = None,
    innounp: Path | None = None,
    force_container_probe: bool = False,
    max_static_layers: int = MAX_STATIC_LAYERS,
    retry_max_static_layers: int | None = None,
    archive_password: str = "infected",
    assessment_only: bool,
    max_file_size: int,
    string_scan_limit: int = DEFAULT_STRING_SCAN_LIMIT,
    family_hint_manifest_identity: dict[str, Any] | None = None,
    component_snapshot: _AnalysisComponentSnapshot | None = None,
    inno_password: str = "",
) -> dict[str, Any]:
    """再開判定に必要なコード・レジストリ・設定指紋を構築する。"""

    catalog = json.dumps(
        [spec.public() for spec in specs],
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    settings = {
        "archive_mode": archive_mode,
        "forced_family": forced_family,
        "minimum_confidence": minimum_confidence,
        "assessment_only": assessment_only,
        "max_file_size": max_file_size,
        "string_scan_limit": string_scan_limit,
        "family_hint_manifest": family_hint_manifest_identity,
        "static_tools": _static_tool_settings(upx, sevenzip, diec, innounp),
        "force_container_probe": force_container_probe,
        "max_static_layers": max_static_layers,
        "retry_max_static_layers": retry_max_static_layers,
        "follow_on_fixed_point": {
            "maximum_artifacts": MAX_FOLLOW_ON_ARTIFACTS,
            "maximum_edges": MAX_FOLLOW_ON_EDGES,
            "maximum_omitted_metadata": MAX_FOLLOW_ON_OMITTED_METADATA,
            "maximum_depth": MAX_FOLLOW_ON_DEPTH,
            "maximum_total_bytes": MAX_FOLLOW_ON_TOTAL_BYTES,
            "maximum_payload_size": MAX_FOLLOW_ON_PAYLOAD_SIZE,
            "maximum_wall_seconds": MAX_FOLLOW_ON_WALL_SECONDS,
            "maximum_child_seconds": MAX_FOLLOW_ON_CHILD_SECONDS,
        },
        "archive_password_configured": bool(archive_password),
        "inno_password_configured": bool(inno_password),
        "handler_catalog_sha256": hashlib.sha256(catalog).hexdigest(),
        "runtime": runtime_dependency_versions(),
    }
    owns_snapshot = component_snapshot is None
    snapshot = component_snapshot or _AnalysisComponentSnapshot.capture(registry, specs)
    fingerprint = snapshot.pipeline_fingerprint(settings)
    if owns_snapshot:
        snapshot.verify()
    return fingerprint


def _build_follow_on_analysis_contract(
    *,
    registry: Path,
    specs: list[HandlerSpec],
    minimum_confidence: str,
    upx: Path | None,
    sevenzip: Path | None,
    diec: Path | None,
    force_container_probe: bool,
    max_static_layers: int,
    retry_max_static_layers: int | None,
    archive_password: str,
    string_scan_limit: int,
    family_hint_manifest_identity: dict[str, Any] | None = None,
    component_snapshot: _AnalysisComponentSnapshot | None = None,
    innounp: Path | None = None,
    inno_password: str = "",
) -> dict[str, Any]:
    """保持済みraw payloadへ実際に適用する設定だけで契約を構築する。"""

    return _build_analysis_contract(
        registry=registry,
        specs=specs,
        archive_mode="raw",
        forced_family=None,
        minimum_confidence=minimum_confidence,
        assessment_only=False,
        upx=upx,
        sevenzip=sevenzip,
        diec=diec,
        innounp=innounp,
        force_container_probe=force_container_probe,
        max_static_layers=max_static_layers,
        retry_max_static_layers=retry_max_static_layers,
        archive_password=archive_password,
        max_file_size=MAX_FOLLOW_ON_PAYLOAD_SIZE,
        string_scan_limit=string_scan_limit,
        family_hint_manifest_identity=family_hint_manifest_identity,
        component_snapshot=component_snapshot,
        inno_password=inno_password,
    )


def load_resumable_case(
    output: Path,
    digest: str,
    *,
    assessment_only: bool,
    expected_contract: dict[str, Any],
    unit: InputUnit,
) -> dict[str, Any] | None:
    """同一入力・同一契約・全成果物一致の完了caseだけを再利用する。"""

    normalize_sha256_digest(digest)
    case_dir = output / "cases" / digest
    if not case_dir.exists():
        return None
    ensure_no_reparse_components(case_dir)
    try:
        report_path = resolve_case_artifact(case_dir, "report.json")
    except ValueError as exc:
        if "reparse point" in str(exc):
            raise
        return None
    try:
        report = load_json_object_strict(report_path)
    except ValueError:
        return None
    integrity_errors = case_integrity_errors(
        case_dir,
        report,
        expected_digest=digest,
        expected_contract=expected_contract,
        require_resumable=True,
    )
    if any("reparse" in error for error in integrity_errors):
        raise ValueError(f"再開対象caseにreparse pointがあります: {digest} ({integrity_errors})")
    if integrity_errors:
        return None
    settings = expected_contract.get("settings")
    if (
        not isinstance(settings, Mapping)
        or type(settings.get("archive_password_configured")) is not bool
        or type(settings.get("inno_password_configured")) is not bool
        or settings["archive_password_configured"]
        or settings["inno_password_configured"]
    ):
        # 公開contractへcredential verifierを保持しないため、値の一致を
        # 証明できない設定済みpasswordのcaseは直接呼出しでも再利用しない。
        return None
    state = report.get("case_state")
    sample = report.get("sample")
    classification = report.get("classification")
    executions = report.get("handler_executions")
    try:
        orchestration = load_json_object_strict(resolve_case_artifact(case_dir, "orchestration.json"))
        candidate_assessment = load_json_object_strict(
            resolve_case_artifact(case_dir, "candidate-handler-assessment.json")
        )
    except (TypeError, ValueError):
        return None
    if (
        isinstance(state, Mapping)
        and state.get("status") == "complete"
        and (orchestration.get("status") != "complete" or orchestration.get("blockers") != [])
    ):
        return None
    provenance = {
        "source_name": unit.source_name,
        "input_kind": unit.input_kind,
        "outer_sha256": unit.outer_sha256,
        "member_name": unit.member_name,
    }
    if any(sample.get(key) != value for key, value in provenance.items()):
        return None
    if report.get("assessment_only") is not assessment_only:
        return None
    selected_families = classification.get("selected_families")
    source_name = sample.get("source_name")
    if not isinstance(source_name, str) or not source_name:
        return None
    statuses = [item.get("status") for item in executions if isinstance(item, dict)]
    return {
        "sha256": digest,
        "source_name": source_name,
        "family": classification.get("family"),
        "selected_family": classification.get("selected_family"),
        "selected_families": selected_families,
        "automation_family": (orchestration.get("family_resolution") or {}).get("family"),
        "automation_state": _automation_summary_state(orchestration),
        "candidate_handler_attempts": int(candidate_assessment.get("planned_attempt_count", 0)),
        "ai_used": False,
        "campaign": classification.get("campaign"),
        "handler_succeeded": sum(status == "succeeded" for status in statuses),
        "handler_failed": sum(status in {"failed", "preflight_failed"} for status in statuses),
        "handler_no_evidence": sum(status == "no_evidence" for status in statuses),
        "handler_ambiguous": sum(status == "ambiguous_evidence" for status in statuses),
        "handler_incompatible": sum(status == "incompatible_input_format" for status in statuses),
        "analysis_stage_failed": report.get("generic_triage") == "failed",
        "analysis_stage_partial": report.get("generic_triage") == "partial",
        "case_state": state.get("status"),
        "report": f"cases/{digest}/report.json",
        "resumed": True,
    }


def _follow_on_worker_root(value: Any, *, name: str) -> Path:
    """内部workerへ渡すrootを絶対・非reparse directoryへ制限する。"""

    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError(f"follow-on {name}が不正です")
    path = Path(value)
    if not path.is_absolute():
        raise ValueError(f"follow-on {name}は絶対pathで指定してください")
    ensure_no_reparse_components(path)
    resolved = path.resolve(strict=True)
    if not resolved.is_dir():
        raise ValueError(f"follow-on {name}は既存directoryではありません")
    return resolved


def _same_file_identity(left: os.stat_result, right: os.stat_result) -> bool:
    """同じfile objectを示す最小identityを比較する。"""

    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def _write_private_regular_file(path: Path, payload: bytes, *, maximum_size: int) -> None:
    """owner限定modeのsingle-link通常fileを排他的に作成する。"""

    if not 0 < len(payload) <= maximum_size:
        raise ValueError("follow-on private file sizeが不正です")
    if not path.is_absolute() or path.exists() or not path.parent.is_dir():
        raise ValueError("follow-on private file pathが不正です")
    ensure_no_reparse_components(path.parent)
    parent_before = path.parent.lstat()
    if not stat.S_ISDIR(parent_before.st_mode):
        raise ValueError("follow-on private file parentがdirectoryではありません")
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
        0o600,
    )
    created: os.stat_result | None = None
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        created = os.fstat(descriptor)
        path_opened = path.lstat()
        parent_opened = path.parent.lstat()
        if (
            not stat.S_ISREG(created.st_mode)
            or created.st_nlink != 1
            or not stat.S_ISREG(path_opened.st_mode)
            or path_opened.st_nlink != 1
            or not _same_file_identity(created, path_opened)
            or not _same_file_identity(parent_before, parent_opened)
            or (os.name != "nt" and stat.S_IMODE(path_opened.st_mode) & 0o077)
        ):
            raise ValueError("follow-on private fileの作成後検証に失敗しました")
        view = memoryview(payload)
        written = 0
        while written < len(view):
            count = os.write(descriptor, view[written:])
            if count <= 0:
                raise OSError("follow-on private fileを書き切れませんでした")
            written += count
        os.fsync(descriptor)
        final_fd = os.fstat(descriptor)
        final_path = path.lstat()
        final_parent = path.parent.lstat()
        if (
            final_fd.st_size != len(payload)
            or final_fd.st_nlink != 1
            or final_path.st_nlink != 1
            or not _same_file_identity(created, final_fd)
            or not _same_file_identity(created, final_path)
            or not _same_file_identity(parent_before, final_parent)
        ):
            raise ValueError("follow-on private fileが書込み中に変更されました")
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        if created is not None and path.exists():
            try:
                current = path.lstat()
                if _same_file_identity(created, current):
                    path.unlink(missing_ok=True)
            except OSError:
                pass
        raise
    os.close(descriptor)


def _read_private_regular_file(
    path: Path,
    *,
    maximum_size: int,
    expected_size: int | None = None,
    expected_sha256: str | None = None,
) -> bytes:
    """private通常fileを単一handleで有界読取りし、置換とhardlinkを拒否する。"""

    if not path.is_absolute():
        raise ValueError("follow-on private fileは絶対pathで指定してください")
    ensure_no_reparse_components(path)
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        before = os.fstat(descriptor)
        path_before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or not stat.S_ISREG(path_before.st_mode)
            or path_before.st_nlink != 1
            or not _same_file_identity(before, path_before)
            or not 0 < before.st_size <= maximum_size
            or (expected_size is not None and before.st_size != expected_size)
            or (os.name != "nt" and stat.S_IMODE(path_before.st_mode) & 0o077)
        ):
            raise ValueError("follow-on private file metadataが不正です")
        remaining = before.st_size + 1
        chunks: list[bytes] = []
        while remaining > 0:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        path_after = path.lstat()
    finally:
        os.close(descriptor)
    if (
        len(raw) != before.st_size
        or not _same_file_identity(before, after)
        or not _same_file_identity(before, path_after)
        or after.st_nlink != 1
        or path_after.st_nlink != 1
        or after.st_size != before.st_size
        or getattr(after, "st_mtime_ns", None) != getattr(before, "st_mtime_ns", None)
    ):
        raise ValueError("follow-on private fileが読取り中に変更されました")
    if expected_sha256 is not None and hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError("follow-on private file hashが一致しません")
    return raw


def _strict_json_object_bytes(raw: bytes, *, label: str) -> dict[str, Any]:
    """重複key・非finite値・非objectを拒否してUTF-8 JSONを読む。"""

    def strict_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"{label}に重複keyがあります")
            value[key] = item
        return value

    def reject_constant(_value: str) -> None:
        raise ValueError(f"{label}に非finite数値があります")

    def parse_finite_float(raw_value: str) -> float:
        parsed = float(raw_value)
        if not math.isfinite(parsed):
            reject_constant(raw_value)
        return parsed

    def parse_bounded_int(raw_value: str) -> int:
        digits = raw_value.removeprefix("-")
        if len(digits) > 128:
            raise ValueError(f"{label}の整数桁数が上限を超えています")
        return int(raw_value)

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=strict_pairs,
            parse_int=parse_bounded_int,
            parse_float=parse_finite_float,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError(f"{label}を解釈できません") from exc
    if not isinstance(value, dict):
        raise TypeError(f"{label}はJSON objectである必要があります")
    pending: list[tuple[Any, int]] = [(value, 0)]
    while pending:
        current, depth = pending.pop()
        if depth > 128:
            raise ValueError(f"{label}の入れ子が深すぎます")
        if isinstance(current, dict):
            pending.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            pending.extend((item, depth + 1) for item in current)
    return value


def _pe_function_layer_selection(
    layers: Sequence[StaticLayer],
) -> tuple[list[tuple[int, StaticLayer]], int]:
    """root保持・深さ優先で、隔離workerへ渡すPE層を有界選択する。"""

    eligible = [
        index
        for index, layer in enumerate(layers)
        if isinstance(layer.data, bytes) and layer.data.startswith(b"MZ")
    ]
    if len(eligible) <= MAX_PE_FUNCTION_WORKER_PROGRAMS:
        return [(index, layers[index]) for index in eligible], len(eligible)
    selected: list[int] = []
    if 0 in eligible:
        selected.append(0)
    ranked = sorted(eligible, key=lambda index: (-int(layers[index].depth), index))
    for index in ranked:
        if index not in selected:
            selected.append(index)
        if len(selected) >= MAX_PE_FUNCTION_WORKER_PROGRAMS:
            break
    return [(index, layers[index]) for index in selected], len(eligible)


def _pe_function_worker_artifact(
    status: str,
    *,
    eligible_pe_layer_count: int,
    requested_program_count: int,
    timeout_seconds: float,
    error_type: str | None = None,
) -> dict[str, Any]:
    """worker失敗を、完了gateを満たさない安全な部分成果物へ正規化する。"""

    worker = {
        "status": status,
        "execution_boundary": "bounded_isolated_process",
        "wall_clock_limit_seconds": timeout_seconds,
        "maximum_active_processes": MAX_PE_FUNCTION_WORKER_ACTIVE_PROCESSES,
        "maximum_memory_bytes": MAX_PE_FUNCTION_WORKER_MEMORY_BYTES,
        "requested_program_count": requested_program_count,
    }
    if isinstance(error_type, str) and re.fullmatch(r"[A-Za-z][A-Za-z0-9_.]{0,127}", error_type):
        worker["error_type"] = error_type
    return {
        "schema_version": 1,
        "analysis_mode": "bounded_static_disassembly_only",
        "status": status,
        "programs": [],
        "counts": {
            "eligible_pe_layer_count": eligible_pe_layer_count,
            "selected_pe_layer_count": 0,
            "analyzed_program_count": 0,
            "representative_function_candidate_count": 0,
            "import_count": 0,
            "call_site_count": 0,
            "process_behavior_count": 0,
        },
        "program_selection": {
            "policy": "root_then_deepest_then_discovery_order",
            "maximum_programs": MAX_PE_FUNCTION_WORKER_PROGRAMS,
            "truncated": eligible_pe_layer_count > 0,
            "artifact_name_or_hash_specific_exception_used": False,
        },
        "completion_contract": {
            "satisfies_reviewed_function_analysis_gate": False,
            "blocker_must_be_retained_without_independent_reviewed_functions": True,
            "required_gate": "validate_function_analysis.py",
            "reason": "automated_candidate_evidence_requires_independent_function_review",
        },
        "safety": {
            "sample_executed": False,
            "sample_emulated": False,
            "network_contacted": False,
            "raw_pseudocode_exported": False,
            "raw_endpoint_or_config_exported": False,
            "source_name_exported": False,
        },
        "worker_execution": worker,
    }


def _pe_function_worker_request_item(
    value: Any,
    *,
    ordinal: int,
    transferred_bytes: int,
) -> tuple[dict[str, Any], int]:
    """worker requestの1層を厳格検証し、次の転送済みbyte数を返す。"""

    expected_keys = {
        "ordinal",
        "sha256",
        "size",
        "depth",
        "relationship",
        "transfer_status",
        "file_name",
    }
    if not isinstance(value, dict) or set(value) != expected_keys or value.get("ordinal") != ordinal:
        raise ValueError("PE function worker layer schemaが不正です")
    digest = normalize_sha256_digest(value.get("sha256"))
    size = value.get("size")
    depth = value.get("depth")
    relationship = value.get("relationship")
    transfer_status = value.get("transfer_status")
    file_name = value.get("file_name")
    if (
        isinstance(size, bool)
        or not isinstance(size, int)
        or size < 2
        or isinstance(depth, bool)
        or not isinstance(depth, int)
        or not 0 <= depth <= 64
        or relationship not in {"root_program", "statically_recovered_program"}
    ):
        raise ValueError("PE function worker layer metadataが不正です")
    if relationship == "root_program" and ordinal != 0:
        raise ValueError("PE function worker root relationshipが不正です")
    expected_name = f"layer-{ordinal:04d}.bin"
    if transfer_status == "available":
        if (
            file_name != expected_name
            or size > MAX_PE_FUNCTION_WORKER_LAYER_BYTES
            or transferred_bytes + size > MAX_PE_FUNCTION_WORKER_TOTAL_BYTES
        ):
            raise ValueError("PE function worker transferred layerが不正です")
        transferred_bytes += size
    elif transfer_status == "input_budget_exceeded":
        if file_name is not None or size <= MAX_PE_FUNCTION_WORKER_LAYER_BYTES:
            raise ValueError("PE function worker input budget recordが不正です")
    elif transfer_status == "worker_total_input_budget_exceeded":
        if (
            file_name is not None
            or size > MAX_PE_FUNCTION_WORKER_LAYER_BYTES
            or transferred_bytes + size <= MAX_PE_FUNCTION_WORKER_TOTAL_BYTES
        ):
            raise ValueError("PE function worker total budget recordが不正です")
    else:
        raise ValueError("PE function worker transfer statusが不正です")
    return {**value, "sha256": digest}, transferred_bytes


def _pe_function_result_has_forbidden_fields(value: Any) -> bool:
    """source名や生endpoint/config用fieldがworker結果へ混入していないか調べる。"""

    pending = [value]
    forbidden = {
        "source_name",
        "source_path",
        "raw_endpoint",
        "raw_config",
        "raw_configuration",
    }
    while pending:
        current = pending.pop()
        if isinstance(current, dict):
            if any(str(key).casefold() in forbidden for key in current):
                return True
            pending.extend(current.values())
        elif isinstance(current, list):
            pending.extend(current)
    return False


def _validate_pe_function_worker_result(
    value: Any,
    *,
    request_layers: Sequence[Mapping[str, Any]],
    eligible_pe_layer_count: int,
    assessment_only: bool,
) -> dict[str, Any]:
    """隔離worker結果を入力manifestと安全契約へ結び付けて検証する。"""

    expected_keys = {
        "schema_version",
        "analysis_mode",
        "status",
        "programs",
        "counts",
        "program_selection",
        "completion_contract",
        "safety",
    }
    if not isinstance(value, dict) or set(value) != expected_keys:
        raise ValueError("PE function worker result schemaが不正です")
    counts = value.get("counts")
    count_keys = {
        "eligible_pe_layer_count",
        "selected_pe_layer_count",
        "analyzed_program_count",
        "representative_function_candidate_count",
        "import_count",
        "call_site_count",
        "process_behavior_count",
    }
    programs = value.get("programs")
    selection = value.get("program_selection")
    completion = value.get("completion_contract")
    safety = value.get("safety")
    if (
        value.get("schema_version") != 1
        or value.get("analysis_mode") != "bounded_static_disassembly_only"
        or value.get("status")
        not in {
            "not_run_assessment_only",
            "not_applicable",
            "candidate_evidence_collected",
            "candidate_evidence_partial",
        }
        or not isinstance(programs, list)
        or len(programs) != len(request_layers)
        or not isinstance(counts, dict)
        or set(counts) != count_keys
        or any(isinstance(item, bool) or not isinstance(item, int) or item < 0 for item in counts.values())
        or counts.get("eligible_pe_layer_count") != eligible_pe_layer_count
        or counts.get("selected_pe_layer_count") != len(request_layers)
        or not isinstance(selection, dict)
        or selection.get("policy") != "root_then_deepest_then_discovery_order"
        or selection.get("maximum_programs") != MAX_PE_FUNCTION_WORKER_PROGRAMS
        or selection.get("truncated") is not (eligible_pe_layer_count > len(request_layers))
        or selection.get("artifact_name_or_hash_specific_exception_used") is not False
        or not isinstance(completion, dict)
        or completion.get("satisfies_reviewed_function_analysis_gate") is not False
        or completion.get("blocker_must_be_retained_without_independent_reviewed_functions") is not True
        or not isinstance(safety, dict)
        or any(
            safety.get(name) is not False
            for name in (
                "sample_executed",
                "sample_emulated",
                "network_contacted",
                "raw_pseudocode_exported",
                "raw_endpoint_or_config_exported",
                "source_name_exported",
            )
        )
        or _pe_function_result_has_forbidden_fields(value)
    ):
        raise ValueError("PE function worker result contractが不正です")
    if assessment_only and (programs or eligible_pe_layer_count != 0):
        raise ValueError("assessment-only PE function worker resultが不正です")
    for program, expected in zip(programs, request_layers, strict=True):
        program_completion = program.get("completion_contract") if isinstance(program, dict) else None
        program_safety = program.get("safety") if isinstance(program, dict) else None
        if (
            not isinstance(program, dict)
            or program.get("program_selector") != f"sha256:{expected['sha256']}"
            or program.get("relationship") != expected["relationship"]
            or program.get("depth") != expected["depth"]
            or not isinstance(program.get("status"), str)
            or not isinstance(program_completion, dict)
            or program_completion.get("satisfies_reviewed_function_analysis_gate") is not False
            or program_completion.get("requires_independent_reviewed_function_logic") is not True
            or not isinstance(program_safety, dict)
            or any(
                program_safety.get(name) is not False
                for name in (
                    "sample_executed",
                    "sample_emulated",
                    "network_contacted",
                    "raw_pseudocode_exported",
                )
            )
        ):
            raise ValueError("PE function worker program contractが不正です")
    return value


def _pe_function_worker_main(
    request_path: str,
    request_size_text: str,
    request_sha256: str,
    response_path: str,
) -> int:
    """PE代表関数候補を静的解析する隔離worker entrypoint。"""

    request_file = Path(request_path)
    response_file = Path(response_path)
    if (
        not request_file.is_absolute()
        or not response_file.is_absolute()
        or response_file.exists()
        or request_file.parent != response_file.parent
        or not response_file.parent.is_dir()
    ):
        return 2
    try:
        ensure_no_reparse_components(response_file.parent)
        if not request_size_text.isascii() or not request_size_text.isdecimal():
            raise ValueError("PE function worker request sizeが不正です")
        request_size = int(request_size_text)
        request_digest = normalize_sha256_digest(request_sha256)
        request_raw = _read_private_regular_file(
            request_file,
            maximum_size=MAX_PE_FUNCTION_WORKER_REQUEST,
            expected_size=request_size,
            expected_sha256=request_digest,
        )
        request = _strict_json_object_bytes(request_raw, label="PE function worker request")
        if set(request) != {
            "schema_version",
            "assessment_only",
            "eligible_pe_layer_count",
            "layers",
        }:
            raise ValueError("PE function worker request schemaが不正です")
        assessment_only = request.get("assessment_only")
        eligible_count = request.get("eligible_pe_layer_count")
        supplied_layers = request.get("layers")
        if (
            request.get("schema_version") != 1
            or type(assessment_only) is not bool
            or isinstance(eligible_count, bool)
            or not isinstance(eligible_count, int)
            or not 0 <= eligible_count <= 1_000_000
            or not isinstance(supplied_layers, list)
            or len(supplied_layers) > MAX_PE_FUNCTION_WORKER_PROGRAMS
            or eligible_count < len(supplied_layers)
            or (assessment_only and (eligible_count != 0 or supplied_layers))
        ):
            raise ValueError("PE function worker request contractが不正です")
        layer_root = request_file.parent / "layers"
        ensure_no_reparse_components(layer_root)
        resolved_layer_root = layer_root.resolve(strict=True)
        if not resolved_layer_root.is_dir() or resolved_layer_root.parent != request_file.parent:
            raise ValueError("PE function worker layer rootが不正です")
        layers: list[dict[str, Any]] = []
        transferred_bytes = 0
        for ordinal, supplied in enumerate(supplied_layers):
            normalized, transferred_bytes = _pe_function_worker_request_item(
                supplied,
                ordinal=ordinal,
                transferred_bytes=transferred_bytes,
            )
            layers.append(normalized)

        import pe_function_analysis

        programs = []
        for layer in layers:
            selector = f"sha256:{layer['sha256']}"
            if layer["transfer_status"] == "available":
                path = resolved_layer_root / str(layer["file_name"])
                if path.parent != resolved_layer_root:
                    raise ValueError("PE function worker layer pathが不正です")
                data = _read_private_regular_file(
                    path,
                    maximum_size=MAX_PE_FUNCTION_WORKER_LAYER_BYTES,
                    expected_size=int(layer["size"]),
                    expected_sha256=str(layer["sha256"]),
                )
                program = pe_function_analysis.analyze_pe(
                    data,
                    program_selector=selector,
                    relationship=str(layer["relationship"]),
                    depth=int(layer["depth"]),
                )
                del data
            else:
                program = pe_function_analysis._base_program(
                    selector,
                    str(layer["relationship"]),
                    int(layer["depth"]),
                )
                program["status"] = str(layer["transfer_status"])
            programs.append(program)
        result = pe_function_analysis.build_static_layer_report(
            programs,
            eligible_pe_layer_count=eligible_count,
            assessment_only=assessment_only,
        )
        response: dict[str, Any] = {"ok": True, "result": result}
    except Exception as exc:  # noqa: BLE001 - worker境界では例外詳細を型へ正規化する
        response = {
            "ok": False,
            "error": "pe_function_worker_failed",
            "error_type": type(exc).__name__,
        }
    encoded = json.dumps(
        response,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    if len(encoded) > MAX_PE_FUNCTION_WORKER_RESPONSE:
        encoded = b'{"error":"pe_function_worker_response_limit","error_type":"ValueError","ok":false}'
    try:
        _write_private_regular_file(
            response_file,
            encoded,
            maximum_size=MAX_PE_FUNCTION_WORKER_RESPONSE,
        )
    except (OSError, ValueError):
        return 3
    return 0


def _run_pe_function_analysis_isolated(
    layers: Sequence[StaticLayer],
    *,
    assessment_only: bool = False,
    timeout_seconds: float = MAX_PE_FUNCTION_WORKER_WALL_SECONDS,
) -> dict[str, Any]:
    """PE静的関数解析を資源制限付き子processへ隔離し、失敗をcase内へ閉じ込める。"""

    selected, eligible_count = (
        ([], 0) if assessment_only else _pe_function_layer_selection(layers)
    )
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not math.isfinite(float(timeout_seconds))
        or float(timeout_seconds) <= 0
    ):
        effective_timeout = MAX_PE_FUNCTION_WORKER_WALL_SECONDS
        return _pe_function_worker_artifact(
            "worker_failed",
            eligible_pe_layer_count=eligible_count,
            requested_program_count=len(selected),
            timeout_seconds=effective_timeout,
            error_type="ValueError",
        )
    effective_timeout = min(float(timeout_seconds), MAX_PE_FUNCTION_WORKER_WALL_SECONDS)
    if not selected:
        import pe_function_analysis

        result = pe_function_analysis.build_static_layer_report(
            [],
            eligible_pe_layer_count=eligible_count,
            assessment_only=assessment_only,
        )
        result["worker_execution"] = {
            "status": (
                "not_started_assessment_only"
                if assessment_only
                else "not_started_no_eligible_pe_layers"
            ),
            "execution_boundary": "parent_process_short_circuit_no_worker_started",
            "wall_clock_limit_seconds": effective_timeout,
            "maximum_active_processes": MAX_PE_FUNCTION_WORKER_ACTIVE_PROCESSES,
            "maximum_memory_bytes": MAX_PE_FUNCTION_WORKER_MEMORY_BYTES,
            "requested_program_count": 0,
        }
        return result
    request_layers = []
    transferred_bytes = 0
    for ordinal, (original_index, layer) in enumerate(selected):
        size = len(layer.data)
        digest = hashlib.sha256(layer.data).hexdigest()
        if size > MAX_PE_FUNCTION_WORKER_LAYER_BYTES:
            transfer_status = "input_budget_exceeded"
            file_name = None
        elif transferred_bytes + size > MAX_PE_FUNCTION_WORKER_TOTAL_BYTES:
            transfer_status = "worker_total_input_budget_exceeded"
            file_name = None
        else:
            transfer_status = "available"
            file_name = f"layer-{ordinal:04d}.bin"
            transferred_bytes += size
        request_layers.append(
            {
                "ordinal": ordinal,
                "sha256": digest,
                "size": size,
                "depth": int(layer.depth),
                "relationship": (
                    "root_program" if original_index == 0 else "statically_recovered_program"
                ),
                "transfer_status": transfer_status,
                "file_name": file_name,
            }
        )
    request = {
        "schema_version": 1,
        "assessment_only": assessment_only,
        "eligible_pe_layer_count": eligible_count,
        "layers": request_layers,
    }
    request_raw = json.dumps(
        request,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    if len(request_raw) > MAX_PE_FUNCTION_WORKER_REQUEST:
        return _pe_function_worker_artifact(
            "worker_failed",
            eligible_pe_layer_count=eligible_count,
            requested_program_count=len(selected),
            timeout_seconds=effective_timeout,
            error_type="ValueError",
        )
    request_digest = hashlib.sha256(request_raw).hexdigest()
    try:
        from bounded_process import run_bounded

        with tempfile.TemporaryDirectory(prefix="pe-function-analysis-") as temporary:
            temporary_root = Path(temporary).resolve(strict=True)
            ensure_no_reparse_components(temporary_root)
            request_path = temporary_root / "request.json"
            response_path = temporary_root / "response.json"
            layer_root = temporary_root / "layers"
            worker_temp = temporary_root / "worker-temp"
            layer_root.mkdir(mode=0o700)
            worker_temp.mkdir(mode=0o700)
            os.chmod(layer_root, 0o700)
            os.chmod(worker_temp, 0o700)
            for item, (_, layer) in zip(request_layers, selected, strict=True):
                if item["transfer_status"] != "available":
                    continue
                _write_private_regular_file(
                    layer_root / str(item["file_name"]),
                    layer.data,
                    maximum_size=MAX_PE_FUNCTION_WORKER_LAYER_BYTES,
                )
            _write_private_regular_file(
                request_path,
                request_raw,
                maximum_size=MAX_PE_FUNCTION_WORKER_REQUEST,
            )
            command = [
                sys.executable,
                "-I",
                "-B",
                str(Path(__file__).resolve()),
                "--pe-function-worker",
                str(request_path),
                str(len(request_raw)),
                request_digest,
                str(response_path),
            ]
            try:
                completed = run_bounded(
                    command,
                    timeout=effective_timeout,
                    check=False,
                    shell=False,
                    env=_bounded_handler_environment(temporary_root=worker_temp),
                    cwd=REPOSITORY_ROOT,
                    input=b"",
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    text=False,
                    require_containment=True,
                    maximum_active_processes=MAX_PE_FUNCTION_WORKER_ACTIVE_PROCESSES,
                    maximum_memory_bytes=MAX_PE_FUNCTION_WORKER_MEMORY_BYTES,
                )
            except subprocess.TimeoutExpired:
                return _pe_function_worker_artifact(
                    "worker_timeout",
                    eligible_pe_layer_count=eligible_count,
                    requested_program_count=len(selected),
                    timeout_seconds=effective_timeout,
                    error_type="TimeoutExpired",
                )
            except (OSError, RuntimeError, subprocess.SubprocessError, ValueError) as exc:
                return _pe_function_worker_artifact(
                    "worker_failed",
                    eligible_pe_layer_count=eligible_count,
                    requested_program_count=len(selected),
                    timeout_seconds=effective_timeout,
                    error_type=type(exc).__name__,
                )
            if completed.returncode != 0:
                return _pe_function_worker_artifact(
                    "worker_failed",
                    eligible_pe_layer_count=eligible_count,
                    requested_program_count=len(selected),
                    timeout_seconds=effective_timeout,
                    error_type="WorkerExitError",
                )
            try:
                response_raw = _read_private_regular_file(
                    response_path,
                    maximum_size=MAX_PE_FUNCTION_WORKER_RESPONSE,
                )
                response = _strict_json_object_bytes(
                    response_raw,
                    label="PE function worker response",
                )
                if response.get("ok") is False and set(response) == {
                    "ok",
                    "error",
                    "error_type",
                }:
                    return _pe_function_worker_artifact(
                        "worker_failed",
                        eligible_pe_layer_count=eligible_count,
                        requested_program_count=len(selected),
                        timeout_seconds=effective_timeout,
                        error_type=(
                            response.get("error_type")
                            if isinstance(response.get("error_type"), str)
                            else "WorkerError"
                        ),
                    )
                if response.get("ok") is not True or set(response) != {"ok", "result"}:
                    raise ValueError("PE function worker response schemaが不正です")
                result = _validate_pe_function_worker_result(
                    response.get("result"),
                    request_layers=request_layers,
                    eligible_pe_layer_count=eligible_count,
                    assessment_only=assessment_only,
                )
            except (OSError, TypeError, ValueError):
                return _pe_function_worker_artifact(
                    "worker_response_invalid",
                    eligible_pe_layer_count=eligible_count,
                    requested_program_count=len(selected),
                    timeout_seconds=effective_timeout,
                    error_type="WorkerResponseError",
                )
    except (OSError, RuntimeError, ValueError) as exc:
        return _pe_function_worker_artifact(
            "worker_failed",
            eligible_pe_layer_count=eligible_count,
            requested_program_count=len(selected),
            timeout_seconds=effective_timeout,
            error_type=type(exc).__name__,
        )
    result["worker_execution"] = {
        "status": "completed",
        "execution_boundary": "bounded_isolated_process",
        "wall_clock_limit_seconds": effective_timeout,
        "maximum_active_processes": MAX_PE_FUNCTION_WORKER_ACTIVE_PROCESSES,
        "maximum_memory_bytes": MAX_PE_FUNCTION_WORKER_MEMORY_BYTES,
        "requested_program_count": len(selected),
    }
    return result


def _follow_on_worker_main() -> int:
    """1つの保持payloadだけを既存pipelineへ通す隔離worker entrypoint。"""

    if not _interpreter_is_isolated():
        return 2
    try:
        response_root = Path.cwd().resolve(strict=True)
        ensure_no_reparse_components(response_root)
        response_file = response_root / "response.json"
        if response_file.exists():
            raise ValueError("follow-on worker responseが既に存在します")
        header = sys.stdin.buffer.read(FOLLOW_ON_WORKER_FRAME_HEADER_BYTES)
        if len(header) != FOLLOW_ON_WORKER_FRAME_HEADER_BYTES:
            raise ValueError("follow-on worker frame headerが切れています")
        request_size = int.from_bytes(header, "big")
        if not 0 < request_size <= MAX_FOLLOW_ON_WORKER_REQUEST:
            raise ValueError("follow-on worker request sizeが不正です")
        request_raw = sys.stdin.buffer.read(request_size)
        if len(request_raw) != request_size:
            raise ValueError("follow-on worker requestが切れています")
        request = _strict_json_object_bytes(request_raw, label="follow-on worker request")
        expected_keys = {
            "schema_version",
            "output",
            "registry",
            "minimum_confidence",
            "upx",
            "sevenzip",
            "diec",
            "innounp",
            "force_container_probe",
            "max_static_layers",
            "retry_max_static_layers",
            "archive_password",
            "inno_password",
            "string_scan_limit",
            "analysis_contract",
            "source_name",
            "expected_sha256",
            "expected_size",
            "depth",
            "parent_sha256",
            "family_hints",
        }
        if not isinstance(request, dict) or set(request) != expected_keys:
            raise ValueError("follow-on worker request schemaが不正です")
        inno_password = request["inno_password"]
        if not isinstance(inno_password, str):
            raise ValueError("follow-on Inno passwordが不正です")
        output = _follow_on_worker_root(request["output"], name="output")
        repository = REPOSITORY_ROOT.resolve(strict=True)
        if output == repository or repository in output.parents:
            raise ValueError("follow-on outputをrepository配下へ作成できません")
        registry = Path(request["registry"])
        ensure_no_reparse_components(registry)
        registry = registry.resolve(strict=True)
        if repository not in registry.parents or not registry.is_file():
            raise ValueError("follow-on registryがrepository境界外です")
        expected_sha256 = normalize_sha256_digest(request["expected_sha256"])
        expected_size = request["expected_size"]
        if (
            type(expected_size) is not int
            or not 0 <= expected_size <= MAX_FOLLOW_ON_PAYLOAD_SIZE
        ):
            raise ValueError("follow-on payload sizeが不正です")
        parent_sha256 = normalize_sha256_digest(request["parent_sha256"])
        supplied_family_hints = request["family_hints"]
        if not isinstance(supplied_family_hints, list):
            raise ValueError("follow-on family_hints must be a list")
        child_family_hint_manifest = (
            classify_sample.normalize_family_hint_manifest(
                {
                    "schema_version": 1,
                    "samples": {expected_sha256: supplied_family_hints},
                }
            )
            if supplied_family_hints
            else None
        )
        depth = request["depth"]
        if not isinstance(depth, int) or isinstance(depth, bool) or not 1 <= depth <= MAX_FOLLOW_ON_DEPTH:
            raise ValueError("follow-on depthが不正です")
        source_name = request["source_name"]
        if (
            not isinstance(source_name, str)
            or not source_name
            or len(source_name) > 512
            or any(ord(character) < 32 or ord(character) == 127 for character in source_name)
        ):
            raise ValueError("follow-on source_nameが不正です")
        data = sys.stdin.buffer.read(expected_size + 1)
        if len(data) != expected_size:
            raise ValueError("follow-on payload lengthが一致しません")
        if hashlib.sha256(data).hexdigest() != expected_sha256:
            raise ValueError("follow-on payload hashが一致しません")
        analysis_contract = request["analysis_contract"]
        if not isinstance(analysis_contract, dict):
            raise ValueError("follow-on analysis_contractが不正です")
        minimum_confidence = request["minimum_confidence"]
        if minimum_confidence not in CONFIDENCE:
            raise ValueError("follow-on minimum_confidenceが不正です")

        clear_handler_caches()
        classify_sample.clear_classifier_caches()
        clear_profile_cache()
        clear_known_hash_cache()
        specs = discover_handlers()
        component_snapshot = _AnalysisComponentSnapshot.capture(registry, specs)
        registered = _registered_families(registry)
        upx = _normalize_tool_path(
            Path(request["upx"]) if isinstance(request["upx"], str) else None,
            "UPX",
        )
        sevenzip = _normalize_tool_path(
            Path(request["sevenzip"]) if isinstance(request["sevenzip"], str) else None,
            "7-Zip",
        )
        diec = _normalize_tool_path(
            Path(request["diec"]) if isinstance(request["diec"], str) else None,
            "Detect It Easy CLI",
        )
        innounp = _normalize_tool_path(
            Path(request["innounp"])
            if isinstance(request["innounp"], str)
            else None,
            "innounp",
        )
        child_contract = _build_follow_on_analysis_contract(
            registry=registry,
            specs=specs,
            minimum_confidence=minimum_confidence,
            upx=upx,
            sevenzip=sevenzip,
            diec=diec,
            innounp=innounp,
            force_container_probe=request["force_container_probe"] is True,
            max_static_layers=int(request["max_static_layers"]),
            retry_max_static_layers=request["retry_max_static_layers"],
            archive_password=str(request["archive_password"]),
            string_scan_limit=int(request["string_scan_limit"]),
            family_hint_manifest_identity=(
                analysis_contract.get("settings", {}).get("family_hint_manifest")
                if isinstance(analysis_contract.get("settings"), dict)
                else None
            ),
            component_snapshot=component_snapshot,
            inno_password=inno_password,
        )
        if analysis_contract != child_contract:
            raise ValueError("follow-on analysis_contractが実行時設定と一致しません")
        unit = InputUnit(
            source_name=source_name,
            data=data,
            input_kind="follow_on_payload",
            outer_sha256=expected_sha256,
            outer_size=len(data),
            member_name=None,
        )
        component_snapshot.verify()
        try:
            result = analyze_unit(
                unit,
                output=output,
                registry=registry,
                specs=specs,
                registered=registered,
                forced_family=None,
                minimum_confidence=minimum_confidence,
                assessment_only=False,
                analysis_contract=child_contract,
                family_hint_manifest=child_family_hint_manifest,
                family_requirements_policy=_load_family_analysis_requirements(),
                upx=upx,
                sevenzip=sevenzip,
                diec=diec,
                innounp=innounp,
                force_container_probe=request["force_container_probe"] is True,
                max_static_layers=int(request["max_static_layers"]),
                retry_max_static_layers=request["retry_max_static_layers"],
                archive_password=str(request["archive_password"]),
                string_scan_limit=int(request["string_scan_limit"]),
                inno_password=inno_password,
                follow_on_lineage={
                    "schema_version": 1,
                    "depth": depth,
                    "parent_sha256": parent_sha256,
                    "root_kind": "retained_terminal_or_final_payload",
                },
            )
        finally:
            component_snapshot.verify()
        response: dict[str, Any] = {"ok": True, "result": result}
    except Exception as exc:  # noqa: BLE001 - worker境界では例外内容を型だけへ正規化する
        response = {
            "ok": False,
            "error": "follow_on_worker_failed",
            "error_type": type(exc).__name__,
        }
    encoded = json.dumps(
        response,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    if len(encoded) > MAX_FOLLOW_ON_WORKER_RESPONSE:
        encoded = b'{"error":"follow_on_worker_response_limit","ok":false}'
    try:
        _write_private_regular_file(
            response_file,
            encoded,
            maximum_size=MAX_FOLLOW_ON_WORKER_RESPONSE,
        )
    except (OSError, ValueError):
        return 3
    return 0


def _execute_follow_on_child(
    *,
    payload: bytes,
    digest: str,
    parent_sha256: str,
    depth: int,
    output: Path,
    registry: Path,
    minimum_confidence: str,
    upx: Path | None,
    sevenzip: Path | None,
    diec: Path | None,
    force_container_probe: bool,
    max_static_layers: int,
    retry_max_static_layers: int | None,
    archive_password: str,
    string_scan_limit: int,
    analysis_contract: dict[str, Any],
    timeout_seconds: float,
    family_hints: Sequence[Mapping[str, Any]] | None = None,
    innounp: Path | None = None,
    inno_password: str = "",
) -> dict[str, Any]:
    """保持payloadを隔離processの既存analyze_unitへwall-clock上限付きで渡す。"""

    normalized_family_hints = []
    if family_hints:
        normalized_manifest = classify_sample.normalize_family_hint_manifest(
            {"schema_version": 1, "samples": {digest: list(family_hints)}}
        )
        normalized_family_hints = classify_sample.family_hints_for_sha256(
            normalized_manifest,
            digest,
        )
    request = {
        "schema_version": 1,
        "output": str(output.resolve(strict=True)),
        "registry": str(registry.resolve(strict=True)),
        "minimum_confidence": minimum_confidence,
        "upx": str(upx) if upx is not None else None,
        "sevenzip": str(sevenzip) if sevenzip is not None else None,
        "diec": str(diec) if diec is not None else None,
        "innounp": str(innounp) if innounp is not None else None,
        "force_container_probe": force_container_probe,
        "max_static_layers": max_static_layers,
        "retry_max_static_layers": retry_max_static_layers,
        "archive_password": archive_password,
        "inno_password": inno_password,
        "string_scan_limit": string_scan_limit,
        "analysis_contract": analysis_contract,
        "source_name": f"follow-on-{digest[:16]}.bin",
        "expected_sha256": digest,
        "expected_size": len(payload),
        "depth": depth,
        "parent_sha256": parent_sha256,
        "family_hints": normalized_family_hints,
    }
    request_raw = json.dumps(
        request,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    if len(request_raw) > MAX_FOLLOW_ON_WORKER_REQUEST:
        raise ValueError("follow-on worker requestがsize上限を超えています")
    frame = (
        len(request_raw).to_bytes(FOLLOW_ON_WORKER_FRAME_HEADER_BYTES, "big")
        + request_raw
        + payload
    )
    from bounded_process import run_bounded

    with tempfile.TemporaryDirectory(prefix="follow-on-analysis-") as temporary:
        temporary_root = Path(temporary).resolve(strict=True)
        ensure_no_reparse_components(temporary_root)
        response_path = temporary_root / "response.json"
        worker_temp = temporary_root / "worker-temp"
        worker_temp.mkdir(mode=0o700)
        os.chmod(worker_temp, 0o700)
        completed = run_bounded(
            [
                sys.executable,
                "-I",
                "-B",
                str(Path(__file__).resolve()),
                "--follow-on-worker",
            ],
            timeout=timeout_seconds,
            check=False,
            shell=False,
            env=_bounded_handler_environment(temporary_root=worker_temp),
            cwd=temporary_root,
            input=frame,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=False,
            require_containment=True,
            maximum_active_processes=MAX_FOLLOW_ON_WORKER_ACTIVE_PROCESSES,
            maximum_memory_bytes=MAX_FOLLOW_ON_WORKER_MEMORY_BYTES,
        )
        if completed.returncode != 0:
            raise RuntimeError("follow-on workerが失敗しました")
        response_raw = _read_private_regular_file(
            response_path,
            maximum_size=MAX_FOLLOW_ON_WORKER_RESPONSE,
        )
        response = _strict_json_object_bytes(response_raw, label="follow-on worker response")
    if response.get("ok") is not True or not isinstance(response.get("result"), dict):
        raise RuntimeError(str(response.get("error") or "follow_on_worker_invalid_response"))
    return response["result"]


def _atomic_replace_json(path: Path, value: object) -> None:
    """case JSONを同一directory内tempからatomic replaceする。"""

    ensure_no_reparse_components(path.parent)
    encoded = _encoded_json_document(value)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".follow-on-", suffix=".json", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        ensure_no_reparse_components(temporary)
        information = temporary.stat()
        if not stat.S_ISREG(information.st_mode) or information.st_nlink != 1:
            raise ValueError("follow-on atomic JSON tempが通常fileではありません")
        os.replace(temporary, path)
        ensure_no_reparse_components(path)
    finally:
        if temporary.exists():
            temporary.unlink(missing_ok=True)


def _encoded_json_document(value: object) -> bytes:
    """atomic JSON保存と事前artifact hash計算で同一のbytesを生成する。"""

    return (json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode("utf-8")


def _retained_outputs_from_wrapper(wrapper: object) -> list[dict[str, Any]]:
    """親再hash済み保持auditと一致するpayload metadataだけを返す。"""

    if not isinstance(wrapper, Mapping):
        return []
    has_outputs = "verified_binary_outputs" in wrapper
    has_audit = "verified_binary_output_audit" in wrapper
    if not has_outputs and not has_audit:
        return []
    if has_outputs != has_audit:
        raise ValueError("保持payload proof fieldが片方だけです")
    supplied = wrapper.get("verified_binary_outputs")
    if not isinstance(supplied, Sequence) or isinstance(supplied, (str, bytes, bytearray)):
        raise TypeError("保持payload metadataのschemaが不正です")
    if len(supplied) > MAX_FOLLOW_ON_ARTIFACTS:
        raise ValueError("保持payload metadataが件数上限を超えています")
    bounded = list(supplied)
    audit = orchestration_outcome._verified_output_audit(  # noqa: SLF001 - 同一pipelineのstrict schema
        wrapper.get("verified_binary_output_audit"),
        output_count=len(bounded),
    )
    if audit is None:
        raise ValueError("保持payload auditのschemaが不正です")
    outputs = []
    for supplied_output in bounded:
        output = orchestration_outcome._verified_binary_output(  # noqa: SLF001
            supplied_output
        )
        if output is None:
            raise ValueError("保持payload metadataを検証できません")
        outputs.append(output)
    return outputs


def _wrapper_follow_on_promotion_eligible(wrapper: object) -> bool:
    """全observed payloadが欠落・切捨てなく保持された監査だけを受理する。"""

    outputs = _retained_outputs_from_wrapper(wrapper)
    if not outputs or not isinstance(wrapper, Mapping):
        return False
    audit = wrapper.get("verified_binary_output_audit")
    if not isinstance(audit, Mapping):
        return False
    count = len(outputs)
    return (
        audit.get("observed_output_count") == count
        and audit.get("retained_output_count") == count
        and audit.get("truncated") is False
        and audit.get("reasons") == []
    )


def _case_wrapper_documents(
    case_dir: Path,
    report: Mapping[str, Any],
) -> tuple[list[tuple[Path, dict[str, Any]]], Path, dict[str, Any]]:
    """selected wrapper群とcandidate assessmentをcase境界内から厳格に読む。"""

    selected = []
    for execution in report.get("handler_executions") or []:
        if not isinstance(execution, Mapping) or not isinstance(execution.get("result"), str):
            continue
        path = resolve_case_artifact(case_dir, execution["result"])
        selected.append((path, load_json_object_strict(path)))
    candidate_path = resolve_case_artifact(case_dir, "candidate-handler-assessment.json")
    return selected, candidate_path, load_json_object_strict(candidate_path)


def _candidate_wrappers(candidate_assessment: Mapping[str, Any]) -> list[dict[str, Any]]:
    wrappers = []
    for family in candidate_assessment.get("families") or []:
        if not isinstance(family, Mapping):
            continue
        for attempt in family.get("attempts") or []:
            if not isinstance(attempt, Mapping):
                continue
            wrapper = attempt.get("result")
            if isinstance(wrapper, dict):
                wrappers.append(wrapper)
    return wrappers


def _follow_on_case_directory(output: Path, digest: str) -> Path:
    """follow-on caseを固定output配下の非reparse directoryへ限定する。"""

    normalized = normalize_sha256_digest(digest)
    ensure_no_reparse_components(output)
    resolved_output = output.resolve(strict=True)
    lexical = output / "cases" / normalized
    ensure_no_reparse_components(lexical)
    resolved = lexical.resolve(strict=True)
    try:
        resolved.relative_to(resolved_output)
    except ValueError as exc:
        raise ValueError("follow-on caseがoutput境界外です") from exc
    if not resolved.is_dir():
        raise ValueError("follow-on caseがdirectoryではありません")
    return resolved


def _case_retained_payloads(
    output: Path,
    digest: str,
    *,
    maximum_records: int,
    maximum_read_bytes: int,
    maximum_omitted_records: int = MAX_FOLLOW_ON_OMITTED_METADATA,
    include_omitted_metadata: bool = False,
    include_omitted_commitment: bool = False,
    deadline: float | None = None,
    monotonic: Callable[[], float] = time.monotonic,
) -> (
    tuple[list[dict[str, Any]], list[str], int, int]
    | tuple[list[dict[str, Any]], list[str], int, int, list[dict[str, Any]]]
    | tuple[
        list[dict[str, Any]],
        list[str],
        int,
        int,
        list[dict[str, Any]],
        dict[str, int | str] | None,
    ]
):
    """caseに保持されたpayloadを実file再検証付きでqueue recordへ変換する。"""

    for label, value in (
        ("maximum_records", maximum_records),
        ("maximum_read_bytes", maximum_read_bytes),
        ("maximum_omitted_records", maximum_omitted_records),
    ):
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValueError(f"{label}は0以上の整数でなければなりません")
    normalize_sha256_digest(digest)
    if include_omitted_commitment and not include_omitted_metadata:
        raise ValueError("commitment出力にはomitted metadata出力が必要です")
    omitted_metadata: list[dict[str, Any]] = []
    committed_omissions: Counter[tuple[str, str, str, str, int]] = Counter()
    errors: set[str] = set()

    def result(
        records: list[dict[str, Any]],
        read_count: int,
        read_bytes: int,
    ) -> (
        tuple[list[dict[str, Any]], list[str], int, int]
        | tuple[list[dict[str, Any]], list[str], int, int, list[dict[str, Any]]]
        | tuple[
            list[dict[str, Any]],
            list[str],
            int,
            int,
            list[dict[str, Any]],
            dict[str, int | str] | None,
        ]
    ):
        base = (records, sorted(errors), read_count, read_bytes)
        if not include_omitted_metadata:
            return base
        ordered_omissions = sorted(
            omitted_metadata,
            key=lambda item: (
                item["sha256"],
                item["path"],
                item["role"],
                item["kind"],
                item["size"],
                item["reason"],
            ),
        )
        if not include_omitted_commitment:
            return (*base, ordered_omissions)
        return (
            *base,
            ordered_omissions,
            canonical_multiset_commitment(committed_omissions),
        )

    def record_omission(
        metadata: Mapping[str, Any],
        reason: str,
        *,
        error: str | None = None,
    ) -> None:
        errors.add(error or reason)
        if len(omitted_metadata) >= maximum_omitted_records:
            errors.add("verified_output_omitted_metadata_limit")
            committed_omissions[metadata_identity(metadata)] += 1
            return
        omitted_metadata.append(
            {
                "sha256": str(metadata["sha256"]),
                "size": int(metadata["size"]),
                "path": str(metadata["path"]),
                "role": str(metadata["role"]),
                "kind": str(metadata["kind"]),
                "reason": reason,
            }
        )

    case_dir = _follow_on_case_directory(output, digest)
    repository = REPOSITORY_ROOT.resolve(strict=True)
    if case_dir == repository or repository in case_dir.parents:
        errors.add("repository_output_retention_forbidden")
        return result([], 0, 0)
    report = load_json_object_strict(resolve_case_artifact(case_dir, "report.json"))
    selected, _candidate_path, candidate_assessment = _case_wrapper_documents(case_dir, report)
    wrappers = [wrapper for _path, wrapper in selected]
    wrappers.extend(_candidate_wrappers(candidate_assessment))
    metadata_records: list[dict[str, Any]] = []
    for wrapper in wrappers:
        try:
            retained_outputs = _retained_outputs_from_wrapper(wrapper)
            retained_claimed = (
                isinstance(wrapper.get("verified_binary_output_audit"), Mapping)
                and wrapper["verified_binary_output_audit"].get("retained_for_follow_on_analysis") is True
            )
            if retained_claimed and not _wrapper_follow_on_promotion_eligible(wrapper):
                errors.add("incomplete_retention_audit")
        except (TypeError, ValueError):
            errors.add("invalid_retention_metadata")
            continue
        for metadata in retained_outputs:
            if len(metadata_records) >= maximum_records:
                record_omission(metadata, "verified_output_edge_limit")
                continue
            metadata_records.append(metadata)

    records: list[dict[str, Any]] = []
    cache: dict[tuple[str, str, int], bytes] = {}
    read_bytes = 0
    read_count = 0
    for index, metadata in enumerate(metadata_records):
        if deadline is not None and monotonic() >= deadline:
            for remaining_metadata in metadata_records[index:]:
                record_omission(
                    remaining_metadata,
                    "verified_output_read_wall_clock_limit",
                )
            break
        child_digest = str(metadata["sha256"])
        size = int(metadata["size"])
        key = (child_digest, str(metadata["path"]), size)
        raw = cache.get(key)
        if raw is None:
            if read_bytes + size > maximum_read_bytes:
                record_omission(metadata, "verified_output_read_bytes_limit")
                continue
            try:
                path = resolve_case_artifact(case_dir, str(metadata["path"]))
                read_options: dict[str, Any] = {}
                if deadline is not None:
                    read_options = {"deadline": deadline, "monotonic": monotonic}
                raw = _read_verified_artifact(
                    path,
                    expected_size=size,
                    expected_sha256=child_digest,
                    **read_options,
                )
            except TimeoutError:
                for remaining_metadata in metadata_records[index:]:
                    record_omission(
                        remaining_metadata,
                        "verified_output_read_wall_clock_limit",
                    )
                break
            except (OSError, ValueError, RuntimeError):
                record_omission(
                    metadata,
                    "artifact_verification_failed",
                    error=f"artifact_verification_failed:{child_digest}",
                )
                continue
            cache[key] = raw
            read_bytes += len(raw)
            read_count += 1
        records.append(
            {
                "sha256": child_digest,
                "size": len(raw),
                "path": str(metadata["path"]),
                "role": str(metadata["role"]),
                "kind": str(metadata["kind"]),
                "data": raw,
            }
        )
    return result(records, read_count, read_bytes)


def _case_directory_strict_complete(
    case_dir: Path,
    digest: str,
    *,
    expected_contract: Mapping[str, Any],
) -> bool:
    """指定case directoryのintegrityと全gateが厳格completeか確認する。"""

    try:
        report = load_json_object_strict(resolve_case_artifact(case_dir, "report.json"))
        if case_integrity_errors(
            case_dir,
            report,
            expected_digest=digest,
            expected_contract=expected_contract,
            require_resumable=True,
        ):
            return False
        outcome = load_json_object_strict(resolve_case_artifact(case_dir, "orchestration.json"))
    except (OSError, TypeError, ValueError):
        return False
    return (
        (report.get("case_state") or {}).get("status") == "complete"
        and outcome.get("status") == "complete"
        and outcome.get("blockers") == []
    )


def _case_strict_complete(
    output: Path,
    digest: str,
    *,
    expected_contract: Mapping[str, Any],
) -> bool:
    """case integrity・resumable state・orchestration gateが全てcompleteか確認する。"""

    try:
        case_dir = _follow_on_case_directory(output, digest)
    except (OSError, TypeError, ValueError):
        return False
    return _case_directory_strict_complete(
        case_dir,
        digest,
        expected_contract=expected_contract,
    )


def _case_result_from_disk(
    output: Path,
    digest: str,
    *,
    resumed: bool = False,
    expected_contract: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """fresh/partial子caseをsummary互換recordへ正規化する。"""

    case_dir = _follow_on_case_directory(output, digest)
    report = load_json_object_strict(resolve_case_artifact(case_dir, "report.json"))
    if expected_contract is not None and case_integrity_errors(
        case_dir,
        report,
        expected_digest=digest,
        expected_contract=expected_contract,
        require_resumable=False,
    ):
        raise ValueError("follow-on case integrityを検証できません")
    outcome = load_json_object_strict(resolve_case_artifact(case_dir, "orchestration.json"))
    candidate = load_json_object_strict(resolve_case_artifact(case_dir, "candidate-handler-assessment.json"))
    classification = report.get("classification") or {}
    executions = [item for item in report.get("handler_executions") or [] if isinstance(item, dict)]
    statuses = [item.get("status") for item in executions]
    case_state = (report.get("case_state") or {}).get("status")
    if case_state not in {"complete", "triaged_unknown", "partial", "failed"}:
        raise ValueError("follow-on caseがterminal stateへ到達していません")
    if case_state == "complete" and (outcome.get("status") != "complete" or outcome.get("blockers") != []):
        raise ValueError("complete caseとorchestration gateが一致しません")
    return {
        "sha256": digest,
        "source_name": (report.get("sample") or {}).get("source_name"),
        "family": classification.get("family"),
        "selected_family": classification.get("selected_family"),
        "selected_families": classification.get("selected_families") or [],
        "automation_family": (outcome.get("family_resolution") or {}).get("family"),
        "automation_state": _automation_summary_state(outcome),
        "candidate_handler_attempts": int(candidate.get("planned_attempt_count", 0)),
        "ai_used": False,
        "campaign": classification.get("campaign"),
        "handler_succeeded": sum(item == "succeeded" for item in statuses),
        "handler_failed": sum(item in {"failed", "preflight_failed"} for item in statuses),
        "handler_no_evidence": sum(item == "no_evidence" for item in statuses),
        "handler_ambiguous": sum(item == "ambiguous_evidence" for item in statuses),
        "handler_incompatible": sum(item == "incompatible_input_format" for item in statuses),
        "analysis_stage_failed": report.get("generic_triage") == "failed",
        "analysis_stage_partial": report.get("generic_triage") == "partial",
        "case_state": case_state,
        "report": f"cases/{digest}/report.json",
        "resumed": resumed,
    }


def _completed_follow_on_child_proof(
    output: Path,
    digest: str,
    *,
    analysis_contract: Mapping[str, Any],
) -> dict[str, Any]:
    """完全な子caseだけから親昇格へ使う暗号学的proofを作る。"""

    case_dir = _follow_on_case_directory(output, digest)
    report = load_json_object_strict(resolve_case_artifact(case_dir, "report.json"))
    errors = case_integrity_errors(
        case_dir,
        report,
        expected_digest=digest,
        expected_contract=analysis_contract,
        require_resumable=False,
    )
    outcome = load_json_object_strict(resolve_case_artifact(case_dir, "orchestration.json"))
    semantic_sha256 = report.get("report_semantic_sha256")
    if (
        errors
        or (report.get("case_state") or {}).get("status") != "complete"
        or outcome.get("status") != "complete"
        or outcome.get("blockers") != []
        or not isinstance(semantic_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", semantic_sha256) is None
    ):
        raise ValueError("follow-on child caseが厳格completeではありません")
    return {
        "sha256": digest,
        "analysis_contract_sha256": analysis_contract.get("sha256"),
        "report_semantic_sha256": semantic_sha256,
    }


def _case_has_follow_on_promotion(output: Path, digest: str) -> bool:
    """既存の厳格complete caseがfollow-on昇格proofを持つか返す。"""

    report = load_json_object_strict(
        resolve_case_artifact(
            _follow_on_case_directory(output, digest),
            "report.json",
        )
    )
    return isinstance(report.get("follow_on_promotion"), Mapping)


def _promote_wrapper_follow_on_audit(
    wrapper: dict[str, Any],
    *,
    proofs: Mapping[str, Mapping[str, Any]],
) -> bool:
    """wrapperの全保持payloadがcompleteの場合だけ解析完了auditへ昇格する。"""

    outputs = _retained_outputs_from_wrapper(wrapper)
    if not outputs or not _wrapper_follow_on_promotion_eligible(wrapper):
        return False
    digests = sorted({str(item["sha256"]) for item in outputs})
    if any(digest not in proofs for digest in digests):
        return False
    audit = wrapper.get("verified_binary_output_audit")
    if not isinstance(audit, dict):
        return False
    proof = {
        "schema_version": 1,
        "status": "all_retained_payloads_strict_complete",
        "children": [dict(proofs[digest]) for digest in digests],
    }
    changed = audit.get("follow_on_analysis_complete") is not True or wrapper.get("follow_on_analysis_proof") != proof
    audit["follow_on_analysis_complete"] = True
    wrapper["follow_on_analysis_proof"] = proof
    return changed


def _build_parent_case_follow_on_promotion(
    output: Path,
    digest: str,
    *,
    case_dir: Path,
    parent_contract: Mapping[str, Any],
    child_contract: Mapping[str, Any],
    specs: list[HandlerSpec],
    complete_child_digests: set[str],
) -> bool:
    """private shadow case内で親昇格documentを構築し、厳格検証する。"""
    report_path = resolve_case_artifact(case_dir, "report.json")
    report = copy.deepcopy(load_json_object_strict(report_path))
    integrity_errors = case_integrity_errors(
        case_dir,
        report,
        expected_digest=digest,
        expected_contract=parent_contract,
        require_resumable=False,
    )
    if integrity_errors:
        raise ValueError("parent case integrityが不正です")

    loaded_selected, candidate_path, loaded_candidate = _case_wrapper_documents(
        case_dir,
        report,
    )
    selected = [(path, copy.deepcopy(wrapper)) for path, wrapper in loaded_selected]
    candidate = copy.deepcopy(loaded_candidate)
    wrappers = [wrapper for _path, wrapper in selected]
    candidate_wrappers = _candidate_wrappers(candidate)
    all_wrappers = [*wrappers, *candidate_wrappers]
    required_digests = {
        str(item["sha256"]) for wrapper in all_wrappers for item in _retained_outputs_from_wrapper(wrapper)
    }
    eligible_digests = required_digests & complete_child_digests
    proofs = {
        child_digest: _completed_follow_on_child_proof(
            output,
            child_digest,
            analysis_contract=child_contract,
        )
        for child_digest in sorted(eligible_digests)
    }

    selected_changed: list[tuple[Path, dict[str, Any]]] = []
    for path, wrapper in selected:
        if _promote_wrapper_follow_on_audit(wrapper, proofs=proofs):
            selected_changed.append((path, wrapper))
    candidate_changed = False
    for wrapper in candidate_wrappers:
        if _promote_wrapper_follow_on_audit(wrapper, proofs=proofs):
            candidate_changed = True

    selected_overrides = {path: wrapper for path, wrapper in selected}
    records = [
        *_legacy_outcome_handler_records(
            case_dir,
            report.get("handler_executions") or [],
            specs,
            wrapper_overrides=selected_overrides,
        ),
        *_candidate_outcome_handler_records(candidate),
    ]
    outcome_path = resolve_case_artifact(case_dir, "orchestration.json")
    outcome = copy.deepcopy(load_json_object_strict(outcome_path))
    resolution = outcome.get("family_resolution")
    resolved_family = resolution.get("family") if isinstance(resolution, Mapping) else None
    candidate_outputs = orchestration_outcome.summarize_handler_outputs(
        records,
        verified_only=False,
    )
    outputs = (
        orchestration_outcome.summarize_handler_outputs(
            records,
            family_filter=resolved_family,
        )
        if isinstance(resolved_family, str)
        else orchestration_outcome.summarize_handler_outputs([])
    )
    outcome["outputs"] = outputs
    outcome["candidate_outputs"] = candidate_outputs
    gates = outcome.get("quality_gates")
    if not isinstance(gates, dict) or not isinstance(gates.get("terminal_payload"), dict):
        raise ValueError("parent orchestration gateが不正です")
    terminal_gate = gates["terminal_payload"]
    required = terminal_gate.get("required")
    satisfied = bool(outputs.get("terminal_payload_sha256"))
    terminal_gate["satisfied"] = satisfied
    terminal_gate["status"] = (
        "not_applicable"
        if required is False
        else "satisfied"
        if satisfied
        else "required_missing"
        if required is True
        else "not_declared"
    )
    old_blockers = [value for value in outcome.get("blockers") or [] if isinstance(value, str)]
    old_actions = [value for value in outcome.get("next_actions_ja") or [] if isinstance(value, str)]
    action_by_blocker = dict(zip(old_blockers, old_actions, strict=False))
    blockers = sorted(
        name for name, gate in gates.items() if isinstance(gate, Mapping) and gate.get("status") == "required_missing"
    )
    outcome["blockers"] = blockers
    outcome["next_actions_ja"] = [
        action_by_blocker.get(name, f"{name}の未解決事項を確認してください。") for name in blockers
    ]
    if blockers:
        outcome["status"] = "partial"
    elif isinstance(resolution, Mapping) and resolution.get("status") == "resolved":
        outcome["status"] = "complete"

    completion = report.get("case_state")
    if not isinstance(completion, dict):
        raise ValueError("parent case_stateが不正です")
    _synchronize_completion_with_outcome(completion, outcome)
    retained_output_digests = outputs.get("retained_terminal_payload_sha256")
    promoted_output_digests = outputs.get("terminal_payload_sha256")
    if (
        not isinstance(retained_output_digests, list)
        or not retained_output_digests
        or retained_output_digests != sorted(set(retained_output_digests))
        or promoted_output_digests != retained_output_digests
        or any(value not in proofs for value in promoted_output_digests)
    ):
        raise ValueError("resolved familyの保持payloadが親別proofと一致しません")
    report["follow_on_promotion"] = {
        "schema_version": 1,
        "status": "verified_children_linked",
        "child_analysis_contract_sha256": child_contract.get("sha256"),
        "children": [proofs[key] for key in promoted_output_digests],
    }

    planned_items = [*selected_changed]
    if candidate_changed:
        planned_items.append((candidate_path, candidate))
    planned_items.append((outcome_path, outcome))
    planned_paths = [path for path, _document in planned_items]
    if len(planned_paths) != len(set(planned_paths)) or report_path in planned_paths:
        raise ValueError("parent commit対象artifact pathが重複しています")
    planned_documents = dict(planned_items)

    manifest = report.get("artifact_sha256")
    if not isinstance(manifest, Mapping) or not manifest:
        raise ValueError("parent artifact manifestが不正です")
    manifest_keys = list(manifest)
    if any(not isinstance(value, str) or not value for value in manifest_keys):
        raise ValueError("parent artifact manifest pathが不正です")
    manifest_paths: dict[Path, str] = {}
    for relative in manifest_keys:
        artifact_path = resolve_case_artifact(case_dir, relative)
        if artifact_path in manifest_paths:
            raise ValueError("parent artifact manifest pathが重複しています")
        manifest_paths[artifact_path] = relative
    if not set(planned_documents).issubset(manifest_paths):
        raise ValueError("parent commit対象artifactがmanifestにありません")

    prepared_manifest = artifact_hashes(case_dir, manifest_keys)
    prepared_documents = {path: _encoded_json_document(document) for path, document in planned_documents.items()}
    for path, encoded in prepared_documents.items():
        prepared_manifest[manifest_paths[path]] = hashlib.sha256(encoded).hexdigest()
    report["artifact_sha256"] = prepared_manifest
    seal_report(report)
    _encoded_json_document(report)

    # ここからがcommit phase。上記のproof、gate、manifest検証失敗では一切書かない。
    for path in sorted(planned_documents, key=lambda value: str(value).casefold()):
        _atomic_replace_json(path, planned_documents[path])
    _atomic_replace_json(report_path, report)
    return _case_directory_strict_complete(
        case_dir,
        digest,
        expected_contract=parent_contract,
    )


def _promote_parent_case_from_follow_on(
    output: Path,
    digest: str,
    *,
    parent_contract: Mapping[str, Any],
    child_contract: Mapping[str, Any],
    specs: list[HandlerSpec],
    complete_child_digests: set[str],
) -> bool:
    """親case全体をWAL付きdirectory swapで同一seal境界へ原子昇格する。"""

    import publish_one_shot_collection as publisher  # noqa: PLC0415

    canonical = _follow_on_case_directory(output, digest)
    canonical.parent.mkdir(parents=True, exist_ok=True)
    with publisher._CasePublicationLock(canonical):  # noqa: SLF001
        publisher._recover_case_publication(canonical)  # noqa: SLF001
        old_tree_sha256 = publisher._case_tree_sha256(canonical)  # noqa: SLF001
        token = (
            f".casepub-{publisher._publication_case_name_key(canonical)}."  # noqa: SLF001
            f"{os.getpid():x}-{time.time_ns():x}"
        )
        staging_container = canonical.parent / f"{token}.staging"
        staging_container_io = publisher._publication_io_path(  # noqa: SLF001
            staging_container
        )
        staging = staging_container_io / digest
        backup = canonical.parent / f"{token}.backup"
        journal = {
            "schema_version": publisher.CASE_PUBLICATION_TRANSACTION_SCHEMA,
            "case_sha256": digest,
            "destination_path_sha256": publisher._publication_case_path_sha256(  # noqa: SLF001
                canonical
            ),
            "existing_destination": True,
            "old_tree_sha256": old_tree_sha256,
            "new_tree_sha256": None,
            "staging_name": staging_container.name,
            "backup_name": backup.name,
            "phase": "building",
        }
        journal_path = publisher._publication_journal_path(canonical)  # noqa: SLF001
        journal_sha256 = publisher._atomic_publication_journal(  # noqa: SLF001
            journal_path,
            journal,
            require_absent=True,
        )
        try:
            staging_container_io.mkdir()
            shutil.copytree(
                publisher._publication_io_path(canonical),  # noqa: SLF001
                staging,
            )
            promoted = _build_parent_case_follow_on_promotion(
                output,
                digest,
                case_dir=staging,
                parent_contract=parent_contract,
                child_contract=child_contract,
                specs=specs,
                complete_child_digests=complete_child_digests,
            )
            if not promoted:
                raise ValueError("follow-on shadow parentが厳格completeではありません")
            new_tree_sha256 = publisher._case_tree_sha256(staging)  # noqa: SLF001
            journal["new_tree_sha256"] = new_tree_sha256
            journal["phase"] = "prepared"
            journal_sha256 = publisher._atomic_publication_journal(  # noqa: SLF001
                journal_path,
                journal,
                expected_sha256=journal_sha256,
            )
            publisher._promote_case_publication(  # noqa: SLF001
                canonical,
                staging,
                new_tree_sha256=new_tree_sha256,
                journal=journal,
                journal_sha256=journal_sha256,
            )
        except BaseException:
            try:
                publisher._recover_case_publication(canonical)  # noqa: SLF001
            except BaseException as recovery_error:
                raise RuntimeError("follow-on parent transactionを自動回復できませんでした") from recovery_error
            raise
    return _case_strict_complete(
        output,
        digest,
        expected_contract=parent_contract,
    )


def _recover_follow_on_parent_transaction(output: Path, digest: str) -> None:
    """case読取前に中断した親directory transactionをrollback／roll-forwardする。"""

    import publish_one_shot_collection as publisher  # noqa: PLC0415

    normalized = normalize_sha256_digest(digest)
    cases_root_lexical = output / "cases"
    canonical_lexical = cases_root_lexical / normalized
    journal_path = publisher._publication_journal_path(  # noqa: SLF001
        canonical_lexical
    )
    if not os.path.lexists(journal_path):
        return
    cases_root = cases_root_lexical.resolve(strict=True)
    canonical = cases_root / normalized
    ensure_no_reparse_components(cases_root)
    with publisher._CasePublicationLock(canonical):  # noqa: SLF001
        publisher._recover_case_publication(canonical)  # noqa: SLF001


def _parent_complete_child_digests(
    parent_digest: str,
    *,
    outbound: Mapping[str, Sequence[int]],
    edges: Sequence[Mapping[str, Any]],
    depths: Mapping[str, int],
    strict_complete_digests: set[str],
) -> set[str]:
    """当該親が通常／shared edgeで到達したchild-contract完了SHAだけを返す。"""

    return {
        str(edges[index]["child_sha256"])
        for index in outbound.get(parent_digest, ())
        if edges[index].get("status") in {"queued", "shared_sha256_reference"}
        and edges[index].get("child_sha256") in strict_complete_digests
        and depths.get(str(edges[index].get("child_sha256")), 0) > 0
    }


def _run_follow_on_fixed_point(
    *,
    root_digests: Sequence[str],
    output: Path,
    registry: Path,
    specs: list[HandlerSpec],
    requirements_policy: dict[str, dict[str, Any]],
    minimum_confidence: str,
    upx: Path | None,
    sevenzip: Path | None,
    diec: Path | None,
    force_container_probe: bool,
    max_static_layers: int,
    retry_max_static_layers: int | None,
    archive_password: str,
    string_scan_limit: int,
    analysis_contract: dict[str, Any],
    root_analysis_contract: Mapping[str, Any],
    resume: bool,
    execute_child: Callable[..., dict[str, Any]] | None = None,
    monotonic: Callable[[], float] = time.monotonic,
    root_family_hints: Mapping[str, Sequence[Mapping[str, Any]]] | None = None,
    innounp: Path | None = None,
    inno_password: str = "",
) -> dict[str, Any]:
    """保持payloadをSHA-256固定点queueで同一job内の子caseへ再投入する。"""

    credential_safe_resume = resume and not archive_password and not inno_password
    repository = REPOSITORY_ROOT.resolve(strict=True)
    resolved_output = output.resolve(strict=True)
    limits = {
        "maximum_artifacts": MAX_FOLLOW_ON_ARTIFACTS,
        "maximum_edges": MAX_FOLLOW_ON_EDGES,
        "maximum_omitted_metadata": MAX_FOLLOW_ON_OMITTED_METADATA,
        "maximum_depth": MAX_FOLLOW_ON_DEPTH,
        "maximum_total_bytes": MAX_FOLLOW_ON_TOTAL_BYTES,
        "maximum_payload_size": MAX_FOLLOW_ON_PAYLOAD_SIZE,
        "maximum_wall_seconds": MAX_FOLLOW_ON_WALL_SECONDS,
        "maximum_child_seconds": MAX_FOLLOW_ON_CHILD_SECONDS,
    }
    base = {
        "schema_version": 1,
        "limits": limits,
        "analysis_contract_sha256": analysis_contract.get("sha256"),
        "executed_sample": False,
        "network_contacted": False,
        "ai_used": False,
    }
    if resolved_output == repository or repository in resolved_output.parents:
        return {
            **base,
            "status": "disabled_repository_output",
            "roots": sorted(set(root_digests)),
            "nodes": [],
            "edges": [],
            "omitted_metadata": [],
            "omitted_metadata_commitments": [],
            "errors": ["repository_output_retention_forbidden"],
            "wall_clock_exhausted": False,
        }
    executor = execute_child or _execute_follow_on_child
    deadline = monotonic() + MAX_FOLLOW_ON_WALL_SECONDS
    roots = sorted({normalize_sha256_digest(item) for item in root_digests})
    supplied_root_hints = root_family_hints or {}
    unknown_hint_roots = set(supplied_root_hints) - set(roots)
    if unknown_hint_roots:
        raise ValueError("root family hints reference a digest outside this fixed-point run")
    hint_context_by_digest: dict[str, list[dict[str, Any]]] = {}
    lineage_root_by_digest: dict[str, str] = {}
    lineage_depth_by_digest: dict[str, int] = {}
    for root_digest in roots:
        raw_hints = list(supplied_root_hints.get(root_digest, ()))
        if raw_hints:
            normalized_manifest = classify_sample.normalize_family_hint_manifest(
                {"schema_version": 1, "samples": {root_digest: raw_hints}}
            )
            hints = classify_sample.family_hints_for_sha256(normalized_manifest, root_digest)
        else:
            hints = []
        hint_context_by_digest[root_digest] = hints
        lineages = _family_hint_lineage_records(hints)
        lineage_contexts = {(item["root_sha256"], item["depth"]) for item in lineages}
        if len(lineage_contexts) == 1:
            lineage_root, lineage_depth = next(iter(lineage_contexts))
            lineage_root_by_digest[root_digest] = lineage_root
            lineage_depth_by_digest[root_digest] = lineage_depth
        elif lineage_contexts:
            # 異なるroot/depthを現在root/depth=0へ黙って畳むと、次の子artifactが
            # depth=1の新規lineageとして記録され、元のprovenance chainを失う。
            # どのchainを継承すべきか決定できない入力はfail closedにする。
            raise ValueError("root family hints contain conflicting artifact lineage contexts")
        else:
            lineage_root_by_digest[root_digest] = root_digest
            lineage_depth_by_digest[root_digest] = 0
    queue: deque[dict[str, Any]] = deque()
    queued: set[str] = set()
    visited: set[str] = set(roots)
    strict_complete_digests: set[str] = set()
    ancestors: dict[str, frozenset[str]] = {digest: frozenset({digest}) for digest in roots}
    depths: dict[str, int] = {digest: 0 for digest in roots}
    nodes: dict[str, dict[str, Any]] = {
        digest: {
            "sha256": digest,
            "depth": 0,
            "state": "root",
        }
        for digest in roots
    }
    edges: list[dict[str, Any]] = []
    outbound: dict[str, list[int]] = {}
    inbound: dict[str, set[str]] = {}
    errors: set[str] = set()
    omitted_metadata: list[dict[str, Any]] = []
    omitted_commitments_by_parent: dict[str, dict[str, Any]] = {}
    queued_bytes = 0
    queued_artifacts = 0
    verified_read_bytes = 0
    verified_read_count = 0
    wall_clock_exhausted = False

    def discover(parent_sha256: str) -> None:
        nonlocal queued_artifacts, queued_bytes, verified_read_bytes, verified_read_count
        nonlocal wall_clock_exhausted
        parent_depth = depths[parent_sha256]
        if monotonic() >= deadline:
            errors.add(f"{parent_sha256}:wall_clock_limit_before_discovery")
            return
        try:
            _recover_follow_on_parent_transaction(output, parent_sha256)
            scan_result = _case_retained_payloads(
                output,
                parent_sha256,
                maximum_records=max(0, MAX_FOLLOW_ON_EDGES - len(edges)),
                maximum_read_bytes=max(0, MAX_FOLLOW_ON_TOTAL_BYTES - verified_read_bytes),
                maximum_omitted_records=max(
                    0,
                    MAX_FOLLOW_ON_OMITTED_METADATA - len(omitted_metadata),
                ),
                include_omitted_metadata=True,
                include_omitted_commitment=True,
                deadline=deadline,
                monotonic=monotonic,
            )
            if not isinstance(scan_result, tuple):
                raise ValueError("保持payload scanの戻り値がtupleではありません")
            if len(scan_result) == 4:
                payloads, extraction_errors, read_count, read_bytes = scan_result
                scan_omissions: list[dict[str, Any]] = []
                scan_commitment = None
            elif len(scan_result) == 5:
                payloads, extraction_errors, read_count, read_bytes, supplied_omissions = scan_result
                if not isinstance(supplied_omissions, list):
                    raise ValueError("omitted metadataがlistではありません")
                scan_omissions = supplied_omissions
                scan_commitment = None
            elif len(scan_result) == 6:
                (
                    payloads,
                    extraction_errors,
                    read_count,
                    read_bytes,
                    supplied_omissions,
                    scan_commitment,
                ) = scan_result
                if not isinstance(supplied_omissions, list):
                    raise ValueError("omitted metadataがlistではありません")
                scan_omissions = supplied_omissions
            else:
                raise ValueError("保持payload scanの戻り値件数が不正です")
            normalized_omissions = []
            allowed_reasons = {
                "artifact_verification_failed",
                "verified_output_edge_limit",
                "verified_output_read_bytes_limit",
                "verified_output_read_wall_clock_limit",
            }
            for omission in scan_omissions:
                if (
                    not isinstance(omission, Mapping)
                    or set(omission) != {"sha256", "size", "path", "role", "kind", "reason"}
                    or omission.get("reason") not in allowed_reasons
                    or not isinstance(omission.get("size"), int)
                    or isinstance(omission.get("size"), bool)
                    or int(omission["size"]) < 0
                    or any(
                        not isinstance(omission.get(key), str) or not omission[key] for key in ("path", "role", "kind")
                    )
                ):
                    raise ValueError("omitted metadata recordが不正です")
                child_digest = normalize_sha256_digest(str(omission["sha256"]))
                normalized_omissions.append(
                    {
                        "parent_sha256": parent_sha256,
                        "sha256": child_digest,
                        "size": int(omission["size"]),
                        "path": str(omission["path"]),
                        "role": str(omission["role"]),
                        "kind": str(omission["kind"]),
                        "reason": str(omission["reason"]),
                    }
                )
            if len(omitted_metadata) + len(normalized_omissions) > MAX_FOLLOW_ON_OMITTED_METADATA:
                raise ValueError("omitted metadataが全体上限を超えました")
            omitted_metadata.extend(normalized_omissions)
            if scan_commitment is not None:
                if (
                    not isinstance(scan_commitment, Mapping)
                    or set(scan_commitment) != {"count", "sha256"}
                    or isinstance(scan_commitment.get("count"), bool)
                    or not isinstance(scan_commitment.get("count"), int)
                    or int(scan_commitment["count"]) <= 0
                    or not isinstance(scan_commitment.get("sha256"), str)
                ):
                    raise ValueError("omitted metadata commitmentが不正です")
                commitment_digest = normalize_sha256_digest(scan_commitment["sha256"])
                if parent_sha256 in omitted_commitments_by_parent:
                    raise ValueError("同一親のomitted metadata commitmentが重複しています")
                omitted_commitments_by_parent[parent_sha256] = {
                    "parent_sha256": parent_sha256,
                    "count": int(scan_commitment["count"]),
                    "sha256": commitment_digest,
                }
                if "verified_output_omitted_metadata_limit" not in extraction_errors:
                    extraction_errors.append("verified_output_omitted_metadata_limit")
            verified_read_count += read_count
            verified_read_bytes += read_bytes
        except (OSError, TypeError, ValueError) as exc:
            payloads = []
            extraction_errors = [f"case_retained_payload_scan_failed:{type(exc).__name__}"]
        if monotonic() >= deadline:
            wall_clock_exhausted = True
            extraction_errors.append("wall_clock_limit_after_discovery")
        errors.update(f"{parent_sha256}:{item}" for item in extraction_errors)
        for payload in payloads:
            child_sha256 = payload["sha256"]
            child_depth = parent_depth + 1
            edge = {
                "parent_sha256": parent_sha256,
                "child_sha256": child_sha256,
                "depth": child_depth,
                "path": payload["path"],
                "role": payload["role"],
                "kind": payload["kind"],
                "size": payload["size"],
                "status": "queued",
            }
            edge_index = len(edges)
            edges.append(edge)
            outbound.setdefault(parent_sha256, []).append(edge_index)
            inbound.setdefault(child_sha256, set()).add(parent_sha256)
            if child_sha256 in ancestors[parent_sha256]:
                edge["status"] = "cycle_excluded"
                continue
            if child_depth > MAX_FOLLOW_ON_DEPTH:
                edge["status"] = "depth_limit"
                continue
            if payload["size"] > MAX_FOLLOW_ON_PAYLOAD_SIZE:
                edge["status"] = "payload_size_limit"
                continue
            if child_sha256 in visited or child_sha256 in queued:
                edge["status"] = "shared_sha256_reference"
                continue
            if queued_artifacts + 1 > MAX_FOLLOW_ON_ARTIFACTS:
                edge["status"] = "artifact_count_limit"
                continue
            if queued_bytes + payload["size"] > MAX_FOLLOW_ON_TOTAL_BYTES:
                edge["status"] = "total_bytes_limit"
                continue
            parent_hints = hint_context_by_digest[parent_sha256]
            inherited_lineage_depth = lineage_depth_by_digest[parent_sha256] + 1
            inherited_manifest = (
                build_artifact_family_hint_manifest(
                    artifact_sha256=child_sha256,
                    parent_sha256=parent_sha256,
                    root_sha256=lineage_root_by_digest[parent_sha256],
                    artifact_kind=str(payload["kind"]),
                    source="one_shot_recovered_artifact",
                    source_id=f"sha256:{parent_sha256}",
                    depth=inherited_lineage_depth,
                    parent_hints=parent_hints,
                )
                if parent_hints and inherited_lineage_depth <= classify_sample.MAX_FAMILY_HINT_LINEAGE_DEPTH
                else None
            )
            inherited_hints = (
                classify_sample.family_hints_for_sha256(inherited_manifest, child_sha256)
                if inherited_manifest is not None
                else []
            )
            queued.add(child_sha256)
            visited.add(child_sha256)
            queued_artifacts += 1
            queued_bytes += payload["size"]
            depths[child_sha256] = child_depth
            ancestors[child_sha256] = frozenset({*ancestors[parent_sha256], child_sha256})
            hint_context_by_digest[child_sha256] = inherited_hints
            lineage_root_by_digest[child_sha256] = (
                lineage_root_by_digest[parent_sha256] if inherited_hints else child_sha256
            )
            lineage_depth_by_digest[child_sha256] = inherited_lineage_depth if inherited_hints else 0
            nodes[child_sha256] = {
                "sha256": child_sha256,
                "depth": child_depth,
                "size": payload["size"],
                "state": "queued",
                "family_hint_count": len(inherited_hints),
                "family_hint_root_sha256": (lineage_root_by_digest[child_sha256] if inherited_hints else None),
                "family_hint_lineage_depth": (lineage_depth_by_digest[child_sha256] if inherited_hints else None),
            }
            queue.append(
                {
                    **payload,
                    "parent_sha256": parent_sha256,
                    "depth": child_depth,
                    "family_hints": inherited_hints,
                }
            )

    for root in roots:
        discover(root)

    while queue:
        item = queue.popleft()
        digest = item["sha256"]
        remaining = deadline - monotonic()
        if remaining <= 0:
            wall_clock_exhausted = True
            nodes[digest]["state"] = "wall_clock_limit"
            while queue:
                pending = queue.popleft()
                nodes[pending["sha256"]]["state"] = "wall_clock_limit"
            break
        resumed_complete = credential_safe_resume and _case_strict_complete(
            output,
            digest,
            expected_contract=analysis_contract,
        )
        remaining = deadline - monotonic()
        if remaining <= 0:
            wall_clock_exhausted = True
            nodes[digest]["state"] = "wall_clock_limit"
            while queue:
                pending = queue.popleft()
                nodes[pending["sha256"]]["state"] = "wall_clock_limit"
            break
        if resumed_complete:
            nodes[digest]["state"] = "resumed_complete"
            nodes[digest]["case_state"] = "complete"
            strict_complete_digests.add(digest)
            discover(digest)
            continue
        remaining = deadline - monotonic()
        if remaining <= 0:
            wall_clock_exhausted = True
            nodes[digest]["state"] = "wall_clock_limit"
            while queue:
                pending = queue.popleft()
                nodes[pending["sha256"]]["state"] = "wall_clock_limit"
            break
        timeout = min(MAX_FOLLOW_ON_CHILD_SECONDS, remaining)
        try:
            executor(
                payload=item["data"],
                digest=digest,
                parent_sha256=item["parent_sha256"],
                depth=item["depth"],
                output=output,
                registry=registry,
                minimum_confidence=minimum_confidence,
                upx=upx,
                sevenzip=sevenzip,
                diec=diec,
                innounp=innounp,
                force_container_probe=force_container_probe,
                max_static_layers=max_static_layers,
                retry_max_static_layers=retry_max_static_layers,
                archive_password=archive_password,
                inno_password=inno_password,
                string_scan_limit=string_scan_limit,
                analysis_contract=analysis_contract,
                timeout_seconds=timeout,
                family_hints=item["family_hints"],
            )
            result = _case_result_from_disk(
                output,
                digest,
                expected_contract=analysis_contract,
            )
            if monotonic() >= deadline:
                wall_clock_exhausted = True
                nodes[digest]["state"] = "wall_clock_limit"
                while queue:
                    pending = queue.popleft()
                    nodes[pending["sha256"]]["state"] = "wall_clock_limit"
                break
            nodes[digest]["state"] = "analyzed"
            nodes[digest]["case_state"] = result.get("case_state")
            if result.get("case_state") == "complete":
                strict_complete_digests.add(digest)
            discover(digest)
        except subprocess.TimeoutExpired:
            nodes[digest]["state"] = "timeout"
        except Exception as exc:  # noqa: BLE001 - 子worker境界の失敗をqueue状態へ正規化する
            nodes[digest]["state"] = "failed"
            nodes[digest]["error_type"] = type(exc).__name__
            errors.add(f"{digest}:child_analysis_failed:{type(exc).__name__}")

    # rootを先に評価し、別rootと同じSHAの保持payloadを入力順序へ依存せず再利用する。
    for root_digest in roots:
        if _case_strict_complete(
            output,
            root_digest,
            expected_contract=root_analysis_contract,
        ):
            strict_complete_digests.add(root_digest)

    promoted_parents: set[str] = set()
    promotion_enabled = not omitted_commitments_by_parent
    for parent_digest in sorted(nodes, key=lambda value: (-depths[value], value)) if promotion_enabled else []:
        if depths[parent_digest] > 0 and nodes[parent_digest].get("state") not in {"analyzed", "resumed_complete"}:
            continue
        if monotonic() >= deadline:
            wall_clock_exhausted = True
            break
        expected_contract = root_analysis_contract if depths[parent_digest] == 0 else analysis_contract
        complete_child_digests = _parent_complete_child_digests(
            parent_digest,
            outbound=outbound,
            edges=edges,
            depths=depths,
            strict_complete_digests=strict_complete_digests,
        )
        if parent_digest in strict_complete_digests or _case_strict_complete(
            output,
            parent_digest,
            expected_contract=expected_contract,
        ):
            strict_complete_digests.add(parent_digest)
            if not _case_has_follow_on_promotion(output, parent_digest):
                continue
        elif not complete_child_digests:
            continue
        try:
            promoted = _promote_parent_case_from_follow_on(
                output,
                parent_digest,
                parent_contract=expected_contract,
                child_contract=analysis_contract,
                specs=specs,
                complete_child_digests=complete_child_digests,
            )
        except (OSError, TypeError, ValueError) as exc:
            errors.add(f"{parent_digest}:parent_promotion_failed:{type(exc).__name__}")
            continue
        if promoted:
            strict_complete_digests.add(parent_digest)
            promoted_parents.add(parent_digest)
            if depths[parent_digest] > 0:
                nodes[parent_digest]["case_state"] = "complete"
        if monotonic() >= deadline:
            wall_clock_exhausted = True
            break

    # 子の厳格complete証明があるedgeだけを完了として公開する。
    for edge in edges:
        if edge["status"] not in {"queued", "shared_sha256_reference"}:
            continue
        child_complete = edge["child_sha256"] in strict_complete_digests
        if edge["status"] == "shared_sha256_reference":
            edge["status"] = "shared_sha256_reused_complete" if child_complete else "shared_sha256_reused_incomplete"
        else:
            edge["status"] = "child_complete" if child_complete else "child_incomplete"
    all_children_complete = bool(edges) and all(
        edge["status"]
        in {
            "child_complete",
            "shared_sha256_reused_complete",
        }
        for edge in edges
    )
    return {
        **base,
        "status": (
            "no_retained_payloads"
            if (
                not edges
                and not omitted_metadata
                and not omitted_commitments_by_parent
                and not errors
                and not wall_clock_exhausted
            )
            else (
                "complete"
                if (
                    all_children_complete
                    and not omitted_metadata
                    and not omitted_commitments_by_parent
                    and not errors
                    and not wall_clock_exhausted
                )
                else "partial"
            )
        ),
        "roots": roots,
        "nodes": [nodes[key] for key in sorted(nodes)],
        "edges": sorted(
            edges,
            key=lambda item: (
                item["parent_sha256"],
                item["child_sha256"],
                item["path"],
            ),
        ),
        "omitted_metadata": sorted(
            omitted_metadata,
            key=lambda item: (
                item["parent_sha256"],
                item["sha256"],
                item["path"],
                item["role"],
                item["kind"],
                item["size"],
                item["reason"],
            ),
        ),
        "omitted_metadata_commitments": [
            omitted_commitments_by_parent[parent] for parent in sorted(omitted_commitments_by_parent)
        ],
        "errors": sorted(errors),
        "queued_artifact_count": queued_artifacts,
        "queued_total_bytes": queued_bytes,
        "verified_read_count": verified_read_count,
        "verified_read_bytes": verified_read_bytes,
        "parent_promotion_enabled": promotion_enabled,
        "promoted_parent_sha256": sorted(promoted_parents),
        "wall_clock_exhausted": wall_clock_exhausted,
    }


def _validate_runtime_handler_catalog(specs: Sequence[HandlerSpec]) -> None:
    """解析直前のautomatic handler集合が有界な入力契約を持つか検証する。"""

    automatic = [
        spec for spec in specs if spec.automatic and spec.supported_interface
    ]
    if not automatic or len(automatic) > 256:
        raise ValueError("automatic handler catalog件数が不正です")
    for spec in automatic:
        formats = [value for value in spec.input_formats if value != "any"]
        if not formats:
            raise ValueError(f"handler input formatが有界ではありません: {spec.id}")


def run_batch(
    inputs: list[Path],
    output: Path,
    *,
    registry: Path = DEFAULT_REGISTRY,
    password: str = "infected",
    archive_mode: str = "auto",
    forced_family: str | None = None,
    minimum_confidence: str = "medium",
    assessment_only: bool = False,
    max_files: int = DEFAULT_MAX_FILES,
    upx: Path | None = None,
    sevenzip: Path | None = None,
    diec: Path | None = None,
    innounp: Path | None = None,
    force_container_probe: bool = False,
    max_static_layers: int = MAX_STATIC_LAYERS,
    retry_max_static_layers: int | None = None,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    string_scan_limit: int = DEFAULT_STRING_SCAN_LIMIT,
    resume: bool = False,
    family_hint_manifest: Path | None = None,
    inno_password: str = "",
) -> dict[str, Any]:
    """複数入力をSHA-256で重複排除し、失敗を検体単位に分離する。"""

    output.mkdir(parents=True, exist_ok=True)
    paths = collect_inputs(inputs, output, max_files)
    if archive_mode == "malwarebazaar":
        paths = [path for path in paths if path.suffix.casefold() == ".zip"]
    if not paths:
        raise ValueError("解析対象ファイルがありません")
    if not isinstance(password, str):
        raise TypeError("archive passwordは文字列で指定してください")
    if not isinstance(inno_password, str):
        raise TypeError("Inno passwordは文字列で指定してください")
    if isinstance(string_scan_limit, bool) or not isinstance(string_scan_limit, int) or string_scan_limit <= 0:
        raise ValueError("string_scan_limitは正の整数で指定してください")
    StaticLayerPolicy(max_layers=max_static_layers)
    if retry_max_static_layers is not None:
        StaticLayerPolicy(max_layers=retry_max_static_layers)
        if retry_max_static_layers <= max_static_layers:
            raise ValueError("retry_max_static_layersは初回上限より大きくしてください")
    upx = _normalize_tool_path(upx, "UPX")
    sevenzip = _normalize_tool_path(sevenzip, "7-Zip")
    diec = _normalize_tool_path(diec, "Detect It Easy CLI")
    innounp = _normalize_tool_path(innounp, "innounp")
    family_hint_document, family_hint_identity = _load_family_hint_manifest(family_hint_manifest)
    family_requirements_policy = _load_family_analysis_requirements()

    clear_handler_caches()
    classify_sample.clear_classifier_caches()
    clear_profile_cache()
    clear_known_hash_cache()
    specs = discover_handlers()
    _validate_runtime_handler_catalog(specs)
    component_snapshot = _AnalysisComponentSnapshot.capture(registry, specs)
    registered = _registered_families(registry)
    forced_family = normalize_family(forced_family) if forced_family else None
    if forced_family and forced_family not in registered:
        raise ValueError(f"未登録のファミリーです: {forced_family}")
    analysis_contract = _build_analysis_contract(
        registry=registry,
        specs=specs,
        archive_mode=archive_mode,
        forced_family=forced_family,
        minimum_confidence=minimum_confidence,
        assessment_only=assessment_only,
        upx=upx,
        sevenzip=sevenzip,
        diec=diec,
        innounp=innounp,
        force_container_probe=force_container_probe,
        max_static_layers=max_static_layers,
        retry_max_static_layers=retry_max_static_layers,
        archive_password=password,
        max_file_size=max_file_size,
        string_scan_limit=string_scan_limit,
        family_hint_manifest_identity=family_hint_identity,
        component_snapshot=component_snapshot,
        inno_password=inno_password,
    )
    follow_on_analysis_contract = _build_follow_on_analysis_contract(
        registry=registry,
        specs=specs,
        minimum_confidence=minimum_confidence,
        upx=upx,
        sevenzip=sevenzip,
        diec=diec,
        innounp=innounp,
        force_container_probe=force_container_probe,
        max_static_layers=max_static_layers,
        retry_max_static_layers=retry_max_static_layers,
        archive_password=password,
        string_scan_limit=string_scan_limit,
        family_hint_manifest_identity=family_hint_identity,
        component_snapshot=component_snapshot,
        inno_password=inno_password,
    )
    component_snapshot.verify()
    credential_safe_follow_on_resume = resume and not password and not inno_password
    cases = []
    errors = []
    duplicates = []
    seen: set[str] = set()
    for input_index, path in enumerate(paths):
        try:
            unit = read_input_unit(
                path,
                password=password,
                archive_mode=archive_mode,
                max_file_size=max_file_size,
            )
        except Exception as exc:  # noqa: BLE001 - 入力単位で後続解析を継続する
            errors.append(
                batch_error_contract.build_record(
                    input_index=input_index,
                    stage="input_read",
                    error=exc,
                )
            )
            continue
        digest = hashlib.sha256(unit.data).hexdigest()
        if digest in seen:
            duplicates.append({"source_name": path.name, "sha256": digest})
            continue
        seen.add(digest)
        if resume:
            try:
                resumed = load_resumable_case(
                    output,
                    digest,
                    assessment_only=assessment_only,
                    expected_contract=analysis_contract,
                    unit=unit,
                )
            except Exception as exc:  # noqa: BLE001 - resume不整合を新規解析と混同しない
                errors.append(
                    batch_error_contract.build_record(
                        input_index=input_index,
                        sha256=digest,
                        stage="resume_validation",
                        error=exc,
                    )
                )
                continue
            if resumed is not None:
                cases.append(resumed)
                continue
        try:
            cases.append(
                analyze_unit(
                    unit,
                    output=output,
                    registry=registry,
                    specs=specs,
                    registered=registered,
                    forced_family=forced_family,
                    minimum_confidence=minimum_confidence,
                    upx=upx,
                    sevenzip=sevenzip,
                    diec=diec,
                    innounp=innounp,
                    force_container_probe=force_container_probe,
                    max_static_layers=max_static_layers,
                    retry_max_static_layers=retry_max_static_layers,
                    archive_password=password,
                    inno_password=inno_password,
                    string_scan_limit=string_scan_limit,
                    assessment_only=assessment_only,
                    analysis_contract=analysis_contract,
                    family_hint_manifest=family_hint_document,
                    family_requirements_policy=family_requirements_policy,
                )
            )
        except Exception as exc:  # noqa: BLE001 - root検体単位で後続解析を継続する
            errors.append(
                batch_error_contract.build_record(
                    input_index=input_index,
                    sha256=digest,
                    stage="root_static_analysis",
                    error=exc,
                )
            )
    if assessment_only:
        follow_on = {
            "schema_version": 1,
            "status": "disabled_assessment_only",
            "roots": sorted(item["sha256"] for item in cases),
            "nodes": [],
            "edges": [],
            "omitted_metadata": [],
            "omitted_metadata_commitments": [],
            "errors": [],
            "executed_sample": False,
            "network_contacted": False,
            "ai_used": False,
        }
    else:
        try:
            follow_on = _run_follow_on_fixed_point(
                root_digests=[item["sha256"] for item in cases],
                output=output,
                registry=registry,
                specs=specs,
                requirements_policy=family_requirements_policy,
                minimum_confidence=minimum_confidence,
                upx=upx,
                sevenzip=sevenzip,
                diec=diec,
                innounp=innounp,
                force_container_probe=force_container_probe,
                max_static_layers=max_static_layers,
                retry_max_static_layers=retry_max_static_layers,
                archive_password=password,
                inno_password=inno_password,
                string_scan_limit=string_scan_limit,
                analysis_contract=follow_on_analysis_contract,
                root_analysis_contract=analysis_contract,
                resume=credential_safe_follow_on_resume,
                root_family_hints={
                    item["sha256"]: (
                        classify_sample.family_hints_for_sha256(
                            family_hint_document,
                            item["sha256"],
                        )
                        if family_hint_document is not None
                        else []
                    )
                    for item in cases
                },
            )
            refreshed = []
            for item in cases:
                try:
                    updated = _case_result_from_disk(
                        output,
                        item["sha256"],
                        resumed=bool(item.get("resumed")),
                        expected_contract=analysis_contract,
                    )
                except (OSError, TypeError, ValueError):
                    updated = item
                refreshed.append(updated)
            cases = refreshed
        except Exception as exc:  # noqa: BLE001 - fixed-point全体の障害をroot結果から分離する
            follow_on = {
                "schema_version": 1,
                "status": "failed",
                "roots": sorted(item["sha256"] for item in cases),
                "nodes": [],
                "edges": [],
                "omitted_metadata": [],
                "omitted_metadata_commitments": [],
                "errors": [f"fixed_point_failed:{type(exc).__name__}"],
                "executed_sample": False,
                "network_contacted": False,
                "ai_used": False,
            }
    component_snapshot.verify()
    root_digests = {item["sha256"] for item in cases}
    derived_parents: dict[str, set[str]] = {}
    for edge in follow_on.get("edges") or []:
        if (
            isinstance(edge, Mapping)
            and edge.get("status")
            in {
                "child_complete",
                "child_incomplete",
            }
            and isinstance(edge.get("child_sha256"), str)
        ):
            derived_parents.setdefault(edge["child_sha256"], set()).add(str(edge.get("parent_sha256")))
    derived_cases = []
    follow_on_errors = {str(value) for value in follow_on.get("errors") or [] if isinstance(value, str)}
    for node in follow_on.get("nodes") or []:
        if not isinstance(node, Mapping) or not isinstance(node.get("depth"), int):
            continue
        digest = node.get("sha256")
        if node["depth"] <= 0 or not isinstance(digest, str) or digest in root_digests:
            continue
        if node.get("state") not in {"analyzed", "resumed_complete"}:
            continue
        try:
            item = _case_result_from_disk(
                output,
                digest,
                resumed=node.get("state") == "resumed_complete",
                expected_contract=follow_on_analysis_contract,
            )
        except (OSError, TypeError, ValueError) as exc:
            follow_on_errors.add(f"{digest}:derived_case_omitted:{type(exc).__name__}")
            if isinstance(node, dict):
                node["state"] = "incomplete_case_omitted"
            continue
        item["case_origin"] = "derived_follow_on"
        item["follow_on_depth"] = node["depth"]
        item["parent_sha256"] = sorted(derived_parents.get(digest, set()))
        derived_cases.append(item)
    if follow_on_errors != set(follow_on.get("errors") or []):
        follow_on["errors"] = sorted(follow_on_errors)
        follow_on["status"] = "partial"
    derived_cases.sort(key=lambda item: (item["follow_on_depth"], item["sha256"]))
    derived_counts = {
        "analyzed": len(derived_cases),
        "identified": sum(bool(item["selected_families"]) for item in derived_cases),
        "unknown_or_ambiguous": sum(not item["selected_families"] for item in derived_cases),
        "complete": sum(item["case_state"] == "complete" for item in derived_cases),
        "triaged_unknown": sum(item["case_state"] == "triaged_unknown" for item in derived_cases),
        "partial": sum(item["case_state"] == "partial" for item in derived_cases),
        "failed": sum(item["case_state"] == "failed" for item in derived_cases),
        "resumed": sum(bool(item.get("resumed")) for item in derived_cases),
    }
    root_case_states = (
        {item["sha256"]: item["case_state"] for item in cases}
        if follow_on["status"] in terminal_payload_acquisition.OPERATIONAL_STATUSES
        else None
    )
    acquisition = terminal_payload_acquisition.build_terminal_payload_acquisition(
        follow_on,
        root_case_states=root_case_states,
    )
    _atomic_replace_json(output / "terminal-payload-acquisition.json", acquisition)
    acquisition_digest = hashlib.sha256((output / "terminal-payload-acquisition.json").read_bytes()).hexdigest()
    _atomic_replace_json(output / "follow-on-analysis.json", follow_on)
    follow_on_digest = hashlib.sha256((output / "follow-on-analysis.json").read_bytes()).hexdigest()
    summary = {
        "schema_version": 1,
        "counts": {
            "input_files": len(paths),
            "analyzed": len(cases),
            "duplicates": len(duplicates),
            "errors": len(errors),
            "identified": sum(bool(item["selected_families"]) for item in cases),
            "unknown_or_ambiguous": sum(not item["selected_families"] for item in cases),
            "automation_resolved": sum(item.get("automation_state") == "resolved" for item in cases),
            "automation_partial": sum(item.get("automation_state") == "partial" for item in cases),
            "automation_unknown": sum(item.get("automation_state") == "unknown" for item in cases),
            "candidate_handler_attempts": sum(item.get("candidate_handler_attempts", 0) for item in cases),
            "handler_successes": sum(item["handler_succeeded"] for item in cases),
            "handler_failures": sum(item["handler_failed"] for item in cases),
            "handler_no_evidence": sum(item["handler_no_evidence"] for item in cases),
            "handler_ambiguous": sum(item["handler_ambiguous"] for item in cases),
            "handler_incompatible": sum(item["handler_incompatible"] for item in cases),
            "analysis_stage_failures": sum(item["analysis_stage_failed"] for item in cases),
            "analysis_stage_partial": sum(item["analysis_stage_partial"] for item in cases),
            "complete": sum(item["case_state"] == "complete" for item in cases),
            "triaged_unknown": sum(item["case_state"] == "triaged_unknown" for item in cases),
            "partial": sum(item["case_state"] == "partial" for item in cases),
            "failed": sum(item["case_state"] == "failed" for item in cases),
            "resumed": sum(bool(item.get("resumed")) for item in cases),
        },
        "catalog": catalog_summary(specs),
        "analysis_contract": analysis_contract,
        "follow_on_analysis_contract": follow_on_analysis_contract,
        "requirements_policy": _requirements_policy_summary(family_requirements_policy),
        "follow_on_analysis": {
            "artifact": "follow-on-analysis.json",
            "sha256": follow_on_digest,
            "status": follow_on.get("status"),
            "node_count": len(follow_on.get("nodes") or []),
            "edge_count": len(follow_on.get("edges") or []),
            "error_count": len(follow_on.get("errors") or []),
        },
        "terminal_payload_acquisition": {
            "artifact": "terminal-payload-acquisition.json",
            "sha256": acquisition_digest,
            "status": acquisition["status"],
            "frontier_count": len(acquisition["frontier"]),
            "selected_count": len(acquisition["selected_sha256"]),
            "pending_count": len(acquisition["pending_sha256"]),
        },
        "cases": cases,
        "derived_cases": derived_cases,
        "derived_counts": derived_counts,
        "duplicates": duplicates,
        "errors": errors,
        "settings": {
            "archive_mode": archive_mode,
            "forced_family": forced_family,
            "minimum_confidence": minimum_confidence,
            "assessment_only": assessment_only,
            "max_files": max_files,
            "max_file_size": max_file_size,
            "string_scan_limit": string_scan_limit,
            "family_hint_manifest": family_hint_identity,
            # root解析契約で封印済みのidentityをそのまま公開する。ここだけ
            # tool名へ縮退すると、toolを利用した長時間jobが全case生成後の
            # runner検証で失敗し、同一検体の再解析が必要になる。
            "static_tools": dict(analysis_contract["settings"]["static_tools"]),
            "force_container_probe": force_container_probe,
            "max_static_layers": max_static_layers,
            "retry_max_static_layers": retry_max_static_layers,
            "resume": resume,
            "follow_on_fixed_point": not assessment_only,
        },
        "executed_sample": False,
        "network_contacted": False,
        "ai_used": False,
    }
    write_json(output / "summary.json", summary)
    return summary


def build_parser() -> argparse.ArgumentParser:
    """日本語helpを持つ一括静的解析CLIを構築する。"""

    parser = JapaneseArgumentParser(description=__doc__)
    parser.add_argument(
        "--input",
        required=True,
        action="append",
        type=Path,
        help="解析するファイルまたはディレクトリ。複数回指定できます。",
    )
    parser.add_argument("--output", required=True, type=Path, help="解析結果の出力先。")
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY, help="検出器レジストリ。")
    parser.add_argument(
        "--password-stdin",
        action="store_true",
        help="外装archive credentialを有界stdinから読みます（automation推奨）。",
    )
    parser.add_argument(
        "--archive-mode",
        choices=("auto", "raw", "malwarebazaar"),
        default="auto",
        help="autoは暗号化単一メンバーZIPだけをメモリ内展開します。",
    )
    parser.add_argument("--family", help="ファミリーを明示選択します。構造一致の代替証拠にはしません。")
    parser.add_argument(
        "--family-hint-manifest",
        type=Path,
        help="root SHA-256へ完全一致する外部familyヒントのstrict JSON。ヒント単独では確定しません。",
    )
    parser.add_argument(
        "--minimum-confidence",
        choices=("low", "medium", "high"),
        default="medium",
        help="ファミリー固有解析器を自動実行する最低確度。",
    )
    parser.add_argument(
        "--assessment-only",
        action="store_true",
        help="適用可否判定だけを行い、汎用・ファミリー固有解析器を実行しません。",
    )
    parser.add_argument("--max-files", type=int, default=DEFAULT_MAX_FILES, help="入力ファイル数の上限。")
    parser.add_argument(
        "--max-file-size",
        type=int,
        default=DEFAULT_MAX_FILE_SIZE,
        help="外装と内包検体それぞれのbyte上限。",
    )
    parser.add_argument(
        "--string-scan-limit",
        type=_positive_integer,
        default=DEFAULT_STRING_SCAN_LIMIT,
        help="各静的復元層から保持する文字列候補数の上限。正の整数で指定します。",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="安全フラグと必須成果物を検証できた完了caseを再利用します。",
    )
    parser.add_argument(
        "--upx",
        type=Path,
        help="任意のUPX実行file。明示指定時だけ静的展開へ使用します。",
    )
    parser.add_argument(
        "--sevenzip",
        type=Path,
        help="任意の7-Zip実行file。7z/RAR/CAB/DMG/PE containerの静的展開に使用します。",
    )
    parser.add_argument(
        "--innounp",
        type=Path,
        help="任意のinnounp実行file。Inno Setupの静的一覧化・選択展開に使用します。",
    )
    parser.add_argument(
        "--inno-password-stdin",
        action="store_true",
        help=(
            "互換credentialを有界stdinから読みます。暗号化Innoの自動解除は"
            "credential transport未対応のためblockedです。"
        ),
    )
    parser.add_argument(
        "--diec",
        type=Path,
        help="任意のDetect It Easy CLI実行file。PE/Mach-O識別補助に使用します。",
    )
    parser.add_argument(
        "--max-static-layers",
        type=int,
        default=MAX_STATIC_LAYERS,
        help="静的復元で保持する層数の初回上限。正の整数で指定します。",
    )
    parser.add_argument(
        "--retry-max-static-layers",
        type=int,
        help="初回に層数上限へ達した検体だけ再試行する上限。初回上限より大きく指定します。",
    )
    parser.add_argument(
        "--force-container-probe",
        action="store_true",
        help="レビュー済み手掛かりがあるPEを7-Zipで追加検査します。",
    )
    return parser


def _runtime_preflight_main() -> int:
    """隔離runtimeでhandler catalogを構築できることを短時間で検証する。"""

    try:
        runtime_contract.import_required_runtime_modules()
        clear_handler_caches()
        specs = discover_handlers()
        _validate_runtime_handler_catalog(specs)
    except Exception:  # noqa: BLE001 - runtime境界では詳細を外へ出さず失敗codeだけ返す
        return 2
    return 0


def _runtime_dependency_preflight_main() -> int:
    """通常CLIで固定runtime依存だけを検査し、catalog発見はrun_batchへ委ねる。"""

    try:
        runtime_contract.import_required_runtime_modules()
    except Exception:  # noqa: BLE001 - runtime境界では詳細を外へ出さず失敗codeだけ返す
        return 2
    return 0


def _interpreter_is_isolated() -> bool:
    """現在のPythonが`-I`で起動された場合だけTrueを返す。"""

    return bool(sys.flags.isolated)


def _direct_cli_request(
    request: Any,
) -> tuple[list[str], str | None, str | None]:
    """direct CLI worker requestを完全一致schemaとcredentialへ正規化する。"""

    expected_keys = {
        "schema_version",
        "arguments",
        "archive_password",
        "inno_password",
    }
    if not isinstance(request, dict) or set(request) != expected_keys:
        raise ValueError("direct CLI worker request schemaが不正です")
    if type(request["schema_version"]) is not int or request["schema_version"] != 1:
        raise ValueError("direct CLI worker request versionが不正です")
    arguments = request["arguments"]
    if not isinstance(arguments, list) or len(arguments) > MAX_DIRECT_CLI_ARGUMENTS:
        raise ValueError("direct CLI worker argv件数が不正です")
    if any(
        not isinstance(value, str)
        or "\x00" in value
        or len(value) > MAX_DIRECT_CLI_ARGUMENT_CHARACTERS
        for value in arguments
    ):
        raise ValueError("direct CLI worker argv値が不正です")
    if _contains_raw_cli_credential_option(arguments):
        raise ValueError("direct CLI worker argvに廃止済みcredential optionがあります")
    credentials: list[str | None] = []
    for name in ("archive_password", "inno_password"):
        credential = request[name]
        if credential is not None and (
            not isinstance(credential, str)
            or "\x00" in credential
            or "\r" in credential
            or "\n" in credential
            or len(credential.encode("utf-8")) > MAX_CLI_CREDENTIAL_BYTES
        ):
            raise ValueError("direct CLI worker credentialが不正です")
        credentials.append(credential)
    return list(arguments), credentials[0], credentials[1]


def _contains_raw_cli_credential_option(arguments: Sequence[str]) -> bool:
    """廃止済みの値付きcredential optionが含まれる場合だけTrueを返す。"""

    raw_options = ("--password", "--inno-password")
    return any(
        value == option or value.startswith(f"{option}=")
        for value in arguments
        for option in raw_options
    )


def _resolve_cli_stdin_credential_options(
    arguments: Sequence[str],
) -> tuple[list[str], str | None, str | None]:
    """stdin credential optionを除去し、private request fieldへ分離する。"""

    resolved = list(arguments)
    options = (
        ("--password-stdin", "archive_password"),
        ("--inno-password-stdin", "inno_password"),
    )
    selected = [(source, target) for source, target in options if source in resolved]
    if not selected:
        return resolved, None, None
    if len(selected) != 1 or resolved.count(selected[0][0]) != 1:
        raise ValueError("stdin credential optionの指定が不正です")
    source, target = selected[0]
    raw = sys.stdin.buffer.read(MAX_CLI_CREDENTIAL_BYTES + 1)
    if not raw or len(raw) > MAX_CLI_CREDENTIAL_BYTES:
        raise ValueError("stdin credential sizeが不正です")
    raw = raw.removesuffix(b"\n").removesuffix(b"\r")
    if b"\x00" in raw or b"\r" in raw or b"\n" in raw:
        raise ValueError("stdin credential形式が不正です")
    try:
        credential = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("stdin credential encodingが不正です") from exc
    resolved.remove(source)
    return (
        resolved,
        credential if target == "archive_password" else None,
        credential if target == "inno_password" else None,
    )


def _direct_cli_response(raw: bytes) -> tuple[int, dict[str, int]]:
    """direct CLI worker応答を固定schemaの終了codeとcountsへ正規化する。"""

    response = _strict_json_object_bytes(raw, label="direct CLI worker response")
    if set(response) != {"schema_version", "exit_code", "counts"}:
        raise ValueError("direct CLI worker response schemaが不正です")
    if type(response["schema_version"]) is not int or response["schema_version"] != 1:
        raise ValueError("direct CLI worker response versionが不正です")
    exit_code = response["exit_code"]
    counts = response["counts"]
    if type(exit_code) is not int or not 0 <= exit_code <= 255:
        raise ValueError("direct CLI worker response終了codeが不正です")
    if not isinstance(counts, dict) or len(counts) > 128:
        raise ValueError("direct CLI worker response countsが不正です")
    if any(
        not isinstance(key, str)
        or not key
        or len(key) > 128
        or type(value) is not int
        or not 0 <= value <= sys.maxsize
        for key, value in counts.items()
    ):
        raise ValueError("direct CLI worker response count値が不正です")
    return exit_code, dict(counts)


def _direct_cli_worker_main() -> int:
    """秘密値をargvへ載せず、有界stdin requestから通常CLIを実行する。"""

    if not _interpreter_is_isolated():
        return 2
    try:
        response_root = Path.cwd().resolve(strict=True)
        ensure_no_reparse_components(response_root)
        request_raw = sys.stdin.buffer.read(MAX_DIRECT_CLI_REQUEST + 1)
        if not request_raw or len(request_raw) > MAX_DIRECT_CLI_REQUEST:
            raise ValueError("direct CLI worker request sizeが不正です")
        request = _strict_json_object_bytes(request_raw, label="direct CLI worker request")
        arguments, archive_password, inno_password = _direct_cli_request(request)
    except (OSError, TypeError, ValueError):
        return 2
    try:
        os.chdir(REPOSITORY_ROOT)
        try:
            exit_code, counts = _execute_cli(
                arguments,
                archive_password_override=archive_password,
                inno_password_override=inno_password,
            )
        finally:
            os.chdir(response_root)
    except BaseException:  # noqa: BLE001 - private request由来の値をstdioへ出さない
        return 2
    try:
        response_raw = json.dumps(
            {"schema_version": 1, "exit_code": exit_code, "counts": counts},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        _write_private_regular_file(
            response_root / "response.json",
            response_raw,
            maximum_size=MAX_DIRECT_CLI_RESPONSE,
        )
    except (OSError, TypeError, ValueError):
        return 2
    return 0


def _run_isolated_cli(argv: Sequence[str] | None) -> int:
    """通常CLIの解析本体を同じPythonの隔離processへ移し、終了codeを返す。"""

    if _interpreter_is_isolated():
        raise RuntimeError("isolated CLIを再帰起動できません")
    arguments = list(sys.argv[1:] if argv is None else argv)
    if _contains_raw_cli_credential_option(arguments):
        return 2
    if any(value in {"-h", "--help"} for value in arguments):
        build_parser().print_help()
        return 0
    try:
        arguments, archive_password, inno_password = (
            _resolve_cli_stdin_credential_options(arguments)
        )
        request = {
            "schema_version": 1,
            "arguments": arguments,
            "archive_password": archive_password,
            "inno_password": inno_password,
        }
        arguments, archive_password, inno_password = _direct_cli_request(request)
        request = {
            "schema_version": 1,
            "arguments": arguments,
            "archive_password": archive_password,
            "inno_password": inno_password,
        }
        request_raw = json.dumps(
            request,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        if not 0 < len(request_raw) <= MAX_DIRECT_CLI_REQUEST:
            raise ValueError("direct CLI worker requestがsize上限を超えています")
        from bounded_process import run_bounded

        with tempfile.TemporaryDirectory(prefix="direct-cli-analysis-") as temporary:
            temporary_root = Path(temporary).resolve(strict=True)
            ensure_no_reparse_components(temporary_root)
            response_path = temporary_root / "response.json"
            worker_temp = temporary_root / "worker-temp"
            worker_temp.mkdir(mode=0o700)
            os.chmod(worker_temp, 0o700)
            completed = run_bounded(
                [
                    sys.executable,
                    "-I",
                    "-B",
                    str(Path(__file__).resolve()),
                    "--direct-cli-worker",
                ],
                cwd=temporary_root,
                env=_bounded_handler_environment(temporary_root=worker_temp),
                shell=False,
                check=False,
                input=request_raw,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=MAX_DIRECT_CLI_SECONDS,
                require_containment=True,
                maximum_active_processes=MAX_DIRECT_CLI_ACTIVE_PROCESSES,
                maximum_memory_bytes=MAX_DIRECT_CLI_MEMORY_BYTES,
            )
            if completed.returncode != 0:
                return 2
            response_raw = _read_private_regular_file(
                response_path,
                maximum_size=MAX_DIRECT_CLI_RESPONSE,
            )
            exit_code, counts = _direct_cli_response(response_raw)
    except (OSError, RuntimeError, subprocess.SubprocessError, ValueError):
        return 2
    print(json.dumps(counts, ensure_ascii=False, indent=2, allow_nan=False))
    return exit_code


def _execute_cli(
    argv: list[str] | None,
    *,
    archive_password_override: str | None = None,
    inno_password_override: str | None = None,
) -> tuple[int, dict[str, int]]:
    """検証済みCLI引数から一括解析を実行し、終了codeと公開countsだけを返す。"""

    if _runtime_dependency_preflight_main() != 0:
        raise RuntimeError("runtime dependency preflight failed")
    args = build_parser().parse_args(argv)
    summary = run_batch(
        args.input,
        args.output,
        registry=args.registry,
        password=(
            "infected" if archive_password_override is None else archive_password_override
        ),
        archive_mode=args.archive_mode,
        forced_family=args.family,
        minimum_confidence=args.minimum_confidence,
        assessment_only=args.assessment_only,
        max_files=args.max_files,
        upx=args.upx,
        sevenzip=args.sevenzip,
        diec=args.diec,
        innounp=args.innounp,
        inno_password=("" if inno_password_override is None else inno_password_override),
        force_container_probe=args.force_container_probe,
        max_static_layers=args.max_static_layers,
        retry_max_static_layers=args.retry_max_static_layers,
        max_file_size=args.max_file_size,
        string_scan_limit=args.string_scan_limit,
        resume=args.resume,
        family_hint_manifest=args.family_hint_manifest,
    )
    counts = summary["counts"]
    incomplete = (
        counts.get("errors", 0)
        + counts.get("triaged_unknown", 0)
        + counts.get("partial", 0)
        + counts.get("failed", 0)
        + (summary.get("derived_counts") or {}).get("triaged_unknown", 0)
    )
    follow_on_status = (summary.get("follow_on_analysis") or {}).get("status")
    if follow_on_status not in {
        "complete",
        "no_retained_payloads",
        "disabled_assessment_only",
    }:
        incomplete += 1
    return (0 if incomplete == 0 else 20), counts


def main(argv: list[str] | None = None) -> int:
    """CLI引数を処理し、失敗を検体単位に分離した一括解析を実行する。"""

    if not _interpreter_is_isolated():
        return _run_isolated_cli(argv)
    try:
        exit_code, counts = _execute_cli(argv)
    except RuntimeError:
        return 2
    print(json.dumps(counts, ensure_ascii=False, indent=2, allow_nan=False))
    return exit_code


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "--runtime-preflight":
        raise SystemExit(_runtime_preflight_main())
    if len(sys.argv) == 6 and sys.argv[1] == "--pe-function-worker":
        raise SystemExit(_pe_function_worker_main(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]))
    if len(sys.argv) == 2 and sys.argv[1] == "--follow-on-worker":
        raise SystemExit(_follow_on_worker_main())
    if len(sys.argv) == 2 and sys.argv[1] == "--direct-cli-worker":
        raise SystemExit(_direct_cli_worker_main())
    raise SystemExit(main())
