"""一括静的解析の入力契約、証拠品質、再開整合性を共通化する。"""

from __future__ import annotations

import hashlib
import json
import math
import os
import platform
import re
import stat
from collections.abc import Iterable, Mapping, Sequence
from importlib import metadata as importlib_metadata
from pathlib import Path, PurePosixPath
from typing import Any

PIPELINE_CONTRACT_VERSION = 2
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
REPORT_SEMANTIC_HASH_FIELD = "report_semantic_sha256"
MAX_ARTIFACT_COUNT = 4_096
MAX_ARTIFACT_PATH_LENGTH = 1_024
MAX_CASE_ARTIFACT_SIZE = 1024 * 1024 * 1024
MAX_JSON_OBJECT_SIZE = 64 * 1024 * 1024
SNAPSHOT_READ_CHUNK_SIZE = 1024 * 1024
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
REQUIRED_KNOWLEDGE_ARTIFACTS = {
    "features": "features.json",
    "features_markdown": "FEATURES.md",
    "campaign_labels": "campaign-labels.json",
    "static_logic": "static-logic.json",
    "static_logic_markdown": "STATIC-LOGIC.md",
}
BASE_REQUIRED_ARTIFACTS = frozenset(
    {
        "static-layers.json",
        "classification.json",
        "applicability.json",
        *REQUIRED_KNOWLEDGE_ARTIFACTS.values(),
    }
)
RESUMABLE_CASE_STATES = frozenset(
    {"complete", "assessment_only_complete"}
)
NETWORK_EVIDENCE_KEYS = frozenset(
    {
        "c2",
        "c2_candidates",
        "config_endpoints",
        "endpoints",
        "findings",
        "network_candidates",
        "network_endpoints",
        "urls",
    }
)
STRUCTURAL_EVIDENCE_KEYS = frozenset(
    {
        "capabilities",
        "commands",
        "logic",
        "marker_hits",
        "matched_patterns",
        "observed_config_keys",
        "pump_observations",
        "recovered_artifacts",
        "webshell_paths",
    }
)
EVIDENCE_CONTROL_KEYS = frozenset(
    {
        "decoded_config_recovered",
        "matched",
        "profile_literal_correlation",
        "reviewed_hash",
        "static_config_recovered",
    }
)
EVIDENCE_METADATA_KEYS = frozenset(
    {
        "attribution_confidence",
        "classification_confidence",
        "confidence",
        "content_exported",
        "error",
        "executed_sample",
        "family",
        "kind",
        "label",
        "limitations",
        "message",
        "name",
        "network_contacted",
        "note",
        "reason",
        "role",
        "schema_version",
        "sha256",
        "size",
        "source",
        "source_name",
        "status",
        "type",
    }
)
NEGATIVE_VALUES = frozenset(
    {
        "error",
        "failed",
        "failure",
        "n/a",
        "",
        "false",
        "none",
        "not_applicable",
        "not_found",
        "not_present",
        "not_recovered",
        "unknown",
        "unresolved",
        "unresolved_variant",
    }
)


def format_compatible(accepted_formats: Sequence[str], actual_format: str) -> bool:
    """ハンドラーの宣言形式と静的に識別した入力形式が両立するか返す。"""

    return "any" in accepted_formats or actual_format in accepted_formats


def _meaningful_evidence_value(value: Any, *, depth: int = 0) -> bool:
    """否定値とmetadataだけのobjectを除外し、実値があるか再帰判定する。"""

    if depth > 16 or value is None or value is False:
        return False
    if value is True:
        return False
    if isinstance(value, str):
        normalized = "_".join(value.strip().casefold().replace("-", " ").split())
        return bool(normalized) and normalized not in NEGATIVE_VALUES and not normalized.startswith(
            ("not_found", "not_recovered", "unknown", "unresolved")
        )
    if isinstance(value, (bytes, bytearray)):
        return bool(value)
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, Mapping):
        return any(
            str(key).casefold()
            not in EVIDENCE_METADATA_KEYS | EVIDENCE_CONTROL_KEYS
            and _meaningful_evidence_value(item, depth=depth + 1)
            for key, item in value.items()
        )
    if isinstance(value, Sequence):
        return any(_meaningful_evidence_value(item, depth=depth + 1) for item in value[:10_000])
    return False


def _meaningful_collection(value: Any) -> bool:
    return isinstance(value, (Mapping, Sequence)) and not isinstance(
        value, (str, bytes, bytearray)
    ) and _meaningful_evidence_value(value)


def _mapping_has_correlated_payload(value: Mapping[str, Any]) -> bool:
    """宣言boolean以外に独立した実値が同じobjectへ存在するか返す。"""

    return any(
        str(key).casefold() not in EVIDENCE_METADATA_KEYS | EVIDENCE_CONTROL_KEYS
        and _meaningful_evidence_value(item)
        for key, item in value.items()
    )


def _collect_evidence(value: Any, state: dict[str, Any], *, depth: int = 0) -> None:
    if depth > 32:
        return
    if isinstance(value, Mapping):
        for raw_key, item in value.items():
            key = str(raw_key).casefold()
            if (
                key == "decoded_config_recovered"
                and item is True
                and _mapping_has_correlated_payload(value)
            ):
                state["decoded_config"] = True
            elif (
                key == "static_config_recovered"
                and item is True
                and _mapping_has_correlated_payload(value)
            ):
                state["static_config"] = True
            elif key in NETWORK_EVIDENCE_KEYS and _meaningful_collection(item):
                state["candidate_groups"].add(key)
                state["candidate_count"] += min(len(item), 100)
            elif key in STRUCTURAL_EVIDENCE_KEYS and _meaningful_collection(item):
                state["structural_groups"].add(key)
                state["structural_count"] += min(len(item), 100)
            elif (
                key in {"variant", "version", "artifact_role"}
                and isinstance(item, str)
                and item.casefold() not in NEGATIVE_VALUES
                and not item.casefold().startswith("unresolved")
            ):
                state["structural_groups"].add(key)
            _collect_evidence(item, state, depth=depth + 1)
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for item in value[:10_000]:
            _collect_evidence(item, state, depth=depth + 1)


def handler_result_quality(value: Any, minimum_score: int = 1) -> dict[str, Any]:
    """戻り値を証拠tierへ正規化し、空の正常終了と有効結果を分離する。"""

    state: dict[str, Any] = {
        "decoded_config": False,
        "static_config": False,
        "corroborated": False,
        "structural_groups": set(),
        "candidate_groups": set(),
        "structural_count": 0,
        "candidate_count": 0,
    }
    _collect_evidence(value, state)
    if state["decoded_config"]:
        tier, label = 4, "decoded_configuration"
    elif state["static_config"]:
        tier, label = 3, "validated_static_configuration"
    elif state["corroborated"] or state["structural_groups"]:
        tier, label = 2, "structural_corroboration"
    elif state["candidate_groups"]:
        tier, label = 1, "literal_candidate"
    else:
        tier, label = 0, "no_evidence"
    score = (
        tier * 10_000
        + min(len(state["structural_groups"]), 99) * 100
        + min(state["structural_count"], 99)
        + min(state["candidate_count"], 99)
    )
    return {
        "tier": tier,
        "tier_name": label,
        "score": score,
        "minimum_score": minimum_score,
        "sufficient": tier > 0 and score >= minimum_score,
        "structural_groups": sorted(state["structural_groups"]),
        "candidate_groups": sorted(state["candidate_groups"]),
    }


def _component_label(path: Path, repository_root: Path) -> str:
    try:
        return path.resolve().relative_to(repository_root.resolve()).as_posix()
    except (OSError, ValueError):
        return f"external:{path.name}"


def build_pipeline_fingerprint(
    *,
    repository_root: Path,
    components: Iterable[Path],
    settings: Mapping[str, Any],
) -> dict[str, Any]:
    """解析コード・レジストリ・ルーティング設定の決定的な指紋を返す。"""

    records = []
    unique: dict[str, Path] = {}
    for supplied in components:
        path = supplied.resolve()
        if path.is_file():
            unique[str(path).casefold()] = path
    for key in sorted(unique):
        path = unique[key]
        data = path.read_bytes()
        records.append(
            {
                "path": _component_label(path, repository_root),
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        )
    payload = {
        "pipeline_contract_version": PIPELINE_CONTRACT_VERSION,
        "settings": dict(sorted(settings.items())),
        "components": records,
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
        "component_count": len(records),
        "settings": payload["settings"],
    }


def normalize_sha256_digest(value: Any) -> str:
    """小文字16進64文字のSHA-256だけを受理する。"""

    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise ValueError(f"不正なSHA-256形式です: {value!r}")
    return value


def runtime_dependency_versions() -> dict[str, Any]:
    """再開可否へ影響するPython実装と主要依存版を返す。"""

    dependencies = {}
    for distribution in (
        "cabarchive",
        "capstone",
        "cryptography",
        "dncil",
        "dnfile",
        "olefile",
        "pefile",
        "pydantic",
        "pyinstaller",
        "pyzipper",
        "PyYAML",
        "ruff",
        "yara-python",
    ):
        try:
            dependencies[distribution] = importlib_metadata.version(distribution)
        except importlib_metadata.PackageNotFoundError:
            dependencies[distribution] = "not_installed"
    return {
        "python_implementation": platform.python_implementation(),
        "python_version": platform.python_version(),
        "dependencies": dependencies,
    }


def _is_reparse_point(path: Path) -> bool:
    """symbolic link、junction、その他のreparse pointを識別する。"""

    try:
        if path.is_symlink():
            return True
        is_junction = getattr(path, "is_junction", None)
        if callable(is_junction) and is_junction():
            return True
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise ValueError(f"path属性を安全に確認できません: {path}") from exc
    return bool(attributes & FILE_ATTRIBUTE_REPARSE_POINT)


class _SnapshotReadError(ValueError):
    """検証済みfile snapshotを取得できない理由を保持する。"""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason


def _stat_has_reparse_attribute(information: os.stat_result) -> bool:
    """stat結果にWindows reparse属性が含まれるか返す。"""

    return bool(
        int(getattr(information, "st_file_attributes", 0))
        & FILE_ATTRIBUTE_REPARSE_POINT
    )


def _same_file_identity(first: os.stat_result, second: os.stat_result) -> bool:
    """deviceとfile IDを使い、同一fileを指すstat結果か確認する。"""

    if first.st_ino == 0 or second.st_ino == 0:
        return False
    try:
        return os.path.samestat(first, second)
    except (AttributeError, OSError):
        return first.st_dev == second.st_dev and first.st_ino == second.st_ino


def _same_file_binding(first: os.stat_result, second: os.stat_result) -> bool:
    """異なるstat API間でも安定するidentity、size、mtimeを比較する。"""

    return (
        _same_file_identity(first, second)
        and first.st_size == second.st_size
        and first.st_mtime_ns == second.st_mtime_ns
        and first.st_nlink == second.st_nlink == 1
    )


def _stable_file_metadata(first: os.stat_result, second: os.stat_result) -> bool:
    """同種stat APIの前後でidentity、size、mtime、ctimeを比較する。"""

    return _same_file_binding(first, second) and first.st_ctime_ns == second.st_ctime_ns


def _validate_snapshot_file(
    path: Path,
    information: os.stat_result,
    *,
    max_bytes: int,
) -> None:
    """snapshot候補が上限内の単一link通常fileであることを確認する。"""

    if _stat_has_reparse_attribute(information):
        raise _SnapshotReadError(
            "reparse_point",
            f"reparse pointの成果物は使用できません: {path}",
        )
    if not stat.S_ISREG(information.st_mode):
        raise _SnapshotReadError(
            "not_regular_file",
            f"通常fileではない成果物です: {path}",
        )
    if information.st_nlink != 1:
        raise _SnapshotReadError(
            "hardlink_forbidden",
            f"hardlinkされた成果物は使用できません: {path}",
        )
    if information.st_size < 0 or information.st_size > max_bytes:
        raise _SnapshotReadError(
            "size_out_of_bounds",
            f"成果物が{max_bytes} bytes上限を超えています: {path}",
        )


def _read_bounded_descriptor(descriptor: int, *, max_bytes: int) -> bytes:
    """descriptorから上限+1 byteだけを読み、それ以上は取得しない。"""

    remaining = max_bytes + 1
    chunks: list[bytes] = []
    while remaining > 0:
        try:
            chunk = os.read(descriptor, min(SNAPSHOT_READ_CHUNK_SIZE, remaining))
        except InterruptedError:
            continue
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _read_regular_file_snapshot(path: Path, *, max_bytes: int) -> bytes:
    """単一handleから不変な通常file snapshotを上限付きで取得する。"""

    path = Path(os.path.abspath(os.fspath(path)))
    if type(max_bytes) is not int or max_bytes < 0:
        raise ValueError(f"不正なsnapshot読取上限です: {max_bytes!r}")
    try:
        ensure_no_reparse_components(path)
    except ValueError as exc:
        raise _SnapshotReadError(
            "reparse_point",
            f"reparse pointを含む成果物pathは使用できません: {path}",
        ) from exc
    try:
        before = path.lstat()
    except OSError as exc:
        raise _SnapshotReadError(
            "unreadable",
            f"成果物を安全に確認できません: {path}",
        ) from exc
    _validate_snapshot_file(path, before, max_bytes=max_bytes)

    flags = os.O_RDONLY | int(getattr(os, "O_BINARY", 0))
    flags |= int(getattr(os, "O_CLOEXEC", 0))
    flags |= int(getattr(os, "O_NOINHERIT", 0))
    flags |= int(getattr(os, "O_NOFOLLOW", 0))
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise _SnapshotReadError(
            "unreadable",
            f"成果物を安全に開けません: {path}",
        ) from exc

    try:
        opened = os.fstat(descriptor)
        _validate_snapshot_file(path, opened, max_bytes=max_bytes)
        if not _same_file_binding(before, opened):
            raise _SnapshotReadError(
                "changed_during_read",
                f"成果物がlstatとopenの間に差し替えられました: {path}",
            )
        data = _read_bounded_descriptor(descriptor, max_bytes=max_bytes)
        after_handle = os.fstat(descriptor)
        _validate_snapshot_file(path, after_handle, max_bytes=max_bytes)
    except _SnapshotReadError:
        raise
    except OSError as exc:
        raise _SnapshotReadError(
            "unreadable",
            f"成果物を安全に読み取れません: {path}",
        ) from exc
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass

    if len(data) > max_bytes:
        raise _SnapshotReadError(
            "size_out_of_bounds",
            f"成果物が{max_bytes} bytes上限を超えています: {path}",
        )
    try:
        ensure_no_reparse_components(path)
        after_path = path.lstat()
    except ValueError as exc:
        raise _SnapshotReadError(
            "reparse_point",
            f"読取中に成果物pathがreparse pointへ変更されました: {path}",
        ) from exc
    except OSError as exc:
        raise _SnapshotReadError(
            "changed_during_read",
            f"読取中に成果物pathが変更されました: {path}",
        ) from exc
    _validate_snapshot_file(path, after_path, max_bytes=max_bytes)
    if not (
        len(data) == opened.st_size
        and _stable_file_metadata(opened, after_handle)
        and _stable_file_metadata(before, after_path)
        and _same_file_binding(opened, after_path)
    ):
        raise _SnapshotReadError(
            "changed_during_read",
            f"読取中に成果物のidentity、size、mtime、ctimeが変更されました: {path}",
        )
    return data


def ensure_no_reparse_components(path: Path) -> None:
    """resolve前の既存path componentにreparse pointがないことを確認する。"""

    absolute = Path(os.path.abspath(os.fspath(path)))
    parts = absolute.parts
    if not parts:
        raise ValueError(f"空のpathは使用できません: {path}")
    current = Path(parts[0])
    candidates = [current]
    for part in parts[1:]:
        current /= part
        candidates.append(current)
    for component in candidates:
        try:
            component.lstat()
        except FileNotFoundError:
            break
        except OSError as exc:
            raise ValueError(f"path componentを安全に確認できません: {component}") from exc
        if _is_reparse_point(component):
            raise ValueError(f"reparse pointを含むpathは使用できません: {component}")


def ensure_tree_without_reparse(root: Path, *, max_entries: int = 100_000) -> None:
    """case tree内の全entryをfollowせず走査し、reparse pointを拒否する。"""

    ensure_no_reparse_components(root)
    pending = [root]
    seen = 0
    while pending:
        directory = pending.pop()
        try:
            entries = os.scandir(directory)
        except OSError as exc:
            raise ValueError(f"case treeを安全に走査できません: {directory}") from exc
        with entries:
            for entry in entries:
                seen += 1
                if seen > max_entries:
                    raise ValueError(f"case tree entry数が上限を超えています: {max_entries}")
                path = Path(entry.path)
                if _is_reparse_point(path):
                    raise ValueError(f"reparse pointを含むcase treeは使用できません: {path}")
                try:
                    if entry.is_dir(follow_symlinks=False):
                        pending.append(path)
                except OSError as exc:
                    raise ValueError(f"case tree entryを安全に確認できません: {path}") from exc


def normalize_artifact_path(value: Any) -> str:
    """成果物pathを曖昧性のない安全なPOSIX相対pathとして検証する。"""

    if not isinstance(value, str) or not value or len(value) > MAX_ARTIFACT_PATH_LENGTH:
        raise ValueError(f"不正な成果物pathです: {value!r}")
    if "\\" in value or "\x00" in value or value.startswith(("/", "//")):
        raise ValueError(f"不正な成果物pathです: {value!r}")
    if re.match(r"^[A-Za-z]:", value):
        raise ValueError(f"絶対pathは使用できません: {value!r}")
    raw_parts = value.split("/")
    if any(
        not part
        or part in {".", ".."}
        or ":" in part
        or part.endswith((" ", "."))
        or any(ord(character) < 32 for character in part)
        for part in raw_parts
    ):
        raise ValueError(f"不正な成果物path componentです: {value!r}")
    parsed = PurePosixPath(value)
    if parsed.is_absolute() or parsed.parts != tuple(raw_parts):
        raise ValueError(f"正規化されていない成果物pathです: {value!r}")
    return parsed.as_posix()


def resolve_case_artifact(case_dir: Path, relative: Any) -> Path:
    """reparse pointとcase境界越えを拒否して通常ファイルを解決する。"""

    normalized = normalize_artifact_path(relative)
    ensure_no_reparse_components(case_dir)
    try:
        root = case_dir.resolve(strict=True)
    except (FileNotFoundError, OSError) as exc:
        raise ValueError(f"case directoryが存在しません: {case_dir}") from exc
    if not root.is_dir():
        raise ValueError(f"case rootがdirectoryではありません: {case_dir}")
    lexical = case_dir.joinpath(*normalized.split("/"))
    ensure_no_reparse_components(lexical)
    try:
        resolved = lexical.resolve(strict=True)
        resolved.relative_to(root)
        mode = resolved.lstat().st_mode
    except (FileNotFoundError, OSError, ValueError) as exc:
        raise ValueError(f"成果物が存在しないかcase境界外です: {normalized}") from exc
    if _is_reparse_point(resolved) or not stat.S_ISREG(mode):
        raise ValueError(f"通常ファイルではない成果物です: {normalized}")
    return resolved


def _strict_object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"JSON objectに重複keyがあります: {key}")
        result[key] = value
    return result


def _reject_non_finite(value: str) -> None:
    """JSON拡張のNaNとInfinityを拒否する。"""

    raise ValueError(f"JSONに非有限数は使用できません: {value}")


def _strict_json_float(value: str) -> float:
    """有限なJSON浮動小数点数だけをPython floatへ変換する。"""

    result = float(value)
    if not math.isfinite(result):
        raise ValueError(f"JSONに非有限数は使用できません: {value}")
    return result


def _strict_json_int(value: str) -> int:
    """128桁以下のJSON整数だけをPython intへ変換する。"""

    digits = value[1:] if value.startswith("-") else value
    if len(digits) > 128:
        raise ValueError("JSON整数の桁数が上限を超えています")
    return int(value)


def _ensure_json_depth(value: Any, *, maximum_depth: int = 128) -> None:
    """再帰を使わず、成果物JSONのcontainer深度を制限する。"""

    pending: list[tuple[Any, int]] = [(value, 0)]
    while pending:
        current, depth = pending.pop()
        if depth > maximum_depth:
            raise ValueError("JSONの入れ子が深すぎます")
        if isinstance(current, dict):
            pending.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            pending.extend((item, depth + 1) for item in current)


def _decode_json_object_strict(data: bytes, *, path: Path) -> dict[str, Any]:
    """検証済みbytesをBOMなしUTF-8の厳密なJSON objectとして解釈する。"""

    try:
        value = json.loads(
            data.decode("utf-8", errors="strict"),
            object_pairs_hook=_strict_object_pairs,
            parse_constant=_reject_non_finite,
            parse_int=_strict_json_int,
            parse_float=_strict_json_float,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError(f"JSON成果物を解釈できません: {path}") from exc
    if not isinstance(value, dict):
        raise TypeError(f"JSON objectが必要です: {path}")
    _ensure_json_depth(value)
    return value


def load_json_object_strict(path: Path) -> dict[str, Any]:
    """単一handle、容量上限、厳密UTF-8でJSON objectを読み込む。"""

    data = _read_regular_file_snapshot(path, max_bytes=MAX_JSON_OBJECT_SIZE)
    return _decode_json_object_strict(data, path=path)


def report_semantic_sha256(report: Mapping[str, Any]) -> str:
    """seal field自身を除くreport全体の決定的なSHA-256を返す。"""

    value = dict(report)
    value.pop(REPORT_SEMANTIC_HASH_FIELD, None)
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def seal_report(report: dict[str, Any]) -> str:
    """reportへ意味内容全体の改ざん検知用digestを付与する。"""

    digest = report_semantic_sha256(report)
    report[REPORT_SEMANTIC_HASH_FIELD] = digest
    return digest


def verify_report_semantics(report: Mapping[str, Any]) -> list[str]:
    """report sealの形式と意味内容との一致を検証する。"""

    recorded = report.get(REPORT_SEMANTIC_HASH_FIELD)
    try:
        normalize_sha256_digest(recorded)
    except ValueError:
        return ["report_semantic_sha256_invalid"]
    try:
        actual = report_semantic_sha256(report)
    except (TypeError, ValueError):
        return ["report_not_canonical_json"]
    if actual != recorded:
        return ["report_semantic_sha256_mismatch"]
    return []


def artifact_hashes(case_dir: Path, relative_paths: Iterable[str]) -> dict[str, str]:
    """case成果物の相対pathとSHA-256を決定的に記録する。"""

    result: dict[str, str] = {}
    supplied = list(relative_paths)
    if not supplied or len(supplied) > MAX_ARTIFACT_COUNT:
        raise ValueError(f"成果物数が不正です: {len(supplied)}")
    normalized = [normalize_artifact_path(relative) for relative in supplied]
    if len(set(normalized)) != len(normalized):
        raise ValueError("成果物pathが重複しています")
    for relative in sorted(normalized):
        path = resolve_case_artifact(case_dir, relative)
        data = _read_regular_file_snapshot(path, max_bytes=MAX_CASE_ARTIFACT_SIZE)
        result[relative] = hashlib.sha256(data).hexdigest()
    return result


def verify_artifact_hashes(case_dir: Path, expected: Mapping[str, Any]) -> list[str]:
    """記録済み成果物の存在・path境界・内容hashを検証し、不一致理由を返す。"""

    errors, _snapshots = _verify_artifact_hashes_with_snapshots(case_dir, expected)
    return errors


def _verify_artifact_hashes_with_snapshots(
    case_dir: Path,
    expected: Mapping[str, Any],
    *,
    capture_paths: frozenset[str] = frozenset(),
) -> tuple[list[str], dict[str, bytes]]:
    """hash検証と、指定成果物の同一snapshot bytes取得を一度に行う。"""

    if not isinstance(expected, Mapping) or not expected:
        return ["artifact_hash_manifest_missing"], {}
    if len(expected) > MAX_ARTIFACT_COUNT:
        return ["artifact_hash_manifest_too_large"], {}
    errors: list[str] = []
    snapshots: dict[str, bytes] = {}
    if any(not isinstance(relative, str) for relative in expected):
        return ["artifact_hash_manifest_non_string_path"], {}
    for relative in sorted(expected):
        digest = expected[relative]
        try:
            normalize_artifact_path(relative)
        except ValueError:
            errors.append(f"unsafe_path:{relative}")
            continue
        try:
            normalize_sha256_digest(digest)
        except ValueError:
            errors.append(f"invalid_sha256:{relative}")
            continue
        try:
            path = resolve_case_artifact(case_dir, relative)
        except ValueError as exc:
            if "reparse point" in str(exc):
                errors.append(f"reparse_point:{relative}")
            else:
                errors.append(f"missing_or_outside:{relative}")
            continue
        try:
            data = _read_regular_file_snapshot(path, max_bytes=MAX_CASE_ARTIFACT_SIZE)
        except _SnapshotReadError as exc:
            prefix = {
                "reparse_point": "reparse_point",
                "hardlink_forbidden": "artifact_hardlink_forbidden",
                "not_regular_file": "artifact_not_regular_file",
                "size_out_of_bounds": "artifact_size_out_of_bounds",
                "changed_during_read": "artifact_changed_during_read",
                "unreadable": "artifact_unreadable",
            }.get(exc.reason, "artifact_snapshot_invalid")
            errors.append(f"{prefix}:{relative}")
            continue
        actual = hashlib.sha256(data).hexdigest()
        if actual != digest:
            errors.append(f"sha256_mismatch:{relative}")
        elif relative in capture_paths:
            snapshots[relative] = data
    return errors, snapshots


def _required_artifact_paths(report: Mapping[str, Any]) -> tuple[set[str], list[str]]:
    required = set(BASE_REQUIRED_ARTIFACTS)
    errors: list[str] = []
    assessment_only = report.get("assessment_only")
    if type(assessment_only) is not bool:
        errors.append("assessment_only_not_boolean")
    elif not assessment_only:
        required.add("generic-triage.json")

    static_layers = report.get("static_layers")
    if static_layers != "static-layers.json":
        errors.append("static_layers_path_mismatch")

    knowledge = report.get("knowledge_artifacts")
    if not isinstance(knowledge, Mapping):
        errors.append("knowledge_artifacts_missing")
    else:
        for key, expected_path in REQUIRED_KNOWLEDGE_ARTIFACTS.items():
            if knowledge.get(key) != expected_path:
                errors.append(f"knowledge_artifact_mismatch:{key}")
        for key, relative in knowledge.items():
            try:
                required.add(normalize_artifact_path(relative))
            except ValueError:
                errors.append(f"unsafe_knowledge_artifact_path:{key}")

    executions = report.get("handler_executions")
    if not isinstance(executions, list) or len(executions) > MAX_ARTIFACT_COUNT:
        errors.append("handler_executions_invalid")
        return required, errors
    result_required_statuses = {"succeeded", "no_evidence", "ambiguous_evidence"}
    for index, execution in enumerate(executions):
        if not isinstance(execution, Mapping):
            errors.append(f"handler_execution_invalid:{index}")
            continue
        status_value = execution.get("status")
        relative = execution.get("result")
        if status_value in result_required_statuses and not isinstance(relative, str):
            errors.append(f"handler_result_missing:{index}")
            continue
        if relative is None:
            continue
        try:
            required.add(normalize_artifact_path(relative))
        except ValueError:
            errors.append(f"unsafe_handler_result_path:{index}")
    return required, errors


def _documented_handler_no_evidence_families(
    report: Mapping[str, Any], executions: Any
) -> tuple[set[str], list[str]]:
    """抽出器の正常なno-evidence完了記録を厳密に検証する。"""

    documented = report.get("documented_handler_no_evidence")
    if documented is None:
        return set(), []
    if not isinstance(documented, Mapping):
        return set(), ["documented_handler_no_evidence_invalid"]
    family = documented.get("family")
    if not isinstance(family, str) or not family or family != family.casefold():
        return set(), ["documented_handler_no_evidence_family_invalid"]
    expected_blockers = sorted(
        {
            "handler_no_evidence",
            f"selected_family_has_no_valid_handler_evidence:{family}",
            "selected_family_layer_incomplete",
        }
    )
    if documented.get("basis") != "all_routed_handler_attempts_completed_without_family_specific_evidence":
        return set(), ["documented_handler_no_evidence_basis_invalid"]
    if (
        documented.get("attribution_effect")
        != "provider_label_retained_but_not_upgraded_to_static_confirmation"
    ):
        return set(), ["documented_handler_no_evidence_attribution_invalid"]
    if documented.get("resolved_blockers") != expected_blockers:
        return set(), ["documented_handler_no_evidence_blockers_invalid"]

    handler_ids = documented.get("handler_ids")
    attempted_layers = documented.get("attempted_layer_sha256")
    if (
        not isinstance(handler_ids, list)
        or not handler_ids
        or any(not isinstance(value, str) or not value for value in handler_ids)
        or handler_ids != sorted(set(handler_ids))
    ):
        return set(), ["documented_handler_no_evidence_handlers_invalid"]
    if (
        not isinstance(attempted_layers, list)
        or not attempted_layers
        or any(
            not isinstance(value, str) or SHA256_RE.fullmatch(value) is None
            for value in attempted_layers
        )
        or attempted_layers != sorted(set(attempted_layers))
    ):
        return set(), ["documented_handler_no_evidence_layers_invalid"]
    if not isinstance(executions, list):
        return set(), ["documented_handler_no_evidence_executions_invalid"]

    relevant = {
        item.get("handler_id"): item
        for item in executions
        if isinstance(item, Mapping)
        and isinstance(item.get("handler_id"), str)
        and item.get("handler_id").partition(":")[0].casefold() == family
    }
    if set(handler_ids) != set(relevant):
        return set(), ["documented_handler_no_evidence_handler_set_mismatch"]
    routed_layers: set[str] = set()
    for handler_id in handler_ids:
        execution = relevant[handler_id]
        evidence = execution.get("selected_evidence")
        attempts = execution.get("attempts")
        if (
            execution.get("status") != "no_evidence"
            or not isinstance(evidence, Mapping)
            or evidence.get("sufficient") is not False
            or not isinstance(attempts, list)
            or not attempts
        ):
            return set(), ["documented_handler_no_evidence_execution_invalid"]
        routed = [
            item
            for item in attempts
            if isinstance(item, Mapping)
            and item.get("routing_role") in {"selected_family_layer", "ancestor_fallback"}
        ]
        if not routed or not any(item.get("routing_role") == "selected_family_layer" for item in routed):
            return set(), ["documented_handler_no_evidence_routing_invalid"]
        for attempt in routed:
            attempt_evidence = attempt.get("evidence")
            layer = attempt.get("layer")
            layer_sha = layer.get("sha256") if isinstance(layer, Mapping) else None
            if (
                attempt.get("status") != "succeeded"
                or attempt.get("evidence_status") != "insufficient"
                or not isinstance(attempt_evidence, Mapping)
                or attempt_evidence.get("sufficient") is not False
                or not isinstance(layer_sha, str)
                or SHA256_RE.fullmatch(layer_sha) is None
            ):
                return set(), ["documented_handler_no_evidence_attempt_invalid"]
            routed_layers.add(layer_sha)
    if routed_layers != set(attempted_layers):
        return set(), ["documented_handler_no_evidence_layer_set_mismatch"]
    return {family}, []


def _case_state_errors(report: Mapping[str, Any], *, require_resumable: bool) -> list[str]:
    errors: list[str] = []
    assessment_only = report.get("assessment_only")
    state = report.get("case_state")
    classification = report.get("classification")
    executions = report.get("handler_executions")
    allowed_execution_statuses = {
        "succeeded",
        "no_evidence",
        "ambiguous_evidence",
        "failed",
        "preflight_failed",
        "incompatible_input_format",
    }
    if type(assessment_only) is not bool:
        return ["assessment_only_not_boolean"]
    if not isinstance(state, Mapping):
        return ["case_state_missing"]
    status_value = state.get("status")
    if status_value not in {
        "complete",
        "triaged_unknown",
        "assessment_only_complete",
        "partial",
        "failed",
    }:
        errors.append("case_state_status_invalid")
    expected_complete = status_value in RESUMABLE_CASE_STATES
    if state.get("complete") is not expected_complete:
        errors.append("case_state_complete_inconsistent")
    resumable = state.get("resumable")
    if type(resumable) is not bool or resumable is not expected_complete:
        errors.append("case_state_resumable_inconsistent")
    if require_resumable and resumable is not True:
        errors.append("case_state_not_resumable")

    blockers = state.get("blockers")
    if (
        not isinstance(blockers, list)
        or any(not isinstance(value, str) or not value for value in blockers)
        or blockers != sorted(set(blockers))
    ):
        errors.append("case_state_blockers_invalid")
    elif expected_complete and blockers:
        errors.append("complete_case_has_blockers")
    elif status_value in {"partial", "failed"} and not blockers:
        errors.append("incomplete_case_missing_blockers")

    if not isinstance(classification, Mapping):
        errors.append("classification_missing")
        selected_families: list[Any] = []
    else:
        selected_families = classification.get("selected_families")
        if (
            not isinstance(selected_families, list)
            or any(not isinstance(value, str) or not value for value in selected_families)
            or selected_families != sorted(set(selected_families))
        ):
            errors.append("selected_families_invalid")
            selected_families = []
        selected_family = classification.get("selected_family")
        if selected_family is not None and (
            not isinstance(selected_family, str) or selected_family not in selected_families
        ):
            errors.append("selected_family_inconsistent")

    generic_status = report.get("generic_triage")
    if assessment_only:
        if status_value not in {"assessment_only_complete", "partial", "failed"}:
            errors.append("assessment_mode_status_inconsistent")
        if generic_status != "not_run_assessment_only":
            errors.append("assessment_mode_generic_status_inconsistent")
        if executions != []:
            errors.append("assessment_mode_handler_execution_present")
    else:
        if status_value == "assessment_only_complete":
            errors.append("analysis_mode_status_inconsistent")
        if generic_status not in {"complete", "partial", "failed"}:
            errors.append("analysis_mode_generic_status_inconsistent")
        if expected_complete and generic_status != "complete":
            errors.append("complete_case_generic_status_inconsistent")
    if status_value == "complete" and not selected_families:
        errors.append("complete_case_missing_selected_family")
    if status_value == "triaged_unknown" and selected_families:
        errors.append("triaged_unknown_has_selected_family")

    successful_families = set()
    handler_ids = set()
    if isinstance(executions, list):
        for index, execution in enumerate(executions):
            if not isinstance(execution, Mapping):
                continue
            handler_id = execution.get("handler_id")
            execution_status = execution.get("status")
            if not isinstance(handler_id, str) or not handler_id or handler_id in handler_ids:
                errors.append(f"handler_id_invalid_or_duplicate:{index}")
                continue
            handler_ids.add(handler_id)
            family, separator, _remainder = handler_id.partition(":")
            if not separator or not family:
                errors.append(f"handler_id_family_missing:{index}")
            if execution_status not in allowed_execution_statuses:
                errors.append(f"handler_status_invalid:{index}")
                continue
            has_result = isinstance(execution.get("result"), str)
            if execution_status in {"succeeded", "no_evidence", "ambiguous_evidence"}:
                if not has_result:
                    errors.append(f"handler_result_missing:{index}")
                evidence = execution.get("selected_evidence")
                sufficient = evidence.get("sufficient") if isinstance(evidence, Mapping) else None
                if execution_status == "no_evidence" and sufficient is not False:
                    errors.append(f"handler_no_evidence_inconsistent:{index}")
                if execution_status in {"succeeded", "ambiguous_evidence"} and sufficient is not True:
                    errors.append(f"handler_success_evidence_inconsistent:{index}")
                if execution_status == "succeeded" and separator:
                    successful_families.add(family)
            elif execution.get("result") is not None:
                errors.append(f"failed_handler_has_result:{index}")
    documented_no_evidence_families, documented_errors = _documented_handler_no_evidence_families(
        report, executions
    )
    errors.extend(documented_errors)
    if status_value == "complete":
        for family in selected_families:
            if family not in successful_families and family not in documented_no_evidence_families:
                errors.append(f"selected_family_without_successful_handler:{family}")
    if status_value == "triaged_unknown" and executions:
        errors.append("triaged_unknown_has_handler_executions")

    for key in (
        "detector_error_families",
        "static_layer_issues",
        "incomplete_selected_layer_attempts",
    ):
        if not isinstance(state.get(key), list):
            errors.append(f"case_state_{key}_invalid")
    return errors


def case_integrity_errors(
    case_dir: Path,
    report: Mapping[str, Any],
    *,
    expected_digest: str | None = None,
    expected_contract: Mapping[str, Any] | None = None,
    require_resumable: bool = True,
) -> list[str]:
    """再開・公開に必要なreport意味整合性と全成果物を検証する。"""

    errors: list[str] = []
    try:
        ensure_tree_without_reparse(case_dir)
    except ValueError:
        return ["case_path_contains_reparse_point"]
    if type(report.get("schema_version")) is not int or report.get("schema_version") != 1:
        errors.append("report_schema_version_invalid")
    errors.extend(verify_report_semantics(report))

    sample = report.get("sample")
    sample_digest = sample.get("sha256") if isinstance(sample, Mapping) else None
    try:
        normalize_sha256_digest(sample_digest)
    except ValueError:
        errors.append("sample_sha256_invalid")
    if expected_digest is not None:
        try:
            normalize_sha256_digest(expected_digest)
        except ValueError:
            errors.append("expected_sha256_invalid")
        else:
            if sample_digest != expected_digest or case_dir.name != expected_digest:
                errors.append("sample_sha256_boundary_mismatch")

    contract = report.get("analysis_contract")
    if not isinstance(contract, Mapping):
        errors.append("analysis_contract_missing")
    else:
        try:
            normalize_sha256_digest(contract.get("sha256"))
        except ValueError:
            errors.append("analysis_contract_sha256_invalid")
        if contract.get("schema_version") != 1:
            errors.append("analysis_contract_schema_invalid")
        if contract.get("pipeline_contract_version") != PIPELINE_CONTRACT_VERSION:
            errors.append("pipeline_contract_version_invalid")
        settings = contract.get("settings")
        if not isinstance(settings, Mapping):
            errors.append("analysis_contract_settings_invalid")
        elif settings.get("assessment_only") is not report.get("assessment_only"):
            errors.append("analysis_contract_mode_mismatch")
        if expected_contract is not None and dict(contract) != dict(expected_contract):
            errors.append("analysis_contract_mismatch")

    if report.get("executed_sample") is not False:
        errors.append("executed_sample_flag_invalid")
    if report.get("network_contacted") is not False:
        errors.append("network_contacted_flag_invalid")
    errors.extend(_case_state_errors(report, require_resumable=require_resumable))

    required, path_errors = _required_artifact_paths(report)
    errors.extend(path_errors)
    verified_semantic_artifacts: dict[str, bytes] = {}
    manifest = report.get("artifact_sha256")
    if not isinstance(manifest, Mapping):
        errors.append("artifact_hash_manifest_missing")
    else:
        manifest_paths = set(manifest) if all(isinstance(key, str) for key in manifest) else set()
        missing = sorted(required - manifest_paths)
        unexpected = sorted(manifest_paths - required)
        errors.extend(f"artifact_manifest_missing:{path}" for path in missing)
        errors.extend(f"artifact_manifest_unexpected:{path}" for path in unexpected)
        artifact_errors, verified_semantic_artifacts = _verify_artifact_hashes_with_snapshots(
            case_dir,
            manifest,
            capture_paths=frozenset({"classification.json", "applicability.json"}),
        )
        errors.extend(artifact_errors)

    if not any(
        error.startswith(("artifact_", "unsafe_", "missing_or_outside", "reparse_point"))
        for error in errors
    ):
        try:
            classification_document = _decode_json_object_strict(
                verified_semantic_artifacts["classification.json"],
                path=case_dir / "classification.json",
            )
            applicability_document = _decode_json_object_strict(
                verified_semantic_artifacts["applicability.json"],
                path=case_dir / "applicability.json",
            )
        except (KeyError, TypeError, ValueError):
            errors.append("semantic_artifact_load_failed")
        else:
            report_classification = report.get("classification")
            if isinstance(report_classification, Mapping):
                root = classification_document.get("root")
                for key in ("selected_families",):
                    if classification_document.get(key) != report_classification.get(key):
                        errors.append(f"classification_artifact_mismatch:{key}")
                    if applicability_document.get(key) != report_classification.get(key):
                        errors.append(f"applicability_artifact_mismatch:{key}")
                for key in ("selected_family", "selection_basis"):
                    if applicability_document.get(key) != report_classification.get(key):
                        errors.append(f"applicability_artifact_mismatch:{key}")
                for report_key, artifact_key in (
                    ("family", "malware_type"),
                    ("confidence", "malware_type_confidence"),
                    ("campaign", "campaign_type"),
                ):
                    expected_value = report_classification.get(report_key)
                    if classification_document.get(artifact_key) != expected_value:
                        errors.append(f"classification_artifact_mismatch:{report_key}")
                    if isinstance(root, Mapping) and root.get(artifact_key) != expected_value:
                        errors.append(f"classification_root_mismatch:{report_key}")
                selection = root.get("one_shot_selection") if isinstance(root, Mapping) else None
                if not isinstance(selection, Mapping):
                    errors.append("classification_root_selection_missing")
                else:
                    if selection.get("family") != report_classification.get("selected_family"):
                        errors.append("classification_artifact_mismatch:selected_family")
                    if selection.get("basis") != report_classification.get("selection_basis"):
                        errors.append("classification_artifact_mismatch:selection_basis")
                handlers = applicability_document.get("handlers")
                if not isinstance(handlers, list):
                    errors.append("applicability_handlers_invalid")
                else:
                    applicable = {
                        item.get("id"): item
                        for item in handlers
                        if isinstance(item, Mapping)
                        and item.get("status") in {"applicable", "applicable_forced"}
                        and isinstance(item.get("id"), str)
                    }
                    for index, execution in enumerate(report.get("handler_executions") or []):
                        if not isinstance(execution, Mapping):
                            continue
                        handler_id = execution.get("handler_id")
                        metadata = applicable.get(handler_id)
                        if metadata is None:
                            errors.append(f"execution_not_applicable:{index}")
                            continue
                        family = metadata.get("family")
                        if not isinstance(family, str) or not str(handler_id).startswith(f"{family}:"):
                            errors.append(f"execution_family_mismatch:{index}")
                if applicability_document.get("executed_sample") is not False:
                    errors.append("applicability_executed_sample_flag_invalid")
                if applicability_document.get("network_contacted") is not False:
                    errors.append("applicability_network_contacted_flag_invalid")
    return sorted(set(errors))
