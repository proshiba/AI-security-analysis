#!/usr/bin/env python3
"""静的unpackerの出力を上限付き認証済みレイヤーDAGへ変換する。"""

from __future__ import annotations

import hashlib
import heapq
import math
import re
import unicodedata
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from unpackers.python_marshal_static import PROFILE as PYTHON_MARSHAL_PROFILE
from unpackers.static_unpacker import (
    detect_format,
    normalize_archive_member_basename,
    valid_pe_extent,
)

try:
    from .static_layer_lineage_adapter import select_static_layer_children
    from .valleyrat_verified_sibling_adapter import (
        VerifiedSiblingBundleLayer,
        recover_verified_sibling_bundle_layer,
    )
    from .zip_sideload_pair import (
        ZipSideLoadArtifactRole,
        analyze_zip_sideload_pairs,
    )
except ImportError:  # pragma: no cover - common directoryを直接sys.pathへ置く実行形態。
    from static_layer_lineage_adapter import select_static_layer_children
    from valleyrat_verified_sibling_adapter import (
        VerifiedSiblingBundleLayer,
        recover_verified_sibling_bundle_layer,
    )
    from zip_sideload_pair import ZipSideLoadArtifactRole, analyze_zip_sideload_pairs

MAX_STATIC_LAYERS = 64
MAX_STATIC_DEPTH = 6
MAX_RECOVERED_LAYER_SIZE = 128 * 1024 * 1024
MAX_RECOVERED_TOTAL_SIZE = 256 * 1024 * 1024
MAX_STATIC_COMPRESSION_RATIO = 100.0
MAX_ARCHIVE_MEMBERS = 512
LINEAGE_SELECTED_PRIORITY = -2
ZIP_SIDELOAD_PAIR_PRIORITY = -1

ACTIONABLE_FORMATS = frozenset({"pe", "elf", "macho", "script", "autoit-a3x", "java-class"})
CONTAINER_FORMATS = frozenset(
    {
        "7z",
        "zip",
        "cab",
        "rar",
        "xz",
        "asar",
        "ole",
        "rtf",
        "apple-disk-image",
    }
)
HIGH_VALUE_KIND_RE = re.compile(
    r"(?:^|[._-])(?:config|command|script|powershell|javascript|js|vbs|"
    r"shellcode|payload|stage|loader|embedded|decoded|decrypted|"
    r"decompressed|reassembled)(?:$|[._-])",
    re.IGNORECASE,
)
LOW_VALUE_RESOURCE_KIND_RE = re.compile(
    r"(?:^|[._-])(?:png|jpe?g|gif|bmp|ico|icon|wav|audio|font|ttf|otf)(?:$|[._-])",
    re.IGNORECASE,
)
PYINSTALLER_ARTIFACT_KIND_RE = re.compile(
    r"^pyinstaller-(caller_preferred|python_script|python_module|pyz_archive|"
    r"pe_name_candidate|nested_archive)-([0-9]{3})-[A-Za-z0-9._-]{1,48}$",
    re.IGNORECASE,
)
PYINSTALLER_FRAMEWORK_SCRIPT_RE = re.compile(
    r"^(?:pyiboot[0-9]*(?:[._-].*)?|pyi[._-]rth(?:[._-].*)?|"
    r"pyi[._-]runtime(?:[._-].*)?)$",
    re.IGNORECASE,
)
PYINSTALLER_FRAMEWORK_MODULE_RE = re.compile(
    r"^pyimod[0-9]*(?:[._-].*)?$",
    re.IGNORECASE,
)
PYINSTALLER_SELECTION_CATEGORIES = frozenset(
    {
        "caller_preferred",
        "python_script",
        "python_module",
        "pyz_archive",
        "pe_name_candidate",
        "nested_archive",
    }
)
PYINSTALLER_ROLE_PRIORITIES = {
    "entry_script": -1,
    "application_module": 0,
    "pyz_archive": 0,
    "pe_child": 1,
    "runtime_script": 2,
    "runtime_module": 2,
    "nested_archive": 3,
    "caller_preferred": 1,
}
PYTHON_MARSHAL_CANDIDATE_KIND_RE = re.compile(
    r"^python-marshal-(?:(?:sequence-)?(?:base64|hex)-decoded|"
    r"literal-(?:structured-bytes|opaque-bytes|script-text))-[0-9]{3}$",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class InputUnit:
    """解析対象のインメモリ検体と公開可能な入力メタデータ。"""

    source_name: str
    data: bytes
    input_kind: str
    outer_sha256: str
    outer_size: int
    member_name: str | None = None

    def __post_init__(self) -> None:
        """入力メタデータとraw入力のhash・size整合性を検証する。"""

        if (
            not isinstance(self.source_name, str)
            or not self.source_name
            or len(self.source_name) > 4096
            or any(ord(character) < 32 or ord(character) == 127 for character in self.source_name)
        ):
            raise ValueError("source_name must be a bounded string without controls")
        if not isinstance(self.data, bytes):
            raise TypeError("data must be immutable bytes")
        if not isinstance(self.input_kind, str) or not self.input_kind:
            raise ValueError("input_kind must be a non-empty string")
        if not re.fullmatch(r"[0-9a-f]{64}", self.outer_sha256):
            raise ValueError("outer_sha256 must be a lowercase SHA-256 digest")
        if isinstance(self.outer_size, bool) or not isinstance(self.outer_size, int) or self.outer_size < 0:
            raise ValueError("outer_size must be a non-negative integer")
        if self.input_kind == "raw":
            if self.outer_size != len(self.data):
                raise ValueError("raw outer_size does not match data")
            if self.outer_sha256 != hashlib.sha256(self.data).hexdigest():
                raise ValueError("raw outer_sha256 does not match data")
        if self.member_name is not None and (not isinstance(self.member_name, str) or not self.member_name):
            raise ValueError("member_name must be a non-empty string when present")


@dataclass(frozen=True)
class StaticLayer:
    """メモリ内だけで保持する認証済み静的復元レイヤー。"""

    name: str
    data: bytes
    sha256: str
    parent_sha256: str | None
    depth: int
    transform: str
    container_candidate_kind: str | None = None
    container_candidate_role: str | None = None
    container_candidate_pair_count: int = 0
    launch_lineage_relation: str | None = None

    def public(self) -> dict[str, Any]:
        """バイト列を含まないレイヤーメタデータを返す。"""

        result = {
            "name": self.name,
            "sha256": self.sha256,
            "size": len(self.data),
            "format": detect_format(self.data, self.name),
            "parent_sha256": self.parent_sha256,
            "depth": self.depth,
            "transform": self.transform,
        }
        if self.container_candidate_kind is not None:
            result["container_priority_candidate"] = {
                "kind": self.container_candidate_kind,
                "role": self.container_candidate_role,
                "pair_count": self.container_candidate_pair_count,
                "queue_prioritization_only": True,
                "execution_confirmed": False,
                "family_confirmation": False,
                "c2_confirmation": False,
            }
        if self.launch_lineage_relation is not None:
            result["launch_lineage_priority"] = {
                "kind": "inno_launch_target",
                "relation": self.launch_lineage_relation,
                "queue_prioritization_only": True,
                "static_execution_lineage_selected": True,
                "sample_execution_observed": False,
                "family_confirmation": False,
                "c2_confirmation": False,
            }
        return result


@dataclass(frozen=True)
class _PendingStaticLayer:
    """digestごとの保留中最良候補と安定順序を保持する。"""

    priority: int
    sequence: int
    discovery_sequence: int
    revision: int
    layer: StaticLayer
    parent_step: dict[str, Any] | None


@dataclass(frozen=True)
class _NewStaticLayerCandidate:
    """同一親から新規にqueueへ追加する候補を発見順のまま保持する。"""

    priority: int
    sequence: int
    discovery_sequence: int
    layer: StaticLayer
    parent_step: dict[str, Any]


@dataclass(frozen=True)
class _RejectedPendingStaticLayer:
    """容量予約を解放したpending候補の再評価用metadataだけを保持する。"""

    priority: int
    sequence: int
    discovery_sequence: int
    event: dict[str, Any]


@dataclass(frozen=True)
class StaticLayerPolicy:
    """再帰展開の件数・深さ・容量・圧縮率上限をまとめた共有ポリシー。"""

    max_layers: int = MAX_STATIC_LAYERS
    max_depth: int = MAX_STATIC_DEPTH
    max_layer_size: int = MAX_RECOVERED_LAYER_SIZE
    max_total_size: int = MAX_RECOVERED_TOTAL_SIZE
    max_compression_ratio: float = MAX_STATIC_COMPRESSION_RATIO
    max_archive_members: int = MAX_ARCHIVE_MEMBERS

    def __post_init__(self) -> None:
        for field, value in (
            ("max_layers", self.max_layers),
            ("max_depth", self.max_depth),
            ("max_layer_size", self.max_layer_size),
            ("max_total_size", self.max_total_size),
            ("max_archive_members", self.max_archive_members),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise ValueError(f"{field}は正の整数で指定してください")
        if (
            not isinstance(self.max_compression_ratio, (int, float))
            or isinstance(self.max_compression_ratio, bool)
            or not math.isfinite(self.max_compression_ratio)
            or self.max_compression_ratio <= 0
        ):
            raise ValueError("max_compression_ratioは有限の正数で指定してください")

    def public(self) -> dict[str, int | float]:
        """公開レポート用の上限値を返す。"""

        return {
            "max_layers": self.max_layers,
            "max_depth": self.max_depth,
            "max_recovered_layer_size": self.max_layer_size,
            "max_recovered_total_size": self.max_total_size,
            "max_archive_compression_ratio": self.max_compression_ratio,
            "max_archive_members": self.max_archive_members,
        }


Unpacker = Callable[..., tuple[dict[str, Any], list[tuple[str, bytes]]]]
Sanitizer = Callable[[Any], Any]


def _identity(value: Any) -> Any:
    return value


def _safe_sanitize(sanitizer: Sanitizer, value: Any) -> Any:
    """サニタイザー自体の失敗時も未加工値を公開せず、型情報だけを返す。"""

    try:
        return sanitizer(value)
    except Exception as exc:  # noqa: BLE001 - 任意sanitizer境界をfail closedにする
        return {
            "sanitization_failed": True,
            "error_type": _safe_error_type(exc),
        }


def _safe_error_type(exc: BaseException) -> str:
    """任意例外の型名を、固定文字種・長さの公開値へ制限する。"""

    name = type(exc).__name__
    if isinstance(name, str) and re.fullmatch(r"[A-Za-z][A-Za-z0-9_.]{0,127}", name):
        return name
    return "Exception"


def _artifact_label(value: object) -> str:
    """unpacker由来の種別を制御文字なしの有界ラベルへ変換する。"""

    try:
        text = str(value)
    except Exception:  # noqa: BLE001 - 任意labelの__str__失敗を閉じ込める
        return "artifact"
    text = "".join(character if 32 <= ord(character) < 127 else "_" for character in text)
    text = re.sub(r"[^A-Za-z0-9._-]+", "_", text).strip("._")
    return (text or "artifact")[:80]


def _artifact_analysis_priority(
    artifact_kind: str,
    blob: bytes,
    detection_name: str | None = None,
    *,
    verified_marshal_candidate: bool = False,
    verified_pyinstaller_role: str | None = None,
) -> int:
    """内容magicと信頼済みtransform種別から静的解析queueの価値tierを返す。

    ``detection_name`` は互換引数として残すが、archive内の任意ファイル名だけで
    opaque blobを実行形式・script相当へ昇格させない。名前は次層の形式判定には
    保持し、queueの資源配分だけを内容由来へ固定する。
    """

    del detection_name
    # 専用marshal parserの完全消費reportと親入力・候補のkind/hash/sizeを
    # 呼出側で照合できた内容だけを、残存PyInstaller stdlibより先に処理する。
    # これはlayer上限内の資源配分であり、family・悪性・payload・C2の根拠ではない。
    if verified_marshal_candidate and PYTHON_MARSHAL_CANDIDATE_KIND_RE.fullmatch(artifact_kind) is not None:
        return -2
    # CArchive reportの親入力・safety・選択entry・artifact identityを呼出側で
    # 全件照合できた場合だけrole優先度を使う。artifact labelだけでは昇格しない。
    # これはlayer上限内の資源配分であり、family・悪性・payload・C2の根拠ではない。
    if verified_pyinstaller_role is not None:
        priority = PYINSTALLER_ROLE_PRIORITIES.get(verified_pyinstaller_role)
        if priority is not None:
            return priority
    artifact_format = detect_format(blob, artifact_kind)
    if artifact_format == "pe" and valid_pe_extent(blob) is None:
        artifact_format = "data"
    if artifact_format in CONTAINER_FORMATS:
        return 0
    if artifact_format in ACTIONABLE_FORMATS:
        return 1
    if artifact_format == "png" or LOW_VALUE_RESOURCE_KIND_RE.search(artifact_kind):
        return 5
    if HIGH_VALUE_KIND_RE.search(artifact_kind):
        return 2
    if "opaque" in artifact_kind.casefold():
        return 3
    return 4


def _verified_artifact_name_hints(
    report: dict[str, Any],
    artifacts: list[tuple[str, bytes]],
) -> dict[int, str]:
    """index・kind・hashが一致する有界basename hintだけを採用する。"""

    envelope = report.get("artifact_name_hints")
    if not isinstance(envelope, dict):
        return {}
    if envelope.get("schema_version") != 1 or envelope.get("complete") is not True:
        return {}
    items = envelope.get("items")
    if not isinstance(items, list) or len(items) > len(artifacts):
        return {}
    hints: dict[int, str] = {}
    used_basenames: set[str] = set()
    for item in items:
        if not isinstance(item, dict):
            continue
        artifact_index = item.get("artifact_index")
        if (
            isinstance(artifact_index, bool)
            or not isinstance(artifact_index, int)
            or not 0 <= artifact_index < len(artifacts)
            or artifact_index in hints
        ):
            continue
        artifact = artifacts[artifact_index]
        if not isinstance(artifact, tuple) or len(artifact) != 2:
            continue
        artifact_kind, blob = artifact
        if not isinstance(blob, bytes):
            continue
        expected_kind = _artifact_label(artifact_kind)
        if item.get("artifact_kind") != expected_kind:
            continue
        digest = item.get("sha256")
        if (
            not isinstance(digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
            or digest != hashlib.sha256(blob).hexdigest()
        ):
            continue
        member_basename = item.get("member_basename")
        try:
            normalized = normalize_archive_member_basename(member_basename)
        except (TypeError, ValueError):
            continue
        collision_key = normalized.casefold()
        if collision_key in used_basenames:
            continue
        used_basenames.add(collision_key)
        hints[artifact_index] = normalized
    return hints


def _verified_zip_artifact_paths(
    report: dict[str, Any],
    artifacts: list[tuple[str, bytes]],
) -> dict[int, str]:
    """ZIP inventoryをartifact index・kind・hash・sizeへ完全照合する。

    `recover_zip` は復元memberをinventoryと同じ順序で先頭へ追加する。後続の
    Equation/OLE候補などと混同しないよう `zip-` artifact集合と、SHA-256を持つ
    inventory行の件数・順序を全件照合し、不整合時は来歴全体を採用しない。
    """

    inventory = report.get("zip")
    if (
        report.get("format") != "zip"
        or not isinstance(inventory, Sequence)
        or isinstance(inventory, (str, bytes, bytearray))
    ):
        return {}
    zip_indices = [
        index
        for index, artifact in enumerate(artifacts)
        if isinstance(artifact, tuple)
        and len(artifact) == 2
        and isinstance(artifact[0], str)
        and artifact[0].casefold().startswith("zip-")
        and isinstance(artifact[1], bytes)
    ]
    records: list[tuple[str, str, int, str]] = []
    observed_paths: set[str] = set()
    for raw_record in inventory:
        if not isinstance(raw_record, Mapping):
            return {}
        digest = raw_record.get("sha256")
        if digest is None:
            continue
        name = raw_record.get("name")
        size = raw_record.get("size")
        artifact_format = raw_record.get("format")
        if (
            not isinstance(name, str)
            or not name
            or len(name) > 4096
            or name != unicodedata.normalize("NFC", name)
            or name.startswith(("/", "\\"))
            or "\\" in name
            or any(ord(character) < 32 or ord(character) == 127 for character in name)
            or not isinstance(digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            or type(size) is not int
            or size < 0
            or not isinstance(artifact_format, str)
            or not artifact_format
            or len(artifact_format) > 80
        ):
            return {}
        path = PurePosixPath(name)
        if (
            path.is_absolute()
            or name != path.as_posix()
            or any(part in {"", ".", ".."} or ":" in part for part in path.parts)
            or name.casefold() in observed_paths
        ):
            return {}
        observed_paths.add(name.casefold())
        records.append((name, digest, size, artifact_format))
    if len(records) != len(zip_indices):
        return {}

    verified: dict[int, str] = {}
    for artifact_index, (name, digest, size, artifact_format) in zip(
        zip_indices,
        records,
        strict=True,
    ):
        artifact_kind, blob = artifacts[artifact_index]
        expected_kind = f"zip-{artifact_format}-{PurePosixPath(name).name}"
        if artifact_kind != expected_kind or len(blob) != size or hashlib.sha256(blob).hexdigest() != digest:
            return {}
        verified[artifact_index] = name
    return verified


def _verified_marshal_candidate_indices(
    report: dict[str, Any],
    artifacts: list[tuple[str, bytes]],
    *,
    parent_sha256: str,
    parent_size: int,
) -> set[int]:
    """完全消費reportと親・artifactへ一対一で束縛できる候補indexだけを返す。"""

    envelope = report.get("python_marshal")
    if not isinstance(envelope, dict):
        return set()
    if (
        envelope.get("schema_version") != 1
        or envelope.get("status") != "artifacts_recovered"
        or envelope.get("profile") != PYTHON_MARSHAL_PROFILE
        or envelope.get("candidate_set_complete") is not True
        or envelope.get("blockers") != []
    ):
        return set()
    input_metadata = envelope.get("input")
    coverage = envelope.get("coverage")
    if not isinstance(input_metadata, dict) or not isinstance(coverage, dict):
        return set()
    if input_metadata != {"size": parent_size, "sha256": parent_sha256}:
        return set()
    if (
        coverage.get("full_consumption") is not True
        or coverage.get("bytes_consumed") != parent_size
        or coverage.get("input_size") != parent_size
    ):
        return set()
    safety = envelope.get("safety")
    if not isinstance(safety, dict) or any(
        safety.get(field) is not False
        for field in (
            "sample_executed",
            "network_contacted",
            "marshal_loads_used",
            "python_bytecode_executed",
            "raw_constant_published",
        )
    ):
        return set()
    candidates = envelope.get("candidates")
    candidate_count = envelope.get("candidate_count")
    if (
        not isinstance(candidates, list)
        or not candidates
        or isinstance(candidate_count, bool)
        or not isinstance(candidate_count, int)
        or candidate_count != len(candidates)
    ):
        return set()
    available: dict[tuple[str, str, int], list[int]] = {}
    for artifact_index, artifact in enumerate(artifacts):
        if not isinstance(artifact, tuple) or len(artifact) != 2:
            continue
        artifact_kind, blob = artifact
        if not isinstance(artifact_kind, str) or not isinstance(blob, bytes):
            continue
        identity = (artifact_kind, hashlib.sha256(blob).hexdigest(), len(blob))
        available.setdefault(identity, []).append(artifact_index)
    verified_indices: set[int] = set()
    verified_digests: set[str] = set()
    total_size = 0
    for expected_index, item in enumerate(candidates):
        if not isinstance(item, dict) or item.get("index") != expected_index:
            return set()
        artifact_kind = item.get("artifact_kind")
        digest = item.get("sha256")
        size = item.get("size")
        if (
            not isinstance(artifact_kind, str)
            or PYTHON_MARSHAL_CANDIDATE_KIND_RE.fullmatch(artifact_kind) is None
            or not isinstance(digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            or isinstance(size, bool)
            or not isinstance(size, int)
            or size <= 0
            or digest in verified_digests
        ):
            return set()
        matching_indices = available.get((artifact_kind, digest, size), [])
        if len(matching_indices) != 1:
            return set()
        verified_indices.add(matching_indices[0])
        verified_digests.add(digest)
        total_size += size
    candidate_total_size = envelope.get("candidate_total_size")
    if (
        isinstance(candidate_total_size, bool)
        or not isinstance(candidate_total_size, int)
        or candidate_total_size != total_size
    ):
        return set()
    return verified_indices


def _pyinstaller_artifact_label(
    category: str,
    index: int,
    normalized_path: str,
) -> str | None:
    """復元器と同じ規則でCArchive artifact labelを再構成する。"""

    if category not in PYINSTALLER_SELECTION_CATEGORIES or not 0 <= index <= 999:
        return None
    try:
        # path全体の安全性を再検証し、basenameだけをlabel再構成へ使う。
        normalize_archive_member_basename(normalized_path)
    except (TypeError, ValueError):
        return None
    basename = PurePosixPath(normalized_path.replace("\\", "/")).name
    label = re.sub(r"[^A-Za-z0-9._-]+", "_", basename).strip("._")
    label = (label or "entry")[:48]
    return f"pyinstaller-{category}-{index:03d}-{label}"


def _pyinstaller_entry_role(
    *,
    category: str,
    typecode: str,
    payload_format: str,
    normalized_path: str,
    blob: bytes,
) -> str | None:
    """検証済みCArchive entryをqueue資源配分用roleへ分類する。"""

    basename = PurePosixPath(normalized_path.replace("\\", "/")).name
    stem = PurePosixPath(basename).stem
    if category == "caller_preferred":
        if typecode == "s" and payload_format == "pyinstaller_python_script_entry":
            category = "python_script"
        elif typecode in {"m", "M"} and payload_format == "pyinstaller_python_module_entry":
            category = "python_module"
        elif typecode == "z" and payload_format == "pyinstaller_pyz":
            category = "pyz_archive"
        elif payload_format == "portable_executable":
            category = "pe_name_candidate"
        else:
            return "caller_preferred"
    if category == "python_script":
        if typecode != "s" or payload_format != "pyinstaller_python_script_entry":
            return None
        return "runtime_script" if PYINSTALLER_FRAMEWORK_SCRIPT_RE.fullmatch(stem) is not None else "entry_script"
    if category == "python_module":
        if typecode not in {"m", "M"} or payload_format != "pyinstaller_python_module_entry":
            return None
        return "runtime_module" if PYINSTALLER_FRAMEWORK_MODULE_RE.fullmatch(stem) is not None else "application_module"
    if category == "pyz_archive":
        if typecode != "z" or payload_format != "pyinstaller_pyz" or not blob.startswith(b"PYZ\0"):
            return None
        return "pyz_archive"
    if category == "pe_name_candidate":
        if payload_format != "portable_executable" or valid_pe_extent(blob) is None:
            return None
        return "pe_child"
    if category == "nested_archive":
        return "nested_archive"
    return None


def _verified_pyinstaller_artifact_roles(
    report: dict[str, Any],
    artifacts: list[tuple[str, bytes]],
    *,
    parent_sha256: str,
    parent_size: int,
) -> dict[int, str]:
    """親・safety・全選択entryへ束縛できたCArchive roleだけを返す。"""

    envelope = report.get("pyinstaller")
    if not isinstance(envelope, dict):
        return {}
    if envelope.get("schema_version") != 1 or envelope.get("status") not in {
        "artifacts_recovered",
        "partial_artifacts_recovered",
    }:
        return {}
    if envelope.get("sample") != {"sha256": parent_sha256, "size": parent_size}:
        return {}
    archive = envelope.get("archive")
    selection = envelope.get("selection")
    safety = envelope.get("safety")
    if (
        not isinstance(archive, dict)
        or archive.get("format") != "PyInstaller CArchive"
        or not isinstance(selection, dict)
        or selection.get("strategy") != "bounded_priority_v1"
        or not isinstance(safety, dict)
    ):
        return {}
    if any(
        safety.get(field) is not False
        for field in (
            "sample_executed",
            "external_process_started",
            "network_contacted",
            "file_written",
        )
    ) or any(
        safety.get(field) is not True
        for field in (
            "bytes_only",
            "all_toc_records_bounds_validated",
            "all_payload_ranges_overlap_validated",
            "all_paths_collision_validated",
            "retained_declared_and_actual_sizes_validated",
            "retained_zlib_eof_validated",
        )
    ):
        return {}
    selected_entries = selection.get("selected_entries")
    retained_count = selection.get("retained_count")
    retained_artifact_count = envelope.get("retained_artifact_count")
    if (
        not isinstance(selected_entries, list)
        or not selected_entries
        or isinstance(retained_count, bool)
        or not isinstance(retained_count, int)
        or isinstance(retained_artifact_count, bool)
        or not isinstance(retained_artifact_count, int)
        or retained_count != len(selected_entries)
        or retained_artifact_count != len(selected_entries)
    ):
        return {}

    available: dict[tuple[str, str, int], list[int]] = {}
    pyinstaller_artifact_indices: set[int] = set()
    for artifact_index, artifact in enumerate(artifacts):
        if not isinstance(artifact, tuple) or len(artifact) != 2:
            continue
        artifact_kind, blob = artifact
        if not isinstance(artifact_kind, str) or not isinstance(blob, bytes):
            continue
        normalized_kind = _artifact_label(artifact_kind)
        if PYINSTALLER_ARTIFACT_KIND_RE.fullmatch(normalized_kind) is not None:
            pyinstaller_artifact_indices.add(artifact_index)
        identity = (normalized_kind, hashlib.sha256(blob).hexdigest(), len(blob))
        available.setdefault(identity, []).append(artifact_index)

    roles: dict[int, str] = {}
    for selected_index, item in enumerate(selected_entries):
        if not isinstance(item, dict):
            return {}
        category = item.get("category")
        typecode = item.get("typecode")
        payload_format = item.get("payload_format")
        normalized_path = item.get("normalized_path")
        digest = item.get("sha256")
        size = item.get("uncompressed_size")
        if (
            not isinstance(category, str)
            or category not in PYINSTALLER_SELECTION_CATEGORIES
            or not isinstance(typecode, str)
            or len(typecode) != 1
            or not isinstance(payload_format, str)
            or not isinstance(normalized_path, str)
            or not isinstance(digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            or isinstance(size, bool)
            or not isinstance(size, int)
            or size <= 0
        ):
            return {}
        artifact_kind = _pyinstaller_artifact_label(category, selected_index, normalized_path)
        if artifact_kind is None or PYINSTALLER_ARTIFACT_KIND_RE.fullmatch(artifact_kind) is None:
            return {}
        matching_indices = available.get((artifact_kind, digest, size), [])
        if len(matching_indices) != 1 or matching_indices[0] in roles:
            return {}
        artifact_index = matching_indices[0]
        blob = artifacts[artifact_index][1]
        role = _pyinstaller_entry_role(
            category=category,
            typecode=typecode,
            payload_format=payload_format,
            normalized_path=normalized_path,
            blob=blob,
        )
        if role is None:
            return {}
        roles[artifact_index] = role
    if set(roles) != pyinstaller_artifact_indices:
        return {}
    return roles


def _stratified_sibling_indices(candidate_count: int) -> list[int]:
    """どの短いprefixでも発見範囲を覆う決定的なsibling順序を返す。

    先頭と末尾を最初に選び、以後は未選択幅が最大の区間の中点を選ぶ。
    artifact名、hash、内容に依存しないため、同一入力では常に同じ順序となる。
    """

    if candidate_count <= 0:
        return []
    if candidate_count == 1:
        return [0]
    order = [0, candidate_count - 1]
    intervals: list[tuple[int, int, int]] = [(-(candidate_count - 1), 0, candidate_count - 1)]
    while intervals:
        _negative_width, left, right = heapq.heappop(intervals)
        if right - left <= 1:
            continue
        midpoint = (left + right) // 2
        order.append(midpoint)
        if midpoint - left > 1:
            heapq.heappush(intervals, (-(midpoint - left), left, midpoint))
        if right - midpoint > 1:
            heapq.heappush(intervals, (-(right - midpoint), midpoint, right))
    if len(order) != candidate_count:
        raise RuntimeError("stratified sibling順序の構築に失敗しました")
    return order


def recover_static_layers(
    unit: InputUnit,
    *,
    unpacker: Unpacker | None = None,
    sanitizer: Sanitizer = _identity,
    policy: StaticLayerPolicy | None = None,
    upx: Path | None = None,
    sevenzip: Path | None = None,
    diec: Path | None = None,
    innounp: Path | None = None,
    force_container_probe: bool = False,
    archive_password: str = "infected",
    inno_password: str = "",
) -> tuple[list[StaticLayer], dict[str, Any]]:
    """任意の共通契約unpackerを使い、復元層を決定的に再帰処理する。"""

    if unpacker is None:
        from unpackers.static_unpacker import unpack_bytes

        unpacker = unpack_bytes
    effective_policy = policy or StaticLayerPolicy()
    root = StaticLayer(
        name=unit.source_name,
        data=unit.data,
        sha256=hashlib.sha256(unit.data).hexdigest(),
        parent_sha256=None,
        depth=0,
        transform="submission",
    )
    layers = [root]
    processed_digests: set[str] = set()
    steps: list[dict[str, Any]] = []
    recovered_total = 0
    reserved_total = 0
    deduplicated_artifacts = 0
    stratified_sibling_group_sizes: dict[tuple[str, int, int], int] = {}
    discovery_sequence = 0
    queue_revision = 0
    root_pending = _PendingStaticLayer(
        priority=-1,
        sequence=discovery_sequence,
        discovery_sequence=discovery_sequence,
        revision=queue_revision,
        layer=root,
        parent_step=None,
    )
    pending_best = {root.sha256: root_pending}
    pending_layers: list[tuple[int, int, int, int, str]] = [(-1, 0, discovery_sequence, queue_revision, root.sha256)]
    limit_events: list[dict[str, Any]] = []
    layer_count_limit_events: list[tuple[int, dict[str, Any]]] = []
    rejected_pending_best: dict[str, _RejectedPendingStaticLayer] = {}

    def lineage_ancestors(
        current: StaticLayer,
    ) -> tuple[tuple[bytes, str, str | None, int], ...]:
        """currentまでの実byte containment chainをroot順で返す。"""

        by_digest = {item.sha256: item for item in layers}
        ancestors: list[StaticLayer] = []
        seen: set[str] = set()
        parent_digest = current.parent_sha256
        while parent_digest is not None and parent_digest not in seen:
            seen.add(parent_digest)
            ancestor = by_digest.get(parent_digest)
            if ancestor is None:
                break
            ancestors.append(ancestor)
            parent_digest = ancestor.parent_sha256
        return tuple((item.data, item.sha256, item.parent_sha256, item.depth) for item in reversed(ancestors))

    def pending_order_key(
        item: _PendingStaticLayer | _NewStaticLayerCandidate,
    ) -> tuple[int, int, int, str]:
        return (
            item.priority,
            -item.layer.depth,
            item.sequence,
            item.layer.sha256,
        )

    def rebalance_pending_sibling_groups() -> None:
        """全pendingと残り枠から、実際に部分選択となるgroupだけを層化する。"""

        nonlocal queue_revision
        pending_in_selection_order = sorted(
            (item for item in pending_best.values() if item.layer.parent_sha256 is not None),
            key=pending_order_key,
        )
        available_slots = max(0, effective_policy.max_layers - len(layers))
        selected_digests = {item.layer.sha256 for item in pending_in_selection_order[:available_slots]}
        sibling_groups: dict[tuple[str, int, int], list[_PendingStaticLayer]] = {}
        for item in pending_in_selection_order:
            parent_sha256 = item.layer.parent_sha256
            if parent_sha256 is None:
                continue
            group_key = (parent_sha256, item.priority, item.layer.depth)
            sibling_groups.setdefault(group_key, []).append(item)
        for group_key, sibling_group in sibling_groups.items():
            # ``sequence`` is the queue rank assigned by an earlier rebalance.
            # Once a group is stratified its current order is already the
            # desired prefix order, so reapplying the permutation after the
            # pending set shrinks would drift toward a different subset.
            # Only the first partial selection is derived from immutable
            # discovery order; later selections preserve that established
            # stratified rank.
            discovery_order = sorted(
                sibling_group,
                key=lambda item: (item.discovery_sequence, item.layer.sha256),
            )
            selected_count = sum(item.layer.sha256 in selected_digests for item in sibling_group)
            is_partially_selected = 0 < selected_count < len(sibling_group)
            if is_partially_selected:
                if group_key in stratified_sibling_group_sizes:
                    desired_order = sibling_group
                else:
                    stratified_sibling_group_sizes[group_key] = len(sibling_group)
                    desired_order = [
                        discovery_order[index] for index in _stratified_sibling_indices(len(discovery_order))
                    ]
            else:
                desired_order = discovery_order
            sequence_slots = sorted(item.discovery_sequence for item in sibling_group)
            desired_sequences = {item.layer.sha256: sequence_slots[index] for index, item in enumerate(desired_order)}
            for item in sibling_group:
                desired_sequence = desired_sequences[item.layer.sha256]
                if item.sequence == desired_sequence:
                    continue
                queue_revision += 1
                replacement = _PendingStaticLayer(
                    priority=item.priority,
                    sequence=desired_sequence,
                    discovery_sequence=item.discovery_sequence,
                    revision=queue_revision,
                    layer=item.layer,
                    parent_step=item.parent_step,
                )
                pending_best[item.layer.sha256] = replacement
                heapq.heappush(
                    pending_layers,
                    (
                        replacement.priority,
                        -replacement.layer.depth,
                        replacement.sequence,
                        replacement.revision,
                        replacement.layer.sha256,
                    ),
                )

    def reject_pending_for_capacity(
        pending: _PendingStaticLayer,
        *,
        reason: str,
    ) -> None:
        """採用不能pendingをqueueから外し、予約だけを即時解放する。"""

        nonlocal reserved_total
        digest = pending.layer.sha256
        current = pending_best.get(digest)
        if current is None or current.revision != pending.revision:
            return
        del pending_best[digest]
        reserved_total -= len(pending.layer.data)
        if reserved_total < recovered_total:
            raise RuntimeError("pending容量予約が回収済み容量を下回りました")
        rejected_pending_best[digest] = _RejectedPendingStaticLayer(
            priority=pending.priority,
            sequence=pending.sequence,
            discovery_sequence=pending.discovery_sequence,
            event={
                "parent_sha256": pending.layer.parent_sha256,
                "kind": pending.layer.transform,
                "sha256": digest,
                "size": len(pending.layer.data),
                "reason": reason,
            },
        )

    def prune_pending_to_layer_capacity() -> None:
        """残りlayer枠に入らないpendingを決定的に除外し、予約を戻す。"""

        available_slots = max(0, effective_policy.max_layers - len(layers))
        ordered = sorted(pending_best.values(), key=pending_order_key)
        for pending in ordered[available_slots:]:
            reject_pending_for_capacity(pending, reason="layer_count_limit")

    def rebalance_pending_to_total_capacity(
        candidates: list[_NewStaticLayerCandidate],
    ) -> list[_NewStaticLayerCandidate]:
        """accepted層を固定し、priority順で総byte枠に収まるpendingだけを残す。"""

        nonlocal reserved_total
        remaining = effective_policy.max_total_size - recovered_total
        selected_digests: set[str] = set()
        for item in sorted([*pending_best.values(), *candidates], key=pending_order_key):
            size = len(item.layer.data)
            if size > remaining:
                continue
            selected_digests.add(item.layer.sha256)
            remaining -= size

        for pending in sorted(pending_best.values(), key=pending_order_key):
            if pending.layer.sha256 not in selected_digests:
                reject_pending_for_capacity(
                    pending,
                    reason="recovered_total_limit",
                )

        accepted_candidates = []
        for candidate in candidates:
            child = candidate.layer
            digest = child.sha256
            if digest in selected_digests:
                reserved_total += len(child.data)
                rejected_pending_best.pop(digest, None)
                accepted_candidates.append(candidate)
                continue
            rejected_pending_best[digest] = _RejectedPendingStaticLayer(
                priority=candidate.priority,
                sequence=candidate.sequence,
                discovery_sequence=candidate.discovery_sequence,
                event={
                    "parent_sha256": child.parent_sha256,
                    "kind": child.transform,
                    "sha256": digest,
                    "size": len(child.data),
                    "reason": "recovered_total_limit",
                },
            )
        if reserved_total > effective_policy.max_total_size:
            raise RuntimeError("pending容量予約が総byte上限を超過しました")
        return accepted_candidates

    while pending_layers:
        _priority, _negative_depth, _sequence, revision, digest = heapq.heappop(pending_layers)
        pending = pending_best.get(digest)
        if pending is None or pending.revision != revision:
            continue
        del pending_best[digest]
        processed_digests.add(digest)
        layer = pending.layer
        if layer.parent_sha256 is not None:
            if len(layers) >= effective_policy.max_layers:
                layer_count_limit_events.append(
                    (
                        pending.discovery_sequence,
                        {
                            "parent_sha256": layer.parent_sha256,
                            "kind": layer.transform,
                            "sha256": layer.sha256,
                            "size": len(layer.data),
                            "reason": "layer_count_limit",
                        },
                    )
                )
                continue
            layers.append(layer)
            recovered_total += len(layer.data)
            parent_step = pending.parent_step
            if parent_step is None:
                raise RuntimeError("queued static layerのparent stepがありません")
            parent_step["accepted_children"].append(layer.public())
        if layer.depth >= effective_policy.max_depth:
            limit_events.append(
                {
                    "parent_sha256": layer.sha256,
                    "reason": "depth_limit",
                }
            )
            steps.append(
                {
                    "input_layer": layer.public(),
                    "status": "skipped_depth_limit",
                }
            )
            continue
        # pending予約は候補発見後の再平衡対象なので、展開枠はaccepted層だけを固定して算出する。
        remaining_total = effective_policy.max_total_size - recovered_total
        if remaining_total <= 0:
            limit_events.append(
                {
                    "parent_sha256": layer.sha256,
                    "reason": "recovered_total_limit",
                }
            )
            steps.append(
                {
                    "input_layer": layer.public(),
                    "status": "skipped_recovered_total_limit",
                }
            )
            continue
        try:
            unpacker_options: dict[str, Any] = {
                "upx": upx,
                "sevenzip": sevenzip,
                "diec": diec,
                "force_container_probe": force_container_probe,
                "archive_password": archive_password,
                "max_archive_members": effective_policy.max_archive_members,
                "max_archive_member_size": min(
                    effective_policy.max_layer_size,
                    remaining_total,
                ),
                "max_archive_total_size": remaining_total,
                "max_archive_compression_ratio": effective_policy.max_compression_ratio,
            }
            # legacy/custom unpackerへ未知keywordを渡さず、未指定時の呼出し契約を保つ。
            if innounp is not None:
                unpacker_options["innounp"] = innounp
            if inno_password:
                unpacker_options["inno_password"] = inno_password
            report, artifacts = unpacker(
                layer.data,
                layer.name,
                **unpacker_options,
            )
            if not isinstance(report, dict) or not isinstance(artifacts, list):
                raise TypeError("unpackerは(dict, list)を返す必要があります")
            zip_sideload_roles: dict[int, ZipSideLoadArtifactRole] = {}
            if report.get("format") == "zip":
                zip_sideload_analysis = analyze_zip_sideload_pairs(
                    artifacts,
                    _verified_zip_artifact_paths(report, artifacts),
                )
                zip_sideload_roles = zip_sideload_analysis.roles_by_index()
                report["zip_sideload_pair_prioritization"] = zip_sideload_analysis.public()
            lineage_selection = select_static_layer_children(
                parent_data=layer.data,
                parent_sha256=layer.sha256,
                parent_parent_sha256=layer.parent_sha256,
                parent_depth=layer.depth,
                parent_ancestors=lineage_ancestors(layer),
                report=report,
                artifacts=artifacts,
            )
            verified_sibling_bundle = recover_verified_sibling_bundle_layer(
                parent_data=layer.data,
                parent_sha256=layer.sha256,
                report=report,
                artifacts=artifacts,
            )
            if isinstance(verified_sibling_bundle, VerifiedSiblingBundleLayer):
                # 正規化ZIPは同居memberのidentity全件結合とstrict lineage成立後だけ
                # 後段へ渡す。ここではfamily/C2を昇格せず、既存detectorへ委ねる。
                report["verified_sibling_bundle_adapter"] = verified_sibling_bundle.public()
                artifacts.append(
                    (
                        "verified-sibling-analysis-container",
                        verified_sibling_bundle.data,
                    )
                )
            step = {
                "input_layer": layer.public(),
                "status": "succeeded",
                "report": _safe_sanitize(sanitizer, report),
                "lineage_child_selection": lineage_selection.public(),
                "accepted_children": [],
            }
        except Exception as exc:  # noqa: BLE001 - 任意unpacker境界をfail closedにする
            steps.append(
                {
                    "input_layer": layer.public(),
                    "status": "failed",
                    "error": "unpacker_failed",
                    "error_type": _safe_error_type(exc),
                }
            )
            continue
        lineage_selected_digests = (
            set(lineage_selection.selected_digests)
            if lineage_selection.status == "complete_selected" and lineage_selection.omitted_commitment.complete
            else set()
        )
        selected_script_launch_digests = {
            edge.target_sha256
            for edge in lineage_selection.validated_edges
            if edge.relation == "script_launch" and edge.target_sha256 in lineage_selected_digests
        }
        artifact_name_hints = _verified_artifact_name_hints(report, artifacts)
        verified_marshal_indices = _verified_marshal_candidate_indices(
            report,
            artifacts,
            parent_sha256=layer.sha256,
            parent_size=len(layer.data),
        )
        verified_pyinstaller_roles = _verified_pyinstaller_artifact_roles(
            report,
            artifacts,
            parent_sha256=layer.sha256,
            parent_size=len(layer.data),
        )
        candidates: list[
            tuple[
                int,
                int,
                str,
                bytes,
                str,
                str,
                ZipSideLoadArtifactRole | None,
                str | None,
            ]
        ] = []
        for artifact_index, artifact in enumerate(artifacts):
            if not isinstance(artifact, tuple) or len(artifact) != 2:
                limit_events.append(
                    {
                        "parent_sha256": layer.sha256,
                        "reason": "malformed_artifact_rejected",
                    }
                )
                continue
            artifact_kind, blob = artifact
            artifact_kind = _artifact_label(artifact_kind)
            if not isinstance(blob, bytes):
                limit_events.append(
                    {
                        "parent_sha256": layer.sha256,
                        "kind": str(artifact_kind),
                        "reason": "non_bytes_artifact_rejected",
                    }
                )
                continue
            if not blob:
                limit_events.append(
                    {
                        "parent_sha256": layer.sha256,
                        "kind": artifact_kind,
                        "reason": "empty_artifact_rejected",
                    }
                )
                continue
            digest = hashlib.sha256(blob).hexdigest()
            if len(blob) > effective_policy.max_layer_size:
                limit_events.append(
                    {
                        "parent_sha256": layer.sha256,
                        "kind": str(artifact_kind),
                        "sha256": digest,
                        "size": len(blob),
                        "reason": "layer_size_limit",
                    }
                )
                continue
            member_basename = artifact_name_hints.get(artifact_index)
            child_name = f"{layer.name}::{artifact_kind}"
            if member_basename is not None:
                child_name = f"{child_name}::{member_basename}"
            zip_sideload_role = zip_sideload_roles.get(artifact_index)
            launch_lineage_relation = (
                "script_launch"
                if digest in selected_script_launch_digests and artifact_kind.casefold().startswith("inno-member-")
                else None
            )
            candidates.append(
                (
                    LINEAGE_SELECTED_PRIORITY
                    if digest in lineage_selected_digests
                    else ZIP_SIDELOAD_PAIR_PRIORITY
                    if zip_sideload_role is not None
                    else _artifact_analysis_priority(
                        artifact_kind,
                        blob,
                        child_name,
                        verified_marshal_candidate=(artifact_index in verified_marshal_indices),
                        verified_pyinstaller_role=verified_pyinstaller_roles.get(artifact_index),
                    ),
                    artifact_index,
                    artifact_kind,
                    blob,
                    digest,
                    child_name,
                    zip_sideload_role,
                    launch_lineage_relation,
                )
            )
        new_candidates: list[_NewStaticLayerCandidate] = []
        new_candidate_digests: set[str] = set()
        pending_topology_changed = False
        for (
            priority,
            _artifact_index,
            artifact_kind,
            blob,
            digest,
            child_name,
            zip_sideload_role,
            launch_lineage_relation,
        ) in sorted(candidates, key=lambda item: (item[0], item[1])):
            if digest in processed_digests:
                deduplicated_artifacts += 1
                continue
            existing = pending_best.get(digest)
            if existing is not None:
                deduplicated_artifacts += 1
                if priority >= existing.priority:
                    continue
                child = StaticLayer(
                    name=child_name,
                    data=blob,
                    sha256=digest,
                    parent_sha256=layer.sha256,
                    depth=layer.depth + 1,
                    transform=str(artifact_kind),
                    container_candidate_kind=(
                        "zip_pe_import_export_adjacent_pair" if zip_sideload_role is not None else None
                    ),
                    container_candidate_role=(zip_sideload_role.role if zip_sideload_role is not None else None),
                    container_candidate_pair_count=(
                        zip_sideload_role.pair_count if zip_sideload_role is not None else 0
                    ),
                    launch_lineage_relation=launch_lineage_relation,
                )
                queue_revision += 1
                replacement = _PendingStaticLayer(
                    priority=priority,
                    sequence=existing.sequence,
                    discovery_sequence=existing.discovery_sequence,
                    revision=queue_revision,
                    layer=child,
                    parent_step=step,
                )
                pending_best[digest] = replacement
                pending_topology_changed = True
                heapq.heappush(
                    pending_layers,
                    (
                        priority,
                        -child.depth,
                        existing.sequence,
                        queue_revision,
                        digest,
                    ),
                )
                continue
            if digest in new_candidate_digests:
                # sorted順の最初が最良priorityかつ同priority内の最初のprovenanceとなる。
                deduplicated_artifacts += 1
                continue
            rejected = rejected_pending_best.get(digest)
            if rejected is not None:
                deduplicated_artifacts += 1
                if priority >= rejected.priority:
                    continue
            child = StaticLayer(
                name=child_name,
                data=blob,
                sha256=digest,
                parent_sha256=layer.sha256,
                depth=layer.depth + 1,
                transform=str(artifact_kind),
                container_candidate_kind=(
                    "zip_pe_import_export_adjacent_pair" if zip_sideload_role is not None else None
                ),
                container_candidate_role=(zip_sideload_role.role if zip_sideload_role is not None else None),
                container_candidate_pair_count=(zip_sideload_role.pair_count if zip_sideload_role is not None else 0),
                launch_lineage_relation=launch_lineage_relation,
            )
            new_candidate_digests.add(digest)
            if rejected is None:
                discovery_sequence += 1
                candidate_sequence = discovery_sequence
                candidate_discovery_sequence = discovery_sequence
            else:
                candidate_sequence = rejected.sequence
                candidate_discovery_sequence = rejected.discovery_sequence
            new_candidates.append(
                _NewStaticLayerCandidate(
                    priority=priority,
                    sequence=candidate_sequence,
                    discovery_sequence=candidate_discovery_sequence,
                    layer=child,
                    parent_step=step,
                )
            )
        new_candidates = rebalance_pending_to_total_capacity(new_candidates)
        for candidate in new_candidates:
            pending_topology_changed = True
            queue_revision += 1
            child = candidate.layer
            pending_best[child.sha256] = _PendingStaticLayer(
                priority=candidate.priority,
                sequence=candidate.sequence,
                discovery_sequence=candidate.discovery_sequence,
                revision=queue_revision,
                layer=child,
                parent_step=candidate.parent_step,
            )
            heapq.heappush(
                pending_layers,
                (
                    candidate.priority,
                    -child.depth,
                    candidate.sequence,
                    queue_revision,
                    child.sha256,
                ),
            )
        if pending_topology_changed:
            rebalance_pending_sibling_groups()
            prune_pending_to_layer_capacity()
        steps.append(step)
    deferred_capacity_events = sorted(
        (
            rejected.discovery_sequence,
            rejected.event,
        )
        for rejected in rejected_pending_best.values()
    )
    limit_events.extend(
        event for _sequence, event in deferred_capacity_events if event["reason"] == "recovered_total_limit"
    )
    layer_count_limit_events.extend(
        (sequence, event) for sequence, event in deferred_capacity_events if event["reason"] == "layer_count_limit"
    )
    limit_events.extend(event for _sequence, event in sorted(layer_count_limit_events))
    public = {
        "schema_version": 1,
        "limits": effective_policy.public(),
        "counts": {
            "layers": len(layers),
            "recovered_layers": len(layers) - 1,
            "recovered_bytes": recovered_total,
            "limit_events": len(limit_events),
            "deduplicated_artifacts": deduplicated_artifacts,
        },
        "layers": [item.public() for item in layers],
        "steps": steps,
        "limit_events": limit_events,
        "selection_policy": {
            "name": "lineage_zip_sideload_verified_pyinstaller_role_format_depth_pending_capacity_stratified_siblings_v6",
            "primary_order": (
                "validated_lineage_then_zip_sideload_or_verified_pyinstaller_role_then_format_priority_then_deeper_layer"
            ),
            "capacity_evaluation": "all_pending_layers_after_each_expansion",
            "under_capacity_same_tier_order": "discovery_order",
            "oversubscribed_same_parent_tier_order": ("endpoints_then_largest_interval_midpoint"),
            "stratified_sibling_groups": len(stratified_sibling_group_sizes),
            "stratified_sibling_candidates": sum(stratified_sibling_group_sizes.values()),
        },
        "executed_sample": False,
        "network_contacted": False,
        "recovered_content_exported": False,
    }
    return layers, public
