#!/usr/bin/env python3
"""静的unpackerの出力を上限付き認証済みレイヤーDAGへ変換する。"""

from __future__ import annotations

import hashlib
import heapq
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from unpackers.static_unpacker import detect_format

try:
    from .static_layer_lineage_adapter import select_static_layer_children
except ImportError:  # pragma: no cover - common directoryを直接sys.pathへ置く実行形態。
    from static_layer_lineage_adapter import select_static_layer_children

MAX_STATIC_LAYERS = 64
MAX_STATIC_DEPTH = 6
MAX_RECOVERED_LAYER_SIZE = 128 * 1024 * 1024
MAX_RECOVERED_TOTAL_SIZE = 256 * 1024 * 1024
MAX_STATIC_COMPRESSION_RATIO = 100.0
MAX_ARCHIVE_MEMBERS = 512
LINEAGE_SELECTED_PRIORITY = -2

ACTIONABLE_FORMATS = frozenset(
    {"pe", "elf", "macho", "script", "autoit-a3x", "java-class"}
)
CONTAINER_FORMATS = frozenset(
    {"7z", "zip", "cab", "rar", "xz", "asar", "ole", "apple-disk-image"}
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

    def public(self) -> dict[str, Any]:
        """バイト列を含まないレイヤーメタデータを返す。"""

        return {
            "name": self.name,
            "sha256": self.sha256,
            "size": len(self.data),
            "format": detect_format(self.data, self.name),
            "parent_sha256": self.parent_sha256,
            "depth": self.depth,
            "transform": self.transform,
        }


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
            or self.max_compression_ratio <= 0
        ):
            raise ValueError("max_compression_ratioは正数で指定してください")

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


def _artifact_analysis_priority(artifact_kind: str, blob: bytes) -> int:
    """magicと信頼済みtransform種別から静的解析queueの価値tierを返す。"""

    artifact_format = detect_format(blob, artifact_kind)
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
    intervals: list[tuple[int, int, int]] = [
        (-(candidate_count - 1), 0, candidate_count - 1)
    ]
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
    pending_layers: list[tuple[int, int, int, int, str]] = [
        (-1, 0, discovery_sequence, queue_revision, root.sha256)
    ]
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
        return tuple(
            (item.data, item.sha256, item.parent_sha256, item.depth)
            for item in reversed(ancestors)
        )

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
            (
                item
                for item in pending_best.values()
                if item.layer.parent_sha256 is not None
            ),
            key=pending_order_key,
        )
        available_slots = max(0, effective_policy.max_layers - len(layers))
        selected_digests = {
            item.layer.sha256 for item in pending_in_selection_order[:available_slots]
        }
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
            selected_count = sum(
                item.layer.sha256 in selected_digests for item in sibling_group
            )
            is_partially_selected = 0 < selected_count < len(sibling_group)
            if is_partially_selected:
                if group_key in stratified_sibling_group_sizes:
                    desired_order = sibling_group
                else:
                    stratified_sibling_group_sizes[group_key] = len(sibling_group)
                    desired_order = [
                        discovery_order[index]
                        for index in _stratified_sibling_indices(len(discovery_order))
                    ]
            else:
                desired_order = discovery_order
            sequence_slots = sorted(
                item.discovery_sequence for item in sibling_group
            )
            desired_sequences = {
                item.layer.sha256: sequence_slots[index]
                for index, item in enumerate(desired_order)
            }
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
        _priority, _negative_depth, _sequence, revision, digest = heapq.heappop(
            pending_layers
        )
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
            lineage_selection = select_static_layer_children(
                parent_data=layer.data,
                parent_sha256=layer.sha256,
                parent_parent_sha256=layer.parent_sha256,
                parent_depth=layer.depth,
                parent_ancestors=lineage_ancestors(layer),
                report=report,
                artifacts=artifacts,
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
            if lineage_selection.status == "complete_selected"
            and lineage_selection.omitted_commitment.complete
            else set()
        )
        candidates: list[tuple[int, int, str, bytes, str]] = []
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
            candidates.append(
                (
                    LINEAGE_SELECTED_PRIORITY
                    if digest in lineage_selected_digests
                    else _artifact_analysis_priority(artifact_kind, blob),
                    artifact_index,
                    artifact_kind,
                    blob,
                    digest,
                )
            )
        new_candidates: list[_NewStaticLayerCandidate] = []
        new_candidate_digests: set[str] = set()
        pending_topology_changed = False
        for priority, _artifact_index, artifact_kind, blob, digest in sorted(candidates):
            if digest in processed_digests:
                deduplicated_artifacts += 1
                continue
            existing = pending_best.get(digest)
            if existing is not None:
                deduplicated_artifacts += 1
                if priority >= existing.priority:
                    continue
                child = StaticLayer(
                    name=f"{layer.name}::{artifact_kind}",
                    data=blob,
                    sha256=digest,
                    parent_sha256=layer.sha256,
                    depth=layer.depth + 1,
                    transform=str(artifact_kind),
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
                name=f"{layer.name}::{artifact_kind}",
                data=blob,
                sha256=digest,
                parent_sha256=layer.sha256,
                depth=layer.depth + 1,
                transform=str(artifact_kind),
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
        event
        for _sequence, event in deferred_capacity_events
        if event["reason"] == "recovered_total_limit"
    )
    layer_count_limit_events.extend(
        (sequence, event)
        for sequence, event in deferred_capacity_events
        if event["reason"] == "layer_count_limit"
    )
    limit_events.extend(
        event for _sequence, event in sorted(layer_count_limit_events)
    )
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
            "name": "format_depth_pending_capacity_stratified_siblings_v3",
            "primary_order": "validated_lineage_then_format_priority_then_deeper_layer",
            "capacity_evaluation": "all_pending_layers_after_each_expansion",
            "under_capacity_same_tier_order": "discovery_order",
            "oversubscribed_same_parent_tier_order": (
                "endpoints_then_largest_interval_midpoint"
            ),
            "stratified_sibling_groups": len(stratified_sibling_group_sizes),
            "stratified_sibling_candidates": sum(
                stratified_sibling_group_sizes.values()
            ),
        },
        "executed_sample": False,
        "network_contacted": False,
        "recovered_content_exported": False,
    }
    return layers, public
