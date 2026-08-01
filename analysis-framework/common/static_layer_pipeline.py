#!/usr/bin/env python3
"""静的unpackerの出力を上限付き認証済みレイヤーDAGへ変換する。"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
from typing import Any, Callable

from unpackers.static_unpacker import detect_format


MAX_STATIC_LAYERS = 32
MAX_STATIC_DEPTH = 6
MAX_RECOVERED_LAYER_SIZE = 64 * 1024 * 1024
MAX_RECOVERED_TOTAL_SIZE = 256 * 1024 * 1024
MAX_STATIC_COMPRESSION_RATIO = 100.0


@dataclass(frozen=True)
class InputUnit:
    """解析対象のインメモリ検体と公開可能な入力メタデータ。"""

    source_name: str
    data: bytes
    input_kind: str
    outer_sha256: str
    outer_size: int
    member_name: str | None = None


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
class StaticLayerPolicy:
    """再帰展開の件数・深さ・容量・圧縮率上限をまとめた共有ポリシー。"""

    max_layers: int = MAX_STATIC_LAYERS
    max_depth: int = MAX_STATIC_DEPTH
    max_layer_size: int = MAX_RECOVERED_LAYER_SIZE
    max_total_size: int = MAX_RECOVERED_TOTAL_SIZE
    max_compression_ratio: float = MAX_STATIC_COMPRESSION_RATIO

    def __post_init__(self) -> None:
        for field, value in (
            ("max_layers", self.max_layers),
            ("max_depth", self.max_depth),
            ("max_layer_size", self.max_layer_size),
            ("max_total_size", self.max_total_size),
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
        }


Unpacker = Callable[..., tuple[dict[str, Any], list[tuple[str, bytes]]]]
Sanitizer = Callable[[Any], Any]


def _identity(value: Any) -> Any:
    return value


def recover_static_layers(
    unit: InputUnit,
    *,
    unpacker: Unpacker | None = None,
    sanitizer: Sanitizer = _identity,
    policy: StaticLayerPolicy | None = None,
    upx: Path | None = None,
    sevenzip: Path | None = None,
    diec: Path | None = None,
    force_container_probe: bool = False,
    archive_password: str = "infected",
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
    seen = {root.sha256}
    steps: list[dict[str, Any]] = []
    recovered_total = 0
    cursor = 0
    limit_events: list[dict[str, Any]] = []
    while cursor < len(layers):
        layer = layers[cursor]
        cursor += 1
        if layer.depth >= effective_policy.max_depth:
            steps.append(
                {
                    "input_layer": layer.public(),
                    "status": "skipped_depth_limit",
                }
            )
            continue
        remaining_total = effective_policy.max_total_size - recovered_total
        remaining_layers = effective_policy.max_layers - len(layers)
        if remaining_total <= 0 or remaining_layers <= 0:
            reason = "recovered_total_limit" if remaining_total <= 0 else "layer_count_limit"
            limit_events.append(
                {
                    "parent_sha256": layer.sha256,
                    "reason": reason,
                }
            )
            steps.append(
                {
                    "input_layer": layer.public(),
                    "status": f"skipped_{reason}",
                }
            )
            continue
        try:
            report, artifacts = unpacker(
                layer.data,
                layer.name,
                upx=upx,
                sevenzip=sevenzip,
                diec=diec,
                force_container_probe=force_container_probe,
                archive_password=archive_password,
                max_archive_members=remaining_layers,
                max_archive_member_size=min(
                    effective_policy.max_layer_size,
                    remaining_total,
                ),
                max_archive_total_size=remaining_total,
                max_archive_compression_ratio=effective_policy.max_compression_ratio,
            )
            if not isinstance(report, dict) or not isinstance(artifacts, list):
                raise TypeError("unpackerは(dict, list)を返す必要があります")
            step = {
                "input_layer": layer.public(),
                "status": "succeeded",
                "report": sanitizer(report),
                "accepted_children": [],
            }
        except Exception as exc:
            steps.append(
                {
                    "input_layer": layer.public(),
                    "status": "failed",
                    "error": sanitizer(f"{type(exc).__name__}: {exc}"),
                }
            )
            continue
        for artifact in artifacts:
            if not isinstance(artifact, tuple) or len(artifact) != 2:
                limit_events.append(
                    {
                        "parent_sha256": layer.sha256,
                        "reason": "malformed_artifact_rejected",
                    }
                )
                continue
            artifact_kind, blob = artifact
            if not isinstance(blob, bytes):
                limit_events.append(
                    {
                        "parent_sha256": layer.sha256,
                        "kind": str(artifact_kind),
                        "reason": "non_bytes_artifact_rejected",
                    }
                )
                continue
            digest = hashlib.sha256(blob).hexdigest()
            if digest in seen:
                continue
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
            if recovered_total + len(blob) > effective_policy.max_total_size:
                limit_events.append(
                    {
                        "parent_sha256": layer.sha256,
                        "kind": str(artifact_kind),
                        "sha256": digest,
                        "size": len(blob),
                        "reason": "recovered_total_limit",
                    }
                )
                continue
            if len(layers) >= effective_policy.max_layers:
                limit_events.append(
                    {
                        "parent_sha256": layer.sha256,
                        "kind": str(artifact_kind),
                        "sha256": digest,
                        "size": len(blob),
                        "reason": "layer_count_limit",
                    }
                )
                continue
            child = StaticLayer(
                name=f"{layer.name}::{artifact_kind}",
                data=blob,
                sha256=digest,
                parent_sha256=layer.sha256,
                depth=layer.depth + 1,
                transform=str(artifact_kind),
            )
            layers.append(child)
            seen.add(digest)
            recovered_total += len(blob)
            step["accepted_children"].append(child.public())
        steps.append(step)
    public = {
        "schema_version": 1,
        "limits": effective_policy.public(),
        "counts": {
            "layers": len(layers),
            "recovered_layers": len(layers) - 1,
            "recovered_bytes": recovered_total,
            "limit_events": len(limit_events),
        },
        "layers": [item.public() for item in layers],
        "steps": steps,
        "limit_events": limit_events,
        "executed_sample": False,
        "network_contacted": False,
        "recovered_content_exported": False,
    }
    return layers, public
