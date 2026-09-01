"""Loopback-only PureRAT/PureHVNC protocol laboratory."""

from __future__ import annotations

from typing import Any

__all__ = [
    "LoopbackCollector",
    "ObservationPolicy",
    "observe_connected_stream",
    "pack_native_frame",
    "parse_native_frame",
]


def __getattr__(name: str) -> Any:
    """利用する機能だけを読み込み、observerへ静的解析依存を要求しない。"""

    if name in {"LoopbackCollector", "pack_native_frame", "parse_native_frame"}:
        from . import lab

        return getattr(lab, name)
    if name in {"ObservationPolicy", "observe_connected_stream"}:
        from . import observer

        return getattr(observer, name)
    raise AttributeError(name)
