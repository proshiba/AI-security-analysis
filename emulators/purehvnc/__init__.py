"""Loopback-only PureRAT/PureHVNC protocol laboratory."""

from .lab import LoopbackCollector, pack_native_frame, parse_native_frame

__all__ = ["LoopbackCollector", "pack_native_frame", "parse_native_frame"]
