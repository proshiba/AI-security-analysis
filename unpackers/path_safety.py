"""Shared validation for untrusted archive and container member paths."""

from __future__ import annotations

import re


def safe_member_name(name: str, kind: str = "archive") -> str:
    """Normalize a member name and reject traversal, absolute, drive, or empty paths."""
    normalized = name.replace("\\", "/")
    if (
        not normalized
        or normalized.startswith("/")
        or re.match(r"^[A-Za-z]:", normalized)
        or any(part in {"", ".", ".."} for part in normalized.split("/"))
    ):
        raise ValueError(f"unsafe {kind} member: {name}")
    return normalized
