"""Tests for targeted Electron NSIS recovery helpers."""

from __future__ import annotations

import pytest

from unpackers.electron_nsis_unpacker import (
    safe_archive_member,
    select_asar_members,
    select_nested_7z_members,
)


def test_selects_nested_archive_and_canonical_asar() -> None:
    """Select only relevant nested containers in deterministic priority order."""
    assert select_nested_7z_members(["$PLUGINSDIR\\app-64.7z", "System.dll"]) == [
        "$PLUGINSDIR\\app-64.7z"
    ]
    assert select_asar_members(["other.asar", "resources\\app.asar"]) == [
        "resources\\app.asar",
        "other.asar",
    ]


def test_rejects_unsafe_archive_member() -> None:
    """Reject traversal and absolute member paths before invoking 7-Zip."""
    with pytest.raises(ValueError):
        safe_archive_member("../payload.7z")
    with pytest.raises(ValueError):
        safe_archive_member("C:\\payload.asar")
