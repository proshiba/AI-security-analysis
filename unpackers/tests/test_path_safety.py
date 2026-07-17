"""Tests for shared untrusted member-path validation."""

from __future__ import annotations

import pytest

from unpackers.path_safety import safe_member_name


def test_safe_member_name_normalizes_separators() -> None:
    """Accept relative members and normalize Windows separators."""
    assert safe_member_name("a\\b.bin") == "a/b.bin"


@pytest.mark.parametrize("value", ["", "/root", "C:\\payload.exe", "../payload", "a/./b"])
def test_safe_member_name_rejects_unsafe_forms(value: str) -> None:
    """Reject empty, absolute, drive-qualified, and traversal member names."""
    with pytest.raises(ValueError, match="unsafe fixture member"):
        safe_member_name(value, "fixture")
