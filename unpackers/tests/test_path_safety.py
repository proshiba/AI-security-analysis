"""信頼できないmember pathの共通検証試験。"""

from __future__ import annotations

import pytest

from unpackers.path_safety import safe_member_name


def test_safe_member_name_normalizes_separators() -> None:
    """相対memberを受理しWindows separatorを正規化する。"""
    assert safe_member_name("a\\b.bin") == "a/b.bin"


@pytest.mark.parametrize(
    "value",
    ["", "/root", "C:\\payload.exe", "../payload", "a/./b", "a/\x01secret"],
)
def test_safe_member_name_rejects_unsafe_forms(value: str) -> None:
    """空、絶対、drive、traversal、制御文字を固定errorで拒否する。"""
    with pytest.raises(ValueError, match="^unsafe_archive_member_path$") as captured:
        safe_member_name(value, "fixture")
    if value:
        assert value not in str(captured.value)
