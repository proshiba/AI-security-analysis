"""Tests for bounded Donut DLL-list validation."""

from unpackers.donut_unpacker import _valid_dll_names


def test_known_dll_lists_and_single_explicit_name() -> None:
    """Accept known multi-basename lists and one explicit DLL filename."""
    assert _valid_dll_names("ole32;oleaut32;wininet;mscoree;shell32")
    assert _valid_dll_names("ole32.dll")


def test_unknown_or_ambiguous_single_name_is_rejected() -> None:
    """Reject unknown modules and an ambiguous single basename."""
    assert not _valid_dll_names("unknown.dll")
    assert not _valid_dll_names("ole32")
