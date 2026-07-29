"""通常文字と数値エスケープが混在するLua置換表を検証する。"""

from __future__ import annotations

from unpackers import luajit_polyrot_structural


def test_decodes_mixed_lua_string_forms() -> None:
    body = '{{"\\033","-","\\091","\\093","\\123","\\125","\\059","\\058","\\063","\\044"}}'
    assert luajit_polyrot_structural._row_values(body) == [
        ["!", "-", "[", "]", "{", "}", ";", ":", "?", ","]
    ]
