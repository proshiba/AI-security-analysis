#!/usr/bin/env python3
"""二段の文字列配列を持つ reviewed JavaScript を非実行でデオブファスケートする。"""

from __future__ import annotations

import re

try:
    from unpackers import _javascript_two_array_impl as _impl
except ModuleNotFoundError:  # ファイルを直接起動した場合
    import _javascript_two_array_impl as _impl  # type: ignore[no-redef]


REVIEWED_SHA256 = _impl.REVIEWED_SHA256
_original_deobfuscate = _impl.deobfuscate
_original_solve_rotation = _impl._core._solve_rotation
_source_text = ""


def _profiled_solve_rotation(
    values: list[str],
    expression: str,
    target: float,
    offset: int,
    definitions: dict[str, tuple[list[str], str]],
    aliases: tuple[str, ...],
) -> tuple[list[str], int]:
    """第二IIFEは直前のtry式を使い、先行する別IIFEとの誤結合を防ぐ。"""
    if offset == 0x14C:
        iife_end = _source_text.index("}(_0x38a0,0x47cf1));")
        try_start = _source_text.rfind("try{var", 0, iife_end)
        match = re.search(
            r"try\{var\s+\w+=(.*?);if\(\w+===\w+\)break",
            _source_text[try_start:iife_end],
            re.S,
        )
        if not match:
            raise ValueError("第二rotation直前のtry式がありません")
        expression = match.group(1)
    return _original_solve_rotation(
        values, expression, target, offset, definitions, aliases
    )


def deobfuscate(data: bytes) -> tuple[dict[str, object], bytes]:
    global _source_text
    _source_text = data.decode("utf-8")
    return _original_deobfuscate(data)


_impl._core._solve_rotation = _profiled_solve_rotation
_impl._core.deobfuscate = deobfuscate
main = _impl.main


if __name__ == "__main__":
    raise SystemExit(main())
