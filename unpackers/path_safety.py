"""信頼できないarchive/container member pathの共通検証。"""

from __future__ import annotations

import re


def safe_member_name(name: str, kind: str = "archive") -> str:
    """separatorを正規化し、危険な相対・絶対pathと制御文字を拒否する。"""
    normalized = name.replace("\\", "/")
    if (
        not normalized
        or normalized.startswith("/")
        or re.match(r"^[A-Za-z]:", normalized)
        or any(part in {"", ".", ".."} for part in normalized.split("/"))
        or any(ord(character) < 32 or ord(character) == 127 for character in normalized)
    ):
        # nameとkindはいずれもcaller由来になり得る。例外は公開reportへ到達しても
        # untrusted member名を含まない固定codeだけにする。
        raise ValueError("unsafe_archive_member_path")
    return normalized
