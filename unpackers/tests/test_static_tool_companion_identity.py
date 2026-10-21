"""7-Zip同伴DLLを含む静的tool identityを検証する。"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from unpackers import static_unpacker


@pytest.mark.skipif(os.name != "nt", reason="Windows版7-Zipの同伴DLL契約です")
def test_sevenzip_runtime_identity_changes_with_companion_dll(tmp_path: Path) -> None:
    """実行前後のidentity比較が7z.dllの置換も検知する。"""

    executable = tmp_path / "7z.exe"
    companion = tmp_path / "7z.dll"
    executable.write_bytes(b"synthetic sevenzip executable")
    companion.write_bytes(b"synthetic sevenzip companion")

    first = static_unpacker._static_tool_identity(executable)
    companion.write_bytes(b"changed synthetic sevenzip companion")
    second = static_unpacker._static_tool_identity(executable)

    assert first["component_names"] == ["7z.exe", "7z.dll"]
    assert first["size"] == len(b"synthetic sevenzip executable") + len(
        b"synthetic sevenzip companion"
    )
    assert first["sha256"] != second["sha256"]
