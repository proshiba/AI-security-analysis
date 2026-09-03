"""analyze_sampleの外部静的tool pathとidentity安全境界を検証する。"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import sys

import pytest


COMMON = Path(__file__).resolve().parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import analyze_sample as analyzer  # noqa: E402


def test_static_tool_identity_uses_name_size_and_sha256_only(tmp_path: Path) -> None:
    """契約identityへ絶対pathやtool内容を公開しない。"""

    tool = tmp_path / ("upx.exe" if os.name == "nt" else "upx")
    payload = b"pinned synthetic static tool"
    tool.write_bytes(payload)

    normalized = analyzer._normalize_tool_path(tool, "UPX")
    identity = analyzer._tool_identity(normalized)

    assert normalized == tool.resolve()
    assert identity == {
        "name": tool.name,
        "size": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }
    assert str(tool.parent) not in repr(identity)


def test_static_tool_path_rejects_hardlink(tmp_path: Path) -> None:
    """operator tool binaryが複数pathで変更可能なhardlinkを拒否する。"""

    tool = tmp_path / "upx.exe"
    alias = tmp_path / "upx-alias.exe"
    tool.write_bytes(b"fixture")
    try:
        os.link(tool, alias)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"このfilesystemではhardlinkを作成できません: {exc}")

    with pytest.raises(ValueError, match="単一link"):
        analyzer._normalize_tool_path(tool, "UPX")


def test_static_tool_path_rejects_reparse_or_symlink(tmp_path: Path) -> None:
    """tool pathのsymlink／reparse経由を拒否する。"""

    tool = tmp_path / "real-upx.exe"
    alias = tmp_path / "linked-upx.exe"
    tool.write_bytes(b"fixture")
    try:
        os.symlink(tool, alias)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"この環境ではsymlinkを作成できません: {exc}")

    with pytest.raises((OSError, RuntimeError, ValueError)):
        analyzer._normalize_tool_path(alias, "UPX")


def test_static_tool_path_rejects_oversized_binary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """tool binaryにも明示的なsize上限を適用する。"""

    tool = tmp_path / "upx.exe"
    tool.write_bytes(b"oversized")
    monkeypatch.setattr(analyzer, "MAX_STATIC_TOOL_BINARY_BYTES", 4)

    with pytest.raises(ValueError, match="通常file"):
        analyzer._normalize_tool_path(tool, "UPX")


def test_batch_summary_preserves_sealed_static_tool_identity(tmp_path: Path) -> None:
    """長時間jobのsummaryがtool名だけへ縮退せずroot契約と一致する。"""

    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"static assessment fixture")
    tool = tmp_path / "sevenzip.exe"
    payload = b"synthetic pinned sevenzip"
    tool.write_bytes(payload)

    summary = analyzer.run_batch(
        [sample],
        tmp_path / "output",
        registry=analyzer.DEFAULT_REGISTRY,
        archive_mode="raw",
        assessment_only=True,
        sevenzip=tool,
    )

    expected = {
        "upx": None,
        "sevenzip": {
            "name": tool.name,
            "size": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
        },
        "diec": None,
    }
    assert summary["analysis_contract"]["settings"]["static_tools"] == expected
    assert summary["settings"]["static_tools"] == expected
