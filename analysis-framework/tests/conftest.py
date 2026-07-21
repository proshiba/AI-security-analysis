"""Windowsの深いcanonical pathでもMAX_PATHを超えないpytest fixture。"""

from __future__ import annotations

from pathlib import Path
import shutil
import tempfile

import pytest


@pytest.fixture
def short_tmp() -> Path:
    """短いOS一時rootを作成し、test後にそのrootだけを削除する。"""

    if Path("C:/").exists():
        # 共有の C:\\tmp 直下は、残留物やACLの影響で名前生成が停止する場合が
        # あるため、短いユーザー専用ディレクトリへテストを隔離する。
        base = Path.home() / ".work"
    else:
        base = Path(tempfile.gettempdir()) / "ai-security-analysis-pytest"
    base.mkdir(parents=True, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix="asa-", dir=base))
    try:
        yield root
    finally:
        resolved = root.resolve()
        if resolved.parent != base.resolve() or not resolved.name.startswith("asa-"):
            raise RuntimeError(f"refusing to remove unexpected test path: {resolved}")
        shutil.rmtree(resolved)
