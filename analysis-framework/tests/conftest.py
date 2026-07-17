"""Windowsの深いcanonical pathでもMAX_PATHを超えないpytest fixture。"""

from __future__ import annotations

from pathlib import Path
import shutil
import tempfile

import pytest


@pytest.fixture
def short_tmp() -> Path:
    """短いOS一時rootを作成し、test後にそのrootだけを削除する。"""

    base = Path("C:/tmp") if Path("C:/").exists() else Path(tempfile.gettempdir())
    base.mkdir(parents=True, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix="asa-", dir=base))
    try:
        yield root
    finally:
        resolved = root.resolve()
        if resolved.parent != base.resolve() or not resolved.name.startswith("asa-"):
            raise RuntimeError(f"refusing to remove unexpected test path: {resolved}")
        shutil.rmtree(resolved)
