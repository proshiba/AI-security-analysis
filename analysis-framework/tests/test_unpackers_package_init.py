"""unpackersパッケージ初期化の軽量性と互換APIを検証する。"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _run_fresh_interpreter(source: str) -> subprocess.CompletedProcess[str]:
    """現在のpytest processのmodule cacheに依存せずimport状態を確認する。"""

    return subprocess.run(
        [sys.executable, "-c", source],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )


def test_managed_metadata_import_does_not_load_static_unpacker() -> None:
    """個別metadata readerから統合unpacker全体へ副作用的に展開しない。"""

    completed = _run_fresh_interpreter(
        "import sys; import unpackers.managed_metadata; assert 'unpackers.static_unpacker' not in sys.modules"
    )

    assert completed.returncode == 0, completed.stderr


def test_package_level_profiled_transform_api_remains_compatible() -> None:
    """従来のパッケージ直下APIは実装関数そのものを返す。"""

    completed = _run_fresh_interpreter(
        "import sys; from unpackers import recover_profiled_transforms as public; "
        "from unpackers.profiled_transform import recover_profiled_transforms as direct; "
        "assert public is direct; assert 'unpackers.static_unpacker' not in sys.modules"
    )

    assert completed.returncode == 0, completed.stderr
