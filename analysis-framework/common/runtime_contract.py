#!/usr/bin/env python3
"""一括静的解析で常に必要なPython runtime依存を一元管理する。"""

from __future__ import annotations

import importlib
import json
from collections.abc import Callable
from types import ModuleType


REQUIRED_RUNTIME_MODULES = (
    "cabarchive",
    "capstone",
    "Cryptodome",
    "cryptography",
    "dncil",
    "dnfile",
    "olefile",
    "pefile",
    "pydantic",
    "pyzipper",
    "yaml",
    "yara",
)


def import_required_runtime_modules(
    *,
    importer: Callable[[str], ModuleType] = importlib.import_module,
) -> tuple[str, ...]:
    """固定依存をすべてimportし、成功したmodule名を決定的順序で返す。"""

    for module_name in REQUIRED_RUNTIME_MODULES:
        importer(module_name)
    return REQUIRED_RUNTIME_MODULES


def isolated_import_probe_source() -> str:
    """`python -I -c`へ渡せる固定依存import probeを返す。"""

    module_names = json.dumps(REQUIRED_RUNTIME_MODULES, ensure_ascii=True)
    return (
        "import importlib; "
        f"[importlib.import_module(name) for name in {module_names}]"
    )
