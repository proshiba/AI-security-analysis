"""AgentTesla JS/LuaJIT/Donut一括解析器の境界を検証する。"""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
FAMILY = ROOT / "malware" / "agenttesla"
MODULE = FAMILY / "agenttesla_luajit_chain.py"


def _load():
    if str(FAMILY) not in sys.path:
        sys.path.insert(0, str(FAMILY))
    spec = importlib.util.spec_from_file_location("agenttesla_luajit_chain", MODULE)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_unrelated_data_is_not_applicable() -> None:
    module = _load()
    report = module.analyze(b"ordinary unrelated input")
    assert report["status"] == "not_applicable"
    assert report["payloads"] == []
    assert report["safety"]["sample_executed"] is False
