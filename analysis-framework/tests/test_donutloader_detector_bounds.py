"""Donut detectorの候補数と復号memory境界を検証する。"""

from __future__ import annotations

import importlib.util
import struct
import sys
from pathlib import Path


FRAMEWORK = Path(__file__).parents[1]
REPOSITORY = FRAMEWORK.parent
for import_root in (str(FRAMEWORK), str(REPOSITORY)):
    if import_root not in sys.path:
        sys.path.insert(0, import_root)


def _load_detector_module():
    path = FRAMEWORK / "malware" / "donutloader" / "detect.py"
    spec = importlib.util.spec_from_file_location("bounded_donutloader_detector", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _invalid_candidate(index: int) -> bytes:
    """strict外形だけを持ち、復号後instance検証には失敗する候補を作る。"""

    instance = bytearray(0x300)
    instance[0] = index
    return b"\xe8" + struct.pack("<I", len(instance)) + instance + b"YU\x48\x89\xe5"


def test_candidate_scan_stops_at_limit_plus_one(monkeypatch) -> None:
    """crafted多数候補でも17件目で探索を止め、16件超を復号しない。"""

    detector = _load_detector_module()
    decrypt_calls = 0

    def reject_instance(_shellcode: bytes):
        nonlocal decrypt_calls
        decrypt_calls += 1
        raise ValueError("synthetic invalid instance")

    monkeypatch.setattr(detector, "decrypt_instance", reject_instance)
    sample = b"".join(_invalid_candidate(index) for index in range(18))
    result = detector.detect(sample, Path("many-candidates.bin"))

    assert result["matched"] is False
    assert result["campaigns"] == []
    assert result["observations"]["call_over_instance_candidates"] == 17
    assert result["observations"]["candidate_limit_exceeded"] is True
    assert decrypt_calls == 16
