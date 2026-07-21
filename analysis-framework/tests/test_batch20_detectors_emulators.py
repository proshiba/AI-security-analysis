"""第20バッチのdetector/emulatorが非通信で動くことを検証する。"""

from __future__ import annotations

import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MALWARE = ROOT / "analysis-framework" / "malware"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


NANO_DETECTOR = _load("batch20_nano_detector", MALWARE / "nanocore" / "network_detector.py")
NANO_EMULATOR = _load("batch20_nano_emulator", MALWARE / "nanocore" / "emulator.py")
YUANBAO_DETECTOR = _load(
    "batch20_yuanbao_detector",
    MALWARE / "valleyrat" / "campaigns" / "yuanbao_sideload" / "network_detector.py",
)
YUANBAO_EMULATOR = _load(
    "batch20_yuanbao_emulator",
    MALWARE / "valleyrat" / "campaigns" / "yuanbao_sideload" / "emulator.py",
)
OFFLOADER_DETECTOR = _load(
    "batch20_offloader_detector", MALWARE / "dotnet_resource_loader" / "offloader_detector.py"
)
OFFLOADER_EMULATOR = _load(
    "batch20_offloader_emulator", MALWARE / "dotnet_resource_loader" / "offloader_emulator.py"
)


def test_nanocore_detector_requires_endpoint_and_process_correlation() -> None:
    config = {"c2": [{"host": "controller.example", "port": 443}]}
    events = [
        {"host": "controller.example", "port": "invalid", "nanocore_process_or_hash_correlation": True},
        {"host": "controller.example", "port": 443, "nanocore_process_or_hash_correlation": False},
    ]
    assert NANO_DETECTOR.detect(events, config)["matched"] is False

    events.append(
        {"host": "CONTROLLER.EXAMPLE", "port": "443", "nanocore_process_or_hash_correlation": True}
    )
    result = NANO_DETECTOR.detect(events, config)
    assert result["matched"] is True
    assert result["c2_confirmed"] is False
    assert result["network_contacted"] is False


def test_nanocore_emulator_generates_no_packets() -> None:
    result = NANO_EMULATOR.emulate({"c2": [{"host": "controller.example", "port": 443}]})
    assert result["targets"] == [{"host": "controller.example", "port": 443}]
    assert result["packets_generated"] == 0
    assert result["network_contacted"] is False
    assert result["commands_executed"] is False


def test_yuanbao_detector_requires_all_correlated_host_stages() -> None:
    events = [
        {"stage": stage, "yuanbao_chain_hash_or_path_correlation": True}
        for stage in ("sfx_extract", "inno_extract", "dll_sideload", "png_read")
    ]
    result = YUANBAO_DETECTOR.detect(events)
    assert result["matched"] is True
    assert result["c2_confirmed"] is False
    emulator = YUANBAO_EMULATOR.emulate()
    assert emulator["files_written"] is False
    assert emulator["processes_started"] is False
    assert emulator["network_contacted"] is False


def test_offloader_detector_and_emulator_are_offline() -> None:
    events = [
        {"stage": stage, "offloader_process_or_hash_correlation": True}
        for stage in ("resource_zip", "temp_extract", "child_start")
    ]
    result = OFFLOADER_DETECTOR.detect(events)
    assert result["matched"] is True
    assert result["c2_confirmed"] is False
    emulator = OFFLOADER_EMULATOR.emulate({"members": [{"name": "child.exe"}]})
    assert emulator["member_count"] == 1
    assert emulator["files_written"] is False
    assert emulator["processes_started"] is False
    assert emulator["network_contacted"] is False
