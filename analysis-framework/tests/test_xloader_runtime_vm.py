"""XLoaderランタイムVM静的追跡器のテスト。"""

from __future__ import annotations

import importlib.util
import struct
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = (
    ROOT
    / "analysis-framework"
    / "malware"
    / "formbook_loader"
    / "runtime_vm.py"
)
SPEC = importlib.util.spec_from_file_location("xloader_runtime_vm", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
RUNTIME_VM = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = RUNTIME_VM
SPEC.loader.exec_module(RUNTIME_VM)


def _synthetic_image() -> tuple[bytes, int, list[int]]:
    image_base = 0x400000
    initializer_offset = 0x20
    dispatcher_offset = 0x300
    selector_disp = -0x3EF
    selectors = [0x97, 0x9D, 0x89, 0xD0, 0x98, 7, 0xA9, 0xA2, 9, 0xD7]
    code = bytearray(b"\x90" * 0x500)
    body = bytearray(b"\x55\x8b\xec\x81\xec\x50\x06\x00\x00")
    body += b"\x68\x8d\x04\x00\x00"
    for index, selector in enumerate(selectors):
        body += b"\xc7\x85" + struct.pack("<iI", selector_disp, selector)
        if index == 7:
            body += b"\xc7\x85" + struct.pack("<iI", -0x4A0, 9)
        call_address = image_base + initializer_offset + len(body)
        target = image_base + dispatcher_offset
        body += b"\xe8" + struct.pack("<i", target - (call_address + 5))
    body += b"\xc3"
    code[initializer_offset : initializer_offset + len(body)] = body
    code[dispatcher_offset : dispatcher_offset + 4] = b"\x55\x8b\xec\xc3"
    return bytes(code), image_base, selectors


def test_runtime_vm_finds_dispatcher_and_selector_sequence() -> None:
    image, image_base, selectors = _synthetic_image()

    profile = RUNTIME_VM.find_runtime_vm(image, image_base)
    report = RUNTIME_VM.build_report(image, profile)

    assert profile.initializer_address == image_base + 0x20
    assert profile.dispatcher_address == image_base + 0x300
    assert [call.selector for call in profile.calls] == selectors
    assert report["unique_selector_count"] == len(set(selectors))
    assert report["raw_marker_retained"] is False
    assert report["raw_key_material_retained"] is False


def test_selector_shape_comparison_ignores_raw_values() -> None:
    image, image_base, _ = _synthetic_image()
    reference = RUNTIME_VM.find_runtime_vm(image, image_base)
    remapped = tuple(
        RUNTIME_VM.SelectorCall(call.call_address, call.selector ^ 0x5A)
        for call in reference.calls
    )
    candidate = RUNTIME_VM.RuntimeVmProfile(
        **{
            **reference.__dict__,
            "calls": remapped,
        }
    )

    comparison = RUNTIME_VM.compare_profiles(reference, candidate)

    assert comparison["normalized_shape_equal"] is True
    assert comparison["normalized_lcs_ratio"] == 1.0
    assert comparison["selector_values_compared"] is False


def test_runtime_vm_rejects_unrelated_x86() -> None:
    with pytest.raises(RUNTIME_VM.RuntimeVmError):
        RUNTIME_VM.find_runtime_vm(b"\x55\x8b\xec\x33\xc0\xc3")
