"""XLoader call target近傍marker fallbackを検証する。"""

from __future__ import annotations

import importlib
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TESTS = ROOT / "analysis-framework" / "tests"
sys.path.insert(0, str(TESTS))

fixture = importlib.import_module("test_xloader_protected_functions")

PROTECTED = fixture.PROTECTED


def test_unique_target_marker_candidate_recovers_without_direct_caller() -> None:
    original, profile, body, wrapper_start, mix = fixture._synthetic_image()
    image = bytearray(original)
    wrapper = PROTECTED.find_wrappers(bytes(image), profile)[0]

    # wrapper内で復号routineの次にある保護対象CALLを、markerの10 byte手前へ向ける。
    protected_call = image.find(b"\xe8", wrapper.decrypt_call + 5, wrapper_start + 0x100)
    assert protected_call > 0
    target = 0x500 - 10
    image[protected_call + 1 : protected_call + 5] = struct.pack(
        "<i", target - (protected_call + 5)
    )

    # 元のdirect callerを除去し、到達関係を持たない局所即値だけを残す。
    image[0x300:0x340] = b"\x90" * 0x40
    candidate_holder = b"\x55\x8b\xec\xc7\x45\xf0" + struct.pack("<I", mix) + b"\xc3"
    image[0x340 : 0x340 + len(candidate_holder)] = candidate_holder

    patched, report = PROTECTED.recover_protected_functions(
        bytes(image),
        profile,
        allow_constant_fallback=False,
        allow_target_marker_fallback=True,
    )

    assert body in patched
    assert report["recovered_count"] == 1
    assert report["target_marker_recovered_count"] == 1
    assert report["functions"][0]["method"] == "target_marker_unique_immediate"
