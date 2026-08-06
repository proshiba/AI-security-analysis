"""GuLoader内部payload二段RC4復号器のテスト。"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = (
    ROOT / "analysis-framework" / "malware" / "guloader" / "inner_payload.py"
)
SPEC = importlib.util.spec_from_file_location("guloader_inner_payload", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
INNER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = INNER
SPEC.loader.exec_module(INNER)


def _fixture():
    first = INNER.Rc4Stage((0x10203040, 0x50607080), (0x11111111,))
    second = INNER.Rc4Stage((0x90A0B0C0, 0xD0E0F000), (0x22222222,))
    plaintext = b"01234567ABCDEFGHijklmnopTAILTAIL"
    first_key = INNER.derive_dword_key(first)
    second_key = INNER.derive_dword_key(second)
    stage1 = bytearray(plaintext)
    for offset in range(0, 24, 8):
        stage1[offset : offset + 8] = INNER.rc4(stage1[offset : offset + 8], second_key)
    encrypted = INNER.rc4(bytes(stage1), first_key)
    image = b"prefix!!" + encrypted + b"suffix"
    profile = INNER.InnerPayloadProfile(
        region_offset=8,
        region_size=len(encrypted),
        first_stage=first,
        second_stage=second,
        second_stage_chunk_size=8,
        second_stage_chunk_count=3,
        expected_input_sha256=INNER.sha256_bytes(image),
        expected_output_sha256=INNER.sha256_bytes(plaintext),
    )
    return image, profile, plaintext


def test_two_stage_recovery_preserves_untransformed_tail() -> None:
    image, profile, plaintext = _fixture()

    recovered, report = INNER.recover_inner_payload(image, profile)

    assert recovered == plaintext
    assert report["status"] == "exact_match"
    assert report["second_stage"]["preserved_tail_size"] == 8
    assert report["safety"]["sample_executed"] is False


def test_expected_input_hash_mismatch_fails_closed() -> None:
    image, profile, _ = _fixture()
    changed = b"X" + image[1:]

    with pytest.raises(INNER.InnerPayloadError, match="入力SHA-256"):
        INNER.recover_inner_payload(changed, profile)


def test_chunk_total_cannot_exceed_region() -> None:
    with pytest.raises(INNER.InnerPayloadError, match="chunk合計"):
        INNER.profile_from_mapping(
            {
                "region_offset": 0,
                "region_size": 8,
                "first_stage": {"base_key_dwords": [1]},
                "second_stage": {"base_key_dwords": [2]},
                "second_stage_chunk_size": 8,
                "second_stage_chunk_count": 2,
            }
        )
