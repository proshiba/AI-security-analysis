"""XLoader C2候補の静的多層復号テスト。"""

from __future__ import annotations

import base64
import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
NATIVE_PATH = (
    ROOT
    / "analysis-framework"
    / "malware"
    / "formbook_loader"
    / "native_xloader.py"
)
C2_PATH = (
    ROOT
    / "analysis-framework"
    / "malware"
    / "formbook_loader"
    / "xloader_c2.py"
)

NATIVE_SPEC = importlib.util.spec_from_file_location("native_xloader", NATIVE_PATH)
assert NATIVE_SPEC is not None and NATIVE_SPEC.loader is not None
NATIVE = importlib.util.module_from_spec(NATIVE_SPEC)
sys.modules[NATIVE_SPEC.name] = NATIVE
NATIVE_SPEC.loader.exec_module(NATIVE)

C2_SPEC = importlib.util.spec_from_file_location("xloader_c2", C2_PATH)
assert C2_SPEC is not None and C2_SPEC.loader is not None
C2 = importlib.util.module_from_spec(C2_SPEC)
sys.modules[C2_SPEC.name] = C2
C2_SPEC.loader.exec_module(C2)


def test_layered_c2_round_trip_and_sanitized_report() -> None:
    first_key = b"first-synthetic-key"
    second_key = b"second-synthetic-key"
    plaintext = b"control.example.test:8443\x00"
    first_layer = NATIVE.encrypt_rc4_sub(plaintext, second_key)
    encoded = base64.b64encode(NATIVE.encrypt_rc4_sub(first_layer, first_key))

    result = C2.decrypt_layered_candidate(encoded, first_key, second_key)
    report = C2.summarize_candidate(encoded, result)

    assert result.plaintext == plaintext
    assert report["endpoint_candidate"] is True
    assert report["endpoint_type"] == "domain"
    assert report["plaintext_retained"] is False
    assert report["version_model"] == "unconfirmed"
    assert report["real_c2_static_decidable"] is False
    assert "control.example" not in str(report)


def test_layered_c2_accepts_same_key_for_both_layers() -> None:
    key = b"shared-synthetic-key"
    plaintext = b"198.51.100.24:443\x00"
    first_layer = NATIVE.encrypt_rc4_sub(plaintext, key)
    encoded = base64.b64encode(NATIVE.encrypt_rc4_sub(first_layer, key))

    result = C2.decrypt_layered_candidate(encoded, key, key)
    report = C2.summarize_candidate(encoded, result)

    assert result.plaintext == plaintext
    assert report["endpoint_candidate"] is True
    assert "synthetic-key" not in str(report)


def test_invalid_base64_is_rejected() -> None:
    with pytest.raises(C2.XLoaderC2Error):
        C2.decode_base64_candidate(b"not a base64 value")


def test_candidate_key_derivation_applies_only_explicit_transforms() -> None:
    seed = bytes(range(20))
    derived = C2.derive_candidate_key(
        seed,
        dword_xor=0x11223344,
        byte_xors=(0xA5,),
        candidate_index=7,
        index_mode="byte",
    )
    expected = bytes(
        value ^ bytes.fromhex("44332211")[index % 4] ^ 0xA5 ^ 7
        for index, value in enumerate(seed)
    )
    assert derived == expected


def test_v8_model_never_promotes_static_candidate_to_real_c2() -> None:
    assessment = C2.assess_version_model(61, "v8_1_plus")

    assert assessment["candidate_count_matches_model"] is False
    assert assessment["real_c2_static_decidable"] is False
    assert assessment["response_or_network_emulation_required"] is True
    assert assessment["legacy_fixed_index_assumption_applied"] is False
