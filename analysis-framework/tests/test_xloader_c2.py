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


def test_current_sample_mode_de_path_table_known_vector() -> None:
    selectors = (39, 50, 43, 47, 33, 40, 13, 59, 57, 28, 29, 54, 49, 4, 24, 15)
    dwords = (
        0x65012E8C, 0x99C253E9, 0x4CD96170, 0x0B7AB896, 0x3828F6E9,
        0x1D038A5F, 0x0F6D8489, 0x05B64482, 0x3B8BF179, 0x54EDB73F,
        0xD3B315C3, 0x8EAA1837, 0x75FAEB3C, 0x9FE78E87, 0x8BFDEE46,
        0x4575B5D3, 0xC1FE05F2, 0x181081B4, 0x18CD2E10, 0x59FF2F9E,
        0x987BDC55, 0x55CFF6A3, 0xF335AFF0, 0xA6570F1C, 0x0953ABC4,
        0x123A983B, 0xCA36D9DC, 0x6F4C1C1C, 0xFFD4F5D0, 0xECEC9DC5,
        0xA4E5B92B, 0x5D8EF964, 0xEBB032C6, 0x4CC3CB55, 0x66D64733,
        0x49B03B7E, 0x1A4A70CF, 0x932D3FAE, 0x5529CAFC, 0xAE8784C8,
        0xDB14AB0F, 0xCB6551CE, 0xA26C40D9, 0x36B8BDE1, 0xF774D91B,
        0x3682DEAF, 0x7B13F42D, 0xAEF67963, 0x4DF778D7, 0xA0381F31,
        0x616DE2A9, 0x54A1AF41, 0xE4859652, 0x2DB2BC2E, 0x3754585F,
        0xB0982C27, 0x937DA286, 0x316DD939, 0x48D4D6BD, 0x8EBB30F9,
        0x6115EA66, 0x4D9BE911, 0x46ABADF7, 0x1D9D361A, 0x9703B68D,
    )
    base_key = bytes.fromhex("caf33c42fb1eba0a236bc4592da83f93bf72a45c")
    expected = (
        "/r79d/", "/sy4v/", "/yim2/", "/lieg/", "/s50d/", "/bvy8/",
        "/iir6/", "/70hw/", "/ue3i/", "/rjwn/", "/ievt/", "/tb8q/",
        "/ximu/", "/s3gf/", "/lsg7/", "/zqgn/",
    )
    assert C2.recover_path_table(selectors, dwords, base_key) == expected
