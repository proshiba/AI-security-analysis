"""共通PE構造プロファイルエンジンの回帰テスト。"""

from __future__ import annotations

import hashlib

import pytest

from classifiers.classify_sample import normalize_detection_result
from common import pe_structural_profile as engine


def _profile(**overrides):
    value = {
        "id": "fixture_appv_loader",
        "family": "fixture",
        "campaign_type": "fixture_sideload",
        "reviewed_sha256": [],
        "required_exports": ["Bootstrap", "DllRegisterServer"],
        "api_markers": [
            "OpenProcess",
            "VirtualAllocEx",
            "WriteProcessMemory",
            "CreateRemoteThread",
        ],
        "minimum_api_markers": 3,
        "resource_rules": [
            {
                "id": "xor_pdf",
                "type_id": 10,
                "xor_key": 85,
                "magic_ascii": "%PDF-",
            }
        ],
        "structural_confidence": "medium",
    }
    value.update(overrides)
    return engine.validate_profile(value)


def test_exact_hash_can_identify_non_pe_delivery_container() -> None:
    data = b"reviewed outer archive"
    profile = _profile(reviewed_sha256=[hashlib.sha256(data).hexdigest()])
    result = engine.evaluate_profile(data, profile)
    assert result["matched"] is True
    assert result["exact_match"] is True
    assert result["structural_match"] is False
    assert result["confidence"] == "high"


def test_structural_profile_combines_independent_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = _profile()
    monkeypatch.setattr(
        engine,
        "inspect_pe",
        lambda _data, _profile: {
            "valid_pe": True,
            "exports": ["Bootstrap", "DllRegisterServer"],
            "required_exports": ["Bootstrap", "DllRegisterServer"],
            "api_markers": [
                "CreateRemoteThread",
                "OpenProcess",
                "WriteProcessMemory",
            ],
            "resource_matches": [
                {
                    "rule_id": "xor_pdf",
                    "type_id": 10,
                    "resource_id": 104,
                    "size": 100,
                    "decoded_sha256": "a" * 64,
                }
            ],
            "parse_status": "parsed",
        },
    )
    result = engine.evaluate_profile(b"MZ" + b"\0" * 62, profile)
    assert result["matched"] is True
    assert result["confidence"] == "medium"
    normalized = normalize_detection_result(
        {
            "matched": True,
            "confidence": result["confidence"],
            "observations": result["observations"],
            "campaigns": [
                {
                    "campaign_type": result["campaign_type"],
                    "confidence": result["confidence"],
                    "reasons": result["reasons"],
                }
            ],
        }
    )
    assert normalized["campaigns"][0]["confidence"] == "medium"


def test_missing_one_evidence_axis_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = _profile()
    monkeypatch.setattr(
        engine,
        "inspect_pe",
        lambda _data, _profile: {
            "valid_pe": True,
            "exports": ["Bootstrap", "DllRegisterServer"],
            "required_exports": ["Bootstrap", "DllRegisterServer"],
            "api_markers": ["OpenProcess", "VirtualAllocEx", "WriteProcessMemory"],
            "resource_matches": [],
            "parse_status": "parsed",
        },
    )
    result = engine.evaluate_profile(b"MZ" + b"\0" * 62, profile)
    assert result["matched"] is False
    assert result["checks"]["resources"] is False
    assert result["confidence"] == "insufficient"


def test_profile_rejects_high_structural_confidence() -> None:
    with pytest.raises(engine.ProfileValidationError, match="mediumまたはlow"):
        _profile(structural_confidence="high")
