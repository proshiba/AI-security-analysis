"""StealC新世代のmodule役割判定を検証する。"""

from __future__ import annotations

from extractors.stealc import extract
from extractors.stealc.structural import classify_module_role


def test_collection_and_c2_core_requires_independent_marker_groups(
    monkeypatch,
) -> None:
    data = b" ".join(
        (
            b"C:\\builder_v3\\build\\json.h",
            b"nlohmann",
            b"Content-Type: application/json",
            b"wininet.dll",
            b"HttpSendRequestW",
            b"HttpOpenRequestW",
            b"Login Data",
            b"Local State",
            b"Cookies",
        )
    )
    structural = classify_module_role(data)
    assert structural["module_role"] == "collection_and_c2_core"
    assert structural["generation_candidate"] == "StealC-v2-or-later"
    assert structural["version_confirmed"] is False

    monkeypatch.setattr(
        "extractors.stealc.integrated.extract_v1",
        lambda _data, _name: {
            "config": {"profile": None, "static_config_recovered": False},
            "limitations": [],
        },
    )
    result = extract(data)
    assert result["config"]["structural_profile"]["module_role"] == (
        "collection_and_c2_core"
    )
    assert result["config"]["protocol_analysis"]["active_probe_policy"] == (
        "guarded_active_reviewed_profile_only"
    )


def test_app_bound_helper_is_not_mislabeled_as_c2_core() -> None:
    structural = classify_module_role(
        b'"app_bound_encrypted_key":" CryptStringToBinaryA CoCreateInstance'
    )
    assert structural["module_role"] == "chrome_app_bound_key_helper"
    assert structural["generation_candidate"].endswith("related-helper")


def test_partial_generic_markers_remain_unknown() -> None:
    structural = classify_module_role(
        b"Content-Type: application/json wininet.dll Login Data"
    )
    assert structural["module_role"] == "unknown"
