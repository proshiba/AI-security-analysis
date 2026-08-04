"""StealCのUTF-16 core markerと内包helper同居時の優先順位を検証する。"""

from __future__ import annotations

from extractors.stealc.structural import classify_module_role


def _wide(value: str) -> bytes:
    return value.encode("utf-16le")


def test_wide_core_markers_take_precedence_over_embedded_helper_strings() -> None:
    core = b"\x00".join(
        _wide(value)
        for value in (
            "C:\\builder_v3\\build\\json.h",
            "nlohmann",
            "Content-Type: application/json",
            "wininet.dll",
            "HttpSendRequestW",
            "HttpOpenRequestW",
            "InternetConnectW",
            "Local State",
            "Steam",
        )
    )
    embedded_helper = (
        b'app_bound_encrypted_key CryptStringToBinaryA CoCreateInstance'
    )
    result = classify_module_role(core + embedded_helper)
    assert result["module_role"] == "collection_and_c2_core"
    assert result["evidence"]["builder_marker"] == "builder_v3"
