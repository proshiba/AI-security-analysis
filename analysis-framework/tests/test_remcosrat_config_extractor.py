from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
FAMILY_DIR = ROOT / "analysis-framework" / "malware" / "remcosrat"
COMMON_DIR = ROOT / "analysis-framework" / "common"


def load(name: str, filename: str):
    path = FAMILY_DIR / filename
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.path[:0] = [str(FAMILY_DIR), str(COMMON_DIR)]
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(FAMILY_DIR))
        sys.path.remove(str(COMMON_DIR))
    return module


def modern_clear(delimiter: bytes) -> bytes:
    fields = [b"0"] * 57
    fields[0] = b"c2.example:2404:1\x1e8.8.8.8:443:0"
    fields[1] = b"reviewed-botnet"
    fields[2] = b"30"
    fields[0x0E] = b"Rmc-TEST"
    fields[0x29] = b"5"
    fields[0x36] = b"agent-certificate"
    fields[0x37] = b"private-key-must-not-be-published"
    fields[0x38] = b"peer-certificate"
    return delimiter.join(fields)


@pytest.mark.parametrize("delimiter", [b"\x7c\x1f\x1e\x1e\x7c", b"\x7c\x1e\x1e\x1f\x7c"])
def test_both_published_delimiters_recover_index_zero_c2(delimiter: bytes) -> None:
    module = load("remcos_config_delimiters", "remcos_config_extractor.py")
    result = module.parse_decrypted_settings(modern_clear(delimiter))
    assert result["field_count"] == 57
    assert [item["endpoint"] for item in result["c2"]] == [
        "c2.example:2404",
        "8.8.8.8:443",
    ]
    assert [item["tls_enabled"] for item in result["c2"]] == [True, False]
    assert result["connect_interval_seconds"] == 30
    assert result["initial_connect_delay_seconds"] == 5


def test_legacy_third_field_is_withheld_instead_of_mislabelled_tls() -> None:
    module = load("remcos_config_legacy", "remcos_config_extractor.py")
    delimiter = module.DELIMITERS[0]
    fields = [b"0"] * 20
    fields[0] = b"old.example:9001:private-password"
    parsed = module.parse_decrypted_settings(delimiter.join(fields))
    assert parsed["c2"][0]["tls_enabled"] is None
    assert parsed["c2"][0]["third_field_kind"] == "withheld_unknown_or_credential"
    assert parsed["credential_or_unknown_c2_field_present"] is True
    assert "private-password" not in json.dumps(parsed, ensure_ascii=False)


def test_endpoint_outside_config_index_zero_is_not_promoted() -> None:
    module = load("remcos_config_index_zero", "remcos_config_extractor.py")
    fields = [b"0"] * 57
    fields[5] = b"decoy.example:4444:1"
    with pytest.raises(ValueError, match="index 0"):
        module.parse_decrypted_settings(module.DELIMITERS[0].join(fields))


def test_extract_config_redacts_key_private_material_and_raw_config(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load("remcos_config_extract", "remcos_config_extractor.py")
    key = b"reviewed-test-key"
    clear = modern_clear(module.DELIMITERS[1])
    resource = bytes([len(key)]) + key + module.rc4_crypt(clear, key)
    monkeypatch.setattr(module, "_settings_resource", lambda _data: resource)
    report = module.extract_config(b"MZ\x00" + b"7.2.6 Pro" + b"\x00" * 64)
    rendered = json.dumps(report, ensure_ascii=False)
    assert report["static_config_recovered"] is True
    assert report["decoded_config_recovered"] is True
    assert report["version_candidates"] == ["7.2.6 Pro"]
    assert report["config"]["tls_material"]["private_key_present"] is True
    assert report["config"]["tls_material"]["private_key_published"] is False
    assert "reviewed-test-key" not in rendered
    assert "private-key-must-not-be-published" not in rendered
    assert report["safety"]["network_contacted"] is False


def test_decode_settings_rejects_empty_ciphertext_and_oversized_resource() -> None:
    module = load("remcos_config_bounds", "remcos_config_extractor.py")
    with pytest.raises(ValueError, match="鍵長"):
        module.decode_settings_blob(b"\x07abcdefg")
    with pytest.raises(ValueError, match="サイズ"):
        module.decode_settings_blob(b"A" * (module.MAX_SETTINGS_BYTES + 1))


def test_hunt_output_has_offline_target_and_configured_certificate_pivot() -> None:
    module = load("remcos_hunt", "c2_detector.py")
    certificate = "a" * 64
    result = module.build_hunt(
        {
            "c2": [
                {
                    "host": "c2.example",
                    "port": 2404,
                    "tls_enabled": True,
                    "monitor_eligible": True,
                }
            ],
            "config": {"tls_material": {"peer_certificate_sha256": certificate}},
            "version_candidates": ["7.2.6 Pro"],
        }
    )
    assert result["targets"][0]["shodan_queries"] == ["hostname:c2.example port:2404"]
    assert result["certificate_pivots"][0]["sha256"] == certificate
    assert result["active_scan_performed"] is False
    assert result["network_contacted"] is False


def test_external_endpoint_hunt_keeps_provider_evidence_separate() -> None:
    module = load("remcos_external_hunt", "c2_detector.py")
    result = module.build_endpoint_hunt(
        ["external.example:4489", "invalid", "external.example:4489"],
        source="external_sandbox_reported_configuration",
    )
    assert len(result["targets"]) == 1
    assert result["targets"][0]["source"] == "external_sandbox_reported_configuration"
    assert result["targets"][0]["shodan_queries"] == ["hostname:external.example port:4489"]
    assert result["active_scan_performed"] is False
    assert result["network_contacted"] is False


def test_standard_handler_declares_bounded_pe_contract() -> None:
    module = load("remcos_standard_handler", "extract_config.py")
    assert module.HANDLER_CONTRACT == {
        "input_formats": ["pe"],
        "minimum_evidence_score": 1,
    }


def test_standard_handler_rebuilds_mapped_pe_without_publishing_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load("remcos_standard_mapped_handler", "extract_config.py")
    original = b"MZmapped-memory"
    rebuilt = b"MZrebuilt-file"

    def fake_extract(data: bytes) -> dict:
        if data == original:
            raise ValueError("resource not present in file layout")
        assert data == rebuilt
        return {
            "sample_sha256": "0" * 64,
            "sample": {"sha256": "0" * 64, "size": len(data), "format": "pe"},
            "limitations": [],
        }

    monkeypatch.setattr(module, "_extract_config", fake_extract)
    monkeypatch.setattr(
        module,
        "rebuild_mapped_pe",
        lambda data, max_output_bytes: (
            rebuilt,
            {
                "status": "rebuilt",
                "input_sha256": hashlib.sha256(data).hexdigest(),
                "output_sha256": hashlib.sha256(rebuilt).hexdigest(),
                "executed": False,
                "network_contacted": False,
            },
        ),
    )

    result = module.extract_config(original)
    assert result["sample_sha256"] == hashlib.sha256(original).hexdigest()
    assert result["sample"]["format"] == "mapped_pe_memory_image"
    assert result["sample"]["reconstructed_pe_sha256"] == hashlib.sha256(rebuilt).hexdigest()
    assert "mapped_pe_reconstruction" in result
    assert rebuilt.hex() not in json.dumps(result)
