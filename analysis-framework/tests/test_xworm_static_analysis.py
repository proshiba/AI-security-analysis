from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7


REPOSITORY = Path(__file__).resolve().parents[2]
COMMON = REPOSITORY / "analysis-framework" / "common"
for candidate in (REPOSITORY, COMMON):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

from extractors.xworm import integrated  # noqa: E402
import handler_catalog as catalog  # noqa: E402


DETECT_SPEC = importlib.util.spec_from_file_location(
    "xworm_detect_for_test",
    REPOSITORY / "analysis-framework" / "malware" / "xworm" / "detect.py",
)
assert DETECT_SPEC and DETECT_SPEC.loader
detector = importlib.util.module_from_spec(DETECT_SPEC)
DETECT_SPEC.loader.exec_module(detector)


def test_xworm_aes_setting_round_trip_matches_reviewed_key_layout() -> None:
    mutex = "fixture-mutex"
    plaintext = b"c2.example.test"
    padder = PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    encryptor = Cipher(algorithms.AES(integrated._aes_key(mutex)), modes.ECB()).encryptor()
    import base64

    encoded = base64.b64encode(
        encryptor.update(padded) + encryptor.finalize()
    ).decode()

    assert integrated.decrypt_setting(encoded, mutex) == plaintext.decode()


def test_xworm_automatic_handler_passes_bounded_preflight() -> None:
    """XWormの局所ECB許可を含む依存関係を隔離workerへ接続できる。"""

    catalog.clear_handler_caches()
    specs = [
        item
        for item in catalog.discover_handlers()
        if item.automatic and item.family == "xworm"
    ]

    assert specs
    for spec in specs:
        actual_format = next(
            (item for item in spec.input_formats if item != "any"),
            "data",
        )
        preflight = catalog.preflight_handler_for_assessment(
            spec,
            actual_format=actual_format,
            input_size=4_096,
        )
        assert preflight["eligible"] is True, preflight["blockers"]
        assert preflight["blockers"] == []
        assert preflight["sample_execution_allowed"] is False
        assert preflight["network_allowed"] is False
        assert preflight["filesystem_write_allowed"] is False
        assert (
            preflight["dependency_audit"]["allowance_counts"][
                "reviewed_source_scoped_call"
            ]
            >= 1
        )


def test_xworm_structural_evidence_requires_successful_config_recovery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        integrated,
        "recover_config",
        lambda _data: {
            "version": "XWorm V6.4",
            "config_endpoints": [{"host": "c2.example.test", "port": 6000}],
            "structural_evidence": {"method_count": 115},
        },
    )

    result = integrated.structural_evidence(b"managed-fixture")

    assert result["matched"] is True
    assert result["version"] == "XWorm V6.4"
    assert result["endpoint_count"] == 1


def test_xworm_extract_publishes_config_but_not_key_or_mutex(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        integrated,
        "recover_config",
        lambda _data: {
            "schema_version": 1,
            "family": "xworm",
            "sha256": "a" * 64,
            "version": "XWorm V6.4",
            "config_endpoints": [{"host": "c2.example.test", "port": 6000}],
            "sleep_seconds": 1,
            "usb_filename": "USB.exe",
            "separator": "<XWormmm>",
            "secret_fields_published": False,
            "crypto_profile": {
                "config_cipher": "AES-256-ECB-PKCS7",
                "mutex_published": False,
                "communication_key_published": False,
            },
            "structural_evidence": {
                "method_count": 115,
                "main": "0x06000014",
            },
            "executed": False,
            "network_contacted": False,
        },
    )

    result = integrated.extract(b"fixture", "fixture.exe")

    assert result["static_config_recovered"] is True
    assert result["config_endpoints"] == [
        {
            "host": "c2.example.test",
            "port": 6000,
            "transport": "tcp",
            "role": "configured_c2",
            "confidence": "confirmed_static_configuration",
            "evidence": {
                "kind": "xworm_managed_settings_aes",
                "all_expected_fields_validated": True,
            },
        }
    ]
    assert result["static_protocol"]["framing"] == "configured_string_delimiter"
    assert result["static_evidence"]["communication_key_published"] is False
    assert "fixture-mutex" not in repr(result)


def test_xworm_exact_review_has_characteristic_functions() -> None:
    functions = integrated._reviewed_functions(integrated.REVIEWED_SHA256)

    assert len(functions) == 8
    assert {item["role"] for item in functions} >= {
        "command_control",
        "command_dispatcher",
        "config_decoder",
        "plugin_loader",
    }
    assert integrated._reviewed_functions("a" * 64) == []


def test_xworm_detector_prefers_reviewed_managed_structure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        detector,
        "structural_evidence",
        lambda _data: {"matched": True, "rule": "fixture"},
    )

    result = detector.detect(b"fixture", Path("fixture.exe"))

    assert result["matched"] is True
    assert result["observations"]["family"] == "xworm"
    assert result["observations"]["static_config_recovered"] is True
    assert result["observations"]["executed"] is False
    assert result["observations"]["network_contacted"] is False
