"""QuasarRAT専用extractorの選択とversion別通信契約を検証する。"""

from __future__ import annotations

import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
COMMON = REPOSITORY_ROOT / "analysis-framework" / "common"
for import_root in (REPOSITORY_ROOT, COMMON):
    if str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))

import handler_catalog
from extractors import config_extractor, quasarrat


def _quasarrat_handler() -> handler_catalog.HandlerSpec:
    values = [item for item in handler_catalog.discover_handlers() if item.family == "quasarrat" and item.automatic]
    assert len(values) == 1
    return values[0]


def test_quasarrat_specialized_extractor_wins_end_to_end() -> None:
    """catalogから隔離実行まで専用extractorを使い、generic TLS値を公開しない。"""

    spec = _quasarrat_handler()
    assert spec.relative_path == "extractors/quasarrat.py"
    assert spec.source == "shared_extractor"
    assert config_extractor.get_extractor("quasar") is quasarrat.extract

    fixture = b"MZ\x00Quasar.Client\x00XClient.Core\x00ReconnectDelay\x00"
    bounded = handler_catalog.execute_handler_bounded_for_assessment(
        spec,
        fixture,
        "quasar-v1.3-fixture.exe",
        actual_format="pe",
    )

    assert bounded["status"] == "completed", "\n".join(bounded["preflight"]["blockers"])
    result = bounded["execution"]["result"]
    assert result["family"] == "quasarrat"
    assert result["config"]["profile"] == "quasarrat"
    assert "transport" not in result["config"]
    assert result["config"]["decoded_config_recovered"] is False


def test_quasarrat_protocol_metadata_is_bound_to_authenticated_config() -> None:
    v13 = {
        "version": "1.3.0",
        "transport": "TLS-capable length-prefixed TCP",
        "static_config_recovered": True,
        "crypto": {
            "hmac_verified_for_all_fields": True,
            "iterations": 100_000,
        },
    }
    quasarrat._apply_versioned_protocol(v13)

    assert v13["transport"] == "raw TCP"
    assert v13["protocol"]["framing"] == "LE32 length prefix"
    assert v13["protocol"]["authentication"] == "HMAC-SHA256"
    assert v13["protocol"]["encryption"] == "AES-128-CBC"
    assert v13["protocol"]["key_derivation"] == "PBKDF2-HMAC-SHA1 (100,000 iterations)"
    assert v13["protocol"]["key_derivation_iterations"] == 100_000
    assert v13["protocol"]["binding"] == "authenticated_static_config"
    assert v13["protocol"]["compression"] == "QuickLZ"
    assert v13["protocol"]["serialization"] == "NetSerializer"
    assert v13["protocol"]["tls"] is False

    unverified_v13 = {"version": "1.3.0", "transport": "TLS-capable length-prefixed TCP"}
    quasarrat._apply_versioned_protocol(unverified_v13)
    assert "transport" not in unverified_v13
    assert "protocol" not in unverified_v13

    v14 = {
        "version": "1.4.0",
        "transport": "TLS-capable length-prefixed TCP",
        "static_config_recovered": True,
        "crypto": {"hmac_verified_for_all_fields": True, "iterations": 50_000},
    }
    quasarrat._apply_versioned_protocol(v14)
    assert "transport" not in v14
    assert "protocol" not in v14
