"""NanoCore設定復号器の自動実行契約を検証する。"""

from __future__ import annotations

import sys
from pathlib import Path

FRAMEWORK = Path(__file__).resolve().parents[1]
COMMON = FRAMEWORK / "common"
if str(FRAMEWORK) not in sys.path:
    sys.path.insert(0, str(FRAMEWORK))
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

from handler_catalog import discover_handlers, preflight_handler_for_assessment  # noqa: E402
from malware.nanocore import extract_config as nanocore_config  # noqa: E402
import handler_evidence  # noqa: E402


def test_nanocore_decryption_handler_is_bounded_and_preflight_eligible() -> None:
    """decrepit TripleDESの使用後もPE限定で隔離workerへ進める。"""

    handler = next(spec for spec in discover_handlers() if spec.family == "nanocore" and spec.automatic)
    assert handler.input_formats == ("pe",)
    assessment = preflight_handler_for_assessment(handler, actual_format="pe", input_size=4096)
    assert assessment["eligible"] is True
    assert assessment["blockers"] == []
    assert assessment["sample_execution_allowed"] is False
    assert assessment["network_allowed"] is False
    assert assessment["filesystem_write_allowed"] is False


def test_nanocore_decoded_config_reaches_static_c2_projection(monkeypatch) -> None:
    """認証済み復号設定をroot hashへ結び付け、live未確認のC2だけへ投影する。"""

    monkeypatch.setattr(nanocore_config, "_resource_envelope", lambda _data: (b"envelope", {"resource_offset": 32}))
    monkeypatch.setattr(
        nanocore_config,
        "decode_envelope",
        lambda _envelope: {
            "Version": "1.2.2.0",
            "PrimaryConnectionHost": "controller.example.org",
            "BackupConnectionHost": "backup.example.org",
            "ConnectionPort": 443,
        },
    )
    result = nanocore_config.extract_config(b"MZ-fixture")
    digest = result["sample_sha256"]
    handler_id = "nanocore:test.py:extract_config"
    evidence = {"sufficient": True, "score": 40102}
    execution = {
        "handler_id": handler_id,
        "status": "succeeded",
        "selected_layer_sha256": digest,
        "selected_evidence": evidence,
    }
    artifact = {
        "handler": {"id": handler_id, "family": "nanocore"},
        "selected_layer": {"sha256": digest},
        "selected_evidence": evidence,
        "result": result,
        "executed_sample": False,
        "network_contacted": False,
    }
    assert handler_evidence.trusted_handler_result(execution, artifact) is True
    document = handler_evidence.build_communication_pattern_document(
        sha256=digest,
        family="nanocore",
        handler_results=[(execution, artifact)],
    )
    endpoints = document["communication"]["confirmed_static_c2_endpoints"]
    assert [(item["host"], item["port"]) for item in endpoints] == [
        ("backup.example.org", 443),
        ("controller.example.org", 443),
    ]
    assert document["config"]["static_config_recovered"] is True
    assert document["communication"]["liveness_confirmed"] is False
    assert all(item["evidence"]["kind"] == "nanocore_des_cbc_typed_config" for item in endpoints)

    artifact["result"] = {**result, "sample_sha256": "0" * 64}
    assert handler_evidence.trusted_handler_result(execution, artifact) is False


def test_nanocore_rejects_non_public_or_malformed_config_host(monkeypatch) -> None:
    """復号成功だけで内部アドレスや不正なhostをC2へ昇格しない。"""

    monkeypatch.setattr(nanocore_config, "_resource_envelope", lambda _data: (b"envelope", {}))
    monkeypatch.setattr(
        nanocore_config,
        "decode_envelope",
        lambda _envelope: {
            "Version": "1.2.2.0",
            "PrimaryConnectionHost": "127.0.0.1",
            "BackupConnectionHost": "bad host",
            "ConnectionPort": 443,
        },
    )
    result = nanocore_config.extract_config(b"MZ-fixture")
    assert result["static_config_recovered"] is False
    assert result["c2"] == []
