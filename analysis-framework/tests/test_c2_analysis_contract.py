from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys


MODULE = Path(__file__).resolve().parents[1] / "common" / "c2_analysis_contract.py"
SPEC = importlib.util.spec_from_file_location("c2_analysis_contract", MODULE)
assert SPEC and SPEC.loader
target = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = target
SPEC.loader.exec_module(target)

DIGEST = "a" * 64


def _complete_contract(outcome: str = "confirmed") -> dict:
    protocol = {
        "status": "confirmed" if outcome == "confirmed" else "not_applicable",
        "method": "合成check-inと応答frameの一致" if outcome == "confirmed" else "終端codeに通信機能なし",
        "confidence": "high",
        "tcp_open_only": False,
    }
    return {
        "schema_version": 1,
        "sha256": DIGEST,
        "family": "fixture",
        "analysis_attempted": True,
        "phase_evidence": [
            {"phase": phase, "status": "completed", "evidence": [f"{phase}を確認した。"]}
            for phase in target.REQUIRED_PHASES
        ],
        "terminal_payload": {
            "reached": True,
            "status": "recovered",
            "family": "fixture",
            "blockers": [],
            "next_actions": [],
        },
        "c2": {
            "outcome": outcome,
            "extraction_attempted": True,
            "endpoints": (
                [{"value": "c2.example:443", "role": "c2", "source": "static_config"}]
                if outcome == "confirmed"
                else []
            ),
            "evidence": ["終端payloadの設定decoderと通信関数を確認した。"],
            "protocol": protocol,
            "live_check": {
                "status": "observed" if outcome == "confirmed" else "not_applicable",
                "target_registered": outcome == "confirmed",
            },
        },
        "automation": {
            "status": "developed_new_handler",
            "handlers": ["handler.py"],
            "tests": ["test_handler.py"],
            "reusable_logic_recorded": True,
        },
        "safety": {
            "sample_executed_locally": False,
            "credentials_published": False,
            "raw_payload_published": False,
        },
    }


def _repository(tmp_path: Path) -> Path:
    (tmp_path / "handler.py").write_text("# handler\n", encoding="utf-8")
    (tmp_path / "test_handler.py").write_text("# test\n", encoding="utf-8")
    return tmp_path


def test_confirmed_protocol_level_c2_passes(tmp_path: Path) -> None:
    result = target.validate_contract(_complete_contract(), DIGEST, repository=_repository(tmp_path))
    assert result["complete"] is True


def test_verified_no_c2_capability_passes(tmp_path: Path) -> None:
    result = target.validate_contract(
        _complete_contract("no_c2_capability_verified"),
        DIGEST,
        repository=_repository(tmp_path),
    )
    assert result["complete"] is True


def test_unresolved_terminal_and_c2_fail() -> None:
    document = target.build_unresolved_contract(DIGEST, "fixture")
    result = target.validate_contract(document, DIGEST)
    codes = {item["code"] for item in result["findings"]}
    assert result["complete"] is False
    assert "terminal_payload_not_reached" in codes
    assert "c2_outcome_unresolved" in codes


def test_tcp_open_only_cannot_confirm_c2(tmp_path: Path) -> None:
    document = _complete_contract()
    document["c2"]["protocol"]["tcp_open_only"] = True
    result = target.validate_contract(document, DIGEST, repository=_repository(tmp_path))
    assert result["complete"] is False
    assert any(item["code"] == "c2_tcp_open_only" for item in result["findings"])


def test_missing_automation_file_fails(tmp_path: Path) -> None:
    result = target.validate_contract(_complete_contract(), DIGEST, repository=tmp_path)
    assert result["complete"] is False
    assert any(item["code"] == "c2_automation_handlers_path" for item in result["findings"])


def test_case_loader_rejects_missing_contract(tmp_path: Path) -> None:
    result = target.validate_case(tmp_path, DIGEST)
    assert result["complete"] is False
    assert result["findings"][0]["code"] == "c2_analysis_file_missing"


def test_case_loader_reads_valid_contract(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    case = repository / "case"
    case.mkdir()
    (case / "c2-analysis.json").write_text(
        json.dumps(_complete_contract(), ensure_ascii=False), encoding="utf-8"
    )
    result = target.validate_case(case, DIGEST, repository=repository)
    assert result["complete"] is True
