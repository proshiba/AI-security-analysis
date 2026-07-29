"""AgentTesla一括解析ハンドラーの自動発見契約を検証する。"""

from __future__ import annotations

from pathlib import Path
import sys


COMMON = Path(__file__).resolve().parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

from analysis_contract import handler_result_quality  # noqa: E402
from handler_catalog import discover_handlers, load_handler  # noqa: E402


def _spec():
    values = [
        item
        for item in discover_handlers()
        if item.family == "agenttesla"
        and item.relative_path
        == "analysis-framework/malware/agenttesla/extract_config.py"
    ]
    assert len(values) == 1
    return values[0]


def test_agenttesla_chain_handler_has_bounded_contract() -> None:
    spec = _spec()
    assert spec.automatic is True
    assert spec.input_formats == ("script", "data", "pe")
    assert spec.input_contract_source == "module_declaration"
    assert spec.minimum_evidence_score == 5


def test_agenttesla_chain_handler_rejects_unrelated_input() -> None:
    spec = _spec()
    handler, _invocation = load_handler(spec)
    result = handler(b"ordinary unrelated input")
    quality = handler_result_quality(
        result,
        minimum_score=spec.minimum_evidence_score,
    )
    assert quality["tier_name"] == "no_evidence"
    assert quality["sufficient"] is False
