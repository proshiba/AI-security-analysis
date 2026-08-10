"""script-only解析カバレッジ監査を検証する。"""

from __future__ import annotations

import sys
from pathlib import Path

COMMON = Path(__file__).resolve().parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

from automation_coverage import build_coverage, render_markdown
from handler_catalog import HandlerSpec


def _spec(family: str, *, automatic: bool = True, supported: bool = True) -> HandlerSpec:
    return HandlerSpec(
        id=f"{family}:extract",
        family=family,
        relative_path=f"malware/{family}/extract.py",
        callable_name="extract",
        invocation="bytes",
        source="test",
        automatic=automatic,
        campaign=None,
        supported_interface=supported,
        reason="fixture",
        input_formats=("pe",),
        input_contract_source="test",
        minimum_evidence_score=1,
    )


def test_coverage_separates_four_automation_states() -> None:
    report = build_coverage(
        registered_families={"full", "classifier", "manual"},
        specs=[
            _spec("full"),
            _spec("candidate"),
            _spec("manual", automatic=False),
        ],
    )
    states = {item["family"]: item["status"] for item in report["families"]}
    assert states == {
        "candidate": "candidate_verification_only",
        "classifier": "classification_only",
        "full": "fully_routable",
        "manual": "manual_handler_only",
    }
    assert report["counts"]["fully_routable"] == 1
    assert report["counts"]["script_only_handler_available"] == 2
    assert report["ai_used"] is False


def test_unsupported_interface_is_not_automatic() -> None:
    report = build_coverage(
        registered_families=set(),
        specs=[_spec("legacy", automatic=True, supported=False)],
    )
    item = report["families"][0]
    assert item["status"] == "manual_only_without_detector"
    assert item["candidate_verification_possible"] is False


def test_markdown_is_japanese_and_deterministic() -> None:
    report = build_coverage(
        registered_families={"full"},
        specs=[_spec("full")],
    )
    rendered = render_markdown(report)
    assert rendered == render_markdown(report)
    assert "既知マルウェア自動解析カバレッジ" in rendered
    assert "生成AIは使用しません" in rendered
    assert "| full | fully_routable | あり | 1 | なし |" in rendered
