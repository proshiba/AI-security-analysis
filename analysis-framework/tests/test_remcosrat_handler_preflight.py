"""Remcos厳格設定handlerの隔離自動解析契約を検証する。"""

from __future__ import annotations

import sys
from pathlib import Path

COMMON = Path(__file__).resolve().parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

from handler_catalog import (
    discover_handlers,
    preflight_handler_for_assessment,
    preflight_handler_runtime_import,
)


def test_remcos_handler_is_bounded_and_preflight_eligible() -> None:
    """共有strict coreを含む依存全体をsnapshot監査してPEだけへ適用する。"""

    handlers = {spec.id: spec for spec in discover_handlers()}
    handler = handlers["remcosrat:analysis.framework.malware.remcosrat.extract.config.py:extract_config"]
    preflight = preflight_handler_for_assessment(
        handler,
        actual_format="pe",
        input_size=4096,
    )

    assert preflight["eligible"] is True, preflight["blockers"]
    assert preflight["blockers"] == []
    assert preflight["sample_execution_allowed"] is False
    assert preflight["network_allowed"] is False
    assert preflight["filesystem_write_allowed"] is False
    assert preflight["dependency_audit"]["issues"] == []

    runtime = preflight_handler_runtime_import(
        handler,
        static_preflight=preflight,
        timeout_seconds=20.0,
    )
    assert runtime["eligible"] is True, runtime["blockers"]
    assert runtime["blockers"] == []


def test_remcos_shared_root_extractor_is_superseded_for_automatic_use() -> None:
    """重複実行を避け、汎用config入口を自動handlerから除外する。"""

    handlers = {spec.id: spec for spec in discover_handlers()}
    handler = handlers["remcosrat:extractors.remcosrat.extractor.py:extract"]
    assert handler.automatic is False
    assert handler.reason == "superseded_by_family_strict_config_handler"
    preflight = preflight_handler_for_assessment(
        handler,
        actual_format="pe",
        input_size=4096,
    )

    assert preflight["eligible"] is False
    assert preflight["blockers"] == ["handler_not_automatic"]
    assert preflight["sample_execution_allowed"] is False
    assert preflight["network_allowed"] is False
    assert preflight["filesystem_write_allowed"] is False
    assert preflight["dependency_audit"]["issues"] == []
