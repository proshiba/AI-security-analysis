"""`--check` が環境由来の差分だけを許容することを確認する。

`ui/data.js` のうち `repo` と `cases[].added_at` は解析成果物ではなく
**生成した環境**で決まる。この2つ以外に差分があれば「古い」と判定しなければ
ならない。ここではその境界を固定する。
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any


MODULE_PATH = Path(__file__).parents[2] / "ui" / "generate_ui_data.py"
SPEC = importlib.util.spec_from_file_location("generate_ui_data_check_tolerance", MODULE_PATH)
assert SPEC and SPEC.loader
target = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(target)


def payload(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "generated_at_utc": "2026-08-11T00:00:00+00:00",
        "repo": {"html_base": "https://example.invalid/o/r", "branch": "main"},
        "stats": {"cases": 2},
        "cases": [
            {"sha256": "a" * 64, "family": "AgentTesla", "added_at": "2026-08-01"},
            {"sha256": "b" * 64, "family": "Formbook", "added_at": "2026-08-02"},
        ],
    }
    base.update(overrides)
    return base


def as_js(data: dict[str, Any]) -> str:
    return "window.MALDB = " + json.dumps(data, ensure_ascii=False) + ";\n"


def tolerated(old: dict[str, Any], new: dict[str, Any]) -> bool:
    return target.only_environment_derived_difference(as_js(old), new)


def test_identical_payload_is_not_reported_as_environment_difference() -> None:
    # 差分ゼロは呼び出し元が先に等値比較で拾う。ここでは「許容すべき差分」が
    # 無いのだから False を返す、という契約を固定する。
    assert tolerated(payload(), payload()) is False


def test_repo_resolved_from_null_is_tolerated() -> None:
    old = payload(repo=None)
    assert tolerated(old, payload()) is True


def test_repo_lost_to_null_is_tolerated() -> None:
    # remote の無いクローンで生成すると null になる。向きは問わない。
    assert tolerated(payload(), payload(repo=None)) is True


def test_added_at_filled_in_is_tolerated() -> None:
    old = payload()
    old["cases"] = [dict(old["cases"][0], added_at=None), old["cases"][1]]
    assert tolerated(old, payload()) is True


def test_added_at_and_repo_together_are_tolerated() -> None:
    old = payload(repo=None)
    old["cases"] = [dict(old["cases"][0], added_at=None), old["cases"][1]]
    assert tolerated(old, payload()) is True


def test_added_at_rewritten_to_another_date_is_drift() -> None:
    old = payload()
    old["cases"] = [dict(old["cases"][0], added_at="2026-07-01"), old["cases"][1]]
    assert tolerated(old, payload()) is False


def test_added_at_regressing_to_null_is_drift() -> None:
    new = payload()
    new["cases"] = [dict(new["cases"][0], added_at=None), new["cases"][1]]
    assert tolerated(payload(), new) is False


def test_other_case_field_change_is_drift() -> None:
    old = payload()
    old["cases"] = [dict(old["cases"][0], family="Unknown"), old["cases"][1]]
    assert tolerated(old, payload()) is False


def test_other_case_field_change_alongside_added_at_is_drift() -> None:
    old = payload()
    old["cases"] = [dict(old["cases"][0], added_at=None, family="Unknown"), old["cases"][1]]
    assert tolerated(old, payload()) is False


def test_case_count_change_is_drift() -> None:
    old = payload()
    old["cases"] = old["cases"][:1]
    old["stats"] = {"cases": 1}
    assert tolerated(old, payload()) is False


def test_stats_change_is_drift() -> None:
    assert tolerated(payload(stats={"cases": 3}), payload()) is False


def test_top_level_addition_is_drift() -> None:
    new = payload()
    new["c2"] = {"endpoints": []}
    assert tolerated(payload(), new) is False


def test_generated_at_change_is_drift() -> None:
    # 生成時刻は成果物のハッシュから決まる決定的な値で、環境由来ではない。
    assert tolerated(payload(generated_at_utc="2026-08-10T00:00:00+00:00"), payload()) is False


def test_case_reordering_is_drift() -> None:
    old = payload()
    old["cases"] = list(reversed(old["cases"]))
    assert tolerated(old, payload()) is False


def test_unparsable_current_file_is_drift() -> None:
    assert target.only_environment_derived_difference("これはJSONではない", payload()) is False
