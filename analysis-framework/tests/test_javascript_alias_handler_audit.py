"""JavaScript alias探索のsource限定プリフライト契約を検証する。"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
COMMON = ROOT / "analysis-framework" / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import handler_catalog as catalog

KEY = (
    "unpackers/javascript_obfuscator.py",
    "reachable:_bounded_alias_closure",
    "time.monotonic",
)


def _monotonic_shape(source: str) -> bool:
    tree = ast.parse(source)
    scope = next(node for node in tree.body if isinstance(node, ast.FunctionDef))
    call = next(node for node in ast.walk(scope) if isinstance(node, ast.Call))
    return catalog._reviewed_source_call_shape_allowed(
        call,
        "time.monotonic",
        tree,
        scope,
        catalog._import_aliases(tree),
        key=KEY,
    )


def test_bounded_alias_closure_passes_recursive_audit() -> None:
    """実装本体は局所containerと引数なし単調時計以外を許可しない。"""

    result = catalog._recursive_handler_side_effect_audit(
        ROOT / "unpackers" / "javascript_obfuscator.py",
        "_bounded_alias_closure",
    )

    assert result["issues"] == [], result["issues"]
    assert result["allowance_counts"]["reviewed_source_scoped_call"] == 2


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("import time\ndef target():\n    return time.monotonic()\n", True),
        ("import time\ndef target():\n    return time.monotonic(1)\n", False),
        ("import time\ndef target():\n    time = object()\n    return time.monotonic()\n", False),
        ("import time\ndef target():\n    return time.time()\n", False),
    ],
    ids=["exact", "argument", "rebound_module", "different_clock"],
)
def test_monotonic_allowance_is_exact_and_fail_closed(source: str, expected: bool) -> None:
    """許可は固定source・contextの引数なしmonotonic読み取りだけに限定する。"""

    assert _monotonic_shape(source) is expected


def test_monotonic_allowance_is_source_and_context_scoped() -> None:
    """同じcall名でも別sourceや別関数へ権限を拡張しない。"""

    assert KEY in catalog._REVIEWED_SOURCE_CALLS
    assert ("unpackers/other.py", KEY[1], KEY[2]) not in catalog._REVIEWED_SOURCE_CALLS
    assert (KEY[0], "reachable:other", KEY[2]) not in catalog._REVIEWED_SOURCE_CALLS
