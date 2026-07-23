"""既知の旧analysis.jsonだけを安全に移行することを検証する。"""

from __future__ import annotations

from pathlib import Path
import sys


COMMON = Path(__file__).parents[1] / "common"
sys.path.insert(0, str(COMMON))

from normalize_analysis_schema import normalize_document  # noqa: E402


def test_recognized_legacy_document_gets_schema_version() -> None:
    value = {key: {} for key in ("case", "config", "c2", "unpack", "layers")}
    normalized, changed = normalize_document(value)
    assert changed
    assert normalized["schema_version"] == 1
    assert value.get("schema_version") is None


def test_unknown_or_current_document_is_not_changed() -> None:
    unknown = {"case": {}, "unexpected": True}
    assert normalize_document(unknown) == (unknown, False)
    current = {"schema_version": 1, "case": {}}
    assert normalize_document(current) == (current, False)
