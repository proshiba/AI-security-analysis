"""UIのcase catalog完全一致契約を検証する。"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest


MODULE_PATH = Path(__file__).resolve().parents[2] / "ui" / "generate_ui_data.py"
SPEC = importlib.util.spec_from_file_location("ui_generate_ui_data", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
ui_data = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ui_data)


def _case_fixture(tmp_path: Path) -> tuple[str, Path, dict]:
    digest = "a" * 64
    case = (
        tmp_path
        / "analysis-results"
        / "malware"
        / "testfamily"
        / "versions"
        / "unknown"
        / "cases"
        / digest
    )
    case.mkdir(parents=True)
    entry = {
        "canonical_path": case.relative_to(tmp_path).as_posix(),
        "case_id": f"sha256:{digest}",
        "case_kind": "malware",
        "family": "testfamily",
        "version_key": "unknown",
    }
    return digest, case, entry


def _set_repository(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(ui_data, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(ui_data, "RESULTS", tmp_path / "analysis-results")


def test_discover_cases_requires_exact_catalog_match(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    digest, _case, entry = _case_fixture(tmp_path)
    catalog = tmp_path / "analysis-results" / "catalog" / "cases.json"
    catalog.parent.mkdir(parents=True)
    catalog.write_text(
        json.dumps({"schema_version": 1, "cases": {digest: entry}}),
        encoding="utf-8",
    )
    _set_repository(monkeypatch, tmp_path)

    assert ui_data.discover_cases() == {digest: entry}


def test_discover_cases_rejects_unregistered_case(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _case_fixture(tmp_path)
    catalog = tmp_path / "analysis-results" / "catalog" / "cases.json"
    catalog.parent.mkdir(parents=True)
    catalog.write_text(
        json.dumps({"schema_version": 1, "cases": {}}),
        encoding="utf-8",
    )
    _set_repository(monkeypatch, tmp_path)

    with pytest.raises(ValueError, match="未登録=1"):
        ui_data.discover_cases()


def test_discover_cases_rejects_stale_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    digest, _case, entry = _case_fixture(tmp_path)
    stale = dict(entry)
    stale["family"] = "wrongfamily"
    catalog = tmp_path / "analysis-results" / "catalog" / "cases.json"
    catalog.parent.mkdir(parents=True)
    catalog.write_text(
        json.dumps({"schema_version": 1, "cases": {digest: stale}}),
        encoding="utf-8",
    )
    _set_repository(monkeypatch, tmp_path)

    with pytest.raises(ValueError, match="identity"):
        ui_data.discover_cases()