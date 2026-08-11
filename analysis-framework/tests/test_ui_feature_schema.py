"""UI生成時のfeatures.json型契約を検証する。"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


MODULE_PATH = Path(__file__).resolve().parents[2] / "ui" / "generate_ui_data.py"
SPEC = importlib.util.spec_from_file_location("ui_generate_feature_schema", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
ui_data = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ui_data)


def _case_fixture(tmp_path: Path) -> tuple[str, Path]:
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
    return digest, case


def test_feature_records_reject_string_with_case_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    digest, case = _case_fixture(tmp_path)
    monkeypatch.setattr(ui_data, "REPO_ROOT", tmp_path)

    with pytest.raises(ValueError) as raised:
        ui_data._feature_object_records(
            {"behaviors": ["legacy text"]},
            "behaviors",
            sha256=digest,
            case_dir=case,
        )

    message = str(raised.value)
    assert f"sha256={digest}" in message
    assert "path=analysis-results/malware/testfamily/versions/unknown/cases/" in message
    assert "field=behaviors[0]" in message
    assert "expected=object, actual=str" in message


@pytest.mark.parametrize(
    ("features", "expected"),
    [
        ({}, []),
        ({"behaviors": None}, []),
        ({"behaviors": [{"id": "execution:test"}]}, [{"id": "execution:test"}]),
    ],
)
def test_feature_records_accept_only_object_arrays(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    features: dict,
    expected: list[dict],
) -> None:
    digest, case = _case_fixture(tmp_path)
    monkeypatch.setattr(ui_data, "REPO_ROOT", tmp_path)

    assert ui_data._feature_object_records(
        features,
        "behaviors",
        sha256=digest,
        case_dir=case,
    ) == expected


def test_feature_records_reject_non_object_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    digest, case = _case_fixture(tmp_path)
    monkeypatch.setattr(ui_data, "REPO_ROOT", tmp_path)

    with pytest.raises(ValueError, match="expected=object, actual=list"):
        ui_data._feature_object_records(
            [],
            "behaviors",
            sha256=digest,
            case_dir=case,
        )
