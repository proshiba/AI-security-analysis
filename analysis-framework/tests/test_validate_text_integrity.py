from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys


MODULE_PATH = Path(__file__).resolve().parents[1] / "common" / "validate_text_integrity.py"
SPEC = importlib.util.spec_from_file_location("validate_text_integrity", MODULE_PATH)
assert SPEC and SPEC.loader
target = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = target
SPEC.loader.exec_module(target)


def test_valid_utf8_japanese_passes(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("# 日本語の解析結果\n", encoding="utf-8")

    result = target.validate_text_integrity(tmp_path)

    assert result["complete"] is True
    assert result["finding_count"] == 0


def test_invalid_utf8_fails(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_bytes(b"# \xff\n")

    result = target.validate_text_integrity(tmp_path)

    assert result["complete"] is False
    assert result["findings"][0]["code"] == "invalid_utf8"


def test_mojibake_and_question_mark_replacement_fail(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("# 縺薙ｌ縺ｯ ???\n", encoding="utf-8")

    result = target.validate_text_integrity(tmp_path)

    assert result["complete"] is False
    assert {item["code"] for item in result["findings"]} == {
        "japanese_mojibake",
        "question_mark_run",
    }


def test_raw_provider_filename_is_not_treated_as_document_corruption(
    tmp_path: Path,
) -> None:
    path = tmp_path / "analysis-results" / "collections" / "malwarebazaar-test" / "manifest.json"
    path.parent.mkdir(parents=True)
    path.write_text(
        json.dumps(
            {"file_name": "?????.exe", "summary": "日本語の説明"},
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    result = target.validate_text_integrity(tmp_path)

    assert result["complete"] is True


def test_human_json_value_is_checked(tmp_path: Path) -> None:
    path = tmp_path / "report.json"
    path.write_text(json.dumps({"summary": "???"}), encoding="utf-8")

    result = target.validate_text_integrity(tmp_path)

    assert result["complete"] is False
    assert result["findings"][0]["code"] == "question_mark_run"


def test_generated_ui_data_checks_docs_but_allows_raw_provider_name(
    tmp_path: Path,
) -> None:
    path = tmp_path / "ui" / "data.js"
    path.parent.mkdir(parents=True)
    value = {
        "cases": [
            {
                "file_name_raw": "?????.exe",
                "docs": {"readme": "# ???\n"},
            }
        ]
    }
    path.write_text(
        "window.ASA_DATA = " + json.dumps(value, ensure_ascii=False) + ";\n",
        encoding="utf-8",
    )

    result = target.validate_text_integrity(tmp_path)

    assert result["complete"] is False
    assert len(result["findings"]) == 1
    assert result["findings"][0]["code"] == "question_mark_run"
