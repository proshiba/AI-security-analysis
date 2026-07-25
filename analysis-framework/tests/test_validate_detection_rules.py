from __future__ import annotations

from pathlib import Path

import pytest

import validate_detection_rules


SIGMA_DOCUMENT = """\
title: テスト用Sigmaルール
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\\\example.exe'
  condition: selection
"""


def test_validate_sigma_file_accepts_single_document(tmp_path: Path) -> None:
    path = tmp_path / "single.yml"
    path.write_text(SIGMA_DOCUMENT, encoding="utf-8")

    assert validate_detection_rules.validate_sigma_file(path) == 1


def test_validate_sigma_file_accepts_multiple_documents_and_skips_empty_ones(
    tmp_path: Path,
) -> None:
    path = tmp_path / "multiple.yml"
    path.write_text(
        f"---\n{SIGMA_DOCUMENT}---\n\n---\n{SIGMA_DOCUMENT}---\n",
        encoding="utf-8",
    )

    assert validate_detection_rules.validate_sigma_file(path) == 2


def test_validate_sigma_file_reports_invalid_document_number(
    tmp_path: Path,
) -> None:
    path = tmp_path / "invalid.yml"
    path.write_text(
        f"{SIGMA_DOCUMENT}---\ntitle: detectionがない文書\nlogsource: {{}}\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match=r"document 2"):
        validate_detection_rules.validate_sigma_file(path)


def test_validate_sigma_file_reports_yaml_error_document_number(
    tmp_path: Path,
) -> None:
    path = tmp_path / "invalid-syntax.yml"
    path.write_text(
        f"{SIGMA_DOCUMENT}---\nlogsource: {{}}\ndetection: [\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match=r"document 2"):
        validate_detection_rules.validate_sigma_file(path)


def test_main_keeps_yara_compilation_and_single_document_compatibility(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    (tmp_path / "single.yml").write_text(SIGMA_DOCUMENT, encoding="utf-8")
    (tmp_path / "single.yar").write_text(
        "rule validator_regression { condition: true }\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "sys.argv",
        ["validate_detection_rules.py", "--results-root", str(tmp_path)],
    )

    assert validate_detection_rules.main() == 0
    assert capsys.readouterr().out == (
        "PASS: parsed 1 Sigma YAML files and compiled 1 YARA files\n"
    )
