"""主要な静的解析自動化API文書の日本語生成契約を検証する。"""

from __future__ import annotations

import importlib.util
import inspect
from pathlib import Path


REPOSITORY = Path(__file__).resolve().parents[2]
GENERATOR = REPOSITORY / "analysis-framework" / "docs" / "generate_common_api_docs.py"
SPEC = importlib.util.spec_from_file_location("generate_common_api_docs", GENERATOR)
assert SPEC is not None and SPEC.loader is not None
target = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(target)


def test_rendered_documents_are_japanese_and_cover_public_functions() -> None:
    """英語pydoc定型文を含めず、公開関数のanchorをすべて生成する。"""

    forbidden = (
        '<html lang="en">',
        "Methods defined here:",
        "Data descriptors defined here:",
        "Implement delattr",
        "Initialize self.",
    )
    target._prepare_imports()
    for module_name, source in target.MODULE_SOURCES.items():
        html = target.render_module(module_name)
        module = __import__(module_name)
        assert '<html lang="ja">' in html
        assert f'href="../../{source}"' in html
        assert not any(text in html for text in forbidden)
        assert str(REPOSITORY) not in html
        assert REPOSITORY.as_posix() not in html
        assert "WindowsPath(" not in html
        assert "PosixPath(" not in html
        public_functions = [
            name
            for name, member in inspect.getmembers(module, inspect.isfunction)
            if member.__module__ == module_name and not name.startswith("_")
        ]
        for name in public_functions:
            assert f'name="-{name}"' in html

    analyze_sample_html = target.render_module("analyze_sample")
    assert (
        "Path('&lt;repo-root&gt;/analysis-framework/registry/malware_types.json')"
        in analyze_sample_html
    )


def test_repository_path_normalization_is_stable_for_platform_spellings() -> None:
    """slash表記が異なるcheckout絶対pathも同じ象徴表現へ固定する。"""

    expected = "prefix/<repo-root>/analysis-framework/common/module.py"
    assert target._normalize_repository_paths(
        f"prefix/{REPOSITORY.as_posix()}/analysis-framework/common/module.py",
        replacement=target.REPOSITORY_PATH_PLACEHOLDER,
    ) == expected
    for path_class in ("WindowsPath", "PosixPath"):
        assert target._normalize_repository_paths(
            f"{path_class}('{REPOSITORY.as_posix()}/analysis-framework/common/module.py')",
            replacement=target.REPOSITORY_PATH_PLACEHOLDER,
        ) == "Path('<repo-root>/analysis-framework/common/module.py')"
    assert target._normalize_repository_paths(
        "prefix/"
        + str(REPOSITORY)
        + "/analysis-framework/common/module.py",
        replacement=target.REPOSITORY_PATH_PLACEHOLDER,
    ) == expected


def test_repository_path_normalization_handles_html_escaped_checkout(
    monkeypatch,
) -> None:
    """pydocがescapeした特殊文字付きcheckout pathも公開HTMLへ残さない。"""

    monkeypatch.setattr(target, "REPOSITORY", Path("C:/repo&name"))
    rendered = "WindowsPath('C:/repo&amp;name/analysis-framework/common/module.py')"

    assert target._normalize_repository_paths(
        rendered,
        replacement="&lt;repo-root&gt;",
    ) == "Path('&lt;repo-root&gt;/analysis-framework/common/module.py')"


def test_unknown_module_is_rejected() -> None:
    """任意moduleをimportして文書化する使い方を許可しない。"""

    try:
        target.render_module("not_allowlisted")
    except ValueError as exc:
        assert str(exc) == "API文書生成の対象外moduleです"
    else:
        raise AssertionError("対象外moduleが受理されました")
