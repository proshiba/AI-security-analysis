"""主要な静的解析自動化API文書の日本語生成契約を検証する。"""

from __future__ import annotations

import importlib.util
import importlib
import inspect
from html import escape
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
        module = importlib.import_module(module_name)
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


def test_managed_resource_boundary_modules_have_fixed_source_paths() -> None:
    """resource／構築前境界の5helperも任意importではなく固定sourceへ束縛する。"""

    modules = (
        "managed_resources",
        "dnfile_resource_adapter",
        "clr_input_binding",
        "managed_resource_snapshot",
        "managed_constructor_guard",
    )
    for name in modules:
        assert target.MODULE_SOURCES[f"unpackers.{name}"] == f"unpackers/{name}.py"
        assert (REPOSITORY / target.MODULE_SOURCES[f"unpackers.{name}"]).is_file()


def test_cli_generates_only_selected_fixed_modules(tmp_path, monkeypatch) -> None:
    """指定moduleだけを更新し、重複指定と他の既存文書を変更しない。"""

    output = tmp_path / "docs" / "pydoc"
    output.mkdir(parents=True)
    unrelated = output / "unrelated.html"
    unrelated.write_text("既存文書", encoding="utf-8")
    monkeypatch.setattr(target, "REPOSITORY", tmp_path)
    monkeypatch.setattr(target, "render_module", lambda name: f"対象:{name}\n")
    monkeypatch.setattr(target.sys, "argv", ["generator", "--module", "unpackers.profiled_transform", "--module", "unpackers.profiled_transform"])
    assert target.main() == 0
    assert (output / "unpackers.profiled_transform.html").read_text(encoding="utf-8") == "対象:unpackers.profiled_transform\n"
    assert unrelated.read_text(encoding="utf-8") == "既存文書"
    assert sorted(path.name for path in output.iterdir()) == ["unpackers.profiled_transform.html", "unrelated.html"]


def test_cli_check_does_not_write_missing_document(tmp_path, monkeypatch) -> None:
    """対象限定checkは差分を報告するだけでfileを作らない。"""

    monkeypatch.setattr(target, "REPOSITORY", tmp_path)
    monkeypatch.setattr(target, "render_module", lambda _name: "未生成文書")
    monkeypatch.setattr(target.sys, "argv", ["generator", "--module", "unpackers.profiled_transform", "--check"])
    assert target.main() == 1
    assert not (tmp_path / "docs").exists()


def test_callable_defaults_have_stable_symbolic_names() -> None:
    """callback既定値のアドレスだけを除き、通常の文字列内容は改変しない。"""

    def callback(value):
        return value

    def routine(handler=callback, message="literal at 0x12345"):
        """安定したsignatureの合成関数。"""

    rendered = target._render_routine(target.pydoc.HTMLDoc(), "routine", routine)
    assert hex(id(callback)) not in rendered
    assert escape(callback.__qualname__) in rendered
    assert "literal at 0x12345" in rendered
    signature = target._signature(routine)
    assert signature is not None and hex(id(callback)) not in signature
    assert "literal at 0x12345" in signature


def test_static_layer_document_has_no_function_memory_address() -> None:
    html = target.render_module("static_layer_pipeline")
    assert "static_layer_pipeline._identity" in html
    assert " at 0x" not in html
