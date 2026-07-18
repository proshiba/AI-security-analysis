"""難解析ケース用の日本語一行変換テスト。"""

from __future__ import annotations

from _ja_hard_case_patterns import translate_line


def test_exact_heading_and_table_translation() -> None:
    assert translate_line("# Deep static triage") == "# 難解析ケースの静的深掘り"
    assert translate_line("## Summary") == "## 集計"
    assert translate_line(
        "| SHA-256 | Family | Category | Status | Layers | Markers | "
        "Missing expected layers |"
    ) == (
        "| SHA-256 | ファミリー | 分類 | 状態 | レイヤー数 | マーカー | "
        "不足している想定レイヤー |"
    )


def test_layer_labels_translate_without_changing_values() -> None:
    digest = "a" * 64
    source = (
        f"- Layer {digest}: format=pe; markers=SmartAssembly; "
        "native-routing=managed_loader_obfuscation:suspected; "
        "managed-routing=resource_obfuscation"
    )
    target = translate_line(source)
    assert target == (
        f"- レイヤー {digest}: 形式=pe; マーカー=SmartAssembly; "
        "ネイティブルーティング=managed_loader_obfuscation:suspected; "
        "マネージドルーティング=resource_obfuscation"
    )
    for value in (
        digest,
        "pe",
        "SmartAssembly",
        "managed_loader_obfuscation:suspected",
        "resource_obfuscation",
    ):
        assert value in target


def test_unknown_line_is_unchanged() -> None:
    source = "Public analysis publication rules"
    assert translate_line(source) == source
