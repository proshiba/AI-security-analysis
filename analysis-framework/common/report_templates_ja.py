"""一括静的解析レポートの日本語テンプレート。"""

from __future__ import annotations

import json


_OMITTED_CONFIG_KEYS = {
    "decoded_strings",
    "recovered_layer_configs",
    "selected_layer_config",
    "source_name",
}


def _compact_config(config: dict) -> dict:
    """巨大な復号文字列を除き、公開に必要な設定だけを返す。"""
    output = {
        key: value
        for key, value in config.items()
        if key not in _OMITTED_CONFIG_KEYS and value not in (None, "", [], {})
    }
    selected = config.get("selected_layer_config")
    if isinstance(selected, dict) and isinstance(selected.get("config"), dict):
        output["selected_recovered_layer"] = {
            "sha256": selected.get("sha256"),
            "kind": selected.get("kind"),
            "depth": selected.get("depth"),
            "config": _compact_config(selected["config"]),
        }
    return output


def _finding_rows(findings: list[dict]) -> str:
    if not findings:
        return "| 回収なし | - | - | 静的抽出では有効な通信候補を確認できず |"
    return "\n".join(
        f"| `{row.get('value', '-')}` | `{row.get('role', '-')}` | "
        f"`{row.get('confidence', '-')}` | `{row.get('source', '-')}` |"
        for row in findings
    )


def _static_logic(item: dict, case: dict) -> str:
    """正規化済み証拠から、実行を伴わない処理ロジックの説明を組み立てる。"""
    unpack = case.get("unpack", {})
    result = case.get("config", {})
    config = result.get("config", {})
    layers = case.get("layers", {}).get("layers", [])
    file_format = item.get("format", unpack.get("format", "unknown"))
    size = unpack.get("size")
    entropy = unpack.get("entropy")
    size_text = f"{size}バイト" if isinstance(size, int) else "不明"
    entropy_text = f"{entropy:.4f}" if isinstance(entropy, (int, float)) else "不明"
    lines = [
        f"- 外層: `{file_format}`形式（{size_text}、エントロピー{entropy_text}）として解析しました。"
        f" 配布形態ラベルは`{item.get('campaign', 'unknown')}`です。"
    ]

    pe = unpack.get("pe")
    if isinstance(pe, dict) and pe:
        machine = pe.get("machine", "unknown")
        architecture = {
            "0x14c": "x86-32",
            "0x8664": "x86-64",
            "0xaa64": "ARM64",
        }.get(machine, machine)
        runtime = (
            ".NET管理コード"
            if pe.get("is_dotnet")
            else "Goバイナリ"
            if pe.get("is_go")
            else "ネイティブPE"
        )
        libraries = pe.get("import_libraries") or []
        library_text = ", ".join(f"`{value}`" for value in libraries[:8]) or "取得なし"
        lines.append(
            f"- PE構造: {architecture}の{runtime}で、インポート{pe.get('imports', 0)}件、"
            f"主要ライブラリは{library_text}です。エントリポイント節は"
            f"`{pe.get('entrypoint_section', 'unknown')}`、節数は{len(pe.get('sections') or [])}です。"
        )
        overlay_size = pe.get("overlay_size", 0)
        resource_count = pe.get("resource_count", 0)
        lines.append(
            f"- アンパック: 判定は`{pe.get('classification', item.get('packing_classification', 'unknown'))}`で、"
            f"オーバーレイ{overlay_size}バイト、リソース{resource_count}件を検査しました。"
        )
        flow = pe.get("control_flow_triage")
        if isinstance(flow, dict) and flow.get("status") == "analyzed":
            metrics = flow.get("metrics", {})
            lines.append(
                "- 制御フロー: エントリポイント到達範囲を逆アセンブルし、"
                f"基本ブロック{metrics.get('basic_blocks', 0)}個、命令{metrics.get('instructions', 0)}個、"
                f"call {metrics.get('calls', 0)}個、分岐{metrics.get('branch_instructions', 0)}個を確認しました。"
                "これは制御フローの静的走査であり、CPUエミュレーションではありません。"
            )
    elif file_format == "script":
        script_result = next(
            (
                unpack.get(key)
                for key in (
                    "javascript_plain_string_array",
                    "javascript_string_array",
                    "javascript_dropper",
                )
                if isinstance(unpack.get(key), dict)
                and unpack[key].get("status") not in {None, "pattern_not_found"}
            ),
            None,
        )
        if script_result:
            lines.append(
                "- スクリプト: 実行せずに難読化構造を解き、"
                f"状態`{script_result.get('status', 'unknown')}`、文字列配列"
                f"{script_result.get('array_size', 0)}要素、置換{script_result.get('substitutions', 0)}件を確認しました。"
            )
        else:
            lines.append("- スクリプト: 既知の難読化構造を静的照合しましたが、復号対象は確定できませんでした。")
    else:
        lines.append("- 形式別走査: 文字列、コンテナ、埋め込みオブジェクトを静的に検査しました。")

    if layers:
        kinds = ", ".join(dict.fromkeys(f"`{row.get('kind', 'unknown')}`" for row in layers))
        lines.append(
            f"- 復元層: 再帰展開で{len(layers)}層を回収しました（{kinds}）。各層は同じ静的抽出器へ再入力し、"
            "回収バイナリ自体は公開していません。"
        )
    else:
        lines.append("- 復元層: 追加レイヤーは回収できず、外層に対して設定抽出を行いました。")

    findings = result.get("findings", [])
    if config.get("static_config_recovered"):
        lines.append(
            f"- 設定/C2: ファミリ固有構造から静的設定を復元し、ネットワーク所見{len(findings)}件を記録しました。"
            "値の埋め込みは確認済みですが、現在の到達性や所有者は未確認です。"
        )
    elif findings:
        lines.append(
            f"- 設定/C2: 静的文字列または復元層から所見{len(findings)}件を得ましたが、"
            "復号済みファミリ設定ではないため候補に留めています。"
        )
    else:
        lines.append(
            "- 設定/C2: ファミリ固有の復号済み設定または十分なネットワーク相関は得られず、"
            "提供元ラベルだけからC2や実機能を断定していません。"
        )
    lines.append(
        "以上はファイル構造、逆アセンブル、文字列復号、回収層から再構成した静的ロジックです。"
        "実行時分岐、メモリー内復号、最終ペイロードの挙動は未確認です。"
    )
    return "\n\n".join(lines)


def render_case(item: dict, case: dict) -> str:
    """1検体の根拠と限界を区別した日本語レポートを生成する。"""
    result = case["config"]
    config = result.get("config", {})
    layers = case.get("layers", {}).get("layers", [])
    layer_rows = "\n".join(
        f"| {row.get('depth', '-')} | `{row.get('kind', 'unknown')}` | "
        f"`{row.get('sha256', 'unknown')}` | {row.get('size', 0)} | "
        f"`{row.get('format', 'unknown')}` |"
        for row in layers
    ) or "| - | 回収なし | - | - | - |"
    limitation_rows = [
        "- 検体と回収レイヤーは実行していません。",
        "- 外部インフラへの接続と能動スキャンは行っていません。",
    ]
    if not config.get("static_config_recovered"):
        limitation_rows.append(
            "- 復号済み静的設定は回収できず、パッキングまたは別方式への対応が必要です。"
        )
    if result.get("limitations"):
        limitation_rows.append(
            f"- 抽出器が報告した{len(result['limitations'])}件の詳細制約は `analysis.json` に保持しています。"
        )
    limitations = "\n".join(limitation_rows)
    compact = _compact_config(config)
    source_attribution = item.get("family", "unknown")
    return f'''# {source_attribution} ケース {item["sha256"]}

## 概要

- 元ファイル名: `{item.get("name", "unknown")}`
- SHA-256: `{item["sha256"]}`
- 提供元ファミリ分類: `{source_attribution}`
- 配布・外層の形: `{item.get("campaign", "unknown")}`
- 形式: `{item.get("format", "unknown")}`
- パッキングの疑い: `{str(item.get("packing_suspected", False)).lower()}`
- パッキング分類: `{item.get("packing_classification", "unknown")}`
- アンパック状態: `{item.get("unpack_status", "unknown")}`
- 静的設定の回収: `{str(bool(config.get("static_config_recovered"))).lower()}`
- プロファイル文字列の相関: `{str(bool(config.get("profile_literal_correlation"))).lower()}`
- 検体の実行: `false`
- 外部ネットワーク接続: `false`


## 静的実行ロジック（根拠別）

{_static_logic(item, case)}

提供元の分類名だけではファミリ本体の静的確認になりません。設定、プロトコル、複数の独立した文字列などを回収できた場合だけ、対応する項目を確認済みとして扱います。

## 静的解析結果

```json
{json.dumps(compact, ensure_ascii=False, indent=2)}
```

巨大な復号文字列や回収バイナリは公開レポートへ埋め込まず、正規化した解析データを `analysis.json` に保持します。

## 設定とC2の証拠

| 値 | 役割 | 確度 | 根拠 |
|---|---|---|---|
{_finding_rows(result.get("findings", []))}

候補の到達性や稼働状態は確認していません。証明書、文書スキーマ、更新配布先などの一般的なURLはC2として扱いません。

## 回収レイヤー

| 深さ | 種別 | SHA-256 | サイズ | 形式 |
|---:|---|---|---:|---|
{layer_rows}

回収したバイナリそのものはリポジトリへコミットしません。

## 制約

{limitations}
'''


def render_family(value: dict, case_links: dict[str, str] | None = None) -> str:
    """1ファミリ分の件数、根拠、検出上の注意を日本語でまとめる。"""
    links = case_links or {
        item["sha256"]: f"cases/{item['sha256']}/README.md"
        for item in value["cases"]
    }
    campaigns = "\n".join(
        f"- `{key}`: {count}件" for key, count in value.get("campaigns", {}).items()
    ) or "- 分類できた配布形態はありません。"
    features = "\n".join(
        f"- `{key}`: {count}/{value['case_count']}件"
        for key, count in value.get("features", {}).items()
    ) or "- 静的に確認できた共通挙動はありません。"
    config_values = "\n".join(
        f"- `{key}`: " + ", ".join(
            f"`{config_value}` ({count}件)" for config_value, count in values.items()
        )
        for key, values in value.get("config_values", {}).items()
    ) or "- 検証済みの共通設定値は回収できませんでした。"
    cases = "\n".join(
        f"| [{item['sha256'][:12]}]({links[item['sha256']]}) | "
        f"`{item.get('format', 'unknown')}` | `{item.get('campaign', 'unknown')}` | "
        f"{item.get('recovered_artifacts', 0)} | {item.get('config_findings', 0)} |"
        for item in value["cases"]
    )
    counts = value.get("counts", {})
    return f'''# {value["signature"]} 追加静的解析

`{value.get("source", "unknown")}` の分類に基づく{value["case_count"]}検体を、実行せずに解析しました。提供元ラベル、配布外層、静的に確認したファミリ本体を分離して記録しています。

## 集計

- ケース数: {value["case_count"]}
- エラー: {counts.get("errors", 0)}件
- パッキングの疑い: {counts.get("packing_suspected", 0)}件
- 回収レイヤーあり: {counts.get("with_recovered_artifacts", 0)}件
- 静的設定を回収: {counts.get("with_static_config", 0)}件
- 通信・設定候補あり: {counts.get("with_config_findings", 0)}件
- 検体の実行: `false`
- 外部ネットワーク接続: `false`

## 配布形態

{campaigns}

## 静的に確認した共通挙動

{features}

## 検証済み設定値

{config_values}

## C2・通信候補

| 値 | 役割 | 確度 | 根拠 |
|---|---|---|---|
{_finding_rows(value.get("findings", []))}

候補を能動的に照会していません。到達性はファミリ同定の根拠にならず、C2であることも意味しません。

## ケース一覧

| SHA-256 | 形式 | 配布・外層の形 | 回収物 | 通信・設定候補 |
|---|---|---|---:|---:|
{cases}

## 検知時の考慮事項

- 単一の一般文字列、証明書URL、正規ソフトウェア名だけではファミリを確定しません。
- 提供元ラベルしかないケースは、静的確認済みの既知ハッシュへ昇格しません。
- 復号済み設定やプロトコル相関がない通信先は候補として扱います。
- 暗号化または難読化された終端レイヤーは、追加のアンパックが必要な未完了点として残します。
'''
