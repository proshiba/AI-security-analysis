#!/usr/bin/env python3
"""Generate publish-safe family and case reports from offline stealer results."""

from __future__ import annotations

import argparse
from collections import Counter
import json
import os
from pathlib import Path
from typing import Any

from malwarebazaar_batch import public_manifest
from result_publication import (
    PublicationError,
    detect_publication_context,
    publication_case_path,
    register_publication_cases,
)

OMITTED_CONFIG_KEYS = {
    "decoded_strings",
    "recovered_layer_configs",
    "selected_layer_config",
    "source_name",
}
AGGREGATE_CONFIG_KEYS = {
    "build_id",
    "campaign_id",
    "c2_urls",
    "delivery_profile",
    "group_id",
    "group_name",
    "install_directory",
    "install_filename",
    "profile",
    "version",
}


def load_case(case_dir: Path) -> dict:
    """Load one normalized case without recovered sample bytes."""
    layers_path = case_dir / "layers.json"
    return {
        "config": json.loads((case_dir / "config.json").read_text(encoding="utf-8")),
        "c2": json.loads((case_dir / "c2-candidates.json").read_text(encoding="utf-8")),
        "unpack": json.loads((case_dir / "unpack.json").read_text(encoding="utf-8")),
        "layers": json.loads(layers_path.read_text(encoding="utf-8")) if layers_path.exists() else {"layers": []},
    }


def compact_config(config: dict[str, Any]) -> dict[str, Any]:
    """Return publish-useful config fields while omitting bulky decoded buffers."""
    output: dict[str, Any] = {}
    for key, value in config.items():
        if key in OMITTED_CONFIG_KEYS or value in (None, "", [], {}):
            continue
        output[key] = value
    selected = config.get("selected_layer_config")
    if isinstance(selected, dict) and isinstance(selected.get("config"), dict):
        output["selected_recovered_layer"] = {
            "sha256": selected.get("sha256"),
            "kind": selected.get("kind"),
            "depth": selected.get("depth"),
            "config": compact_config(selected["config"]),
        }
    return output


def _aggregate_config_values(config: dict[str, Any], values: dict[str, Counter]) -> None:
    """Count stable scalar and list config values for the family overview."""
    selected = config.get("selected_layer_config")
    candidates = [config]
    if isinstance(selected, dict) and isinstance(selected.get("config"), dict):
        candidates.append(selected["config"])
    for candidate in candidates:
        for key in AGGREGATE_CONFIG_KEYS:
            value = candidate.get(key)
            items = value if isinstance(value, list) else [value]
            for item in items:
                if isinstance(item, (str, int)) and item not in ("", None):
                    values[key][str(item)] += 1


def summarize_family(summary: dict, pipeline_root: Path) -> dict:
    """Aggregate campaigns, formats, features, and findings across analyzed cases."""
    campaigns, formats, features, findings = Counter(), Counter(), Counter(), []
    config_values: dict[str, Counter] = {key: Counter() for key in sorted(AGGREGATE_CONFIG_KEYS)}
    cases = []
    for item in summary["cases"]:
        case = load_case(pipeline_root / item["sha256"])
        campaigns[item["campaign"]] += 1
        formats[item["format"]] += 1
        config = case["config"]["config"]
        for feature, present in config.get("features", {}).items():
            if present:
                features[feature] += 1
        _aggregate_config_values(config, config_values)
        findings.extend(case["config"].get("findings", []))
        cases.append(
            {
                **item,
                "limitations": case["config"].get("limitations", []),
                "layer_count": len(case["layers"].get("layers", [])),
            }
        )
    unique_findings = []
    seen = set()
    for finding in findings:
        key = (finding.get("kind"), finding.get("value"), finding.get("role"))
        if key not in seen:
            seen.add(key)
            unique_findings.append(finding)
    return {
        "schema_version": 1,
        "family": summary["family"],
        "signature": summary["signature"],
        "source": summary.get("source", "local-offline-intake"),
        "counts": summary.get("counts", {}),
        "case_count": len(cases),
        "campaigns": dict(sorted(campaigns.items())),
        "formats": dict(sorted(formats.items())),
        "features": dict(sorted(features.items())),
        "config_values": {key: dict(sorted(counter.items())) for key, counter in config_values.items() if counter},
        "findings": unique_findings,
        "cases": cases,
        "sample_executed": False,
        "network_contacted": False,
    }


def render_case(item: dict, case: dict) -> str:
    """Render a compact, evidence-qualified case README."""
    findings = case["config"].get("findings", [])
    finding_rows = (
        "\n".join(
            f"| `{row['value']}` | `{row['role']}` | `{row['confidence']}` | `{row['source']}` |" for row in findings
        )
        or "| 復元なし | - | - | 静的抽出が未完了 |"
    )
    limitations = (
        "\n".join(f"- 制約事項: {value}" for value in case["config"].get("limitations", [])) or "- 特記事項なし"
    )
    layers = case["layers"].get("layers", [])
    layer_rows = (
        "\n".join(
            f"| {row.get('depth', '-')} | `{row.get('kind', 'unknown')}` | "
            f"`{row.get('sha256', 'unknown')}` | {row.get('size', 0)} | "
            f"`{row.get('format', 'unknown')}` |"
            for row in layers
        )
        or "| - | 復元なし | - | - | - |"
    )
    config = compact_config(case["config"].get("config", {}))
    return f"""# {item["family"]} ケース {item["sha256"]}

## 概要

- 元ファイル名: `{item["name"]}`
- SHA-256: `{item["sha256"]}`
- キャンペーン形態: `{item["campaign"]}`
- 形式: `{item["format"]}`
- パッキングの疑い: `{str(item["packing_suspected"]).lower()}`
- パッキング分類: `{item.get("packing_classification", "unknown")}`
- アンパック状態: `{item.get("unpack_status", "unknown")}`
- 復元した静的レイヤー数: {item["recovered_artifacts"]}
- 検体の実行: `false`
- ネットワーク接続: `false`

## 設定とC2の証拠

| 値 | 役割 | 確度 | 根拠 |
|---|---|---|---|
{finding_rows}

埋め込み値だけでは、サーバーが稼働中であることや、このファミリーだけが制御していることを証明できません。

## 静的設定のスナップショット

```json
{json.dumps(config, ensure_ascii=False, indent=2)}
```

範囲を限定した復号文字列の証拠を含む、正規化済み抽出器出力の完全版は `analysis.json` に保持します。

## 復元したレイヤー

| 深さ | 種別 | SHA-256 | サイズ | 形式 |
|---:|---|---|---:|---|
{layer_rows}

復元したバイト列は意図的にコミットしません。

## アンパックの詳細

- ルートのエントロピー: {case["unpack"]["entropy"]}
- ルートのパッキング評価: `{case["unpack"].get("pe", {}).get("packing_suspected", False)}`
- 解析した再帰レイヤー数: {case["config"].get("layers_analyzed", 0)}
- 7zの状態: `{case["unpack"].get("sevenzip", {}).get("status", "not_applicable")}`
- UPXの状態: `{case["unpack"].get("upx", {}).get("status", "not_applicable")}`

## 制約

{limitations}
"""


def render_family(
    value: dict, case_links: dict[str, str] | None = None
) -> str:
    """Render a family README with detection trade-offs and all case outcomes."""
    links = case_links or {
        item["sha256"]: f"cases/{item['sha256']}/README.md"
        for item in value["cases"]
    }
    campaigns = "\n".join(f"- `{key}`: {count}" for key, count in value["campaigns"].items())
    features = (
        "\n".join(f"- `{key}`: {count}/{value['case_count']}" for key, count in value["features"].items())
        or "- 静的に確認できる挙動特徴はありません"
    )
    findings = (
        "\n".join(
            f"| `{row['value']}` | `{row['role']}` | `{row['confidence']}` | `{row['source']}` |"
            for row in value["findings"]
        )
        or "| 復元なし | - | - | パック／暗号化済み、またはリテラル設定なし |"
    )
    config_values = (
        "\n".join(
            f"- `{key}`: " + ", ".join(f"`{config_value}` ({count})" for config_value, count in values.items())
            for key, values in value["config_values"].items()
        )
        or "- 検証済みファミリー設定値は復元されませんでした"
    )
    cases = "\n".join(
        f"| [{item['sha256'][:12]}]({links[item['sha256']]}) | `{item['format']}` | "
        f"`{item['campaign']}` | `{str(item['packing_suspected']).lower()}` | {item['recovered_artifacts']} | "
        f"{item['config_findings']} |"
        for item in value["cases"]
    )
    return f"""# {value["signature"]}解析

`{value["source"]}` 由来の提出物{value["case_count"]}件を静的解析しました。ローダー、パッカー、運用者はそれぞれ独立して変化し得るため、配布形態とマルウェアファミリーを分離して扱います。

## 一括解析の結果

- ケース数: {value["case_count"]}
- エラー数: {value["counts"].get("errors", 0)}
- パッキングが疑われるケース数: {value["counts"].get("packing_suspected", 0)}
- 成果物を復元したケース数: {value["counts"].get("with_recovered_artifacts", 0)}
- 検証済み静的設定を持つケース数: {value["counts"].get("with_static_config", 0)}
- 検体の実行: `false`
- ネットワーク接続: `false`

## キャンペーン／配布形態

{campaigns}

## 静的に観測した挙動特徴

{features}

## C2／設定の所見

| 値 | 役割 | 確度 | 根拠 |
|---|---|---|---|
{findings}

能動的なC2チェックインは実施していません。オフライン評価と受動的な照会生成には `analysis-framework/common/c2_candidate_detector.py` を使用してください。

## 検証済み設定値

{config_values}

## ケース一覧

| SHA-256 | 形式 | キャンペーン | パック済み | レイヤー数 | 所見数 |
|---|---|---|---:|---:|---:|
{cases}

## 検知時の考慮事項

- **誤検知リスク高:** ブラウザデータベース、ウォレット、`osascript` への一般的なアクセス、Goランタイム文字列、高エントロピーPEセクション。バックアップ、移行、企業資産管理、インストーラー、正規Goアプリケーションも一致し得ます。
- **誤検知リスク中:** スクリプトインタープリター、ネットワークダウンロード、実行の組み合わせ、または複数のブラウザ／ウォレット保存領域を読む未署名プロセス。管理自動化やソフトウェア配布と重なる場合があります。
- **誤検知リスク低:** ファミリー固有文字列、レビュー済み設定パス／ホスト、資格情報保存領域の収集、異常な親子関係またはネットワーク文脈を組み合わせます。ビルダー／バージョン変更による見逃しはなお起こり得ます。

`rules/` 配下の検知ルールは出発点であり、環境に合わせた調整が必要です。C2リテラルは永続的なファミリーシグネチャではなく、短期間のIOC一致として使用してください。

## 安全性と制約

- 検体は一度も実行しておらず、復元レイヤーもコミットしていません。
- 外部インフラには接続していません。
- 未知のパッカーとパスワード保護された入れ子アーカイブは未解決です。
- 情報源による帰属と検証済み静的証拠を分離して保持します。
"""


def generate(
    summary_path: Path,
    pipeline_root: Path,
    destination: Path,
    acquisition_manifest: Path | None = None,
) -> dict:
    """Write one family index plus normalized per-case reports and JSON."""
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    value = summarize_family(summary, pipeline_root)
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "summary.json").write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if acquisition_manifest:
        manifest = public_manifest(json.loads(acquisition_manifest.read_text(encoding="utf-8")))
        (destination / "malwarebazaar-manifest.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
    canonical_context = None
    try:
        canonical_context = detect_publication_context(destination, destination.name)
    except PublicationError:
        if any(
            parent.name == "analysis-results"
            for parent in destination.resolve().parents
        ):
            raise
    case_links: dict[str, str] = {}
    published_cases: list[Path] = []
    for item in value["cases"]:
        case = load_case(pipeline_root / item["sha256"])
        if canonical_context is None:
            case_root = destination / "cases" / item["sha256"]
        else:
            case_root, resolved_context = publication_case_path(
                destination, canonical_context.family, item["sha256"]
            )
            if resolved_context != canonical_context:
                raise PublicationError(
                    "publication context changed during generation"
                )
        case_root.mkdir(parents=True, exist_ok=True)
        case_links[item["sha256"]] = Path(
            os.path.relpath(case_root / "README.md", destination)
        ).as_posix()
        (case_root / "README.md").write_text(render_case(item, case), encoding="utf-8")
        (case_root / "analysis.json").write_text(
            json.dumps(
                {"schema_version": 1, "case": item, **case},
                ensure_ascii=False,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        published_cases.append(case_root)
    (destination / "README.md").write_text(
        render_family(value, case_links), encoding="utf-8"
    )
    if canonical_context is not None:
        register_publication_cases(canonical_context, published_cases)
    return value


def build_parser() -> argparse.ArgumentParser:
    """Build the report-generation parser."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--summary", required=True, type=Path)
    parser.add_argument("--pipeline-root", required=True, type=Path)
    parser.add_argument("--destination", required=True, type=Path)
    parser.add_argument("--acquisition-manifest", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Generate one family report tree."""
    args = build_parser().parse_args(argv)
    value = generate(args.summary, args.pipeline_root, args.destination, args.acquisition_manifest)
    print(json.dumps({"family": value["family"], "cases": value["case_count"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
