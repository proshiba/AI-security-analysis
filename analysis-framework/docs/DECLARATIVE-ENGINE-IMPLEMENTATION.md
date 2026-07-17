# 宣言型エンジンの実装

`asa/v1alpha1` の実装には、厳格な定義検証、決定的なDAGコンパイル、オフライン静的解析ランナーが含まれます。

## 実装済み機能

- 厳格なPydanticモデルとYAML読み込み
- 任意コードを実行できない条件DSL
- 重み付きファミリー／キャンペーン採点と、同点時にunknownとする処理
- 許可リスト方式でメジャーバージョンを管理するステップカタログ
- 依存関係検証と決定的なDAG順序
- オフライン能力ポリシーの適用
- 生ファイルと単一メンバー暗号化ZIPの受け入れ
- 正規化した探索結果と、レビュー済みファミリー／キャンペーン推定
- 受け入れ、インベントリ、文字列、IOC、PE、.NET、Go、スクリプト、ISO、ファミリー設定、レポートのオフライン実装
- FLOSSとGhidra MCPを自動実行しない可用性確認
- `validate`、`plan`、`asa-analyze` の各CLI
- 29件のマルウェア定義と31件のパイプライン

## オフライン解析の実行

```powershell
$env:PYTHONPATH = '<repo-root>\analysis-framework\src;<repo-root>'
python -m asa.runtime_cli `
  --sample C:\samples\submission.zip `
  --definitions .\analysis-framework\definitions `
  --output C:\analysis-output\case
```

レビュー済みの解析者ヒントは、任意の `--family-hint` と `--campaign-hint` で指定できます。未知または同点の分類は `needs_review` のままであり、ヒントによってポリシーやステップ検証を迂回することはありません。

出力:

- `facts.json`: 正規化した探索証拠
- `plan.json`: コンパイル済みファミリー／キャンペーンDAG
- `steps/<step-id>/result.json`: ステップごとの静的解析結果
- `run.json`: 最終的なステップ状態と安全フラグ

## 定義の検証

```powershell
python -m asa.cli validate --definitions .\analysis-framework\definitions
```

## コンパイルだけを実行

```powershell
python -m asa.cli plan `
  --definitions .\analysis-framework\definitions `
  --facts C:\analysis-output\discovery-facts.json `
  --policy offline-default `
  --output C:\analysis-output\plan.json
```

## 安全境界

- YAMLからPythonパス、PowerShell、シェルコマンドを指定することはできません。
- すべてのステップは、カタログの許可リストと宣言済みメジャーバージョンに一致しなければなりません。
- ポリシーが拒否した能力を、パイプラインまたはマルウェア定義から復活させることはできません。
- 未知または同点の分類を既知ハンドラーへ強制しません。
- 検体のバイト列は解析するだけで、実行可能コードとして起動またはロードしません。
- 実行時ステップは外部インフラへ接続しません。
- このリリースのFLOSSとGhidra MCPステップは事前確認だけです。
- ZIP内容はメモリに保持し、アーカイブのパストラバーサルを拒否します。
