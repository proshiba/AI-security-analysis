# 一括静的解析と解析器適用可否判定

`common/analyze_sample.py` は、検体または検体ディレクトリを渡すと、入力認証、SHA-256重複排除、全登録検出器の評価、既存解析器の適用可否判定、汎用静的トリアージ、ファミリー固有設定抽出、統合レポート生成を1回で行います。検体を実行せず、外部ホストにも接続しません。

## 推奨コマンド

```powershell
python .\analysis-framework\common\analyze_sample.py `
  --input C:\malware-lab\incoming `
  --output C:\malware-lab\analysis-output
```

既存のPowerShell入口も、追加オプションがない場合は同じ処理へ委譲します。

```powershell
.\analysis-framework\Invoke-Analysis.ps1 `
  -Sample C:\malware-lab\incoming\sample.zip `
  -OutputDirectory C:\malware-lab\analysis-output `
  -Python .\analysis-framework\.venv\Scripts\python.exe
```

複数のファイルまたはディレクトリは `--input` を繰り返して指定します。同一SHA-256は1回だけ解析し、1検体のエラーで残りを停止しません。

## 処理順

1. symlinkと出力ディレクトリを除外し、ファイル数・ファイルサイズ上限を確認する。
2. `auto`モードでは、暗号化された単一メンバーZIPだけをMalwareBazaar受け入れ用外装として認証し、内包物をメモリ内で読む。通常のZIP bundleは構造検出のため外装のまま扱う。
3. 既存の静的アンパッカーでPE埋め込み物、ZIPメンバー、スクリプトの静的復号結果などをメモリ内で最大3層まで再帰復元する。層数、個別サイズ、総復元量に上限を適用し、復元本文は保存しない。
4. ルート検体と各復元層に対して `registry/malware_types.json` の全検出器を評価し、既知SHA-256、構造一致、曖昧性、検出器エラーを分離する。
5. `malware/**` と `extractors/**` にある既存の `extract_config`、`extract`、`analyze`、`extract_directory` 関数をASTで棚卸しし、共通バイト列APIへ適合するか判定する。
6. いずれかの層で一意に選択されたファミリーの標準解析器だけをimport前検証し、全層へ失敗分離付きで試行する。設定、IOC、ファミリー情報などの静的証拠が最も強い成功結果を採用し、同点ではルートに近い層を優先する。
7. 結果から資格情報、メールアドレス、URLのuserinfo・query・fragment、復元バイナリ本文を除去してJSONへ保存する。unknown、同確度競合、キャンペーン不一致では特殊解析器を強制しない。
8. 静的結果から関数／スクリプト単位のロジックを構造化し、正規化hashとSimHashを付ける。バイナリで関数解析が未実施の場合は要追加解析として明示する。
9. 挙動・検体特徴profileを作り、登録済みの強いcampaign fingerprintと一致する場合だけ自動labelを付ける。

## 適用状態

各caseの `applicability.json` は、過去に作成した解析関数を次の状態で列挙します。

| 状態 | 意味 |
|---|---|
| `applicable` | 検出器が一意に選択したファミリーの標準解析器。自動実行対象 |
| `applicable_forced` | `--family` で解析者が明示したファミリーの標準解析器。構造一致の代替証拠ではない |
| `not_applicable` | 別ファミリー用のため実行しない |
| `manual_review` | 未登録ファミリー、キャンペーン専用、派生版専用などのため自動流用しない |
| `unsupported_interface` | Path入力、追加の必須引数など、インメモリ共通APIへ未移行 |

対応件数は `summary.json` と `applicability.json` の `catalog` に記録します。件数はリポジトリ内スクリプトの追加・移行に応じて自動更新されるため、固定値を文書へ転記しません。

`applicability.json` の `family_coverage` は、登録済み検出器と既存解析器の対応をファミリー単位でも示します。`automatic_handler_available`、`manual_or_unsupported_only`、`no_handler_implemented`、`handler_without_registered_detector` を区別するため、解析関数が未実装のファミリーや検出器未登録の過去スクリプトも見落としません。

## 主な出力

```text
<output>/
  summary.json
  cases/<sha256>/
    report.json
    static-layers.json
    classification.json
    applicability.json
    generic-triage.json
    features.json
    FEATURES.md
    static-logic.json
    STATIC-LOGIC.md
    campaign-labels.json
    handlers/<family>-<handler-id-hash>.json
```

- `summary.json`: 入力数、解析数、重複数、入力エラー数、識別数、汎用解析段階の失敗数、解析器成功・失敗数
- `static-layers.json`: 静的復元の親子関係、方法、上限適用状況。復元本文は含まない
- `classification.json`: ルートと全復元層の検出器評価、選択ファミリー、キャンペーン、曖昧性、判定根拠
- `applicability.json`: 全既存解析器の対応状況とimport前検証結果
- `generic-triage.json`: 形式、hash、entropy、PE／ELF／script構造、未確認の静的IOC候補
- `features.json`／`FEATURES.md`: IOC値や検知ルールを除いた、機械可読／人向けの挙動・検体特徴
- `static-logic.json`／`STATIC-LOGIC.md`: 関数／スクリプト単位の役割、処理手順、呼出関係、API、制御フロー、正規化fingerprint、根拠
- `campaign-labels.json`: 登録済みの強い共有証拠との一致結果。一致なしも明示する
- `handlers/*.json`: 適用可能なファミリー固有解析器の無害化済み結果、試行層、採用層、証拠score

正規化したスクリプト本文は既定で保存しません。出力は公開前提の最終成果物ではなく、解析者がレビューする中間成果物です。IOCの役割、確度、配布先とC2の分離は別途確認してください。関数ロジックのレビューと類似性判定は[静的ロジック記録とコード類似性](STATIC-LOGIC-AND-CODE-SIMILARITY.md)、特徴profileとcampaign相関は[検体特徴と攻撃キャンペーン相関](CASE-KNOWLEDGE-CAMPAIGNS.md)を参照してください。

## 判定だけを行う

```powershell
python .\analysis-framework\common\analyze_sample.py `
  --input C:\malware-lab\incoming\sample.bin `
  --output C:\malware-lab\assessment `
  --assessment-only
```

このモードではルート検体の検出器評価と解析器カタログの適用判定だけを行い、静的アンパック、汎用トリアージ、ファミリー固有解析器は実行しません。

## ファミリーを明示する

```powershell
python .\analysis-framework\common\analyze_sample.py `
  --input C:\malware-lab\incoming\sample.bin `
  --output C:\malware-lab\analysis-output `
  --family nanocore
```

`--family` は解析者が外部根拠を持つ場合のルーティング補助です。検出器が一致しない場合も `explicit_user_type_unmatched` または明示選択として記録し、ファミリー帰属の確認済み証拠には昇格しません。派生版専用解析器は自動実行しません。

## アーカイブモード

- `auto`: 既定。暗号化単一メンバーZIPだけをメモリ内展開し、通常ZIPはbundleのまま解析する。
- `raw`: ZIPを含むすべての入力をそのまま解析する。
- `malwarebazaar`: 各入力を単一メンバーZIPとして認証する。生ファイルを混在させない。

アーカイブmember名、member数、個別サイズ、総展開量、圧縮率を検証し、path traversalとzip bomb候補を拒否します。

## 旧ValleyRATワークフロー

`ProfilePath`、`NetworkEvidence`、`AllowLiveC2Check`、`CollectJarm`、または `LegacyValleyWorkflow` を指定した `Invoke-Analysis.ps1` は、従来のValleyRATキャンペーン専用処理を使用します。ライブ通信は一括静的解析には含まれず、現在のタスクで明示的に許可された場合だけ実行してください。

## 終了コード

- `0`: 入力エラーと解析器エラーなし
- `20`: 1件以上の入力エラー、汎用解析段階の失敗、import前検証失敗、または解析器エラーあり。成功したcaseと成功した段階の結果は保持する
