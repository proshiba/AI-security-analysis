# AI Security Analysis

マルウェア種別を横断して、解析機能と解析結果を管理するリポジトリです。

## Top-level layout

```text
analysis-framework/              # 実行可能な解析機能
  common/                        # マルウェア非依存の共通処理
  classifiers/                   # マルウェア種・キャンペーン識別器
  registry/                      # type/handler登録
  malware/
    <malware-type>/              # 種別固有のcommon/campaign/config/docs/tests
analysis-results/                # 実行機能から独立した公開可能な結果
  <malware-type>/
    cases/<sha256>/
```

新しいマルウェア種を追加するときは、`AAA-analysis/` のような独立トップを増やしません。機能は `analysis-framework/malware/aaa/`、結果は `analysis-results/aaa/` に追加します。共通化できる処理と識別器は `analysis-framework` 直下へ昇格します。

現在の対応種別は ValleyRAT です。詳細は [analysis-framework](analysis-framework/README.md) と [analysis-results](analysis-results/README.md) を参照してください。
