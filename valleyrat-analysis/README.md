# ValleyRAT Analysis

ValleyRAT の感染チェーンを構造的に識別し、キャンペーン別 handler で静的解析するリポジトリです。解析機能は `analysis/`、公開可能な解析結果は `results/` に分離しています。検体本体は収録しません。

## 構成

```text
analysis/
  common/                         # ファミリー非依存の安全な展開・共通処理
  classifiers/                    # マルウェアタイプ/キャンペーン識別器
  registry/                       # type と handler の登録情報
  malware/valleyrat/
    common/                       # ValleyRAT 内の共通処理
    campaigns/
      dll_sideload_vvas_bundle/   # chgport/LoggerCollector/vvaS 型
      msi_embedded_cab_custom_actions/ # MSI/CAB/cef_frame 型
config/                           # hash 固定 profile と外部観測証拠
results/cases/<sha256>/            # 検体を含まない解析結果
tests/                             # 既知検体の回帰テスト
docs/                              # 設計・追加 handler 手順
```

## 識別方針

`classify_sample.py` は最初に SHA-256 と ZIP/MSI/OLE/CAB/PE の構造を検査します。既知 hash はマルウェアタイプを高信頼で割り当て、未知 hash は構造だけから ValleyRAT 候補を中信頼で提示します。キャンペーン handler の選択にはファミリーラベルを使用しません。

## 実行

```powershell
.\Invoke-Analysis.ps1 `
  -Sample C:\quarantine\inner-sample.zip `
  -OutputDirectory C:\analysis-output\case `
  -ProfilePath .\config\profiles\<sha256>.json
```

MSI/CAB 型で process 帰属付き外部観測を相関する場合は `-NetworkEvidence` を指定します。ライブ C2 接続はこの統一入口に実装していません。

## 安全性

- 検体、復号バイナリ、PCAP、Ghidra project は Git 管理対象外です。
- handler は検体を実行しません。
- C2 は静的 config または process 帰属付き観測から判定します。
- 未知構造は既知 handler に強制せず停止します。

詳細は [設計](docs/PATTERN-DESIGN.md) と [ValleyRAT workflow](docs/VALLEYRAT-WORKFLOW.md) を参照してください。
