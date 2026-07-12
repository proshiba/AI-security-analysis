# Analysis framework

複数のマルウェア種に対応する解析機能です。`Invoke-Analysis.ps1` が共通識別器を実行し、`malware_type` と `campaign_type` に対応する handler へ処理を渡します。

```text
common/                    # ZIP安全展開、Ghidra連携など
classifiers/               # family/campaign識別
registry/                  # malware typeとcampaignの登録
malware/<type>/
  common/                  # type内共通処理
  campaigns/<campaign>/    # 感染チェーン別handler
  config/                  # profile/evidence metadata
  docs/
  tests/
```

ValleyRAT固有の処理は [malware/valleyrat](malware/valleyrat/README.md) にあります。
