# Analysis results

静的解析・設定抽出・IOC評価の公開用結果です。検体本体、復元バイナリ、資格情報、ローカル解析パスは含めません。

標準配置は次のとおりです。

```text
analysis-results/<malware-family>/cases/<sample-sha256>/
analysis-results/<malware-family>/refresh-YYYYMMDD/cases/<sample-sha256>/
```

## Families

- [ValleyRAT](valleyrat/README.md) / [behavior and C2 model](valleyrat/BEHAVIOR-C2.md)
- [AgentTesla](agenttesla/README.md)
- [RemcosRAT](remcosrat/README.md)
- [VenomRAT](venomrat/README.md) / [behavior and C2 model](venomrat/BEHAVIOR-C2.md)
- [Formbook](formbook/README.md) / [behavior and C2 model](formbook/BEHAVIOR-C2.md)
- [Vidar](vidar/README.md) / [behavior and C2 model](vidar/BEHAVIOR-C2.md)
- [LummaStealer](lummastealer/README.md) / [behavior and C2 model](lummastealer/BEHAVIOR-C2.md)
- [RemusStealer](remusstealer/README.md) / [behavior and C2 model](remusstealer/BEHAVIOR-C2.md)
- [Atomic macOS Stealer (AMOS)](amosstealer/README.md) / [behavior and C2 model](amosstealer/BEHAVIOR-C2.md)
- [Unclassified malware](unclassified/README.md)

## Latest refresh

- [2026-07-15: 9 families / 90 new samples](REFRESH-2026-07-15.md)
- [2026-07-15: unpacking reassessment and remaining blockers](UNPACKING-REASSESSMENT-2026-07-15.md)

各レポートでは、MalwareBazaarの署名ラベル、静的に確認したファミリーマーカー、配布・ローダー形態、復号済み設定、候補IOCを区別します。埋め込みURLやIPは、それだけでは稼働中C2や当該ファミリー専用インフラを意味しません。

すべてのrefresh解析は検体をローカル実行せず、実インフラへの接続も行いません。Sigma/YARAは検知仮説であり、正規ソフトウェアとの重複、署名・普及度、親子プロセス、通信先を組み合わせて環境別に検証してください。

## PureHVNC and DonutLoader cases


- [SpyGlace / APT-C-60 2026](spyglace/README.md) / [campaign analysis and IOC set](spyglace/campaigns/apt-c60-2026/README.md)
- [PureHVNC / PureRAT](purehvnc/README.md)
- [DonutLoader](donutloader/README.md)

The DonutLoader result preserves both delivery classification and terminal PureRAT identity; configured C2 is not attributed to the delivery host or intermediate loader.
