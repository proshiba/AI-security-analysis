# Analysis results

解析機能から分離した、公開可能なマルウェア種別・検体別の結果です。

```text
analysis-results/<malware-type>/cases/<sample-sha256>/
```

- [ValleyRAT](valleyrat/README.md)（[ファミリ挙動・C2モデル](valleyrat/BEHAVIOR-C2.md)）
- [AgentTesla](agenttesla/README.md)
- [RemcosRAT](remcosrat/README.md)

各ファミリREADMEは全解析ケースの索引とファミリ共通の挙動/C2モデルを、各case READMEはその検体で観測した配布・実行チェーン、想定される機能、C2の役割、根拠、確度を記録します。配布URL、ステージ取得先、資格情報送信先、対話型C2は混同せず、confirmed、inferred、unverifiedで確度を明示します。

検体本体、復号済み実行ファイル、PCAP、Ghidra project、認証情報は保存しません。各種別の `manifest.sha256` でREADME、IOCメタデータ、Sigma/YARAの整合性を確認できます。C2の生存状態は静的IOCとは別の時点依存情報であり、明示的な許可なしにライブ確認しません。

- [VenomRAT](venomrat/README.md) — Japan-observed delivery cluster, static payload/configuration analysis, and detection material.

- [MX-Go](unclassified/mx-go/README.md) — unclassified Japan-targeted remotely controlled bulk-email spam bot.
