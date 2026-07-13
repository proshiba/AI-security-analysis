# Analysis results

解析機能から分離した、公開可能なマルウェア種別・検体別の結果です。

```text
analysis-results/<malware-type>/cases/<sample-sha256>/
```

- [ValleyRAT](valleyrat/README.md)
- [AgentTesla](agenttesla/README.md)
- [RemcosRAT](remcosrat/README.md)

検体本体、復号済み実行ファイル、PCAP、Ghidra project、認証情報は保存しません。各種別の `manifest.sha256` でREADME、IOCメタデータ、Sigma/YARAの整合性を確認できます。C2の生存状態は静的IOCとは別の時点依存情報であり、明示的な許可なしにライブ確認しません。
