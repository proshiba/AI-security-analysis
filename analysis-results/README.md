# Analysis results

解析機能から分離した、公開可能な解析結果をマルウェア種別ごとに保存します。

```text
analysis-results/<malware-type>/cases/<sample-sha256>/
```

検体、実行可能ファイル、復号バイナリ、PCAP、Ghidra project、資格情報は保存しません。各種別の `manifest.sha256` で結果ファイルの整合性を管理します。
