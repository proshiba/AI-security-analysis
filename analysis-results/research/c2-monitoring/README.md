# C2稼働状況モニタリング

解析済み検体から静的またはprocess帰属付きで復元したC2 endpointを、日付別のスナップショットとして保存します。TCP openだけをC2稼働とは判定せず、到達性、application応答、malware固有protocol一致を別々に評価します。

## 実行結果

- [2026-08-02：過去1週間解析分10 endpoint](2026-08-02/README.md)

## 再実行

監視スクリプト、manifest schema、confidence基準、安全境界は [C2定期モニタリング手順](../../../analysis-framework/common/C2-MONITORING.md) を参照してください。日付別ディレクトリには、レビュー済み`targets.json`、観測証跡`monitoring-results.json`、日本語一覧`README.md`を保持します。
