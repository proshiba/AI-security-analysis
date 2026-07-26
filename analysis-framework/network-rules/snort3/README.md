# Snort 3通信検知候補

このディレクトリは、公開PCAPを独自に解析して得たSnort 3候補を保持します。外部記事のIOCを機械的にruleへ変換しません。

## 現在の成果物

- `mta-20260726-candidates.rules`: Malware-Traffic-Analysis.netのWindows感染PCAP 50件から作成し、人手レビューで背景通信を除外した11候補

各候補の正例capture、初回・最終観測日、経過日数、制約は次を参照してください。

- `analysis-results/network-traffic/malware-traffic-analysis-net/2026-07-26/signature-evidence.json`
- `analysis-results/network-traffic/malware-traffic-analysis-net/2026-07-26/rejected-signature-candidates.json`

## 運用上の状態

現在の11件は`candidate`です。PCAP上のsemantic positiveと、同じ50件内のcross-family一致がないことは確認していますが、次は未完了です。

- Snort 3 engineによる構文検証
- 独立した無害PCAP corpusによる負例試験
- 同一familyの別variantによる再現率試験

これらが完了するまで本番IDSへ投入しません。

## 安全性

- PCAPをnetwork interfaceへreplayしない。
- 検体やexport objectを実行しない。
- live C2や配布先へ接続しない。
- 単一IP、単一domain、共有serviceだけで悪性判定しない。
- 古いPCAPだけで観測した候補は`legacy`または再検証必須として扱う。
