# コレクション：2026-07-27 ValleyRAT／FormBook個別調査

ユーザー提供の攻撃情報を起点に、配布物の取得、静的解析、Ghidra関数レビュー、PCAP相関、限定的な到達性確認を行った2件の索引です。

- ValleyRAT: ZIP→IMG→正規host＋悪性PDFCore互換DLL→Winos memory stage
- FormBook: ZIP→JavaScript→PowerShell→Google Drive stage→memory loader
- 検体実行: 実施していません
- 外部接続: 配布objectの上限付き取得と、明示許可されたValleyRAT endpointへの限定確認だけを実施しました

## ケース

- [ValleyRATケース](../../malware/valleyrat/versions/unknown/cases/ee0ef34a4402dea54ec8b4e0557de9605a038a4f2b82380f2978296fd60f9791/README.md)
- [FormBookケース](../../malware/formbook/versions/unknown/cases/12dadccc337579815e4a1245a6a01931445e510c63388b7c90b87b865af42be9/README.md)

ケースの正本は`manifest.json`のSHA-256です。検体、memory dump、PCAP、配布objectはこのリポジトリへ含めません。
