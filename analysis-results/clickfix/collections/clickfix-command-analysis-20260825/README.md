# ClickFix収集済みcommand 10件の静的解析

`C:\Users\Administrator\Desktop\kentai\clickfix-command.txt`へ2026-08-25 00:06 JSTに保存されたpt1～pt10を解析しました。10ラベルは6つの一意commandで、pt4／pt8／pt9とpt5／pt6／pt7がそれぞれ完全一致します。

- source SHA-256: `8326ca91fcb530acaebfa6a42ea240fdfc6321e73090043cc60f63bd4d8296b0`
- size: `1916` bytes
- labels: `10`
- unique commands: `6`
- command／PowerShell／payload実行: `なし`

## 非公開証跡の保管

原本command fileと限定GET応答4件は、password `infected`のWinZip AES-256 archiveとしてS3へ保管し、upload後にsize、SSE-S3、archive SHA-256、manifest SHA-256を照合しました。原本は削除していません。

- object: `s3://malware-analysis-datastore-720232834682/analysis-targets/clickfix-command-file-20260825/2026/08/clickfix-command-file-20260825-20260824T232803Z-57ea6cd804e4.zip`
- archive SHA-256: `ededee3771844406c90c99b3c4a41f24cbdbf4c1ecfa98b5dac92df43a37ff42`
- datastore manifest SHA-256: `57ea6cd804e42dd318f138d182e120d6f2a606073c5f726b1e40629118187e1f`
- SSE: `AES256`
- files: `5`（原本1件、限定GET応答4件）

## 結論

- 6パターンすべてが、PowerShellでremote responseを取得し、IEXまたは動的ScriptProperty getterでmemory内評価するClickFix commandです。
- pt2は文字列置換後、別の子powershell.exeを生成します。
- pt5／pt6／pt7は`Add-Member ScriptProperty`とproperty readでIEX文字列を避けます。
- pt10はfake security ticket、window title変更、TLS 1.2指定で正規verificationを装い、Base64 URLを復号します。
- 現在の限定GETでは404、403、DNS非公開、timeoutとなり、実行可能stageとterminal malwareは復元できませんでした。
- 後段不明部分を一般的ClickFix挙動から推測していません。

## case一覧

| label | domain | 実行方式 | terminal payload | 成果物 |
|---|---|---|---|---|
| pt1 | `fingerprint-verification.info` | Invoke-RestMethod + Invoke-Expression | `not_retrieved` | [case](../../fingerprint-verification.info/cases/20260825-command-pt1) |
| pt2 | `rrewardgoldshop.com` | 文字列置換 + Process.Start + 子PowerShell IEX | `not_retrieved` | [case](../../rrewardgoldshop.com/cases/20260825-command-pt2) |
| pt3 | `makeverizyjar.info` | Invoke-RestMethod + Invoke-Expression | `not_retrieved` | [case](../../makeverizyjar.info/cases/20260825-command-pt3) |
| pt4, pt8, pt9 | `imagehopeag.com` | WebClient.DownloadString + Invoke-Expression | `not_retrieved` | [case](../../imagehopeag.com/cases/20260825-command-pt4-pt8-pt9) |
| pt5, pt6, pt7 | `spielportal.com` | Invoke-RestMethod + 動的ScriptProperty getter | `not_retrieved` | [case](../../spielportal.com/cases/20260825-command-pt5-pt6-pt7) |
| pt10 | `triapfog.com` | Base64 URL復号 + Invoke-RestMethod + Invoke-Expression | `not_retrieved` | [case](../../triapfog.com/cases/20260825-command-pt10) |

各caseのREADMEとOVERALL-LOGICへ、原文command line、復号後文字列、静的process chain、最終取得状態を記載しています。
