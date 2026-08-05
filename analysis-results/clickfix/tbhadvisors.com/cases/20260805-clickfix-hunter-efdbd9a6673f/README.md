# ClickFixケース: tbhadvisors.com

## 概要

- ケースID: `20260805-clickfix-hunter-efdbd9a6673f`
- 観測日時: `2026-07-27T22:22:02.212Z`
- 解析日: `2026-08-05`
- 情報源: [ClickFix Hunter](https://clickfix.carsonww.com/domains/tbhadvisors.com)
- 情報源タグ: `ClickFix, clipboard-hijack, fake-captcha`
- 情報源の確度: `100`
- 情報源上のマルウェア表記: `未確認`
- ライブ確認: HTTP 200を観測
- 実ブラウザ確認: ok（JavaScript 実行、clipboard event 0件）

`ClearFake`または`ClickFix`は配布cluster／手法を示し、終端マルウェアのfamily名とは限りません。
本caseでは配布先、stage取得先、終端C2を役割別に分けています。

## 配布マルウェア

- 終端binary payloadは取得できませんでした。

providerが`ClearFake`と記載している場合も、これはWeb inject／配布frameworkの識別です。
LummaStealer、NetSupport RAT等の終端familyを、このcaseの個別証跡なしに補完していません。

## 感染チェーン

1. 利用者が`tbhadvisors.com`のlanding pageまたは侵害ページへ到達する。
2. fake CAPTCHA／verification等のClickFix lureが、clipboardへのcommand設定と手動実行を促す。
3. PowerShellが逆順文字列からTelegram URLを復元し、ページdescriptionの2トークンから次段hostを取得して `/l.dat` をメモリ内実行する。
4. 後続stageまたは終端payloadは、取得できた静的証跡だけを採用する。

### ライブ後段評価

- Telegram dead-drop URLはHTTP 200でしたが、現在のdescriptionは一般的なgroup招待文で、元commandが要求する2トークンを返しませんでした。このため `/l.dat` のhostを現在は復元できず、感染チェーンはresolverで停止します。

段階別の状態、根拠、停止位置は[感染チェーン](INFECTION-CHAIN.md)、
実行・モジュール比較図は[全体ロジック](OVERALL-LOGIC.md)を参照してください。

## 実行されるプロセスとcommand

想定されるprocess chain: `powershell.exe`

- pattern: `telegram_dead_drop_powershell`
- コマンドSHA-256: `d2bf03344bcc740adb870c21a0c531478ad173e1a13ddcc1994eb258f081aaf1`
- 正規化説明: PowerShellが逆順文字列からTelegram URLを復元し、ページdescriptionの2トークンから次段hostを取得して `/l.dat` をメモリ内実行する。

生commandはquery、invite token等を含み得るため公開せず、hashと処理ロジックを残しました。

## 追加通信先

### commandから確認

- `https://t.me/<redacted>`

### ライブ観測

- `149.154.167.99`（解析時DNS解決。共有基盤を含むためIOCから除外）
- `162.159.135.42`（解析時DNS解決。共有基盤を含むためIOCから除外）

redirect、本文hash、HTTP statusは[live-observation.json](live-observation.json)に記録しています。
DNS・RDAP・証明書・ASN／netblock・portの調査は[インフラ調査](INFRASTRUCTURE.md)、
既存sandbox実行の照合は[Hatching Triage照合](TRIAGE.md)を参照してください。
TCP open、通常HTTP応答、DNS解決だけではC2と判定していません。

## Sigma

[case別Sigma候補](rules/sigma.yml)を参照してください。RunMRUとLOLBINの複合条件を使い、
domain単独の検知は行いません。

## IOC

[IOC一覧](IOC-LIST.md)と[構造化IOC](iocs.json)を参照してください。
公開IOC数は1件です。

## 確度と制約

- provider報告とcommandは`confirmed_provider_report`、解析時のHTTP/DNSは`observed_at_analysis_time`です。
- 実ブラウザでJavaScript実行後の状態を観測し、clipboard書き込み値はinterceptしました。取得commandはOS clipboardへ転送せず、貼り付け・実行していません。
- 検体、script、DLL、PEをローカル実行していません。
- geo-fence、bot対策、時限配信、1回限りのtokenにより、provider観測とライブ結果が異なる可能性があります。
- ClickFix Hunterのsandbox観測。terminal payloadは静的追跡結果で別評価する。
