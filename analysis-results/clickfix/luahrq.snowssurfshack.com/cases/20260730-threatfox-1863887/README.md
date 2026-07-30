# ClickFixケース: luahrq.snowssurfshack.com

## 概要

- ケースID: `20260730-threatfox-1863887`
- 観測日時: `2026-07-30 05:38:30 UTC`
- 解析日: `2026-07-30`
- 情報源: [ThreatFox](https://threatfox.abuse.ch/browse/tag/clearfake/)
- 情報源タグ: `ClearFake, Windows, clearfake, win-0x0cd5`
- 情報源の確度: `100`
- 情報源上のマルウェア表記: `ClearFake`
- ライブ確認: HTTP 207を観測

`ClearFake`または`ClickFix`は配布cluster／手法を示し、終端マルウェアのfamily名とは限りません。
本caseでは配布先、stage取得先、終端C2を役割別に分けています。

## 配布マルウェア

- 終端binary payloadは取得できませんでした。

providerが`ClearFake`と記載している場合も、これはWeb inject／配布frameworkの識別です。
LummaStealer、NetSupport RAT等の終端familyを、このcaseの個別証跡なしに補完していません。

## 感染チェーン

1. 利用者が`luahrq.snowssurfshack.com`のlanding pageまたは侵害ページへ到達する。
2. fake CAPTCHA／verification等のClickFix lureが、clipboardへのcommand設定と手動実行を促す。
3. 実行commandは未取得
4. 後続stageまたは終端payloadは、取得できた静的証跡だけを採用する。

### ライブ後段評価

- GETに対してHTTP 207 Multi-Statusを観測しました。WebDAV互換endpointの可能性を支持しますが、ファイル一覧取得や変更系methodは送信していません。

図は[全体ロジック](OVERALL-LOGIC.md)を参照してください。

## 実行されるプロセスとcommand

想定されるprocess chain: 未確認

- providerまたはライブ本文から実行commandを取得できませんでした。

生commandはquery、invite token等を含み得るため公開せず、hashと処理ロジックを残しました。

## 追加通信先

### commandから確認

- このcaseでは追加stage URLを復元できませんでした。

### ライブ観測

- `104.21.89.135`（解析時DNS解決。共有基盤を含むためIOCから除外）
- `172.67.159.204`（解析時DNS解決。共有基盤を含むためIOCから除外）

redirect、本文hash、HTTP statusは[live-observation.json](live-observation.json)に記録しています。
DNS・RDAP・証明書・netblock・portは[インフラ調査](INFRASTRUCTURE.md)、Triageの既存実行は
[Hatching Triage照合](TRIAGE.md)を参照してください。TCP open、通常HTTP応答、DNS解決だけでは
C2と判定していません。

## Sigma

[case別Sigma候補](rules/sigma.yml)を参照してください。RunMRUとLOLBINの複合条件を使い、
domain単独の検知は行いません。

## IOC

[IOC一覧](IOC-LIST.md)と[構造化IOC](iocs.json)を参照してください。
公開IOC数は1件です。

## 確度と制約

- provider報告とcommandは`confirmed_provider_report`、解析時のHTTP/DNSは`observed_at_analysis_time`です。
- JavaScriptを実行せず、GET本文を上限付きで取得して静的に確認しました。
- 検体、script、DLL、PEをローカル実行していません。
- geo-fence、bot対策、時限配信、1回限りのtokenにより、provider観測とライブ結果が異なる可能性があります。
- payload_deliveryとして報告。終端payloadのfamilyとは区別する。
