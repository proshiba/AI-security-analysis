# 一次資料で照合したキャンペーン

[STIX 2.1一式](bundle.json)には、公開一次資料とローカル成果物を照合した5活動を収録しています。正本は [`reviewed_public_campaigns.json`](../../../analysis-framework/registry/reviewed_public_campaigns.json) で、[`generate_reviewed_public_campaigns.py`](../../../analysis-framework/common/generate_reviewed_public_campaigns.py) が7件の完全一致ケースラベルと本一式だけを更新します。全ケースの自動相関とは独立です。

| 活動 | ローカルとの一致 | 帰属境界 |
|---|---|---|
| TA577／Latrodectus（2023-11-27） | Proofpoint掲載のLNKとDLLのSHA-256が完全一致 | TA577はProofpoint評価。LNKはマルウェアではなくFile SCO |
| TA578／Latrodectus（2024-03-04、03-07） | Proofpoint掲載のDLLのSHA-256が完全一致 | TA578はProofpoint評価。残りのLatrodectus検体へ拡張しない |
| APT-C-60／SpyGlace（2026年） | JPCERT/CC掲載の符号化ファイル4件のSHA-256が完全一致 | APT-C-60はJPCERT/CC評価。DarkHotelとの同一視はしない |
| `Head Mare`による`TrueConf`侵害（2026年7月） | 公開報告の`MD5`値とローカルで検証した`SHA-256`値を対応づけた | 元の改ざんインストーラーの同一性だけを確認。後段の`PhantomCore`子`DLL`と`C2`接続先は独立して復元できていない |
| ShadowPad／grandfoodtony.com（2021年） | ローカル設定の`www.grandfoodtony.com`はKaspersky ICS CERT掲載の登録ドメイン配下 | 公開報告にこのSHA-256、キャンペーンID、ポート・Casper構造の対応はない。低確度候補に留め、アクターには結ばない |

STIXの`first_seen`と`last_seen`は日付を特定できた2023年・2024年の活動にのみ設定します。2026年7月のローカル取得日や一次資料の公表日を活動日へ転用しません。Actorとの`attributed-to`関係は各一次資料の評価を示し、独立の帰属確認ではありません。

## 出典

- [Proofpoint／Team Cymru：Latrodectus活動とIOC](https://www.proofpoint.com/us/blog/threat-insight/latrodectus-spider-bytes-ice)
- [JPCERT/CC：APT-C-60の2026年活動](https://blogs.jpcert.or.jp/en/2026/07/apt-c-60_2026.html)
- [Kaspersky：Head MareによるTrueConf侵害](https://securelist.ru/tr/head-mare-targets-trueconf-server-with-phantomcore/116557/)
- [Kaspersky ICS CERT：2021年ShadowPad活動](https://ics-cert.kaspersky.com/publications/reports/2022/06/27/attacks-on-industrial-control-systems-using-shadowpad/)
