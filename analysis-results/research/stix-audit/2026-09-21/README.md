# ファミリー・類似性・C2インフラの証拠監査（2026-09-21）

## 結論と監査範囲

公開済みのファミリー別STIX、審査済みインフラSTIX入力、`analysis-results/malware/**/iocs.json`の全3,163ファイルを照合した。ネットワーク関連1,166 recordは[再実行可能な値非公開監査](c2-inventory-audit.json)で全件を証拠階層に分類した。さらに[別形式C2成果物の監査](c2-artifact-coverage.json)で8形式・2,196 caseを横断した。一方、**自由記述、研究領域の日別監視、公開PCAP実体まで取り込む全データソース監査ではない**。今回の作業では検体実行、実C2接続、追加ポート探索を行っていない。

重要な修正は、汎用コードの完全一致をファミリー間の系譜として読めるNoteから除外したこと、通信未観測の設定先を`beacons-to`や確定Campaignに昇格させないこと、SNIの有無で異なるFDMTP証明書を分けたこと、一次資料に掲載された不足IOCを補ったことである。根拠のないファミリー・攻撃主体・現在のC2稼働を新たに確定していない。

## 検体分類とコード類似性

再生成した[ファミリー索引](../../../stix/index.json)には66ファミリーが残る。うち出典付きOSINT登録は44、残る22は主に公開ローカル概要に依拠する。索引対象のcatalog caseは1,873件だが、**個別reportの高確度分類と具体的な選択根拠を同時に満たすcaseは29件**である。「66ファミリーが存在する」という整理と「1,873件の検体すべての帰属が独立に証明された」は別の主張であり、後者はしていない。

元の横断コード類似候補28 Noteは、低確度caseの配置、関数名を遡らないhash比較、汎用runtimeやSDKの一致を含んでいた。例としてRemusStealer–Vidarの208一致群のうち205群はGo標準ライブラリ由来、ACRStealer–ValleyRATの12群はすべてDelayLoad関数由来だった。RemusStealer–Xwormには公開SDKのAgGateway等が混入していた。これらはファミリー系譜・同一開発者・同一攻撃者の根拠にならない。[生成器](../../../../analysis-framework/common/generate_family_stix.py)は元の`static-logic.json`へ戻って関数名とロジックを照合し、root caseと内部layerのSHA-256を区別し、高確度caseだけを比較する。結果、**現在の入力で独立に支持できる横断コード類似Noteは0件**となった。これは実際に類似する検体が存在しないという証明ではない。

`.NET resource loader`など5件は複数検体を便宜的にまとめた技術クラスタであり、STIXのmalware familyでも単一instanceでもないためBundleから除外した。元の検体解析データは削除していない。[判定基準](../../../../analysis-framework/docs/FAMILY-STIX.md)に除外条件を記録した。

静的C2値を持つ200個の`iocs.json`を別途初回分類と突合すると、同階層`classification.json`がある155件のうち153件は保存先familyと一致し、2件のNanoCoreは初回が`unknown`だった。この2件は後続の静的レビューでNanoCore設定が独立に確認されており、現時点では**初回判定と後続結論の状態非同期**であって誤帰属の証拠ではない。残る45件には初回`classification.json`がない。したがって保存先ディレクトリ名だけで全件の確定判定を主張しない。

## C2全件棚卸しの結果

| 対象・分類 | 件数 | 読み方 |
|---|---:|---|
| 検体別network record | 1,166 | 全レコードを証拠階層へ分類。C2だけではない |
| 静的設定に基づくC2候補 | 505 record／公開可能な値151種類 | 設定に存在する通信先。実通信や現行稼働ではない |
| 未確定のC2候補 | 111 record | family・役割・設定との紐付けを追加確認する対象 |
| 外部sandbox設定候補 | 65 record | 自前の静的根拠としては扱わない |
| 審査済みSTIX endpoint | 164 | 選定OSINTクラスタ・個別解析の集合で全件自動取り込みではない |
| 上記のうち根拠付きC2／設定のみ | 68／3 | 68台の稼働サーバー、3台の現行DNSという意味ではない |
| STIXの報告のみ／ピボットのみ | 25／56 | ファミリーC2への自動昇格をしない |

静的C2の151種類とSTIXの確定または設定のみの宛先は、**厳密値の一致が0、host単位の一致も0**だった。AsyncRAT、NoodleRAT、ShadowPadは両集合に同じfamily名があるが、ローカル自動解析の検体と手編纂したOSINTクラスタが異なる。この0件を正規化の失敗やC2不在と解釈しない。現行STIXをリポジトリ内の全C2一覧としてハントに用いると、大量のローカル設定先を見落とす。

### `iocs.json`以外のC2成果物と日別監視

8形式のcase単位JSONを調べると、明示的なendpoint欄のあるcaseは213件あり、そのうち**20件は同caseの`iocs.network`が空、45件は`iocs.json`自体が欠落**していた。したがって前述の505 record／151種類は、検体設定を含む全C2値の上限でも総数でもない。別形式で数えた設定表明237 record、静的endpoint表明152、`c2-analysis`表明164、`indicators`のC2表明41、候補文字列268、監視計画20、network-evidence表明30は互いに重複し、一意のC2数へ合算できない。監視計画・候補・記録内の「confirmed」というラベルも、独立した通信確認として再解釈しない。

具体的には、PureHVNCの一つのcaseでは`config.json`に`tirakian.com:56001`～`:56003`がある一方、同caseの`iocs.network`は空だった。`c2-analysis.json`の非空endpoint 164件のうち161件は同caseのIOC表記へ厳密に転記されていたが、残るDarkCometの静的候補3件は同caseに`iocs.json`がなく、稼働確認も未解決だった。これらは監査器の件数とは別に行った個別照合であり、同値の別表記や別caseまで自動的に統合しない。

`analysis-results`全体の`iocs.json`は3,641件で、検体別3,163件との差478件はClickFix領域408件とresearch領域70件にある。ClickFixの当該ファイルは主に配布・遷移・DNS文脈の`indicators[]`で、`network[]`およびC2役割は見つからなかった。一方、research領域には`network[]`が非空の3ファイル・7 recordがあり、C2に類する役割が2件ある。この2件は本監査器の検体別ネットワーク1,166 recordには含まれない。別のC2情報源として確認を続ける必要がある。

[2026-09-21の日別C2監視結果](../../c2-monitoring/2026-09-21/monitoring-results.json)は有効対象304件を扱う別の時系列スナップショットである。プロトコル確認3件と、transport到達のみ86件、DNS解決のみ32件、不達174件などを区別する。過去の監視32ファイルを単純合算した値は一意のC2数ではない。本タスクで新たなライブ照会は実施していない。公開の`protocol-observations.json`はトラフィック要約であり、全HTTP・TLS・DNS観測を悪性C2と見なさない。リポジトリにはPCAP/PCAPNG実体がなく、元パケットの独立再審査は今回できていない。

静的C2 recordのうち95件は項目単位の`source`と`evidence`が未記録であり、同caseの他成果物を追跡しない限り公開STIXへ昇格しない。審査済みSTIXの`sample-config`由来C2のうち32件は`sample_sha256`の直接紐付けがない。記事に記載された検体hashを一対一に確認できる場合だけ補完し、同一ファミリーというだけで検体へ接続しない。STIXに時刻付きで記録した45 endpointはすべて**証明書ピボットのTLS観測**であり、C2チェックイン時刻を記録したものではない。

## 一次資料・過去観測の再照合による修正

- [Censysのsostener.vbs調査](https://censys.com/blog/unmasking-the-infrastructure-of-a-spearphishing-campaign/)はRemcos設定先を5件報告する。元入力にあった共通証明書の2件に、`trabajonuevos.duckdns.org:3010`、`remc21.duckdns.org:3010`、`gotemburgoxm.duckdns.org:8090`と履歴DNSを追加した。最初の2件はlistener未観測のため`configured-only`とし、確定CampaignではなくGroupingに置いた。`gotemburgoxm`のTLS fingerprint値は記事本文にないため、別の共通leafと同一視しない。
- [FortinetのQuickFox/FDMTP調査](https://www.fortinet.com/blog/threat-research/quickfox-supply-chain-attack-used-to-deploy-fdmtp-implant)のTable 4には登録・ノード取得用staging domainが7件ある。元入力の1件から7件へ補完したが、直接のsocket C2ノード10 IPとは別の攻撃補助基盤とした。共有CDNの解決先を専用C2へ昇格しない。
- [過去のFDMTP TLS観測](../../daily-news-malware/2026-08-06/infrastructure-summary.json)で、履歴DNS先25 IPの443番に**SNIなし**で接続したleaf SHA-256は`ffe0435800af23ac24e6ab0b4b6f44de63de578138ad6db5f459049d572537e8`。`www.wangmeng66.top`を**SNI指定**した別接続のleafは`f3aa1b05947d9434e3bd46ab323c070db4adde159a018b5386593d310aab7dfb`だった。後者の接続で選ばれたIPは元JSONにないため、同時に得た10件のDNS A結果すべてへ割り当てない。過去の観測は限定的な能動TLS接続であり「受動的観測」という旧記述も修正した。
- [STIX 2.1仕様](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html)の意味に合わせ、通信実測がない静的設定・一次解析記事由来のC2は`malware uses infrastructure`とし、`beacons-to`は通信実測根拠に限定した。`Observed Data`も正確な通信・TLS観測時刻がない設定値に対して捏造しない。

## 未解決事項と次の監査優先度

まず項目単位の出典・証拠がない95 recordをcase内の`config.json`、静的復号メモ、reportへ遡り、値とport、root SHA-256、family判定を一件ずつ確かめる。次に、別形式に明示endpointがあるのに`iocs.network`が空・欠落する65 caseについて、設定値、候補、監視計画、実測を人手確認してからIOC側へ反映する。`sample_sha256`が欠けるSTIXの32件は一次資料上の検体との一対一対応だけで補完する。初回分類がない45件は後続レビューの最終判定を優先する状態モデルが必要である。research側の2 C2類似recordと日別監視を含む形式横断の値照合、原PCAPが利用できる場合の独立再審査も残る。最後に日時のある実通信が存在する場合だけ、証明書観測時刻とは別のC2通信時系列を作る。

再実行は次のとおり。試験45件と両STIX生成器の`--check`、監査JSONの`--check`を通した。

```powershell
python .\analysis-framework\common\audit_c2_inventory.py --repository . --as-of 2026-09-21 --check .\analysis-results\research\stix-audit\2026-09-21\c2-inventory-audit.json
python .\analysis-framework\common\audit_c2_artifact_coverage.py --repository . --as-of 2026-09-21 --check .\analysis-results\research\stix-audit\2026-09-21\c2-artifact-coverage.json
python .\analysis-framework\common\generate_family_stix.py --repository . --as-of 2026-09-21 --check
python .\analysis-framework\common\generate_infrastructure_stix.py --repository . --as-of 2026-09-21 --check
python -m pytest -q .\analysis-framework\tests\test_generate_family_stix.py .\analysis-framework\tests\test_generate_infrastructure_stix.py .\analysis-framework\tests\test_audit_c2_inventory.py .\analysis-framework\tests\test_audit_c2_artifact_coverage.py .\analysis-framework\tests\test_inventory_infrastructure_evidence.py
```
