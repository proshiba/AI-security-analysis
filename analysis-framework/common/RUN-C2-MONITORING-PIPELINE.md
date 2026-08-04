# C2監視・MaxMindエンリッチ・履歴管理の統合手順

## 目的

`analysis-results`全体のIOC履歴から`.onion`以外の通常IP／FQDNを抽出し、限定したC2候補へのライブチェック、MaxMind GeoLite2 City/ASN照合、DNS/IP遷移の分類、継続監視対象の更新、機械可読JSONと日本語Markdownの生成を一連の手順で実行します。今後のC2監視では、対象漏れ、Geo/AS、DNS履歴、停止履歴の付与漏れを防ぐため、この抽出器と統合ランナーを標準経路として使います。

## 実行

```powershell
py -3.13 -m pip install -r analysis-framework\requirements-maxmind.txt

py -3.13 analysis-framework\common\build_all_c2_monitoring_targets.py `
  --results-root analysis-results `
  --output-plan analysis-results\research\c2-monitoring\YYYY-MM-DD\targets.json `
  --output-inventory analysis-results\research\c2-monitoring\YYYY-MM-DD\candidate-inventory.json `
  --date YYYY-MM-DD `
  --write

py -3.13 analysis-framework\common\run_c2_monitoring_pipeline.py `
  --targets analysis-results\research\c2-monitoring\YYYY-MM-DD\targets.json `
  --output-directory analysis-results\research\c2-monitoring\YYYY-MM-DD `
  --history-root analysis-results\research\c2-monitoring `
  --maxmind-cache-dir C:\Users\Administrator\MalwareSamples\maxmind\current `
  --allow-network `
  --allow-malware-registration-tasking
```

抽出器は`network`、`configured_c2`、`configured_or_observed_c2`、`indicators`、researchの`network.c2`を走査し、C2／control／exfil等の役割だけを採用します。配布専用、kill-switch、`not_c2`、private／loopback IP、`.eth`／`.sol`／XMP `.did`／`.iid`誤endpointは理由付きで`candidate-inventory.json`へ除外記録を残します。`.onion`はユーザー指定により監視対象外です。`--history-root`を省略した場合は`output-directory`の親を使います。統合ランナーは直近の`active-targets.json`も重複排除して統合します。

daily解析では`--allow-network`を必須とします。C2へ接続する前にCity/ASN両DBのbuild時刻を確認し、いずれかが24時間以上前なら公式checksumを検証した最新版へ更新します。閾値は`--maxmind-max-build-age-hours`で厳しくできますが、dailyでは24時間を超える値へ変更しません。

MaxMindが公開している最新版自体のbuild時刻が24時間以上前の場合も取得成功として扱いますが、`latest_available_still_stale`とedition別の`stale_after_refresh`を結果へ明記します。operatorが無条件更新を要求するときだけ`--refresh-maxmind-databases`を追加します。

## DNS/IP遷移の扱い

- 各観測のA/AAAA解決結果、ASN、organization、観測日時を`dns_tracking.history`へ残します。
- 前回とIP集合が異なる場合は`raw_ip_changed=true`とし、生の変化を失いません。
- Cloudflare、Akamai、Fastly等の同一共有CDN provider内でedge IPだけが変わった場合は`shared_cdn_rotation_ignored`と分類します。この変化は履歴には残しますが、`infrastructure_ip_change_count`には加えません。
- 非CDN間の変更、またはCDN providerが変わった変更は`infrastructure_ip_change`として数えます。
- DNS解決あり／なしの遷移は`resolution_state_changed`とし、単独ではインフラ移転と断定しません。

CDN判定は観測IPのMaxMind ASN／organizationを使います。CDN経由であることはoriginやC2所有者を示さないため、DNS履歴だけで帰属を確定しません。

各IPは`ip_details`として固定し、IP、AS番号、AS組織、国・地域・都市、インフラタグ、防弾ホスティング評価を同じ観測点に保存します。IP集合が変わった場合は`transition`を生成し、`from`（旧IP集合）、`to`（新IP集合）、`removed`、`added`の各要素へこの完全なIP詳細を保持します。これにより、単なる`1.2.3.4 -> 5.6.7.8`ではなく、AS・Geo・インフラ種別を含む移転として追跡できます。

インフラタグと防弾ホスティング評価は`c2_infrastructure_classifications.json`を正本とします。`防弾ホスティング`はprovider自身の明示、政府措置、または信頼できる脅威インテリジェンスによる明示評価がある場合だけ付与します。高密度かつ継続的なC2悪用等の複数の状況証拠だけの場合は`防弾ホスティング - 疑い`へ限定し、単一の悪性IP観測だけではどちらも付与しません。共有CDNのedge IPからoriginの属性を推定しません。ルールには根拠URL、取得日、確度、判断理由を必須とします。

一般タグとして`DNS解決先`、`ホスティング`、`CDN`、`Anycast／共有エッジ`、`VPN／Proxy`、`Tor関連`、`ドメイン事業者`、`C2候補インフラ`を扱います。organization名だけから付ける汎用タグは低～中確度のservice種別であり、providerの悪性やC2所有を意味しません。

## 継続監視と停止条件

観測結果を次の状態へ正規化します。

- `active_on`: transportまたはapplication応答を確認。次回も監視する。
- `active_grace`: 最新観測はOFFだが停止条件未達。次回も監視する。
- `active_unobserved`: proxy利用不可やライブチェック無効等で未観測。次回も監視する。
- `retired_stopped`: 最新観測がOFFで、最後のON以後または初回OFFから7日以上経過し、その間に2回以上のOFF実観測がある。停止履歴へ移し、次回active対象から外す。

単発timeout、DNS解決失敗、proxy利用不可等の未観測だけでは停止しません。停止済みendpointが新しい観測でONになった場合は`monitoring_reactivated_after_new_evidence`を記録してactiveへ戻します。

## 安全境界

- 監視対象は`effective-targets.json`に列挙した完全一致host/portだけです。port不明hostは`dns_resolve`としてDNSだけを観測し、C2 serviceへ接続しません。`.onion`は対象へ含めません。
- 1対象1回の限定観測、最大5秒です。応答は原則最大256 byte、完全一致AgentTesla FTP認証は最大1024 byteです。StealC／Lumma／Remusは最大3秒・計2 HTTP要求とし、応答上限をそれぞれ16,384／65,536／8,192 byteへ固定します。raw本文は保存しません。
- 既知のmalware固有protocolは`c2_protocol_probe_profiles.json`の完全一致profileだけを使用します。送信内容を`targets.json`へ直接指定することはできません。
- Winos heartbeatとvvaS固定check-inはレビュー済みendpointへ各1回だけ許可します。N520はserver-first handshakeだけを検証し、check-inを送りません。
- StealC／Lumma／Remusは`--allow-network`と`--allow-malware-registration-tasking`の二重ゲート、完全一致profile、単一IP pinが揃う場合だけ、合成IDの登録とtask取得を各1回行います。実victim metadata、task実行、task内URL追跡、payload取得、debug、upload、doneは行いません。FormBook／XLoaderは受動観測のみです。
- 固有protocolを復元済みのendpointは単純なTCP接続確認へ降格させず、完全一致応答だけを`c2_protocol_confirmed`とします。
- `MAXMIND_LICENSE_KEY`、Authorization header、署名付きdownload URL、MMDB本体は公開成果物へ保存しません。
- MMDBはリポジトリ外のprivate cacheへ保存します。
- DB鮮度確認と必要な更新が完了できない場合、C2ライブチェックを開始せずfail-closedで終了します。
- GeoLite2は概略位置情報です。個人・世帯・住所の識別やC2稼働確定には使いません。

## 出力

- `targets.json`: `analysis-results`全体のIOC履歴から抽出した`.onion`以外の通常IP／FQDN候補。入力原本として保持する。
- `candidate-inventory.json`: 走査数、全通常hostカバレッジ、除外理由、parse errorを保持する監査在庫。
- `effective-targets.json`: 全履歴候補と前回active対象を統合した、今回実際に観測した対象。
- `monitoring-results.json`: 観測事実、稼働確度、DNS履歴、ライフサイクル、Geo/AS、DB provenance。
- `monitoring-history.json`: 停止済みを含むendpointごとの全DNS・稼働履歴と状態遷移。
- `active-targets.json`: 次回へ引き継ぐ継続監視対象。`retired_stopped`は含めない。
- `README.md`: C2一覧、confidence、DNS/IP遷移、継続監視／停止履歴、MaxMind Geo/AS、安全境界。

公開結果には次のattributionを保持します。

> This product includes GeoLite2 Data created by MaxMind, available from https://www.maxmind.com.
