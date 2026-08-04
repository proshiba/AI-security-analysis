# 対象限定のC2稼働状況

対象期間は `2026-08-03T00:00:00+09:00` から `2026-08-04T23:59:59+09:00`、監視対象は 6 endpointです。状態内訳は c2_protocol_confirmed: 2、not_reachable_at_observation: 2、transport_reachable_c2_not_confirmed: 2 です。



監視scopeは `valleyrat_pdfcore8_20260803_three_cases` です。`.onion`は対象外で、入力planへ明示した根拠付きendpointだけを確認しています。

この結果は観測時点のスナップショットです。TCP open、TLS証明書、一般HTTP/FTP応答だけではC2を確定しません。到達性とC2稼働確度を分離します。OFFが7日以上継続し、2回以上の実観測がある対象だけを停止扱いにして次回active対象から外します。

## 一覧

| ファミリー | endpoint | 関連case数 | 確認時刻（UTC） | 確認方法 | 観測結果 | confidence | 根拠 |
|---|---|---:|---|---|---|---|---|
| valleyrat | `ljdnxz[.]cc:8856` | 1 | 2026-08-03T23:16:33.819129+00:00 | DNS解決＋単一TCP接続（送受信なし） | transport_reachable_c2_not_confirmed / TCP到達性のみでC2 applicationは未確認<br>監視状態: 継続監視（ON） | 到達 0.90（高）<br>C2稼働 0.25（低）<br>手法上限 0.25（低） | analysis-results/malware/valleyrat/versions/unknown/cases/e0e1ae775ef8e530875235f035fb623b217d48fa810537144c872fcf41592648/iocs.json:network |
| valleyrat | `ljdnxz[.]cc:8868` | 1 | 2026-08-03T23:16:34.269917+00:00 | 完全一致・IP pinning済みWinos heartbeat 1 frame＋64 byte限定受信 | c2_protocol_confirmed / review済みmalware固有protocol応答が一致<br>監視状態: 継続監視（ON） | 到達 1.00（高）<br>C2稼働 0.95（高）<br>手法上限 0.95（高） | analysis-results/malware/valleyrat/versions/unknown/cases/e0e1ae775ef8e530875235f035fb623b217d48fa810537144c872fcf41592648/iocs.json:network |
| valleyrat | `auk218[.]club:7811` | 1 | 2026-08-03T23:16:34.710188+00:00 | DNS解決＋単一TCP接続（送受信なし） | not_reachable_at_observation / この観測時点では到達応答なし。停止の恒久判定ではない<br>監視状態: 継続監視（OFF猶予） | 到達 0.00（低）<br>C2稼働 0.00（低）<br>手法上限 0.25（低） | analysis-results/malware/valleyrat/versions/unknown/cases/12a22fece1fb6c9aa5620ae910b9b0a98b9013b0b8efb77369ec1bed40ddb18d/iocs.json:network |
| valleyrat | `auk218[.]club:7800` | 1 | 2026-08-03T23:16:37.936008+00:00 | 完全一致・IP pinning済みWinos heartbeat 1 frame＋64 byte限定受信 | not_reachable_at_observation / この観測時点では到達応答なし。停止の恒久判定ではない<br>監視状態: 継続監視（OFF猶予） | 到達 0.00（低）<br>C2稼働 0.00（低）<br>手法上限 0.95（高） | analysis-results/malware/valleyrat/versions/unknown/cases/12a22fece1fb6c9aa5620ae910b9b0a98b9013b0b8efb77369ec1bed40ddb18d/iocs.json:network |
| valleyrat | `haochisadnka[.]cc:6698` | 1 | 2026-08-03T23:16:40.940055+00:00 | DNS解決＋単一TCP接続（送受信なし） | transport_reachable_c2_not_confirmed / TCP到達性のみでC2 applicationは未確認<br>監視状態: 継続監視（ON） | 到達 0.90（高）<br>C2稼働 0.25（低）<br>手法上限 0.25（低） | analysis-results/malware/valleyrat/versions/unknown/cases/61a602b23169ad451a22661e2e356e16ef2bd3c7ef7a23d5892ac4f79baff0b5/iocs.json:network |
| valleyrat | `haochisadnka[.]cc:6685` | 1 | 2026-08-03T23:16:41.383035+00:00 | 完全一致・IP pinning済みWinos heartbeat 1 frame＋64 byte限定受信 | c2_protocol_confirmed / review済みmalware固有protocol応答が一致<br>監視状態: 継続監視（ON） | 到達 1.00（高）<br>C2稼働 0.95（高）<br>手法上限 0.95（高） | analysis-results/malware/valleyrat/versions/unknown/cases/61a602b23169ad451a22661e2e356e16ef2bd3c7ef7a23d5892ac4f79baff0b5/iocs.json:network |

## confidenceの読み方

- `到達`: 今回のtransport／application到達観測の確からしさです。
- `C2稼働`: 観測結果が、解析済みmalwareのC2 application稼働を示す確度です。TCP接続だけなら最大0.25です。
- `手法上限`: その確認方法が、成功時でも単独で到達できるC2確度の上限です。malware固有protocolとの一致がない限り0.60以下です。
- `negative_observation_confidence` はJSONに保持し、拒否は比較的強い停止側観測、timeoutは弱い停止側観測として区別します。

## DNS/IP遷移履歴

raw IP変化は 0 回、CDN除外後のインフラIP変化は 0 回、同一共有CDN内ローテーションとして除外した変化は 0 回です。

Cloudflare、Akamai、Fastly等の共有CDNでは、同一provider内のedge IP入替を履歴へ残しますが、C2インフラ自体のIP変化件数には加えません。providerまたは非CDN ASNが変わった場合はインフラ変化として扱います。詳細は `monitoring-history.json` の `dns_tracking.history` を参照してください。

## 旧IPから新IPへの遷移

| endpoint | 観測時刻（UTC） | 旧IP（AS・Geo・タグ） | 新IP（AS・Geo・タグ） | 分類 |
|---|---|---|---|---|
| - | - | - | - | 現時点ではIP遷移なし |

## 最新IPのAS・Geo・インフラタグ

| endpoint | IP | AS / 組織 | Geo | タグ | 防弾ホスティング評価 |
|---|---|---|---|---|---|
| `ljdnxz[.]cc:8856` | `121[.]127[.]253[.]206` | AS152194 / CTG Server Limited | 香港 | 防弾ホスティング - 疑い、C2候補インフラ、DNS解決先、ホスティング | 防弾ホスティング - 疑い |
| `ljdnxz[.]cc:8868` | `121[.]127[.]253[.]206` | AS152194 / CTG Server Limited | 香港 | 防弾ホスティング - 疑い、C2候補インフラ、DNS解決先、ホスティング | 防弾ホスティング - 疑い |
| `auk218[.]club:7811` | `118[.]107[.]0[.]196` | AS152194 / CTG Server Limited | シンガポール | 防弾ホスティング - 疑い、C2候補インフラ、DNS解決先、ホスティング | 防弾ホスティング - 疑い |
| `haochisadnka[.]cc:6698` | `134[.]122[.]185[.]201` | AS152194 / CTG Server Limited | シンガポール | 防弾ホスティング - 疑い、C2候補インフラ、DNS解決先、ホスティング | 防弾ホスティング - 疑い |
| `haochisadnka[.]cc:6685` | `134[.]122[.]185[.]201` | AS152194 / CTG Server Limited | シンガポール | 防弾ホスティング - 疑い、C2候補インフラ、DNS解決先、ホスティング | 防弾ホスティング - 疑い |

`防弾ホスティング`は明示的なprovider評価、`防弾ホスティング - 疑い`は高密度C2悪用等の状況証拠に基づきます。単一の悪性IP観測だけでは付与しません。完全な理由とOSINT sourceはJSONの`infrastructure.bulletproof_hosting`を参照してください。

## 継続監視と停止履歴

次回active対象は 6 件、停止履歴へ移した対象は 0 件です。ONの対象、7日未満のOFF、proxy利用不可等の未観測対象は継続監視します。

停止条件は、最後のON以後または初回OFFから7日以上が経過し、その期間に2回以上のOFF実観測があり、最新観測もOFFであることです。単発timeoutや未観測だけでは停止しません。次回対象は `active-targets.json`、停止を含む全履歴は `monitoring-history.json` を参照してください。

<!-- maxmind-enrichment:start -->
## MaxMind Geo/ASエンリッチ

- IP照合: `5/5`
- GeoLite2 City DB構築時刻: `2026-07-31T04:47:37+00:00`
- GeoLite2 ASN DB構築時刻: `2026-08-03T08:15:42+00:00`
- 公式checksum照合: City `True` / ASN `True`
- ライブチェック前鮮度確認: `True` / 上限 `24.0`時間
- 鮮度超過による更新: `True` / 更新後も公開最新版が24時間超: `True`
- 更新後の鮮度超過: City `True` / ASN `False`
- MaxMind帰属表記（原文）: This product includes GeoLite2 Data created by MaxMind, available from https://www.maxmind.com.

| C2 endpoint | 観測IP | Geo | AS |
|---|---|---|---|
| `ljdnxz.cc:8856` | `121.127.253.206` | 香港 | AS152194 / CTG Server Limited |
| `ljdnxz.cc:8868` | `121.127.253.206` | 香港 | AS152194 / CTG Server Limited |
| `auk218.club:7811` | `118.107.0.196` | シンガポール | AS152194 / CTG Server Limited |
| `haochisadnka.cc:6698` | `134.122.185.201` | シンガポール | AS152194 / CTG Server Limited |
| `haochisadnka.cc:6685` | `134.122.185.201` | シンガポール | AS152194 / CTG Server Limited |

> GeoLite2は概略位置情報です。個人・世帯・住所の識別やC2稼働確証には使用しません。
<!-- maxmind-enrichment:end -->

## 安全境界

既知portは完全一致host・単一portへ各1回、port不明hostはDNS解決だけを行い、timeout最大5秒、応答最大256 byteで確認しました。レビュー済み完全一致profileに限り、Winos heartbeatまたはvvaS check-inを合計2回送信しました。送信内容は固定で、victim metadataを含まず、stage要求・command pollingは行っていません。認証情報、port range、redirect追跡は使用していません。`.onion`は本監視の対象外です。

機械可読の完全な根拠、DNS解決先、証明書／banner hash、個別timeoutは [monitoring-results.json](monitoring-results.json)、今回の実効対象は [effective-targets.json](effective-targets.json)、次回active対象は [active-targets.json](active-targets.json) を参照してください。
