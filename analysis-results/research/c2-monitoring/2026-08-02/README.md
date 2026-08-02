# 過去1週間解析分のC2稼働状況

対象期間は `2026-07-26T00:00:00+09:00` から `2026-08-02T23:59:59+09:00`、監視対象は 13 endpointです。状態内訳は application_endpoint_reachable_c2_not_confirmed: 1、not_observed_proxy_unavailable: 3、not_reachable_at_observation: 2、server_first_response_reachable_c2_not_confirmed: 1、transport_reachable_c2_not_confirmed: 6 です。

この結果は観測時点のスナップショットです。TCP open、TLS証明書、一般HTTP/FTP応答だけではC2を確定しません。到達性とC2稼働確度を分離し、停止側の判定も恒久停止とは扱いません。

## 一覧

| ファミリー | endpoint | 関連case数 | 確認時刻（UTC） | 確認方法 | 観測結果 | confidence | 根拠 |
|---|---|---:|---|---|---|---|---|
| ValleyRAT / Winos | `haochisadnka[.]cc:6685` | 1 | 2026-08-02T04:18:01.960966+00:00 | DNS解決＋単一TCP接続（送受信なし） | transport_reachable_c2_not_confirmed / TCP到達性のみでC2 applicationは未確認 | 到達 0.90（高）<br>C2稼働 0.25（低）<br>手法上限 0.25（低） | analysis_history.yaml: ValleyRAT / Winos 2026-07-27 c2<br>analysis-results/malware/valleyrat/versions/unknown/cases/ee0ef34a4402dea54ec8b4e0557de9605a038a4f2b82380f2978296fd60f9791/README.md:C2稼働確認 |
| ValleyRAT / Winos | `haochisadnka[.]cc:6698` | 1 | 2026-08-02T04:18:02.419155+00:00 | DNS解決＋単一TCP接続（送受信なし） | transport_reachable_c2_not_confirmed / TCP到達性のみでC2 applicationは未確認 | 到達 0.90（高）<br>C2稼働 0.25（低）<br>手法上限 0.25（低） | analysis_history.yaml: ValleyRAT / Winos 2026-07-27 c2<br>analysis-results/malware/valleyrat/versions/unknown/cases/ee0ef34a4402dea54ec8b4e0557de9605a038a4f2b82380f2978296fd60f9791/README.md:C2稼働確認 |
| ValleyRAT / Winos | `haochisadnka[.]cc:6699` | 1 | 2026-08-02T04:18:02.634481+00:00 | DNS解決＋単一TCP接続（送受信なし） | not_reachable_at_observation / この観測時点では到達応答なし。停止の恒久判定ではない | 到達 0.00（低）<br>C2稼働 0.00（低）<br>手法上限 0.25（低） | analysis_history.yaml: ValleyRAT / Winos 2026-07-27 c2<br>analysis-results/malware/valleyrat/versions/unknown/cases/ee0ef34a4402dea54ec8b4e0557de9605a038a4f2b82380f2978296fd60f9791/README.md:C2稼働確認 |
| ValleyRAT（PureRAT系終端候補を含む配布chain） | `pure26[.]myftp[.]org:56001` | 1 | 2026-08-02T04:18:05.646368+00:00 | DNS解決＋単一TCP接続（送受信なし） | transport_reachable_c2_not_confirmed / TCP到達性のみでC2 applicationは未確認 | 到達 0.90（高）<br>C2稼働 0.25（低）<br>手法上限 0.25（低） | analysis-results/malware/valleyrat/versions/unknown/cases/307594e042248ad7cc9627e8de385851bd92df452216b1b829077d3a93ac815b/README.md:通信<br>analysis-results/malware/valleyrat/versions/unknown/cases/307594e042248ad7cc9627e8de385851bd92df452216b1b829077d3a93ac815b/OVERALL-LOGIC.md:通信先 |
| PureLogs（PureRAT / PureHVNC同梱候補） | `logs[.]uvexio[.]com:8443` `/ping` | 1 | 2026-08-02T04:18:05.738264+00:00 | DNS解決＋TLS/HTTP GET 1回（redirectなし） | application_endpoint_reachable_c2_not_confirmed / 限定HTTP応答を確認したが所有者・C2 protocolは未確認 | 到達 0.95（高）<br>C2稼働 0.60（中）<br>手法上限 0.60（中） | analysis_history.yaml: PureLogs 2026-07-29 c2<br>analysis-results/malware/purelogs/versions/unknown/cases/0f2abaabea8bb9454e5cf979e58eba7de10172dab1f3ebff6a9face304f4ce48/iocs.json:configured_or_observed_c2 |
| PureLogs（PureRAT / PureHVNC同梱候補） | `tea[.]vexexo[.]com:56001` | 1 | 2026-08-02T04:18:05.954360+00:00 | DNS解決＋単一TCP接続（送受信なし） | transport_reachable_c2_not_confirmed / TCP到達性のみでC2 applicationは未確認 | 到達 0.90（高）<br>C2稼働 0.25（低）<br>手法上限 0.25（低） | analysis_history.yaml: PureLogs 2026-07-29 c2<br>analysis-results/malware/purelogs/versions/unknown/cases/0f2abaabea8bb9454e5cf979e58eba7de10172dab1f3ebff6a9face304f4ce48/iocs.json:configured_or_observed_c2 |
| AgentTesla | `ftp[.]vilimorin[.]com:21` | 1 | 2026-08-02T04:18:06.038648+00:00 | DNS解決＋単一TCP接続＋server-first banner限定受信 | server_first_response_reachable_c2_not_confirmed / server-first応答を確認したがmalware固有fingerprintではない | 到達 0.95（高）<br>C2稼働 0.50（中）<br>手法上限 0.55（中） | analysis_history.yaml: AgentTesla 2026-07-29 c2<br>analysis-results/malware/agenttesla/versions/2026-07-js-luajit-donut-ftp/cases/3f09145757282e6a59cd69319ac3b9da3265022a1d4f92a1646f8ddbaad89333/README.md:C2 |
| Efimer | `gfoqsewps57xcyxoedle2gd53o6jne6y5nq5eh25muksqwzutzq7b3ad[.]onion:80` | 95 | 2026-08-02T04:18:06.172692+00:00 | DNS解決＋単一TCP接続（送受信なし）（localhost Tor SOCKS5経由） | not_observed_proxy_unavailable / loopback Tor SOCKS5へ接続できず対象へ到達していない | 到達 0.00（低）<br>C2稼働 0.00（低）<br>手法上限 0.25（低） | analysis-results/malware/efimer/versions/unknown/cases/f02758770d616fc8ff7ddbe5caf069d4bbd2bae5422a32a95cfa8c7f6a0a9b8d/handler-results.json:results[0].result.c2<br>過去1週間にGit追加されたEfimer 91 caseのhandler-results.json完全一致集約<br>analysis-results/malware/efimer/versions/unknown/cases/5e7928e464b8274c85179ed0d6b03668b19d6129a40e06a7309b15944d1fd071/iocs.json:network[0] |
| Efimer | `hek5ensy7wqqls2cafflihs7sdqr4dwxux47vp3k7pgffeasxsfeeyid[.]onion:80` | 95 | 2026-08-02T04:18:08.209206+00:00 | DNS解決＋単一TCP接続（送受信なし）（localhost Tor SOCKS5経由） | not_observed_proxy_unavailable / loopback Tor SOCKS5へ接続できず対象へ到達していない | 到達 0.00（低）<br>C2稼働 0.00（低）<br>手法上限 0.25（低） | analysis-results/malware/efimer/versions/unknown/cases/f02758770d616fc8ff7ddbe5caf069d4bbd2bae5422a32a95cfa8c7f6a0a9b8d/handler-results.json:results[0].result.c2<br>過去1週間にGit追加されたEfimer 91 caseのhandler-results.json完全一致集約<br>analysis-results/malware/efimer/versions/unknown/cases/5e7928e464b8274c85179ed0d6b03668b19d6129a40e06a7309b15944d1fd071/iocs.json:network[2] |
| Efimer | `swjxev2rvxfivi2wvkxre5vaxkjeepxzxva4u4ydm2qbkbakh6wnyead[.]onion:80` | 95 | 2026-08-02T04:18:10.229979+00:00 | DNS解決＋単一TCP接続（送受信なし）（localhost Tor SOCKS5経由） | not_observed_proxy_unavailable / loopback Tor SOCKS5へ接続できず対象へ到達していない | 到達 0.00（低）<br>C2稼働 0.00（低）<br>手法上限 0.25（低） | analysis-results/malware/efimer/versions/unknown/cases/f02758770d616fc8ff7ddbe5caf069d4bbd2bae5422a32a95cfa8c7f6a0a9b8d/handler-results.json:results[0].result.c2<br>過去1週間にGit追加されたEfimer 91 caseのhandler-results.json完全一致集約<br>analysis-results/malware/efimer/versions/unknown/cases/5e7928e464b8274c85179ed0d6b03668b19d6129a40e06a7309b15944d1fd071/iocs.json:network[3] |
| maskgram-stealer | `wintersonyae246leisekoshachiy[.]icu:443` | 1 | 2026-08-02T04:18:12.268267+00:00 | DNS解決＋単一TCP接続（送受信なし） | transport_reachable_c2_not_confirmed / TCP到達性のみでC2 applicationは未確認 | 到達 0.90（高）<br>C2稼働 0.25（低）<br>手法上限 0.25（低） | analysis-results/malware/maskgram-stealer/versions/unknown/cases/11f0f5b941e46c270da2705545255105008325a28dd26dac5669128c9651135a/iocs.json:network[0] |
| maskgram-stealer | `samtpfotchensnezhok9566leisegepard[.]sbs:443` | 1 | 2026-08-02T04:18:12.282811+00:00 | DNS解決＋単一TCP接続（送受信なし） | not_reachable_at_observation / この観測時点では到達応答なし。停止の恒久判定ではない | 到達 0.00（低）<br>C2稼働 0.00（低）<br>手法上限 0.25（低） | analysis-results/malware/maskgram-stealer/versions/unknown/cases/11f0f5b941e46c270da2705545255105008325a28dd26dac5669128c9651135a/iocs.json:network[1] |
| maskgram-stealer | `geschmeidig6307-kotyatanet[.]sbs:443` | 1 | 2026-08-02T04:18:12.287742+00:00 | DNS解決＋単一TCP接続（送受信なし） | transport_reachable_c2_not_confirmed / TCP到達性のみでC2 applicationは未確認 | 到達 0.90（高）<br>C2稼働 0.25（低）<br>手法上限 0.25（低） | analysis-results/malware/maskgram-stealer/versions/unknown/cases/11f0f5b941e46c270da2705545255105008325a28dd26dac5669128c9651135a/iocs.json:network[2] |

## confidenceの読み方

- `到達`: 今回のtransport／application到達観測の確からしさです。
- `C2稼働`: 観測結果が、解析済みmalwareのC2 application稼働を示す確度です。TCP接続だけなら最大0.25です。
- `手法上限`: その確認方法が、成功時でも単独で到達できるC2確度の上限です。malware固有protocolとの一致がない限り0.60以下です。
- `negative_observation_confidence` はJSONに保持し、拒否は比較的強い停止側観測、timeoutは弱い停止側観測として区別します。

<!-- maxmind-enrichment:start -->
## MaxMind Geo/ASエンリッチ

- IP照合: `11/11`
- GeoLite2 City build: `2026-07-31T04:47:37+00:00`
- GeoLite2 ASN build: `2026-08-01T08:15:50+00:00`
- 公式checksum照合: City `True` / ASN `True`
- ライブチェック前鮮度確認: `True` / 上限 `24.0`時間
- 鮮度超過による更新: `True` / 更新後も公開最新版が24時間超: `True`
- 更新後の鮮度超過: City `True` / ASN `False`
- attribution: This product includes GeoLite2 Data created by MaxMind, available from https://www.maxmind.com.

| C2 endpoint | 観測IP | Geo | AS |
|---|---|---|---|
| `haochisadnka.cc:6685` | `134.122.185.201` | シンガポール | AS152194 / CTG Server Limited |
| `haochisadnka.cc:6698` | `134.122.185.201` | シンガポール | AS152194 / CTG Server Limited |
| `haochisadnka.cc:6699` | `134.122.185.201` | シンガポール | AS152194 / CTG Server Limited |
| `pure26.myftp.org:56001` | `151.241.154.227` | アメリカ / ニュージャージー州 / エジソン | AS399486 / 12651980 CANADA INC. |
| `logs.uvexio.com:8443` | `193.26.115.118` | アメリカ / フロリダ州 / マイアミ | AS210558 / 1337 Services GmbH |
| `tea.vexexo.com:56001` | `185.139.214.102` | アメリカ / ネバダ州 / ラスベガス | AS200019 / Alexhost Srl |
| `ftp.vilimorin.com:21` | `66.29.137.55` | アメリカ | AS22612 / Namecheap, Inc. |
| `wintersonyae246leisekoshachiy.icu:443` | `104.21.45.164` | 未取得 | AS13335 / Cloudflare, Inc. |
| `wintersonyae246leisekoshachiy.icu:443` | `172.67.216.166` | 未取得 | AS13335 / Cloudflare, Inc. |
| `geschmeidig6307-kotyatanet.sbs:443` | `104.21.29.202` | 未取得 | AS13335 / Cloudflare, Inc. |
| `geschmeidig6307-kotyatanet.sbs:443` | `172.67.149.199` | 未取得 | AS13335 / Cloudflare, Inc. |

> GeoLite2は概略位置情報です。個人・世帯・住所の識別やC2稼働確証には使用しません。
<!-- maxmind-enrichment:end -->

## 安全境界

完全一致host・単一portへ各1回、timeout最大5秒、応答最大256 byteで確認しました。malware check-in、victim metadata、stage要求、command polling、認証情報、port range、redirect追跡は使用していません。`.onion`はlocalhostのTor SOCKS5を通じて対象へ接続できた場合だけ観測成立とします。

機械可読の完全な根拠、DNS解決先、証明書／banner hash、個別timeoutは [monitoring-results.json](monitoring-results.json)、再実行対象は [targets.json](targets.json) を参照してください。
