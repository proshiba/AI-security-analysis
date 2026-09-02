# 対象限定のC2稼働状況

対象期間は `リポジトリ収録開始` から `2026-09-02T23:59:59+09:00`、監視対象は 21 endpointです。状態内訳は c2_protocol_confirmed: 5、not_observed_safety_gate: 7、not_reachable_at_observation: 9 です。

全3113 IOCファイルを走査し、通常IP/FQDN 230 hostのうち230 hostを計画へ反映（カバレッジ 100.00%）。既知port 173 endpoint、port不明 88 hostはDNS-onlyです。レビュー済みmalware固有protocolは 21 endpointへ適用しました。

監視scopeは `reviewed_protocol_profiles_only` です。`.onion`は対象外で、入力planへ明示した根拠付きendpointだけを確認しています。

この結果は観測時点のスナップショットです。TCP open、TLS証明書、一般HTTP/FTP応答だけではC2を確定しません。到達性とC2稼働確度を分離します。OFFが7日以上継続し、2回以上の実観測がある対象だけを停止扱いにして次回active対象から外します。

## 一覧

| ファミリー | endpoint | 関連case数 | 確認時刻（UTC） | 確認方法 | 観測結果 | confidence | 根拠 |
|---|---|---:|---|---|---|---|---|
| valleyrat | `118[.]107[.]21[.]88:9999` | 1 | 2026-09-01T23:18:24.569909+00:00 | 完全一致・N520 TLS server-first 44 byte handshake検証（check-in送信なし） | not_reachable_at_observation / Nmap transport到達性だけを確認し、malware固有C2応答は未確認<br>監視状態: 停止（監視対象外） | 到達 0.00（低）<br>C2稼働 0.00（低）<br>手法上限 0.95（高） | analysis-results/malware/valleyrat/versions/unknown/cases/d11e793159f0da3c88a9ecebb8e5df88919843a1eeaaf71117377db58224a1ae/n520-live-summary.json:c2 |
| asyncrat | `191[.]96[.]78[.]221:7788` | 1 | 2026-09-01T23:18:24.569984+00:00 | 完全一致・AsyncRAT TLS圧縮MessagePack Ping 1 frame＋64 byte限定応答 | not_observed_safety_gate / Nmap NSEの安全gateが未充足、またはNmap実体を利用できないため観測していない<br>監視状態: 継続監視（未観測） | 到達 0.00（低）<br>C2稼働 0.00（低）<br>手法上限 0.95（高） | analysis-results/research/c2-protocol-profiles/2026-08-04/profiles-evidence.json:analysis[0] |
| redlinestealer | `192[.]144[.]32[.]84:16383` | 1 | 2026-09-01T23:18:24.570046+00:00 | 完全一致・RedLine SOAP 1.1 CheckConnect 1要求＋4 KiB限定応答 | not_observed_safety_gate / Nmap NSEの安全gateが未充足、またはNmap実体を利用できないため観測していない<br>監視状態: 継続監視（未観測） | 到達 0.00（低）<br>C2稼働 0.00（低）<br>手法上限 0.98（高） | analysis-results/malware/redlinestealer/versions/unknown/cases/3f3ac0a31d28e9bbc85df54dd4300c9b15bf255b192fab15d94505ea1e528b02/config.json:/config/network_candidates/0<br>analysis-results/malware/redlinestealer/versions/unknown/cases/3f3ac0a31d28e9bbc85df54dd4300c9b15bf255b192fab15d94505ea1e528b02/indicators.json:indicators[1]<br>analysis-results/malware/redlinestealer/versions/unknown/cases/3f3ac0a31d28e9bbc85df54dd4300c9b15bf255b192fab15d94505ea1e528b02/indicators.json:indicators[2] |
| valleyrat | `192[.]252[.]180[.]45:6666` | 1 | 2026-09-01T23:18:25.438270+00:00 | 完全一致・IP pinning済みWinos heartbeat 1 frame＋64 byte限定受信 | c2_protocol_confirmed / allowlist済みNSEでreview済みmalware固有protocol応答が完全一致<br>監視状態: 継続監視（ON） | 到達 1.00（高）<br>C2稼働 0.95（高）<br>手法上限 0.95（高） | analysis-results/malware/valleyrat/versions/unknown/cases/6469edd613ceb62dd8e14a75628a6b75fa443ef4311da2b45e805bc7d18afe25/network-evidence.json:live_check |
| valleyrat | `202[.]95[.]8[.]27:6666` | 1 | 2026-09-01T23:18:27.647964+00:00 | 完全一致・レビュー済みvvaS check-in 3 byte＋64 byte限定header検証 | not_reachable_at_observation / Nmap transport到達性だけを確認し、malware固有C2応答は未確認<br>監視状態: 停止（監視対象外） | 到達 0.00（低）<br>C2稼働 0.00（低）<br>手法上限 0.95（高） | analysis-framework/malware/valleyrat/config/profiles/8bf54a76924ad62e3b5562826f0e491c4c498f166276b071c177b694762199f6.json:live_c2_targets[0] |
| valleyrat | `202[.]95[.]8[.]27:8888` | 1 | 2026-09-01T23:18:29.887241+00:00 | 完全一致・レビュー済みvvaS check-in 3 byte＋64 byte限定header検証 | not_reachable_at_observation / Nmap transport到達性だけを確認し、malware固有C2応答は未確認<br>監視状態: 停止（監視対象外） | 到達 0.00（低）<br>C2稼働 0.00（低）<br>手法上限 0.95（高） | analysis-framework/malware/valleyrat/config/profiles/8bf54a76924ad62e3b5562826f0e491c4c498f166276b071c177b694762199f6.json:live_c2_targets[1] |
| stealc | `31[.]77[.]228[.]62:80` | 1 | 2026-09-01T23:18:29.887340+00:00 | 完全一致・StealC v2合成端末登録＋loader task取得（最大2要求） | not_observed_safety_gate / Nmap NSEの安全gateが未充足、またはNmap実体を利用できないため観測していない<br>監視状態: 継続監視（未観測） | 到達 0.00（低）<br>C2稼働 0.00（低）<br>手法上限 0.95（高） | analysis-results/research/stealer-protocol-profiles/2026-08-04/analysis-summary.json:samples[0]<br>analysis-results/research/stealer-protocol-profiles/2026-08-04/analysis-summary.json:analysis[0] |
| purehvnc | `45[.]192[.]211[.]77:56001` | 2 | 2026-09-01T23:18:29.887375+00:00 | 完全一致・PureRAT direct TLS 1.0 handshake＋leaf証明書pin（application data送信なし） | not_observed_safety_gate / Nmap NSEの安全gateが未充足、またはNmap実体を利用できないため観測していない<br>監視状態: 継続監視（未観測） | 到達 0.00（低）<br>C2稼働 0.00（低）<br>手法上限 0.92（高） | analysis-framework/malware/purehvnc/purerat_441_emulator_evidence.json |
| valleyrat | `64[.]81[.]30[.]192:6666` | 1 | 2026-09-01T23:18:30.719786+00:00 | 完全一致・IP pinning済みWinos heartbeat 1 frame＋64 byte限定受信 | c2_protocol_confirmed / allowlist済みNSEでreview済みmalware固有protocol応答が完全一致<br>監視状態: 継続監視（ON） | 到達 1.00（高）<br>C2稼働 0.95（高）<br>手法上限 0.95（高） | analysis-results/malware/valleyrat/versions/unknown/cases/6469edd613ceb62dd8e14a75628a6b75fa443ef4311da2b45e805bc7d18afe25/iocs.json:network[1]<br>analysis-results/malware/valleyrat/versions/unknown/cases/6469edd613ceb62dd8e14a75628a6b75fa443ef4311da2b45e805bc7d18afe25/network-evidence.json:live_check |
| valleyrat | `auk218[.]club:7800` | 1 | 2026-09-01T23:18:31.585581+00:00 | 完全一致・IP pinning済みWinos heartbeat 1 frame＋64 byte限定受信 | c2_protocol_confirmed / allowlist済みNSEでreview済みmalware固有protocol応答が完全一致<br>監視状態: 継続監視（ON） | 到達 1.00（高）<br>C2稼働 0.95（高）<br>手法上限 0.95（高） | analysis-results/malware/valleyrat/versions/unknown/cases/12a22fece1fb6c9aa5620ae910b9b0a98b9013b0b8efb77369ec1bed40ddb18d/iocs.json:network[1]<br>analysis-results/malware/valleyrat/versions/unknown/cases/12a22fece1fb6c9aa5620ae910b9b0a98b9013b0b8efb77369ec1bed40ddb18d/network-evidence.json:live_check |
| lummastealer | `bizsmmit[.]cyou:80` | 1 | 2026-09-01T23:18:31.585684+00:00 | 完全一致・Lumma v6設定登録＋合成hwid task取得（最大2要求） | not_observed_safety_gate / Nmap NSEの安全gateが未充足、またはNmap実体を利用できないため観測していない<br>監視状態: 継続監視（未観測） | 到達 0.00（低）<br>C2稼働 0.00（低）<br>手法上限 0.95（高） | analysis-results/research/stealer-protocol-profiles/2026-08-04/analysis-summary.json:samples[2]<br>analysis-results/research/stealer-protocol-profiles/2026-08-04/analysis-summary.json:analysis[2] |
| darkcomet | `f168[.]com[.]co:1604` | 2 | 2026-09-01T23:18:33.879303+00:00 | 完全一致・DarkComet RC4 server-first IDTYPE復号（application data送信なし） | not_reachable_at_observation / Nmap transport到達性だけを確認し、malware固有C2応答は未確認<br>監視状態: 停止（監視対象外） | 到達 0.00（低）<br>C2稼働 0.00（低）<br>手法上限 0.98（高） | analysis-results/malware/darkcomet/versions/unknown/cases/a3fa75fe9b9c0ca9ccdc85ae6733024cbc64c545031aad9150f03fed9335850a/darkcomet-terminal-config.json:config.netdata[1] |
| darkcomet | `f168[.]name:1604` | 2 | 2026-09-01T23:18:36.136865+00:00 | 完全一致・DarkComet RC4 server-first IDTYPE復号（application data送信なし） | not_reachable_at_observation / Nmap transport到達性だけを確認し、malware固有C2応答は未確認<br>監視状態: 停止（監視対象外） | 到達 0.00（低）<br>C2稼働 0.00（低）<br>手法上限 0.98（高） | analysis-results/malware/darkcomet/versions/unknown/cases/a3fa75fe9b9c0ca9ccdc85ae6733024cbc64c545031aad9150f03fed9335850a/darkcomet-terminal-config.json:config.netdata[0] |
| darkcomet | `f168hi[.]com:1604` | 2 | 2026-09-01T23:18:38.400437+00:00 | 完全一致・DarkComet RC4 server-first IDTYPE復号（application data送信なし） | not_reachable_at_observation / Nmap transport到達性だけを確認し、malware固有C2応答は未確認<br>監視状態: 停止（監視対象外） | 到達 0.00（低）<br>C2稼働 0.00（低）<br>手法上限 0.98（高） | analysis-results/malware/darkcomet/versions/unknown/cases/a3fa75fe9b9c0ca9ccdc85ae6733024cbc64c545031aad9150f03fed9335850a/darkcomet-terminal-config.json:config.netdata[2] |
| agenttesla | `ftp[.]vilimorin[.]com:21` | 1 | 2026-09-01T23:18:38.400502+00:00 | 完全一致・private資格情報によるFTP USER/PASS/QUIT限定認証（file操作なし） | not_observed_safety_gate / Nmap NSEの安全gateが未充足、またはNmap実体を利用できないため観測していない<br>監視状態: 継続監視（未観測） | 到達 0.00（低）<br>C2稼働 0.00（低）<br>手法上限 0.95（高） | analysis-results/malware/agenttesla/versions/2026-07-js-luajit-donut-ftp/cases/3f09145757282e6a59cd69319ac3b9da3265022a1d4f92a1646f8ddbaad89333/config.json:config_endpoints[0]<br>analysis-results/malware/agenttesla/versions/2026-07-js-luajit-donut-ftp/cases/3f09145757282e6a59cd69319ac3b9da3265022a1d4f92a1646f8ddbaad89333/iocs.json:network[0] |
| valleyrat | `haochisadnka[.]cc:6685` | 1 | 2026-09-01T23:18:39.268476+00:00 | 完全一致・IP pinning済みWinos heartbeat 1 frame＋64 byte限定受信 | c2_protocol_confirmed / allowlist済みNSEでreview済みmalware固有protocol応答が完全一致<br>監視状態: 継続監視（ON） | 到達 1.00（高）<br>C2稼働 0.95（高）<br>手法上限 0.95（高） | analysis-results/malware/valleyrat/versions/unknown/cases/ee0ef34a4402dea54ec8b4e0557de9605a038a4f2b82380f2978296fd60f9791/iocs.json:network[0] |
| valleyrat | `ljdnxz[.]cc:8868` | 1 | 2026-09-01T23:18:40.122778+00:00 | 完全一致・IP pinning済みWinos heartbeat 1 frame＋64 byte限定受信 | c2_protocol_confirmed / allowlist済みNSEでreview済みmalware固有protocol応答が完全一致<br>監視状態: 継続監視（ON） | 到達 1.00（高）<br>C2稼働 0.95（高）<br>手法上限 0.95（高） | analysis-results/malware/valleyrat/versions/unknown/cases/e0e1ae775ef8e530875235f035fb623b217d48fa810537144c872fcf41592648/network-evidence.json:live_check |
| venomrat | `s2gj9tonn[.]localto[.]net:6377` | 1 | 2026-09-01T23:18:40.122880+00:00 | 完全一致・VenomRAT TLS圧縮MessagePack Ping 1 frame＋64 byte限定応答 | not_observed_safety_gate / Nmap NSEの安全gateが未充足、またはNmap実体を利用できないため観測していない<br>監視状態: 継続監視（未観測） | 到達 0.00（低）<br>C2稼働 0.00（低）<br>手法上限 0.95（高） | analysis-results/malware/venomrat/versions/v6.0.3/cases/6a24ba25482c73d193fcc208d8ae267236b870b9ab30c44cabe2dc8bfb7a1073/iocs.json:network[2]<br>analysis-results/research/c2-protocol-profiles/2026-08-04/profiles-evidence.json:analysis[1] |
| purehvnc | `tirakian[.]com:56001` | 1 | 2026-09-01T23:18:40.862874+00:00 | 完全一致・PureRAT 4 byte prelude＋TLS 1.2昇格と検体内蔵証明書pin照合（応答受信なし） | not_reachable_at_observation / Nmap transport到達性だけを確認し、malware固有C2応答は未確認<br>監視状態: 停止（監視対象外） | 到達 0.00（低）<br>C2稼働 0.00（低）<br>手法上限 0.95（高） | analysis-results/malware/purehvnc/versions/v4.4.1/cases/e55412555b4699c6d3ce2ac60df81eb1ee0d5aa412a303555c8f64037d5633d0/config.json:config.certificate_sha256<br>analysis-results/malware/purehvnc/versions/v4.4.1/cases/e55412555b4699c6d3ce2ac60df81eb1ee0d5aa412a303555c8f64037d5633d0/iocs.json:configured_c2[0] |
| purehvnc | `tirakian[.]com:56002` | 1 | 2026-09-01T23:18:41.596918+00:00 | 完全一致・PureRAT 4 byte prelude＋TLS 1.2昇格と検体内蔵証明書pin照合（応答受信なし） | not_reachable_at_observation / Nmap transport到達性だけを確認し、malware固有C2応答は未確認<br>監視状態: 停止（監視対象外） | 到達 0.00（低）<br>C2稼働 0.00（低）<br>手法上限 0.95（高） | analysis-results/malware/purehvnc/versions/v4.4.1/cases/e55412555b4699c6d3ce2ac60df81eb1ee0d5aa412a303555c8f64037d5633d0/config.json:config.certificate_sha256<br>analysis-results/malware/purehvnc/versions/v4.4.1/cases/e55412555b4699c6d3ce2ac60df81eb1ee0d5aa412a303555c8f64037d5633d0/iocs.json:configured_c2[1] |
| purehvnc | `tirakian[.]com:56003` | 1 | 2026-09-01T23:18:42.351562+00:00 | 完全一致・PureRAT 4 byte prelude＋TLS 1.2昇格と検体内蔵証明書pin照合（応答受信なし） | not_reachable_at_observation / Nmap transport到達性だけを確認し、malware固有C2応答は未確認<br>監視状態: 停止（監視対象外） | 到達 0.00（低）<br>C2稼働 0.00（低）<br>手法上限 0.95（高） | analysis-results/malware/purehvnc/versions/v4.4.1/cases/e55412555b4699c6d3ce2ac60df81eb1ee0d5aa412a303555c8f64037d5633d0/config.json:config.certificate_sha256<br>analysis-results/malware/purehvnc/versions/v4.4.1/cases/e55412555b4699c6d3ce2ac60df81eb1ee0d5aa412a303555c8f64037d5633d0/iocs.json:configured_c2[2] |

## confidenceの読み方

- `到達`: 今回のtransport／application到達観測の確からしさです。
- `C2稼働`: 観測結果が、解析済みmalwareのC2 application稼働を示す確度です。TCP接続だけなら最大0.25です。
- `手法上限`: その確認方法が、成功時でも単独で到達できるC2確度の上限です。malware check-inやmalware固有protocolとの一致がない限り0.60以下です。
- `negative_observation_confidence` はJSONに保持し、拒否は比較的強い停止側観測、timeoutは弱い停止側観測として区別します。

## DNS/IP遷移履歴

raw IP変化は 85 回、CDN除外後のインフラIP変化は 0 回、同一共有CDN内ローテーションとして除外した変化は 13 回です。

Cloudflare、Akamai、Fastly等の共有CDNでは、同一provider内のedge IP入替を履歴へ残しますが、C2インフラ自体のIP変化件数には加えません。providerまたは非CDN ASNが変わった場合はインフラ変化として扱います。詳細は `monitoring-history.json` の `dns_tracking.history` を参照してください。

## 旧IPから新IPへの遷移

| endpoint | 観測時刻（UTC） | 旧IP（AS・Geo・タグ） | 新IP（AS・Geo・タグ） | 分類 |
|---|---|---|---|---|
| `118[.]107[.]21[.]88:9999` | 2026-08-24T04:31:08.450698+00:00 | `118[.]107[.]21[.]88`<br>AS152194 / CTG Server Limited<br>シンガポール<br>防弾ホスティング - 疑い、C2候補インフラ、ホスティング<br>防弾ホスティング - 疑い | 解決なし | DNS解決状態変化 |
| `118[.]107[.]21[.]88:9999` | 2026-08-25T02:18:00.466393+00:00 | 解決なし | `118[.]107[.]21[.]88`<br>AS152194 / CTG Server Limited<br>シンガポール<br>防弾ホスティング - 疑い、C2候補インフラ、ホスティング<br>防弾ホスティング - 疑い | DNS解決状態変化 |
| `191[.]96[.]78[.]221:7788` | 2026-08-07T01:22:36.636825+00:00 | `191[.]96[.]78[.]221`<br>AS270353 / Tyna Host - Datacenter no Brasil<br>ブラジル連邦共和国 / ミナス・ジェライス州 / Muriaé<br>C2候補インフラ、ホスティング<br>防弾ホスティング判定不能 | 解決なし | DNS解決状態変化 |
| `191[.]96[.]78[.]221:7788` | 2026-08-08T04:29:59.306435+00:00 | 解決なし | `191[.]96[.]78[.]221`<br>AS270353 / Tyna Host - Datacenter no Brasil<br>ブラジル連邦共和国 / ミナス・ジェライス州 / Muriaé<br>C2候補インフラ、ホスティング<br>防弾ホスティング判定不能 | DNS解決状態変化 |
| `191[.]96[.]78[.]221:7788` | 2026-08-13T04:16:07.865987+00:00 | `191[.]96[.]78[.]221`<br>AS270353 / Tyna Host - Datacenter no Brasil<br>ブラジル連邦共和国 / ミナス・ジェライス州 / Muriaé<br>C2候補インフラ、ホスティング<br>防弾ホスティング判定不能 | 解決なし | DNS解決状態変化 |
| `191[.]96[.]78[.]221:7788` | 2026-08-14T22:37:15.268044+00:00 | 解決なし | `191[.]96[.]78[.]221`<br>AS270353 / Tyna Host - Datacenter no Brasil<br>ブラジル連邦共和国 / ミナス・ジェライス州 / Muriaé<br>C2候補インフラ、ホスティング<br>防弾ホスティング判定不能 | DNS解決状態変化 |
| `191[.]96[.]78[.]221:7788` | 2026-08-16T03:12:56.627310+00:00 | `191[.]96[.]78[.]221`<br>AS270353 / Tyna Host - Datacenter no Brasil<br>ブラジル連邦共和国 / ミナス・ジェライス州 / Muriaé<br>C2候補インフラ、ホスティング<br>防弾ホスティング判定不能 | 解決なし | DNS解決状態変化 |
| `191[.]96[.]78[.]221:7788` | 2026-08-16T23:49:05.393017+00:00 | 解決なし | `191[.]96[.]78[.]221`<br>AS270353 / Tyna Host - Datacenter no Brasil<br>ブラジル連邦共和国 / ミナス・ジェライス州 / Muriaé<br>C2候補インフラ、ホスティング<br>防弾ホスティング判定不能 | DNS解決状態変化 |
| `191[.]96[.]78[.]221:7788` | 2026-08-18T00:18:00.295768+00:00 | `191[.]96[.]78[.]221`<br>AS270353 / Tyna Host - Datacenter no Brasil<br>ブラジル連邦共和国 / ミナス・ジェライス州 / Muriaé<br>C2候補インフラ、ホスティング<br>防弾ホスティング判定不能 | 解決なし | DNS解決状態変化 |
| `191[.]96[.]78[.]221:7788` | 2026-08-22T04:14:42.919685+00:00 | 解決なし | `191[.]96[.]78[.]221`<br>AS270353 / Tyna Host - Datacenter no Brasil<br>ブラジル連邦共和国 / ミナス・ジェライス州 / Muriaé<br>C2候補インフラ、ホスティング<br>防弾ホスティング判定不能 | DNS解決状態変化 |
| `191[.]96[.]78[.]221:7788` | 2026-08-24T04:31:08.450889+00:00 | `191[.]96[.]78[.]221`<br>AS270353 / Tyna Host - Datacenter no Brasil<br>ブラジル連邦共和国 / ミナス・ジェライス州 / Muriaé<br>C2候補インフラ、ホスティング<br>防弾ホスティング判定不能 | 解決なし | DNS解決状態変化 |
| `191[.]96[.]78[.]221:7788` | 2026-08-25T02:18:21.080322+00:00 | 解決なし | `191[.]96[.]78[.]221`<br>AS270353 / Tyna Host - Datacenter no Brasil<br>ブラジル連邦共和国 / ミナス・ジェライス州 / Muriaé<br>C2候補インフラ、ホスティング<br>防弾ホスティング判定不能 | DNS解決状態変化 |
| `191[.]96[.]78[.]221:7788` | 2026-08-26T00:16:07.430007+00:00 | `191[.]96[.]78[.]221`<br>AS270353 / Tyna Host - Datacenter no Brasil<br>ブラジル連邦共和国 / ミナス・ジェライス州 / Muriaé<br>C2候補インフラ、ホスティング<br>防弾ホスティング判定不能 | 解決なし | DNS解決状態変化 |
| `192[.]144[.]32[.]84:16383` | 2026-08-22T04:14:49.730956+00:00 | 解決なし | `192[.]144[.]32[.]84`<br>AS397966 / ReadyDedis, LLC<br>アメリカ / ニュージャージー州 / North Bergen<br>C2候補インフラ<br>防弾ホスティング判定不能 | DNS解決状態変化 |
| `192[.]144[.]32[.]84:16383` | 2026-08-24T04:31:08.450927+00:00 | `192[.]144[.]32[.]84`<br>AS397966 / ReadyDedis, LLC<br>アメリカ / ニュージャージー州 / North Bergen<br>C2候補インフラ<br>防弾ホスティング判定不能 | 解決なし | DNS解決状態変化 |
| `192[.]252[.]180[.]45:6666` | 2026-08-24T04:31:08.450960+00:00 | `192[.]252[.]180[.]45`<br>AS152194 / CTG Server Limited<br>アメリカ<br>防弾ホスティング - 疑い、C2候補インフラ、ホスティング<br>防弾ホスティング - 疑い | 解決なし | DNS解決状態変化 |
| `192[.]252[.]180[.]45:6666` | 2026-08-25T02:18:23.073563+00:00 | 解決なし | `192[.]252[.]180[.]45`<br>AS152194 / CTG Server Limited<br>アメリカ<br>防弾ホスティング - 疑い、C2候補インフラ、ホスティング<br>防弾ホスティング - 疑い | DNS解決状態変化 |
| `202[.]95[.]8[.]27:6666` | 2026-08-24T04:31:08.451086+00:00 | `202[.]95[.]8[.]27`<br>AS152194 / CTG Server Limited<br>中国<br>防弾ホスティング - 疑い、C2候補インフラ、ホスティング<br>防弾ホスティング - 疑い | 解決なし | DNS解決状態変化 |
| `202[.]95[.]8[.]27:6666` | 2026-08-25T02:18:35.053749+00:00 | 解決なし | `202[.]95[.]8[.]27`<br>AS152194 / CTG Server Limited<br>中国<br>防弾ホスティング - 疑い、C2候補インフラ、ホスティング<br>防弾ホスティング - 疑い | DNS解決状態変化 |
| `202[.]95[.]8[.]27:8888` | 2026-08-24T04:31:08.451096+00:00 | `202[.]95[.]8[.]27`<br>AS152194 / CTG Server Limited<br>中国<br>防弾ホスティング - 疑い、C2候補インフラ、ホスティング<br>防弾ホスティング - 疑い | 解決なし | DNS解決状態変化 |
| `202[.]95[.]8[.]27:8888` | 2026-08-25T02:18:37.248109+00:00 | 解決なし | `202[.]95[.]8[.]27`<br>AS152194 / CTG Server Limited<br>中国<br>防弾ホスティング - 疑い、C2候補インフラ、ホスティング<br>防弾ホスティング - 疑い | DNS解決状態変化 |
| `31[.]77[.]228[.]62:80` | 2026-08-05T23:44:57.456978+00:00 | 解決なし | `31[.]77[.]228[.]62`<br>AS202226 / Great Flower<br>アメリカ<br>C2候補インフラ<br>防弾ホスティング判定不能 | DNS解決状態変化 |
| `31[.]77[.]228[.]62:80` | 2026-08-07T01:23:19.120367+00:00 | `31[.]77[.]228[.]62`<br>AS202226 / Great Flower<br>アメリカ<br>C2候補インフラ<br>防弾ホスティング判定不能 | 解決なし | DNS解決状態変化 |
| `31[.]77[.]228[.]62:80` | 2026-08-11T00:25:34.505770+00:00 | 解決なし | `31[.]77[.]228[.]62`<br>AS202226 / Great Flower<br>アメリカ<br>C2候補インフラ<br>防弾ホスティング判定不能 | DNS解決状態変化 |
| `31[.]77[.]228[.]62:80` | 2026-08-13T04:16:53.159765+00:00 | `31[.]77[.]228[.]62`<br>AS202226 / Great Flower<br>アメリカ<br>C2候補インフラ<br>防弾ホスティング判定不能 | 解決なし | DNS解決状態変化 |
| `31[.]77[.]228[.]62:80` | 2026-08-22T04:15:22.121089+00:00 | 解決なし | `31[.]77[.]228[.]62`<br>AS202226 / Great Flower<br>アメリカ<br>C2候補インフラ<br>防弾ホスティング判定不能 | DNS解決状態変化 |
| `31[.]77[.]228[.]62:80` | 2026-08-24T04:31:08.451201+00:00 | `31[.]77[.]228[.]62`<br>AS202226 / Great Flower<br>アメリカ<br>C2候補インフラ<br>防弾ホスティング判定不能 | 解決なし | DNS解決状態変化 |
| `31[.]77[.]228[.]62:80` | 2026-08-27T23:31:40.592218+00:00 | 解決なし | `31[.]77[.]228[.]62`<br>AS202226 / Great Flower<br>アメリカ<br>C2候補インフラ<br>防弾ホスティング判定不能 | DNS解決状態変化 |
| `31[.]77[.]228[.]62:80` | 2026-08-31T22:48:56.454970+00:00 | `31[.]77[.]228[.]62`<br>AS202226 / Great Flower<br>アメリカ<br>C2候補インフラ<br>防弾ホスティング判定不能 | 解決なし | DNS解決状態変化 |
| `64[.]81[.]30[.]192:6666` | 2026-08-24T04:31:08.451368+00:00 | `64[.]81[.]30[.]192`<br>AS979 / NetLab Global<br>アメリカ / カリフォルニア州 / ロサンゼルス<br>C2候補インフラ<br>防弾ホスティング判定不能 | 解決なし | DNS解決状態変化 |
| `64[.]81[.]30[.]192:6666` | 2026-08-25T02:19:01.036855+00:00 | 解決なし | `64[.]81[.]30[.]192`<br>AS979 / NetLab Global<br>アメリカ / カリフォルニア州 / ロサンゼルス<br>C2候補インフラ<br>防弾ホスティング判定不能 | DNS解決状態変化 |
| `auk218[.]club:7800` | 2026-08-05T23:45:33.676855+00:00 | 解決なし | `118[.]107[.]0[.]196`<br>AS152194 / CTG Server Limited<br>シンガポール<br>防弾ホスティング - 疑い、C2候補インフラ、DNS解決先、ホスティング<br>防弾ホスティング - 疑い | DNS解決状態変化 |
| `auk218[.]club:7800` | 2026-08-24T04:31:08.451475+00:00 | `118[.]107[.]0[.]196`<br>AS152194 / CTG Server Limited<br>シンガポール<br>防弾ホスティング - 疑い、C2候補インフラ、DNS解決先、ホスティング<br>防弾ホスティング - 疑い | 解決なし | DNS解決状態変化 |
| `auk218[.]club:7800` | 2026-08-25T02:19:13.222063+00:00 | 解決なし | `118[.]107[.]0[.]196`<br>AS152194 / CTG Server Limited<br>シンガポール<br>防弾ホスティング - 疑い、C2候補インフラ、DNS解決先、ホスティング<br>防弾ホスティング - 疑い | DNS解決状態変化 |
| `bizsmmit[.]cyou:80` | 2026-08-05T23:45:37.462885+00:00 | 解決なし | `64[.]89[.]161[.]173`<br>AS205759 / Ghosty Networks LLC<br>アメリカ<br>C2候補インフラ、DNS解決先、ホスティング<br>防弾ホスティング判定不能 | DNS解決状態変化 |
| `bizsmmit[.]cyou:80` | 2026-08-07T01:23:58.787370+00:00 | `64[.]89[.]161[.]173`<br>AS205759 / Ghosty Networks LLC<br>アメリカ<br>C2候補インフラ、DNS解決先、ホスティング<br>防弾ホスティング判定不能 | 解決なし | DNS解決状態変化 |
| `bizsmmit[.]cyou:80` | 2026-08-08T04:31:26.789204+00:00 | 解決なし | `64[.]89[.]161[.]173`<br>AS205759 / Ghosty Networks LLC<br>アメリカ<br>C2候補インフラ、DNS解決先、ホスティング<br>防弾ホスティング判定不能 | DNS解決状態変化 |
| `bizsmmit[.]cyou:80` | 2026-08-10T01:11:13.447699+00:00 | `64[.]89[.]161[.]173`<br>AS205759 / Ghosty Networks LLC<br>アメリカ<br>C2候補インフラ、DNS解決先、ホスティング<br>防弾ホスティング判定不能 | 解決なし | DNS解決状態変化 |
| `bizsmmit[.]cyou:80` | 2026-08-11T00:26:18.546465+00:00 | 解決なし | `64[.]89[.]161[.]173`<br>AS205759 / Ghosty Networks LLC<br>アメリカ<br>C2候補インフラ、DNS解決先、ホスティング<br>防弾ホスティング判定不能 | DNS解決状態変化 |
| `bizsmmit[.]cyou:80` | 2026-08-13T04:17:49.996852+00:00 | `64[.]89[.]161[.]173`<br>AS205759 / Ghosty Networks LLC<br>アメリカ<br>C2候補インフラ、DNS解決先、ホスティング<br>防弾ホスティング判定不能 | 解決なし | DNS解決状態変化 |
| `bizsmmit[.]cyou:80` | 2026-08-22T04:15:55.172601+00:00 | 解決なし | `64[.]89[.]161[.]173`<br>AS205759 / Ghosty Networks LLC<br>アメリカ<br>C2候補インフラ、DNS解決先、ホスティング<br>防弾ホスティング判定不能 | DNS解決状態変化 |
| `bizsmmit[.]cyou:80` | 2026-08-24T04:31:08.451514+00:00 | `64[.]89[.]161[.]173`<br>AS205759 / Ghosty Networks LLC<br>アメリカ<br>C2候補インフラ、DNS解決先、ホスティング<br>防弾ホスティング判定不能 | 解決なし | DNS解決状態変化 |
| `bizsmmit[.]cyou:80` | 2026-08-27T23:32:15.961260+00:00 | 解決なし | `64[.]89[.]161[.]173`<br>AS205759 / Ghosty Networks LLC<br>アメリカ<br>C2候補インフラ、DNS解決先、ホスティング<br>防弾ホスティング判定不能 | DNS解決状態変化 |
| `bizsmmit[.]cyou:80` | 2026-08-31T22:49:25.910257+00:00 | `64[.]89[.]161[.]173`<br>AS205759 / Ghosty Networks LLC<br>アメリカ<br>C2候補インフラ、DNS解決先、ホスティング<br>防弾ホスティング判定不能 | 解決なし | DNS解決状態変化 |
| `f168[.]com[.]co:1604` | 2026-08-16T03:14:14.995850+00:00 | 解決なし | `104[.]21[.]96[.]48`<br>AS13335 / Cloudflare, Inc.<br>Geo未取得<br>Anycast／共有エッジ、C2候補インフラ、CDN、DNS解決先、ホスティング<br>防弾ホスティング根拠なし（共有CDN） | DNS解決状態変化 |
| `f168[.]com[.]co:1604` | 2026-08-18T00:19:23.902582+00:00 | `104[.]21[.]96[.]48`<br>AS13335 / Cloudflare, Inc.<br>Geo未取得<br>Anycast／共有エッジ、C2候補インフラ、CDN、DNS解決先、ホスティング<br>防弾ホスティング根拠なし（共有CDN） | `172[.]67[.]173[.]5`<br>AS13335 / Cloudflare, Inc.<br>Geo未取得<br>Anycast／共有エッジ、C2候補インフラ、CDN、DNS解決先、ホスティング<br>防弾ホスティング根拠なし（共有CDN） | 共有CDNローテーション（除外） |
| `f168[.]com[.]co:1604` | 2026-08-18T22:12:34.130455+00:00 | `172[.]67[.]173[.]5`<br>AS13335 / Cloudflare, Inc.<br>Geo未取得<br>Anycast／共有エッジ、C2候補インフラ、CDN、DNS解決先、ホスティング<br>防弾ホスティング根拠なし（共有CDN） | `104[.]21[.]96[.]48`<br>AS13335 / Cloudflare, Inc.<br>Geo未取得<br>Anycast／共有エッジ、C2候補インフラ、CDN、DNS解決先、ホスティング<br>防弾ホスティング根拠なし（共有CDN） | 共有CDNローテーション（除外） |
| `f168[.]com[.]co:1604` | 2026-08-24T04:31:08.451651+00:00 | `104[.]21[.]96[.]48`<br>AS13335 / Cloudflare, Inc.<br>Geo未取得<br>Anycast／共有エッジ、C2候補インフラ、CDN、DNS解決先、ホスティング<br>防弾ホスティング根拠なし（共有CDN） | 解決なし | DNS解決状態変化 |
| `f168[.]com[.]co:1604` | 2026-08-25T02:19:23.843370+00:00 | 解決なし | `172[.]67[.]173[.]5`<br>AS13335 / Cloudflare, Inc.<br>Geo未取得<br>Anycast／共有エッジ、C2候補インフラ、CDN、DNS解決先、ホスティング<br>防弾ホスティング根拠なし（共有CDN） | DNS解決状態変化 |
| `f168[.]com[.]co:1604` | 2026-08-26T00:17:20.288979+00:00 | `172[.]67[.]173[.]5`<br>AS13335 / Cloudflare, Inc.<br>Geo未取得<br>Anycast／共有エッジ、C2候補インフラ、CDN、DNS解決先、ホスティング<br>防弾ホスティング根拠なし（共有CDN） | `104[.]21[.]96[.]48`<br>AS13335 / Cloudflare, Inc.<br>Geo未取得<br>Anycast／共有エッジ、C2候補インフラ、CDN、DNS解決先、ホスティング<br>防弾ホスティング根拠なし（共有CDN） | 共有CDNローテーション（除外） |
| `f168[.]com[.]co:1604` | 2026-08-27T02:30:59.006179+00:00 | `104[.]21[.]96[.]48`<br>AS13335 / Cloudflare, Inc.<br>Geo未取得<br>Anycast／共有エッジ、C2候補インフラ、CDN、DNS解決先、ホスティング<br>防弾ホスティング根拠なし（共有CDN） | `172[.]67[.]173[.]5`<br>AS13335 / Cloudflare, Inc.<br>Geo未取得<br>Anycast／共有エッジ、C2候補インフラ、CDN、DNS解決先、ホスティング<br>防弾ホスティング根拠なし（共有CDN） | 共有CDNローテーション（除外） |
| `f168[.]name:1604` | 2026-08-16T03:14:17.238749+00:00 | 解決なし | `172[.]67[.]221[.]66`<br>AS13335 / Cloudflare, Inc.<br>Geo未取得<br>Anycast／共有エッジ、C2候補インフラ、CDN、DNS解決先、ホスティング<br>防弾ホスティング根拠なし（共有CDN） | DNS解決状態変化 |
| `f168[.]name:1604` | 2026-08-16T23:50:25.129603+00:00 | `172[.]67[.]221[.]66`<br>AS13335 / Cloudflare, Inc.<br>Geo未取得<br>Anycast／共有エッジ、C2候補インフラ、CDN、DNS解決先、ホスティング<br>防弾ホスティング根拠なし（共有CDN） | `104[.]21[.]24[.]253`<br>AS13335 / Cloudflare, Inc.<br>Geo未取得<br>Anycast／共有エッジ、C2候補インフラ、CDN、DNS解決先、ホスティング<br>防弾ホスティング根拠なし（共有CDN） | 共有CDNローテーション（除外） |
| `f168[.]name:1604` | 2026-08-18T00:19:26.228588+00:00 | `104[.]21[.]24[.]253`<br>AS13335 / Cloudflare, Inc.<br>Geo未取得<br>Anycast／共有エッジ、C2候補インフラ、CDN、DNS解決先、ホスティング<br>防弾ホスティング根拠なし（共有CDN） | `172[.]67[.]221[.]66`<br>AS13335 / Cloudflare, Inc.<br>Geo未取得<br>Anycast／共有エッジ、C2候補インフラ、CDN、DNS解決先、ホスティング<br>防弾ホスティング根拠なし（共有CDN） | 共有CDNローテーション（除外） |
| `f168[.]name:1604` | 2026-08-24T04:31:08.451662+00:00 | `172[.]67[.]221[.]66`<br>AS13335 / Cloudflare, Inc.<br>Geo未取得<br>Anycast／共有エッジ、C2候補インフラ、CDN、DNS解決先、ホスティング<br>防弾ホスティング根拠なし（共有CDN） | 解決なし | DNS解決状態変化 |
| `f168[.]name:1604` | 2026-08-25T02:19:26.095777+00:00 | 解決なし | `172[.]67[.]221[.]66`<br>AS13335 / Cloudflare, Inc.<br>Geo未取得<br>Anycast／共有エッジ、C2候補インフラ、CDN、DNS解決先、ホスティング<br>防弾ホスティング根拠なし（共有CDN） | DNS解決状態変化 |
| `f168[.]name:1604` | 2026-08-26T00:17:22.527307+00:00 | `172[.]67[.]221[.]66`<br>AS13335 / Cloudflare, Inc.<br>Geo未取得<br>Anycast／共有エッジ、C2候補インフラ、CDN、DNS解決先、ホスティング<br>防弾ホスティング根拠なし（共有CDN） | `104[.]21[.]24[.]253`<br>AS13335 / Cloudflare, Inc.<br>Geo未取得<br>Anycast／共有エッジ、C2候補インフラ、CDN、DNS解決先、ホスティング<br>防弾ホスティング根拠なし（共有CDN） | 共有CDNローテーション（除外） |
| `f168[.]name:1604` | 2026-08-27T23:32:28.397036+00:00 | `104[.]21[.]24[.]253`<br>AS13335 / Cloudflare, Inc.<br>Geo未取得<br>Anycast／共有エッジ、C2候補インフラ、CDN、DNS解決先、ホスティング<br>防弾ホスティング根拠なし（共有CDN） | `172[.]67[.]221[.]66`<br>AS13335 / Cloudflare, Inc.<br>Geo未取得<br>Anycast／共有エッジ、C2候補インフラ、CDN、DNS解決先、ホスティング<br>防弾ホスティング根拠なし（共有CDN） | 共有CDNローテーション（除外） |
| `f168hi[.]com:1604` | 2026-08-16T03:14:19.476624+00:00 | 解決なし | `104[.]21[.]82[.]149`<br>AS13335 / Cloudflare, Inc.<br>Geo未取得<br>Anycast／共有エッジ、C2候補インフラ、CDN、DNS解決先、ホスティング<br>防弾ホスティング根拠なし（共有CDN） | DNS解決状態変化 |
| `f168hi[.]com:1604` | 2026-08-16T23:50:27.341672+00:00 | `104[.]21[.]82[.]149`<br>AS13335 / Cloudflare, Inc.<br>Geo未取得<br>Anycast／共有エッジ、C2候補インフラ、CDN、DNS解決先、ホスティング<br>防弾ホスティング根拠なし（共有CDN） | `172[.]67[.]158[.]176`<br>AS13335 / Cloudflare, Inc.<br>Geo未取得<br>Anycast／共有エッジ、C2候補インフラ、CDN、DNS解決先、ホスティング<br>防弾ホスティング根拠なし（共有CDN） | 共有CDNローテーション（除外） |
| `f168hi[.]com:1604` | 2026-08-18T00:19:28.554777+00:00 | `172[.]67[.]158[.]176`<br>AS13335 / Cloudflare, Inc.<br>Geo未取得<br>Anycast／共有エッジ、C2候補インフラ、CDN、DNS解決先、ホスティング<br>防弾ホスティング根拠なし（共有CDN） | `104[.]21[.]82[.]149`<br>AS13335 / Cloudflare, Inc.<br>Geo未取得<br>Anycast／共有エッジ、C2候補インフラ、CDN、DNS解決先、ホスティング<br>防弾ホスティング根拠なし（共有CDN） | 共有CDNローテーション（除外） |
| `f168hi[.]com:1604` | 2026-08-21T16:34:54.350958+00:00 | `104[.]21[.]82[.]149`<br>AS13335 / Cloudflare, Inc.<br>Geo未取得<br>Anycast／共有エッジ、C2候補インフラ、CDN、DNS解決先、ホスティング<br>防弾ホスティング根拠なし（共有CDN） | `172[.]67[.]158[.]176`<br>AS13335 / Cloudflare, Inc.<br>Geo未取得<br>Anycast／共有エッジ、C2候補インフラ、CDN、DNS解決先、ホスティング<br>防弾ホスティング根拠なし（共有CDN） | 共有CDNローテーション（除外） |
| `f168hi[.]com:1604` | 2026-08-24T04:31:08.451672+00:00 | `172[.]67[.]158[.]176`<br>AS13335 / Cloudflare, Inc.<br>Geo未取得<br>Anycast／共有エッジ、C2候補インフラ、CDN、DNS解決先、ホスティング<br>防弾ホスティング根拠なし（共有CDN） | 解決なし | DNS解決状態変化 |
| `f168hi[.]com:1604` | 2026-08-25T02:19:28.328505+00:00 | 解決なし | `104[.]21[.]82[.]149`<br>AS13335 / Cloudflare, Inc.<br>Geo未取得<br>Anycast／共有エッジ、C2候補インフラ、CDN、DNS解決先、ホスティング<br>防弾ホスティング根拠なし（共有CDN） | DNS解決状態変化 |
| `f168hi[.]com:1604` | 2026-08-26T00:17:24.758026+00:00 | `104[.]21[.]82[.]149`<br>AS13335 / Cloudflare, Inc.<br>Geo未取得<br>Anycast／共有エッジ、C2候補インフラ、CDN、DNS解決先、ホスティング<br>防弾ホスティング根拠なし（共有CDN） | `172[.]67[.]158[.]176`<br>AS13335 / Cloudflare, Inc.<br>Geo未取得<br>Anycast／共有エッジ、C2候補インフラ、CDN、DNS解決先、ホスティング<br>防弾ホスティング根拠なし（共有CDN） | 共有CDNローテーション（除外） |
| `f168hi[.]com:1604` | 2026-08-31T22:49:39.215594+00:00 | `172[.]67[.]158[.]176`<br>AS13335 / Cloudflare, Inc.<br>Geo未取得<br>Anycast／共有エッジ、C2候補インフラ、CDN、DNS解決先、ホスティング<br>防弾ホスティング根拠なし（共有CDN） | `104[.]21[.]82[.]149`<br>AS13335 / Cloudflare, Inc.<br>Geo未取得<br>Anycast／共有エッジ、C2候補インフラ、CDN、DNS解決先、ホスティング<br>防弾ホスティング根拠なし（共有CDN） | 共有CDNローテーション（除外） |
| `ftp[.]vilimorin[.]com:21` | 2026-08-05T23:45:38.882774+00:00 | 解決なし | `66[.]29[.]137[.]55`<br>AS22612 / Namecheap, Inc.<br>アメリカ<br>C2候補インフラ、DNS解決先、ドメイン事業者、ホスティング<br>防弾ホスティング判定不能 | DNS解決状態変化 |
| `ftp[.]vilimorin[.]com:21` | 2026-08-07T01:24:03.766404+00:00 | `66[.]29[.]137[.]55`<br>AS22612 / Namecheap, Inc.<br>アメリカ<br>C2候補インフラ、DNS解決先、ドメイン事業者、ホスティング<br>防弾ホスティング判定不能 | 解決なし | DNS解決状態変化 |
| `ftp[.]vilimorin[.]com:21` | 2026-08-08T04:31:32.861349+00:00 | 解決なし | `66[.]29[.]137[.]55`<br>AS22612 / Namecheap, Inc.<br>アメリカ<br>C2候補インフラ、DNS解決先、ドメイン事業者、ホスティング<br>防弾ホスティング判定不能 | DNS解決状態変化 |
| `ftp[.]vilimorin[.]com:21` | 2026-08-10T01:11:25.701254+00:00 | `66[.]29[.]137[.]55`<br>AS22612 / Namecheap, Inc.<br>アメリカ<br>C2候補インフラ、DNS解決先、ドメイン事業者、ホスティング<br>防弾ホスティング判定不能 | 解決なし | DNS解決状態変化 |
| `haochisadnka[.]cc:6685` | 2026-08-08T04:31:33.642579+00:00 | `134[.]122[.]185[.]201`<br>AS152194 / CTG Server Limited<br>シンガポール<br>防弾ホスティング - 疑い、C2候補インフラ、DNS解決先、ホスティング<br>防弾ホスティング - 疑い | 解決なし | DNS解決状態変化 |
| `haochisadnka[.]cc:6685` | 2026-08-10T01:11:26.323554+00:00 | 解決なし | `134[.]122[.]185[.]201`<br>AS152194 / CTG Server Limited<br>シンガポール<br>防弾ホスティング - 疑い、C2候補インフラ、DNS解決先、ホスティング<br>防弾ホスティング - 疑い | DNS解決状態変化 |
| `haochisadnka[.]cc:6685` | 2026-08-24T04:31:08.451860+00:00 | `134[.]122[.]185[.]201`<br>AS152194 / CTG Server Limited<br>シンガポール<br>防弾ホスティング - 疑い、C2候補インフラ、DNS解決先、ホスティング<br>防弾ホスティング - 疑い | 解決なし | DNS解決状態変化 |
| `haochisadnka[.]cc:6685` | 2026-08-25T02:19:38.543739+00:00 | 解決なし | `134[.]122[.]185[.]201`<br>AS152194 / CTG Server Limited<br>シンガポール<br>防弾ホスティング - 疑い、C2候補インフラ、DNS解決先、ホスティング<br>防弾ホスティング - 疑い | DNS解決状態変化 |
| `ljdnxz[.]cc:8868` | 2026-08-24T04:31:08.451962+00:00 | `121[.]127[.]253[.]206`<br>AS152194 / CTG Server Limited<br>香港<br>防弾ホスティング - 疑い、C2候補インフラ、DNS解決先、ホスティング<br>防弾ホスティング - 疑い | 解決なし | DNS解決状態変化 |
| `ljdnxz[.]cc:8868` | 2026-08-25T02:19:45.474751+00:00 | 解決なし | `121[.]127[.]253[.]206`<br>AS152194 / CTG Server Limited<br>香港<br>防弾ホスティング - 疑い、C2候補インフラ、DNS解決先、ホスティング<br>防弾ホスティング - 疑い | DNS解決状態変化 |
| `s2gj9tonn[.]localto[.]net:6377` | 2026-08-16T23:50:48.804947+00:00 | 解決なし | `45[.]140[.]42[.]50`<br>AS62240 / Clouvider Limited<br>ドイツ連邦共和国 / ヘッセン州 / フランクフルト・アム・マイン<br>C2候補インフラ、DNS解決先<br>防弾ホスティング判定不能 | DNS解決状態変化 |
| `s2gj9tonn[.]localto[.]net:6377` | 2026-08-18T00:19:55.484024+00:00 | `45[.]140[.]42[.]50`<br>AS62240 / Clouvider Limited<br>ドイツ連邦共和国 / ヘッセン州 / フランクフルト・アム・マイン<br>C2候補インフラ、DNS解決先<br>防弾ホスティング判定不能 | 解決なし | DNS解決状態変化 |
| `s2gj9tonn[.]localto[.]net:6377` | 2026-08-22T04:16:39.835808+00:00 | 解決なし | `45[.]140[.]42[.]50`<br>AS62240 / Clouvider Limited<br>ドイツ連邦共和国 / ヘッセン州 / フランクフルト・アム・マイン<br>C2候補インフラ、DNS解決先<br>防弾ホスティング判定不能 | DNS解決状態変化 |
| `s2gj9tonn[.]localto[.]net:6377` | 2026-08-24T04:31:08.452176+00:00 | `45[.]140[.]42[.]50`<br>AS62240 / Clouvider Limited<br>ドイツ連邦共和国 / ヘッセン州 / フランクフルト・アム・マイン<br>C2候補インフラ、DNS解決先<br>防弾ホスティング判定不能 | 解決なし | DNS解決状態変化 |
| `s2gj9tonn[.]localto[.]net:6377` | 2026-08-25T02:19:58.526366+00:00 | 解決なし | `45[.]140[.]42[.]50`<br>AS62240 / Clouvider Limited<br>ドイツ連邦共和国 / ヘッセン州 / フランクフルト・アム・マイン<br>C2候補インフラ、DNS解決先<br>防弾ホスティング判定不能 | DNS解決状態変化 |
| `s2gj9tonn[.]localto[.]net:6377` | 2026-08-26T00:17:55.109622+00:00 | `45[.]140[.]42[.]50`<br>AS62240 / Clouvider Limited<br>ドイツ連邦共和国 / ヘッセン州 / フランクフルト・アム・マイン<br>C2候補インフラ、DNS解決先<br>防弾ホスティング判定不能 | 解決なし | DNS解決状態変化 |
| `tirakian[.]com:56001` | 2026-08-24T04:31:08.452292+00:00 | `194[.]56[.]225[.]109`<br>AS142594 / SpeedyPage Ltd<br>シンガポール<br>C2候補インフラ、DNS解決先<br>防弾ホスティング判定不能 | 解決なし | DNS解決状態変化 |
| `tirakian[.]com:56002` | 2026-08-24T04:31:08.452302+00:00 | `194[.]56[.]225[.]109`<br>AS142594 / SpeedyPage Ltd<br>シンガポール<br>C2候補インフラ、DNS解決先<br>防弾ホスティング判定不能 | 解決なし | DNS解決状態変化 |
| `tirakian[.]com:56003` | 2026-08-24T04:31:08.452312+00:00 | `194[.]56[.]225[.]109`<br>AS142594 / SpeedyPage Ltd<br>シンガポール<br>C2候補インフラ、DNS解決先<br>防弾ホスティング判定不能 | 解決なし | DNS解決状態変化 |

## 最新IPのAS・Geo・インフラタグ

| endpoint | IP | AS / 組織 | Geo | タグ | 防弾ホスティング評価 |
|---|---|---|---|---|---|
| `118[.]107[.]21[.]88:9999` | `118[.]107[.]21[.]88` | AS152194 / CTG Server Limited | シンガポール | 防弾ホスティング - 疑い、C2候補インフラ、ホスティング | 防弾ホスティング - 疑い |
| `192[.]252[.]180[.]45:6666` | `192[.]252[.]180[.]45` | AS152194 / CTG Server Limited | アメリカ | 防弾ホスティング - 疑い、C2候補インフラ、ホスティング | 防弾ホスティング - 疑い |
| `202[.]95[.]8[.]27:6666` | `202[.]95[.]8[.]27` | AS152194 / CTG Server Limited | 中国 | 防弾ホスティング - 疑い、C2候補インフラ、ホスティング | 防弾ホスティング - 疑い |
| `202[.]95[.]8[.]27:8888` | `202[.]95[.]8[.]27` | AS152194 / CTG Server Limited | 中国 | 防弾ホスティング - 疑い、C2候補インフラ、ホスティング | 防弾ホスティング - 疑い |
| `64[.]81[.]30[.]192:6666` | `64[.]81[.]30[.]192` | AS979 / NetLab Global | アメリカ / カリフォルニア州 / ロサンゼルス | C2候補インフラ | 防弾ホスティング判定不能 |
| `auk218[.]club:7800` | `118[.]107[.]0[.]196` | AS152194 / CTG Server Limited | シンガポール | 防弾ホスティング - 疑い、C2候補インフラ、DNS解決先、ホスティング | 防弾ホスティング - 疑い |
| `f168[.]com[.]co:1604` | `172[.]67[.]173[.]5` | AS13335 / Cloudflare, Inc. | 未取得 | Anycast／共有エッジ、C2候補インフラ、CDN、DNS解決先、ホスティング | 防弾ホスティング根拠なし（共有CDN） |
| `f168[.]name:1604` | `172[.]67[.]221[.]66` | AS13335 / Cloudflare, Inc. | 未取得 | Anycast／共有エッジ、C2候補インフラ、CDN、DNS解決先、ホスティング | 防弾ホスティング根拠なし（共有CDN） |
| `f168hi[.]com:1604` | `104[.]21[.]82[.]149` | AS13335 / Cloudflare, Inc. | 未取得 | Anycast／共有エッジ、C2候補インフラ、CDN、DNS解決先、ホスティング | 防弾ホスティング根拠なし（共有CDN） |
| `haochisadnka[.]cc:6685` | `134[.]122[.]185[.]201` | AS152194 / CTG Server Limited | シンガポール | 防弾ホスティング - 疑い、C2候補インフラ、DNS解決先、ホスティング | 防弾ホスティング - 疑い |
| `ljdnxz[.]cc:8868` | `121[.]127[.]253[.]206` | AS152194 / CTG Server Limited | 香港 | 防弾ホスティング - 疑い、C2候補インフラ、DNS解決先、ホスティング | 防弾ホスティング - 疑い |

`防弾ホスティング`は明示的なprovider評価、`防弾ホスティング - 疑い`は高密度C2悪用等の状況証拠に基づきます。単一の悪性IP観測だけでは付与しません。完全な理由とOSINT sourceはJSONの`infrastructure.bulletproof_hosting`を参照してください。

## 継続監視と停止履歴

次回active対象は 12 件、停止履歴へ移した対象は 92 件です。ONの対象、7日未満のOFF、proxy利用不可等の未観測対象は継続監視します。

停止条件は、最後のON以後または初回OFFから7日以上が経過し、その期間に2回以上のOFF実観測があり、最新観測もOFFであることです。単発timeoutや未観測だけでは停止しません。次回対象は `active-targets.json`、停止を含む全履歴は `monitoring-history.json` を参照してください。

<!-- maxmind-enrichment:start -->
## MaxMind Geo/ASエンリッチ

- IP照合: `11/11`
- GeoLite2 City DB構築時刻: `2026-09-01T14:36:41+00:00`
- GeoLite2 ASN DB構築時刻: `2026-09-01T08:15:50+00:00`
- 公式checksum照合: City `True` / ASN `True`
- ライブチェック前鮮度確認: `True` / 上限 `24.0`時間
- 鮮度超過による更新: `True` / 更新後も公開最新版が24時間超: `False`
- 更新後の鮮度超過: City `False` / ASN `False`
- MaxMind帰属表記（原文）: This product includes GeoLite2 Data created by MaxMind, available from https://www.maxmind.com.

| C2 endpoint | 観測IP | Geo | AS |
|---|---|---|---|
| `118.107.21.88:9999` | `118.107.21.88` | シンガポール | AS152194 / CTG Server Limited |
| `192.252.180.45:6666` | `192.252.180.45` | アメリカ | AS152194 / CTG Server Limited |
| `202.95.8.27:6666` | `202.95.8.27` | 中国 | AS152194 / CTG Server Limited |
| `202.95.8.27:8888` | `202.95.8.27` | 中国 | AS152194 / CTG Server Limited |
| `64.81.30.192:6666` | `64.81.30.192` | アメリカ / カリフォルニア州 / ロサンゼルス | AS979 / NetLab Global |
| `auk218.club:7800` | `118.107.0.196` | シンガポール | AS152194 / CTG Server Limited |
| `f168.com.co:1604` | `172.67.173.5` | 未取得 | AS13335 / Cloudflare, Inc. |
| `f168.name:1604` | `172.67.221.66` | 未取得 | AS13335 / Cloudflare, Inc. |
| `f168hi.com:1604` | `104.21.82.149` | 未取得 | AS13335 / Cloudflare, Inc. |
| `haochisadnka.cc:6685` | `134.122.185.201` | シンガポール | AS152194 / CTG Server Limited |
| `ljdnxz.cc:8868` | `121.127.253.206` | 香港 | AS152194 / CTG Server Limited |

> GeoLite2は概略位置情報です。個人・世帯・住所の識別やC2稼働確証には使用しません。
<!-- maxmind-enrichment:end -->

## 安全境界

既知portは完全一致host・単一portへ各1回、port不明hostはDNS解決だけを行い、timeout最大5秒、応答最大65536 byteで確認しました。レビュー済み完全一致profileに限り、malware固有protocol要求を合計5対象へ送信しました。送信内容はprofile固定または合成IDだけで、実ホストのvictim metadataを含みません。task取得、task実行、payload取得は行っていません。認証情報は使用していません。port range、redirect追跡は使用していません。`.onion`は本監視の対象外です。

機械可読の完全な根拠、DNS解決先、証明書／banner hash、個別timeoutは [monitoring-results.json](monitoring-results.json)、今回の実効対象は [effective-targets.json](effective-targets.json)、次回active対象は [active-targets.json](active-targets.json) を参照してください。
