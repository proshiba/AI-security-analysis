# 2026-09-28 C2限定ライブ確認の対象・証拠境界

本日の静的解析から得た候補を全履歴IOCへ反映し、Nmapの許可済みNSEだけで限定観測した。検体の実行、後段payloadの取得、認証、登録・task取得、任意command送信、redirect追跡は行っていない。対象と詳細な個別観測は[`targets.json`](targets.json)、[`effective-targets.json`](effective-targets.json)、[`monitoring-results.json`](monitoring-results.json)を正本とする。

## 対象の構築と保留

- 全履歴の再生成対象は324件。直近の**実観測**から54件を継続し、実効対象378件を重複なく1回ずつ評価した。計画だけ作成されライブ結果のない2026-09-26を最新観測と誤認する不具合を修正している。
- 実際のservice接続試行は306件、port不明でDNS-onlyとした対象は63件、別の安全gateまたはprofile不足でserviceへ接続しなかった対象は9件である。「378件の評価」を「378件のC2接続」と読み替えない。
- 本日のNanoCore追加静的解析から、`www.s666hn[.]com:8080`と`s666hn[.]com:8080`を設定上の接続先候補として追加した。Bun同梱JSから復元した主・予備5 hostはportが未確認のためDNS-onlyとした。後段取得path、Telegram dead-drop、外向きIP確認サービス、NanoCoreのDNS resolverは追加していない。
- 以前のactive対象にのみ残っていた30件を新たに隔離した。3件は利用者の区別がpath側にある共有サービス（`telegram.me`、`eth-sepolia.g.alchemy.com`、`sepolia.infura.io`）、2件は配布専用の`elxxvvx.xyz`と`172.245.89.137`、25件は参照元の2026-09-18 `ioc-summary.json`が現リポジトリにも確認可能な履歴にもなく、役割を再検証できない候補である。25件の内訳はTCP 5件、DNS-only 20件。元の監視履歴は削除せず、対象別の除外理由を`targets.json`の`carry_forward_exclusions`へ記録した。出典が復旧し、C2/control/exfilの役割を再監査できるまで接続しない。
- C2用途未確定のROR13系16検体・12種類の静的接続先候補は、今回のC2ライブ対象へ昇格させていない。

## 観測結果

| 結果 | 件数 | 解釈 |
|---|---:|---|
| マルウェア固有protocol応答を確認 | 2 | ValleyRAT Winosのreview済みheartbeat 1回に対し、各16 byteの期待したcontrol応答を受信。2件とも`valleyrat-c2.nse`、送信15 byte、認証・task・操作commandなし。 |
| TCP到達のみ | 90 | 接続先serviceへ到達したが、C2 protocolは未確認。NanoCoreの主・予備2件を含む。 |
| DNS解決のみ・C2 service未確認 | 57 | port不明のBun主・予備5 hostを含む。DNS解決だけでC2稼働とは扱わない。 |
| 観測時に到達不能 | 214 | その時点の結果であり、恒久的な停止を意味しない。 |
| DNS未解決 | 6 | C2 serviceへの接続はない。 |
| 安全gateにより未観測 | 7 | 別途許可を要する送信は行っていない。 |
| 必要なprofileを満たさず未確認 | 2 | 無根拠な汎用probeへ降格していない。 |

前回2026-09-25にWinos応答を確認した`ljdnxz[.]cc:8868`は、今回のTCPとreview済みheartbeatのいずれでも観測時のport状態が`closed`だった。これは時点差であり、恒久停止やインフラ廃棄の証明ではない。

MaxMind GeoLite2 City/ASNは接続前にbuild時刻を確認し、両DBを公式SHA-256で検証した最新版へ更新した。ASN版は2026-09-28構築、City版は公開最新版自体が2026-09-25構築で24時間を超えており、`latest_available_still_stale=true`として記録した。Geo/AS情報は概略で、C2運営者や所在地を確定するものではない。

本結果は、C2候補の静的帰属、当日の到達性、malware固有応答を区別している。特にTCP open、DNS応答、証明書だけではC2を確認済みにしない。隔離した30件と未確定の静的候補を含むため、「全履歴のすべての記録先へ接続した」とは扱わない。
