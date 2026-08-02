# C2定期モニタリング手順

`monitor_recent_c2.py` は、解析済み検体から人がレビューしたC2完全一致endpointを限定観測し、機械可読JSONと日本語一覧表を同時生成します。候補の自動抽出結果を無条件に接続対象へ昇格させないことが前提です。

## 入力

`targets.json` は次の条件を満たす必要があります。

- `analysis_window.start/end` で対象解析期間を固定する。
- hostは完全一致FQDN、IP、または`.onion`とし、wildcard、CIDR、port listを使わない。
- 各endpointにfamily、単一port、protocol、method、解析case、根拠sourceを付ける。
- 配布先、decoy、正規update、local proxyはC2へ混同しない。
- `.onion`は`transport: tor-socks5`とし、proxyはlocalhostだけを許可する。

現在のmethodは次の4種類です。

| method | 動作 | C2稼働confidence上限 |
|---|---|---:|
| `tcp_connect` | DNS解決後、単一portへTCP接続。application dataの送受信なし | 0.25 |
| `passive_banner` | TCP接続後、server-first応答を最大256 byte受信。送信なし | 0.55 |
| `tls_handshake` | 標準TLS handshakeだけを実行 | 0.45 |
| `http_get` | 指定pathへGETを1回。redirectなし、body最大256 byte | 0.60 |

TCP open、一般TLS、HTTP status、FTP bannerはC2所有者やmalware固有applicationを証明しません。`c2_operational_confidence` と `reachability_confidence` は必ず分離して読みます。

## 実行

最初にnetworkなしでmanifest、安全上限、出力形式を確認します。

```powershell
py -3.13 .\analysis-framework\common\monitor_recent_c2.py `
  --targets .\analysis-results\research\c2-monitoring\2026-08-02\targets.json `
  --output-directory .\.work\c2-monitoring-preview
```

レビュー後、明示的な許可があるtaskでだけ`--allow-network`を指定します。

```powershell
py -3.13 .\analysis-framework\common\monitor_recent_c2.py `
  --targets .\analysis-results\research\c2-monitoring\2026-08-02\targets.json `
  --output-directory .\analysis-results\research\c2-monitoring\2026-08-02 `
  --allow-network
```

出力は`monitoring-results.json`と`README.md`です。banner本文やcookie、redirect先は公開せず、長さ、SHA-256、MurmurHash3、許可したHTTP headerだけを保持します。

## 判定

- `transport_reachable_c2_not_confirmed`: TCP到達のみ。C2稼働confidenceは最大0.25。
- `tls_endpoint_reachable_c2_not_confirmed`: TLS成立のみ。
- `application_endpoint_reachable_c2_not_confirmed`: 限定HTTP応答あり。C2固有応答ではない。
- `server_first_response_reachable_c2_not_confirmed`: server-first応答あり。family fingerprint一致前は未確認。
- `not_reachable_at_observation`: 今回の観測で応答なし。恒久停止を意味しない。
- `not_observed_proxy_unavailable`: Tor等の観測経路がなく、対象へ接続できていない。
- `c2_protocol_confirmed`: review済みmalware固有server-first protocolが一致した場合だけ使用する。

## 解決IPのgeo付与

UIの世界地図プロット用に、解決IPの国・都市・緯度経度・ASNを別成果物として保存します。照会先は第三者のIP情報API(`ipwho.is`)だけで、**監視対象のC2へは接続しません**。private／loopback／reservedと`.onion`は照会しません。

```powershell
py -3.13 .\analysis-framework\common\enrich_c2_geo.py `
  --results .\analysis-results\research\c2-monitoring\2026-08-02\ `
  --allow-network
```

`--allow-network`なしでは照会対象の一覧を表示するだけです。`--check`は通信せず、既存`ip-geo.json`が全ての解決IPを網羅しているかだけを検証します。

geolocationは登録情報ベースの推定です。物理的な設置場所やC2所有者の確定には使わず、ASNやhosting事業者の傾向を見る材料として扱います。

## 判定の補足

停止側の判断は`negative_observation_confidence`も確認します。明示的なconnection refusedは比較的強い観測、timeoutはfirewall、遅延、Tor circuit不成立でも生じる弱い観測です。前回結果を上書きせず日付別ディレクトリへ保存し、DNS、証明書、banner hashの変化を時系列比較します。

## 安全境界

このmonitorはmalware check-in、victim metadata、stage要求、command polling、認証、任意payload、JARM、port range、redirect追跡を行いません。これらが必要なprotocol検証はloopback emulatorまたは隔離sandboxで行い、公開C2へは送信しません。

単体テストは次で実行します。

```powershell
py -3.13 -m pytest .\analysis-framework\tests\test_monitor_recent_c2.py -q
```
