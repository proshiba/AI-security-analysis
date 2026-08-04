# C2定期モニタリング手順

`monitor_recent_c2.py` は、解析済み検体から人がレビューしたC2完全一致endpointを限定観測し、機械可読JSONと日本語一覧表を同時生成します。候補の自動抽出結果を無条件に接続対象へ昇格させないことが前提です。

## 入力

`targets.json` は次の条件を満たす必要があります。

- `analysis_window.start/end` で対象解析期間を固定する。
- hostは完全一致FQDN、IP、または`.onion`とし、wildcard、CIDR、port listを使わない。
- 各endpointにfamily、単一port、protocol、method、解析case、根拠sourceを付ける。
- 配布先、decoy、正規update、local proxyはC2へ混同しない。
- `.onion`は`transport: tor-socks5`とし、proxyはlocalhostだけを許可する。

現在のmethodは次の14種類です。

| method | 動作 | C2稼働confidence上限 |
|---|---|---:|
| `dns_resolve` | port不明FQDNをDNS解決。C2 serviceへ接続しない | 0.05 |
| `tcp_connect` | DNS解決後、単一portへTCP接続。application dataの送受信なし | 0.25 |
| `passive_banner` | TCP接続後、server-first応答を最大256 byte受信。送信なし | 0.55 |
| `tls_handshake` | 標準TLS handshakeだけを実行 | 0.45 |
| `http_get` | 指定pathへGETを1回。redirectなし、body最大256 byte | 0.60 |
| `winos_heartbeat` | 完全一致profileへWinos heartbeatを1 frame送信 | 0.95 |
| `vvas_checkin` | 完全一致profileへreview済み3 byte check-inを1回送信 | 0.95 |
| `n520_server_first` | TLS server-first 44 byte応答を検証。check-in送信なし | 0.95 |
| `ftp_authenticated` | private vaultの完全一致資格情報で`USER`／`PASS`／`QUIT`だけを送信。replyは最大1024 byte、本文非保存 | 0.95 |
| `asyncrat_tls_messagepack` | AsyncRATの`Packet=Ping`と`pong`を圧縮MessagePackで検証 | 0.95 |
| `venomrat_tls_messagepack` | VenomRATの`Pac_ket=Ping`と`Po_ng`を圧縮MessagePackで検証 | 0.95 |
| `stealc_v2_registration_task` | StealC v2へ合成端末を`create`し、tokenで`loader` taskを1回取得 | 0.95 |
| `lumma_v6_registration_task` | Lumma v6へ`uid/cid`を送信し、合成hwidでtaskを1回取得 | 0.95 |
| `remus_registration_task` | Remusへ合成端末を登録し、復号tokenで`step=1` taskを1回取得 | 0.95 |

TCP open、一般TLS、HTTP status、FTP bannerはC2所有者やmalware固有applicationを証明しません。`c2_operational_confidence` と `reachability_confidence` は必ず分離して読みます。

## 実行

最初にnetworkなしでmanifest、安全上限、出力形式を確認します。

```powershell
py -3.13 .\analysis-framework\common\monitor_recent_c2.py `
  --targets .\analysis-results\research\c2-monitoring\2026-08-02\targets.json `
  --output-directory .\.work\c2-monitoring-preview
```

レビュー後、明示的な許可があるtaskでだけ`--allow-network`を指定します。`--allow-network`だけではAsyncRAT／VenomRATはTLS handshakeと証明書観測までで、匿名Pingは送りません。匿名Pingには`--allow-reviewed-application-probes`、AgentTesla FTP認証にはさらに`--allow-authentication`とリポジトリ外`--private-credential-vault`が必要です。StealC／Lumma／Remusの合成登録とtask取得には、独立した`--allow-malware-registration-tasking`も必要です。

```powershell
py -3.13 .\analysis-framework\common\monitor_recent_c2.py `
  --targets .\analysis-results\research\c2-monitoring\2026-08-02\targets.json `
  --output-directory .\analysis-results\research\c2-monitoring\2026-08-02 `
  --allow-network `
  --allow-malware-registration-tasking
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

解決IPの国・都市・緯度経度・ASは、MaxMind GeoLite2 City/ASNで付与します。手順は [MAXMIND-C2-ENRICHMENT.md](MAXMIND-C2-ENRICHMENT.md) を参照してください。geoの出所はこれ1本に絞ります（第三者APIと併用すると同一IPで国が食い違うため）。

GeoLite2の位置はIPインフラの概略であり、C2稼働・攻撃者の所在地・個人や住所の特定には使いません。

## 判定の補足

停止側の判断は`negative_observation_confidence`も確認します。明示的なconnection refusedは比較的強い観測、timeoutはfirewall、遅延、Tor circuit不成立でも生じる弱い観測です。前回結果を上書きせず日付別ディレクトリへ保存し、DNS、証明書、banner hashの変化を時系列比較します。

## 安全境界

既定ではmalware application dataも認証も送信しません。完全一致profileと追加フラグがある場合だけ、AsyncRAT／VenomRATは空`Message`のPing 1 frame、AgentTeslaは`USER`／必要時の`PASS`／`QUIT`だけを送信できます。StealC／Lumma／Remusは、さらに`--allow-malware-registration-tasking`がある場合だけ、実端末情報を含まない合成IDで登録し、task要求を1回だけ送信します。取得したtaskは実行せず、task本文・token・合成ID・raw応答を公開せず、task内URLやpayloadも追跡しません。FormBook／XLoaderは受動観測のみです。端末名、ユーザー名、active window、OS、stage要求、任意command、FTP file／directory操作、JARM、port range、redirect追跡は行いません。

AsyncRAT／VenomRATの証明書不一致は`mismatch_inconclusive`と`certificate_mismatch_excludes_c2=false`で保存します。不一致だけを根拠に非C2または停止へ降格しません。証明書完全一致は強い加点、期待MessagePack応答一致はprotocol確認です。

単体テストは次で実行します。

```powershell
py -3.13 -m pytest .\analysis-framework\tests\test_monitor_recent_c2.py -q
```
