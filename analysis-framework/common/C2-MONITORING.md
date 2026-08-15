# C2定期モニタリング手順

`monitor_recent_c2.py` は、解析済み検体から人がレビューしたC2完全一致endpointを限定観測し、機械可読JSONと日本語一覧表を同時生成します。候補の自動抽出結果を無条件に接続対象へ昇格させないことが前提です。
対象へのnetwork接触は[`nmap_c2_detector.py`](../nmap/nmap_c2_detector.py)がallowlist済みNSEを起動する経路だけです。Python側の直接DNS／socket／TLS／HTTP probeは標準monitorから呼び出さず、結果policyへ`network_execution_backend=nmap_nse_only`と`python_direct_probe_used=false`を固定します。


## 通常probeとRAT host emulatorの分離

通常のC2監視は、DNS解決、TCP接続、server-first応答、またはreview済みの1回だけのapplication probeを行う短時間処理です。RATの遠隔操作channelへ登録してcommandを待つ処理は通常probeへ追加せず、[`run_defensive_rat_emulator.py`](run_defensive_rat_emulator.py)を入口とする防御的host emulatorへ分離します。AgentTeslaのFTP exfiltration sinkやStealC／Lumma／Remusのtask serviceは対話型RAT channelではないため、host emulatorではなく既存のbounded probeで扱います。

host emulatorのlive sessionには、現在のtaskでの明示許可に加え、`--allow-network`、`--allow-live-c2-emulation`、完全一致の`--acknowledge-profile`、存在するkill-switch fileが必要です。接続先、IP、SNI、証明書、送受信量、時間、frame数はreview済みprofileへ固定します。受信commandは実行せず、file／plugin／stage転送と未知commandには応答せず終了します。詳細は[防御的RATホストエミュレーター](../docs/RAT-C2-HOST-EMULATOR.md)を参照してください。

AsyncRAT／VenomRATのhost emulatorは、合成`ClientInfo`に続けて空`Message`へsanitizeした固定Ping requestを1回送信し、C2の`pong`／`Po_ng`またはtaskを最大1 frameだけ受信します。実検体の`KeepAlivePacket`はactive window titleを`Ping.Message`へ入れますが、エミュレーターは`GetActiveWindowTitle`を呼びません。受信したheartbeat応答やtaskには返信せず、任意操作結果のfake replyも実装していません。

現在実装されているのは短時間・単一接続のsession runnerです。常時稼働、無限再接続、command待受service、任意操作結果のfake replyは未実装であり、既存runnerを常駐化して代用しません。

## 入力

`targets.json` は次の条件を満たす必要があります。

- `analysis_window.start/end` で対象解析期間を固定する。
- hostは完全一致FQDN、IP、または`.onion`とし、wildcard、CIDR、port listを使わない。
- 各endpointにfamily、単一port、protocol、method、解析case、根拠sourceを付ける。
- 配布先、decoy、正規update、local proxyはC2へ混同しない。
- `.onion`は`transport: tor-socks5`とし、proxyはlocalhostだけを許可する。

現在のmethodは次の19種類です。すべて[`nmap/profiles.json`](../nmap/profiles.json)のNSE bindingを持ち、未登録methodは実行前に拒否します。

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
| `protocol_profile_required` | review済み固有profileがない対象はDNS観測だけで停止 | 0.05 |
| `purerat_direct_tls_certificate_pin` | PureRAT direct TLSの証明書pinを観測。TLS version厳密保証がないため確定へ昇格しない | 0.92 |
| `darkcomet_server_first_idtype` | DarkCometのserver-first `IDTYPE`をNSEで受信専用検証 | 0.98 |
| `redline_checkconnect_soap11` | RedLineの固定SOAP `CheckConnect`をNSEで1要求だけ検証 | 0.98 |
| `xloader_v8_get_registration` | private protocol未実装のためNSE transport-onlyで停止 | 0.15 |

TCP open、一般TLS、HTTP status、FTP bannerはC2所有者やmalware固有applicationを証明しません。`c2_operational_confidence` と `reachability_confidence` は必ず分離して読みます。

## 実行

最初にnetworkなしでmanifest、安全上限、出力形式を確認します。

```powershell
py -3.13 .\analysis-framework\common\monitor_recent_c2.py `
  --targets .\analysis-results\research\c2-monitoring\2026-08-02\targets.json `
  --nmap C:\Tools\Nmap\nmap.exe `
  --output-directory .\.work\c2-monitoring-preview
```

レビュー後、明示的な許可があるtaskでだけ`--allow-network`を指定します。`--allow-network`だけではAsyncRAT／VenomRATはTLS handshakeと証明書観測までで、匿名Pingは送りません。匿名Pingには`--allow-reviewed-application-probes`、AgentTesla FTP認証にはさらに`--allow-authentication`とリポジトリ外`--private-credential-vault`が必要です。StealC／Lumma／Remusの合成登録とtask取得には、独立した`--allow-malware-registration-tasking`も必要です。

```powershell
py -3.13 .\analysis-framework\common\monitor_recent_c2.py `
  --targets .\analysis-results\research\c2-monitoring\2026-08-02\targets.json `
  --nmap C:\Tools\Nmap\nmap.exe `
  --output-directory .\analysis-results\research\c2-monitoring\2026-08-02 `
  --allow-network `
  --allow-malware-registration-tasking
```

出力は`monitoring-results.json`と`README.md`です。banner本文やcookie、redirect先は公開せず、長さ、SHA-256、MurmurHash3、許可したHTTP headerだけを保持します。

## host emulator証跡の監視統合

終了したhost emulator sessionは、private transcriptそのものではなく公開要約を監視用sidecarへ変換してから、統合runnerへ渡します。公開要約と監視planはそれぞれexpected SHA-256付きで不変snapshotとして読み、endpoint、family、emulator／protocol profile、registry pin、sample hashが完全一致しない入力、期限切れ、重複sessionは拒否します。

```powershell
$targetsSha256 = (Get-FileHash .\analysis-results\research\c2-monitoring\YYYY-MM-DD\targets.json -Algorithm SHA256).Hash.ToLowerInvariant()
$summarySha256 = (Get-FileHash C:\private\session-public.json -Algorithm SHA256).Hash.ToLowerInvariant()

py -3.13 .\analysis-framework\common\build_rat_emulation_evidence.py `
  --targets .\analysis-results\research\c2-monitoring\YYYY-MM-DD\targets.json `
  --targets-sha256 $targetsSha256 `
  --public-summary C:\private\session-public.json `
  --public-summary-sha256 $summarySha256 `
  --output C:\private\rat-emulation-evidence.json

$sidecarSha256 = (Get-FileHash C:\private\rat-emulation-evidence.json -Algorithm SHA256).Hash.ToLowerInvariant()

py -3.13 .\analysis-framework\common\run_c2_monitoring_pipeline.py `
  --targets .\analysis-results\research\c2-monitoring\YYYY-MM-DD\targets.json `
  --output-directory .\analysis-results\research\c2-monitoring\YYYY-MM-DD `
  --maxmind-cache-dir C:\Users\Administrator\MalwareSamples\maxmind\current `
  --rat-emulation-evidence C:\private\rat-emulation-evidence.json `
  --rat-emulation-evidence-sha256 $sidecarSha256
```

`--rat-emulation-evidence`と`--rat-emulation-evidence-sha256`は必ず同時に指定します。片方だけの指定、読取後の置換、SHA-256不一致は通信開始前に拒否します。両方を省略した場合は新規session sidecarを取り込まず、既存の通常監視を実行します。過去runにprotocol activityがある場合、その履歴表示は維持します。

sidecarから公開するのはsession時刻、profile ID、確認状態、registration／Ping requestの送信件数、heartbeat応答／taskの受信件数・分類・長さ・SHA-256、private transcript root hash、archive／manifest SHA-256等のallowlist項目だけです。任意操作結果のfake replyは未実装であり、`synthetic_reply_sent`は`false`でなければ取り込みません。raw frame、復号command本文、引数、path、URL、token、鍵、合成ID、ローカルpathは公開しません。private transcriptは`archive_analysis_datastore.py`を使い、解析対象別のpassword `infected`のWinZip AES-256 archiveとしてS3 bucket `malware-analysis-datastore-720232834682`へ保管します。

## 判定

- `transport_reachable_c2_not_confirmed`: TCP到達のみ。C2稼働confidenceは最大0.25。
- `tls_endpoint_reachable_c2_not_confirmed`: TLS成立のみ。
- `application_endpoint_reachable_c2_not_confirmed`: 限定HTTP応答あり。C2固有応答ではない。
- `server_first_response_reachable_c2_not_confirmed`: server-first応答あり。family fingerprint一致前は未確認。
- `not_reachable_at_observation`: 今回の観測で応答なし。恒久停止を意味しない。
- `not_observed_proxy_unavailable`: Tor等の観測経路がなく、対象へ接続できていない。
- `c2_protocol_confirmed`: review済みmalware固有server-first protocolが一致した場合だけ使用する。

host emulatorでcommandを受信した場合は、protocol activityが観測された強い肯定証拠として扱います。一方、短時間session中にcommandを受信しなかったことはC2停止、`not_reachable_at_observation`、または監視終了の根拠にしません。到達性とDNSは従来の`dns_tracking`／`monitoring_lifecycle`、host emulatorのsessionとcommand fingerprintは`protocol_activity_tracking`へ分離して記録します。

## 解決IPのgeo付与

解決IPの国・都市・緯度経度・ASは、MaxMind GeoLite2 City/ASNで付与します。手順は [MAXMIND-C2-ENRICHMENT.md](MAXMIND-C2-ENRICHMENT.md) を参照してください。geoの出所はこれ1本に絞ります（第三者APIと併用すると同一IPで国が食い違うため）。

GeoLite2の位置はIPインフラの概略であり、C2稼働・攻撃者の所在地・個人や住所の特定には使いません。

## 判定の補足

停止側の判断は`negative_observation_confidence`も確認します。明示的なconnection refusedは比較的強い観測、timeoutはfirewall、遅延、Tor circuit不成立でも生じる弱い観測です。前回結果を上書きせず日付別ディレクトリへ保存し、DNS、証明書、banner hashの変化を時系列比較します。

## 安全境界

既定ではmalware application dataも認証も送信しません。完全一致profileと追加フラグがある場合だけ、通常probeのAsyncRAT／VenomRATは空`Message`のPing 1 frame、host emulatorは合成`ClientInfo`と空`Message`のPingを順に送信し、応答またはtaskを1 frameだけ受信できます。どちらもactive windowを取得せず、`pong`／`Po_ng`やtaskへ返信しません。AgentTeslaは`USER`／必要時の`PASS`／`QUIT`だけを送信できます。StealC／Lumma／Remusは、さらに`--allow-malware-registration-tasking`がある場合だけ、実端末情報を含まない合成IDで登録し、task要求を1回だけ送信します。取得したtaskは実行せず、task本文・token・合成ID・raw応答を公開せず、task内URLやpayloadも追跡しません。FormBook／XLoaderは受動観測のみです。端末名、ユーザー名、active window、OS、stage要求、任意command、FTP file／directory操作、JARM、port range、redirect追跡は行いません。

AsyncRAT／VenomRATの証明書不一致は`mismatch_inconclusive`と`certificate_mismatch_excludes_c2=false`で保存します。不一致だけを根拠に非C2または停止へ降格しません。証明書完全一致は強い加点、期待MessagePack応答一致はprotocol確認です。

単体テストは次で実行します。

```powershell
py -3.13 -m pytest .\analysis-framework\tests\test_monitor_recent_c2.py -q
py -3.13 -m pytest .\analysis-framework\tests\test_build_rat_emulation_evidence.py .\analysis-framework\tests\test_rat_emulation_evidence.py .\analysis-framework\tests\test_c2_monitoring_history.py -q
```
