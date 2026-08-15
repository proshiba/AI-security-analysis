# Nmap NSEによるC2稼働確認

C2候補へ接触する機能は、すべて[`nmap_c2_detector.py`](../nmap/nmap_c2_detector.py)を経由してNmap NSEで実行します。Pythonは対象選択、中央profileの完全一致検証、NSE引数fileの生成、Nmap XMLのallowlist化、判定だけを担当し、DNS、TCP、TLS、HTTP、FTP、UDP、malware固有protocolのsocketを直接開きません。

旧[`c2_detector.py`](c2_detector.py)はoffline planとの互換用です。`--allow-network`を指定しても`python_direct_c2_probe_disabled`を返し、対象へ接続しません。Nmapが見つからない場合、NSE bindingが登録されていない場合、中央profileとhost／port／sample SHA-256が一致しない場合、または未レビューの送信byte列が要求された場合は、Pythonへfallbackせずfail-closedとします。

## 対応する観測

- `dns_observe`：Nmapが解決したA／AAAAだけを記録し、serviceへ接続しません。
- `tcp_connect`／`passive_banner`：TCP openまたは上限付きserver-first bannerを観測します。application dataは送信しません。
- `tls_handshake`：application dataを送らず、TLS version、cipher、証明書SHA-256を観測します。
- `http_get`／`https_get`：redirectを追跡せず、指定pathへGETを1回だけ送信します。
- malware固有method：[`c2_protocol_probe_profiles.json`](c2_protocol_probe_profiles.json)と[`nmap/profiles.json`](../nmap/profiles.json)の完全一致bindingだけを使用します。

汎用transportの到達だけでは`c2_confirmed=true`にしません。malware固有確認は、review済みprofileが固定するrequest、応答形式、上限、host、port、sample、追加acknowledgementのすべてが一致した場合だけ実行します。

## 単一対象の実行

外部対象への接触には、通常のnetwork許可に加えて、確認したい動作に対応する明示gateが必要です。

```powershell
python .\analysis-framework\nmap\nmap_c2_detector.py `
  192.0.2.10 443 `
  --protocol https `
  --sample-sha256 <sha256> `
  --allow-network `
  --nmap C:\Tools\Nmap\nmap.exe `
  --output .\c2-observation.json
```

中央profileに一致する固有protocolでは、完全一致host、port、protocol、sample SHA-256を指定します。adapterが中央registryから一意のprofile IDを解決し、method固有gateも検証します。

```powershell
python .\analysis-framework\nmap\nmap_c2_detector.py `
  <reviewed-host> <reviewed-port> `
  --protocol <reviewed-protocol> `
  --sample-sha256 <sha256> `
  --allow-network `
  --allow-reviewed-application-probes `
  --nmap C:\Tools\Nmap\nmap.exe `
  --output .\c2-protocol-observation.json
```

送信byte列、expected stage、SNI pin、証明書pinなどをCLIから自由入力することはできません。これらは中央profileから解決し、NSEへは権限制限した一時`--script-args-file`で渡します。結果にはraw banner、cookie、task本文、token、資格情報、private key、復号済みpayloadを含めません。

## workflowへの統合

稼働確認は暗黙に実行しません。レビュー済みprofileに`live_c2_targets`を定義し、operatorが`-AllowLiveC2Check`とNmap実行fileを指定する必要があります。

```powershell
.\analysis-framework\Invoke-Analysis.ps1 `
  -Sample C:\quarantine\sample.zip `
  -OutputDirectory C:\analysis-output\case `
  -ProfilePath .\analysis-framework\malware\valleyrat\config\profiles\<sha256>.json `
  -AllowLiveC2Check `
  -Nmap C:\Tools\Nmap\nmap.exe
```

出力先は`<OutputDirectory>/c2-live/`です。`-CollectJarm`と`-JarmScript`は廃止済みの互換引数で、指定すると接触前に拒否します。JARM、port range scan、redirect追跡、候補endpointへの一斉送信は実行しません。

## 判定方法

- `alive=true`は、選択したNSEがtransportまたはapplication endpointから十分な応答を得たことを示します。
- `c2_confirmed=true`は、review済みのmalware固有protocol応答が完全一致した場合だけ設定します。
- TCP open、TLS確立、HTTP status、FTP banner、DNS解決だけではC2の所有者を証明できません。
- timeout、部分応答、不正形式、上限超過、profile不一致、未登録protocolは判定不能または拒否であり、C2否定には使いません。
- Nmap出力はallowlistへ再投影し、結果policyへ`network_execution_backend=nmap_nse_only`と`python_direct_probe_used=false`を固定します。
- 結果にはtimestampを付け、過去のDNS／IP／証明書観測を上書きしません。

## 日次の継続監視

daily解析で明示的に許可されたC2ライブチェックは、[`build_all_c2_monitoring_targets.py`](build_all_c2_monitoring_targets.py)で`analysis-results`全体のIOC履歴から対象を再生成し、[`run_c2_monitoring_pipeline.py`](run_c2_monitoring_pipeline.py)で観測します。`.onion`は対象外とし、通常のglobal IP／FQDNは計画へ含めます。既知portは完全一致endpointへ限定したNSEを1回だけ実行し、port不明hostはDNS観測だけを行ってC2稼働とは判定しません。

```powershell
python .\analysis-framework\common\run_c2_monitoring_pipeline.py `
  --targets .\analysis-results\research\c2-monitoring\YYYY-MM-DD\targets.json `
  --output-directory .\analysis-results\research\c2-monitoring\YYYY-MM-DD `
  --history-root .\analysis-results\research\c2-monitoring `
  --maxmind-cache-dir C:\malware-lab\maxmind\current `
  --nmap C:\Tools\Nmap\nmap.exe `
  --allow-network
```

`targets.json`は`protocol_profile_id`だけを保持し、送信byte列、期待header、channel role、SNI、IP pinningはregistryから解決します。IDとhost／portが完全一致しない場合は接続前に拒否し、IP直指定hostはhost自体と単一pinが一致する場合だけ許可します。

結果ではTCP到達を`transport_reachable_c2_not_confirmed`、固有protocolの完全一致だけを`c2_protocol_confirmed`として区別します。DNSのA／AAAA解決先は観測日時、ASN、organizationとともに履歴化します。共有CDNのedge IPはoriginではないため、CDN判定だけから防弾ホスティングや攻撃者インフラへ帰属させません。

ONの対象、7日未満のOFF、proxy利用不可などの未観測対象は次回も監視します。最新観測がOFFで、最後のON以後または初回OFFから7日以上経過し、その間に2回以上のOFF実観測がある対象だけを停止履歴へ移します。停止済み対象に新しいON証拠が得られた場合は、再開eventを残して監視へ戻します。

成果物と再実行手順は[`RUN-C2-MONITORING-PIPELINE.md`](RUN-C2-MONITORING-PIPELINE.md)を参照してください。NSEとbindingの一覧、loopback harnessは[`nmap/README.md`](../nmap/README.md)を参照してください。

## emulatorとoffline解析の境界

MX-Go、N520、Winos、vvaS、PureRAT、AsyncRAT、VenomRATなどのhost emulatorは、localhost限定の合成labです。emulatorのcheck-in、fake result、task取得、artifact保存はC2検知ではなく、Nmap監視pipelineへ混在させません。

`c2_candidate_detector.py`はconfig extractorのJSONを読み、DNS、TCP、HTTP、Shodanへ接続せずに受動的pivotを作成します。静的config抽出、IOC生成、protocol復元も引き続きPythonで行いますが、抽出したendpointへ接触する段階だけをNmap NSEへ統一します。
