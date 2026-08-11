# C2稼働確認とShodan fingerprint収集

`c2_detector.py` の既定動作は通信を行わない事前確認です。明示的に `--allow-network` を指定した場合だけ、profileに基づく範囲限定の稼働確認を実行し、case report用のJSONを書き出します。

対応するprobeは次のとおりです。

- `tcp`：接続し、必要な場合だけ明示したhex値を送信して、上限付きでbannerを取得します。
- `udp`：明示された単一のホストとポートへ、長さ0のデータグラムを1回だけ送ります。応答がない場合は稼働中とも停止中とも判定せず、マルウェア固有payloadは送信しません。
- `vvas`：復元済みの3 byte check-inを送信し、最大64 byteを読み、期待headerとstage sizeが一致した場合だけ `c2_confirmed=true` とします。
- `n520`：TLSを確立してapplication dataを送らず、server-firstの44 byte handshakeを厳密に読みます。CRC32とsession由来magicの両方が一致した場合だけ `c2_confirmed=true` とします。
- `http`／`https`：redirectなしでGETを1回だけ行い、上限付きbody、status、title、headerを取得します。
- `tls`：HTTP requestを送らず、TLS確立と証明書metadataを取得します。
- TLS serviceに対して、任意でSalesforce JARMを呼び出せます。

JARM helperが保持するのはstdout最大64 KiB、stderr最大16 KiBです。出力超過またはtimeout時はhelperを終了し、fingerprintを返しません。

収集する検知fieldには、raw bannerのSHA-256、Shodan `hash:` 用の符号付きMurmurHash3 x86_32、HTTP title、TLS version／cipher、証明書SHA-256、JARM、DNS解決結果、生成したShodan query候補が含まれます。

N520のserver-first検知は、対象をレビューした後に直接実行できます。

```powershell
python .\analysis-framework\common\c2_detector.py 118.107.21.88 9999 --protocol n520 --sni update.microsoft.com --allow-network --output n520-c2.json
```

このmodeが送信するのはTLS handshakeだけです。暗号化されたN520 endpoint check-inは送信しません。

明示的に許可された範囲限定の収集では、空のcommand-1 registrationを1回送り、暗号化frameまたはcommand-16／18 plugin payloadをAES ZIP内にだけ保存できます。

```powershell
python .\analysis-framework\common\c2_detector.py 118.107.21.88 9999 --protocol n520 --n520-checkin --n520-wait 15 --artifact-zip n520-artifacts.zip --allow-network --output n520-collection.json
```

collectorはstation IDを送信せず、最大16 MiB、最大30秒だけ受信します。応答を実行せず、operator／admin commandも模倣しません。

## workflowへの統合

稼働確認は暗黙に実行しません。レビュー済みprofileに `live_c2_targets` を定義し、operatorが `-AllowLiveC2Check` を渡す必要があります。

```powershell
.\analysis-framework\Invoke-Analysis.ps1 `
  -Sample C:\quarantine\sample.zip `
  -OutputDirectory C:\analysis-output\case `
  -ProfilePath .\analysis-framework\malware\valleyrat\config\profiles\<sha256>.json `
  -AllowLiveC2Check -CollectJarm
```

出力先は `<OutputDirectory>/c2-live/` です。`-CollectJarm` は10回のactive TLS ClientHello probeを行い、TLS以外のprotocolでは無視されます。

## 判定方法

- `alive=true` は、選択したprobeに対してtransport／application endpointから十分な応答があったことを示します。
- `c2_confirmed=true` はより厳格で、マルウェア固有protocolとの一致が必要です。
- N520確認では暗号化endpoint check-inやhost telemetryの送信を行わず、server-first handshakeだけを検証します。
- HTTP／TLSへ到達できることだけでは、C2の所有者を証明できません。
- UDPの空データグラムに応答がない結果は判定不能です。応答またはICMPエラーを得た場合でも、固有protocolと一致しない限り `c2_confirmed=true` にはしません。
- 全byteが0のJARMはfingerprintではなく、Shodan queryへ変換してはいけません。
- custom protocolのbanner hashがShodanで有効なのは、Shodan側が互換probe payloadを使った場合だけです。
- 結果にはtimestampを付け、過去のDNS／IP／証明書観測を上書きしません。

## 日次の継続監視

daily解析で明示的に許可されたC2ライブチェックは、[`build_all_c2_monitoring_targets.py`](build_all_c2_monitoring_targets.py)で`analysis-results`全体のIOC履歴から対象を再生成し、[`run_c2_monitoring_pipeline.py`](run_c2_monitoring_pipeline.py)で観測する経路を標準とします。`.onion`は対象外とし、通常のglobal IP／FQDNは全件を計画へ含めます。既知portは完全一致endpointへ限定probeを1回だけ実行し、port不明hostはDNS解決だけを行ってC2稼働とは判定しません。直近の`active-targets.json`も統合します。

既知のmalware固有protocolは[`c2_protocol_probe_profiles.json`](c2_protocol_probe_profiles.json)を正本とします。`targets.json`には`protocol_profile_id`だけを保持し、送信byte列、期待header、channel role、SNI、IP pinningはregistryから解決します。IDとhost/portが完全一致しない場合は接続前に拒否し、IP直指定hostはhost自体と単一pinが一致する場合だけ許可します。現在のレビュー済みprofileは、Winosの`control`／`stage_and_control`への固定C9 heartbeat 1 frame、vvaSへの固定3 byte check-in、N520のserver-first 44 byte handshakeです。Winosは最大64 byteだけを受信してstageを要求せず、N520ではcheck-inを送りません。いずれもvictim metadata、command polling、任意commandを送信しません。

結果では`tcp_connect`成功を`transport_reachable_c2_not_confirmed`、固有protocolの完全一致だけを`c2_protocol_confirmed`として区別します。静的解析でprotocolを復元済みのendpointを、実装上の都合だけで`tcp_connect`へ降格させてはいけません。

DNSのA／AAAA解決先は観測日時、ASN、organizationとともに履歴化します。Cloudflare、Akamai、Fastly等の同一共有CDN内でedge IPだけが変わった場合は、生のIP変化として残しつつC2インフラ変化件数から除外します。

履歴の各IPにはAS番号・AS組織、国・地域・都市、インフラタグ、防弾ホスティング評価を付与します。IP集合が変化したeventは、旧IP集合と新IP集合の双方に同じ詳細を保持し、追加IPと消失IPも分けて記録します。共有CDNのedge IPはoriginではないため、CDN判定だけから防弾ホスティングや攻撃者インフラへ帰属させません。

防弾ホスティング評価は根拠付きregistryで管理し、信頼できる情報源による明示評価がある場合だけ`防弾ホスティング`、複数の状況証拠はあるが運営意図を確認できない場合は`防弾ホスティング - 疑い`とします。単一IPの悪用観測やorganization名だけでは確定しません。

ONの対象、7日未満のOFF、proxy利用不可等の未観測対象は次回も監視します。最新観測がOFFで、最後のON以後または初回OFFから7日以上経過し、その間に2回以上のOFF実観測がある対象だけを停止履歴へ移し、次回のactive対象から外します。停止済み対象に新しいON証拠が得られた場合は、再開eventを残して監視へ戻します。

成果物と再実行手順は[`RUN-C2-MONITORING-PIPELINE.md`](RUN-C2-MONITORING-PIPELINE.md)を参照してください。
## MX-Goのlocalhost限定protocol mode

`mxgo` は封じ込めを優先したlab modeです。`preview` はDNSやnetwork activityなしで合成heartbeatの説明を生成します。`checkin` と `recipients` は `localhost`、`127.0.0.1`、`::1` だけを受け付け、`--mxgo-allow-loopback-network` を必須とします。recipient結果には件数とhashだけを含めます。詳細は [MX-Go emulator](../../emulators/unclassified/mx_go/README.md) を参照してください。

このmodeから第三者の稼働中MX-Go serverへcheck-inしたり、実際のrecipient dataを取得したりすることは意図的にできません。

## offlineのstealer候補mode

`c2_candidate_detector.py` はconfig extractorのJSONを読み、DNS、TCP、HTTP、Shodanへ接続せずに受動的Shodan pivotを作成します。追加した5つのstealer familyは既定でこのoffline modeを使用します。active protocol behaviorは、[`emulators/stealers/`](../../emulators/stealers/README.md) のloopback限定synthetic labでだけ表現します。
