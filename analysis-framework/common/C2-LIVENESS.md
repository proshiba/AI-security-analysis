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

## MX-Goのlocalhost限定protocol mode

`mxgo` は封じ込めを優先したlab modeです。`preview` はDNSやnetwork activityなしで合成heartbeatの説明を生成します。`checkin` と `recipients` は `localhost`、`127.0.0.1`、`::1` だけを受け付け、`--mxgo-allow-loopback-network` を必須とします。recipient結果には件数とhashだけを含めます。詳細は [MX-Go emulator](../../emulators/unclassified/mx_go/README.md) を参照してください。

このmodeから第三者の稼働中MX-Go serverへcheck-inしたり、実際のrecipient dataを取得したりすることは意図的にできません。

## offlineのstealer候補mode

`c2_candidate_detector.py` はconfig extractorのJSONを読み、DNS、TCP、HTTP、Shodanへ接続せずに受動的Shodan pivotを作成します。追加した5つのstealer familyは既定でこのoffline modeを使用します。active protocol behaviorは、[`emulators/stealers/`](../../emulators/stealers/README.md) のloopback限定synthetic labでだけ表現します。
