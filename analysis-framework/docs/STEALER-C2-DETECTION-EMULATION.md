# Stealer C2 detectorとemulator

## 対象と結論

この実装はLumma、Remus、Vidar、StealC、FormBook、AMOSを対象に、受動PCAP判定、Nmapによる安全な到達性・限定probe、loopback emulatorを分離します。HTTP status、Host、port、domain、一般的なJSON POSTだけでは`c2_confirmed=true`へ昇格しません。

| family | 高精度detector | Nmap | emulator |
|---|---|---|---|
| StealC | 同一endpoint・同一path上の連続JSON POSTとfamily帰属 | review済みRC4鍵とbuildを使う合成登録1回だけ。token形状一致時のみ確認 | 固定lab鍵のRC4/Base64登録subset |
| Lumma | 同一endpoint上の`uid/cid`登録から`uid/pid/hwid/file` uploadまでの順序 | review済みprofileの合成登録1回。`c2_confirmed=false` | 登録request形状まで |
| Remus | 同一endpoint上の登録、debug、step、uploadの4段階順序 | review済みprofileの合成登録1回。`c2_confirmed=false` | 登録requestとopaque envelope形状まで |
| Vidar | 静的復元URL、port、path、User-Agent hashとPCAPの完全一致 | 固定profileのroot `HEAD`と陰性対照。最大0.60のprobable判定 | profile照合後のpassive sink |
| FormBook | 4件の公開PCAPに共通するGET／POST fan-outとreview済み静的bootstrap経路 | 固定経路と陰性対照の`HEAD`差分。最大0.60のprobable判定 | passive sink。XLoader v8のreview済みprofileは別emulator |
| AMOS | 同一endpoint・同一64桁campaign IDの`/ledger/`から`/ledger/live/`への順序 | ledger 2経路と陰性対照の`HEAD`差分。最大0.65のprobable判定 | 対応する2経路のpassive sink |

StealCの`create`登録とRC4暗号化JSONは、Proofpointが公開したC2 protocol説明とローカルPCAP解析の双方に整合します。FormBookはMandiantがHTTP、RC4、変更Base64、`FBNG` command形状を公開していますが、このrepositoryの一般化対象ではterminal URIと鍵が揃わないため、古い汎用signatureを送信しません。Lummaの能動操作はMicrosoftが説明するMaaS/C2運用とローカルPCAPの完全一致profileに限定します。AMOSはvariant間のC2差が大きいため、SentinelOneのvariant研究も踏まえ、今回回収した`ledger` pair以外へ一般化しません。

参考資料:

- [ProofpointによるStealC C2分析: StealC You Later](https://www.proofpoint.com/us/blog/threat-insight/stealc-you-later-proofpoint-and-ibm-x-force-support-operation-endgame)
- [MandiantによるFormBook配布分析: Significant FormBook Distribution Campaigns](https://cloud.google.com/blog/topics/threat-intelligence/formbook-malware-distribution-campaigns/)
- [MicrosoftによるLumma Stealer分析](https://www.microsoft.com/en-us/security/blog/2025/05/21/lumma-stealer-breaking-down-the-delivery-techniques-and-capabilities-of-a-prolific-infostealer/)
- [SentinelOneによるAtomic Stealer variant分析](https://www.sentinelone.com/blog/atomic-stealer-threat-actor-spawns-second-variant-of-macos-malware-sold-on-telegram/)
- [ローカルのPCAP・静的profile解析](../../analysis-results/research/stealer-protocol-profiles/2026-08-04/README.md)

## 受動PCAP detector

[`stealer_protocol_evidence.py`](../common/stealer_protocol_evidence.py)は`TShark`の固定field出力を読み、次だけを公開reportへ残します。

- socket接続先、HTTP Host、URI path、Content-Type
- form key名、multipart name、query key名
- request frame順序
- User-Agent原文ではなくSHA-256

本文、query値、token、filename、User-Agent原文、victim metadataは保持しません。

```powershell
py -3.13 .\analysis-framework\common\stealer_protocol_evidence.py `
  --pcap C:\isolated\capture.pcapng `
  --tshark 'C:\Program Files\Wireshark\tshark.exe' `
  --family remusstealer `
  --output C:\isolated\remus-protocol-evidence.json
```

Vidarは静的extractor出力を`--reviewed-profile`へ渡した場合だけ高信頼判定になります。profileのURLとUser-Agentは入力に使いますが、判定結果へ値を再掲しません。

```powershell
py -3.13 .\analysis-framework\common\stealer_protocol_evidence.py `
  --pcap C:\isolated\capture.pcapng `
  --tshark 'C:\Program Files\Wireshark\tshark.exe' `
  --family vidar `
  --reviewed-profile C:\isolated\vidar-static-profile.json `
  --output C:\isolated\vidar-protocol-evidence.json
```

### Vidar dead-drop snapshotの相関

[`dead_drop_capture.py`](../malware/vidar/dead_drop_capture.py)は、静的configへ束縛されたTelegram、Pinterest、Steam、Epic Games community profile候補を取得計画へ正規化します。既定はnetworkへ接続せず、取得可否と未確認候補をJSON表示するだけです。

```powershell
py -3.13 .\analysis-framework\malware\vidar\dead_drop_capture.py `
  --config C:\isolated\vidar-config.json
```

実取得は`--allow-network`、一意な`--service`、repository外にある**存在しない新規path**の`--private-output-directory`を同時に指定した場合だけ有効です。Windowsでは既存のlocal fixed drive上の親directoryだけを許可し、作成と同時にcurrent user＋Administrators限定のprotected DACLを設定・再検証します。UNC、mapped network drive、removable media、CD-ROM、RAM diskは拒否します。POSIXではmode `0700`を要求します。

静的に完全一致したHTTPS host／routeへ1回だけGETし、全DNS応答がglobal unicastであることを確認して選択IPへpinします。DNS、TLS、HTTP header、本文受信の全体を1つのabsolute deadlineでkill可能な子processへ隔離します。HTTP `200`、一意な`Content-Length`、その値と完全一致する非空UTF-8本文だけを受理し、redirect、圧縮、partial response、`Transfer-Encoding`、不明Content-Type、上限超過を拒否します。復元endpointには接続しません。raw本文、取得metadata、manifestはnetwork前に固定したfile handleへ保存し、directory handle、device／inode、symlink／reparse point、size、SHA-256を保存前後に再検証します。

```powershell
py -3.13 .\analysis-framework\malware\vidar\dead_drop_capture.py `
  --config C:\isolated\vidar-config.json `
  --sample-sha256 <64桁SHA-256> `
  --service telegram `
  --service epic_games `
  --private-output-directory C:\isolated\vidar-snapshots `
  --allow-network
```

[`dead_drop_snapshot.py`](../malware/vidar/dead_drop_snapshot.py)はlive接続を行わず、analystが保存したoffline snapshotまたは上記限定取得manifestだけを解析します。限定取得receiptは検体SHA-256、正規化した静的configのSHA-256、元URL、service、取得時刻、本文path／size／SHA-256、取得metadataのSHA-256へ完全に束縛し、相関器が保存fileから再計算します。offline入力についてrepository公開状態は断定せず`not_assessed`とし、限定取得toolが管理したpathだけを非公開保存検証済みとして区別します。1サービスにつきsnapshotは1件に限定し、異なる2サービス以上が同じglobal unicast IPv4:portを示した場合だけ`probable_c2=true`とします。

```powershell
py -3.13 .\analysis-framework\malware\vidar\dead_drop_snapshot.py `
  --config C:\isolated\vidar-config.json `
  --manifest C:\isolated\snapshots\manifest.json `
  --output C:\isolated\vidar-dead-drop-result.json
```

この結果は共有サービスそのものをC2とせず、相関endpointも`c2_confirmed=false`、confidence `0.85`の候補に固定します。snapshotが1サービスだけ、本文に複数endpointがある、source URLやSHA-256が不一致、private／loopback／multicast IPだけの場合はfail-closedです。相関tool自身にはHTTP client、認証、live probe、検体実行機能がなく、限定取得toolも検体や復元endpointを実行・照会しません。

## Nmapによる観測

Nmap mappingは[`profiles.json`](../nmap/profiles.json)に集約しています。StealC、Lumma、Remusは[`stealer-http-c2.nse`](../nmap/scripts/stealer-http-c2.nse)のfamily別modeを持ち、FormBook／Vidar／AMOSは[`stealer-route-c2.nse`](../nmap/scripts/stealer-route-c2.nse)の固定経路差分modeを使います。実行にはexact profile、同値acknowledgement、数値IP pin、timeout、request budgetが必要です。

FormBookのPCAP fan-outは受動判定として維持し、review済み単一経路だけを`profile_limited_probable_families`へ追加します。FormBook／Vidar／AMOSの能動側は要求bodyなしの`HEAD`経路差分だけを許可します。詳しい安全境界と実行方法は[`STEALER-ROUTE-PROBES.md`](../nmap/STEALER-ROUTE-PROBES.md)を参照してください。TCP openや経路差だけで`c2_confirmed=true`にはなりません。

loopbackでtransport境界だけを確認する例:

```powershell
nmap -n -sT -Pn -p 18080 `
  --script .\analysis-framework\nmap\scripts\c2-transport-observe.nse `
  --script-args c2-transport.mode=tcp-open `
  127.0.0.1
```

## Loopback emulatorの利用

[`emulators/stealers/lab.py`](../../emulators/stealers/lab.py)を使用します。

```powershell
py -3.13 .\emulators\stealers\lab.py server --host 127.0.0.1 --port 18080
py -3.13 .\emulators\stealers\lab.py client --family stealc --base-url http://127.0.0.1:18080
py -3.13 .\emulators\stealers\lab.py client --family amosstealer --base-url http://127.0.0.1:18080
```

安全境界は次のとおりです。

- bind先、client接続先、accepted peerはloopbackだけです。
- redirectを追跡しません。
- 1 connectionにつき1 request、bodyは64 KiB以下です。
- 合成IDだけを使用し、victim metadataを送信しません。
- task、command、payload、plugin、configを返しません。
- FormBook、Vidar、AMOSのroute responseはwire互換C2 responseではありません。
- すべてのclient結果で`c2_confirmed=false`を固定します。

保存済みsnapshot parserだけを検証するときは、[`dead_drop_loopback_emulator.py`](../malware/vidar/dead_drop_loopback_emulator.py)を使えます。numeric loopbackへ1接続だけbindし、`GET /profile`へ合成本文を1回返します。本文へ指定できるendpointはRFC 5737 documentation networkだけであり、実在するpublic IPは拒否します。

```powershell
py -3.13 .\analysis-framework\malware\vidar\dead_drop_loopback_emulator.py `
  --service telegram `
  --endpoint 192.0.2.10:443 `
  --bind 127.0.0.1 `
  --port 18081
```

このfacadeはVidarの最終C2 protocolを再現しません。task、command、payload、victim metadataを送らず、raw request／responseも保持しません。

## 精度境界

- RemusとLummaはfieldが別endpointに分散した場合や順序が逆の場合に一致しません。
- StealCは単独のJSON POST、異なるpath、family帰属なしでは一致しません。
- Vidarは静的profileなし、endpoint不一致、User-Agent hash不一致では一致しません。
- Vidar dead-drop snapshot相関は独立2サービス未満、同じendpointへの合意なし、保存本文の完全性不一致では候補を返しません。snapshot本文だけでprotocol確認へ昇格しません。
- AMOSは片方のrouteだけ、campaign ID不一致、別endpointでは一致しません。
- FormBookは単一HTTP requestやstatusからterminal C2を推測せず、受動側は6 endpoint以上のfan-out、能動側は完全一致profileと陰性対照差を要求します。

これらの制約により、検出不能なvariantを無理に陽性化せず、追加のstatic recoveryまたはprocess帰属PCAPが必要な状態を明示します。
