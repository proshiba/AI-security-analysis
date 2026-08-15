# Stealer C2 detectorとemulator

## 対象と結論

この実装はLumma、Remus、Vidar、StealC、FormBook、AMOSを対象に、受動PCAP判定、Nmapによる安全な到達性・限定probe、loopback emulatorを分離します。HTTP status、Host、port、domain、一般的なJSON POSTだけでは`c2_confirmed=true`へ昇格しません。

| family | 高精度detector | Nmap | emulator |
|---|---|---|---|
| StealC | 同一endpoint・同一path上の連続JSON POSTとfamily帰属 | review済みRC4鍵とbuildを使う合成登録1回だけ。token形状一致時のみ確認 | 固定lab鍵のRC4/Base64登録subset |
| Lumma | 同一endpoint上の`uid/cid`登録から`uid/pid/hwid/file` uploadまでの順序 | review済みprofileの合成登録1回。`c2_confirmed=false` | 登録request形状まで |
| Remus | 同一endpoint上の登録、debug、step、uploadの4段階順序 | review済みprofileの合成登録1回。`c2_confirmed=false` | 登録requestとopaque envelope形状まで |
| Vidar | 静的復元URL、port、path、User-Agent hashとPCAPの完全一致 | 固定profileのroot `HEAD`と陰性対照。最大0.60のprobable判定 | profile照合後のpassive sink |
| FormBook | terminal wire signature未回収として明示的に低信頼・受動限定 | application dataを送らないtransport観測だけ | passive sink。XLoader v8のreview済みprofileは別emulator |
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

## Nmapによる観測

Nmap mappingは[`profiles.json`](../nmap/profiles.json)に集約しています。StealC、Lumma、Remusは[`stealer-http-c2.nse`](../nmap/scripts/stealer-http-c2.nse)のfamily別modeを持ち、Vidar／AMOSは[`stealer-route-c2.nse`](../nmap/scripts/stealer-route-c2.nse)の固定経路差分modeを使います。実行にはexact profile、同値acknowledgement、数値IP pin、timeout、request budgetが必要です。

FormBookだけを`passive_only_families`へ残し、終端URI・鍵・応答契約が揃うまでtransport観測だけを許可します。Vidar／AMOSは`profile_limited_probable_families`へ移し、要求bodyなしの`HEAD`経路差分だけを許可します。詳しい安全境界と実行方法は[`STEALER-ROUTE-PROBES.md`](../nmap/STEALER-ROUTE-PROBES.md)を参照してください。TCP openや経路差だけで`c2_confirmed=true`にはなりません。

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
- FormBook、Vidar、AMOSのresponseはwire互換C2 responseではありません。
- すべてのclient結果で`c2_confirmed=false`を固定します。

## 精度境界

- RemusとLummaはfieldが別endpointに分散した場合や順序が逆の場合に一致しません。
- StealCは単独のJSON POST、異なるpath、family帰属なしでは一致しません。
- Vidarは静的profileなし、endpoint不一致、User-Agent hash不一致では一致しません。
- AMOSは片方のrouteだけ、campaign ID不一致、別endpointでは一致しません。
- FormBookは一般的なHTTP trafficからterminal C2を推測しません。

これらの制約により、検出不能なvariantを無理に陽性化せず、追加のstatic recoveryまたはprocess帰属PCAPが必要な状態を明示します。
