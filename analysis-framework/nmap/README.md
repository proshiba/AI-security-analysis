# Nmap C2検知スクリプト

C2検知で対象へ接触する処理は、すべてNmap NSEを実行backendとします。Pythonは対象選択、中央profileの完全一致検証、NSE引数fileの生成、Nmap XMLのallowlist化、結果の評価だけを担当し、DNS、TCP、TLS、HTTP、FTP、malware固有protocolのsocketを直接開きません。単なるport openをマルウェア固有C2とは扱わず、Nmapで検証できる短いprotocol応答だけを根拠にします。検体の実行、task本文の公開、task実行、追加payloadの追跡は行いません。

標準adapterは同じNmapフォルダ内の[`nmap_c2_detector.py`](nmap_c2_detector.py)です。`monitor_recent_c2.py`、`run_c2_monitoring_pipeline.py`、`c2_validation.py`、`invoke_analysis.py`、`Invoke-Analysis.ps1`、PureRAT／AgentTesla／RedLineのfamily別active CLIは、すべてこのadapterへ収束します。

旧`c2_detector.py`はoffline plan生成との互換用です。`--allow-network`を指定しても`python_direct_c2_probe_disabled`を返し、外部targetへ接続しません。family別の旧socket helperは合成fixtureとloopback unit testの互換部品であり、標準active C2検知backendではありません。

実行policyは`network_execution_backend=nmap_nse_only`と`python_direct_probe_used=false`を公開結果へ固定します。21 methodの完全対応は[`profiles.json`](profiles.json)を正本とし、Nmapが見つからない場合、中央profileに一致しない独自送信が要求された場合、またはNSE bindingが未登録の場合はPythonへfallbackせずfail-closedとします。FormBook／Vidar／AMOSの経路差分方式は[`STEALER-ROUTE-PROBES.md`](STEALER-ROUTE-PROBES.md)を参照してください。

## 対応範囲

| family | script／mode | 送信・確認内容 | 最大confidence | 判定上の注意 |
| --- | --- | --- | ---: | --- |
| ValleyRAT／Winos | `valleyrat-c2.nse`／`winos` | 匿名heartbeat 1 frame、制御応答 `C9`／`CA`／`CB` | 0.95 | victim metadataは送らず、送信frameの反射応答を除外する |
| 汎用DNS | `c2-dns-observe.nse` | Nmapが解決したA／AAAAだけを記録 | 0.05 | serviceへ接続せず`c2_confirmed=false`固定 |
| 汎用transport | `c2-transport-observe.nse` | TCP open、server-first、TLS、またはGET 1回 | 0.60 | 到達性だけでfamily C2へ昇格しない |
| ValleyRAT／vvaS | `valleyrat-c2.nse`／`vvas` | `333200`、14-byte固定stage header | 0.95 | stage本体は取得しない |
| ValleyRAT／N520 | `valleyrat-c2.nse`／`n520` | TLS server-first 44-byte frame、magic、CRC32 | 0.98 | application dataは送らない |
| AgentTesla | `agenttesla-ftp-c2.nse` | FTP banner、任意で検体由来USER／PASS | 0.95 | bannerだけでは0.35。file操作はしない |
| AsyncRAT | `dotnet-rat-c2.nse`／`asyncrat` | TLS、gzip圧縮MessagePack Ping／pong | 0.98 | 証明書不一致だけでは除外しない |
| VenomRAT | `dotnet-rat-c2.nse`／`venomrat` | TLS、gzip圧縮MessagePack Ping／Po_ng | 0.98 | 証明書不一致だけでは除外しない |
| PureRAT／PureHVNC 4.4.1 direct-TLS | `purerat-direct-tls.nse` | application dataを送らないTLS接続、leaf証明書SHA-256 | 0.92 | `c2_confirmed=false`固定。NmapだけではTLS 1.0完全一致を保証しない |
| StealC v2 | `stealer-http-c2.nse`／`stealc` | RC4登録、復号済みaccess token形式 | 0.90 | task取得はしない |
| Lumma v6 | `stealer-http-c2.nse`／`lumma` | uid登録、HTTP応答形状 | 0.78 | protocol固有確認ではなく推定 |
| Remus | `stealer-http-c2.nse`／`remus` | tag／exp登録、HTTP 201、envelope長 | 0.78 | protocol固有確認ではなく推定 |
| FormBook | `stealer-route-c2.nse`／`formbook` | 固定profileのreview済み経路と陰性対照を`HEAD`で比較 | 0.60 | probable判定のみ。query／body／cookieを送らず`c2_confirmed=false`固定 |
| Vidar | `stealer-route-c2.nse`／`vidar` | 固定profileのroot `HEAD`と陰性対照 | 0.60 | probable判定のみ。Telegram／Steam dead-dropへ接続しない |
| AMOS | `stealer-route-c2.nse`／`amos` | 同一campaignのledger 2経路と陰性対照を`HEAD`で比較 | 0.65 | body／victim dataなし。`c2_confirmed=false`固定 |
| DarkComet | `darkcomet-c2.nse` | RC4 server-first challengeの`IDTYPE`完全一致 | 0.98 | application dataは送信しない |
| RedLine Stealer | `redline-c2.nse` | 固定SOAP 1.1 `CheckConnect`を1要求、厳密なboolean応答 | 0.98 | review済みprofileのIP・port以外には送信しない |
| XLoader | `xloader-c2.nse`／`transport-only` | Nmap scanで確認済みのTCP到達性だけを明示的に記録 | 0.15 | `c2_confirmed=false`固定。登録requestや候補一斉送信はしない |

機械可読の対応表は[`profiles.json`](profiles.json)にあります。`purerat-c2.nse`は`04000000` plaintext prelude後にTLSへ昇格する別variantのloopback回帰用として保持しますが、現行21 methodの正式bindingには含めません。`gh0strat`、`remcosrat`、`prometei`、`spyglace`、`purelogs`の現行実装は設定抽出・event照合・汎用transport確認が中心で、review済みのon-wire固有応答がありません。誤検知を避けるため、現時点ではNSEのマルウェア固有確認対象に含めていません。

### DarkCometの受信専用判定

`darkcomet-c2.nse`はTCP接続後に最大13 byte（判定上限12 byteと超過検知1 byte）だけを受信し、送信は行いません。検体から静的に復元したnetwork RC4 keyでraw 6 byteまたはASCII-hex 12 byteを復号し、平文が6 byteの`IDTYPE`へ完全一致した場合だけC2と判定します。主形式は静的コードで確認したASCII-hexで、rawは互換形式として記録します。6／12 byteを受信した時点では確定せず、EOFまたは単一の全体期限まで13 byte目の有無を確認します。

対象検体ではnetwork keyが10-byte ASCIIの`#KCMDDC5#-`であり、PWDは連結されません。設定resourceの復号key `#KCMDDC5#-890`は別用途なので、network profileへ流用すると判定を誤ります。中央profileは静的key導出、完全一致host・port、受信上限、公開証拠JSONの内容検証とSHA-256固定が揃わない限り登録しません。NSEへ渡すkeyは、この検証を通ったprofileから保護した`--script-args-file`へ生成します。

このプローブはserver-first challengeだけを検証し、implant側の`SERVER`応答、端末登録、command poll、payload取得は行いません。RC4 keyをshell historyへ残さないよう、実運用では保護した`--script-args-file`を使用してください。

名前解決はNmap本体がNSE開始前に行うため、script内の期限ではDNS時間を制限できません。NSEの期限は接続開始から受信終了までで、結果へ`dns_timeout_bounded=false`と`deadline_scope=post_dns_connect_receive`を記録します。不一致、部分、不正形式、超過、無応答の`confidence`は`0.0`です。

### RedLineのCheckConnect判定

`redline-c2.nse`は、review済みprofile IDと同値の`redline.acknowledge-profile`を別引数で要求し、`192.144.32.84:16383`、`POST /`、SOAPAction、XML bodyを固定します。production profileでIPまたはportが異なる場合、または生成requestがreview済みの357 byte／SHA-256と異なる場合は、application dataを送る前に停止します。送信は最大1要求、requestは512 byte以下、responseはHTTP headerを含め4096 byte以下です。raw socketを使うためredirectを追跡せず、端末情報、資格情報、task取得要求は送信しません。

HTTP 2xx、単一の`Content-Length`、`text/xml; charset=utf-8`、SOAP 1.1の`Envelope > Body > CheckConnectResponse > CheckConnectResult`というnamespace付き一意な親子構造、単純なxsd:booleanをすべて満たした場合だけ`c2_confirmed=true`とします。booleanが`true`ならconfidence 0.98、`false`でもRedLine固有protocol応答は成立するため0.95ですが、後者はC2がimplantの接続を受理したことまでは示しません。DOCTYPE、entity、comment、追加要素、重複header、chunked response、redirectは拒否します。

### XLoaderのNSE境界

XLoaderは、64候補中の実C2選択とrequest／responseの多層暗号に検体固有のprivate materialが必要です。NSEへ鍵や復元済みendpoint群を埋め込まず、`xloader.mode=transport-only,xloader.acknowledge-no-protocol-check=true`を明示した場合だけ、Nmap本体が確認したTCP openを低確度の能力情報として返します。NSE自身は追加socketを開かず、application data、端末登録、candidate spray、task取得を一切送信しません。したがって結果の`c2_confirmed`と`probable_c2`は常に`false`です。review済みのNSE protocol実装が完成するまではtransport観測だけでfail-closedとし、private Python socket probeへfallbackしません。

FormBookの完全な登録protocolは引き続きno-send境界です。`xloader.variant=formbook`はTCP到達性だけを0.15で記録します。一方、追加静的解析でreviewした単一bootstrap経路と4件の公開PCAPで確認したfan-out形状は、terminal鍵や登録値を使わない別の検出根拠です。`stealer-route-c2.nse`の`formbook` modeは固定経路と陰性対照へ2回だけ`HEAD`を送り、差が成立した場合も0.60のprobable判定に限定します。404、root page、domain単独、または陰性対照と同じ応答では昇格しません。

### Vidar／AMOSの経路差分判定

`stealer-route-c2.nse`は、script内のreview済みprofileを引数で上書きできない形で固定し、同値acknowledgementと数値IP pinが揃った場合だけ通信します。FormBookとVidarはreview済み経路と陰性対照の2回、AMOSは二つのledger経路と陰性対照の3回だけ`HEAD`を送ります。要求body、query、端末情報、cookie、認証情報は送らず、redirectと応答bodyも追跡しません。経路差が成立した場合でもprotocol固有応答ではないため、FormBook／Vidarは0.60、AMOSは0.65の`probable_c2=true`に限定し、`c2_confirmed=false`を維持します。profile ID、実行例、status条件は[`STEALER-ROUTE-PROBES.md`](STEALER-ROUTE-PROBES.md)に記載しています。

## 実行例

標準運用ではadapterを使います。NSE引数に資格情報や鍵が必要な場合もcommand lineへ展開せず、権限制限した一時`--script-args-file`だけに書きます。

```powershell
py -3.13 .\analysis-framework\nmap\nmap_c2_detector.py <host> <port> `
  --protocol https --sample-sha256 <sha256> `
  --nmap C:\Tools\Nmap\nmap.exe `
  --allow-network --output .\.work\c2-observation.json
```

対象へ能動的な通信を送るため、許可された監視対象だけに使用します。profile値は対象検体の解析結果から取得し、shell historyや公開ログへの資格情報・RC4 keyの残存に注意してください。

NSEの直接起動は原則としてadapterの中央profile照合と追加許可gateを迂回するため、外部targetの標準運用では使用しません。例外は、中央active methodへ昇格していないFormBook／Vidar／AMOSのprofile限定調査です。この場合も[`STEALER-ROUTE-PROBES.md`](STEALER-ROUTE-PROBES.md)の固定profile、同値acknowledgement、数値IP pin、許可済み監視対象という全条件を満たす場合だけ使用します。通常のscript単体確認は`verify_nse.py`が起動するnumeric loopback fixtureで行います。

## 動作検証

`verify_nse.py` はloopback上で一時的な模擬C2を起動し、Nmap 7.99を実際に39回呼び出して、汎用DNS／transportと全malware固有modeの正応答、Winos送信frameのecho拒否、DarkCometのraw EOF、ASCII-hex 6+6遅延分割、12+1遅延超過、wrong key、malformed、partial、overlong、StealCのredirect拒否、RedLineのtrue／false／追加要素拒否／redirect拒否／acknowledgement拒否／production target不一致拒否、XLoader／FormBookのno-send境界、FormBook／Vidar／AMOSの経路一致・不一致を確認します。外部networkには接続しません。TLS証明書とprivate keyは一時directoryだけに生成し、終了時に削除します。

```powershell
python .\analysis-framework\nmap\verify_nse.py --nmap C:\Tools\Nmap\nmap.exe
python -m pytest .\analysis-framework\tests\test_nmap_c2_scripts.py -q
```

統合試験では、Winos、vvaS、N520、AsyncRAT、VenomRAT、PureRAT、AgentTesla FTP、StealC、Lumma、Remus、DarkComet、RedLine、XLoader、FormBook、Vidar、AMOSの送受信または受信専用処理と最終statusを検証します。DarkCometとXLoader／FormBook transport fixtureはクライアントからapplication dataを1 byteでも受信した場合に失敗するため、no-send境界も確認できます。FormBook／Vidar／AMOS route fixtureは要求数、method、Host、User-Agent、bodyなしを固定します。`profiles.json`と中央の`c2_protocol_probe_profiles.json`の対応漏れもunit testで検出します。
