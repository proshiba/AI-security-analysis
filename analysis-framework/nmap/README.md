# Nmap C2検知スクリプト

C2検知で対象へ接触する処理は、すべてNmap NSEを実行backendとします。Pythonは対象選択、中央profileの完全一致検証、NSE引数fileの生成、Nmap XMLのallowlist化、結果の評価だけを担当し、DNS、TCP、TLS、HTTP、FTP、malware固有protocolのsocketを直接開きません。単なるport openをマルウェア固有C2とは扱わず、Nmapで検証できる短いprotocol応答だけを根拠にします。検体の実行、task本文の公開、task実行、追加payloadの追跡は行いません。

標準adapterは同じNmapフォルダ内の[`nmap_c2_detector.py`](nmap_c2_detector.py)です。`monitor_recent_c2.py`、`run_c2_monitoring_pipeline.py`、`c2_validation.py`、`invoke_analysis.py`、`Invoke-Analysis.ps1`、PureRAT／AgentTesla／RedLineのfamily別active CLIは、すべてこのadapterへ収束します。

旧`c2_detector.py`はoffline plan生成との互換用です。`--allow-network`を指定しても`python_direct_c2_probe_disabled`を返し、外部targetへ接続しません。family別の旧socket helperは合成fixtureとloopback unit testの互換部品であり、標準active C2検知backendではありません。

実行policyは`network_execution_backend=nmap_nse_only`と`python_direct_probe_used=false`を公開結果へ固定します。20 methodの完全対応は[`profiles.json`](profiles.json)を正本とし、Nmapが見つからない場合、中央profileに一致しない独自送信が要求された場合、またはNSE bindingが未登録の場合はPythonへfallbackせずfail-closedとします。FormBook／XLoaderは`passive_only`で、application-layer methodを正式bindingへ登録しません。Vidar／AMOSの経路差分方式は[`STEALER-ROUTE-PROBES.md`](STEALER-ROUTE-PROBES.md)を参照してください。

## 対応範囲

| family | script／mode | 送信・確認内容 | 最大confidence | 判定上の注意 |
| --- | --- | --- | ---: | --- |
| ValleyRAT／Winos | `valleyrat-c2.nse`／`winos` | 匿名heartbeat 1 frame、制御応答 `C9`／`CA`／`CB` | 0.95 | victim metadataは送らず、送信frameの反射応答を除外する |
| 汎用DNS | `c2-dns-observe.nse` | Nmapが解決したA／AAAAだけを記録 | 0.05 | serviceへ接続せず`c2_confirmed=false`固定 |
| 汎用transport | `c2-transport-observe.nse` | TCP open、server-first、TLS、またはGET 1回。TLSは明示時のみ送信ゼロでN520型44 byte／`TIMEOUT`を判定 | 0.90 | N520型完全一致もprobable止まり。`TIMEOUT`はcluster証拠のみでfamily C2へ昇格しない |
| ValleyRAT／vvaS | `valleyrat-c2.nse`／`vvas` | `333200`、14-byte固定stage header | 0.95 | stage本体は取得しない |
| ValleyRAT／N520 | `valleyrat-c2.nse`／`n520` | TLS server-first 44-byte frame、magic、CRC32 | 0.98 | application dataは送らない |
| AgentTesla | `agenttesla-ftp-c2.nse` | FTP banner、任意で検体由来USER／PASS | 0.95 | bannerだけでは0.35。file操作はしない |
| AsyncRAT | `dotnet-rat-c2.nse`／`asyncrat` | TLS、gzip圧縮MessagePack Ping／pong | 0.98 | 証明書不一致だけでは除外しない |
| VenomRAT | `dotnet-rat-c2.nse`／`venomrat` | TLS、gzip圧縮MessagePack Ping／Po_ng | 0.98 | 証明書不一致だけでは除外しない |
| PureRAT／PureHVNC 4.4.1 direct-TLS | `purerat-direct-tls.nse` | application dataを送らないTLS接続、leaf証明書SHA-256 | 0.75 | 証明書一致もprobableのみで`c2_confirmed=false`固定。NmapだけではTLS 1.0完全一致を保証しない |
| PureRAT／PureHVNC v4.1.9 family-level旧prelude（e554 v4.4.1互換仮説） | `purerat-c2.nse` | e554の固定3 endpointへ`04000000`後にTLS昇格、leaf証明書SHA-256 | 0.60 | `04000000`はv4.1.9のfamily-level証拠。e554でのwire bindingは未確認であり、完全一致時もprobableのみ、`c2_confirmed=false`固定 |
| PureLogs `http_aes_v5` | `purelogs-c2.nse` | 0f2の固定endpointへ証明書pin後、HTTPS `GET /ping`を1回 | 0.70 | `legacy_socket_3des`には適用しない。200かつ本文が厳密に`OK`でもprobableのみ。redirectなし、応答上限1 KiB、`c2_confirmed=false`固定 |
| StealC v2 | `stealer-http-c2.nse`／`stealc` | RC4登録、復号済みaccess token形式 | 0.90 | task取得はしない |
| Lumma v6 | `stealer-http-c2.nse`／`lumma` | uid登録、HTTP応答形状 | 0.78 | protocol固有確認ではなく推定 |
| Remus | `stealer-http-c2.nse`／`remus` | tag／exp登録、HTTP 201、envelope長 | 0.78 | protocol固有確認ではなく推定 |
| FormBook | `c2-transport-observe.nse`または`xloader-c2.nse`／`transport-only` | TCP接続、TLS handshake、server-first受信まで | 0.45 | `passive_only`。既知経路への`HEAD`や汎用HTTP要求もproductionでは拒否 |
| Vidar | `stealer-route-c2.nse`／`vidar` | 固定profileのroot `HEAD`と陰性対照 | 0.60 | probable判定のみ。Telegram／Steam dead-dropへ接続しない |
| AMOS | `stealer-route-c2.nse`／`amos` | 同一campaignのledger 2経路と陰性対照を`HEAD`で比較 | 0.65 | body／victim dataなし。`c2_confirmed=false`固定 |
| DarkComet | `darkcomet-c2.nse` | RC4 server-first challengeの`IDTYPE`完全一致 | 0.98 | application dataは送信しない |
| RedLine Stealer | `redline-c2.nse` | 固定SOAP 1.1 `CheckConnect`を1要求、厳密なboolean応答 | 0.98 | review済みprofileのIP・port以外には送信しない |
| XLoader | `xloader-c2.nse`／`transport-only` | Nmap scanで確認済みのTCP到達性だけを明示的に記録 | 0.15 | `c2_confirmed=false`固定。登録requestや候補一斉送信はしない |

機械可読の対応表は[`profiles.json`](profiles.json)にあります。`purerat-c2.nse`の`04000000` plaintext prelude後にTLSへ昇格する経路は、v4.1.9のfamily-level公開解析で確認された形式を、e554 v4.4.1個別検体のendpoint・証明書へ適用する旧互換仮説です。保存済みe554証拠はprelude自体を確定しないため、C2確認には使用しません。`gh0strat`、`remcosrat`、`prometei`、`spyglace`はreview済みのon-wire固有応答がなく、現時点ではNSEのマルウェア固有確認対象に含めていません。

### PureLogsの限定`/ping`判定

PureLogsの通信世代は次のように分離します。

| variant | 公開資料で確認された境界 | このリポジトリでの扱い |
|---|---|---|
| `legacy_socket_3des` | ANY.RUNはraw socket、4-byte length、GZip／TripleDES、応答方向のbyte reversal、hash/data/hash形状を報告。Fortinetも旧世代がsocket方式だったと記載 | 全field、鍵導出、方向別変換を検体またはPCAPで確定できていないため、profile、能動probe、復号codecを提供しない |
| `http_aes_v5` | FortinetはHTTPへ移行した現行世代とAESを報告 | 0f2 caseのreview済みHTTPS `/ping`だけをNmap profile化。0f2自身のversion文字列を確認したとは扱わず、AESを使う収集endpointや登録通信は送信しない |

このため公開記事の記述だけから旧世代codecを実装しません。`legacy_socket_3des`のsocket framingやTripleDES処理を`http_aes_v5`へ流用せず、反対方向の流用もしません。

`purelogs-c2.nse`は`http_aes_v5`側の0f2 caseで確認した`logs.uvexio.com:8443`、固定IP`193.26.115.118`、leaf証明書SHA-256 `9e254cab…eeac3`だけを許可します。中央profile IDと同値acknowledgement、review済みhost／IP／port、期待証明書が一つでも欠ける場合はsocketを開きません。TLS接続後も証明書を先に照合し、不一致ならHTTP要求を送信しません。

送信するapplication dataは固定した`GET /ping` 1回だけです。raw socketを使うためredirectを追跡せず、header終端を最大1,022 byteで有界受信した後、`Content-Length: 2`と一致する本文2 byteだけを読みます。headerと本文の合計は最大1,024 byte、chunked／圧縮／重複headerは拒否し、本文が厳密に`OK`の場合だけconfidence 0.70の`probable_c2=true`とします。SHA-256の対象はHTTP全体ではなく本文だけで、結果へ`response_hash_scope=http_body`を明示します。adapterは送受信byte数、response size、request bodyなし、raw response非公開も相互検証します。`/plugin`や収集・終了endpoint、POST、victim data、task、payloadは要求しません。条件がすべて一致してもHTTP pingは固有command protocolの証明ではないため、`c2_confirmed=false`を維持します。Nmap NSEではTLS 1.2だけを強制したことを保証できないため、`tls_version_enforced_by_nse=false`を明示します。

### PureRAT direct-TLS証明書pin

`purerat-direct-tls.nse`はd025 carrierから復元した`45.192.211.77:56001`へTLS-firstで接続し、application data、plaintext prelude、登録、task pollを一切送信せず、review済みleaf証明書SHA-256だけを照合します。Nmap socketでは実際のnegotiated versionをTLS 1.0へ固定したと証明できないため、証明書が一致してもconfidence 0.75の`probable_c2=true`に限定します。NSE単体とadapterの両方で`c2_confirmed=false`、`exact_profile_match=false`を固定し、Pythonの厳密なTLS version確認と同じ証拠強度へ昇格させません。

### PureRAT旧prelude互換仮説

`04000000`を送信してからTLSへ昇格する形式は、Check Pointによるv4.1.9のfamily-level公開解析で確認されています。一方、e554 v4.4.1個別検体から静的に確認したものは`tirakian.com:56001`、`:56002`、`:56003`とleaf証明書SHA-256 `67260a71…17410b`であり、この個体が同じpreludeを送ることは確認できていません。family-levelの確認とsample-levelの未確認を統合しません。

`purerat-c2.nse`は、この差を明示した互換仮説としてe554の3 endpointへだけ適用します。profile IDごとにportを固定し、同値acknowledgement、review済みhostname、期待証明書が一致しない場合はsocketを開きません。portruleもこの3 portだけを許可し、従来の「走査した全open TCP portへprelude送信」は廃止しました。

e554への`04000000`適用は旧実装との互換仮説であり、e554の保存済み静的設定だけから当該wire preludeを確定しません。証明書が一致してもconfidence 0.60のprobableに限定し、`c2_confirmed=false`、`compatibility_hypothesis=true`を固定します。また`reconnect_ssl()`ではTLS 1.2だけを強制したことをNSE結果から検証できないため、`tls_version_enforced_by_nse=false`とします。

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

FormBookの完全な登録protocolは引き続きno-send境界です。`xloader.variant=formbook`はTCP到達性だけを0.15で記録します。追加静的解析でreviewした単一bootstrap経路と4件の公開PCAPで確認したfan-out形状は、オフライン相関とloopback回帰だけに利用します。`stealer-route-c2.nse`の`formbook` modeはproduction bindingから除外し、`monitor_recent_c2.py`と`nmap_c2_detector.py`は完全一致profileや許可flagの有無にかかわらずHEAD送信を拒否します。

FormBook／XLoaderの公開Nmap結果には、静的endpoint束縛、capture endpoint束縛、URL鍵による暗号束縛、server command protocolという4つの独立証拠classの必要数と不足classを明示します。transport-only観測では取得数を常に0とし、TCP open、TLS証明書、server-first byte、HTTP statusをこれらの代用にしません。4 classの相関は保存済みcaptureを`formbook_protocol.py assess-passive`へ渡すオフライン工程でだけ評価し、Nmap結果単独では`probable_c2`と`c2_confirmed`をともにfalseへ固定します。

### Vidar／AMOSの経路差分判定

`stealer-route-c2.nse`は、script内のreview済みprofileを引数で上書きできない形で固定し、同値acknowledgementと数値IP pinが揃った場合だけ通信します。productionで許可するのはVidarのreview済み経路と陰性対照の2回、AMOSの二つのledger経路と陰性対照の3回だけです。要求body、query、端末情報、cookie、認証情報は送らず、redirectと応答bodyも追跡しません。経路差が成立した場合でもprotocol固有応答ではないため、Vidarは0.60、AMOSは0.65の`probable_c2=true`に限定し、`c2_confirmed=false`を維持します。profile ID、実行例、status条件は[`STEALER-ROUTE-PROBES.md`](STEALER-ROUTE-PROBES.md)に記載しています。

## 実行例

標準運用ではadapterを使います。NSE引数に資格情報や鍵が必要な場合もcommand lineへ展開せず、権限制限した一時`--script-args-file`だけに書きます。

```powershell
py -3.13 .\analysis-framework\nmap\nmap_c2_detector.py <host> <port> `
  --protocol https --sample-sha256 <sha256> `
  --nmap C:\Tools\Nmap\nmap.exe `
  --allow-network --allow-reviewed-application-probes `
  --acknowledge-profile <exact-profile-id> `
  --output .\.work\c2-observation.json
```

対象へ能動的な通信を送るため、許可された監視対象だけに使用します。profile値は対象検体の解析結果から取得し、shell historyや公開ログへの資格情報・RC4 keyの残存に注意してください。

NSEの直接起動はadapterの中央profile照合と追加許可gateを迂回するため、外部targetの標準運用では使用しません。FormBook／XLoaderに例外はなく、既知経路、登録値、汎用HTTP要求を送信しません。Vidar／AMOSのprofile限定調査だけは、[`STEALER-ROUTE-PROBES.md`](STEALER-ROUTE-PROBES.md)の固定profile、同値acknowledgement、数値IP pin、許可済み監視対象という全条件を満たす場合に限ります。通常のscript単体確認は`verify_nse.py`が起動するnumeric loopback fixtureで行います。

## 動作検証

`verify_nse.py` はloopback上で一時的な模擬C2を起動し、Nmap 7.99を実際に40回呼び出して、汎用DNS／transport、送信ゼロのN520型44-byte frameと`TIMEOUT` marker、review済みloopback profileを持つmalware固有modeの正応答、Winos送信frameのecho拒否、DarkCometのraw EOF、ASCII-hex 6+6遅延分割、12+1遅延超過、wrong key、malformed、partial、overlong、StealCのredirect拒否、RedLineのtrue／false／追加要素拒否／redirect拒否／acknowledgement拒否／production target不一致拒否、XLoader／FormBookのno-send境界、FormBook／Vidar／AMOSの経路一致・不一致を確認します。PureLogsと旧PureRAT preludeはproduction endpoint以外を許可しないため、この動的loopback一覧へは含めません。外部networkには接続しません。TLS証明書とprivate keyは一時directoryだけに生成し、終了時に削除します。

```powershell
python .\analysis-framework\nmap\verify_nse.py --nmap C:\Tools\Nmap\nmap.exe
python -m pytest .\analysis-framework\tests\test_nmap_c2_scripts.py -q
```

統合試験では、Winos、vvaS、N520、AsyncRAT、VenomRAT、PureRAT、AgentTesla FTP、StealC、Lumma、Remus、DarkComet、RedLine、XLoader、FormBook、Vidar、AMOSの送受信または受信専用処理と最終statusを検証します。DarkCometとXLoader／FormBook transport fixtureはクライアントからapplication dataを1 byteでも受信した場合に失敗するため、no-send境界も確認できます。FormBook／Vidar／AMOS route fixtureは要求数、method、Host、User-Agent、bodyなしを固定します。PureLogsと旧PureRAT preludeについては、NSE構文解析、固定profile gate、応答上限、adapter側のconfirmed抑止を外部接続なしのunit testで検証します。`profiles.json`と中央の`c2_protocol_probe_profiles.json`の対応漏れもunit testで検出します。
