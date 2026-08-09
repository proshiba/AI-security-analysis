# Nmap C2検知スクリプト

既存のPython C2検出器でレビュー済みの通信だけを、Nmap NSEで再現するための実装です。単なるport openをマルウェア固有C2とは扱わず、Nmapで無理なく検証できる短いprotocol応答を根拠にします。検体の実行、task本文の公開、task実行、追加payloadの追跡は行いません。

## 対応範囲

| family | script／mode | 送信・確認内容 | 最大confidence | 判定上の注意 |
| --- | --- | --- | ---: | --- |
| ValleyRAT／Winos | `valleyrat-c2.nse`／`winos` | 匿名heartbeat 1 frame、制御応答 `C9`／`CA`／`CB` | 0.95 | victim metadataは送らない |
| ValleyRAT／vvaS | `valleyrat-c2.nse`／`vvas` | `333200`、14-byte固定stage header | 0.95 | stage本体は取得しない |
| ValleyRAT／N520 | `valleyrat-c2.nse`／`n520` | TLS server-first 44-byte frame、magic、CRC32 | 0.98 | application dataは送らない |
| AgentTesla | `agenttesla-ftp-c2.nse` | FTP banner、任意で検体由来USER／PASS | 0.95 | bannerだけでは0.35。file操作はしない |
| AsyncRAT | `dotnet-rat-c2.nse`／`asyncrat` | TLS、gzip圧縮MessagePack Ping／pong | 0.98 | 証明書不一致だけでは除外しない |
| VenomRAT | `dotnet-rat-c2.nse`／`venomrat` | TLS、gzip圧縮MessagePack Ping／Po_ng | 0.98 | 証明書不一致だけでは除外しない |
| PureRAT／PureHVNC | `purerat-c2.nse` | `04000000`後のTLS昇格、証明書SHA-256 | 0.98 | 証明書pinなしは0.80で観測扱い |
| StealC v2 | `stealer-http-c2.nse`／`stealc` | RC4登録、復号済みaccess token形式 | 0.90 | task取得はしない |
| Lumma v6 | `stealer-http-c2.nse`／`lumma` | uid登録、HTTP応答形状 | 0.78 | protocol固有確認ではなく推定 |
| Remus | `stealer-http-c2.nse`／`remus` | tag／exp登録、HTTP 201、envelope長 | 0.78 | protocol固有確認ではなく推定 |
| DarkComet | `darkcomet-c2.nse` | RC4 server-first challengeの`IDTYPE`完全一致 | 0.98 | application dataは送信しない |
| RedLine Stealer | `redline-c2.nse` | 固定SOAP 1.1 `CheckConnect`を1要求、厳密なboolean応答 | 0.98 | review済みprofileのIP・port以外には送信しない |
| XLoader | `xloader-c2.nse`／`transport-only` | Nmap scanで確認済みのTCP到達性だけを明示的に記録 | 0.15 | `c2_confirmed=false`固定。登録requestや候補一斉送信はしない |

機械可読の対応表は [`profiles.json`](profiles.json) にあります。`gh0strat`、`remcosrat`、`prometei`、`spyglace`、`purelogs` の現行実装は設定抽出・event照合・汎用transport確認が中心で、レビュー済みのon-wire固有応答がありません。誤検知を避けるため、現時点ではNSEのマルウェア固有確認対象に含めていません。

### DarkCometの受信専用判定

`darkcomet-c2.nse`はTCP接続後に最大13 byte（判定上限12 byteと超過検知1 byte）だけを受信し、送信は行いません。検体から静的に復元したnetwork RC4 keyでraw 6 byteまたはASCII-hex 12 byteを復号し、平文が6 byteの`IDTYPE`へ完全一致した場合だけC2と判定します。主形式は静的コードで確認したASCII-hexで、rawは互換形式として記録します。6／12 byteを受信した時点では確定せず、EOFまたは単一の全体期限まで13 byte目の有無を確認します。

対象検体ではnetwork keyが10-byte ASCIIの`#KCMDDC5#-`であり、PWDは連結されません。設定resourceの復号key `#KCMDDC5#-890`は別用途なので、network profileへ流用すると判定を誤ります。中央profileは静的key導出、完全一致host・port、受信上限、公開証拠JSONの内容検証とSHA-256固定が揃わない限り登録しません。NSEへ渡すkeyは、この検証を通ったprofileから保護した`--script-args-file`へ生成します。

このプローブはserver-first challengeだけを検証し、implant側の`SERVER`応答、端末登録、command poll、payload取得は行いません。RC4 keyをshell historyへ残さないよう、実運用では保護した`--script-args-file`を使用してください。

名前解決はNmap本体がNSE開始前に行うため、script内の期限ではDNS時間を制限できません。NSEの期限は接続開始から受信終了までで、結果へ`dns_timeout_bounded=false`と`deadline_scope=post_dns_connect_receive`を記録します。不一致、部分、不正形式、超過、無応答の`confidence`は`0.0`です。

### RedLineのCheckConnect判定

`redline-c2.nse`は、review済みprofile IDと同値の`redline.acknowledge-profile`を別引数で要求し、`192.144.32.84:16383`、`POST /`、SOAPAction、XML bodyを固定します。production profileでIPまたはportが異なる場合、または生成requestがreview済みの357 byte／SHA-256と異なる場合は、application dataを送る前に停止します。送信は最大1要求、requestは512 byte以下、responseはHTTP headerを含め4096 byte以下です。raw socketを使うためredirectを追跡せず、端末情報、資格情報、task取得要求は送信しません。

HTTP 2xx、単一の`Content-Length`、`text/xml; charset=utf-8`、SOAP 1.1の`Envelope > Body > CheckConnectResponse > CheckConnectResult`というnamespace付き一意な親子構造、単純なxsd:booleanをすべて満たした場合だけ`c2_confirmed=true`とします。booleanが`true`ならconfidence 0.98、`false`でもRedLine固有protocol応答は成立するため0.95ですが、後者はC2がimplantの接続を受理したことまでは示しません。DOCTYPE、entity、comment、追加要素、重複header、chunked response、redirectは拒否します。

### XLoaderのNSE境界

XLoaderは、64候補中の実C2選択とrequest／responseの多層暗号に検体固有のprivate materialが必要です。NSEへ鍵や復元済みendpoint群を埋め込まず、`xloader.mode=transport-only,xloader.acknowledge-no-protocol-check=true`を明示した場合だけ、Nmap本体が確認したTCP openを低確度の能力情報として返します。NSE自身は追加socketを開かず、application data、端末登録、candidate spray、task取得を一切送信しません。したがって結果の`c2_confirmed`と`probable_c2`は常に`false`です。protocol確認は、完全一致のprivate profileと鍵境界を検証するPython側の専用probeへ引き継ぎます。

## 実行例

対象へ能動的な通信を送るため、許可された監視対象だけに使用します。profile値は対象検体の解析結果から取得し、shell historyや公開ログへの資格情報・RC4 keyの残存に注意してください。

```powershell
nmap -sT -Pn -p 6685 --script .\analysis-framework\nmap\scripts\valleyrat-c2.nse --script-args valleyrat.mode=winos haochisadnka.cc
nmap -sT -Pn -p 7788 --script .\analysis-framework\nmap\scripts\dotnet-rat-c2.nse --script-args "dotnet-rat.family=asyncrat,dotnet-rat.expected-cert=<sha256>" 191.96.78.221
nmap -sT -Pn -p 21 --script .\analysis-framework\nmap\scripts\agenttesla-ftp-c2.nse --script-args-file <protected-args-file> <host>
nmap -sT -Pn -p 80 --script .\analysis-framework\nmap\scripts\stealer-http-c2.nse --script-args-file <protected-args-file> <host>
nmap -sT -Pn -p 1604 --script .\analysis-framework\nmap\scripts\darkcomet-c2.nse --script-args-file <protected-args-file> <host>
nmap -sT -Pn -p 16383 --script .\analysis-framework\nmap\scripts\redline-c2.nse --script-args redline.profile-id=redline-3f3ac0a3-checkconnect-v1,redline.acknowledge-profile=redline-3f3ac0a3-checkconnect-v1 192.144.32.84
nmap -sT -Pn -p <port> --script .\analysis-framework\nmap\scripts\xloader-c2.nse --script-args xloader.mode=transport-only,xloader.acknowledge-no-protocol-check=true <single-reviewed-host>
```

## 動作検証

`verify_nse.py` はloopback上で一時的な模擬C2を起動し、Nmap 7.99を実際に25回呼び出して、全modeの正応答、DarkCometのraw EOF、ASCII-hex 6+6遅延分割、12+1遅延超過、wrong key、malformed、partial、overlong、RedLineのtrue／false／追加要素拒否／redirect拒否／acknowledgement拒否／production target不一致拒否、XLoaderのno-send境界を確認します。外部networkには接続しません。TLS証明書とprivate keyは一時directoryだけに生成し、終了時に削除します。

```powershell
python .\analysis-framework\nmap\verify_nse.py --nmap C:\Users\Administrator\Tools\Nmap\nmap.exe
python -m pytest .\analysis-framework\tests\test_nmap_c2_scripts.py -q
```

統合試験では、Winos、vvaS、N520、AsyncRAT、VenomRAT、PureRAT、AgentTesla FTP、StealC、Lumma、Remus、DarkComet、RedLine、XLoaderの送受信または受信専用処理と最終statusを検証します。DarkCometとXLoaderのfixtureはクライアントからapplication dataを1 byteでも受信した場合に失敗するため、no-send境界も確認できます。`profiles.json`と中央の`c2_protocol_probe_profiles.json`の対応漏れもunit testで検出します。
