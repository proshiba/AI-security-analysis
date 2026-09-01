# profile定義family向けloopback lab

このlabはAsyncRAT、DarkComet、DCRat、Gh0st RAT、GuLoader、HijackLoader、njRAT、QuasarRAT、RedLine Stealer、Snake Keylogger、XWormの解析器を、検体や外部C2を使わずに統合試験する合成環境です。マルウェアの実wire protocolとは互換性がなく、`uint32-be length + strict UTF-8 JSON`だけを使用します。

## 安全境界

- bind先、client接続先、accepted peerをIPv4／IPv6のliteral loopbackへ限定します。
- 合成requestはfamily categoryごとの固定fieldと完全一致する必要があります。hostname、username、file、credentialなどの追加fieldは受理しません。
- JSONの重複key、非標準数値、64 KiB超のframe、宣言長と実長の不一致を拒否します。
- clientは応答bodyを読む前に宣言長を検証し、family、lab marker、accepted、profile match、空command listを完全照合します。
- serverは1接続1frame、I/O timeout 5秒、待受queue 8、daemon threadに制限します。
- command、task、stage、pluginを返さず、実端末情報を取得しません。

## 利用方法

通信しないpreview:

```powershell
py -3.13 .\emulators\families\lab.py preview --family quasarrat
```

loopback serverとclient:

```powershell
py -3.13 .\emulators\families\lab.py server --host 127.0.0.1 --port 19090
py -3.13 .\emulators\families\lab.py client --family asyncrat --host 127.0.0.1 --port 19090 --timeout 5
```

client結果の`profile_matched=true`と`response_family_matched=true`はlocal fixtureとの一致だけを示します。`wire_compatible_with_malware=false`を維持し、C2稼働確認や実protocol互換性の根拠には使いません。`request_sha256`と`response_sha256`は合成frameの再現性確認用で、検体や受信commandのhashではありません。

## テスト

```powershell
py -3.13 -B -m pytest -q .\emulators\families\tests\test_lab.py
```
