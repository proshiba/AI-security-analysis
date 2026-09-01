# Stealer C2 loopback検証lab

このlabはStealC、Lumma、Remus、FormBook、Vidar、AMOSについて、解析済みのrequest形状と安全境界を確認するためのものです。実C2へ接続するclientではなく、serverとclientの双方をloopbackへ固定します。

## 実装範囲

| family | 実装した範囲 | wire互換性 | C2確認 |
|---|---|---|---|
| StealC | 固定lab鍵によるRC4/Base64登録とaccess token形状 | 登録subset | 行わない |
| Lumma | `uid`、`cid`登録request | request形状だけ | 行わない |
| Remus | `tag`、`exp`、`hwid`登録とopaque envelope形状 | task意味論なし | 行わない |
| FormBook | lab marker必須のpassive sink | なし | 行わない |
| Vidar | 静的profile照合後に使うpassive sink | なし | 行わない |
| AMOS | 同一campaign IDの`/ledger/`と`/ledger/live/` sink | route形状だけ | 行わない |

FormBookのterminal wire protocolは一般化していません。review済みXLoader v8 profileについては、別の[`xloader_emulator.py`](../../analysis-framework/malware/formbook_loader/xloader_emulator.py)がofflineで復号とno-op command生成を検証します。

## 安全境界

- bind先、client接続先、accepted peerをloopbackへ限定します。
- IPv4／IPv6のliteral loopbackだけを許可し、credential、追加path、query、fragment付きbase URLを拒否します。
- redirectを追跡せず、環境変数のHTTP proxyも使用しません。
- 1 connectionにつき1 requestだけを処理します。
- request bodyは64 KiB以下に限定し、宣言長と実長を検証します。
- responseも64 KiB以下に限定し、familyごとにstatus、Content-Type、固定合成bodyを完全照合します。
- JSONの重複key、非標準数値、formの非ASCII byte、未知fieldを拒否します。
- hostname、username、file、tokenなどの実被害端末情報を送信しません。
- task、command、payload、plugin、configを返しません。
- request logと本文を保存しません。

## 利用方法

```powershell
py -3.13 .\emulators\stealers\lab.py server --host 127.0.0.1 --port 18080
py -3.13 .\emulators\stealers\lab.py client --family stealc --base-url http://127.0.0.1:18080 --timeout 5
py -3.13 .\emulators\stealers\lab.py client --family amosstealer --base-url http://127.0.0.1:18080
```

clientのJSON結果では`c2_confirmed=false`、`commands_returned=false`、`network_scope=loopback_only`、`proxy_used=false`を常に確認できます。`responses_validated=true`はlocal fixtureがfamily別の固定応答契約と一致したことだけを示し、実C2確認ではありません。`response_bytes`には本文を残さず応答sizeだけを記録します。
