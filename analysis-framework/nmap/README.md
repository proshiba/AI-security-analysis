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

機械可読の対応表は [`profiles.json`](profiles.json) にあります。`gh0strat`、`remcosrat`、`prometei`、`spyglace`、`purelogs` の現行実装は設定抽出・event照合・汎用transport確認が中心で、レビュー済みのon-wire固有応答がありません。誤検知を避けるため、現時点ではNSEのマルウェア固有確認対象に含めていません。

## 実行例

対象へ能動的な通信を送るため、許可された監視対象だけに使用します。profile値は対象検体の解析結果から取得し、shell historyや公開ログへの資格情報・RC4 keyの残存に注意してください。

```powershell
nmap -sT -Pn -p 6685 --script .\analysis-framework\nmap\scripts\valleyrat-c2.nse --script-args valleyrat.mode=winos haochisadnka.cc
nmap -sT -Pn -p 7788 --script .\analysis-framework\nmap\scripts\dotnet-rat-c2.nse --script-args "dotnet-rat.family=asyncrat,dotnet-rat.expected-cert=<sha256>" 191.96.78.221
nmap -sT -Pn -p 21 --script .\analysis-framework\nmap\scripts\agenttesla-ftp-c2.nse --script-args-file <protected-args-file> <host>
nmap -sT -Pn -p 80 --script .\analysis-framework\nmap\scripts\stealer-http-c2.nse --script-args-file <protected-args-file> <host>
```

## 動作検証

`verify_nse.py` はloopback上で一時的な模擬C2を起動し、Nmap 7.99を実際に10回呼び出して、全modeの正応答を確認します。外部networkには接続しません。TLS証明書とprivate keyは一時directoryだけに生成し、終了時に削除します。

```powershell
python .\analysis-framework\nmap\verify_nse.py --nmap C:\Users\Administrator\Tools\Nmap\nmap.exe
python -m pytest .\analysis-framework\tests\test_nmap_c2_scripts.py -q
```

統合試験では、Winos、vvaS、N520、AsyncRAT、VenomRAT、PureRAT、AgentTesla FTP、StealC、Lumma、Remusの送受信と最終statusを検証します。`profiles.json`と中央の`c2_protocol_probe_profiles.json`の対応漏れもunit testで検出します。
