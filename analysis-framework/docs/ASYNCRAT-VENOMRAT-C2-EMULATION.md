# AsyncRAT／VenomRATのC2検出と防御的エミュレーション

## 対象範囲

本実装は、完全SHA-256一致の静的解析から確認したTLS 1.2、4-byte little-endian長、原文長、GZip、MessagePack mapを対象とします。検体は実行せず、外部C2への接続は通常手順では行いません。

| family | profile ID | packet key | 合成送信 | review済み応答 |
|---|---|---|---|---|
| AsyncRAT 0.5.8 | `asyncrat-058-20f21565-191-96-78-221-7788` | `Packet` | `ClientInfo`、空`Message`の`Ping` | `pong` |
| VenomRAT 6.0.3 | `venomrat-603-6a24ba25-localto-6377` | `Pac_ket` | `ClientInfo`、空`Message`の`Ping` | `Po_ng` |

検出はTLS 1.2とfamily別の1-field heartbeat responseが両方一致した場合だけ`c2_confirmed=true`とします。証明書SHA-256の一致はexact build互換性の追加根拠です。証明書不一致だけではfork、改変build、rotationを除外できないため、family C2の否定には使いません。

## C2 detectorの判定契約

`tls_messagepack_c2_detector.py`は、取得済みのapplication frameをofflineで評価します。次をfail-closedで拒否します。

- profile ID、sample SHA-256、endpoint、packet key、certificate pin、上限の変更
- TLS 1.2以外のnegotiated version
- familyをまたいだ`Packet`／`Pac_ket`の混同
- heartbeat field以外を追加した応答
- duplicate key、noncanonical MessagePack、GZip bomb、連結／trailing data、宣言長不一致

公開結果にraw frame、応答値、command引数は含めず、sizeとSHA-256だけを記録します。外部targetの標準観測は`analysis-framework/nmap/nmap_c2_detector.py`から`dotnet-rat-c2.nse`を起動します。`--allow-network`に加えて`--allow-reviewed-application-probes`がある場合だけ、中央profileが固定する空`Message`のPingを1 frame送信し、それ以外はapplication data送信前に拒否します。Python TLS／socket probeへfallbackしません。

## host emulatorの安全境界

`tls_messagepack_rat_host_emulator.py`はマルウェアclient側の最小挙動を再現します。

1. 実端末から値を取得せず、固定合成`ClientInfo`を1回送信します。
2. active window titleを取得せず、`Message`を空文字にした`Ping`を1回送信します。
3. 最大1 application frameを受信してheartbeat、file／plugin、operation、unknownへ分類します。
4. 受信commandを実行せず、file／pluginを保持せず、結果を返信せず終了します。

任意operationのresult serializerは静的に確定していません。`synthetic_result_decision()`はoffline metadataだけを返し、`wire_bytes=None`、`send_allowed=false`を維持します。

通信なしpreflight:

```powershell
py -3.13 -B analysis-framework/common/run_defensive_rat_emulator.py preflight `
  --profile-id asyncrat-058-20f21565-191-96-78-221-7788

py -3.13 -B analysis-framework/common/run_defensive_rat_emulator.py preflight `
  --profile-id venomrat-603-6a24ba25-localto-6377
```

## C2側loopback fixture

`tls_messagepack_loopback_c2_emulator.py`はTLSを終端しないapplication-layer fixtureです。numeric loopbackへ1接続だけbindし、完全一致の合成`ClientInfo`と`Ping`を受けた場合だけ固定`pong`／`Po_ng`を1 frame返します。

- task、plugin、file、operation resultは送信しません。
- raw frame、合成端末値、command引数を結果へ保持しません。
- 外部IP、hostname、wildcard bindを開始前に拒否します。
- 実C2やTLS serverの代替ではなく、codecとhost emulatorの統合試験専用です。

手動起動例:

```powershell
$env:PYTHONPATH = (Resolve-Path analysis-framework/common).Path
py -3.13 -B -m tls_messagepack_loopback_c2_emulator `
  --profile-id asyncrat-058-20f21565-191-96-78-221-7788 `
  --bind 127.0.0.1 `
  --port 17788
```

このserverはapplication frameを待つため、通常は次のloopback統合testから使用します。

```powershell
$env:PYTHONPATH = (Resolve-Path analysis-framework/common).Path
py -3.13 -B -m pytest -q `
  analysis-framework/tests/test_tls_messagepack_c2_detector.py `
  analysis-framework/tests/test_tls_messagepack_loopback_c2_emulator.py `
  analysis-framework/tests/test_tls_messagepack_rat_host_emulator.py `
  analysis-framework/tests/test_nmap_c2_detector.py `
  analysis-framework/tests/test_nmap_c2_scripts.py
```

## 未実装の境界

- 任意taskの成功／失敗result serializer
- file／plugin／stageの送受信
- shell、process、filesystem、registry、画面、camera、clipboardなどの実処理
- loopback fixtureのTLS終端または外部公開
- 常時接続、再接続、複数endpoint fallback

外部live sessionは短期lease、kill-switch、MaxMind、完全一致profile、複数の明示flagを要求する別経路です。本書のloopback fixtureをlive C2確認や解析完了証拠へ昇格してはいけません。

関連文書は[共通の防御的RATホストエミュレーター](RAT-C2-HOST-EMULATOR.md)と[ValleyRAT／PureRATエミュレーターの実装状況](VALLEYRAT-PURERAT-EMULATOR-STATUS.md)です。
