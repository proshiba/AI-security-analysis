# ValleyRAT候補TLS証明書クラスタ調査

## 結論

指定された8 IPは、現時点で一括して「ValleyRAT C2確定」とは判定できません。ただし、`107[.]155[.]109[.]150`と`110[.]173[.]48[.]35`から`110[.]173[.]48[.]38`までの5台は、2026-09-14 12:26 UTC時点で次の3点が完全一致しました。

- TCP/443がopenでTLS handshakeが成立する。
- leaf証明書はSHA-1 `7f1ed4a13d8a2ba6e690ecaf66a9dfa42dd8d9d1`、SHA-256 `ff887bedc2a83426ee1febcafe193f6601f263aca1f8fb137033173af00dc7c0`で一致する。
- client application dataを1 byteも送らない場合、TLS上でprintable ASCII 7 byteの固定`TIMEOUT`をserver-firstで返す。応答SHA-256は`ab5b50c3846ccfef52997e6e153b187022cde34b543019aa4feaf1f732feff50`で一致する。

これは5台が同一service実装または同一front-end構成に属する強いcluster証拠です。一方、既知ValleyRAT N520型のserver-first frameは44 byteで、session magicとCRC32を持ちます。今回の5台はこの形式に一致せず、固定`TIMEOUT`がValleyRAT固有であることを示す公開資料や検体由来の静的根拠も得られていません。したがって`c2_confirmed=false`、`probable_c2=false`を維持します。

## ThreatFoxと検体の紐付け

ThreatFox Community APIの`ip:port`完全一致検索を2026-09-14に実施しました。APIはIOC検索結果に`malware_samples`を含める仕様です（[ThreatFox API](https://threatfox.abuse.ch/api/)）。

| endpoint | ThreatFox | 登録内容 | 検体・reference |
| --- | --- | --- | --- |
| `185[.]9[.]17[.]250:443` | IOC ID [1892367](https://threatfox.abuse.ch/ioc/1892367/) | ValleyRAT、confidence 75、tags `ValleyRAT`／`winos`、reporter `whoamix302`、first seen 2026-09-01 07:27:30 UTC | `malware_samples` 0件、referenceなし |
| `43[.]154[.]230[.]182:443` | IOC ID [1892371](https://threatfox.abuse.ch/ioc/1892371/) | ValleyRAT、confidence 75、tags `ValleyRAT`／`winos`、reporter `whoamix302`、first seen 2026-09-01 07:27:28 UTC | `malware_samples` 0件、referenceなし |
| 残る6 endpoint | 完全一致なし | ThreatFox上の直接帰属なし | 紐付け検体なし |

2件は同一reporterが2秒差で登録した同一campaign候補ですが、ThreatFoxレコード自体から取得できる検体hashや外部解析referenceはありません。比較として、検体由来の別ValleyRATレコードではThreatFoxがMalwareBazaarのSHA-256をreferenceとして表示します（[検体紐付けのある例](https://threatfox.abuse.ch/ioc/1839263/)）。今回の2件にはその根拠がありません。

MalwareBazaarのValleyRAT最新100件もmetadata-onlyで選定し、指定IPまたは証明書hashへの直接pivotを確認しましたが、一致はありませんでした。これは「該当検体が存在しない」ことの証明ではなく、今回得られた公開情報から検体を特定できなかったことを意味します。検体downloadや実行は行っていません。

## ライブ観測結果

| endpoint | 時刻（UTC） | port | TLS証明書 | server-first | ValleyRAT判定 |
| --- | --- | --- | --- | --- | --- |
| `107[.]155[.]109[.]150:443` | 12:26:07 | open | 共通SHA-1／SHA-256一致 | `TIMEOUT`、7 byte | 未確定 |
| `110[.]173[.]48[.]35:443` | 12:26:11 | open | 共通SHA-1／SHA-256一致 | `TIMEOUT`、7 byte | 未確定 |
| `110[.]173[.]48[.]36:443` | 12:26:15 | open | 共通SHA-1／SHA-256一致 | `TIMEOUT`、7 byte | 未確定 |
| `110[.]173[.]48[.]37:443` | 12:26:19 | open | 共通SHA-1／SHA-256一致 | `TIMEOUT`、7 byte | 未確定 |
| `110[.]173[.]48[.]38:443` | 12:26:23 | open | 共通SHA-1／SHA-256一致 | `TIMEOUT`、7 byte | 未確定 |
| `45[.]64[.]52[.]195:443` | 12:15:50 | closed | 未観測 | 未観測 | 判定不能 |
| `43[.]154[.]230[.]182:443` | 12:15:53 | filtered | 未観測 | 未観測 | 判定不能 |
| `185[.]9[.]17[.]250:443` | 12:15:55 | filtered | 未観測 | 未観測 | 判定不能 |

`filtered`は観測地点から応答が得られなかった状態で、停止やC2否定を意味しません。ThreatFox登録の2台が観測時にfilteredだったため、ユーザー提示の証明書を当該2台から再取得することはできませんでした。

## 受動エミュレータ／検知機能

[`c2-transport-observe.nse`](../../../../analysis-framework/nmap/scripts/c2-transport-observe.nse)と[`nmap_c2_detector.py`](../../../../analysis-framework/nmap/nmap_c2_detector.py)へ、`--observe-n520-server-first`を追加しました。

1. 対象1 endpointへNmap NSEで単一TLS接続を行う。
2. client application dataを送らず、最初の7 byteを受信する。
3. `TIMEOUT`なら同一service markerとして記録し、family確定には使用しない。
4. それ以外は最大44 byteまで受信し、N520型のsession magicとCRC32を検証する。
5. 44 byte完全一致でも汎用候補調査では`probable_c2=true`までとし、`c2_confirmed=false`を維持する。
6. raw response、端末情報、認証、登録、task poll、command、payloadを送信・保存・公開しない。

```powershell
python .\analysis-framework\nmap\nmap_c2_detector.py `
  <IP> 443 `
  --protocol tls `
  --family valleyrat `
  --observe-n520-server-first `
  --timeout 3 `
  --nmap C:\Tools\Nmap\nmap.exe `
  --allow-network `
  --output .\observation.json
```

外部対象へWinos 15-byte heartbeatやvvaS `33 32 00`は送っていません。指定endpointへ結び付く検体hashと完全一致profileがない状態でmalware固有requestを送ると、別serviceに対する誤送信とfamily誤認の両方が起こり得るためです。

## 評価

| 仮説 | 評価 | 根拠 |
| --- | --- | --- |
| 8 IPが同じTLS clusterだった | 部分確認 | 5台は証明書と`TIMEOUT` markerまで一致。3台は現在観測不能 |
| ThreatFoxの2 IPがValleyRATとして報告されている | 確認 | APIの2レコード、confidence 75、`ValleyRAT/winos`タグ |
| 2 IPへ紐付く検体がThreatFoxにある | 否定 | 両レコードとも`malware_samples` 0件、referenceなし |
| 5台が既知N520型ValleyRAT C2である | 現在の応答とは不一致 | 7-byte `TIMEOUT`であり、44-byte magic＋CRC32ではない |
| 5台が別方式のValleyRAT C2である | 未確定 | 共通service証拠は強いが、検体由来request／response根拠がない |

最終的なfamily確定には、この8 IPのいずれかを静的configに持つ検体SHA-256、または同一証明書と`TIMEOUT` markerをValleyRAT server実装へ結び付ける再現可能なprotocol根拠が必要です。Winos4.0／ValleyRATには複数variantが存在し、設定や通信差分があることも報告されています（[Proofpoint](https://www.proofpoint.com/us/blog/threat-insight/ta4922-suspected-chinese-crime-group-going-global)）。証明書だけでのfamily帰属は避けます。

## 安全境界と検証

- マルウェア検体実行：なし
- マルウェア検体download：なし
- 外部接続：ユーザー指定8 IPのTCP/443だけ
- application data送信：0 byte
- 端末登録、認証、task取得、command送信、payload取得：すべてなし
- raw request／response公開：なし
- 実装検証：関連pytest 26件中26件成功、Nmap 7.99 loopback統合試験41件中41件成功

Nmap 7.99 installerは公式配布物を使用し、SHA-256 `fda839f35d9f8f18a11670e17d0332ce9d05a3556c5a20e91b0b56c57774f611`を[公式digest](https://nmap.org/dist/sigs/nmap-7.99-setup.exe.digest.txt)と照合しました。
