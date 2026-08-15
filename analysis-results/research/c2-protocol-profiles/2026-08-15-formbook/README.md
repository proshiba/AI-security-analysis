# FormBook／XLoader HTTP検出の追加解析

## 結論

FormBook／XLoaderの発見率を、単一hostやHTTP statusに依存せず改善した。受動側は4件の公開PCAPに共通する複数endpointのHTTP fan-outを検出し、能動側は静的解析でreviewした単一bootstrap経路と固定陰性対照だけを`HEAD`で比較する。暗号化された登録応答は未確認であるため、能動側の上限はconfidence 0.60の`probable_c2`であり、`c2_confirmed`は常にfalseとする。

機械可読な集計は[`route-fanout-evidence.json`](route-fanout-evidence.json)に記録した。route、query値、User-Agent値、cookie、bodyは同JSONへ公開していない。

## 受動fan-out

次の条件をすべて満たすendpointを1組として数える。

- 同一User-Agentである。
- 4文字の英数字経路を使う。
- GETが同じ2個のquery名を持つ。
- 同じendpointと経路へPOSTが存在する。
- 6以上の異なるendpointと6以上の異なる経路で成立する。

4件の公開観測では13〜15 endpointが一致した。単一endpoint、5 endpoint以下、query名の組が異なる通信、POSTを伴わないGETはfail-closedとなる。HTTP statusは判定条件へ使わない。これはdecoy、redirect、404、一般的なWeb応答だけで誤昇格させないためである。

## 静的bootstrap経路

検体`3f79dba83a2059c77f593c3247acf8f3d2b4c3e8a60f9ba1a656d0c04e600948`の復元済みXLoader像をGhidraで再確認した。初期16 recordのうちrecord 12は通常pool値を独立bootstrapへ置換し、`www[.]plantaonewsms[.]com[.]br:80/ximu/`を使用する。GET／POST builderと固定User-Agentも同じnetwork初期化flowで確認した。

一方、request生成に必要なURL seedはruntime contextから読み出して変換される。静的像には一意なwriterがなく、受信bufferの後段consumerも回収範囲外である。このため、登録GET、query値、暗号化response判定をNmapへ移植していない。

## Nmapの境界

`stealer-route-c2.nse`の`formbook` modeは、完全一致profile ID、同値acknowledgement、数値IP pinが揃った場合だけ動作する。

- review済み経路と固定陰性対照へ、最大2回の`HEAD`を送る。
- request body、query、cookie、端末情報、認証情報を送らない。
- redirectとresponse bodyを追跡しない。
- review済み経路が存在status、陰性対照が不存在statusの場合だけ0.60とする。
- 両経路が404、同じstatus、無応答、不正headerの場合は昇格しない。
- 候補endpointや4文字経路を一斉送信しない。

この差分は経路能力の証拠であり、implantの受理、現在の運用主体、暗号化C2 responseを意味しない。

## 実行安全性

追加解析は保存済みPCAP、memory dump、復元済みstatic imageだけを使用した。検体、CLR、shellcodeを実行せず、外部C2へ接続していない。Nmap統合試験はnumeric loopbackだけを使用する。検体、memory dump、復号payload、Ghidra projectはGitへ追加していない。
