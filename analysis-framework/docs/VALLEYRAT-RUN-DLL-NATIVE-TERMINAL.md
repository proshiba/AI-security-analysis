# ValleyRAT run DLL型native終端の静的系譜

## 目的

`run` exportを持つx86 DLLについて、検体を実行せず、外部へ通信せずに、
固定幅設定からValleyRATの初回登録送信までを静的に検証する。
個別検体のhash、実C2、raw config、binaryはこの文書へ記録しない。

## 厳格判定の証拠鎖

`run_dll_native_terminal.py` は、次の関係がすべて成立した場合だけ
`terminal_family_lineage_proven=true` を返す。

1. `run` exportが`CreateThread`へ渡す静的callbackを復元できる。
2. 3組のhost、port、transport selector sourceがcallbackから参照される。
3. hostとportが同じ有界copy helperにより、それぞれ一意なruntime bufferへ
   コピーされる。selectorも3 sourceから同じruntime fieldへ入る。
4. selector値`1`の比較とconditional moveを介して、TCP transportのconstructor
   戻り値が選択される。
5. runtime portが数値化され、その戻り値とruntime hostが、選択済みtransportの
   connect methodへ渡る。
6. constructorが設定したvtableからconnect、send、recv worker、callback setterを
   復元し、connect/send/recvが同じobject内socket fieldを使う。
7. 送信側と受信parserの双方で、4-byte総長、10-byte session header、合計14-byte
   header、および16-bit marker `0x00CA`が対応する。
8. 受信parserが登録済みcallbackを呼び、先頭command byteを上限付きjump tableで
   分岐するdispatcherへ到達する。dispatcherにはprocess、file、registry、event log
   など複数種類の操作と、同じtransportのsend methodを使う返信経路がある。
9. 初回登録serializerがcommand `6`、固定長buffer、複数種類のhost inventoryを
   構築し、同じtransportのsend methodへ渡す。
10. byte `0xC9`を一定間隔で送るkeepalive workerとtimeout判定を確認できる。

上記の一部だけが一致する場合、設定値を復元できてもfamily確定には使わず、
`candidate_config_recovered=true` のroute-only候補に留める。

## 通信frame

確認対象のTCP frameは次の構造を持つ。

| offset | size | 用途 |
| ---: | ---: | --- |
| 0 | 4 | frame全体長 |
| 4 | 4 | session field 1 |
| 8 | 4 | session field 2 |
| 12 | 2 | marker `0x00CA` |
| 14 | 可変 | payload。先頭byteがcommand |

受信parserは14 bytesを超えるまで待ち、2つのsession fieldとmarkerを照合してから、
payloadだけをcallbackへ渡す。送信serializerは同じfieldを生成する。marker literalの
存在だけ、import名だけ、またはendpointらしい文字列だけでは証明にしない。

## 初回登録と定期通信

初回登録payloadは先頭commandが`6`で、hostname、address、system、memory、drive、
interactive sessionなど複数種類のinventoryを固定長領域へ格納する。抽出器はraw
inventoryやraw frameを出力しない。

keepaliveはcommand byte `0xC9`を約10秒間隔で同じsend methodへ渡す。最後の受信から
約60秒を超えた場合はtransportを閉じる分岐がある。この情報は静的なprotocol記述で
あり、抽出器自身が接続、送信、受信を行うことはない。

## 安全境界と上限

- 検体実行、emulation、live C2接続を行わない。
- 入力、section、import、function bytes、instruction、direct targetに上限を設ける。
- file-backed executable section外のcode pointerや、重複・不正なIATを拒否する。
- socket field、frame producer/consumer、callback、serializerのいずれかが不明なら
  欠落codeを返してfail-closedにする。
- 公開結果には絶対address、raw config、raw frameを含めない。

## 回帰試験

合成x86 fixtureで正常な全証拠鎖を確認し、少なくとも次のmutationを拒否する。

- frame markerの変更
- sendだけ異なるsocket fieldを使う変更
- dispatcher command上限の変更
- 初回登録commandの変更
- TCP以外のselector
- 上限超過入力と不正source範囲
