# 8系統の終端ペイロード復元ギャップ棚卸し（2026-09-22）

## 対象と結論

前回の国内観測に基づく調査で列挙したPureRAT／PureHVNC、DcRAT、AsyncRAT、VenomRAT、Formbook、LummaStealer、RemusStealer、ValleyRATの終端未復元ケースを、[終端ギャップ台帳](../../../../intelligence/terminal-payload-recovery/inventory.csv)から漏れなく再点検した。対象は104件であり、[機械可読JSON](cases.json)と[CSV](cases.csv)に各SHA-256、整理先、停止理由、既存成果物、元byte証拠の有無、次の安全な手順を記録した。DcRAT整理先の該当ケースは0件である。

この104件は「終端まで復元・検証済み」の件数ではない。台帳は旧来の人手記録も取り込み、`report.json`の`complete`と終端復元の成立が矛盾するケースがある。ファミリーフォルダー名や提供元のsignatureから終端ファミリーを確定しない。

| 整理先 | 件数 | `report.json`あり | 公開`static-layers.json`に子層あり | 内部選択familyあり |
|---|---:|---:|---:|---:|
| PureRAT／PureHVNC | 3 | 3 | 1 | 1 |
| DcRAT | 0 | 0 | 0 | 0 |
| AsyncRAT | 3 | 3 | 0 | 0 |
| VenomRAT | 8 | 0 | 0 | 0 |
| Formbook | 11 | 9 | 0 | 0 |
| LummaStealer | 16 | 0 | 0 | 0 |
| RemusStealer | 22 | 17 | 0 | 0 |
| ValleyRAT | 41 | 24 | 2 | 5 |
| 合計 | 104 | 56 | 3 | 6 |

`report.json`がない48件にも旧形式の解析文書や外部保管物があり得るため、「解析未実施」とは解釈しない。96件は人手記録の`human_documented_terminal_gap`を持つが、これだけでは実際の復号失敗位置を特定できない。必要な終端byteの不在が明記された3件はValleyRAT整理先`6546aad6...`、VenomRAT整理先`3187d3e3...`と`6d25076b...`である。

## 元byteと既存復元証拠

ユーザーディレクトリの隔離済み候補をファイル名で横断し、実byteがある候補はSHA-256を再計算した。16件のroot実byteと、暗号化ZIPのmemberを認証済みの1件について完全一致を確認した。別の6件は同じSHA名のローカルZIPを確認したが、member照合前なので`archive_named_only`とした。case名を含む私有アーカイブのオブジェクトキーは19件で観測した。ただしオブジェクト名だけでは必要な終端byteの内包を証明できず、旧collection単位の保管物もあるため、残りを「存在しない」と判定しない。公開CSVには私有絶対パス、アーカイブURI、復号設定の生値を含めない。

AsyncRAT整理先の`f6f7dbd6...`は特に台帳の陳腐化が明らかである。別の私有静的解析ではrootからDonut子層を経て64,512 byteの終端PE `8e07ec3b2017e3be75d8d3d56a847f705ac6389427471ed52481cef870351600`を復元し、保持実byteを再ハッシュして一致した。さらに動的saltを使うprofileでHMAC検証済み設定を静的復元し、BwRat／VenomRAT系のprotocol lineageと候補endpointを得ている。ただし現在の公開caseは`unclassified`／終端未取得のままで、親子・設定証拠の同期とseal検証が済むまで完了へ昇格しない。提供元のAsyncRATラベルと終端帰属は矛盾しており、家族名を機械的に上書きしない。

ValleyRAT整理先の`4972c57c...`では別の私有静的解析に3,194 byteのOnyx shellcodeがあるが、解析記録自体が`unresolved_component_only`とする。これは終端ValleyRATの証拠ではない。`a7f8757c...`の別再解析は内部ValleyRAT選択と子層を示す一方、設定・通信・静的層の未完了を残す。公開caseの状態値だけで解決と数えない。

## 今回の実byteを用いた再解析

[AsyncRAT整理先2件の追補](ASYNCRAT-CANDIDATES-STATIC.md)では、`f6f7dbd6...`の終端.NET PEとHMAC検証済み設定を非実行で再現した。自己表記は`BwRat  1.0.0`で、提供元のAsyncRATラベルと整合しないため、終端ファミリーは保留する。`3610fcc5...`ではNSIS memberと追加PEまで抽出したが、暗号化dataから終端への復号は未完了である。[ValleyRAT／Gh0stRAT報告`df603ed5...`の追補](../japan-recent-unfinished-20260922/VALLEY-DF603-STATIC.md)ではInno内層4件のchecksumを検証したが、保護されたDLLとbinary dataの後段が残る。

[私有保管から検証した2件の追補](ARCHIVED-ASYNC-VALLEY-STATIC.md)では、AsyncRAT報告`5e84fd91...`はThemida内層が未取得で、外部判定もXWorm等と競合する。ValleyRAT報告`658fc8b2...`は入口からAV停止処理への静的到達性を確認したが、RAT本体・設定・C2は未確認である。どちらも対象別保管物の全memberのハッシュを照合したうえで、終端未完了のまま残す。

[代表関数選定の再評価](REPRESENTATIVE-SELECTION-LIMIT.md)では、同`658fc8b2...`の誤ってC2分配器とされたCFG補助関数を自動選定から除外した。ただし保管済みcall graphにedgeが0件だったため、AV停止主処理はなお自動選定されない。実ケースを解消したと誤表示せず、直接call graph取得の不足を次の改修点に残す。

[対象別私有保管の可用性監査](ARCHIVED-SOURCE-AVAILABILITY.json)は104件と現時点の対象別保管領域を照合した。ケースSHAを含む保管キーは15件／16 ZIPで、HeadObjectのsize・SSE・ハッシュメタデータまで一致した。うちFormbook整理先2件はZIP・manifest・全member・root SHA-256を追加認証し、再静的解析の入力として使用可能になった。この監査単独では、残る13件のZIP内部認証も、保管キーが一致しない89件のデータ不存在も証明しない。別作業で認証したAsyncRAT／ValleyRAT整理先の元byteの結果は、上記個別追補に分離して記す。

[Formbook整理先2件の再解析](ARCHIVED-FORMBOOK-STATIC.md)は、短い隔離出力先では解析エラーなく完走したが、どちらもrootのみ・終端ファミリー／設定／C2未復元だった。最初の長い出力先で出た`FileNotFoundError`はWindowsのパス長によるもので、解析器に出力先の事前検査と明確な短縮案内を追加した。この運用エラーと復号不能を混同しない。

[元入力照合キュー](../japan-recent-unfinished-20260922/TERMINAL-SOURCE-QUEUE.json)は104件全てについて、公開の元ZIP hash／sizeと任意の私有入力を分離して記録する。既知の私有ルート1か所を照合した時点で外装ZIPが一致したのは上記AsyncRAT整理先2件のみで、70件はそのルートにZIPなし、29件は公開の外装完全性情報なし、3件は必要な終端byteが元検体に不在である。外装一致はZIP memberの認証や終端復元ではない。別のローカル検体、私有S3 archive、公開sandbox artifactの確認結果は個別に扱い、この1ルートの陰性を全域の不在へ拡張しない。判定と再解析の入口は[自動化手順](../../../../analysis-framework/docs/TERMINAL-GAP-SOURCE-QUEUE.md)に記した。

## 次回以降の自動化で優先する修正

1. 完全root SHA-256を鍵に、私有の別解析と公開caseの親子SHA-256、transform、保持byteの再ハッシュ、設定復号の検証状態を照合する。再解析成果物の単純コピーではなく、矛盾を明示してからcaseの品質ゲートを再実行する。
2. local ZIP名、case別アーカイブキー、archive memberの完全ハッシュ、必要な終端byteの保持状態を別の値として管理する。`archive_named_only`やオブジェクト名一致を`verified_root_byte`へ昇格しない。
3. 一律の`human_documented_terminal_gap`ではなく、静的層の停止点、保護方式、未解決resource／method body、handler例外、必要byte不在を機械抽出して次の最小手順へ結び付ける。
4. `case_state.complete`、`c2-analysis.json`、終端到達証拠が矛盾する場合は完了表示をfail-closedで拒否する。典型例は`4972c57c...`である。
5. ローカルまたは私有保管から取得した子byteを、隔離領域で再ハッシュ後に静的fixed-point解析へ渡し、取得済み・解析済み・設定確認済みを分離して記録する。

本調査では検体や子payloadの実行、CPU／CLRエミュレーション、ライブC2接続は行っていない。上記の再解析と機能実装は一部ケースに限られ、104件全体の完遂を主張しない。
