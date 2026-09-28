# Ghidra入口復元後の関数inventory安定確認

`ghidra_function_batch.py`は、検体を実行せず、localhostのGhidra MCPに明示的なprogram selectorを渡して静的解析を行います。

## 防止する早期確定

`analyzed=true`と`analyzing=false`は、関数一覧が今後増えないことの証明ではありません。初回の関数数が0件で、入口を復元した直後に1件だけ見え、その後に背景解析で多数の関数が見つかる場合があります。入口1件だけを即時に完了cacheへ保存しないようにします。

入口復元後は、同じselectorへの明示的な`/run_analysis`で`success=true`を確認します。その後、状態・metadata・全ページの関数inventory・metadata・状態の順に取得し、以下を満たす同一snapshotが10秒以上続くまで待ちます。

- 前後の状態が`analyzing=false`、`analyzed=true`であり、再解析要求がない。
- 前後の`analysis_status.function_count`とmetadataの全関数数が一致する。
- 関数inventoryが終端まで取得でき、既知関数の縮小・置換がない。
- inventoryの関数識別子と全関数総数が変わらない。

Ghidraのmetadataと状態の総数には外部関数が含まれますが、`list_functions_enhanced`のinventoryは非外部関数だけです。両者を単純に同数とはせず、総数が非外部関数数以上であることと差分を記録します。例えば全関数313件・非外部295件は、外部18件として説明できる組合せです。

## 待機上限と再開

待機・各HTTP要求・関数一覧の各ページを、`--analysis-timeout`から作るmonotonic deadlineに拘束します。10秒の静穏期間を確認できない、件数が不一致、解析が続く、一覧が縮小する場合は、完了扱いにせず再試行対象を残します。待機上限を10秒以下にすると、入口復元後の静穏確認を通常は完了できません。

`status=recovered`の入口復元cacheは、同一selector・件数に拘束された`inventory_stability`証拠がなければ再利用しません。再開時に既に入口1件がある場合も、単に「関数あり」として再確定せず、再解析と静穏確認を行います。入口復元を必要としなかった既知の完了cacheは、この変更だけを理由に再解析しません。

## 完全性の意味

静穏確認は、今回取得した関数一覧が観測期間内に安定したことの証拠です。任意の長さの遅延、未定義コード、逆コンパイルの誤りが存在しないことや、マルウェアの終端payload・C2・全機能が解明されたことまでは保証しません。関数取得の完全性と、個別マルウェア解析の完了・C2確認を分離します。

synthetic testでは、入口1件から295件への遅延増加、解析中への復帰、statusとmetadataの不一致、再解析成功応答の欠落、旧cache・別selector・不正件数の証拠を検証します。試験は合成応答と仮想時計だけを使い、実検体の実行やC2への接続を行いません。

## 通常待機の応答契約

通常の`_wait_for_analysis`も、`analyzing`が明示booleanであることを検証します。欠落、数値0、空文字列、不正な応答をidleへ読み替えません。正常な状態応答に含まれない`error`キーも、値が空文字列／null／falseかどうかにかかわらず拒否します。HTTP応答が戻った後にも総deadlineを確認し、期限後の`analyzing=false`を待機成功として受理しません。`analyzed=false`のidle応答は既存の再解析判断へ返し、解析済みと補完しません。

この最小防御は、通常経路の全metadata／全inventory共同静穏確認を追加したものではありません。通常経路にも共同観測を適用する改善と、長い資料回収の終了時のsnapshot再照合は残件です。10秒静穏後に新たなqueueが始まる場合もあり、有限のpollや保存済み`analyzed`flagだけから全queueの完了を保証しません。
