# 2026-09-23 C2監視の承認範囲監査

## 結論

当日生成した[`targets.json`](targets.json)は289 target recordでしたが、実行時に直近の`active-targets.json`を自動統合したため、[`effective-targets.json`](effective-targets.json)と[`monitoring-results.json`](monitoring-results.json)は322 target recordになりました。host:portで重複排除した実効endpointは318件です。

当日の明示確認で示した件数は289件でした。追加33件を含む実効集合のcommitmentを別途提示していなかったため、厳格な承認範囲としては33件を範囲外と扱います。本監査は生成済みJSONを書き換えず、観測事実と制御上の問題を明示するものです。

## 追加33件の由来

統合runnerは、2026-09-22の`active-targets.json`に残っていた対象を当日planへ重複排除して追加しました。コード上の経路は`run_c2_monitoring_pipeline.py`の`load_latest_active_plan()`と`carry_forward_active_targets()`です。追加対象の元証拠は、主に2026-09-18、2026-09-21、2026-09-22のdaily news handoffです。

追加33件の内訳は次のとおりです。

- DNS解決のみ: 25件。port接続やapplication data送信はありません。
- TCP単一接続試行: 8件。このうち6件でtransport接続が成立しました。
- 追加分のapplication data送信・protocol応答受信・認証・登録・task polling: すべて0件です。

## 実行全体の接触範囲

322 target record全体では、`target_contact_attempted=true`が270件、`target_connection_established=true`が91件でした。malware固有application dataを送信したのは、完全一致profileによるWinos heartbeatの成功3件だけです。各成功観測は15 byte送信、16 byte受信でした。

認証、malware登録、task polling、task実行、payload取得、file転送、victim metadata送信は行っていません。本日の実効322件はすべてtimeout 3秒です。汎用policyに記録された5秒は実装上の最大値であり、本日の実行値ではありません。本日の成功したTLS／HTTP観測に基づく証明書hash／banner hashは取得していません。

## 再発防止

次回以降は、通常のライブ許可だけでは当日`targets.json`外のcarry-forward対象を追加できません。

- pipelineは`--allow-carry-forward-targets`を独立した明示許可として要求します。
- 日次orchestratorは`--allow-live-c2`とは別に`--allow-c2-carry-forward`を要求します。
- 追加対象が1件以上あり、独立許可がない場合は、MaxMind取得やNmap起動より前にfail-closedで停止します。
- ライブ許可前のoffline stageにも、当日件数、追加件数、実効件数を必ず表示します。
- preflight／planは当該invocationのcarry-forward許可状態を表示します。
- 継続監視機能自体は削除せず、実効範囲を理解したoperatorが独立flagを付けた場合だけ維持します。

今後の承認確認では、当日入力件数、carry-forward追加件数、実効件数を区別して提示します。
