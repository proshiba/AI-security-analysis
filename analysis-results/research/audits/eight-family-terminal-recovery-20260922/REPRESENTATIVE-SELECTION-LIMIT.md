# 代表関数選定の再評価と限界

対象は `658fc8b2caf56d7572f065bdc7bcf248f1ba3e96901ba6ed3eee4291e524d46e` の保存済みGhidra解析である。暗号化保管物のサイズ・SHA-256、内部目録、および `ghidra-raw-index.json` のサイズ・SHA-256を照合してから、関数選定器だけを再実行した。検体は実行せず、Ghidraの再解析やC2接続も行っていない。

保存済みの関数inventoryは1,339件だが、取得済み `ghidra_call_graph.edges` は0件だった。このため、改良後の「入口から観測されたcall edgeへの到達性」加点は、このケースには適用できない。再選定では入口 `0x140042218` を選び、Control Flow Guard補助関数 `_guard_dispatch_icall`（`0x140065ab0`）はcommand dispatcherとして選ばなくなった。一方、既存の別途静的追跡で入口からの直接callが確認された `0x140006340` とAV無効化処理群の `0x140011740` は、保存済みcall graphだけを使う自動選定では依然として選ばれなかった。

これは実検体での終端ペイロード、ValleyRAT本体、設定、C2の確認を意味しない。既存の `STATIC-LOGIC.md` や `static-logic.json` は修正後の選定で再生成していない。次回の自動化では、call graphが空のときに検証済みPEの入口からの直接callを、誤デコードと関数境界を検査しながら別の静的証拠として取得し、Ghidraの関数inventoryと突合する必要がある。直接callが得られない場合、到達性は未知として残し、名前・addressの近さから補完しない。
