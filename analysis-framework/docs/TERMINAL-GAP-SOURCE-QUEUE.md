# 終端未復元ケースの元入力照合

`terminal_gap_source_queue.py` は、終端ギャップ台帳のケースを横断し、元の暗号化ZIPに戻れるかを静的証拠だけで判定します。検体の復元・実行、外部照会、C2通信、自動再解析は行いません。これらは別の安全境界とジョブ契約に委ねます。

入力ZIPのSHA-256とサイズは、ケースの `report.json` にある `authenticated_single_member_zip` の外装情報、およびケースが所属する収集単位の `malwarebazaar-manifest.json` から取得します。両者が競合すれば停止します。生PEや別の親レイヤーの `outer_sha256` をZIPのhashとして扱いません。`--input-root` を指定した場合のみ、リポジトリ外の私有領域にある `<検体SHA-256>.zip` を単一走査し、外装SHA-256とサイズを照合します。入力の絶対pathは公開JSONへ残しません。

```powershell
py -3.13 .\analysis-framework\common\terminal_gap_source_queue.py --repository . --family asyncrat --family venomrat --input-root C:\analysis-lab\private\archives --output .\analysis-results\research\terminal-queue\queue.json --write
py -3.13 .\analysis-framework\common\terminal_gap_source_queue.py --repository . --family asyncrat --family venomrat --input-root C:\analysis-lab\private\archives --output .\analysis-results\research\terminal-queue\queue.json --check
```

`verified` は、保持元ZIPが記録済み外装hash・sizeと一致したことだけを意味します。ZIP内のmemberの同一性や展開後root検体の認証は行わず、終端payload、family、設定、C2が復元されたという意味でもありません。member/rootの認証と静的解析は、別ジョブで改めて実施します。`source_integrity_unbound` は公開記録に元ZIPの認証値がなく、単に同名fileがあるだけでは再解析へ進めない状態です。`required_terminal_bytes_absent` は元検体の再解析では解消しないため、完全一致の公開sandbox artifactや配布chainを探します。`conflicting_source_bindings`、重複、hash不一致は人手で根拠を解決するまで進めません。全行の `automatic_dispatch_allowed` は `false` 固定です。

再解析時は、検証済み入力を標準の `analysis_job_runner.py` へ新しい契約として渡し、静的レイヤー・終端設定・通信処理まで改めて検証します。同じ未完了結果へ単純に無限再試行しないため、実装または証拠の変化とケースの未解決理由を先に確認します。
