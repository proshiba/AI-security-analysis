# C2候補の全履歴オフライン計画（2026-09-25）

本書は[対象一覧](targets.json)と[候補在庫](candidate-inventory.json)の生成状態のみを示す。**本日分のライブC2確認結果ではない。** 当日タスクに対する明示的なライブ通信許可が未確認のため、DNS解決、TCP接続、HTTP要求、マルウェアprotocol probeは実施していない。前日までの観測値を本日観測として再利用しない。

全履歴のIOCファイル4,004件を走査し、解析可能な通常IP／FQDN 208 hostの208件を計画に反映した（coverage 100%）。計画上のendpointは302件で、既知portに基づくnetwork service endpointが284件、port不明のDNS-only対象が18件。レビュー済みprotocol targetは21件、profile-only targetは13件、protocol profile拒否は1件。解析時のparse errorは0件である。これは対象計画の完全性であって、C2稼働の確認率ではない。

本日の静的解析・公開sandboxで得たURLやhostは、候補と確認済みC2を分離したまま評価する。共有サービス上のdead-drop、通信役割未確認host、StealCのベースURLだけの部分設定を、TCP到達性や証明書だけでC2確定へ昇格しない。[当日の解析・証拠境界](../../daily-malware-followup/2026-09-25/README.md)も参照する。

次の実監視は、当日許可、MaxMind DBの鮮度確認、レビュー済みprofileの完全一致、既存active対象との統合を満たした場合にのみ実施する。未実施の現状で日次解析を完了・公開済みとみなさない。
