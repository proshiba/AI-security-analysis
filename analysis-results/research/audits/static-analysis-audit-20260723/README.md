# 静的解析カバレッジ監査

この報告書はリポジトリのメタデータと公開成果物だけから作成しています。
検体の読込み・実行、CPU／CILエミュレーション、外部通信はいずれも行っていません。

## カバレッジ

| 項目 | 件数 |
|---|---:|
| ケースディレクトリ | 3362 |
| 一意なSHA-256 | 3362 |
| 公開JSON文書 | 45058 |
| IOC一覧 | 3855 |
| 履歴登録SHA-256 | 611 |
| 静的設定を復元できていないケース | 2674 |
| マルウェア定義 | 31 |
| ワークフロー定義 | 33 |
| レジストリ登録ファミリー | 79 |

## analysis.json の状態

| 状態 | 件数 |
|---|---:|
| bounded_static_terminal_recovery_attempted_not_recovered | 1 |
| c2_protocol_confirmation_pending | 1 |
| characteristic_function_static_analysis_complete | 839 |
| characteristic_function_static_analysis_complete_with_documented_limits | 857 |
| config_recovered_final_c2_unresolved | 2 |
| function_review_required | 697 |
| missing | 431 |
| 要確認 | 58 |
| partial | 4 |
| 完了 | 383 |
| reclassification_pending_runtime_route_table_and_request_schema_unresolved | 1 |
| reviewed_function_logic | 1 |
| サイズ上限でスキップ | 1 |
| specialized_static_recovery_and_representative_function_review_complete_root_lineage_pending | 1 |
| terminal_component_static_analysis_complete_family_unresolved_by_design | 1 |
| terminal_config_recovered_protocol_unverified | 1 |
| terminal_static_logic_complete | 4 |
| triaged_unknown_with_reviewed_function_inventory | 1 |

## 契約・完全性に関する指摘

| 指摘 | 件数 |
|---|---:|
| JSON解析エラー | 0 |
| 監査上限を超えた公開文書 | 0 |
| READMEがないケース | 0 |
| IOC一覧がないケース | 0 |
| schema_versionがないanalysis.json | 0 |
| 標準外のIOC一覧 | 0 |
| 外部情報提供者データの公開境界違反 | 0 |
| 不正な履歴項目 | 0 |
| 履歴未登録のケースSHA-256 | 2753 |
| 静的設定を復元できていないケース | 2674 |

## 未解決結果の印

| 分類 | ケース数 |
|---|---:|
| 未復元（`not_recovered`） | 219 |
| 不明または多重配布（`unknown_or_nested_delivery`） | 99 |
| 未解決（`unresolved`） | 3357 |

## 難解析ケースの構造トリアージ

~~~json
{
  "total": 80,
  "analyzed": 80,
  "partial": 0,
  "not_found": 0,
  "layers_analyzed": 155,
  "budget_limited_cases": 0,
  "protector_marker_cases": 16,
  "expected_children_missing_cases": 0
}
~~~

対応するJSONには対象パスとSHA-256を全件収録しています。
