# MalwareBazaar Vidar追加解析1件（2026-08-16）

MalwareBazaarの最新候補から、内部の静的根拠でVidar設定を確認できた1件を公開した。暗号化ZIPから完全SHA-256一致のmemberだけをrepository外で静的に読み、検体を実行していない。

- 対象観測時刻: `2026-08-15 08:59:38`
- 取得: `1/1`、pending `0`
- 公開段階: `analysis_followup_pending`
- 解析契約SHA-256: `9573bb1947967e0dbc05d8815a21851ee9316550534fcecb41e99c9c0c24514a`
- 検体実行: なし
- dead-drop／C2への接続: なし
- Vidar固有handler成功: `1`
- 静的設定回収: `1`
- 代表関数レビュー: `1`
- 確認済み直接C2: `0`

## 分類内訳

| 正規分類 | 件数 |
|---|---:|
| [vidar](sources/vidar/README.md) | 1 |

## 静的ロジック状態

| 状態 | 件数 |
|---|---:|
| `reviewed_function_logic` | 1 |

設定version `3.0`、build ID、Telegram・Pinterest・Steamのdead-drop 3件を回収した。最終C2は未解決であり、直接C2へ昇格していない。個別の設定、関数、制約は正規caseを参照する。
