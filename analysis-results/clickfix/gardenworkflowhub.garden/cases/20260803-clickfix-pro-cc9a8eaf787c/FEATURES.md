# 挙動・検体特徴

| 種別 | 特徴 | 確度 |
|---|---|---|
| 配布手法 | ClickFix / fake verification | provider報告 |
| domain | `gardenworkflowhub.garden` | provider報告 |
| clipboard | `未確認` | providerまたはライブHTML |
| 実ブラウザ | `ok` / event `0`件 | 解析時ブラウザ観測 |
| command系列 | `未確認` | 静的command解析 |
| HTTP応答 | `[207]` | 解析時ライブ観測 |
| WebDAV Multi-Status | `観測` | GET応答 |
| Telegram resolver | `対象外` | 限定ライブ観測 |
| body形式 | `{'other': 1}` | 解析時ライブ観測 |
| 終端binary | `0`件 | 上限付きGET |

本ファイルは挙動と特徴だけを扱い、IOC値や検知条件の詳細は別成果物へ分離しています。
