# 挙動・検体特徴

| 種別 | 特徴 | 確度 |
|---|---|---|
| 配布手法 | ClickFix / fake verification | provider報告 |
| domain | `project-jetbrk03429.pages.dev` | provider報告 |
| clipboard | `未確認` | providerまたはライブHTML |
| command系列 | `未確認` | 静的command解析 |
| HTTP応答 | `[200]` | 解析時ライブ観測 |
| WebDAV Multi-Status | `未観測` | GET応答 |
| Telegram resolver | `対象外` | 限定ライブ観測 |
| body形式 | `{'html': 1}` | 解析時ライブ観測 |
| 終端binary | `0`件 | 上限付きGET |

本ファイルは挙動と特徴だけを扱い、IOC値や検知条件の詳細は別成果物へ分離しています。
