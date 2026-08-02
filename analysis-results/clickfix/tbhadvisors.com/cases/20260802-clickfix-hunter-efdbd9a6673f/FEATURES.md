# 挙動・検体特徴

| 種別 | 特徴 | 確度 |
|---|---|---|
| 配布手法 | ClickFix / fake verification | provider報告 |
| domain | `tbhadvisors.com` | provider報告 |
| clipboard | `確認` | providerまたはライブHTML |
| command系列 | `telegram_dead_drop_powershell` | 静的command解析 |
| HTTP応答 | `[200]` | 解析時ライブ観測 |
| WebDAV Multi-Status | `未観測` | GET応答 |
| Telegram resolver | `到達・次段token未復元` | 限定ライブ観測 |
| body形式 | `{'html': 2}` | 解析時ライブ観測 |
| 終端binary | `0`件 | 上限付きGET |

本ファイルは挙動と特徴だけを扱い、IOC値や検知条件の詳細は別成果物へ分離しています。
