# 感染チェーン

```mermaid
flowchart LR
  A["fake verification / ClickFix lure"] --> B["利用者がcommandをcopy"]
  B -. "実行は未観測" .-> C["Run dialogまたはPowerShellへpaste"]
  C -. "静的復元" .-> D["powershell.exe"]
  D --> E["Invoke-RestMethod + 動的ScriptProperty getter"]
  E --> F["spielportal.com"]
  F -. "後段未復元" .-> G["任意PowerShell stage / terminal payload"]
```

| phase | 内容 | 状態 |
|---|---|---|
| lure | fake verification／browser challenge | command文面から推定 |
| clipboard | pt5, pt6, pt7として原文取得 | 確認済み |
| user execution | paste／Enter | 未観測・未実行 |
| shell | 利用者起点（Run dialogまたは既存shell） → powershell.exe → ScriptBlock.Create → ScriptProperty getter評価（同一process） | commandから静的復元 |
| stage retrieval | spielportal.com/cj5JpRGuScm5B9ok7 | command原文で確認 |
| current retrieval | timeout | analyst probeで観測 |
| terminal payload | malware family／hash／最終command | 未取得 |
