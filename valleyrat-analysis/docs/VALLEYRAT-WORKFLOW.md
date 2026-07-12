# 複数 ValleyRAT 検体の解析

`Invoke-ValleyRATWorkflow.ps1` は検体ごとの profile に従い、感染チェーン別の段階を実行する。検体は実行しない。

## 実行例

```powershell
$case = 'C:\Users\Administrator\MalwareSamples\b433ecdf855beaaf91d57522eebe9c9e1c3fc756f711bd79ac1b3ecf6c75016c'
$profile = '.\profiles\b433ecdf855beaaf91d57522eebe9c9e1c3fc756f711bd79ac1b3ecf6c75016c.json'
.\Invoke-ValleyRATWorkflow.ps1 -CaseRoot $case -ConfigPath $profile
```

新 MSI 検体の既定順序は `Extract → Inventory → MSI → MSIChain`。主な出力:

- `workflow-output/extraction-result.json`: hash 検証付き展開結果
- `workflow-output/msi-analysis.json`: OLE/CAB/PE stream inventory
- `workflow-output/msi-chain-c2-analysis.json`: CAB payload、sideload edge、C2 候補・確定値
- `evidence/<hash>-triage.json`: process 帰属付き外部観測と出典

## b433... の確認済み結果

感染チェーンは `KL-X86Gicasc.msi → CAB → mesedge.exe → cef_frame.dll!TbsAppInstance`。`cef_frame.dll` は protected loader。Triage では `mesedge.exe` PID 2068 が `www.tq8j.com` を解決し、`103.45.64.246:443` に反復接続した。この process 帰属により高信頼 C2 とする。正規 LetsVPN の `LetsPRO.exe` 通信は C2 判定から除外する。

## 追加検体

1. profile を追加し、期待 hash と package type を固定する。
2. `Classify-InfectionChain.py` を実行する。
3. `infection-chain-patterns.json` の推奨段階を選ぶ。
4. MSI/CAB 系なら `MSIChain` を実行し、必要なら同じ schema の network evidence を渡す。
5. `Test-TwoSampleRegression.ps1` に fixture を追加する。

TCP 接続可否だけでは C2 としない。ライブ接続は別段階で、ユーザーの明示許可がある場合だけ行う。
