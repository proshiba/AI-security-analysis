# 全体ロジック

## 実行フロー

```mermaid
flowchart LR
  E0["利用者がlanding pageへ到達"] --> E1["ClickFix / fake CAPTCHA lure"]
  E1 -.未観測.-> E2["clipboardへcommandまたはURLを設定"]
  E2 -.未観測.-> E3["利用者がRun dialog / terminalで実行"]
  E3 -.未観測.-> E4["実行commandは未取得"]
  E4 -.未解決.-> E5["終端payload / malware"]
```

実線は情報源またはライブHTMLで確認した関係、点線はこのcaseで未観測の関係です。

## 感染チェーン

```mermaid
flowchart LR
  I0["配布・侵害domain: franklintowing.net"] --> I1["landing page"]
  I1 -.未観測.-> I2["clipboard操作"]
  I2 -.未観測.-> I3["Windows shell / LOLBIN"]
  I3 -.未観測.-> I4["追加stage取得先"]
  I4 -.未解決.-> I5["終端マルウェア"]
```

## モジュール関係

```mermaid
flowchart TD
  M0["Web landing / inject"] --> M1["lure UI"]
  M1 -.未観測.-> M2["clipboard処理"]
  M2 -.未観測.-> M3["shell command"]
  M3 -.未観測.-> M4["downloader / resolver"]
  M4 -.未解決.-> M5["payload module"]
```

## 比較プロファイル

| 軸 | 本case |
|---|---|
| 配布文脈 | `ThreatFox`で`franklintowing.net`を観測 |
| lure | `ClearFake, clearfake` |
| clipboard | `unverified` |
| command系列 | `unverified` |
| 終端payload | `未取得` |
| ライブ状態 | `HTTP応答を観測: 206` |

## 他caseとの比較

同一domain、単一tag、単一IPだけではcampaign同一性を判定しません。command系列とstage構造の
2軸以上が一致した場合に限り、同一cluster候補として上位索引で扱います。
